//! ExternEVM custom EvmFactory — v3
//!
//! Designated fetcher rotation + commit-reveal binding.
//! Exactly one validator fetches per request (chosen deterministically).
//! Fetcher commits a hash of their answer before revealing.
//! Non-fetchers wait for the verified reveal.
//! In-block cache eliminates duplicate API hits within a single block.
//! Single-node mode: commit-reveal skipped, behavior identical to v1.

use alloy_evm::{
    eth::EthEvmContext,
    evm::EvmFactory,
    precompiles::{DynPrecompile, PrecompileInput, PrecompilesMap},
    Database, Evm, EvmEnv,
};
use alloy_primitives::{keccak256, Address, B256, Bytes, U256};
use alloy_sol_types::{SolValue, sol};
use rand::RngCore;
use rand::rngs::OsRng;
use revm::{
    inspector::NoOpInspector,
    precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult},
    Inspector,
};
use serde_json::Value as JsonValue;
use std::time::{Duration, Instant};

use crate::extern_proto::{
    commit_sender, reveal_sender, ExternCommitMsg, ExternRevealMsg,
    compute_request_hash,
};
use crate::protocol_store::{global_store, ValidatorCommit};

// ---------------------------------------------------------------------------
// Precompile address
// ---------------------------------------------------------------------------
/// Address of the API_CALL precompile: 0x00000000000000000000000000000000000000AA
pub const API_CALL_ADDRESS: Address = {
    let mut addr = [0u8; 20];
    addr[19] = 0xAA;
    Address::new(addr)
};

// ---------------------------------------------------------------------------
// Gas constants
// ---------------------------------------------------------------------------

const GAS_CACHE_HIT: u64 =    100; // in-block cache hit — just a hashmap lookup
const GAS_VERIFY:    u64 =  1_000; // non-fetcher path — verify commit+reveal
const GAS_FETCH:     u64 = 10_000; // fetcher path — HTTP + commit + reveal

// Legacy constant kept for v2 compat path in single-node
const API_CALL_GAS: u64 = 3_000;

// ---------------------------------------------------------------------------
// Safety limits
// ---------------------------------------------------------------------------

const MAX_BODY_SIZE: usize    = 4096;
const MAX_RESPONSE_SIZE: usize = 32_768;
const HTTP_TIMEOUT_MS: u64    = 5000;

// ---------------------------------------------------------------------------
// Timing (configurable via env for devnet tuning)
// ---------------------------------------------------------------------------

fn commit_window_ms() -> u64 {
    std::env::var("EXTERNEVM_COMMIT_WINDOW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

fn reveal_window_ms() -> u64 {
    std::env::var("EXTERNEVM_REVEAL_WINDOW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

// ---------------------------------------------------------------------------
// ABI struct (unchanged from v2 — Solidity interface never changes)
// ---------------------------------------------------------------------------

sol! {
    #[derive(Debug)]
    struct ApiRequest {
        string url;
        string method;
        bytes headers;
        bytes body;
        string responsePath;
        uint8 responseType;
    }
}

// ---------------------------------------------------------------------------
// Validator identity
// ---------------------------------------------------------------------------

fn node_validator_address() -> Address {
    use std::sync::LazyLock;
    static ADDR: LazyLock<Address> = LazyLock::new(|| {
        if let Ok(hex_str) = std::env::var("EXTERNEVM_VALIDATOR_ADDRESS") {
            let hex_str = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
            if hex_str.len() == 40 {
                let mut addr = [0u8; 20];
                let mut valid = true;
                for i in 0..20 {
                    match u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                        Ok(b) => addr[i] = b,
                        Err(_) => { valid = false; break; }
                    }
                }
                if valid {
                    let a = Address::new(addr);
                    eprintln!("[ExternEVM] Validator address from env: {:?}", a);
                    return a;
                }
            }
            eprintln!("[ExternEVM] Invalid EXTERNEVM_VALIDATOR_ADDRESS, using default");
        }
        let mut addr = [0u8; 20];
        addr[0] = 0xf3; addr[1] = 0x9F; addr[2] = 0xd6; addr[3] = 0xe5;
        addr[4] = 0x1a; addr[5] = 0xad; addr[6] = 0x88; addr[7] = 0xF6;
        addr[8] = 0xF4; addr[9] = 0xce; addr[10] = 0x6a; addr[11] = 0xB8;
        addr[12] = 0x82; addr[13] = 0x72; addr[14] = 0x79; addr[15] = 0xcf;
        addr[16] = 0xfF; addr[17] = 0xb9; addr[18] = 0x22; addr[19] = 0x66;
        Address::new(addr)
    });
    *ADDR
}

fn ensure_validator_registered() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let addr = node_validator_address();
        global_store().register_validator(addr);
        eprintln!("[ExternEVM v3] Registered self as validator: {:?}", addr);
    });
}

// ---------------------------------------------------------------------------
// Current block number — updated externally via update_current_block()
// ---------------------------------------------------------------------------

static CURRENT_BLOCK: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

    /// Update the current block number used for in-block cache keying.
/// Called by the executor at the start of each block.
pub fn update_current_block(block: u64) {
    CURRENT_BLOCK.store(block, std::sync::atomic::Ordering::Relaxed);
    global_store().evict_old_cache_entries(block);
}

fn current_block_number() -> u64 {
    CURRENT_BLOCK.load(std::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// URL safety (unchanged from v2)
// ---------------------------------------------------------------------------

fn is_private_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let host_part = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let host = host_part.split('/').next().unwrap_or(host_part).split(':').next().unwrap_or(host_part);
    matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0" | "::1" | "[::1]")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || (host.starts_with("172.")
            && host.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()).is_some_and(|n| (16..=31).contains(&n)))
}

// ---------------------------------------------------------------------------
// HTTP call (unchanged from v2)
// ---------------------------------------------------------------------------

fn perform_http_call(request: &ApiRequest) -> Result<JsonValue, String> {
    tokio::task::block_in_place(|| {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(HTTP_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let mut req_builder = match request.method.as_str() {
            "GET"  => client.get(&request.url),
            "POST" => client.post(&request.url),
            other  => return Err(format!("unsupported method: {other}")),
        };

        req_builder = req_builder.header("User-Agent", "ExternEVM/0.7.0");

        if !request.headers.is_empty() {
            match serde_json::from_slice::<serde_json::Value>(&request.headers) {
                Ok(JsonValue::Object(map)) => {
                    for (key, val) in map {
                        if let Some(v) = val.as_str() {
                            req_builder = req_builder.header(&key, v);
                        }
                    }
                }
                Ok(_)  => return Err("headers must be a JSON object".to_string()),
                Err(e) => return Err(format!("failed to parse headers JSON: {e}")),
            }
        }

        if request.method == "POST" && !request.body.is_empty() {
            req_builder = req_builder.body(request.body.to_vec());
        }

        let response = req_builder.send().map_err(|e| format!("HTTP request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()));
        }

        let body_bytes = response.bytes().map_err(|e| format!("failed to read response body: {e}"))?;

        if body_bytes.len() > MAX_RESPONSE_SIZE {
            return Err(format!("response size {} exceeds max {}", body_bytes.len(), MAX_RESPONSE_SIZE));
        }

        serde_json::from_slice(&body_bytes).map_err(|e| format!("failed to parse response JSON: {e}"))
    })
}

// ---------------------------------------------------------------------------
// JSON path extraction (unchanged from v2)
// ---------------------------------------------------------------------------

fn extract_json_path<'a>(json: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    if path.is_empty() {
        return Some(json);
    }
    let mut current = json;
    for segment in path.split('.') {
        if let Some(bracket_pos) = segment.find('[') {
            let field = &segment[..bracket_pos];
            let idx_str = &segment[bracket_pos + 1..segment.len() - 1];
            if !field.is_empty() {
                current = current.get(field)?;
            }
            let idx: usize = idx_str.parse().ok()?;
            current = current.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current)
}

// ---------------------------------------------------------------------------
// JSON value → ABI-encoded bytes (unchanged from v2)
// ---------------------------------------------------------------------------

fn encode_json_value(value: &JsonValue, response_type: u8) -> Result<Vec<u8>, String> {
    match response_type {
        0 => {
            let raw: Bytes = value.to_string().into_bytes().into();
            Ok((raw,).abi_encode_params())
        }
        1 => {
            let num = match value {
                JsonValue::Number(n) => {
                    if let Some(u) = n.as_u64() { U256::from(u) }
                    else if let Some(f) = n.as_f64() { U256::from(f as u64) }
                    else { return Err("cannot convert number to uint256".into()); }
                }
                JsonValue::String(s) => {
                    let cleaned = s.replace(',', "");
                    if let Ok(u) = cleaned.parse::<u64>() { U256::from(u) }
                    else if let Ok(f) = cleaned.parse::<f64>() { U256::from(f as u64) }
                    else { return Err(format!("cannot parse '{s}' as uint256")); }
                }
                JsonValue::Bool(b) => U256::from(if *b { 1u64 } else { 0u64 }),
                _ => return Err("cannot convert to uint256".into()),
            };
            Ok((num,).abi_encode_params())
        }
        2 => {
            let s = match value {
                JsonValue::String(s) => s.clone(),
                other => other.to_string(),
            };
            Ok((s,).abi_encode_params())
        }
        3 => {
            let b = match value {
                JsonValue::Bool(b) => *b,
                JsonValue::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
                JsonValue::String(s) => matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"),
                JsonValue::Null => false,
                _ => false,
            };
            Ok((b,).abi_encode_params())
        }
        _ => Err(format!("invalid responseType: {response_type}")),
    }
}

// ---------------------------------------------------------------------------
// Commitment helper
// ---------------------------------------------------------------------------

fn compute_commitment(value: &[u8], salt: &[u8; 32]) -> B256 {
    let mut preimage = Vec::with_capacity(value.len() + 32);
    preimage.extend_from_slice(value);
    preimage.extend_from_slice(salt);
    keccak256(&preimage)
}

// ---------------------------------------------------------------------------
// Precompile entry point
// ---------------------------------------------------------------------------

fn api_call_precompile(input: PrecompileInput<'_>) -> PrecompileResult {
    ensure_validator_registered();

    // Backward compat: empty input → uint256(1234)
    if input.data.is_empty() {
        if input.gas < GAS_CACHE_HIT {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }
        let output = (U256::from(1234u64),).abi_encode_params();
        return Ok(PrecompileOutput::new(GAS_CACHE_HIT, output.into(), input.reservoir));
    }

    // Decode ABI input
    let request = match ApiRequest::abi_decode(input.data) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("[ExternEVM v3] ABI decode error: {e}");
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("API_CALL: failed to decode ApiRequest".into()),
                input.reservoir,
            ));
        }
    };

    eprintln!(
        "[ExternEVM v3] API_CALL: url={} method={} path={} type={}",
        request.url, request.method, request.responsePath, request.responseType
    );

    // Validation (unchanged from v2)
    if request.url.is_empty() {
        return Ok(PrecompileOutput::halt(PrecompileHalt::Other("API_CALL: url is empty".into()), input.reservoir));
    }
    if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
        return Ok(PrecompileOutput::halt(PrecompileHalt::Other("API_CALL: url must start with http:// or https://".into()), input.reservoir));
    }
    if is_private_url(&request.url) {
        return Ok(PrecompileOutput::halt(PrecompileHalt::Other("API_CALL: private/loopback URLs are blocked".into()), input.reservoir));
    }
    if request.method != "GET" && request.method != "POST" {
        return Ok(PrecompileOutput::halt(PrecompileHalt::Other("API_CALL: method must be GET or POST".into()), input.reservoir));
    }
    if request.body.len() > MAX_BODY_SIZE {
        return Ok(PrecompileOutput::halt(PrecompileHalt::Other("API_CALL: body exceeds max size".into()), input.reservoir));
    }
    if request.responseType > 3 {
        return Ok(PrecompileOutput::halt(PrecompileHalt::Other("API_CALL: responseType must be 0-3".into()), input.reservoir));
    }

    let request_hash = compute_request_hash(
        &request.url,
        &request.method,
        &request.responsePath,
        request.responseType,
    );
    let block_number = current_block_number();
    let store = global_store();

    // 1. In-block cache hit — same endpoint already fetched this block
    if let Some(cached) = store.check_cache(request_hash, block_number) {
        if input.gas < GAS_CACHE_HIT {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }
        eprintln!("[ExternEVM v3] cache hit for request {:?}", request_hash);
        return Ok(PrecompileOutput::new(GAS_CACHE_HIT, cached.into(), input.reservoir));
    }

    let validators = store.get_validators();
    let my_addr = node_validator_address();

    // 2. Single-node fast path — skip commit-reveal overhead entirely
    if validators.len() <= 1 {
        if input.gas < API_CALL_GAS {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }
        let json = match perform_http_call(&request) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[ExternEVM v3] HTTP error (single-node): {e}");
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(format!("API_CALL: HTTP error: {e}").into()),
                    input.reservoir,
                ));
            }
        };
        let extracted = match extract_json_path(&json, &request.responsePath) {
            Some(v) => v.clone(),
            None => {
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other("API_CALL: JSON path not found".into()),
                    input.reservoir,
                ));
            }
        };
        match encode_json_value(&extracted, request.responseType) {
            Ok(encoded) => {
                store.populate_cache(request_hash, block_number, encoded.clone());
                eprintln!("[ExternEVM v3] single-node: returning {} bytes", encoded.len());
                return Ok(PrecompileOutput::new(API_CALL_GAS, encoded.into(), input.reservoir));
            }
            Err(e) => {
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(format!("API_CALL: encode error: {e}").into()),
                    input.reservoir,
                ));
            }
        }
    }

    // 3. Designate fetcher
    let designated = match store.designate_fetcher(request_hash) {
        Some(d) => d,
        None => {
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("API_CALL: no validators registered".into()),
                input.reservoir,
            ));
        }
    };

    eprintln!(
        "[ExternEVM v3] request {:?} → designated fetcher: {:?} (I am: {:?})",
        request_hash, designated, my_addr
    );

    if my_addr == designated {
        // ----------------------------------------------------------------
        // FETCHER PATH: fetch → commit → wait → reveal → return
        // ----------------------------------------------------------------
        if input.gas < GAS_FETCH {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }

        // Fetch
        let json = match perform_http_call(&request) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[ExternEVM v3] HTTP error (fetcher): {e}");
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(format!("API_CALL: HTTP error: {e}").into()),
                    input.reservoir,
                ));
            }
        };
        let extracted = match extract_json_path(&json, &request.responsePath) {
            Some(v) => v.clone(),
            None => {
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other("API_CALL: JSON path not found".into()),
                    input.reservoir,
                ));
            }
        };
        let encoded = match encode_json_value(&extracted, request.responseType) {
            Ok(e) => e,
            Err(e) => {
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(format!("API_CALL: encode error: {e}").into()),
                    input.reservoir,
                ));
            }
        };

        // Generate salt and commitment
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let commitment = compute_commitment(&encoded, &salt);

        // Store our own commit locally
        store.store_commit(ValidatorCommit {
            request_hash,
            validator: my_addr,
            commitment,
            received_at_ms: unix_ms(),
        });

        // Broadcast commit to peers
        let _ = commit_sender().send(ExternCommitMsg {
            request_hash,
            commitment,
            validator: my_addr,
        });
        eprintln!("[ExternEVM v3] committed for request {:?}", request_hash);

        // Wait for commit window so non-fetchers can receive our commit
        std::thread::sleep(Duration::from_millis(commit_window_ms()));

        // Broadcast reveal
        let _ = reveal_sender().send(ExternRevealMsg {
            request_hash,
            value: encoded.clone(),
            salt: B256::from(salt),
            validator: my_addr,
        });
        eprintln!("[ExternEVM v3] revealed for request {:?}", request_hash);

        store.populate_cache(request_hash, block_number, encoded.clone());
        eprintln!("[ExternEVM v3] fetcher: returning {} bytes", encoded.len());
        Ok(PrecompileOutput::new(GAS_FETCH, encoded.into(), input.reservoir))

    } else {
        // ----------------------------------------------------------------
        // NON-FETCHER PATH: wait for verified reveal from designated fetcher
        // ----------------------------------------------------------------
        if input.gas < GAS_VERIFY {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }

        let deadline =
            Instant::now() + Duration::from_millis(commit_window_ms() + reveal_window_ms());

        loop {
            if let Some(value) = store.get_verified_reveal(request_hash, designated) {
                eprintln!(
                    "[ExternEVM v3] non-fetcher: verified reveal from {:?}, returning {} bytes",
                    designated,
                    value.len()
                );
                store.populate_cache(request_hash, block_number, value.clone());
                return Ok(PrecompileOutput::new(GAS_VERIFY, value.into(), input.reservoir));
            }

            if Instant::now() > deadline {
                eprintln!(
                    "[ExternEVM v3] timeout waiting for reveal from designated fetcher {:?}",
                    designated
                );
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(
                        "API_CALL: timeout — designated fetcher did not reveal".into(),
                    ),
                    input.reservoir,
                ));
            }

            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

// ---------------------------------------------------------------------------
// Unix ms helper
// ---------------------------------------------------------------------------

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Precompile registration
// ---------------------------------------------------------------------------

fn api_call_dyn_precompile() -> DynPrecompile {
    DynPrecompile::new_stateful(
        PrecompileId::Custom("API_CALL".into()),
        api_call_precompile,
    )
}
/// Inject the API_CALL precompile into the given precompiles map.
pub fn inject_api_call_precompile(precompiles: &mut PrecompilesMap) {
    precompiles.apply_precompile(&API_CALL_ADDRESS, |_| Some(api_call_dyn_precompile()));
}

// ---------------------------------------------------------------------------
// ExternEvmFactory (unchanged from v2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ExternEvmFactory {
    inner: alloy_evm::EthEvmFactory,
}

impl ExternEvmFactory {
    pub fn new() -> Self {
        Self { inner: alloy_evm::EthEvmFactory::default() }
    }
}

impl EvmFactory for ExternEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> =
        <alloy_evm::EthEvmFactory as EvmFactory>::Evm<DB, I>;
    type Context<DB: Database> =
        <alloy_evm::EthEvmFactory as EvmFactory>::Context<DB>;
    type Tx = <alloy_evm::EthEvmFactory as EvmFactory>::Tx;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        <alloy_evm::EthEvmFactory as EvmFactory>::Error<DBError>;
    type HaltReason = <alloy_evm::EthEvmFactory as EvmFactory>::HaltReason;
    type Spec = <alloy_evm::EthEvmFactory as EvmFactory>::Spec;
    type BlockEnv = <alloy_evm::EthEvmFactory as EvmFactory>::BlockEnv;
    type Precompiles = <alloy_evm::EthEvmFactory as EvmFactory>::Precompiles;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        evm_env: EvmEnv<Self::Spec, Self::BlockEnv>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let mut evm = self.inner.create_evm(db, evm_env);
        inject_api_call_precompile(evm.precompiles_mut());
        evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut evm = self.inner.create_evm_with_inspector(db, input, inspector);
        inject_api_call_precompile(evm.precompiles_mut());
        evm
    }
}