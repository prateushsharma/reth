//! ExternEVM custom EvmFactory — v2 + p2p broadcasting
//!
//! Wraps the standard `EthEvmFactory` and injects the API_CALL precompile
//! at address 0x00000000000000000000000000000000000000AA.
//!
//! v1: Single node fetches API, returns result directly.
//! v2: Node fetches API, stores value in protocol store, computes
//!     median/majority across all submissions, returns aggregated result.
//!     Broadcasts fetched values to peers via extern/1 subprotocol.
//!     In single-node mode, behavior is identical to v1.

use alloy_evm::{
    eth::EthEvmContext,
    evm::EvmFactory,
    precompiles::{DynPrecompile, PrecompileInput, PrecompilesMap},
    Database, Evm, EvmEnv,
};
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolValue, sol};
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::result::{EVMError, HaltReason},
    inspector::NoOpInspector,
    precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult},
    primitives::hardfork::SpecId,
    Inspector,
};
use serde_json::Value as JsonValue;
use std::time::Duration;

use crate::protocol_store::{
    self, global_store, compute_median_uint256, compute_majority_string,
    compute_majority_bool,
};
use crate::extern_proto::{broadcast_sender, compute_request_hash, ExternDataMsg};

/// The address of the API_CALL precompile: 0x00000000000000000000000000000000000000AA
pub const API_CALL_ADDRESS: Address = {
    let mut addr = [0u8; 20];
    addr[19] = 0xAA;
    Address::new(addr)
};

/// Fixed gas cost for API_CALL precompile.
const API_CALL_GAS: u64 = 3_000;

/// Maximum request body size in bytes.
const MAX_BODY_SIZE: usize = 4096;

/// Maximum response body size in bytes.
const MAX_RESPONSE_SIZE: usize = 32_768;

/// HTTP timeout in milliseconds.
const HTTP_TIMEOUT_MS: u64 = 5000;

// ---------------------------------------------------------------------------
// ABI struct definition — matches the Solidity struct exactly.
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
// Configurable validator address
// ---------------------------------------------------------------------------

/// Get this node's validator address.
/// Reads from EXTERNEVM_VALIDATOR_ADDRESS env var, falls back to dev account 1.
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
        // Default: first Hardhat/Anvil dev account
        // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
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

// ---------------------------------------------------------------------------
// One-time initialization
// ---------------------------------------------------------------------------

/// Ensures this node is registered as a validator in the protocol store.
/// Called once on first precompile invocation.
fn ensure_validator_registered() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let addr = node_validator_address();
        let store = global_store();
        store.register_validator(addr);
        eprintln!(
            "[ExternEVM v2] Registered self as validator: {:?}",
            addr
        );
    });
}

// ---------------------------------------------------------------------------
// URL safety validation
// ---------------------------------------------------------------------------

fn is_private_url(url: &str) -> bool {
    let lower = url.to_lowercase();

    let host_part = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);

    let host = host_part
        .split('/')
        .next()
        .unwrap_or(host_part)
        .split(':')
        .next()
        .unwrap_or(host_part);

    matches!(
        host,
        "localhost" | "127.0.0.1" | "0.0.0.0" | "::1" | "[::1]"
    ) || host.starts_with("10.")
        || host.starts_with("192.168.")
        || (host.starts_with("172.")
            && host
                .split('.')
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .is_some_and(|n| (16..=31).contains(&n)))
}

// ---------------------------------------------------------------------------
// HTTP call (blocking inside tokio)
// ---------------------------------------------------------------------------

fn perform_http_call(request: &ApiRequest) -> Result<JsonValue, String> {
    eprintln!("[ExternEVM v2] HTTP response received, parsing...");

    let result = tokio::task::block_in_place(|| {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(HTTP_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let mut req_builder = match request.method.as_str() {
            "GET" => client.get(&request.url),
            "POST" => client.post(&request.url),
            other => return Err(format!("unsupported method: {other}")),
        };

        req_builder = req_builder.header("User-Agent", "ExternEVM/0.6.0");

        // Parse custom headers if provided
        if !request.headers.is_empty() {
            match serde_json::from_slice::<serde_json::Value>(&request.headers) {
                Ok(JsonValue::Object(map)) => {
                    for (key, val) in map {
                        if let Some(v) = val.as_str() {
                            req_builder = req_builder.header(&key, v);
                        }
                    }
                }
                Ok(_) => {
                    return Err("headers must be a JSON object".to_string());
                }
                Err(e) => {
                    return Err(format!("failed to parse headers JSON: {e}"));
                }
            }
        }

        if request.method == "POST" && !request.body.is_empty() {
            req_builder = req_builder.body(request.body.to_vec());
        }

        let response = req_builder
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }

        let body_bytes = response
            .bytes()
            .map_err(|e| format!("failed to read response body: {e}"))?;

        if body_bytes.len() > MAX_RESPONSE_SIZE {
            return Err(format!(
                "response size {} exceeds max {}",
                body_bytes.len(),
                MAX_RESPONSE_SIZE
            ));
        }

        let json: JsonValue = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("failed to parse response JSON: {e}"))?;

        Ok(json)
    });

    result
}

// ---------------------------------------------------------------------------
// JSON path extraction
// ---------------------------------------------------------------------------

fn extract_json_path<'a>(json: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    if path.is_empty() {
        return Some(json);
    }

    let mut current = json;

    for segment in path.split('.') {
        // Check for array indexing: "field[0]"
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
// JSON value → ABI-encoded bytes (direct, used as fallback)
// ---------------------------------------------------------------------------

fn encode_json_value(value: &JsonValue, response_type: u8) -> Result<Vec<u8>, String> {
    match response_type {
        // raw bytes
        0 => {
            let raw: Bytes = value.to_string().into_bytes().into();
            Ok((raw,).abi_encode_params())
        }
        // uint256
        1 => {
            let num = match value {
                JsonValue::Number(n) => {
                    if let Some(u) = n.as_u64() {
                        U256::from(u)
                    } else if let Some(f) = n.as_f64() {
                        U256::from(f as u64)
                    } else {
                        return Err("cannot convert number to uint256".into());
                    }
                }
                JsonValue::String(s) => {
                    let cleaned = s.replace(',', "");
                    if let Ok(u) = cleaned.parse::<u64>() {
                        U256::from(u)
                    } else if let Ok(f) = cleaned.parse::<f64>() {
                        U256::from(f as u64)
                    } else {
                        return Err(format!("cannot parse '{s}' as uint256"));
                    }
                }
                JsonValue::Bool(b) => U256::from(if *b { 1u64 } else { 0u64 }),
                _ => return Err("cannot convert to uint256".into()),
            };
            Ok((num,).abi_encode_params())
        }
        // string
        2 => {
            let s = match value {
                JsonValue::String(s) => s.clone(),
                other => other.to_string(),
            };
            Ok((s,).abi_encode_params())
        }
        // bool
        3 => {
            let b = match value {
                JsonValue::Bool(b) => *b,
                JsonValue::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
                JsonValue::String(s) => {
                    matches!(s.to_lowercase().as_str(), "true" | "1" | "yes")
                }
                JsonValue::Null => false,
                _ => false,
            };
            Ok((b,).abi_encode_params())
        }
        _ => Err(format!("invalid responseType: {response_type}")),
    }
}

// ---------------------------------------------------------------------------
// v2 aggregation: collect submissions and compute median/majority
// ---------------------------------------------------------------------------

/// Given a request ID and response type, collect all validator submissions
/// from the protocol store and compute the aggregated result.
///
/// For response_type 1 (uint256): computes median
/// For response_type 2 (string): computes majority vote
/// For response_type 3 (bool): computes majority vote
/// For response_type 0 (bytes): computes majority vote on raw strings
///
/// Returns the ABI-encoded aggregated result.
fn aggregate_submissions(
    request_id: &alloy_primitives::B256,
    response_type: u8,
) -> Result<Vec<u8>, String> {
    let store = global_store();
    let submissions = store.get_submissions(request_id);

    if submissions.is_empty() {
        return Err("No submissions found for request".to_string());
    }

    let num_submissions = submissions.len();

    match response_type {
        // uint256 — median
        1 => {
            let mut values: Vec<U256> = Vec::new();
            for sub in &submissions {
                let value_str = String::from_utf8(sub.value.clone())
                    .map_err(|_| "invalid UTF-8 in submission value")?;
                let cleaned = value_str.trim().replace(',', "");
                let num = cleaned
                    .parse::<f64>()
                    .map_err(|_| format!("cannot parse submission as number: {value_str}"))?;
                if num < 0.0 {
                    return Err(format!("negative value in submission: {num}"));
                }
                values.push(U256::from(num as u64));
            }

            let median = compute_median_uint256(&mut values)
                .ok_or("empty values for median")?;

            eprintln!(
                "[ExternEVM v2] Aggregation: {} submissions, values={:?}, median={}",
                num_submissions, values, median
            );

            Ok((median,).abi_encode_params())
        }

        // string — majority vote
        2 => {
            let values: Vec<String> = submissions
                .iter()
                .filter_map(|s| String::from_utf8(s.value.clone()).ok())
                .collect();

            match compute_majority_string(&values) {
                Some(result) => {
                    eprintln!(
                        "[ExternEVM v2] Aggregation: {} submissions, majority string={}",
                        num_submissions, result
                    );
                    Ok((result,).abi_encode_params())
                }
                None => {
                    eprintln!(
                        "[ExternEVM v2] No majority for string, using first submission"
                    );
                    let fallback = values.into_iter().next()
                        .ok_or("no string values")?;
                    Ok((fallback,).abi_encode_params())
                }
            }
        }

        // bool — majority vote
        3 => {
            let values: Vec<bool> = submissions
                .iter()
                .filter_map(|s| {
                    String::from_utf8(s.value.clone()).ok().map(|s| {
                        matches!(s.trim().to_lowercase().as_str(), "true" | "1" | "yes")
                    })
                })
                .collect();

            match compute_majority_bool(&values) {
                Some(result) => {
                    eprintln!(
                        "[ExternEVM v2] Aggregation: {} submissions, majority bool={}",
                        num_submissions, result
                    );
                    Ok((result,).abi_encode_params())
                }
                None => {
                    let fallback = values.into_iter().next().unwrap_or(false);
                    Ok((fallback,).abi_encode_params())
                }
            }
        }

        // raw bytes — majority vote on string representation
        0 => {
            let values: Vec<String> = submissions
                .iter()
                .filter_map(|s| String::from_utf8(s.value.clone()).ok())
                .collect();

            let result = compute_majority_string(&values)
                .or_else(|| values.into_iter().next())
                .ok_or("no raw byte values")?;

            let raw_bytes: Bytes = result.into_bytes().into();
            Ok((raw_bytes,).abi_encode_params())
        }

        _ => Err(format!("invalid responseType for aggregation: {response_type}")),
    }
}

// ---------------------------------------------------------------------------
// Precompile entry point
// ---------------------------------------------------------------------------

fn api_call_id() -> PrecompileId {
    PrecompileId::Custom("API_CALL".into())
}

fn api_call_precompile(input: PrecompileInput<'_>) -> PrecompileResult {
    let gas_used = API_CALL_GAS;

    if input.gas < gas_used {
        return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
    }

    // Ensure this node is registered as a validator
    ensure_validator_registered();

    // --- Backward compat: empty input → uint256(1234) ---
    if input.data.is_empty() {
        let output = (U256::from(1234u64),).abi_encode_params();
        return Ok(PrecompileOutput::new(gas_used, output.into(), input.reservoir));
    }

    // --- Decode ABI input ---
    let request = match ApiRequest::abi_decode(input.data) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("[ExternEVM v2] ABI decode error: {e}");
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("API_CALL: failed to decode ApiRequest".into()),
                input.reservoir,
            ));
        }
    };

    eprintln!(
        "[ExternEVM v2] API_CALL decoded:\n  url:          {}\n  method:       {}\n  headers:      {} bytes\n  body:         {} bytes\n  responsePath: {}\n  responseType: {}",
        request.url, request.method, request.headers.len(), request.body.len(),
        request.responsePath, request.responseType
    );

    // --- Validation ---
    if request.url.is_empty() {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::Other("API_CALL: url is empty".into()),
            input.reservoir,
        ));
    }

    if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::Other("API_CALL: url must start with http:// or https://".into()),
            input.reservoir,
        ));
    }

    if is_private_url(&request.url) {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::Other("API_CALL: private/loopback URLs are blocked".into()),
            input.reservoir,
        ));
    }

    if request.method != "GET" && request.method != "POST" {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::Other("API_CALL: method must be GET or POST".into()),
            input.reservoir,
        ));
    }

    if request.body.len() > MAX_BODY_SIZE {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::Other("API_CALL: body exceeds max size".into()),
            input.reservoir,
        ));
    }

    if request.responseType > 3 {
        return Ok(PrecompileOutput::halt(
            PrecompileHalt::Other("API_CALL: responseType must be 0-3".into()),
            input.reservoir,
        ));
    }

    // --- Perform HTTP call ---
    let json = match perform_http_call(&request) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[ExternEVM v2] HTTP error: {e}");
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::Other(format!("API_CALL: HTTP error: {e}").into()),
                input.reservoir,
            ));
        }
    };

    // --- Extract value at JSON path ---
    let extracted = match extract_json_path(&json, &request.responsePath) {
        Some(v) => v.clone(),
        None => {
            eprintln!(
                "[ExternEVM v2] JSON path '{}' not found in response",
                request.responsePath
            );
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("API_CALL: JSON path not found".into()),
                input.reservoir,
            ));
        }
    };

    eprintln!(
        "[ExternEVM v2] Extracted value at '{}': {}",
        request.responsePath, extracted
    );

    // --- v2: Store value in protocol store and aggregate ---
    let store = global_store();

    // Use a deterministic request hash for cross-node correlation.
    // Every node calling the same API with same params gets the same hash.
    let request_hash = compute_request_hash(
        &request.url,
        &request.method,
        &request.responsePath,
        request.responseType,
    );

    // Create a pending request in the store
    store.create_request(
        request_hash,
        0, // block_created placeholder
        request.url.clone(),
        request.method.clone(),
        request.headers.to_vec(),
        request.body.to_vec(),
        request.responsePath.clone(),
        request.responseType,
    );

    // Store this node's fetched value as raw string bytes
    let value_str = match &extracted {
        JsonValue::String(s) => s.clone(),
        other => other.to_string(),
    };

    let validator_addr = node_validator_address();

    if let Err(e) = store.submit_value(
        request_hash,
        validator_addr,
        value_str.as_bytes().to_vec(),
        0, // block_submitted placeholder
    ) {
        eprintln!("[ExternEVM v2] Failed to store submission: {e}");
    }

    // --- Broadcast to peers via extern/1 subprotocol ---
    let raw_value_bytes = value_str.as_bytes().to_vec();

    let broadcast_msg = ExternDataMsg {
        request_hash,
        value: raw_value_bytes,
        response_type: request.responseType,
        validator: validator_addr,
    };

    let tx = broadcast_sender();
    match tx.send(broadcast_msg) {
        Ok(receivers) => {
            eprintln!(
                "[ExternEVM v2] Broadcast value to {} peer connections",
                receivers
            );
        }
        Err(_) => {
            eprintln!("[ExternEVM v2] No peers connected, broadcast skipped");
        }
    }

    // --- Wait briefly for peer values ---
    let peer_wait_ms: u64 = std::env::var("EXTERNEVM_PEER_WAIT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if tx.receiver_count() > 0 {
        eprintln!(
            "[ExternEVM v2] Waiting {}ms for peer values...",
            peer_wait_ms
        );
        std::thread::sleep(Duration::from_millis(peer_wait_ms));
    }

    // --- Aggregate: compute median/majority from all submissions ---
    match aggregate_submissions(&request_hash, request.responseType) {
        Ok(encoded) => {
            eprintln!(
                "[ExternEVM v2] Returning aggregated response ({} bytes, responseType={})",
                encoded.len(),
                request.responseType
            );
            Ok(PrecompileOutput::new(gas_used, encoded.into(), input.reservoir))
        }
        Err(e) => {
            eprintln!(
                "[ExternEVM v2] Aggregation failed ({}), falling back to direct encode",
                e
            );
            // Fallback: encode directly from the extracted value (v1 behavior)
            match encode_json_value(&extracted, request.responseType) {
                Ok(encoded) => {
                    Ok(PrecompileOutput::new(gas_used, encoded.into(), input.reservoir))
                }
                Err(e2) => {
                    Ok(PrecompileOutput::halt(
                        PrecompileHalt::Other(format!("API_CALL: encode error: {e2}").into()),
                        input.reservoir,
                    ))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Precompile registration
// ---------------------------------------------------------------------------

fn api_call_dyn_precompile() -> DynPrecompile {
    DynPrecompile::new_stateful(api_call_id(), api_call_precompile)
}

pub fn inject_api_call_precompile(precompiles: &mut PrecompilesMap) {
    precompiles.apply_precompile(&API_CALL_ADDRESS, |_| Some(api_call_dyn_precompile()));
}

// ---------------------------------------------------------------------------
// ExternEvmFactory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ExternEvmFactory {
    inner: alloy_evm::EthEvmFactory,
}

impl ExternEvmFactory {
    pub fn new() -> Self {
        Self {
            inner: alloy_evm::EthEvmFactory::default(),
        }
    }
}

impl EvmFactory for ExternEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> =
        <alloy_evm::EthEvmFactory as EvmFactory>::Evm<DB, I>;

    type Context<DB: Database> =
        <alloy_evm::EthEvmFactory as EvmFactory>::Context<DB>;

    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError, HaltReason>;
    type HaltReason = HaltReason;
    type Spec = SpecId;

    fn create_evm<DB: Database, I: Inspector<EthEvmContext<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Tx, Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut evm = self.inner.create_evm(db, input, inspector);
        inject_api_call_precompile(evm.precompiles_mut());
        evm
    }

    fn create_evm_with_inspector<DB, I>(
        &self,
        db: DB,
        input: EvmEnv<Self::Tx, Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I>
    where
        DB: Database,
        I: Inspector<EthEvmContext<DB>>,
    {
        let mut evm = self.inner.create_evm_with_inspector(db, input, inspector);
        inject_api_call_precompile(evm.precompiles_mut());
        evm
    }
}