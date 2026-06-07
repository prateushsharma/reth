//! ExternEVM custom EvmFactory — v4
//!
//! Designated fetcher rotation + commit-reveal binding (v3) +
//! TLS certificate attestation (v4).
//!
//! The designated fetcher now signs an attestation binding the revealed value
//! to a genuine TLS session with a certificate-validated domain:
//!   digest = keccak256(requestHash ‖ domain ‖ certFingerprint ‖ responseHash ‖ timestamp)
//! signed with the validator's secp256k1 key (EXTERNEVM_VALIDATOR_PRIVKEY).
//!
//! Single-node mode: commit-reveal AND attestation skipped, behavior identical to v1.

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
    compute_request_hash, compute_attestation_digest,
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
const GAS_VERIFY:    u64 =  1_500; // non-fetcher path — verify commit+reveal+attestation (v4: was 1_000)
const GAS_FETCH:     u64 = 12_000; // fetcher path — HTTP + cert capture + commit + sign + reveal (v4: was 10_000)

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

/// v4: load this node's secp256k1 signing key from EXTERNEVM_VALIDATOR_PRIVKEY.
/// Returns None if unset/invalid — the fetcher path then halts with a clear error.
fn node_validator_signing_key() -> Option<secp256k1::SecretKey> {
    use std::sync::LazyLock;
    static KEY: LazyLock<Option<secp256k1::SecretKey>> = LazyLock::new(|| {
        let raw = std::env::var("EXTERNEVM_VALIDATOR_PRIVKEY").ok()?;
        let hex_str = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
        if hex_str.len() != 64 {
            eprintln!("[ExternEVM v4] EXTERNEVM_VALIDATOR_PRIVKEY must be 32-byte hex");
            return None;
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            match u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                Ok(b) => bytes[i] = b,
                Err(_) => {
                    eprintln!("[ExternEVM v4] EXTERNEVM_VALIDATOR_PRIVKEY is not valid hex");
                    return None;
                }
            }
        }
        match secp256k1::SecretKey::from_slice(&bytes) {
            Ok(sk) => Some(sk),
            Err(e) => {
                eprintln!("[ExternEVM v4] invalid secp256k1 secret key: {e}");
                None
            }
        }
    });
    (*KEY).clone()
}

/// v4: derive the Ethereum-style address from a secp256k1 secret key.
fn address_from_secret_key(sk: &secp256k1::SecretKey) -> Address {
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, sk);
    let uncompressed = pk.serialize_uncompressed(); // 65 bytes, leading 0x04
    let hash = keccak256(&uncompressed[1..]);       // hash the 64-byte body
    Address::from_slice(&hash[12..])
}

fn ensure_validator_registered() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let addr = node_validator_address();
        global_store().register_validator(addr);
        eprintln!("[ExternEVM v4] Registered self as validator: {:?}", addr);

        // v4: sanity-check that the signing key (if present) matches the identity.
        if let Some(sk) = node_validator_signing_key() {
            let derived = address_from_secret_key(&sk);
            if derived != addr {
                eprintln!(
                    "[ExternEVM v4] WARNING: EXTERNEVM_VALIDATOR_PRIVKEY derives {:?} but \
                     EXTERNEVM_VALIDATOR_ADDRESS is {:?} — attestations will be rejected by peers",
                    derived, addr
                );
            }
        }
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

/// v4: extract the host (domain) from a URL. Both signer and verifier call this
/// on the same request URL, so consistency — not canonicalization — is what matters.
fn extract_host(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .split(':')
        .next()
        .unwrap_or(after_scheme)
        .to_string()
}

// ---------------------------------------------------------------------------
// HTTP call (v4: captures raw body bytes + server leaf certificate)
// ---------------------------------------------------------------------------

struct HttpResult {
    json: JsonValue,
    body_bytes: Vec<u8>,
    cert_der: Option<Vec<u8>>,
}

fn perform_http_call(request: &ApiRequest) -> Result<HttpResult, String> {
    tokio::task::block_in_place(|| {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(HTTP_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none())
            .tls_info(true) // v4: surface the peer certificate on the response
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let mut req_builder = match request.method.as_str() {
            "GET"  => client.get(&request.url),
            "POST" => client.post(&request.url),
            other  => return Err(format!("unsupported method: {other}")),
        };

        req_builder = req_builder.header("User-Agent", "ExternEVM/0.8.0");

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

        // v4: capture the leaf cert DER BEFORE consuming the response with .bytes().
        let cert_der = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|info| info.peer_certificate())
            .map(|der| der.to_vec());

        let body_bytes = response.bytes().map_err(|e| format!("failed to read response body: {e}"))?;

        if body_bytes.len() > MAX_RESPONSE_SIZE {
            return Err(format!("response size {} exceeds max {}", body_bytes.len(), MAX_RESPONSE_SIZE));
        }

        let json = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("failed to parse response JSON: {e}"))?;

        Ok(HttpResult { json, body_bytes: body_bytes.to_vec(), cert_der })
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
// Attestation signing (v4)
// ---------------------------------------------------------------------------

/// Sign a 32-byte attestation digest, producing a 65-byte recoverable signature:
/// r(32) ‖ s(32) ‖ v(1), where v is the raw recovery id (0 or 1). The verifier
/// recovers the signer address with the same convention.
fn sign_attestation(digest: B256, sk: &secp256k1::SecretKey) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::signing_only();
    let msg = secp256k1::Message::from_digest(digest.0);
    let recoverable = secp.sign_ecdsa_recoverable(&msg, sk);
    let (recovery_id, compact) = recoverable.serialize_compact();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&compact);        // r ‖ s
    out.push(i32::from(recovery_id) as u8);   // v (0 or 1)
    out
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
            eprintln!("[ExternEVM v4] ABI decode error: {e}");
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("API_CALL: failed to decode ApiRequest".into()),
                input.reservoir,
            ));
        }
    };

    eprintln!(
        "[ExternEVM v4] API_CALL: url={} method={} path={} type={}",
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
        eprintln!("[ExternEVM v4] cache hit for request {:?}", request_hash);
        return Ok(PrecompileOutput::new(GAS_CACHE_HIT, cached.into(), input.reservoir));
    }

    let validators = store.get_validators();
    let my_addr = node_validator_address();

    // 2. Single-node fast path — skip commit-reveal AND attestation entirely
    if validators.len() <= 1 {
        if input.gas < API_CALL_GAS {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }
        let http = match perform_http_call(&request) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[ExternEVM v4] HTTP error (single-node): {e}");
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(format!("API_CALL: HTTP error: {e}").into()),
                    input.reservoir,
                ));
            }
        };
        let extracted = match extract_json_path(&http.json, &request.responsePath) {
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
                eprintln!("[ExternEVM v4] single-node: returning {} bytes", encoded.len());
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
        "[ExternEVM v4] request {:?} → designated fetcher: {:?} (I am: {:?})",
        request_hash, designated, my_addr
    );

    if my_addr == designated {
        // ----------------------------------------------------------------
        // FETCHER PATH: fetch → attest → commit → wait → reveal → return
        // ----------------------------------------------------------------
        if input.gas < GAS_FETCH {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }

        // Fetch (captures raw bytes + cert)
        let http = match perform_http_call(&request) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[ExternEVM v4] HTTP error (fetcher): {e}");
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(format!("API_CALL: HTTP error: {e}").into()),
                    input.reservoir,
                ));
            }
        };
        let extracted = match extract_json_path(&http.json, &request.responsePath) {
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

        // v4: build the TLS attestation
        let cert_der = match http.cert_der {
            Some(c) if !c.is_empty() => c,
            _ => {
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(
                        "API_CALL: v4 attestation requires HTTPS (no TLS certificate captured)".into(),
                    ),
                    input.reservoir,
                ));
            }
        };
        let sk = match node_validator_signing_key() {
            Some(k) => k,
            None => {
                return Ok(PrecompileOutput::halt(
                    PrecompileHalt::Other(
                        "API_CALL: EXTERNEVM_VALIDATOR_PRIVKEY not set (required to sign v4 attestation)".into(),
                    ),
                    input.reservoir,
                ));
            }
        };
        let domain = extract_host(&request.url);
        let response_hash = keccak256(&http.body_bytes);
        let timestamp_secs = unix_secs();
        let attestation_digest =
            compute_attestation_digest(request_hash, &domain, &cert_der, response_hash, timestamp_secs);
        let attestation_sig = sign_attestation(attestation_digest, &sk);

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
        eprintln!("[ExternEVM v4] committed for request {:?}", request_hash);

        // Wait for commit window so non-fetchers can receive our commit
        std::thread::sleep(Duration::from_millis(commit_window_ms()));

        // Broadcast reveal (now carrying the TLS attestation)
        let _ = reveal_sender().send(ExternRevealMsg {
            request_hash,
            value: encoded.clone(),
            salt: B256::from(salt),
            validator: my_addr,
            cert_der,
            response_hash,
            timestamp_secs,
            attestation_sig,
        });
        eprintln!("[ExternEVM v4] revealed (with attestation) for request {:?}", request_hash);

        store.populate_cache(request_hash, block_number, encoded.clone());
        eprintln!("[ExternEVM v4] fetcher: returning {} bytes", encoded.len());
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
                    "[ExternEVM v4] non-fetcher: verified reveal from {:?}, returning {} bytes",
                    designated,
                    value.len()
                );
                store.populate_cache(request_hash, block_number, value.clone());
                return Ok(PrecompileOutput::new(GAS_VERIFY, value.into(), input.reservoir));
            }

            if Instant::now() > deadline {
                eprintln!(
                    "[ExternEVM v4] timeout waiting for reveal from designated fetcher {:?}",
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
// Unix time helpers
// ---------------------------------------------------------------------------

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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