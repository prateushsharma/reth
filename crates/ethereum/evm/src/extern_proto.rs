//! ExternEVM custom devp2p subprotocol — shared types and broadcast channels.
//!
//! v3 added ExternCommitMsg and ExternRevealMsg alongside ExternDataMsg.
//! v4 extends ExternRevealMsg with a TLS certificate attestation: the
//! designated fetcher signs a digest binding the revealed value to a genuine
//! TLS session with a certificate-validated domain. The shared
//! `compute_attestation_digest` helper guarantees signer and verifier hash
//! identical bytes.

use alloy_primitives::{Address, B256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use tokio::sync::broadcast;

const BROADCAST_CHANNEL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Wire message type discriminants
// ---------------------------------------------------------------------------

pub const MSG_TYPE_DATA:   u8 = 0x00; // v2 compat
pub const MSG_TYPE_COMMIT: u8 = 0x01; // v3
pub const MSG_TYPE_REVEAL: u8 = 0x02; // v3 + v4 (reveal now carries attestation)

// ---------------------------------------------------------------------------
// Message structs
// ---------------------------------------------------------------------------

/// v2 compat: open value broadcast (kept for single-node fallback path)
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ExternDataMsg {
    pub request_hash: B256,
    pub value: Vec<u8>,
    pub response_type: u8,
    pub validator: Address,
}

/// v3 phase 1: commitment broadcast — hides the actual fetched value
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ExternCommitMsg {
    pub request_hash: B256,
    pub commitment: B256,
    pub validator: Address,
}

/// v3 phase 2 + v4 attestation: reveal broadcast.
///
/// v3 fields expose value + salt for commit-reveal verification.
/// v4 fields carry the TLS certificate attestation:
///   - `cert_der`        : server leaf certificate, DER-encoded
///   - `response_hash`   : keccak256 of the raw response body bytes
///   - `timestamp_secs`  : unix seconds when the fetch occurred
///   - `attestation_sig` : 65-byte secp256k1 recoverable signature over
///                         `compute_attestation_digest(...)`
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ExternRevealMsg {
    pub request_hash: B256,
    pub value: Vec<u8>,
    pub salt: B256, // 32-byte random salt, B256 implements RLP
    pub validator: Address,
    // v4 additions:
    pub cert_der: Vec<u8>,
    pub response_hash: B256,
    pub timestamp_secs: u64,
    pub attestation_sig: Vec<u8>, // 65 bytes, secp256k1 recoverable
}

// ---------------------------------------------------------------------------
// Broadcast channels — one per message type
// ---------------------------------------------------------------------------

static DATA_TX: std::sync::LazyLock<broadcast::Sender<ExternDataMsg>> =
    std::sync::LazyLock::new(|| broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0);

static COMMIT_TX: std::sync::LazyLock<broadcast::Sender<ExternCommitMsg>> =
    std::sync::LazyLock::new(|| broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0);

static REVEAL_TX: std::sync::LazyLock<broadcast::Sender<ExternRevealMsg>> =
    std::sync::LazyLock::new(|| broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0);

pub fn broadcast_sender() -> broadcast::Sender<ExternDataMsg> {
    DATA_TX.clone()
}
pub fn broadcast_subscribe() -> broadcast::Receiver<ExternDataMsg> {
    DATA_TX.subscribe()
}

pub fn commit_sender() -> broadcast::Sender<ExternCommitMsg> {
    COMMIT_TX.clone()
}
pub fn commit_subscribe() -> broadcast::Receiver<ExternCommitMsg> {
    COMMIT_TX.subscribe()
}

pub fn reveal_sender() -> broadcast::Sender<ExternRevealMsg> {
    REVEAL_TX.clone()
}
pub fn reveal_subscribe() -> broadcast::Receiver<ExternRevealMsg> {
    REVEAL_TX.subscribe()
}

// ---------------------------------------------------------------------------
// Request hash helper (unchanged from v2)
// ---------------------------------------------------------------------------

pub fn compute_request_hash(
    url: &str,
    method: &str,
    response_path: &str,
    response_type: u8,
) -> B256 {
    use alloy_primitives::keccak256;
    let mut data = Vec::new();
    data.extend_from_slice(url.as_bytes());
    data.push(0xFF);
    data.extend_from_slice(method.as_bytes());
    data.push(0xFF);
    data.extend_from_slice(response_path.as_bytes());
    data.push(0xFF);
    data.push(response_type);
    keccak256(&data)
}

// ---------------------------------------------------------------------------
// Attestation digest helper (v4)
// ---------------------------------------------------------------------------

/// Compute the digest the designated fetcher signs to attest a TLS session.
///
/// digest = keccak256(
///     request_hash      ‖ 0xFF ‖
///     domain            ‖ 0xFF ‖
///     keccak256(cert_der) ‖ 0xFF ‖   // cert fingerprint
///     response_hash     ‖ 0xFF ‖
///     timestamp_secs (big-endian u64)
/// )
///
/// Both signer (externevm.rs) and verifier (extern_p2p.rs) MUST call this so
/// the bytes hashed are byte-for-byte identical. The cert fingerprint is
/// derived from the DER inside this function — callers pass the raw DER, never
/// a pre-hashed fingerprint, removing any chance of the two sides disagreeing
/// on how the fingerprint is formed.
pub fn compute_attestation_digest(
    request_hash: B256,
    domain: &str,
    cert_der: &[u8],
    response_hash: B256,
    timestamp_secs: u64,
) -> B256 {
    use alloy_primitives::keccak256;
    let cert_fingerprint = keccak256(cert_der);
    let mut data = Vec::new();
    data.extend_from_slice(request_hash.as_slice());
    data.push(0xFF);
    data.extend_from_slice(domain.as_bytes());
    data.push(0xFF);
    data.extend_from_slice(cert_fingerprint.as_slice());
    data.push(0xFF);
    data.extend_from_slice(response_hash.as_slice());
    data.push(0xFF);
    data.extend_from_slice(&timestamp_secs.to_be_bytes());
    keccak256(&data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_extern_data_msg_rlp_roundtrip() {
        let msg = ExternDataMsg {
            request_hash: B256::from([0xABu8; 32]),
            value: vec![0x00, 0x01, 0x02, 0x03],
            response_type: 1,
            validator: Address::from([0xCCu8; 20]),
        };
        let mut buf = alloy_rlp::BytesMut::new();
        msg.encode(&mut buf);
        let decoded = ExternDataMsg::decode(&mut buf.as_ref()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_extern_commit_msg_rlp_roundtrip() {
        let msg = ExternCommitMsg {
            request_hash: B256::from([0xAAu8; 32]),
            commitment: B256::from([0xBBu8; 32]),
            validator: Address::from([0x01u8; 20]),
        };
        let mut buf = alloy_rlp::BytesMut::new();
        msg.encode(&mut buf);
        let decoded = ExternCommitMsg::decode(&mut buf.as_ref()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_extern_reveal_msg_rlp_roundtrip() {
        let msg = ExternRevealMsg {
            request_hash: B256::from([0xCCu8; 32]),
            value: vec![0u8; 32],
            salt: B256::from([0xDDu8; 32]),
            validator: Address::from([0x02u8; 20]),
            cert_der: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
            response_hash: B256::from([0xEEu8; 32]),
            timestamp_secs: 1_700_000_000,
            attestation_sig: vec![0x7Au8; 65],
        };
        let mut buf = alloy_rlp::BytesMut::new();
        msg.encode(&mut buf);
        let decoded = ExternRevealMsg::decode(&mut buf.as_ref()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_compute_request_hash_deterministic() {
        let h1 = compute_request_hash("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd", "GET", "bitcoin.usd", 1);
        let h2 = compute_request_hash("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd", "GET", "bitcoin.usd", 1);
        assert_eq!(h1, h2);
        let h3 = compute_request_hash("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd", "GET", "ethereum.usd", 1);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_compute_attestation_digest_deterministic() {
        let rh = B256::from([0x01u8; 32]);
        let resp = B256::from([0x02u8; 32]);
        let cert = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let ts = 1_700_000_000u64;

        // same inputs → same digest
        let d1 = compute_attestation_digest(rh, "api.coingecko.com", &cert, resp, ts);
        let d2 = compute_attestation_digest(rh, "api.coingecko.com", &cert, resp, ts);
        assert_eq!(d1, d2);

        // changing any single input changes the digest
        assert_ne!(d1, compute_attestation_digest(B256::from([0xFFu8; 32]), "api.coingecko.com", &cert, resp, ts));
        assert_ne!(d1, compute_attestation_digest(rh, "api.evil.com", &cert, resp, ts));
        assert_ne!(d1, compute_attestation_digest(rh, "api.coingecko.com", &[0x00u8], resp, ts));
        assert_ne!(d1, compute_attestation_digest(rh, "api.coingecko.com", &cert, B256::from([0x99u8; 32]), ts));
        assert_ne!(d1, compute_attestation_digest(rh, "api.coingecko.com", &cert, resp, ts + 1));
    }

    #[test]
    fn test_broadcast_channel_works() {
        let tx = broadcast_sender();
        let mut rx = broadcast_subscribe();
        let msg = ExternDataMsg {
            request_hash: B256::from([0x11u8; 32]),
            value: vec![1, 2, 3],
            response_type: 1,
            validator: Address::from([0x22u8; 20]),
        };
        tx.send(msg.clone()).unwrap();
        assert_eq!(rx.try_recv().unwrap(), msg);
    }
}