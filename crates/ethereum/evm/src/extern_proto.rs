//! ExternEVM custom devp2p subprotocol — shared types and broadcast channels.
//!
//! v3 adds ExternCommitMsg and ExternRevealMsg alongside the existing
//! ExternDataMsg. Each has its own broadcast channel so extern_p2p.rs
//! can fan-out all three message types to peers independently.

use alloy_primitives::{Address, B256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use tokio::sync::broadcast;

const BROADCAST_CHANNEL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Wire message type discriminants
// ---------------------------------------------------------------------------

pub const MSG_TYPE_DATA:   u8 = 0x00; // v2 compat
pub const MSG_TYPE_COMMIT: u8 = 0x01; // v3
pub const MSG_TYPE_REVEAL: u8 = 0x02; // v3

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

/// v3 phase 2: reveal broadcast — exposes value + salt for verification
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ExternRevealMsg {
    pub request_hash: B256,
    pub value: Vec<u8>,
    pub salt: B256, // 32-byte random salt, B256 implements RLP
    pub validator: Address,
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