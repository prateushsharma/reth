//! ExternEVM custom devp2p subprotocol — shared types and broadcast channel.
//!
//! Message types and the broadcast channel live here (in the EVM crate)
//! so that the precompile can send values.
//!
//! The ProtocolHandler / ConnectionHandler implementations live in
//! bin/reth/src/extern_p2p.rs because they depend on reth-network,
//! which would create a circular dependency if imported here.

use alloy_primitives::{Address, B256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capacity of the broadcast channel used by the precompile to fan-out
/// fetched values to all per-peer connection streams.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Wire message — RLP encoded
// ---------------------------------------------------------------------------

/// A message broadcast between ExternEVM nodes carrying a fetched API value.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ExternDataMsg {
    /// Identifies which API request this value belongs to.
    pub request_hash: B256,
    /// The raw value bytes (UTF-8 string representation of extracted JSON).
    pub value: Vec<u8>,
    /// The response type (0=bytes, 1=uint256, 2=string, 3=bool).
    pub response_type: u8,
    /// The validator address that fetched this value.
    pub validator: Address,
}

// ---------------------------------------------------------------------------
// Global broadcast channel
// ---------------------------------------------------------------------------

static BROADCAST_TX: std::sync::LazyLock<broadcast::Sender<ExternDataMsg>> =
    std::sync::LazyLock::new(|| {
        let (tx, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        tx
    });

/// Get a clone of the global broadcast sender.
/// Called by the precompile after fetching a value.
pub fn broadcast_sender() -> broadcast::Sender<ExternDataMsg> {
    BROADCAST_TX.clone()
}

/// Subscribe to the global broadcast channel.
/// Called by each per-peer connection to receive values to forward.
pub fn broadcast_subscribe() -> broadcast::Receiver<ExternDataMsg> {
    BROADCAST_TX.subscribe()
}

// ---------------------------------------------------------------------------
// Helper: compute request hash
// ---------------------------------------------------------------------------

/// Compute a deterministic hash for an API request.
/// Every node calling the same API endpoint with the same parameters
/// produces the same hash.
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

    #[test]
    fn test_extern_data_msg_rlp_roundtrip() {
        use alloy_rlp::{Decodable, Encodable};

        let msg = ExternDataMsg {
            request_hash: B256::from([0xAB; 32]),
            value: vec![0x00, 0x01, 0x02, 0x03],
            response_type: 1,
            validator: Address::from([0xCC; 20]),
        };

        let mut buf = alloy_rlp::BytesMut::new();
        msg.encode(&mut buf);

        let mut slice = buf.as_ref();
        let decoded = ExternDataMsg::decode(&mut slice).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_compute_request_hash_deterministic() {
        let h1 = compute_request_hash(
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd",
            "GET",
            "bitcoin.usd",
            1,
        );
        let h2 = compute_request_hash(
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd",
            "GET",
            "bitcoin.usd",
            1,
        );
        assert_eq!(h1, h2);

        let h3 = compute_request_hash(
            "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
            "GET",
            "ethereum.usd",
            1,
        );
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_broadcast_channel_works() {
        let tx = broadcast_sender();
        let mut rx = broadcast_subscribe();

        let msg = ExternDataMsg {
            request_hash: B256::from([0x11; 32]),
            value: vec![1, 2, 3],
            response_type: 1,
            validator: Address::from([0x22; 20]),
        };

        tx.send(msg.clone()).unwrap();
        let received = rx.try_recv().unwrap();
        assert_eq!(msg, received);
    }
}