//! ExternEVM custom devp2p subprotocol — `extern/1`
//!
//! Broadcasts fetched API values between ExternEVM nodes so that
//! each node can compute a median across all validators.

use alloy_primitives::{Address, B256};
use alloy_rlp::{BytesMut, Decodable, Encodable, RlpDecodable, RlpEncodable};
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities,
    multiplex::ProtocolConnection,
    protocol::Protocol,
    Capability,
};
use reth_network::{
    protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler},
    Direction,
};
use reth_network_api::PeerId;
use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::broadcast;

use crate::protocol_store::global_store;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Protocol name registered during RLPx handshake.
/// Must be <= 8 ASCII characters.
const EXTERN_PROTO_NAME: &str = "extern";

/// Protocol version.
const EXTERN_PROTO_VERSION: u8 = 1;

/// Number of message IDs this protocol uses.
/// We use 1: ExternDataMsg (id = 0).
const EXTERN_PROTO_MSG_COUNT: u8 = 1;

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
    /// Computed as keccak256(url || method || responsePath || responseType).
    pub request_hash: B256,
    /// The raw value bytes (before ABI encoding).
    /// For uint256: big-endian 32 bytes.
    /// For string: UTF-8 bytes.
    /// For bool: single byte 0x00 or 0x01.
    /// For raw bytes: the raw bytes.
    pub value: Vec<u8>,
    /// The response type so the receiver knows how to interpret `value`.
    /// 0 = bytes, 1 = uint256, 2 = string, 3 = bool.
    pub response_type: u8,
    /// The validator address that fetched this value.
    pub validator: Address,
}

impl ExternDataMsg {
    /// Encode this message into RLP bytes prefixed with the message ID (0x00).
    pub fn encode_to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        // Message ID for our single message type
        buf.extend_from_slice(&[0x00]);
        self.encode(&mut buf);
        buf
    }

    /// Decode from bytes (assumes message ID byte already stripped by multiplexer).
    pub fn decode_from_bytes(data: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        Self::decode(data)
    }
}

// ---------------------------------------------------------------------------
// Global broadcast channel
// ---------------------------------------------------------------------------

/// A lazily initialized global broadcast sender.
/// The precompile sends `ExternDataMsg` through this channel.
/// Every per-peer `ExternEvmConnection` subscribes to it.
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
/// Called by each `ExternEvmConnection` to receive values to forward to its peer.
fn broadcast_subscribe() -> broadcast::Receiver<ExternDataMsg> {
    BROADCAST_TX.subscribe()
}

// ---------------------------------------------------------------------------
// ProtocolHandler — factory, one per node
// ---------------------------------------------------------------------------

/// The ExternEVM protocol handler. Registered with Reth's network stack.
/// Creates an `ExternEvmConnHandler` for every peer connection.
#[derive(Clone)]
pub struct ExternEvmProtoHandler {
    /// This node's validator address, so we can filter out our own broadcasts.
    pub local_validator: Address,
}

impl ExternEvmProtoHandler {
    /// Create a new protocol handler.
    pub fn new(local_validator: Address) -> Self {
        Self { local_validator }
    }
}

impl fmt::Debug for ExternEvmProtoHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternEvmProtoHandler")
            .field("local_validator", &self.local_validator)
            .finish()
    }
}

impl ProtocolHandler for ExternEvmProtoHandler {
    type ConnectionHandler = ExternEvmConnHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(ExternEvmConnHandler {
            local_validator: self.local_validator,
        })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(ExternEvmConnHandler {
            local_validator: self.local_validator,
        })
    }
}

// ---------------------------------------------------------------------------
// ConnectionHandler — per-peer negotiation
// ---------------------------------------------------------------------------

/// Handles protocol negotiation for a single peer connection.
pub struct ExternEvmConnHandler {
    local_validator: Address,
}

impl ConnectionHandler for ExternEvmConnHandler {
    type Connection = ExternEvmConnection;

    fn protocol(&self) -> Protocol {
        Protocol::new(
            Capability::new_static(EXTERN_PROTO_NAME, EXTERN_PROTO_VERSION),
            EXTERN_PROTO_MSG_COUNT,
        )
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        // If the remote doesn't support extern/1, keep the connection alive
        // (they can still sync blocks via eth/68).
        eprintln!("[ExternEVM p2p] Peer does not support extern/1, keeping connection");
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        eprintln!(
            "[ExternEVM p2p] Protocol negotiated with peer {:?} ({:?})",
            peer_id, direction
        );
        ExternEvmConnection::new(conn, self.local_validator, peer_id)
    }
}

// ---------------------------------------------------------------------------
// Connection — per-peer message stream
// ---------------------------------------------------------------------------

/// A bidirectional connection to a single peer for the `extern/1` protocol.
///
/// This is a `Stream<Item = BytesMut>`:
/// - Items yielded = messages to SEND to the peer (from our broadcast channel)
/// - Incoming messages from the peer arrive via `self.conn` and are processed
///   in `poll_next` (stored in the protocol store).
pub struct ExternEvmConnection {
    /// The bidirectional protocol connection to the peer.
    conn: ProtocolConnection,
    /// Receives broadcasts from our local precompile.
    broadcast_rx: broadcast::Receiver<ExternDataMsg>,
    /// This node's validator address (to skip re-broadcasting our own messages).
    local_validator: Address,
    /// The remote peer's ID (for logging).
    peer_id: PeerId,
    /// Outgoing message buffer.
    pending_out: VecDeque<BytesMut>,
}

impl ExternEvmConnection {
    fn new(conn: ProtocolConnection, local_validator: Address, peer_id: PeerId) -> Self {
        Self {
            conn,
            broadcast_rx: broadcast_subscribe(),
            local_validator,
            peer_id,
            pending_out: VecDeque::new(),
        }
    }

    /// Process an incoming message from the peer.
    fn handle_incoming(&self, mut data: BytesMut) {
        if data.is_empty() {
            return;
        }

        // First byte is the message ID (0x00 for ExternDataMsg).
        let msg_id = data[0];
        let payload = &data[1..];

        if msg_id != 0x00 {
            eprintln!(
                "[ExternEVM p2p] Unknown message ID {} from peer {:?}",
                msg_id, self.peer_id
            );
            return;
        }

        let mut slice = payload;
        match ExternDataMsg::decode_from_bytes(&mut slice) {
            Ok(msg) => {
                eprintln!(
                    "[ExternEVM p2p] Received value from validator {:?} for request {:?} (type={})",
                    msg.validator, msg.request_hash, msg.response_type
                );

                // Store the received value in the protocol store.
                let store = global_store();

                // The protocol store's submit_value expects:
                // (request_id, validator, value_bytes, block_number)
                // For the p2p layer, we use request_hash as request_id
                // and block 0 as a placeholder (the actual block doesn't matter
                // for cross-node value collection in v2).
                //
                // We also need to ensure the remote validator is registered.
                if !store.is_validator(&msg.validator) {
                    store.register_validator(msg.validator);
                    eprintln!(
                        "[ExternEVM p2p] Auto-registered remote validator {:?}",
                        msg.validator
                    );
                }

                match store.submit_value(msg.request_hash, msg.validator, msg.value.clone(), 0) {
                    Ok(()) => {
                        eprintln!(
                            "[ExternEVM p2p] Stored peer value for request {:?}",
                            msg.request_hash
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[ExternEVM p2p] Failed to store peer value: {}",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[ExternEVM p2p] Failed to decode ExternDataMsg from peer {:?}: {}",
                    self.peer_id, e
                );
            }
        }
    }
}

impl Stream for ExternEvmConnection {
    type Item = BytesMut;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        // 1. Drain any pending outgoing messages first.
        if let Some(msg) = this.pending_out.pop_front() {
            return Poll::Ready(Some(msg));
        }

        // 2. Poll for incoming messages from the peer.
        loop {
            match this.conn.poll_next_unpin(cx) {
                Poll::Ready(Some(data)) => {
                    this.handle_incoming(data);
                    // Continue polling — there might be more incoming messages.
                }
                Poll::Ready(None) => {
                    // Connection closed by peer.
                    eprintln!(
                        "[ExternEVM p2p] Connection closed by peer {:?}",
                        this.peer_id
                    );
                    return Poll::Ready(None);
                }
                Poll::Pending => break,
            }
        }

        // 3. Check for new broadcasts from our local precompile.
        loop {
            match this.broadcast_rx.try_recv() {
                Ok(msg) => {
                    // Don't send our own messages back to ourselves.
                    if msg.validator == this.local_validator {
                        // But we DO want to forward our value to this peer.
                        // Actually we DO want to send it — the point is to
                        // broadcast to all peers. "our own" here means we
                        // already stored it locally, but we still need to
                        // send it over the wire to the remote peer.
                    }
                    // Encode and queue for sending.
                    let encoded = msg.encode_to_bytes();
                    this.pending_out.push_back(encoded);
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    // Broadcast channel closed — should never happen.
                    eprintln!("[ExternEVM p2p] Broadcast channel closed");
                    return Poll::Ready(None);
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!(
                        "[ExternEVM p2p] Broadcast lagged by {} messages, some values missed",
                        n
                    );
                    // Continue receiving what's available.
                }
            }
        }

        // If we queued any outgoing messages, return the first one.
        if let Some(msg) = this.pending_out.pop_front() {
            return Poll::Ready(Some(msg));
        }

        // Register waker so we get polled again when broadcast has new data.
        // The broadcast channel doesn't directly support wakers on try_recv,
        // so we rely on the network event loop polling us periodically.
        // For more responsive broadcasting, we could wrap broadcast_rx in a
        // proper async stream, but for v2 the slight delay is acceptable.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ---------------------------------------------------------------------------
// Helper: compute request hash
// ---------------------------------------------------------------------------

/// Compute a deterministic hash for an API request.
/// This is used to correlate values across nodes — every node calling the
/// same API endpoint with the same parameters produces the same hash.
pub fn compute_request_hash(
    url: &str,
    method: &str,
    response_path: &str,
    response_type: u8,
) -> B256 {
    use alloy_primitives::keccak256;

    let mut data = Vec::new();
    data.extend_from_slice(url.as_bytes());
    data.push(0xFF); // separator
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
        let msg = ExternDataMsg {
            request_hash: B256::from([0xAB; 32]),
            value: vec![0x00, 0x01, 0x02, 0x03],
            response_type: 1,
            validator: Address::from([0xCC; 20]),
        };

        // Encode
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);

        // Decode
        let mut slice = buf.as_ref();
        let decoded = ExternDataMsg::decode(&mut slice).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_extern_data_msg_encode_with_id() {
        let msg = ExternDataMsg {
            request_hash: B256::ZERO,
            value: vec![42],
            response_type: 1,
            validator: Address::ZERO,
        };

        let encoded = msg.encode_to_bytes();
        // First byte should be message ID 0x00
        assert_eq!(encoded[0], 0x00);
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

        // Different URL → different hash
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