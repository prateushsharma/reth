//! ExternEVM extern/1 subprotocol — ProtocolHandler + ConnectionHandler.

use alloy_primitives::bytes::BytesMut;
use alloy_primitives::Address;
use alloy_rlp::{Decodable, Encodable};
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities,
    multiplex::ProtocolConnection,
    protocol::Protocol,
    Capability,
};
use reth_evm_ethereum::extern_proto::{broadcast_subscribe, ExternDataMsg};
use reth_evm_ethereum::protocol_store::global_store;
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
    task::{Context, Poll},
};
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EXTERN_PROTO_NAME: &str = "extern";
const EXTERN_PROTO_VERSION: usize = 1;
const EXTERN_PROTO_MSG_COUNT: u8 = 1;

// ---------------------------------------------------------------------------
// ProtocolHandler — factory, one per node
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ExternEvmProtoHandler {
    pub local_validator: Address,
}

impl ExternEvmProtoHandler {
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

pub struct ExternEvmConnection {
    conn: ProtocolConnection,
    broadcast_rx: broadcast::Receiver<ExternDataMsg>,
    local_validator: Address,
    peer_id: PeerId,
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

    fn handle_incoming(&self, data: BytesMut) {
        if data.is_empty() {
            return;
        }

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
        match ExternDataMsg::decode(&mut slice) {
            Ok(msg) => {
                eprintln!(
                    "[ExternEVM p2p] Received value from validator {:?} for request {:?} (type={})",
                    msg.validator, msg.request_hash, msg.response_type
                );

                let store = global_store();

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
                        eprintln!("[ExternEVM p2p] Failed to store peer value: {}", e);
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

        // 1. Drain pending outgoing messages
        if let Some(msg) = this.pending_out.pop_front() {
            return Poll::Ready(Some(msg));
        }

        // 2. Poll for incoming messages from the peer
        loop {
            match this.conn.poll_next_unpin(cx) {
                Poll::Ready(Some(data)) => {
                    this.handle_incoming(data);
                }
                Poll::Ready(None) => {
                    eprintln!(
                        "[ExternEVM p2p] Connection closed by peer {:?}",
                        this.peer_id
                    );
                    return Poll::Ready(None);
                }
                Poll::Pending => break,
            }
        }

        // 3. Check for broadcasts from our local precompile
        loop {
            match this.broadcast_rx.try_recv() {
                Ok(msg) => {
                    // Encode: message ID byte + RLP payload
                    let mut buf = BytesMut::new();
                    buf.extend_from_slice(&[0x00]);
                    msg.encode(&mut buf);
                    this.pending_out.push_back(buf);
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    eprintln!("[ExternEVM p2p] Broadcast channel closed");
                    return Poll::Ready(None);
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!(
                        "[ExternEVM p2p] Broadcast lagged by {} messages",
                        n
                    );
                }
            }
        }

        // Return first queued outgoing message
        if let Some(msg) = this.pending_out.pop_front() {
            return Poll::Ready(Some(msg));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}