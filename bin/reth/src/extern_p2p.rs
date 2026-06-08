//! ExternEVM extern/1 subprotocol — ProtocolHandler + ConnectionHandler.
//!
//! v4: transports three message types over extern/1 —
//!   0x00 ExternDataMsg   (v2 compat — open value)
//!   0x01 ExternCommitMsg (v3 — commitment)
//!   0x02 ExternRevealMsg (v3 reveal + v4 TLS attestation)
//! Each has its own broadcast channel; the connection drains all three
//! outbound and dispatches all three inbound. Reveal receipt feeds the v4
//! attestation fields into the protocol store; the attestation itself is
//! verified later at the precompile read path (check_reveal), where the
//! request domain is available.

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
use reth_evm_ethereum::extern_proto::{
    broadcast_subscribe, commit_subscribe, reveal_subscribe, ExternCommitMsg, ExternDataMsg,
    ExternRevealMsg, MSG_TYPE_COMMIT, MSG_TYPE_DATA, MSG_TYPE_REVEAL,
};
use reth_evm_ethereum::protocol_store::{global_store, ValidatorCommit};
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
const EXTERN_PROTO_MSG_COUNT: u8 = 3; // v4: data + commit + reveal

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

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
    data_rx: broadcast::Receiver<ExternDataMsg>,
    commit_rx: broadcast::Receiver<ExternCommitMsg>,
    reveal_rx: broadcast::Receiver<ExternRevealMsg>,
    local_validator: Address,
    peer_id: PeerId,
    pending_out: VecDeque<BytesMut>,
}

impl ExternEvmConnection {
    fn new(conn: ProtocolConnection, local_validator: Address, peer_id: PeerId) -> Self {
        Self {
            conn,
            data_rx: broadcast_subscribe(),
            commit_rx: commit_subscribe(),
            reveal_rx: reveal_subscribe(),
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
        let store = global_store();

        match msg_id {
            MSG_TYPE_DATA => {
                let mut slice = payload;
                match ExternDataMsg::decode(&mut slice) {
                    Ok(msg) => {
                        eprintln!(
                            "[ExternEVM p2p] DATA from {:?} for request {:?} (type={})",
                            msg.validator, msg.request_hash, msg.response_type
                        );
                        if !store.is_validator(&msg.validator) {
                            store.register_validator(msg.validator);
                        }
                        match store.submit_value(msg.request_hash, msg.validator, msg.value.clone(), 0) {
                            Ok(()) => {}
                            Err(e) => eprintln!("[ExternEVM p2p] DATA store failed: {}", e),
                        }
                    }
                    Err(e) => eprintln!(
                        "[ExternEVM p2p] decode ExternDataMsg from {:?} failed: {}",
                        self.peer_id, e
                    ),
                }
            }
            MSG_TYPE_COMMIT => {
                let mut slice = payload;
                match ExternCommitMsg::decode(&mut slice) {
                    Ok(msg) => {
                        eprintln!(
                            "[ExternEVM p2p] COMMIT from {:?} for request {:?}",
                            msg.validator, msg.request_hash
                        );
                        if !store.is_validator(&msg.validator) {
                            store.register_validator(msg.validator);
                        }
                        store.store_commit(ValidatorCommit {
                            request_hash: msg.request_hash,
                            validator: msg.validator,
                            commitment: msg.commitment,
                            received_at_ms: unix_ms(),
                        });
                    }
                    Err(e) => eprintln!(
                        "[ExternEVM p2p] decode ExternCommitMsg from {:?} failed: {}",
                        self.peer_id, e
                    ),
                }
            }
            MSG_TYPE_REVEAL => {
                let mut slice = payload;
                match ExternRevealMsg::decode(&mut slice) {
                    Ok(msg) => {
                        eprintln!(
                            "[ExternEVM p2p] REVEAL from {:?} for request {:?} ({} cert bytes)",
                            msg.validator,
                            msg.request_hash,
                            msg.cert_der.len()
                        );
                        if !store.is_validator(&msg.validator) {
                            store.register_validator(msg.validator);
                        }
                        // Stores the reveal + v4 attestation fields and runs the
                        // commit-reveal binding check. Attestation is verified
                        // later at the read path (check_reveal), where the domain
                        // is known.
                        let commit_ok = store.store_reveal(
                            msg.request_hash,
                            msg.validator,
                            msg.value.clone(),
                            msg.salt.0,
                            msg.cert_der.clone(),
                            msg.response_hash,
                            msg.timestamp_secs,
                            msg.attestation_sig.clone(),
                        );
                        if !commit_ok {
                            eprintln!(
                                "[ExternEVM p2p] REVEAL from {:?} failed commit-reveal binding",
                                msg.validator
                            );
                        }
                    }
                    Err(e) => eprintln!(
                        "[ExternEVM p2p] decode ExternRevealMsg from {:?} failed: {}",
                        self.peer_id, e
                    ),
                }
            }
            other => {
                eprintln!(
                    "[ExternEVM p2p] Unknown message ID {} from peer {:?}",
                    other, self.peer_id
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

        // 3. Drain DATA broadcasts
        loop {
            match this.data_rx.try_recv() {
                Ok(msg) => {
                    let mut buf = BytesMut::new();
                    buf.extend_from_slice(&[MSG_TYPE_DATA]);
                    msg.encode(&mut buf);
                    this.pending_out.push_back(buf);
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    eprintln!("[ExternEVM p2p] DATA broadcast channel closed");
                    return Poll::Ready(None);
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!("[ExternEVM p2p] DATA broadcast lagged by {} messages", n);
                }
            }
        }

        // 4. Drain COMMIT broadcasts
        loop {
            match this.commit_rx.try_recv() {
                Ok(msg) => {
                    let mut buf = BytesMut::new();
                    buf.extend_from_slice(&[MSG_TYPE_COMMIT]);
                    msg.encode(&mut buf);
                    this.pending_out.push_back(buf);
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    eprintln!("[ExternEVM p2p] COMMIT broadcast channel closed");
                    return Poll::Ready(None);
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!("[ExternEVM p2p] COMMIT broadcast lagged by {} messages", n);
                }
            }
        }

        // 5. Drain REVEAL broadcasts
        loop {
            match this.reveal_rx.try_recv() {
                Ok(msg) => {
                    let mut buf = BytesMut::new();
                    buf.extend_from_slice(&[MSG_TYPE_REVEAL]);
                    msg.encode(&mut buf);
                    this.pending_out.push_back(buf);
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    eprintln!("[ExternEVM p2p] REVEAL broadcast channel closed");
                    return Poll::Ready(None);
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!("[ExternEVM p2p] REVEAL broadcast lagged by {} messages", n);
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
