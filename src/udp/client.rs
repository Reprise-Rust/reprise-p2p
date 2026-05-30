use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};
use anyhow::{anyhow, Context};
use ed25519_dalek::SigningKey;
use log::{debug, info, warn};
use rand::random;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::udp::messages;
use crate::udp::messages::{FromServerMessage, PublicKey};
use crate::udp::quic;
use crate::udp::reusable_udp_socket::ReusableUdpSocket;

struct PeerState {
    /// Whether we're actively trying to connect to this peer.
    active: bool,
    /// The last `remote_session_id` we accepted from the server for this peer.
    /// Used to ignore duplicate notifications.
    last_accepted_session_id: Option<u32>,
}

pub struct UdpConnectionEstablisher {
    p2p_server_addr: SocketAddrV4,
    trusted_remotes: BTreeMap<PublicKey, PeerState>,
    last_request_tm: Option<Instant>,
    key: SigningKey,
    session_id: u32,
    parent_socket: ReusableUdpSocket,
    p2p_server_socket: Option<UdpSocket>,
}

const REQUEST_PLACEMENT_INTERVAL: u64 = 2;

/// A fully hole-punched, ready-to-use P2P connection.
pub struct NewP2pConnection {
    pub pubkey: PublicKey,
    pub remote_addr: SocketAddrV4,
    pub socket: UdpSocket,
    pub is_listener: bool,
}

impl UdpConnectionEstablisher {
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4) -> UdpConnectionEstablisher {
        UdpConnectionEstablisher {
            last_request_tm: None,
            trusted_remotes: BTreeMap::new(),
            key,
            p2p_server_addr,
            session_id: random(),
            parent_socket: ReusableUdpSocket::new(),
            p2p_server_socket: None,
        }
    }

    pub fn add_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.insert(key, PeerState {
            active: true,
            last_accepted_session_id: None,
        });
    }

    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.remove(&key);
    }

    fn start_new_session(&mut self) {
        self.session_id = random();
        for trusted_remote in self.trusted_remotes.values_mut() {
            trusted_remote.active = true;
        }
    }

    async fn place_connection_requests(&mut self) -> anyhow::Result<()> {
        self.p2p_server_socket.take();
        let socket = self.parent_socket.new_connection(self.p2p_server_addr).await.context("Preparing connection to P2P server")?;
        for (pubkey, state) in &self.trusted_remotes {
            if !state.active {
                continue;
            }
            let payload = messages::ToServerSignedMessage::ConnectionRequest {
                peer_pubkey: *pubkey,
                session_id: self.session_id,
            }.to_bytes(&self.key);
            let res = socket.send(&payload).await;
            if let Err(e) = res {
                warn!("Failed to place connection request: {}", e);
            }
        }
        self.p2p_server_socket = Some(socket);
        self.last_request_tm = Some(Instant::now());

        Ok(())
    }

    /// Perform the full hole punch handshake on the given socket.
    /// Returns `true` if the hole was successfully punched.
    async fn hole_punch(&self, socket: &UdpSocket, peer: SocketAddrV4) -> bool {
        // Phase 1: Punch exchange (up to 500ms)
        info!("Starting hole punch to {}...", peer);
        let punch_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut punch_interval = tokio::time::interval(Duration::from_millis(20));
        let mut got_punch = false;
        let mut got_punch_ack = false;

        let mut buf = vec![0u8; 2000];
        loop {
            let now = tokio::time::Instant::now();
            if now >= punch_deadline {
                break;
            }
            if got_punch && got_punch_ack {
                break;
            }

            tokio::select! {
                _ = punch_interval.tick() => {
                    if let Err(e) = socket.send(b"punch").await {
                        warn!("Error sending punch message: {:?}", e)
                    }
                }
                recv = socket.recv(&mut buf) => {
                    match recv {
                        Ok(sz) => {
                            let msg = &buf[..sz];
                            if msg == b"punch" {
                                info!("Received punch from {}, sending ack", peer);
                                let _ = socket.send(b"punch ack").await;
                                got_punch = true;
                            } else if msg == b"punch ack" {
                                info!("Received punch ack from {}", peer);
                                got_punch_ack = true;
                            }
                        }
                        Err(e) => {
                            warn!("Recv error during punch: {:?}", e);
                        }
                    }
                }
            }
        }

        if !got_punch || !got_punch_ack {
            warn!("Hole punching failed (timeout) — got_punch={}, got_punch_ack={}", got_punch, got_punch_ack);
            return false;
        }

        // Phase 2: Drain remaining punch/ack packets (200ms)
        info!("Punch exchange done, draining socket...");
        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            let now = tokio::time::Instant::now();
            if now >= drain_deadline {
                break;
            }
            match tokio::time::timeout_at(drain_deadline, socket.recv(&mut buf)).await {
                Ok(Ok(sz)) => {
                    let msg = &buf[..sz];
                    if msg != b"punch" && msg != b"punch ack" {
                        warn!("Unexpected packet during drain: {:?}", msg);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Recv error during drain: {:?}", e);
                }
                Err(_) => {
                    break;
                }
            }
        }

        // Phase 3: Settle (200ms)
        info!("Drain done, settling...");
        tokio::time::sleep(Duration::from_millis(200)).await;

        info!("Hole punched with {}!", peer);
        true
    }

    /// Block for `dur`, returning a new hole-punched connection or an error.
    /// The returned connection has already completed the full hole punch handshake
    /// and is ready for immediate send/recv use.
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<anyhow::Result<NewP2pConnection>> {
        if self.trusted_remotes.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            return None; // No requests to put on P2P server
        }

        if self.last_request_tm.is_none_or(|i| i.elapsed().as_secs() > REQUEST_PLACEMENT_INTERVAL) {
            if let Err(e) = self.place_connection_requests().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                return Some(Err(e));
            }
        }

        let mut buf = vec![0; 2000];
        if let Some(ref socket) = self.p2p_server_socket {
            match timeout(dur, socket.recv(&mut buf)).await {
                Ok(Ok(sz)) => {
                    let msg = &buf[..sz];
                    let res = FromServerMessage::try_parse(msg);
                    if let Ok(msg) = res {
                        match msg {
                            FromServerMessage::InitiateConnectionRequest {
                                peer_address,
                                peer_pubkey,
                                remote_session_id,
                                is_listener,
                            } => {
                                // use new session id for all future requests
                                self.start_new_session();
                                let context = format!("Handling InitiateConnectionRequest from p2p server for peer {}, session_id={}", peer_address, remote_session_id);
                                if let Some(state) = self.trusted_remotes.get_mut(&peer_pubkey) {
                                    if !state.active {
                                        debug!("Got duplicate connection notification, ignoring");
                                        return None;
                                    }

                                    if state.last_accepted_session_id == Some(remote_session_id) {
                                        debug!("Got duplicate connection notification with same session_id, ignoring");
                                        return None;
                                    }

                                    state.active = false;
                                    state.last_accepted_session_id = Some(remote_session_id);

                                    let res = self.parent_socket.new_connection(peer_address).await.context(context.clone());
                                    let Ok(socket) = res else {
                                        let Err(e) = res else {unreachable!()};
                                        return Some(Err(anyhow!(e).context(context)));
                                    };

                                    if !self.hole_punch(&socket, peer_address).await {
                                        return Some(Err(anyhow::anyhow!("Hole punch failed for peer {}", peer_address).context(context)));
                                    }

                                    return Some(Ok(NewP2pConnection {
                                        pubkey: peer_pubkey,
                                        remote_addr: peer_address,
                                        socket,
                                        is_listener,
                                    }))
                                }
                                else {
                                    debug!("Got connection request from p2p server, but client's pubkey is not in trusted list!");
                                    return Some(Err(anyhow::anyhow!("Peer pubkey not in trusted list")));
                                }
                            }
                        }
                    }
                    let Err(e) = res else {unreachable!()};
                    warn!("Cannot parse message from p2p server: {}", e);
                    Some(Err(anyhow::anyhow!("Cannot parse message from p2p server: {}", e)))
                }
                Ok(Err(e)) => {
                    warn!("Failed to receive message from server: {}", e);
                    Some(Err(anyhow::anyhow!("Failed to receive message from server: {}", e)))
                }
                Err(_) => {
                    None // no new messages from P2P server
                }
            }
        }
        else {
            // no p2p connection socket, retry preparing connection to P2P server
            if let Err(e) = self.place_connection_requests().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                return Some(Err(e));
            }
            None // was no p2p connection socket but we placed a new one
        }
    }
}

/// A QUIC connection established over a hole-punched UDP connection.
pub struct QuicP2pConnection {
    pub quic_connection: quinn::Connection,
    pub remote_pubkey: PublicKey,
    pub remote_addr: SocketAddrV4,
}

/// Wraps `UdpConnectionEstablisher` and additionally establishes a QUIC connection
/// on top of each hole-punched UDP connection.
pub struct UdpQuicConnectionEstablisher {
    inner: UdpConnectionEstablisher,
    signing_key: SigningKey,
}

impl UdpQuicConnectionEstablisher {
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4) -> UdpQuicConnectionEstablisher {
        UdpQuicConnectionEstablisher {
            signing_key: key.clone(),
            inner: UdpConnectionEstablisher::new(key, p2p_server_addr).await,
        }
    }

    pub fn add_trusted_remote(&mut self, key: PublicKey) {
        self.inner.add_trusted_remote(key);
    }

    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        self.inner.remove_trusted_remote(key);
    }

    /// Block for `dur`, returning a fully established QUIC connection or an error.
    /// Internally performs UDP hole-punching and then establishes a QUIC connection
    /// using the appropriate role (server/client).
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<anyhow::Result<QuicP2pConnection>> {
        let conn = self.inner.poll_accept(dur).await?;
        let Ok(conn) = conn else {
            let Err(e) = conn else {unreachable!()};
            return Some(Err(e));
        };

        let remote_addr = conn.remote_addr;
        let remote_pubkey = conn.pubkey;
        let is_listener = conn.is_listener;

        let res = quic::make_quin_endpoint(&self.signing_key, conn.socket.into_std().unwrap(), remote_pubkey).await;
        let Ok(ep) = res else {
            let Err(e) = res else {unreachable!()};
            return Some(Err(e));
        };

        let res = if is_listener {
            quic::establish_server_quic_connection(ep, &self.signing_key, remote_addr, remote_pubkey).await
        } else {
            quic::establish_client_quic_connection(ep).await
        };
        let Ok(quic_connection) = res else {
            let Err(e) = res else {unreachable!()};
            return Some(Err(e));
        };

        Some(Ok(QuicP2pConnection {
            quic_connection,
            remote_pubkey,
            remote_addr,
        }))
    }
}
