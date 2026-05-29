use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};
use ed25519_dalek::SigningKey;
use log::{info, warn};
use rand::random;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::udp::messages;
use crate::udp::messages::{FromServerMessage, PublicKey};
use crate::udp::reusable_udp_socket::ReusableUdpSocket;

struct PeerState {
    /// Whether we're actively trying to connect to this peer.
    active: bool,
    /// The last `remote_session_id` we accepted from the server for this peer.
    /// Used to ignore duplicate notifications.
    last_accepted_session_id: Option<u32>,
}

pub struct UdpClient {
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
}

impl UdpClient {
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4) -> UdpClient {
        UdpClient {
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

    async fn place_connection_requests(&mut self) -> Option<()> {
        self.session_id = random();
        self.p2p_server_socket.take();
        let socket = self.parent_socket.new_connection(self.p2p_server_addr).await?;
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

        Some(())
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

    /// Block for `dur`, immediately returning if a new hole-punched connection is ready.
    /// The returned connection has already completed the full hole punch handshake
    /// and is ready for immediate send/recv use.
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<NewP2pConnection> {
        if self.trusted_remotes.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            return None;
        }

        if self.last_request_tm.is_none_or(|i| i.elapsed().as_secs() > REQUEST_PLACEMENT_INTERVAL) {
            if self.place_connection_requests().await.is_none() {
                warn!("Failed to connect udp socket to p2p server!")
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
                                remote_session_id
                            } => {
                                if let Some(state) = self.trusted_remotes.get_mut(&peer_pubkey) {
                                    if !state.active {
                                        warn!("Got duplicate connection notification, ignoring");
                                        return None;
                                    }

                                    if state.last_accepted_session_id == Some(remote_session_id) {
                                        return None;
                                    }

                                    state.active = false;
                                    state.last_accepted_session_id = Some(remote_session_id);

                                    let socket = self.parent_socket.new_connection(peer_address).await;
                                    let Some(socket) = socket else {
                                        warn!("Failed to connect udp socket to remote peer");
                                        return None
                                    };

                                    if !self.hole_punch(&socket, peer_address).await {
                                        warn!("Hole punch failed for peer {}", peer_address);
                                        return None;
                                    }

                                    return Some(NewP2pConnection {
                                        pubkey: peer_pubkey,
                                        remote_addr: peer_address,
                                        socket
                                    })
                                }
                                else {
                                    warn!("Got connection request from p2p server, but client's pubkey is not in trusted list!");
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                    }
                    else if let Err(e) = res {
                        warn!("Cannot parse message from p2p server: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                Ok(Err(e)) => {
                    warn!("Failed to receive message from server: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(_) => {
                    return None;
                }
            }
        }

        None
    }
}
