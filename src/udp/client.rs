use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};
use ed25519_dalek::SigningKey;
use log::warn;
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

    /// Returns None if failed to start a new connection
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

    /// Block for `dur`, immediately returning if new connection request appears.
    /// Highly recommended to call this function in separate task in a loop
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
                                        // Duplicate notification for the same session — ignore.
                                        return None;
                                    }

                                    state.active = false;
                                    state.last_accepted_session_id = Some(remote_session_id);
                                    let socket = self.parent_socket.new_connection(peer_address).await;
                                    let Some(socket) = socket else {
                                        warn!("Failed to connect udp socket to remote peer");
                                        return None
                                    };
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
