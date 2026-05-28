use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddrV4};
use std::time::{Duration, Instant};
use ed25519_dalek::SigningKey;
use log::warn;
use rand::random;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::udp::messages;
use crate::udp::messages::{FromServerMessage, PublicKey};
use crate::udp::reusable_udp_socket::ReusableUdpSocket;

pub struct UdpClient {
    p2p_server_addr: SocketAddrV4,
    trusted_remotes: BTreeMap<PublicKey, bool>,
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
        self.trusted_remotes.insert(key, true);
    }

    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.remove(&key);
    }

    async fn place_connection_requests(&mut self) {
        self.p2p_server_socket.take(); // remove previous connected socket
        let socket = self.parent_socket.new_connection(self.p2p_server_addr).await; // create a new connected socket
        for (pubkey, _) in &self.trusted_remotes {
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
    }

    /// Block for `dur`, immediately returning if new connection request appears.
    /// Highly recommended to call this function in separate task in a loop
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<NewP2pConnection> {
        if self.trusted_remotes.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            return None;
        }

        if self.last_request_tm.is_none_or(|i| i.elapsed().as_secs() > REQUEST_PLACEMENT_INTERVAL) {
            self.place_connection_requests().await;
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
                                if let Some(e) = self.trusted_remotes.get_mut(&peer_pubkey) {
                                    if !*e {
                                        // we are not connecting to this client currently
                                        warn!("Got client connection request, but we are already connecting to this client");
                                        return None;
                                    }

                                    *e = false;
                                    // we can initiate p2p connection
                                    let socket = self.parent_socket.new_connection(peer_address).await;
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