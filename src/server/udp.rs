use crate::ctrlc_reg::ShutdownListener;
use crate::udp::messages::{FromServerMessage, PublicKey, ToServerRawMessage, ToServerSignedMessage};
use chrono::Utc;
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::{select, time};

const REQUEST_TIMEOUT_S: u64 = 10;
const SIGNED_MSG_VALID_S: i64 = 30;

#[derive(Clone)]
struct RequestInfo {
    requester_pubkey: PublicKey,
    requester_addr: SocketAddrV4,
    requester_session_id: u32,
    trusted_remotes: Vec<PublicKey>,
    tm: Instant,
}

struct UdpState {
    /// Map from (requester_pubkey, target_pubkey) to the pending request info.
    requests: HashMap<PublicKey, RequestInfo>,
    last_session_ids: HashMap<PublicKey, ActiveSession>,
}
struct ActiveSession {
    session_id: u32,
    remote_addr: SocketAddrV4,
    remote_peer: PublicKey,
}

impl UdpState {
    fn new() -> Self {
        Self {
            requests: HashMap::new(),
            last_session_ids: HashMap::new(),
        }
    }

    fn cleanup(&mut self) {
        if self.requests.iter().any(|(_, info)| {
            info.tm.elapsed().as_secs() <= REQUEST_TIMEOUT_S && !info.trusted_remotes.is_empty()
        }) {
            self.requests.retain(|_, info| {
                info.tm.elapsed().as_secs() <= REQUEST_TIMEOUT_S && !info.trusted_remotes.is_empty()
            });
        }
    }
}

pub async fn run_udp_server(port: u16, mut shutdown: ShutdownListener) {
    let socket = UdpSocket::bind(("0.0.0.0", port)).await.unwrap();
    info!("[Reprise:P2P:UDP] UDP server started on port {}!", port);

    let mut state = UdpState::new();
    let mut buf = vec![0u8; 2000];
    loop {
        select! {
            res = socket.recv_from(&mut buf) => {
                if let Err(e) = res {
                    warn!("[Reprise:UDP] Error receiving from socket: {}", e);
                    time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                let Ok((sz, addr)) = res else {
                    unreachable!();
                };

                // <- message parsed

                let SocketAddr::V4(addr) = addr else {
                    warn!("Ignoring IPv6 message from {}", addr);
                    continue;
                };
                let msg = &buf[..sz];
                let res = ToServerRawMessage::try_parse(msg);
                if let Err(e) = res {
                    error!("[Reprise:UDP] Error parsing client message: {}", e);
                    time::sleep(Duration::from_millis(20)).await;
                    continue;
                }

                match res.unwrap() {
                    ToServerRawMessage::SignedMessage(msg) => {
                        let res = ToServerSignedMessage::try_parse(msg);
                        let Ok((parsed_msg, sender_pubkey, tm)) = res else { unreachable!() };

                        // <- message validated, signature and body valid

                        let now = Utc::now();
                        if (now - tm).num_seconds().abs() > SIGNED_MSG_VALID_S {
                            // Reject messages with timestamps too far from now (replay protection).
                            warn!("[Reprise:UDP] Rejected message with stale timestamp (diff: {}s)", (now - tm).num_seconds().abs());
                            continue;
                        }

                        match parsed_msg {
                            ToServerSignedMessage::ConnectionRequest {
                                peer_pubkeys,
                                session_id
                            } => {
                                state.cleanup();

                                // 1) check last established connection for this user, session must be different
                                if let Some(active_session) = state.last_session_ids.get(&sender_pubkey) && active_session.session_id == session_id {
                                    let lost_request_bytes = FromServerMessage::NeedNewSession {
                                        old_session_id: session_id,
                                    }.to_bytes();
                                    if let Err(e) = socket.send_to(&lost_request_bytes, addr).await {
                                        warn!("[Reprise:UDP] Failed to send lost request notification to {}: {}", addr, e);
                                    }
                                    continue;
                                }

                                // remove previous our request if we have one
                                state.requests.remove(&sender_pubkey);

                                // 2) search for valid incoming request from one of peer_pubkeys
                                let mut pending_request = None;
                                for peer_pubkey in &peer_pubkeys {
                                    if state.requests.get_mut(peer_pubkey).is_some_and(|r| {
                                        r.trusted_remotes.iter().any(|k| k == &sender_pubkey)
                                    }) {
                                        // found matching incoming request, remove it
                                        let req = state.requests.remove(peer_pubkey).unwrap();

                                        // check for the same ip addr
                                        let peer_addr = req.requester_addr;
                                        if peer_addr == addr {
                                            let to_original = FromServerMessage::ErrorSameIp {
                                                peer_pubkey: sender_pubkey,
                                            };

                                            let to_new = FromServerMessage::ErrorSameIp {
                                                peer_pubkey: peer_pubkey.clone(),
                                            };

                                            let to_original_bytes = to_original.to_bytes();
                                            let to_new_bytes = to_new.to_bytes();

                                            if let Err(e) = socket.send_to(&to_original_bytes, peer_addr).await {
                                                warn!("[Reprise:UDP] Failed to send to original requester {}: {}", peer_addr, e);
                                            }
                                            if let Err(e) = socket.send_to(&to_new_bytes, addr).await {
                                                warn!("[Reprise:UDP] Failed to send to new requester {}: {}", addr, e);
                                            }
                                        }
                                        else {
                                            pending_request = Some(req);
                                            break;
                                        }
                                    }
                                }

                                // if found incoming request from other peer
                                if let Some(request) = pending_request {
                                    // <- at this point we have matched requests and they are removed from state
                                    info!("[Reprise:UDP] Matched connection request: {:?} at {} <-> {:?} at {}", request.requester_pubkey, request.requester_addr, sender_pubkey, addr);

                                    let to_original = FromServerMessage::InitiateConnectionRequest {
                                        peer_pubkey: sender_pubkey,
                                        peer_address: addr,
                                        remote_session_id: session_id,
                                        is_listener: false,
                                    };

                                    let to_new = FromServerMessage::InitiateConnectionRequest {
                                        peer_pubkey: request.requester_pubkey,
                                        peer_address: request.requester_addr,
                                        remote_session_id: request.requester_session_id,
                                        is_listener: true
                                    };

                                    let to_original_bytes = to_original.to_bytes();
                                    let to_new_bytes = to_new.to_bytes();

                                    if let Err(e) = socket.send_to(&to_original_bytes, request.requester_addr).await {
                                        warn!("[Reprise:UDP] Failed to send to original requester {}: {}", request.requester_addr, e);
                                    }
                                    if let Err(e) = socket.send_to(&to_new_bytes, addr).await {
                                        warn!("[Reprise:UDP] Failed to send to new requester {}: {}", addr, e);
                                    }

                                    state.last_session_ids.insert(sender_pubkey, ActiveSession {
                                        remote_peer: request.requester_pubkey,
                                        remote_addr: request.requester_addr,
                                        session_id: request.requester_session_id,
                                    });
                                    state.last_session_ids.insert(request.requester_pubkey, ActiveSession {
                                        remote_peer: sender_pubkey,
                                        remote_addr: addr,
                                        session_id,
                                    });
                                }
                                else {
                                    state.requests.insert(sender_pubkey,
                                        RequestInfo {
                                            requester_pubkey: sender_pubkey,
                                            requester_addr: addr,
                                            requester_session_id: session_id,
                                            trusted_remotes: peer_pubkeys,
                                            tm: Instant::now(),
                                        }
                                    );
                                }
                            }
                        }
                    }
                    ToServerRawMessage::Ping {
                        payload
                    } => {

                        let resp = FromServerMessage::Pong {
                            payload
                        };

                        let res = socket.send_to(&resp.to_bytes(), addr).await;
                        if let Err(e) = res {
                            warn!("Failed to reply to ping request: {:?}", e);
                        }
                    }
                }
            }

            _ = shutdown.wait() => {
                info!("[Reprise:P2P:UDP] Shutdown signal received! Quitting udp server loop..");
                break;
            }
        }
    }
}
