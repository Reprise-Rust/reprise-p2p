use crate::ctrlc_reg::ShutdownListener;
use crate::udp::messages::{FromServerMessage, PublicKey, ToServerSignedMessage};
use chrono::Utc;
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::select;

const REQUEST_TIMEOUT_S: u64 = 10;
const SIGNED_MSG_VALID_S: i64 = 30;

struct PendingRequest {
    requester_pubkey: PublicKey,
    requester_addr: SocketAddrV4,
    requester_session_id: u32,
    tm: Instant,
}

struct UdpState {
    /// Map from (requester_pubkey, target_pubkey) to the pending request info.
    requests: HashMap<PublicKey, HashMap<PublicKey, PendingRequest>>,
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
        self.requests.retain(|_sender_pubkey, inner_map| {
            inner_map.retain(|_peer_pubkey, v| v.tm.elapsed().as_secs() < REQUEST_TIMEOUT_S);
            !inner_map.is_empty()
        });
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
                match res {
                    Err(e) => {
                        warn!("[Reprise:UDP] Error receiving from socket: {}", e);
                    }
                    Ok((sz, addr)) => {
                        let SocketAddr::V4(addr) = addr else {
                            warn!("Ignoring IPv6 message from {}", addr);
                            continue;
                        };
                        let msg = &buf[..sz];
                        match ToServerSignedMessage::try_parse(msg) {
                            Err(e) => {
                                error!("[Reprise:UDP] Error parsing client message: {}", e);
                            }
                            Ok((parsed_msg, sender_pubkey, tm)) => {
                                // Reject messages with timestamps too far from now (replay protection).
                                let now = Utc::now();
                                if (now - tm).num_seconds().abs() > SIGNED_MSG_VALID_S {
                                    warn!("[Reprise:UDP] Rejected message with stale timestamp (diff: {}s)", (now - tm).num_seconds().abs());
                                    continue;
                                }

                                match parsed_msg {
                                    ToServerSignedMessage::ConnectionRequest {
                                        peer_pubkeys,
                                        session_id
                                    } => {
                                        state.cleanup();

                                        if let Some(active_session) = state.last_session_ids.get(&sender_pubkey) && active_session.session_id == session_id {
                                            let lost_request_bytes = FromServerMessage::LostConnectionRequest {
                                                peer_address: active_session.remote_addr,
                                                peer_pubkey: active_session.remote_peer,
                                            }.to_bytes();
                                            if let Err(e) = socket.send_to(&lost_request_bytes, addr).await {
                                                warn!("[Reprise:UDP] Failed to send lost request notification to {}: {}", addr, e);
                                            }
                                            continue;
                                        }

                                        let mut pending_request = None;

                                        for peer_pubkey in &peer_pubkeys {
                                            if let Some(inner_map) = state.requests.get_mut(peer_pubkey) {
                                                pending_request = inner_map.remove(&sender_pubkey).map(|req| (peer_pubkey, req))
                                            }
                                            if pending_request.is_some() {
                                                break;
                                            }
                                        }

                                        if let Some((peer_pubkey, pending)) = pending_request {
                                            if let Some(true) = state.requests.get(peer_pubkey).map(|inner| inner.is_empty()) {
                                                state.requests.remove(peer_pubkey);
                                            }

                                            info!("[Reprise:UDP] Matched connection request between peers");

                                            let to_original = FromServerMessage::InitiateConnectionRequest {
                                                peer_pubkey: sender_pubkey,
                                                peer_address: addr,
                                                remote_session_id: session_id,
                                                is_listener: false,
                                            };

                                            let to_new = FromServerMessage::InitiateConnectionRequest {
                                                peer_pubkey: pending.requester_pubkey,
                                                peer_address: pending.requester_addr,
                                                remote_session_id: pending.requester_session_id,
                                                is_listener: true
                                            };

                                            let to_original_bytes = to_original.to_bytes();
                                            let to_new_bytes = to_new.to_bytes();

                                            if let Err(e) = socket.send_to(&to_original_bytes, pending.requester_addr).await {
                                                warn!("[Reprise:UDP] Failed to send to original requester {}: {}", pending.requester_addr, e);
                                            }
                                            if let Err(e) = socket.send_to(&to_new_bytes, addr).await {
                                                warn!("[Reprise:UDP] Failed to send to new requester {}: {}", addr, e);
                                            }

                                            state.last_session_ids.insert(sender_pubkey, ActiveSession {
                                                session_id: pending.requester_session_id,
                                                remote_addr: pending.requester_addr,
                                                remote_peer: pending.requester_pubkey
                                            });

                                            state.requests.remove(&sender_pubkey);
                                        }
                                        else {
                                            state.requests.insert(sender_pubkey,
                                                HashMap::from_iter(peer_pubkeys.into_iter().map(|peer_pubkey| {
                                                    (peer_pubkey, PendingRequest {
                                                        requester_pubkey: sender_pubkey,
                                                        requester_addr: addr,
                                                        requester_session_id: session_id,
                                                        tm: Instant::now(),
                                                    })
                                                }))
                                            );
                                        }
                                    }
                                }
                            }
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
