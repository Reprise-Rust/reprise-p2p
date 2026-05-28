use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use chrono::Utc;
use log::{error, info, warn};
use tokio::net::UdpSocket;
use tokio::select;
use crate::ctrlc_reg::ShutdownListener;
use crate::udp::messages::{FromServerMessage, PublicKey, ToServerSignedMessage};

const REQUEST_TIMEOUT_S: u64 = 10;
const SIGNED_MSG_VALID_S: i64 = 10;

struct PendingRequest {
    requester_pubkey: PublicKey,
    requester_addr: SocketAddr,
    requester_session_id: u32,
    tm: Instant,
}

struct UdpState {
    /// Map from (requester_pubkey, target_pubkey) to the pending request info.
    requests: HashMap<(PublicKey, PublicKey), PendingRequest>,
}

impl UdpState {
    fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    fn cleanup(&mut self) {
        self.requests.retain(|_, v| v.tm.elapsed().as_secs() < REQUEST_TIMEOUT_S);
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
                                        peer_pubkey,
                                        session_id
                                    } => {
                                        state.cleanup();

                                        let forward_key = (sender_pubkey, peer_pubkey);
                                        let reverse_key = (peer_pubkey, sender_pubkey);

                                        if let Some(pending) = state.requests.remove(&reverse_key) {
                                            // Matching reverse request found — notify both peers and remove both entries.
                                            info!("[Reprise:UDP] Matched connection request between peers");

                                            let to_original = FromServerMessage::InitiateConnectionRequest {
                                                peer_pubkey: sender_pubkey,
                                                peer_address: match addr {
                                                    SocketAddr::V4(a) => a,
                                                    SocketAddr::V6(_) => {
                                                        warn!("[Reprise:UDP] IPv6 not supported, skipping");
                                                        continue;
                                                    }
                                                },
                                                remote_session_id: session_id,
                                            };

                                            let to_new = FromServerMessage::InitiateConnectionRequest {
                                                peer_pubkey: pending.requester_pubkey,
                                                peer_address: match pending.requester_addr {
                                                    SocketAddr::V4(a) => a,
                                                    SocketAddr::V6(_) => {
                                                        warn!("[Reprise:UDP] IPv6 not supported, skipping");
                                                        continue;
                                                    }
                                                },
                                                remote_session_id: pending.requester_session_id,
                                            };

                                            let to_original_bytes = to_original.to_bytes();
                                            let to_new_bytes = to_new.to_bytes();

                                            if let Err(e) = socket.send_to(&to_original_bytes, pending.requester_addr).await {
                                                warn!("[Reprise:UDP] Failed to send to original requester {}: {}", pending.requester_addr, e);
                                            }
                                            if let Err(e) = socket.send_to(&to_new_bytes, addr).await {
                                                warn!("[Reprise:UDP] Failed to send to new requester {}: {}", addr, e);
                                            }
                                        } else {
                                            // No match yet — store this request.
                                            state.requests.insert(forward_key, PendingRequest {
                                                requester_pubkey: sender_pubkey,
                                                requester_addr: addr,
                                                requester_session_id: session_id,
                                                tm: Instant::now(),
                                            });
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
