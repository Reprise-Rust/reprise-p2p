mod state;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use log::{info, warn};
use reprise_net_util::tcp_channel::ChannelError;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;
use crate::config::ServerConfig;
use crate::ctrlc_reg::ShutdownListener;
use crate::server::state::State;
use crate::tcp::messages::{NatServerChannel, ToNatClientMsg, ToNatServerMsg};
use crate::tcp::{CONNECTION_REQUEST_TIMEOUT_MS, SCHEDULE_CON_MS};

pub async fn run_server(cfg: ServerConfig, shutdown: ShutdownListener) {
    let mut set = JoinSet::new();
    if let Some(tcp_port) = cfg.tcp_handler_port {
        set.spawn(run_tcp_server(tcp_port, shutdown.clone()));
    }
    if let Some(udp_port) = cfg.udp_handler_port {
    }

    set.join_all().await;
}

async fn run_tcp_server(port: u16, mut shutdown: ShutdownListener) {
    let listener = TcpListener::bind(("0.0.0.0", port)).await.unwrap();
    info!("[Reprise:P2P:TCP] TCP server started on port {}!", port);

    let state = State::new();
    loop {
        select! {
            Ok((stream, addr)) = listener.accept() => {
                let state = state.clone();
                tokio::spawn(async move {
                    handle_tcp_client(stream, addr, state).await;
                });
            }

            _ = shutdown.wait() => {
                info!("[Reprise:P2P:TCP] Shutdown signal received! Quiting tcp server loop..");
                break;
            }
        }
    }
}

async fn handle_tcp_client(stream: TcpStream, addr: SocketAddr, state: State) {
    info!("[Reprise:P2P:TCP] New incoming connection: {:?}", addr);

    let mut channel = NatServerChannel::new(stream, Duration::from_secs(5), Duration::from_secs(5), 1_000);

    loop {
        state.poll_update();
        match channel.poll_recv(Duration::from_millis(100)).await {
            Ok(Some(msg)) =>  match msg {
                ToNatServerMsg::GetClients(clients) => {
                    let clients = state.get_clients(clients.app);
                    channel.send(ToNatClientMsg::Clients(clients)).await.unwrap();
                }
                ToNatServerMsg::AnnounceAndCheck(announce) => {
                    if let Some(incoming_connection) = state.announce_check(announce.clone(), addr) {
                        info!("[Reprise:P2P:TCP] {}: got pending connection from {} ({:.1}s left)",
                            announce, incoming_connection.addr,
                            incoming_connection.tm.saturating_duration_since(Instant::now()).as_secs_f32());
                        if incoming_connection.tx.send(()).is_ok() {
                            info!("[Reprise:P2P:TCP] {:?}: Connection confirmed!", addr);
                            // schedule connection in SCHEDULE_CON_MS
                            channel.send(ToNatClientMsg::RemoteAddr(incoming_connection.addr)).await.unwrap();
                            channel.send(ToNatClientMsg::StartCountdown(Duration::from_millis(SCHEDULE_CON_MS))).await.unwrap();
                        }
                    }
                    else {
                        // no request available - drop connection
                        break;
                    }
                }
                ToNatServerMsg::ConnectionRequest(request) => {
                    if let Some((rx, dst_addr)) = state.insert_connection_request(request, addr) {
                        channel.send(ToNatClientMsg::RemoteAddr(dst_addr)).await.unwrap();

                        info!("[Reprise:P2P:TCP] {:?}: Inserted connection request to {:?}", addr, dst_addr);
                        match tokio::time::timeout(Duration::from_millis(CONNECTION_REQUEST_TIMEOUT_MS), rx).await {
                            Ok(Ok(())) => {
                                info!("[Reprise:P2P:TCP] {:?}: Connection confirmed!", addr);
                                // schedule connection in SCHEDULE_CON_MS
                                channel.send(ToNatClientMsg::StartCountdown(Duration::from_millis(SCHEDULE_CON_MS))).await.unwrap();
                            }
                            _ => {
                                // timeout or sender dropped
                            }
                        }

                        // at this point announcement could be removed by poll_update, but it's fine.
                        state.remove_connection_request(request.session);
                    }
                    else {
                        // requested client not found - drop connection
                        warn!("[Reprise:P2P:TCP] {:?}: Requested client not found - dropping connection!", addr);
                        break
                    }
                }
            }
            Ok(None) => continue,
            Err(e) => match e {
                ChannelError::ConnectionClosed => {
                    break;
                }
                e => {
                    warn!("[Reprise:P2P:TCP] Error receiving message from client {:?}: {:?}", addr, e);
                }
            }

        }
    }
}
