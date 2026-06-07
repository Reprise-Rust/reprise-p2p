use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use log::{info, trace};
use reprise_net_util::tcp_channel::{ChannelError, WriteError};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time;
use crate::tcp::messages::{ClientAnnouncement, ConnectionRequest, GetClients, NatClientChannel, ToNatClientMsg, ToNatServerMsg};
use crate::tcp::reusable_tcp_socket::ReusableTcpSocket;

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("Failed to establish direct TCP connection with client")]
    P2pConnectionFailed,
    #[error("Did not find client with given session id")]
    NoSessionId,
    #[error("Connection to helper server failed")]
    ConnectionFailed(io::Error),
    #[error("No response from server")]
    NoResponse,
    #[error("Channel error: {0}")]
    ChannelError(#[from] ChannelError),
    #[error("Channel error during sending: {0}")]
    WriteError(#[from] WriteError),
    #[error("Did not find any new incoming connection requests on helper server")]
    NoPendingConnections,
}

pub struct P2PTcpConnector {
    nat_server: SocketAddr,
    parent_socket: ReusableTcpSocket,
}

impl P2PTcpConnector {
    /// Create new TcpConnector - connect to other clients other NAT via helper server (`crate::server::run_server`)
    ///
    /// Default server port is 47002
    pub fn new(nat_addr: impl Into<SocketAddr>) -> Self {
        let parent_socket = ReusableTcpSocket::new();
        Self {
            parent_socket,
            nat_server: nat_addr.into(),
        }
    }

    pub async fn scan_connections(&mut self) -> Result<Vec<ClientAnnouncement>, RequestError> {
        let socket = self.parent_socket.clone();
        let res = time::timeout(Duration::from_secs(10), socket.connect(self.nat_server)).await;
        if let Ok(Ok(con)) = res {
            let mut channel = NatClientChannel::new(con, Duration::from_secs(5), Duration::from_secs(5), 1_000);

            trace!("[Reprise:P2P:TCP] Scanning clients...");
            let res = channel.send(ToNatServerMsg::GetClients(GetClients {
                app: "test_app".to_string()
            })).await;
            if let Ok(_) = res {
                // receive response
                let clients = match channel.recv_exact_msg(Duration::from_secs(3), |m| {
                    if let ToNatClientMsg::Clients(clients) = m {
                        Some(clients.clone())
                    }
                    else {
                        None
                    }
                }).await {
                    Ok(Some(clients)) => {
                        clients
                    }
                    Ok(None) => {
                        return Err(RequestError::NoResponse);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };

                Ok(clients)
            }
            else if let Err(e) = res {
                Err(e.into())
            }
            // covered all cases
            else { unreachable!() }
        }
        else if let Err(_) = res {
            Err(RequestError::ConnectionFailed(io::Error::from(io::ErrorKind::TimedOut)))
        }
        else if let Ok(Err(e)) = res  {
            Err(RequestError::ConnectionFailed(e))
        }
        // covered all cases
        else { unreachable!(); }
    }

    pub async fn connect_client(&mut self, session: u64) -> Result<(TcpStream, SocketAddr), RequestError> {
        let socket = self.parent_socket.clone();
        let res = time::timeout(Duration::from_secs(10), socket.connect(self.nat_server)).await;
        if let Ok(Ok(con)) = res {
            let mut channel = NatClientChannel::new(con, Duration::from_secs(5), Duration::from_secs(5), 1_000);

            trace!("[Reprise:P2P:TCP] Sending connection request...");
            let res = channel.send(ToNatServerMsg::ConnectionRequest(ConnectionRequest {
                session
            })).await;
            if let Ok(_) = res {
                // 1) receive remote address
                let remote_addr = match channel.recv_exact_msg(Duration::from_secs(3), |m| {
                    if let ToNatClientMsg::RemoteAddr(addr) = m {
                        Some(*addr)
                    }
                    else {
                        None
                    }
                }).await {
                    Ok(Some(addr)) => {
                        addr
                    }
                    Ok(None) | Err(ChannelError::ConnectionClosed) => {
                        return Err(RequestError::NoSessionId);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };

                // 2) receive countdown signal
                let dur = match channel.recv_exact_msg(Duration::from_secs(3), |m| {
                    if let ToNatClientMsg::StartCountdown(dur) = m {
                        Some(*dur)
                    }
                    else {
                        None
                    }
                }).await {
                    Ok(Some(addr)) => {
                        addr
                    }
                    Ok(None) => {
                        return Err(RequestError::NoResponse);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };
                let dur = dur.min(Duration::from_secs(2));

                info!("[Reprise:P2P:TCP] Starting countdown for remote addr {:?}: {}ms", remote_addr, dur.as_millis());
                time::sleep(dur).await;

                let deadline = Instant::now() + Duration::from_millis(500);
                let mut res = Err(RequestError::P2pConnectionFailed);
                while Instant::now() < deadline {
                    let socket = self.parent_socket.clone();
                    trace!("[Reprise:P2P:TCP] Connecting to {:?}!", remote_addr);
                    match time::timeout(Duration::from_secs(1), socket.connect(remote_addr)).await {
                        Ok(Ok(con)) => {
                            let local = con.local_addr().ok();
                            info!("[Reprise:P2P:TCP] Connected to {} (local: {:?})", remote_addr, local);
                            res = Ok((con, remote_addr));
                            break;
                        }
                        e => {
                            trace!("[Reprise:P2P:TCP] Failed to establish direct client connection! {:?}", e);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }

                // now we can drop nat server connection
                drop(channel);
                // rotate ports for next connection
                self.parent_socket.rotate_port();

                res
            }
            else if let Err(e) = res  {
                Err(e.into())
            }
            // covered all cases
            else { unreachable!() }
        }
        else if let Err(_) = res {
            Err(RequestError::ConnectionFailed(io::Error::from(io::ErrorKind::TimedOut)))
        }
        else if let Ok(Err(e)) = res  {
            Err(RequestError::ConnectionFailed(e))
        }
        // covered all cases
        else { unreachable!() }
    }
}
