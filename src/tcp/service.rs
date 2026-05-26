use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use log::{info, trace, warn};
use reprise_net_util::tcp_channel::ChannelError;
use tokio::net::TcpStream;
use tokio::time;
use crate::tcp::messages::{ClientAnnouncementData, NatClientChannel, ToNatClientMsg, ToNatServerMsg};
use crate::tcp::RequestError;
use crate::tcp::reusable_tcp_socket::ReusableTcpSocket;

pub struct P2PTcpService {
    nat_server: SocketAddr,
    parent_socket: ReusableTcpSocket,
    adv_data: ClientAnnouncementData,
}

impl P2PTcpService {
    /// Create new TcpService - advertise our service to helper server (`crate::server::run_server`)
    ///
    /// Default server port is 47002
    pub fn new(nat_addr: impl Into<SocketAddr>, adv_data: ClientAnnouncementData) -> Self {
        let parent_socket = ReusableTcpSocket::new();
        Self {
            parent_socket,
            nat_server: nat_addr.into(),
            adv_data
        }
    }
    pub fn adv_data(&self) -> &ClientAnnouncementData {
        &self.adv_data
    }
    pub fn set_adv_data(&mut self, data: ClientAnnouncementData) {
        self.adv_data = data;
    }

    /// Dual function polling method:
    /// 1) Place announcement to server so other clients can place connection request
    /// 2) Check for incoming connection requests, consume one if exists, try establish p2p connection and return socket connected to remote client.
    ///
    /// Should be called with 1s interval
    pub async fn poll_accept(&mut self) -> Result<(TcpStream, SocketAddr), RequestError> {
        let socket = self.parent_socket.clone();
        let res = time::timeout(Duration::from_secs(10), socket.connect(self.nat_server)).await;
        if let Ok(Ok(con)) = res {
            let mut nat_server_channel = NatClientChannel::new(con, Duration::from_secs(5), Duration::from_secs(5), 1_000);
            let res = nat_server_channel.send(ToNatServerMsg::AnnounceAndCheck(self.adv_data.clone())).await;
            if let Ok(_) = res {

                // 1) receive address
                let remote_addr = match nat_server_channel.recv_exact_msg(Duration::from_secs(3), |m| {
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
                    Ok(None) => {
                        return Err(RequestError::NoResponse);
                    }
                    Err(ChannelError::ConnectionClosed) => {
                        // early return - no pending connections
                        return Err(RequestError::NoPendingConnections);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };

                // 2) wait for countdown start
                let wait_dur = match nat_server_channel.recv_exact_msg(Duration::from_secs(3), |m| {
                    if let ToNatClientMsg::StartCountdown(wait_dur) = m {
                        Some(*wait_dur)
                    }
                    else {
                        None
                    }
                }).await {
                    Ok(Some(wait_dur)) => {
                        wait_dur
                    }
                    Ok(None) => {
                        return Err(RequestError::NoResponse);
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };
                let wait_dur = wait_dur.min(Duration::from_secs(2));

                info!("[Reprise:P2P:TCP] Starting countdown for remote addr {:?}: {}ms", remote_addr, wait_dur.as_millis());
                time::sleep(wait_dur).await;

                let deadline = Instant::now() + Duration::from_millis(500);
                let mut res = Err(RequestError::P2pConnectionFailed);
                while Instant::now() < deadline {
                    let socket = self.parent_socket.clone();
                    trace!("[Reprise:P2P:TCP] Connecting to {:?}!", remote_addr);

                    match time::timeout(Duration::from_secs(1), socket.connect(remote_addr)).await {
                        Ok(Ok(con)) =>  {
                            res = Ok((con, remote_addr));
                            break;
                        }
                        e =>  {
                            warn!("[Reprise:P2P:TCP] Failed to accept incoming P2P connection! {:?}", e);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }

                // now we can drop old connection
                drop(nat_server_channel);
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