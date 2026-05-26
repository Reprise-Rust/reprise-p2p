
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use std::time::Duration;
use reprise_net_util::tcp_channel::{TcpChannel, TcpChannelMessages};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub enum ToNatServerMsg {
    AnnounceAndCheck(ClientAnnouncementData),
    GetClients(GetClients),
    ConnectionRequest(ConnectionRequest),
}

#[derive(Debug, Clone, PartialEq, bincode::Encode, bincode::Decode)]
pub struct ClientAnnouncementData {
    pub session: u64,
    pub app: String,
    pub username: String,
}

impl Display for ClientAnnouncementData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[{}] {}", self.app, self.username))
    }
}

#[derive(Debug, Clone, PartialEq, bincode::Encode, bincode::Decode)]
pub struct GetClients {
    pub app: String,
}


#[derive(Copy, Debug, Clone, PartialEq, bincode::Encode, bincode::Decode)]
pub struct ConnectionRequest {
    pub session: u64,
}
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct ClientAnnouncement {
    pub data: ClientAnnouncementData,
    pub addr: SocketAddr,
    pub tm_ago: Duration,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub enum ToNatClientMsg {
    Clients(Vec<ClientAnnouncement>),
    RemoteAddr(SocketAddr),
    StartCountdown(Duration),
}

pub struct NatClient;

pub struct NatServer;

impl TcpChannelMessages for NatClient {
    type TxMessage = ToNatServerMsg;
    type RxMessage = ToNatClientMsg;
}

impl TcpChannelMessages for NatServer {
    type TxMessage = ToNatClientMsg;
    type RxMessage = ToNatServerMsg;
}

pub type NatClientChannel = TcpChannel<NatClient>;
pub type NatServerChannel = TcpChannel<NatServer>;
