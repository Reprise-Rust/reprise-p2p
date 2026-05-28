use std::cell::OnceCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use log::info;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{UdpSocket};
use crate::p2p_interface_tracker::P2pInterfaceTracker;

pub struct ReusableUdpSocket {
    socket: Socket,
    p2p_interface_tracker: OnceCell<P2pInterfaceTracker>,
}
impl ReusableUdpSocket {
    fn new_inner(p2p_interface_tracker: Option<P2pInterfaceTracker>) -> Self {
        let parent_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        parent_socket.set_reuse_address(true).unwrap();
        #[cfg(not(windows))]
        parent_socket.set_reuse_port(true).unwrap();
        parent_socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()).unwrap();

        info!("Socket local address: {:?}", parent_socket.local_addr().unwrap());

        Self {
            socket: parent_socket,
            p2p_interface_tracker: OnceCell::from(p2p_interface_tracker.unwrap_or_else(P2pInterfaceTracker::new)),
        }
    }

    pub fn new() -> Self {
        Self::new_inner(None)
    }

    pub async fn new_connection(&mut self, remote: SocketAddrV4) -> UdpSocket {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.set_reuse_address(true).unwrap();
        #[cfg(not(windows))]
        socket.set_reuse_port(true).unwrap();

        self.p2p_interface_tracker.get_or_init(P2pInterfaceTracker::new);
        let interface_tracker = self.p2p_interface_tracker.get_mut().unwrap();
        
        let best_interface = interface_tracker.current_interface();
        let addr = if cfg!(windows) && let Some(i) = &best_interface {
            if let IpAddr::V4(addr) = i.addr.ip() {
                addr
            }
            else {
                // ipv6 addresses were filtered before
                unreachable!()
            }
        }
        else {
            Ipv4Addr::UNSPECIFIED
        };
        socket.bind(&SocketAddr::from((addr, self.local_addr().port())).into()).unwrap(); // bind to the same port and correct interface address
        #[cfg(not(windows))]
        if let Some(i) = best_interface {
            socket.bind_device(Some(i.name.as_bytes())).unwrap();
        };

        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true).unwrap();
        
        let res = UdpSocket::from_std(std_socket).unwrap();
        res.connect(remote).await.unwrap();
        res
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap().as_socket().unwrap()
    }
}
