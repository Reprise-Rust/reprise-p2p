use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use if_addrs::{IfAddr, Ifv4Addr};
use log::info;
use multicast_discovery_socket::interfaces::InterfaceTracker;
use tokio::net::TcpSocket;

pub struct ReusableTcpSocket {
    socket: TcpSocket,
    interface_tracker: InterfaceTracker<()>,
    prev_interface: String,
}
impl ReusableTcpSocket {
    fn new_inner() -> Self {
        let interface_tracker = InterfaceTracker::new();

        let parent_socket = TcpSocket::new_v4().unwrap();
        parent_socket.set_reuseaddr(true).unwrap();
        #[cfg(not(windows))]
        parent_socket.set_reuseport(true).unwrap();
        parent_socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED,0))).unwrap();
        info!("Socket local address: {:?}", parent_socket.local_addr().unwrap());

        Self {
            socket: parent_socket,
            interface_tracker,
            prev_interface: String::new(),
        }
    }

    pub fn new() -> Self {
        let mut socket = Self::new_inner();
        // #[cfg(windows)]
        {
            // call listen to force show firewall exception prompt on windows
            let socket = socket.clone();
            let listener = socket.listen(1024).unwrap();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_millis(1), listener.accept()).await;
            });
        }
        socket
    }

    pub fn rotate_port(&mut self) -> Self {
        let mut new = Self::new_inner();
        new.prev_interface = new.prev_interface;
        new
    }

    pub fn clone(&mut self) -> TcpSocket {
        self.interface_tracker.poll_updates(|i| {});
        let mut best_interface = None;
        let mut highest_priority = 0;

        for (i, _) in self.interface_tracker.iter_mut() {
            let name = i.name.as_str();

            // 1. Hard filter: Skip interfaces that are definitively virtual/VPN/Local
            if i.is_p2p ||
                i.addr.ip().is_ipv6() ||
                matches!(i.addr, IfAddr::V4(Ifv4Addr { prefixlen: 32, .. })) ||
                name.starts_with("lo") ||        // Loopback
                name.starts_with("docker") ||    // Docker default bridge
                name.starts_with("br-") ||       // Custom docker/VM bridges
                name.starts_with("veth") ||      // Virtual ethernet pairs
                name.starts_with("tun") ||       // OpenVPN / generic tunnels
                name.starts_with("tap") ||       // Layer 2 tunnels
                name.starts_with("wg") ||        // WireGuard
                name.starts_with("tailscale") ||    // Tailscale
                name.starts_with("amn")    // Tailscale

                ||
            // windows adapter names
                name.starts_with("AmneziaVPN") ||
                name.starts_with("Tailscale") ||
                name.starts_with("ZeroTier") ||
                name.starts_with("outline")
            {
                continue;
            }

            // 2. Score the remaining valid interfaces
            let current_priority = if name.starts_with("en") || name.starts_with("eth") || name.starts_with("Ethernet") {
                3 // Highest priority: Wired Ethernet (e.g., enp3s0)
            } else if name.starts_with("wl") || name.starts_with("Wireless") {
                2 // Medium priority: Wireless (e.g., wlp4s0)
            } else {
                1 // Lowest priority: Unknown prefix, but passed the filter
            };

            // 3. Keep the interface with the best score
            if current_priority > highest_priority {
                highest_priority = current_priority;
                best_interface = Some(i.clone());
            }
        }

        if let Some(i) = &best_interface {
            if self.prev_interface != i.name && !self.prev_interface.is_empty(){
                info!("Network interface changed: {} -> {}", self.prev_interface, i.name);
            }
            if self.prev_interface.is_empty() && !i.name.is_empty() {
                info!("Selected interface: {}", i.name);
            }
            self.prev_interface = i.name.to_string();
        }

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        #[cfg(not(windows))]
        socket.set_reuseport(true).unwrap();
        socket.set_zero_linger().unwrap();
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
        socket.bind((addr, self.socket.local_addr().unwrap().port()).into()).unwrap();
        #[cfg(not(windows))]
        if let Some(i) = best_interface {
            socket.bind_device(Some(i.name.as_bytes())).unwrap();
        };

        socket
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }
}
