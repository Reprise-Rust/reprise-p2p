use if_addrs::{IfAddr, Ifv4Addr, Interface};
use log::info;
use multicast_discovery_socket::interfaces::InterfaceTracker;

pub struct P2pInterfaceTracker {
    interface_tracker: InterfaceTracker<()>,
    prev_interface: String,
}

impl P2pInterfaceTracker {
    pub fn new() -> Self {
        Self {
            interface_tracker: InterfaceTracker::new(),
            prev_interface: String::new(),
        }
    }

    pub fn current_interface(&mut self) -> Option<Interface> {
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
            if current_priority == highest_priority && let Some(ref prev_best) = best_interface {
                if i.addr.ip() > prev_best.addr.ip() { // sort must be stable, but this can be a bad criteria (if we stuck in incorrect interface)
                    best_interface = Some(i.clone());
                }
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

        best_interface
    }
}