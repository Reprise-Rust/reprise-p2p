use std::borrow::Cow;
use std::collections::{BTreeMap, Bound};
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{anyhow, Context};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use if_addrs::Interface;
use log::{debug, error, info, warn};
use multicast_discovery_socket::config::MulticastDiscoveryConfig;
use multicast_discovery_socket::{MulticastDiscoverySocket, PollResult};
use quinn::{rustls, EndpointConfig, TransportConfig};
use rand::seq::SliceRandom;
use rand::random;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::p2p_interface_tracker::P2pInterfaceTracker;
use crate::udp::client::peer_state::PeerState;
use crate::udp::messages;
use crate::udp::messages::{transform_discovery_data, FromServerMessage, PublicKey, ToServerRawMessage};
use crate::udp::quic;

const HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS: u64 = 100;
const HOLE_PUNCH_FAILED_MAX_TIMEOUT_MS: u64 = 5_000;
const LOCAL_DISCOVERY_DURATION_SECS: u64 = 6;
const LOCAL_DISCOVERY_ENABLE_DELAY_SECS: u64 = 3;

enum PeerStateKind {
    ConnectionActive,
    Enabled,
    DisabledUntil(Instant),
}

mod peer_state {
    use std::cmp::min;
    use std::time::{Duration, Instant};
    use log::info;
    use crate::udp::client::{PeerStateKind, HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS, HOLE_PUNCH_FAILED_MAX_TIMEOUT_MS, LOCAL_DISCOVERY_DURATION_SECS};

    pub struct PeerState {
        /// Logical connection state for this peer
        state_kind: PeerStateKind,

        failure_retry_timeout: Duration,
        /// The last `remote_session_id` we accepted from the server for this peer.
        /// Used to ignore duplicate notifications.
        last_accepted_session_id: Option<u32>,
        last_error_same_ip: Option<Instant>,
    }


    impl PeerState {
        pub fn is_server_discovery_enabled(&self) -> bool {
            !self.is_local_discovery_enabled() && match self.state_kind {
                PeerStateKind::ConnectionActive => false,
                PeerStateKind::DisabledUntil(i) => i < Instant::now(),
                PeerStateKind::Enabled => true,
            }
        }

        pub fn is_local_discovery_enabled(&self) -> bool {
            self.last_error_same_ip.is_some_and(|t| t.elapsed() < Duration::from_secs(LOCAL_DISCOVERY_DURATION_SECS))
        }

        /// Can only be called after creation or on_hole_punch_err/resume_discovery/on_new_connection_request
        /// when got new request from p2p server. Next call: on_hole_punch_err or on_connection_established 
        /// Returns false if session id is invalid (matches previous session id for client)
        pub fn on_new_connection_request(&mut self, remote_session_id: u32) -> bool {
            if self.last_accepted_session_id == Some(remote_session_id) {
                return false
            }
            self.last_error_same_ip = None;
            self.last_accepted_session_id = Some(remote_session_id);
            true
        }

        /// Can only be called after on_new_connection_request
        pub fn on_hole_punch_err(&mut self) {
            self.state_kind = PeerStateKind::DisabledUntil(Instant::now() + self.failure_retry_timeout);
            self.failure_retry_timeout += min(self.failure_retry_timeout, Duration::from_secs(1));
            self.failure_retry_timeout = self.failure_retry_timeout.min(Duration::from_millis(HOLE_PUNCH_FAILED_MAX_TIMEOUT_MS));
        }

        pub fn on_error_same_ip(&mut self) {
            if !matches!(self.state_kind, PeerStateKind::ConnectionActive) {
                self.last_error_same_ip = Some(Instant::now());
                info!("Got err same ip");
            }
        }

        /// Can only be called after on_new_connection_request
        pub fn on_connection_established(&mut self) {
            self.state_kind = PeerStateKind::ConnectionActive;
            self.failure_retry_timeout = Duration::from_millis(HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS);
        }
        
        
        /// Can only be called after on_connection_established
        pub fn resume_discovery(&mut self) {
            self.state_kind = PeerStateKind::Enabled;
        }
    }

    impl Default for PeerState {
        fn default() -> Self {
            Self {
                state_kind: PeerStateKind::Enabled,
                failure_retry_timeout: Duration::from_millis(HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS),
                last_accepted_session_id: None,
                last_error_same_ip: None
            }
        }
    }
}

struct LocalDiscovery {
    local_discovery_config: LocalDiscoveryConfig,
    multicast_discovery_socket: MulticastDiscoverySocket<[u8; 32]>,
    socket: UdpSocket,
}

pub struct UdpConnectionEstablisher {
    p2p_server_addr: SocketAddrV4,
    trusted_remotes: BTreeMap<PublicKey, PeerState>,
    last_request_tm: Option<Instant>,
    key: SigningKey,
    session_id: u32,
    socket: UdpSocket,
    local_discovery: Option<LocalDiscovery>,
    p2p_interface_tracker: P2pInterfaceTracker,
    cur_interface: Option<String>,
    last_p2p_server_ping_send_tm: Option<Instant>,
    last_p2p_server_ping: Option<(Instant, u64)>,
    last_p2p_server_pong: Option<Instant>,
    /// Keep first 5 seconds of polling with local discovery disabled
    poll_start_tm: Option<Instant>,
}

const REQUEST_PLACEMENT_INTERVAL: u64 = 1;

/// A fully hole-punched, ready-to-use P2P connection.
pub struct NewP2pConnection {
    pub pubkey: PublicKey,
    pub remote_addr: SocketAddr,
    pub socket: UdpSocket,
    pub is_listener: bool,
}

async fn new_udp_socket(best_interface: Option<Interface>) -> UdpSocket {
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

    let socket = UdpSocket::bind((addr, 0)).await;
    let Ok(socket) = socket else {
        // fallback - default socket bind
        return UdpSocket::bind("0.0.0.0:0").await.unwrap()
    };
    #[cfg(not(windows))]
    if let Some(i) = best_interface {
        if let Err(e) = socket.bind_device(Some(i.name.as_bytes())) {
            warn!("Failed to bind socket to specific device {}", i.name)
        }
    };
    socket
}

#[derive(Clone)]
pub struct LocalDiscoveryConfig {
    pub multicast_group_addr: Ipv4Addr,
    pub service_name: Cow<'static, str>,
    pub obfuscation_key: String,
}

#[derive(Error)]
pub struct HolePunchError {
    got_punch: bool,
    got_ack: bool,
}

impl Display for HolePunchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.got_ack && !self.got_punch {

            f.write_str("Did not receive packets from client at all!")
        }
        else if self.got_ack {
            f.write_str("We got ack from client, but missed punch packet (strange)")
        }
        else {
            f.write_str("We got punch but did not receive ack")
        }
    }
}
impl Debug for HolePunchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

impl UdpConnectionEstablisher {
    /// Create a new `UdpConnectionEstablisher` with the given signing key and P2P server address.
    /// key is not validated for other peers! it is only used for signing messages to the P2P server and identification of other peers.
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4, local_discovery_config: Option<LocalDiscoveryConfig>) -> UdpConnectionEstablisher {
        if let Some(error) = check_system_time_error().await {
            if error > 0.0 {
                error!("System time invalid! time difference: +{:.02} hours", error);
            }
            else {
                error!("System time invalid! time difference: -{:.02} hours", -error);
            }
        }


        let local_discovery = if let Some(local_discovery_config) = local_discovery_config {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.expect("Creating socket for local discovery");
            let local_port = socket.local_addr().unwrap().port();
            let multicast_discovery_config = &MulticastDiscoveryConfig::new(local_discovery_config.multicast_group_addr.clone(), local_discovery_config.service_name.clone());

            Some(LocalDiscovery {
                socket,
                multicast_discovery_socket: MulticastDiscoverySocket::new_with_service(
                    multicast_discovery_config,
                    local_port,
                    transform_discovery_data(key.verifying_key().to_bytes(), local_discovery_config.obfuscation_key.clone())).unwrap(),
                local_discovery_config
            })
        } else {
            None
        };

        let mut p2p_interface_tracker = P2pInterfaceTracker::new();
        UdpConnectionEstablisher {
            last_request_tm: None,
            trusted_remotes: BTreeMap::new(),
            poll_start_tm: None,
            key,
            p2p_server_addr,
            session_id: random(),
            socket: new_udp_socket(p2p_interface_tracker.current_interface()).await,
            cur_interface: p2p_interface_tracker.current_interface().map(|i| i.name),
            p2p_interface_tracker,
            local_discovery,
            last_p2p_server_ping_send_tm: None,
            last_p2p_server_ping: None,
            last_p2p_server_pong: None,
        }
    }

    pub fn add_trusted_remote(&mut self, key: PublicKey) {
        if self.trusted_remotes.get(&key).is_none() {
            // reset last request tm to send new trusted remotes list as soon as possible
            self.last_request_tm = None;
        }
        self.trusted_remotes.entry(key).or_default();
    }

    /// This will re-enable discovery for this peer
    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        if self.trusted_remotes.get(&key).is_some() {
            // reset last request tm to send new trusted remotes list as soon as possible
            self.last_request_tm = None;
        }
        self.trusted_remotes.remove(&key);
    }

    pub fn set_trusted_remote_list(&mut self, new_trusted_remotes: Vec<PublicKey>) {
        // add new
        for trusted in &new_trusted_remotes {
            self.add_trusted_remote(*trusted)
        }
        // remove old
        self.trusted_remotes.retain(|k, _| {
            let should_keep = new_trusted_remotes.contains(k);
            if !should_keep {
                // reset last request tm to send new trusted remotes list as soon as possible
                self.last_request_tm = None;
            }
            should_keep
        });
    }

    /// Feedback method. Call this after connection returned by poll_accept failed or closed
    /// This will re-enable discovery for this peer
    pub fn on_connection_closed(&mut self, key: PublicKey) {
        self.trusted_remotes.entry(key).or_default().resume_discovery();
        // reset last request tm to send new trusted remotes list as soon as possible
        self.last_request_tm = None;
    }

    /// Take up to 50 trusted remotes. If there are more than 50, pick exactly 50 at random.
    fn new_available_remotes_list(&mut self) -> Vec<PublicKey> {
        let mut available: Vec<PublicKey> = self.trusted_remotes.iter()
            .filter(|(_, s)| s.is_server_discovery_enabled())
            .map(|(k, _)| *k)
            .collect();

        if available.len() > 50 {
            available.shuffle(&mut rand::rng());
            available.truncate(50);
        }

        available
    }
    async fn place_connection_requests(&mut self, peer_pubkeys_list: Vec<PublicKey>) -> anyhow::Result<()> {
        let socket = &self.socket;

        let payload = messages::ToServerSignedMessage::ConnectionRequest {
            peer_pubkeys: peer_pubkeys_list,
            session_id: self.session_id,
        }.to_bytes(&self.key);
        let res = socket.send_to(&payload, self.p2p_server_addr).await;
        if let Err(e) = res {
            warn!("Failed to place connection request: {}", e);
        }
        self.last_request_tm = Some(Instant::now());

        Ok(())
    }

    /// Perform the full hole punch handshake on the given socket.
    /// Returns the actual peer address (may differ from `peer` under symmetric NAT)
    /// if the hole was successfully punched.
    ///
    /// Uses `send_to`/`recv_from` instead of `connect` so we can discover the peer's
    /// actual source port. This is required for symmetric NAT traversal: when a peer
    /// behind symmetric NAT sends to us, the source port we see differs from the
    /// server-reported port. We must reply to the actual source port.
    async fn hole_punch(socket: &UdpSocket, peer: SocketAddrV4) -> Result<SocketAddr, HolePunchError> {
        info!("Starting hole punch to {}...", peer);

        let mut cur_send_dst = peer.into();
        let punch_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut punch_interval = tokio::time::interval(Duration::from_millis(20));
        let mut got_punch = false;
        let mut got_punch_ack = false;

        let mut buf = vec![0u8; 2000];
        loop {
            let now = tokio::time::Instant::now();
            if now >= punch_deadline {
                break;
            }
            if got_punch && got_punch_ack {
                break;
            }

            tokio::select! {
                _ = punch_interval.tick() => {
                    if let Err(e) = socket.send_to(b"punch", cur_send_dst).await {
                        warn!("Error sending punch message: {:?}", e)
                    }
                }
                recv = socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((sz, src)) => {
                            let msg = &buf[..sz];
                            if msg == b"punch" {
                                if src != cur_send_dst {
                                    info!("Received punch from {} (expected {}), sending ack", src, peer);
                                    cur_send_dst = src;
                                }
                                let _ = socket.send_to(b"punch ack", src).await;
                                got_punch = true;
                            } else if msg == b"punch ack" {
                                info!("Received punch ack from {} (expected {})", src, peer);
                                got_punch_ack = true;
                            }
                        }
                        Err(e) => {
                            warn!("Recv error during punch: {:?}", e);
                        }
                    }
                }
            }
        }

        if !got_punch || !got_punch_ack {
            warn!("Hole punching failed (timeout) — got_punch={}, got_punch_ack={}", got_punch, got_punch_ack);
            return Err(HolePunchError {
                got_ack: got_punch_ack,
                got_punch
            });
        }

        // Phase 2: Drain remaining punch/ack packets (200ms)
        info!("Punch exchange done, draining socket...");
        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            let now = tokio::time::Instant::now();
            if now >= drain_deadline {
                break;
            }
            match tokio::time::timeout_at(drain_deadline, socket.recv_from(&mut buf)).await {
                Ok(Ok((sz, _src))) => {
                    let msg = &buf[..sz];
                    if msg != b"punch" && msg != b"punch ack" {
                        warn!("Unexpected packet during drain: {:?}", msg);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Recv error during drain: {:?}", e);
                }
                Err(_) => {
                    break;
                }
            }
        }

        // Phase 3: Settle (200ms)
        info!("Drain done, settling...");
        tokio::time::sleep(Duration::from_millis(200)).await;

        info!("Hole punched with {} (local: {:?})!", cur_send_dst, socket.local_addr().ok());
        Ok(cur_send_dst)
    }

    /// Block for `dur`, returning a new hole-punched connection or an error.
    /// The returned connection has already completed the full hole punch handshake
    /// and is ready for immediate send/recv use.
    ///
    /// In case of error or no clients to accept, block for 100ms
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<anyhow::Result<NewP2pConnection>> {
        if self.poll_start_tm.is_none() {
            self.poll_start_tm = Some(Instant::now());
        }

        let cur_interface = self.p2p_interface_tracker.current_interface().clone();
        let cur_interface_name = cur_interface.as_ref().map(|i| i.name.clone());
        if cur_interface_name != self.cur_interface {
            self.socket = new_udp_socket(cur_interface.clone()).await;
            if let Some(ref mut local_disc) = self.local_discovery {
                local_disc.socket = new_udp_socket(cur_interface.clone()).await;
                *local_disc.multicast_discovery_socket.local_service_port().unwrap() = local_disc.socket.local_addr().unwrap().port();
            }
            self.cur_interface = cur_interface_name;
        }

        if let Some(local_discovery) = self.local_discovery.as_mut() {
            'local_discovery: {
                // 1) multicast discovery
                // 1.1) announcement enable decision and polling
                let announcement_enabled = self.poll_start_tm.is_some_and(|tm| tm.elapsed().as_secs() > LOCAL_DISCOVERY_ENABLE_DELAY_SECS) &&
                    (self.last_p2p_server_pong.is_some_and(|tm| tm.elapsed().as_secs() < 10) || self.trusted_remotes.iter().any(|(_, s)| s.is_local_discovery_enabled()));

                local_discovery.multicast_discovery_socket.set_announce_en(announcement_enabled);
                local_discovery.multicast_discovery_socket.set_discover_replies_en(announcement_enabled);

                let mut res = None;
                local_discovery.multicast_discovery_socket.poll(|msg| {
                    match msg {
                        PollResult::DiscoveredClient {
                            addr,
                            discover_id,
                            adv_data
                        } => {
                            for pubkey in self.trusted_remotes.keys() {
                                let remote_obf_key = transform_discovery_data(*pubkey, local_discovery.local_discovery_config.obfuscation_key.clone());
                                if remote_obf_key == *adv_data {
                                    if is_local_discovery_enabled_for(&self.last_p2p_server_pong, &self.trusted_remotes, &pubkey) && self.trusted_remotes.get(pubkey).map(|s| s.is_server_discovery_enabled()).unwrap_or(false) {
                                        res = Some((addr, pubkey));
                                    }
                                }
                            }
                        }
                        PollResult::DisconnectedClient {
                            addr,
                            discover_id
                        } => {


                        }
                    }
                });

                if let Some((addr, pubkey)) = res {
                    info!("Discovered client {} via local discovery, trying to connect...", addr);
                    let mut buf = Vec::new();
                    buf.extend_from_slice(b"multicast-discovery-p2p");
                    buf.extend_from_slice(&self.key.verifying_key().to_bytes());
                    match local_discovery.socket.try_send_to(&buf, addr.into()) {
                        Ok(sz) => {
                            if sz != buf.len() {
                                warn!("[local disyovery connection] Invalid sent data size!");
                                break 'local_discovery;
                            }
                        }
                        Err(e) => {
                            warn!("[local discovery connection] Failed to send udp message");
                            break 'local_discovery;
                        }
                    }

                    let socket = new_udp_socket(self.p2p_interface_tracker.current_interface()).await;

                    return Some(Ok(NewP2pConnection {
                        pubkey: *pubkey,
                        remote_addr: addr.into(),
                        is_listener: false,
                        socket
                    }))
                }

                // 1.2) multicast discovery client connection
                let mut buf = [0; 100];
                if let Ok((sz, addr)) = local_discovery.socket.try_recv_from(&mut buf) {
                    let msg = &buf[..sz];
                    let pattern = b"multicast-discovery-p2p";
                    if msg.starts_with(pattern) && msg.len() == 32 + pattern.len() {
                        let pubkey_bytes = &msg[pattern.len()..];
                        if let Ok(pubkey) = PublicKey::try_from(pubkey_bytes) {
                            if is_local_discovery_enabled_for(&self.last_p2p_server_pong, &self.trusted_remotes, &pubkey) && self.trusted_remotes.get(&pubkey).map(|s| s.is_server_discovery_enabled()).unwrap_or(false) {
                                info!("Received multicast discovery connection from {}, trying to connect...", addr);

                                let socket = mem::replace(&mut local_discovery.socket, new_udp_socket(self.p2p_interface_tracker.current_interface()).await);
                                *local_discovery.multicast_discovery_socket.local_service_port().unwrap() = local_discovery.socket.local_addr().unwrap().port();

                                return Some(Ok(NewP2pConnection {
                                    pubkey,
                                    remote_addr: addr,
                                    is_listener: true,
                                    socket,
                                }))
                            }
                        }
                    }
                }
            }
        }

        // 2.1) server-assisted discovery, server ping
        if self.last_p2p_server_ping_send_tm.is_none_or(|i| i.elapsed().as_secs() > 3) {
            self.last_p2p_server_ping_send_tm = Some(Instant::now());
            let payload = random();
            let ping_packet = ToServerRawMessage::Ping {
                payload
            };

            let res = self.socket.send_to(&ping_packet.to_bytes(), self.p2p_server_addr).await;
            if let Err(e) = res {
                warn!("Failed to send ping to p2p discovery server: {:?}", e);
            }
            else {
                self.last_p2p_server_ping = Some((Instant::now(), payload));
            }
        }
        // 2.2) server-assisted discovery, send requests
        if self.last_request_tm.is_none_or(|i| i.elapsed().as_secs() > REQUEST_PLACEMENT_INTERVAL) {
            let peer_pubkeys_list = self.new_available_remotes_list();

            if peer_pubkeys_list.is_empty() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                return None; // No requests to put on P2P server
            }

            if let Err(e) = self.place_connection_requests(peer_pubkeys_list).await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                return Some(Err(e).context("Placing connection request to P2P server"));
            }
        }

        let mut buf = vec![0; 2000];
        match timeout(dur, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((sz, addr))) => {
                // 1) parse as p2p server message
                if addr != self.p2p_server_addr.into() {
                    warn!("Ignoring UDP packet not from p2p server");
                    return None;
                }
                let msg = &buf[..sz];
                let res = FromServerMessage::try_parse(msg).context("Parsing message from P2P server");
                if let Ok(msg) = res {
                    match msg {
                        FromServerMessage::InitiateConnectionRequest {
                            peer_address,
                            peer_pubkey,
                            remote_session_id,
                            is_listener,
                        } => {
                            // use new session id for all future requests
                            let context = format!("Handling InitiateConnectionRequest from p2p server for peer {}, session_id={}", peer_address, remote_session_id);
                            if let Some(state) = self.trusted_remotes.get_mut(&peer_pubkey) {
                                if !state.is_server_discovery_enabled() {
                                    // According to local state, we are already connected to this client.
                                    debug!("Got duplicate connection notification, ignoring");
                                    return None;
                                }

                                if !state.on_new_connection_request(remote_session_id) {
                                    debug!("Got duplicate connection notification with same session_id, ignoring");
                                    return None;
                                }

                                // New valid connection request received from p2p server, swapping sockets and setting up new session id
                                info!("Starting server-initiated p2p connection to {}", peer_address);
                                let socket = mem::replace(&mut self.socket, new_udp_socket(self.p2p_interface_tracker.current_interface()).await);
                                self.session_id = random();

                                let actual_peer_addr = match Self::hole_punch(&socket, peer_address).await {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        state.on_hole_punch_err();
                                        return Some(Err(anyhow!(e).context(context)));
                                    }
                                };

                                // mark connection as connected (or connection in progress)
                                state.on_connection_established();
                                self.last_request_tm = None; // retry immediately on next poll
                                Some(Ok(NewP2pConnection {
                                    pubkey: peer_pubkey,
                                    remote_addr: actual_peer_addr,
                                    socket,
                                    is_listener,
                                }))
                            }
                            else {
                                debug!("Got connection request from p2p server, but client's pubkey is not in trusted list!");
                                Some(Err(anyhow::anyhow!("Peer pubkey not in trusted list")))
                            }
                        }
                        FromServerMessage::NeedNewSession {
                            old_session_id
                        } => {
                            if self.session_id == old_session_id {
                                self.session_id = random();
                                warn!("Got lost request, starting new session...");
                            }
                            None
                        }
                        FromServerMessage::ErrorSameIp {
                            peer_pubkey
                        } => {
                            if let Some(state) = self.trusted_remotes.get_mut(&peer_pubkey) {
                                state.on_error_same_ip();
                            }

                            None
                        }
                        FromServerMessage::Pong {
                            payload
                        } => {
                            if self.last_p2p_server_ping.is_none_or(|(tm, last_payload)| {
                                last_payload == payload && tm.elapsed().as_secs() < 10
                            }) {
                                self.last_p2p_server_pong = Some(Instant::now());
                            }

                            None
                        }
                    }
                }
                else {
                    let Err(e) = res else {unreachable!()};
                    warn!("Cannot parse message from p2p server: {}", e);
                    Some(Err(e))
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to receive message from server: {}", e);
                Some(Err(e).context("Receiving message from P2P server"))
            }
            Err(_) => {
                None // no new messages from P2P server
            }
        }
    }
}


fn is_local_discovery_enabled_for(last_p2p_server_pong: &Option<Instant>, trusted_remotes: &BTreeMap<PublicKey, PeerState>, pubkey: &PublicKey) -> bool {
    last_p2p_server_pong.is_some_and(|tm| tm.elapsed().as_secs() < 10)
        || trusted_remotes.get(pubkey).map(|s| s.is_local_discovery_enabled()).unwrap_or(false)
}


// If Some => your system time is off by `value` hours from real time
pub async fn check_system_time_error() -> Option<f32> {
    let system_time = Utc::now();
    match tokio::time::timeout(Duration::from_secs(1), reqwest::get("https://timeapi.io/api/v1/time/current/unix".to_string())).await {
        Err(_) => {
            // cannot connect to timeapi.io
        }
        Ok(Err(e)) => {
            // request error
        }
        Ok(Ok(res)) => {
            if let Ok(res) = res.text().await {
                let res = res.strip_prefix("{\"unix_timestamp\":")?;
                let res = res.strip_suffix("}")?;
                let tm: i64 = res.parse().ok()?;
                if tm.abs_diff(system_time.timestamp()) > 5 {
                    return Some((system_time.timestamp() - tm) as f32 / 3600.0);
                }
            }
        }
    }
    None
}

/// A QUIC connection established over a hole-punched UDP connection.
pub struct QuicP2pConnection {
    pub quic_connection: quinn::Connection,
    pub remote_pubkey: PublicKey,
    pub remote_addr: SocketAddr,
}

/// Wraps `UdpConnectionEstablisher` and additionally establishes a QUIC connection
/// on top of each hole-punched UDP connection.
pub struct UdpQuicConnectionEstablisher {
    inner: UdpConnectionEstablisher,
    signing_key: SigningKey,
    endpoint_config: EndpointConfig,
    transport_config: Arc<TransportConfig>,
}

impl UdpQuicConnectionEstablisher {
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4, local_discovery_config: Option<LocalDiscoveryConfig>, endpoint_config: EndpointConfig,
                     transport_config: Arc<TransportConfig>) -> UdpQuicConnectionEstablisher {
        let _ = rustls::crypto::ring::default_provider().install_default();
        UdpQuicConnectionEstablisher {
            signing_key: key.clone(),
            inner: UdpConnectionEstablisher::new(key, p2p_server_addr, local_discovery_config).await,
            endpoint_config,
            transport_config
        }
    }

    pub fn add_trusted_remote(&mut self, key: PublicKey) {
        self.inner.add_trusted_remote(key);
    }

    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        self.inner.remove_trusted_remote(key);
    }

    pub fn set_trusted_remote_list(&mut self, new_trusted_remotes: Vec<PublicKey>) {
        self.inner.set_trusted_remote_list(new_trusted_remotes);
    }

    /// Feedback method. Call this after connection returned by poll_accept failed or closed
    /// This will re-enable discovery for this peer
    pub fn on_connection_closed(&mut self, key: PublicKey) {
        self.inner.on_connection_closed(key);
    }


    /// Block for `dur`, returning a fully established QUIC connection or an error.
    /// Internally performs UDP hole-punching and then establishes a QUIC connection
    /// using the appropriate role (server/client).
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<anyhow::Result<QuicP2pConnection>> {
        let conn = match self.inner.poll_accept(dur).await? {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };

        let remote_addr = conn.remote_addr;
        let remote_pubkey = conn.pubkey;
        let is_listener = conn.is_listener;

        let ep = match quic::make_quin_endpoint(self.endpoint_config.clone(), self.transport_config.clone(), &self.signing_key, conn.socket.into_std().unwrap(), remote_pubkey).await {
            Ok(ep) => ep,
            Err(e) => {
                self.inner.on_connection_closed(remote_pubkey);
                return Some(Err(e));
            }
        };

        let res = if is_listener {
            quic::establish_server_quic_connection(ep).await.context("Establishing client quic connection")
        } else {
            quic::establish_client_quic_connection(ep, self.transport_config.clone(), &self.signing_key, remote_addr, remote_pubkey).await.context("Establishing server quic connection")
        };
        match res {
            Ok(quic_connection) => {
                info!("[Reprise:P2P:UDP:QUIC] Connection established with {:?} (remote: {})", remote_pubkey, remote_addr);
                Some(Ok(QuicP2pConnection {
                    quic_connection,
                    remote_pubkey,
                    remote_addr,
                }))
            }
            Err(e) => {
                self.inner.on_connection_closed(remote_pubkey);
                Some(Err(e))
            }
        }
    }
}
