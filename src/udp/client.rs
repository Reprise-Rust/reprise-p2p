use std::cmp::min;
use std::collections::{BTreeMap, Bound};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Context;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use if_addrs::Interface;
use log::{debug, error, info, warn};
use quinn::{rustls, EndpointConfig, TransportConfig};
use rand::random;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::p2p_interface_tracker::P2pInterfaceTracker;
use crate::udp::messages;
use crate::udp::messages::{FromServerMessage, PublicKey};
use crate::udp::quic;

const HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS: u64 = 100;
const HOLE_PUNCH_FAILED_MAX_TIMEOUT_MS: u64 = 5_000;

enum PeerStateKind {
    ConnectionActive,
    Enabled,
    DisabledUntil(Instant),
}

struct PeerState {
    /// Whether we're actively trying to connect to this peer.
    state_kind: PeerStateKind,
    failure_retry_timeout: Duration,
    /// The last `remote_session_id` we accepted from the server for this peer.
    /// Used to ignore duplicate notifications.
    last_accepted_session_id: Option<u32>,
}

impl PeerState {
    fn is_discovery_enabled(&self) -> bool {
        match self.state_kind {
            PeerStateKind::ConnectionActive => false,
            PeerStateKind::DisabledUntil(i) => i < Instant::now(),
            PeerStateKind::Enabled => true,
        }
    }
}

impl Default for PeerState {
    fn default() -> Self {
        Self {
            state_kind: PeerStateKind::Enabled,
            failure_retry_timeout: Duration::from_millis(HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS),
            last_accepted_session_id: None,
        }
    }
}

pub struct UdpConnectionEstablisher {
    p2p_server_addr: SocketAddrV4,
    trusted_remotes: BTreeMap<PublicKey, PeerState>,
    last_request_tm: Option<Instant>,
    key: SigningKey,
    session_id: u32,
    socket: UdpSocket,
    p2p_interface_tracker: P2pInterfaceTracker,
    cur_interface: Option<String>,
    last_trusted_peer_offset: PublicKey,
}

const REQUEST_PLACEMENT_INTERVAL: u64 = 2;

/// A fully hole-punched, ready-to-use P2P connection.
pub struct NewP2pConnection {
    pub pubkey: PublicKey,
    pub remote_addr: SocketAddrV4,
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

impl UdpConnectionEstablisher {
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4) -> UdpConnectionEstablisher {
        if let Some(error) = check_system_time_error().await {
            if error > 0.0 {
                error!("System time invalid! time difference: +{:.02} hours", error);
            }
            else {
                error!("System time invalid! time difference: -{:.02} hours", -error);
            }
        }

        let mut p2p_interface_tracker = P2pInterfaceTracker::new();
        UdpConnectionEstablisher {
            last_request_tm: None,
            trusted_remotes: BTreeMap::new(),
            key,
            p2p_server_addr,
            session_id: random(),
            socket: new_udp_socket(p2p_interface_tracker.current_interface()).await,
            cur_interface: p2p_interface_tracker.current_interface().map(|i| i.name),
            p2p_interface_tracker,
            last_trusted_peer_offset: PublicKey::default(),
        }
    }

    pub fn add_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.entry(key).or_default();
    }

    /// This will re-enable discovery for this peer
    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.remove(&key);
    }

    pub fn set_trusted_remote_list(&mut self, new_trusted_remotes: Vec<PublicKey>) {
        // add new
        for trusted in &new_trusted_remotes {
            self.trusted_remotes.entry(*trusted).or_default();
        }
        // remove old
        self.trusted_remotes.retain(|k, _| new_trusted_remotes.contains(k));
    }

    /// Feedback method. Call this after connection returned by poll_accept failed or closed
    /// This will re-enable discovery for this peer
    pub fn on_connection_closed(&mut self, key: PublicKey) {
        self.trusted_remotes.entry(key).or_default().state_kind = PeerStateKind::Enabled;
    }

    fn new_available_remotes_list(&mut self) -> Vec<PublicKey> {
        let iter_forward = self.trusted_remotes.range(self.last_trusted_peer_offset..);
        let iter_wrap = self.trusted_remotes.range(..self.last_trusted_peer_offset);

        let result: Vec<PublicKey> = iter_forward.chain(iter_wrap)
            .filter(|(_, s)| s.is_discovery_enabled())
            .take(10)
            .map(|(k, _)| *k)
            .collect();

        if let Some(last_key) = result.last() {
            let next_entry = self.trusted_remotes
                .range((Bound::Excluded(*last_key), Bound::Unbounded))
                .next();

            self.last_trusted_peer_offset = match next_entry {
                Some((k, _)) => *k,
                None => {
                    *self.trusted_remotes.keys().next().unwrap_or(last_key)
                }
            };
        }

        result
    }
    async fn place_connection_requests(&mut self, peer_pubkeys_list: Vec<PublicKey>) -> anyhow::Result<()> {
        let socket = &self.socket;
        socket.connect(&self.p2p_server_addr).await?;

        let payload = messages::ToServerSignedMessage::ConnectionRequest {
            peer_pubkeys: peer_pubkeys_list,
            session_id: self.session_id,
        }.to_bytes(&self.key);
        let res = socket.send(&payload).await;
        if let Err(e) = res {
            warn!("Failed to place connection request: {}", e);
        }
        self.last_request_tm = Some(Instant::now());

        Ok(())
    }

    /// Perform the full hole punch handshake on the given socket.
    /// Returns `true` if the hole was successfully punched.
    async fn hole_punch(socket: &UdpSocket, peer: SocketAddrV4) -> bool {
        // Phase 1: Punch exchange (up to 500ms)
        info!("Starting hole punch to {}...", peer);
        if let Err(e) = socket.connect(peer).await {
            warn!("Failed to `connect` to {peer} before starting hole punching!");
        }
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
                    if let Err(e) = socket.send(b"punch").await {
                        warn!("Error sending punch message: {:?}", e)
                    }
                }
                recv = socket.recv(&mut buf) => {
                    match recv {
                        Ok(sz) => {
                            let msg = &buf[..sz];
                            if msg == b"punch" {
                                info!("Received punch from {}, sending ack", peer);
                                let _ = socket.send(b"punch ack").await;
                                got_punch = true;
                            } else if msg == b"punch ack" {
                                info!("Received punch ack from {}", peer);
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
            return false;
        }

        // Phase 2: Drain remaining punch/ack packets (200ms)
        info!("Punch exchange done, draining socket...");
        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            let now = tokio::time::Instant::now();
            if now >= drain_deadline {
                break;
            }
            match tokio::time::timeout_at(drain_deadline, socket.recv(&mut buf)).await {
                Ok(Ok(sz)) => {
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

        info!("Hole punched with {}!", peer);
        true
    }

    /// Block for `dur`, returning a new hole-punched connection or an error.
    /// The returned connection has already completed the full hole punch handshake
    /// and is ready for immediate send/recv use.
    pub async fn poll_accept(&mut self, dur: Duration) -> Option<anyhow::Result<NewP2pConnection>> {
        let cur_interface = self.p2p_interface_tracker.current_interface();
        let cur_interface_name = cur_interface.as_ref().map(|i| i.name.clone());
        if cur_interface_name != self.cur_interface {
            self.socket = new_udp_socket(cur_interface).await;
            self.cur_interface = cur_interface_name;
        }

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
        match timeout(dur, self.socket.recv(&mut buf)).await {
            Ok(Ok(sz)) => {
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
                                if !state.is_discovery_enabled() {
                                    debug!("Got duplicate connection notification, ignoring");
                                    return None;
                                }

                                if state.last_accepted_session_id == Some(remote_session_id) {
                                    debug!("Got duplicate connection notification with same session_id, ignoring");
                                    return None;
                                }
                                state.last_accepted_session_id = Some(remote_session_id);

                                // New valid connection request received from p2p server, swapping sockets and setting up new session id
                                let socket = mem::replace(&mut self.socket, new_udp_socket(self.p2p_interface_tracker.current_interface()).await);
                                self.session_id = random();

                                if !Self::hole_punch(&socket, peer_address).await {
                                    state.state_kind = PeerStateKind::DisabledUntil(Instant::now() + state.failure_retry_timeout);
                                    state.failure_retry_timeout += min(state.failure_retry_timeout, Duration::from_secs(1));
                                    state.failure_retry_timeout = state.failure_retry_timeout.min(Duration::from_millis(HOLE_PUNCH_FAILED_MAX_TIMEOUT_MS));
                                    self.last_request_tm = None; // retry immediately on next poll
                                    return Some(Err(anyhow::anyhow!("Hole punch failed").context(context)));
                                }

                                // mark connection as connected (or connection in progress)
                                state.state_kind = PeerStateKind::ConnectionActive;
                                state.failure_retry_timeout = Duration::from_millis(HOLE_PUNCH_FAILED_INITIAL_TIMEOUT_MS);
                                self.last_request_tm = None; // retry immediately on next poll
                                Some(Ok(NewP2pConnection {
                                    pubkey: peer_pubkey,
                                    remote_addr: peer_address,
                                    socket,
                                    is_listener,
                                }))
                            }
                            else {
                                debug!("Got connection request from p2p server, but client's pubkey is not in trusted list!");
                                Some(Err(anyhow::anyhow!("Peer pubkey not in trusted list")))
                            }
                        }
                        FromServerMessage::LostConnectionRequest {
                            peer_address,
                            peer_pubkey
                        } => {
                            self.session_id = random();
                            warn!("Got lost connection notification from {}, new session id assigned", peer_address);
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

// If Some => your system time is off by `value` hours from real time
pub async fn check_system_time_error() -> Option<f32> {
    let system_time = Utc::now();
    match tokio::time::timeout(Duration::from_secs(1), reqwest::get(format!("https://timeapi.io/api/v1/time/current/unix"))).await {
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
    pub remote_addr: SocketAddrV4,
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
    pub async fn new(key: SigningKey, p2p_server_addr: SocketAddrV4, endpoint_config: EndpointConfig, transport_config: Arc<TransportConfig>) -> UdpQuicConnectionEstablisher {
        let _ = rustls::crypto::ring::default_provider().install_default();
        UdpQuicConnectionEstablisher {
            signing_key: key.clone(),
            inner: UdpConnectionEstablisher::new(key, p2p_server_addr).await,
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
            quic::establish_server_quic_connection(ep, self.transport_config.clone(), &self.signing_key, remote_addr, remote_pubkey).await.context("Establishing server quic connection")
        } else {
            quic::establish_client_quic_connection(ep).await.context("Establishing client quic connection")
        };
        match res {
            Ok(quic_connection) => Some(Ok(QuicP2pConnection {
                quic_connection,
                remote_pubkey,
                remote_addr,
            })),
            Err(e) => {
                self.inner.on_connection_closed(remote_pubkey);
                Some(Err(e))
            }
        }
    }
}
