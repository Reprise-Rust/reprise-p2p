use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use log::info;
use parking_lot::Mutex;
use tokio::sync::oneshot;
use crate::tcp::{ANNOUNCEMENT_DURATION_MS, CONNECTION_REQUEST_TIMEOUT_MS};
use crate::tcp::messages::{ClientAnnouncement, ClientAnnouncementData, ConnectionRequest};

struct KnownClient {
    last_announcement: Instant,
    data: ClientAnnouncementData,
    addr: SocketAddr,
    pending_connection: Option<IncomingConnection>
}

struct InnerState {
    clients: HashMap<u64, KnownClient>
}

impl InnerState {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }
}

pub struct IncomingConnection {
    /// Deadlien after which this request is no longer available
    pub tm: Instant,
    pub addr: SocketAddr,
    pub tx: oneshot::Sender<()>,
}

#[derive(Clone)]
pub struct State {
    inner: Arc<Mutex<InnerState>>,
}

impl State {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerState::new()))
        }
    }

    pub fn announce_check(&self, announce: ClientAnnouncementData, addr: SocketAddr) -> Option<IncomingConnection> {
        let mut g = self.inner.lock();

        // 1) update existing announce
        let entry = g.clients.entry(announce.session).and_modify(|e| {
            e.last_announcement = Instant::now();
            e.addr = addr;
            e.data = announce.clone();
        }).or_insert(KnownClient {
            last_announcement: Instant::now(),
            data: announce.clone(),
            addr,
            pending_connection: None
        });

        // 2) check for pending connection
        entry.pending_connection.take_if(|c| c.tm > Instant::now())
    }

    pub fn get_clients(&self, app: String) -> Vec<ClientAnnouncement> {
        let g = self.inner.lock();
        g.clients.values().map(|c| ClientAnnouncement {
            tm_ago: c.last_announcement.elapsed(),
            addr: c.addr,
            data: c.data.clone(),
        }).collect()
    }


    /// Some -> inserted new request
    pub fn insert_connection_request(&self, request: ConnectionRequest, addr: SocketAddr) -> Option<(oneshot::Receiver<()>, SocketAddr)> {
        let mut g = self.inner.lock();
        if let Some(client) = g.clients.get_mut (&request.session) {
            // found client, insert connection request
            let (tx, rx) = oneshot::channel();
            client.pending_connection = Some(IncomingConnection {
                tm: Instant::now() + Duration::from_millis(CONNECTION_REQUEST_TIMEOUT_MS - 500),
                addr,
                tx
            });

            Some((rx, client.addr))
        }
        else {
            None
        }
    }

    /// Remove previously inserted request if client still exist
    pub fn remove_connection_request(&self, session: u64) {
        let mut g = self.inner.lock();
        if let Some(client) = g.clients.get_mut(&session) {
            client.pending_connection = None;
        }
    }

    /// Cleanup announcements older than ANNOUNCEMENT_DURATION_MS
    pub fn poll_update(&self) {
        let mut g = self.inner.lock();

        let mut to_remove = Vec::new();
        for e in g.clients.values() {
            if e.last_announcement.elapsed() > Duration::from_millis(ANNOUNCEMENT_DURATION_MS) {
                to_remove.push(e.data.session);
            }
        }

        for id in to_remove {
            if let Some(client) = g.clients.remove(&id) {
                info!("Removed announcement: {}", client.data);
            }

        }
    }
}
