mod reusable_tcp_socket;
pub(crate) mod messages;
pub use messages::ClientAnnouncementData;
mod service;
mod connector;
pub use service::*;
pub use connector::*;


pub const SCHEDULE_CON_MS: u64 = 500;
pub const CONNECTION_REQUEST_TIMEOUT_MS: u64 = 5000;
pub const ANNOUNCEMENT_DURATION_MS: u64 = 3000;
