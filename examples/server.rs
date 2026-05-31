use log::Level;
use reprise_p2p::config::ServerConfig;
use reprise_p2p::ctrlc_reg::{ShutdownListener, ShutdownSignal};
use reprise_p2p::server::run_server;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Info).unwrap();

    let shutdown = ShutdownListener::register_ctrl_c();
    run_server(ServerConfig::default(), shutdown).await
}