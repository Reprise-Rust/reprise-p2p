use log::Level;
use p2p_lib::config::ServerConfig;
use p2p_lib::ctrlc_reg::{ShutdownListener, ShutdownSignal};
use p2p_lib::server::run_server;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Info).unwrap();

    let shutdown = ShutdownListener::register_ctrl_c();
    run_server(ServerConfig::default(), shutdown).await
}