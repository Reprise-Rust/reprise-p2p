use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use log::{info, Level};
use rand::rngs;
use rand::rand_core::UnwrapErr;
use p2p_lib::udp::client::UdpClient;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Info).unwrap();

    let server_addr = SocketAddrV4::new(Ipv4Addr::new(155, 212, 168, 136), 47002);

    let mut rng = UnwrapErr(rngs::SysRng::default());
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);

    let v_key = signing_key.verifying_key();
    let pubkey_enc = STANDARD_NO_PAD.encode(v_key.as_bytes());
    println!("Hello, new client!");
    println!("\n\nYour key: {}", pubkey_enc);
    println!("\n");
    print!("Enter another client's key: ");
    std::io::stdout().flush().unwrap();

    let peer_key = loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let decoded = STANDARD_NO_PAD.decode(input.trim());
        match decoded {
            Ok(k) if k.len() != 32 => {
                println!("Invalid key length!");
                continue;
            }
            Ok(k) => break k,
            Err(e) => {
                println!("Invalid key: {}", e);
            }
        }
    };

    let mut client = UdpClient::new(signing_key, server_addr).await;
    client.add_trusted_remote(peer_key.try_into().unwrap());
    println!("Remote peer added, waiting for connection...");

    loop {
        if let Some(new_connection) = client.poll_accept(Duration::from_millis(100)).await {
            info!("Got new connection request from P2P server: {}", new_connection.remote_addr);
        }
    }
}