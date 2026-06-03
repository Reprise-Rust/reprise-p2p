use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use log::{error, info, Level};
use quinn::{EndpointConfig, TransportConfig};
use rand::rngs;
use rand::rand_core::UnwrapErr;
use reprise_p2p::udp::client::UdpQuicConnectionEstablisher;

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

    let peer_key: [u8; 32] = peer_key.try_into().unwrap();
    let mut client = UdpQuicConnectionEstablisher::new(signing_key.clone(), server_addr, EndpointConfig::default(), Arc::new(TransportConfig::default())).await;
    client.add_trusted_remote(peer_key);
    println!("Initialized, waiting for connection...");

    // Long-running stdin reader — lives for the entire program.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<String>(32);
    std::thread::spawn(move || {
        loop {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                break;
            }
            if stdin_tx.blocking_send(line.trim().to_string()).is_err() {
                break;
            }
        }
        error!("stdin task finished!")
    });

    loop {
        match client.poll_accept(Duration::from_millis(100)).await {
            None => {
                // just timeout or invalid connection request
            }
            Some(Ok(conn)) => {
                info!("QUIC connection established with: {}", conn.remote_addr);
                run_chat_session(conn.quic_connection, conn.remote_addr, &mut stdin_rx).await;
                println!("Disconnected. Waiting for new connection...");
                // Re-add to re-enable connection requests with this remote
                client.on_connection_closed(peer_key);
            }
            Some(Err(e)) => {
                error!("Connection attempt failed: {:#?}", e);
                // Timeout or transient error — just retry
            }
        }
    }
}

async fn run_chat_session(
    con: quinn::Connection,
    remote_addr: SocketAddrV4,
    stdin_rx: &mut tokio::sync::mpsc::Receiver<String>,
) {
    println!("=== Chat with {:?} started! Type /exit to quit. ===", remote_addr);

    loop {
        tokio::select! {
            line = stdin_rx.recv() => {
                match line {
                    Some(msg) if msg == "/exit" => {
                        println!("Exiting chat...");
                        break;
                    }
                    Some(msg) => {
                        let bytes = msg.into_bytes().into();
                        if con.send_datagram_wait(bytes).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        error!("stdin channel closed, exiting.");
                        break;
                    }
                }
            }
            recv = con.read_datagram() => {
                match recv {
                    Ok(buf) => {
                        let msg = String::from_utf8_lossy(&buf);
                        println!("<peer> {}", msg);
                    }
                    Err(_) => {
                        println!("Connection lost.");
                        break;
                    }
                }
            }
        }
    }

    info!("Chat session ended.");
}
