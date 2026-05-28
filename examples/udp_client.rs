use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use log::{info, warn, Level};
use rand::rngs;
use rand::rand_core::UnwrapErr;
use p2p_lib::udp::client::UdpClient;
use tokio::sync::mpsc;

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
    let mut client = UdpClient::new(signing_key, server_addr).await;
    client.add_trusted_remote(peer_key);
    println!("Remote peer added, waiting for connection...");

    loop {
        if let Some(new_connection) = client.poll_accept(Duration::from_millis(100)).await {
            info!("Got new connection request from P2P server: {}", new_connection.remote_addr);
            run_chat_session(new_connection).await;
            client.add_trusted_remote(peer_key);
            println!("Disconnected. Waiting for new connection...");
        }
    }
}

enum NetEvent {
    ChatMessage(String),
    Disconnected,
}

async fn run_chat_session(conn: p2p_lib::udp::client::NewP2pConnection) {
    let (net_tx, mut net_rx) = mpsc::channel::<NetEvent>(32);
    let (send_tx, send_rx) = mpsc::channel::<String>(32);
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(32);

    // Spawn blocking stdin reader.
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
    });

    // Spawn network task.
    let net_task = tokio::spawn(async move {
        let socket = conn.socket;
        let peer = conn.remote_addr;
        let mut send_rx = send_rx;

        // --- Punch phase ---
        info!("Starting hole punch to {}...", peer);
        let punch_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut punch_interval = tokio::time::interval(Duration::from_millis(20));
        let mut hole_punched = false;

        let mut buf = vec![0u8; 2000];
        loop {
            let now = tokio::time::Instant::now();
            if now >= punch_deadline {
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
                            } else if msg == b"punch ack" {
                                info!("Received punch ack from {} - hole punched!", peer);
                                hole_punched = true;
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        if !hole_punched {
            warn!("Hole punching failed (timeout)");
            let _ = net_tx.send(NetEvent::Disconnected).await;
            return;
        }

        let _ = net_tx.send(NetEvent::ChatMessage(format!("=== Chat with {:?} started! Type /exit to quit. ===", peer))).await;

        loop {
            tokio::select! {
                recv = socket.recv(&mut buf) => {
                    match recv {
                        Ok(sz) => {
                            let msg = String::from_utf8_lossy(&buf[..sz]).to_string();
                            if net_tx.send(NetEvent::ChatMessage(format!("<peer> {}", msg))).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = net_tx.send(NetEvent::Disconnected).await;
                            break;
                        }
                    }
                }
                msg = send_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if socket.send(msg.as_bytes()).await.is_err() {
                                let _ = net_tx.send(NetEvent::Disconnected).await;
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // --- Main task loop: drives terminal I/O ---
    loop {
        tokio::select! {
            event = net_rx.recv() => {
                match event {
                    Some(NetEvent::ChatMessage(msg)) => {
                        println!("{}", msg);
                    }
                    Some(NetEvent::Disconnected) | None => {
                        break;
                    }
                }
            }
            line = stdin_rx.recv() => {
                match line {
                    Some(msg) if msg == "/exit" => {
                        println!("Exiting chat...");
                        break;
                    }
                    Some(msg) => {
                        if send_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    net_task.abort();
    info!("Chat session ended.");
}
