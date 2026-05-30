use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{error, info, Level};
use quinn::{rustls, ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rand::rngs;
use rand::rand_core::UnwrapErr;
use rcgen::{CertificateParams, PKCS_ED25519};
use p2p_lib::udp::client::UdpClient;
use crate::quic::{establish_client_quic_connection, establish_server_quic_connection, make_quin_endpoint, PeerPublicKeyVerifier};

#[path = "common/quic.rs"]
mod quic;

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
    let mut client = UdpClient::new(signing_key.clone(), server_addr).await;

    // create quinn endpoint
    println!("Remote peer added, waiting for connection...");

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
        // Re-add after each failure to initiate placing connection requests to this remote to p2p server
        client.add_trusted_remote(peer_key);
        if let Some(conn) = client.poll_accept(Duration::from_millis(100)).await {
            info!("Hole-punched connection established with: {}", conn.remote_addr);

            let is_listener = conn.is_listener;
            let remote_addr = conn.remote_addr;
            let remote_pubkey = conn.pubkey;
            let res = make_quin_endpoint(&signing_key, conn).await;
            if let Err(e) = res {
                error!("Failed to prepare QUIC endpoint before connection: {e:?}");
                continue;
            }
            let Ok(ep) = res else {
                unreachable!()
            };

            info!("Establishing QUIC connection...");
            let res = if is_listener {
                establish_server_quic_connection(ep, &signing_key, remote_addr, remote_pubkey).await.context("establish server quic connection")
            }
            else {
                establish_client_quic_connection(ep).await.context("establish client quic connection")
            };
            if let Ok(con) = res {
                run_chat_session(con, is_listener, remote_addr, &mut stdin_rx).await;
                println!("Disconnected. Waiting for new connection...");
            }
            else if let Err(e) = res {
                error!("Failed to establish QUIC connection: {e:#?}");
            }
        }
    }
}

async fn run_chat_session(
    con: quinn::Connection,
    role: bool,
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
