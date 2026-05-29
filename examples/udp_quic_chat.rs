use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
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
use crate::quic::PeerPublicKeyVerifier;

#[path = "common/quic.rs"]
mod quic;

fn quinn_cert_from_key(signing_key: &SigningKey) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let pkcs8_bytes = signing_key.to_pkcs8_der().unwrap();
    let priv_key_der = PrivateKeyDer::Pkcs8(pkcs8_bytes.as_bytes().into());

    let keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_bytes.as_bytes().into(), &PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec!["reprise-p2p".to_string()]).unwrap();
    let cert = params.self_signed(&keypair).unwrap();

    (cert.der().clone(), priv_key_der.clone_key())
}

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
    client.add_trusted_remote(peer_key);

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
        if let Some(conn) = client.poll_accept(Duration::from_millis(100)).await {
            info!("Hole-punched connection established with: {}", conn.remote_addr);

            let endpoint_config = EndpointConfig::default();
            let (cert, key) = quinn_cert_from_key(&signing_key);

            let expected_pubkey = VerifyingKey::from_bytes(&conn.pubkey).unwrap();
            let verifier = Arc::new(PeerPublicKeyVerifier::new(expected_pubkey));

            let rustls_server_config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier.clone()) // Требуем кастомную проверку клиента!
                .with_single_cert(vec![cert.clone()], key.clone_key())
                .unwrap();

            let quic_server_config = QuicServerConfig::try_from(rustls_server_config).unwrap();
            let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));;

            let mut ep = Endpoint::new(endpoint_config, Some(server_config), conn.socket.into_std().unwrap(), Arc::new(TokioRuntime)).unwrap();
            info!("Establishing QUIC connection...");
            let con = if conn.is_listener {
                let incoming = ep.accept().await.unwrap();
                incoming.await.unwrap()
            }
            else {
                let rustls_client_config = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_client_auth_cert(vec![cert.clone()], key.clone_key())
                    .unwrap();

                let quic_client_config = QuicClientConfig::try_from(rustls_client_config).unwrap();
                let client_config = ClientConfig::new(Arc::new(quic_client_config));
                ep.set_default_client_config(client_config);

                let connecting = ep.connect(conn.remote_addr.into(), "reprise-p2p").unwrap();
                connecting.await.unwrap()
            };
            run_chat_session(con, conn.is_listener, conn.remote_addr, &mut stdin_rx).await;
            client.add_trusted_remote(peer_key);
            println!("Disconnected. Waiting for new connection...");
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
