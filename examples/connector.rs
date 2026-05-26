use std::io::{stdin, Read};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration};
use log::{error, info, warn, Level};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::spawn_blocking;
use tokio::time;
use p2p_lib::tcp::P2PTcpConnector;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Info).unwrap();
    
    let server = (Ipv4Addr::new(155, 212, 168, 136), 47002);
    let mut connector = P2PTcpConnector::new(server);

    println!("Begin scanning for clients. Server: {:?}", server);
    let established_connections = Arc::new(Mutex::new(Vec::new()));
    loop {
        let res = connector.scan_connections().await;
        let mut clients = if let Err(e) = res {
            error!("Error during scanning connections: {:?}", e);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        else if let Ok(clients) = res{
            clients
        } else {unreachable!()};

        // ignore established connections (defined by tcp connection)
        for (_, session_id) in established_connections.lock().unwrap().clone() {
            if let Some(idx) = clients.iter().position(|c| c.data.session == session_id) {
                clients.swap_remove(idx);
            }
        }

        if clients.is_empty() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!("No clients found, retrying...");
            continue;
        }

        println!("Available clients:");
        for (i, client) in clients.iter().enumerate() {
            println!("[{}] {} - {:?}", i+1, client.data, client.addr);
        }
        println!("\n[0] - Scan again");

        let choice = spawn_blocking(|| {
            let mut buf = String::new();
            stdin().read_line(&mut buf).ok().unwrap();
            let choice = buf.trim().parse::<usize>()
                .inspect_err(|e| warn!("Invalid input: {}", e))
                .ok().unwrap_or(0);

            choice
        }).await.unwrap();

        if choice == 0 {
            // retry scan...
            continue;
        }
        if choice > clients.len() {
            warn!("Client index {} is out of bounds", choice);
            continue;
        }

        let client = &clients[choice - 1];
        let session_id = client.data.session;
        let res = connector.connect_client(session_id).await;
        if let Ok((mut stream, remote_addr)) = res {
            info!("P2P connection established to {:?}!", remote_addr);

            let connections_clone = established_connections.clone();
            connections_clone.lock().unwrap().push((remote_addr, session_id));
            tokio::spawn(async move {
                if let Err(e) = stream.write_all(b"hello!").await {
                    warn!("Failed to send message: {:?}", e);
                }
                time::sleep(Duration::from_secs(5)).await;
                info!("P2P streamnection with {:?} dropped!", remote_addr);
                connections_clone.lock().unwrap().retain(|(_, s)| *s != session_id);
                drop(stream)
            });
        }
        else if let Err(e) = res {
            warn!("Failed to establish P2P connection: {:?}", e);
        }
    }
}