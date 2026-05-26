use std::net::Ipv4Addr;
use std::time::{Duration};
use log::{error, info, warn, Level};
use rand::random;
use tokio::io::AsyncReadExt;
use tokio::time;
use p2p_lib::tcp::{P2PTcpService, RequestError};

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Info).unwrap();
    
    let server = (Ipv4Addr::new(155, 212, 168, 136), 47002);
    let adv_data = p2p_lib::tcp::ClientAnnouncementData {
        app: "p2p example".to_string(),
        username: "SkyGrel19".to_string(),
        session: random(),
    };
    let mut service = P2PTcpService::new(server, adv_data);

    println!("Begin waiting for connections. Server: {:?}", server);
    loop {
        let res = service.poll_accept().await;
        if let Ok((mut stream, remote_addr)) = res {
            info!("P2P connection established to {:?}!", remote_addr);

            tokio::spawn(async move {
                stream.readable().await.unwrap();
                let mut buf = [0; 5];
                if stream.read_exact(&mut buf).await.is_ok() {
                    info!("Got message! {:?}", buf);
                }
                else {
                    warn!("Failed to read message!");
                }
                time::sleep(Duration::from_secs(5)).await;
                info!("P2P streamnection with {:?} dropped!", remote_addr);
                drop(stream)
            });
        }
        else if let Err(RequestError::NoPendingConnections) = res {
            // ...
        }
        else if let Err(e) = res {
            error!("Failed to announce and check: {:?}", e);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}