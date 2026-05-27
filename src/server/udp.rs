use std::collections::BTreeSet;
use log::{error, info, warn};
use tokio::net::UdpSocket;
use crate::ctrlc_reg::ShutdownListener;
use crate::udp::messages::{FromServerMessage, PublicKey, ToServerSignedMessage};

const SIGNED_MSG_VALID_S: usize = 10;
struct ClientsRequests {
    requests: BTreeSet<(PublicKey, PublicKey)>
}

pub async fn run_udp_server(port: u16, mut shutdown: ShutdownListener) {
    let socket = UdpSocket::bind(("0.0.0.0", port)).await.unwrap();
    info!("[Reprise:P2P:UDP] UDP server started on port {}!", port);

    let mut buf = vec![0u8; 2000];
    loop {
        let res = socket.recv_from(&mut buf).await;
        if let Err(e) = res {
            warn!("[Reprise:UDP] Error receiving from socket: {}", e);
        }
        else if let Ok((sz, addr)) = res {
            let msg = buf[..sz].to_vec();
            let client_msg = ToServerSignedMessage::try_parse(&msg);
            if let Err(e) = client_msg {
                error!("[Reprise:UDP] Error parsing client message: {}", e);
            }
            else if let Ok((parsed_msg, pubkey, tm)) = client_msg {
                match parsed_msg {
                    ToServerSignedMessage::ConnectionRequest {
                        peer_pubkey,
                        session_id
                    } => {
                        
                    }
                }
            }
        }
    }
}
