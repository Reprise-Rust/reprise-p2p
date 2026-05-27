use std::net::SocketAddrV4;
use thiserror::Error;

pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];

enum ToServerRawMessage {
    /// Signed message generated at `timestamp`, valid for 10 seconds after generation timestamp.
    SignedMessage {
        pubkey: PublicKey,
        timestamp: u64,
        payload: Vec<u8>,
        signature: Signature,
    }
}

pub enum ToServerSignedMessage {
    /// Place temporary connection slot to the server. Connection will be established on matching connection request from other peer
    ConnectionRequest {
        peer_pubkey: PublicKey,
        session_id: u32
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Signature validation failed")]
    SignatureValidationFailed,
}

impl ToServerSignedMessage {
    pub fn try_parse(bytes: &[u8]) -> Result<(ToServerSignedMessage, PublicKey, u64), ParseError> {
        todo!()
    }
}

pub enum FromServerMessage {
    InitiateConnectionRequest {
        peer_pubkey: PublicKey,
        peer_address: SocketAddrV4,
        remote_session_id: u32,
    }
}

impl FromServerMessage {
    
}