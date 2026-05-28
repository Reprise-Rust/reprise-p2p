use std::net::SocketAddrV4;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use thiserror::Error;

pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];

pub const PROTOCOL_VERSION: u8 = 1;
pub const TO_SERVER_SIGNED_PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid message id: {0}")]
    InvalidMessageId(u8),
    #[error("Unsupported protocol version! cur: {cur}, remote: {remote}")]
    UnsupportedVersion {
        cur: u8,
        remote: u8
    },
    #[error("Unsupported message protocol version! cur: {cur}, remote: {remote}")]
    UnsupportedMessageVersion {
        cur: u8,
        remote: u8
    },


    #[error("Message is too short")]
    TooShort,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
}

enum ToServerRawMessage {
    /// Signed message generated at `timestamp`, valid for 10 seconds after generation timestamp.
    SignedMessage {
        pubkey: PublicKey,
        timestamp: DateTime<Utc>,
        payload: Vec<u8>,
        signature: Signature,
    }
}

impl ToServerRawMessage {
    fn try_parse(bytes: &[u8]) -> Result<ToServerRawMessage, ParseError> {
        if bytes.len() < 3 {
            return Err(ParseError::TooShort);
        }

        let msg_id = bytes[0];
        let remote_ver = bytes[1];
        let msg_ver = bytes[2];
        let bytes = &bytes[3..];

        match msg_id {
            1 => {
                if bytes.len() < 8+64+32 {
                    return Err(ParseError::TooShort);
                }

                let timestamp = DateTime::from_timestamp_millis(i64::from_le_bytes(bytes[..8].try_into().unwrap())).ok_or(ParseError::InvalidTimestamp)?;
                let bytes = &bytes[8..];

                let signature = bytes[..64].try_into().unwrap();
                let bytes = &bytes[64..];

                let pubkey = bytes[..32].try_into().unwrap();
                let payload = bytes[32..].to_vec();

                Ok(ToServerRawMessage::SignedMessage {
                    timestamp,
                    pubkey,
                    signature,
                    payload
                })
            },
            _ => {
                Err(ParseError::InvalidMessageId(msg_id))
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![];
        match self {
            Self::SignedMessage {
                payload,
                timestamp,
                signature,
                pubkey
            } => {
                res.extend_from_slice(&[1, PROTOCOL_VERSION, TO_SERVER_SIGNED_PROTOCOL_VERSION]);
                res.extend_from_slice(&timestamp.timestamp().to_le_bytes());
                res.extend_from_slice(signature);
                res.extend_from_slice(pubkey);
                res.extend_from_slice(payload);

                res
            }
        }
    }
}

pub enum ToServerSignedMessage {
    /// Place temporary connection slot to the server. Connection will be established on matching connection request from other peer
    ConnectionRequest {
        peer_pubkey: PublicKey,
        session_id: u32
    }
}

impl ToServerSignedMessage {
    /// Input: raw bytes of incoming UDP datagram
    pub fn try_parse(bytes: &[u8]) -> Result<(ToServerSignedMessage, PublicKey, DateTime<Utc>), ParseError> {

    }
    /// Output: raw bytes of outgoing UDP datagram
    pub fn to_bytes(&self, key: &SigningKey) -> Vec<u8> {
        match self {
            Self::ConnectionRequest {
                session_id,
                peer_pubkey
            } => {

            }
        }
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