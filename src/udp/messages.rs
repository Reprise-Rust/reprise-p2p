use std::net::{Ipv4Addr, SocketAddrV4};
use chrono::{DateTime, Utc};
use ed25519_dalek::{ed25519, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];

pub const PROTOCOL_VERSION: u8 = 2;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid message id: {0}")]
    InvalidMessageId(u8),
    #[error("Unsupported protocol version! cur: {cur}, remote: {remote}")]
    UnsupportedVersion {
        cur: u8,
        remote: u8
    },

    #[error("Message is too short")]
    TooShort,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Invalid message content format")]
    InvalidContentFormat,
    #[error("Signature verification failed")]
    InvalidSignature,
}

enum ToServerRawMessage {
    /// Signed message generated at `timestamp`, valid for 10 seconds after generation timestamp.
    /// The signature is formed for (timestamp | payload) message
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
        if remote_ver > PROTOCOL_VERSION {
            return Err(ParseError::UnsupportedVersion {
                cur: PROTOCOL_VERSION,
                remote: remote_ver,
            })
        }
        let bytes = &bytes[2..];

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
                res.extend_from_slice(&[1, PROTOCOL_VERSION]);
                res.extend_from_slice(&timestamp.timestamp_millis().to_le_bytes());
                res.extend_from_slice(signature);
                res.extend_from_slice(pubkey);
                res.extend_from_slice(payload);

                res
            }
        }
    }
}

pub enum ToServerSignedMessage {
    /// Place temporary connection slot to the server. Connection will be established on matching connection request from other peer, included in list. All previous requests are invalidated on receiving this message
    /// Maximum: 10 connection requests
    ConnectionRequest {
        peer_pubkeys: Vec<PublicKey>,
        session_id: u32
    }
}

impl ToServerSignedMessage {
    /// Input: raw bytes of incoming UDP datagram
    pub fn try_parse(bytes: &[u8]) -> Result<(ToServerSignedMessage, PublicKey, DateTime<Utc>), ParseError> {
        let raw_msg = ToServerRawMessage::try_parse(&bytes)?;

        match raw_msg {
            ToServerRawMessage::SignedMessage {
                pubkey,
                timestamp,
                payload,
                signature
            } => {
                let verifying_key = VerifyingKey::from_bytes(&pubkey).map_err(|_| ParseError::InvalidContentFormat)?;

                let mut msg = timestamp.timestamp_millis().to_le_bytes().to_vec();
                msg.extend_from_slice(&payload);

                verifying_key.verify(&msg, &ed25519::Signature::from_bytes(&signature)).map_err(|_| ParseError::InvalidSignature)?;
                // After verification, parse message

                if payload.len() == 0 {
                    return Err(ParseError::TooShort);
                }

                let msg_id = payload[0];
                let payload = &payload[1..];
                let msg = match msg_id {
                    1 => {
                        if payload.len() < 4 + 32 {
                            return Err(ParseError::InvalidContentFormat);
                        }

                        let session_id = u32::from_le_bytes(payload[..4].try_into().unwrap());
                        let payload = &payload[4..];

                        let peer_pubkeys_len = payload[0] as usize;
                        if peer_pubkeys_len > 10 {
                            return Err(ParseError::InvalidContentFormat);
                        }
                        let mut payload = &payload[1..];

                        let mut peer_pubkeys = Vec::with_capacity(peer_pubkeys_len);
                        for _ in 0..peer_pubkeys_len {
                            let peer_pubkey = payload[..32].try_into().unwrap();
                            peer_pubkeys.push(peer_pubkey);
                            payload = &payload[32..];
                        }

                        Self::ConnectionRequest {
                            session_id,
                            peer_pubkeys,
                        }
                    }
                    _ => {
                        return Err(ParseError::InvalidMessageId(msg_id));
                    }
                };

                Ok((msg, pubkey, timestamp))
            }
        }
    }

    /// Output: raw bytes of outgoing UDP datagram
    pub fn to_bytes(&self, key: &SigningKey) -> Vec<u8> {
        match self {
            Self::ConnectionRequest {
                session_id,
                peer_pubkeys
            } => {
                if peer_pubkeys.len() > 10 {
                    panic!("Cannot encode ConnectionRequest! Maximum 10 peer public keys allowed per message!");
                }

                let mut payload = Vec::new();
                payload.extend_from_slice(&[1]);
                payload.extend_from_slice(&session_id.to_le_bytes());
                payload.push(peer_pubkeys.len() as u8);
                for pubkey in peer_pubkeys {
                    payload.extend_from_slice(pubkey);
                }

                let timestamp = Utc::now();
                let timestamp_ms = timestamp.timestamp_millis();
                let mut msg = timestamp_ms.to_le_bytes().to_vec();
                msg.extend_from_slice(&payload);

                let signature = key.sign(&msg).to_bytes();

                let our_pubkey = key.verifying_key().to_bytes();
                let res = ToServerRawMessage::SignedMessage {
                    pubkey: our_pubkey,
                    payload,
                    signature,
                    timestamp,
                };

                res.to_bytes()
            }
        }
    }
}

pub enum FromServerMessage {
    InitiateConnectionRequest {
        peer_pubkey: PublicKey,
        peer_address: SocketAddrV4,
        remote_session_id: u32,
        is_listener: bool,
    },
    /// Notification about lost connection request, meaning we should regenerate new session id
    LostConnectionRequest {
        peer_pubkey: PublicKey,
        peer_address: SocketAddrV4,
    }
}

impl FromServerMessage {
    pub fn try_parse(bytes: &[u8]) -> Result<FromServerMessage, ParseError> {
        if bytes.len() == 0 {
            return Err(ParseError::TooShort);
        }
        let msg_id = bytes[0];
        let bytes = &bytes[1..];
        let msg = match msg_id {
            1 => {
                if bytes.len() < 32 + 4 + 2 + 4 + 1 {
                    return Err(ParseError::TooShort);
                }

                let pubkey = bytes[..32].try_into().unwrap();
                let bytes = &bytes[32..];

                let ip_addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let port = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
                let addr = SocketAddrV4::new(ip_addr, port);
                let bytes = &bytes[6..];

                let remote_session_id = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                let bytes = &bytes[4..];

                let is_listener = bytes[0] == 1;

                Self::InitiateConnectionRequest {
                    remote_session_id,
                    peer_pubkey: pubkey,
                    peer_address: addr,
                    is_listener,
                }
            }
            2 => {
                if bytes.len() < 32 + 4 + 2 {
                    return Err(ParseError::TooShort);
                }

                let pubkey = bytes[..32].try_into().unwrap();
                let bytes = &bytes[32..];

                let ip_addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let port = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
                let addr = SocketAddrV4::new(ip_addr, port);

                Self::LostConnectionRequest {
                    peer_pubkey: pubkey,
                    peer_address: addr,
                }
            }
            _ => {
                return Err(ParseError::InvalidMessageId(msg_id));
            }
        };

        Ok(msg)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::InitiateConnectionRequest { peer_pubkey, peer_address, remote_session_id, is_listener } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&[1]);

                payload.extend_from_slice(peer_pubkey);
                payload.extend_from_slice(&peer_address.ip().octets());
                payload.extend_from_slice(&peer_address.port().to_le_bytes());
                payload.extend_from_slice(&remote_session_id.to_le_bytes());
                payload.push(*is_listener as u8);

                payload
            }
            Self::LostConnectionRequest { peer_pubkey, peer_address } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&[2]);

                payload.extend_from_slice(peer_pubkey);
                payload.extend_from_slice(&peer_address.ip().octets());
                payload.extend_from_slice(&peer_address.port().to_le_bytes());

                payload
            }
        }
    }
}