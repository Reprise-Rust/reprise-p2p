use std::collections::BTreeSet;
use ed25519_dalek::SigningKey;
use crate::udp::messages::PublicKey;

pub struct UdpClient {
    trusted_remotes: BTreeSet<PublicKey>,
    key: SigningKey
}

impl UdpClient {
    pub fn new(key: SigningKey) -> UdpClient {
        UdpClient {
            trusted_remotes: BTreeSet::new(),
            key,
        }
    }

    pub fn add_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.insert(key);
    }

    pub fn remove_trusted_remote(&mut self, key: PublicKey) {
        self.trusted_remotes.remove(&key);
    }

    pub fn poll_accept(&mut self) {

    }
}