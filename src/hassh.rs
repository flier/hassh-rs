use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use std::time::{Duration, SystemTime};

use crate::packet::{KeyExchange, Packet, Version};

#[derive(Clone, Debug, PartialEq)]
pub struct Hassh {
    pub ts: Option<Duration>,
    pub src: SocketAddr,
    pub dest: SocketAddr,
    pub version: Version,
    pub kex: KeyExchange,
}

impl Deref for Hassh {
    type Target = KeyExchange;

    fn deref(&self) -> &Self::Target {
        &self.kex
    }
}

impl KeyExchange {
    pub fn client_algo(&self) -> String {
        format!(
            "{};{};{};{}",
            self.kex_algs,
            self.encr_algs_client_to_server,
            self.mac_algs_client_to_server,
            self.comp_algs_client_to_server,
        )
    }

    pub fn server_algo(&self) -> String {
        format!(
            "{};{};{};{}",
            self.kex_algs,
            self.encr_algs_server_to_client,
            self.mac_algs_server_to_client,
            self.comp_algs_server_to_client,
        )
    }

    pub fn client_hash(&self) -> md5::Digest {
        md5::compute(self.client_algo())
    }

    pub fn server_hash(&self) -> md5::Digest {
        md5::compute(self.server_algo())
    }
}

#[derive(Debug, Default)]
pub struct Hassher {
    versions: HashMap<(SocketAddr, SocketAddr), Version>,
}

impl Hassher {
    pub fn process_packet(&mut self, packet: Packet) -> Option<Hassh> {
        match packet {
            Packet::Version { src, dest, version } => {
                self.versions.insert((src, dest), version);
                None
            }
            Packet::KeyExchange { src, dest, kex } => Some(Hassh {
                ts: Some(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap(),
                ),
                src,
                dest,
                version: self.versions.get(&(src, dest)).cloned()?,
                kex,
            }),
        }
    }
}
