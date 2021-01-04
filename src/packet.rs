//! Anaylyze the SSH packet
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str;

use pnet_packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    vlan::VlanPacket,
    Packet as _,
};
use ssh_parser::{
    parse_ssh_identification, parse_ssh_packet, SshPacket, SshPacketKeyExchange, SshVersion,
};

use crate::Error;

/// The SSH packet
#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    Version(Version),
    KeyExchange(KeyExchange),
}

/// The SSH version
#[derive(Clone, Debug, PartialEq)]
pub struct Version {
    pub proto: String,
    pub software: String,
    pub comments: Option<String>,
}

impl From<SshVersion<'_>> for Version {
    fn from(version: SshVersion) -> Self {
        unsafe {
            Version {
                proto: str::from_utf8_unchecked(version.proto).to_string(),
                software: str::from_utf8_unchecked(version.software).to_string(),
                comments: version
                    .comments
                    .map(|s| str::from_utf8_unchecked(s).to_string()),
            }
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SSH-{}-{}", self.proto, self.software)?;
        if let Some(ref comments) = self.comments {
            write!(f, " {}", comments)?;
        }
        Ok(())
    }
}

/// The SSH key exchange algorithms
#[derive(Clone, Debug, PartialEq)]
pub struct KeyExchange {
    pub kex_algs: String,
    pub server_host_key_algs: String,
    pub encr_algs_client_to_server: String,
    pub encr_algs_server_to_client: String,
    pub mac_algs_client_to_server: String,
    pub mac_algs_server_to_client: String,
    pub comp_algs_client_to_server: String,
    pub comp_algs_server_to_client: String,
    pub langs_client_to_server: String,
    pub langs_server_to_client: String,
}

impl From<SshPacketKeyExchange<'_>> for KeyExchange {
    fn from(kex: SshPacketKeyExchange) -> Self {
        unsafe {
            KeyExchange {
                kex_algs: str::from_utf8_unchecked(kex.kex_algs).to_string(),
                server_host_key_algs: str::from_utf8_unchecked(kex.server_host_key_algs)
                    .to_string(),
                encr_algs_client_to_server: str::from_utf8_unchecked(
                    kex.encr_algs_client_to_server,
                )
                .to_string(),
                encr_algs_server_to_client: str::from_utf8_unchecked(
                    kex.encr_algs_server_to_client,
                )
                .to_string(),
                mac_algs_client_to_server: str::from_utf8_unchecked(kex.mac_algs_client_to_server)
                    .to_string(),
                mac_algs_server_to_client: str::from_utf8_unchecked(kex.mac_algs_server_to_client)
                    .to_string(),
                comp_algs_client_to_server: str::from_utf8_unchecked(
                    kex.comp_algs_client_to_server,
                )
                .to_string(),
                comp_algs_server_to_client: str::from_utf8_unchecked(
                    kex.comp_algs_server_to_client,
                )
                .to_string(),
                langs_client_to_server: str::from_utf8_unchecked(kex.langs_client_to_server)
                    .to_string(),
                langs_server_to_client: str::from_utf8_unchecked(kex.langs_server_to_client)
                    .to_string(),
            }
        }
    }
}

/// Parse a SSH packet
pub fn parse(data: &[u8]) -> Result<Option<(SocketAddr, SocketAddr, Packet)>, Error> {
    let eth = EthernetPacket::new(data).ok_or_else(|| Error::Packet("ethernet".into()))?;
    let ty = eth.get_ethertype();
    parse_ethernet(ty, eth.payload())
}

fn parse_ethernet(
    ty: EtherType,
    payload: &[u8],
) -> Result<Option<(SocketAddr, SocketAddr, Packet)>, Error> {
    match ty {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| Error::Packet("vlan".into()))
            .and_then(|vlan| parse_ethernet(vlan.get_ethertype(), vlan.payload())),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| Error::Packet("ipv4".into()))
            .and_then(parse_ipv4),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| Error::Packet("ipv4".into()))
            .and_then(parse_ipv6),

        _ => Ok(None),
    }
}

fn parse_ipv4(ip: Ipv4Packet) -> Result<Option<(SocketAddr, SocketAddr, Packet)>, Error> {
    if ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        TcpPacket::new(ip.payload())
            .ok_or_else(|| Error::Packet("tcp".into()))
            .and_then(|tcp| {
                parse_tcp(
                    IpAddr::V4(ip.get_source()),
                    IpAddr::V4(ip.get_destination()),
                    tcp,
                )
            })
    } else {
        Ok(None)
    }
}

fn parse_ipv6(ip: Ipv6Packet) -> Result<Option<(SocketAddr, SocketAddr, Packet)>, Error> {
    if ip.get_next_header() == IpNextHeaderProtocols::Tcp {
        TcpPacket::new(ip.payload())
            .ok_or_else(|| Error::Packet("tcp".into()))
            .and_then(|tcp| {
                parse_tcp(
                    IpAddr::V6(ip.get_source()),
                    IpAddr::V6(ip.get_destination()),
                    tcp,
                )
            })
    } else {
        Ok(None)
    }
}

fn parse_tcp(
    saddr: IpAddr,
    daddr: IpAddr,
    tcp: TcpPacket,
) -> Result<Option<(SocketAddr, SocketAddr, Packet)>, Error> {
    let src = SocketAddr::new(saddr, tcp.get_source());
    let dest = SocketAddr::new(daddr, tcp.get_destination());
    let payload = tcp.payload();

    if payload.starts_with(b"SSH-") {
        parse_ssh_identification(payload)
            .map(|(_, (_, version))| Some((src, dest, Packet::Version(version.into()))))
    } else {
        parse_ssh_packet(payload).map(|(_, (pkt, _))| {
            if let SshPacket::KeyExchange(kex) = pkt {
                Some((src, dest, Packet::KeyExchange(kex.into())))
            } else {
                None
            }
        })
    }
    .map_err(|err| Error::Nom(err.to_string()))
}
