use thiserror::Error;

/// An error
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(feature = "pcap-file")]
    #[error(transparent)]
    Pcap(#[from] pcap_parser::PcapError),

    #[cfg(feature = "live-capture")]
    #[error(transparent)]
    Live(#[from] pcap::Error),

    #[error("parse ssh packet, {0}")]
    Nom(String),

    #[error("parse {0} packet")]
    Packet(String),
}
