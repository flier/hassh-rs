//! hassh - A SSH fingerprinting library written in Rust
//!
//! This crate enables a consumer to fingerprint the [Key Exchange](https://tools.ietf.org/html/rfc4253#section-6.5) portion of a SSH handshake.
//! It can hash SSH handshakes over IPv4 and IPv6.
//! It heavily depends on the [ssh-parser](https://github.com/rusticata/ssh-parser) project from [Rusticata](https://github.com/rusticata).
//!
//! "HASSH" is a network fingerprinting standard which can be used to identify specific Client and Server SSH implementations.
//! The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint.
//!
//! See the original [HASSH](https://github.com/salesforce/hassh) project for more information.
//!
//! ## Example
//!
//! Example of fingerprinting a packet capture file:
//!
//! ```rust,no_run
//! use hassh::pcap;
//!
//! for hassh in pcap::open("test.pcap").unwrap() {
//!     println!("{:x}", hassh.client_hash());
//! }
//! ```
//!
//! Example of fingerprinting a live capture:
//!
//! ```rust,no_run
//! use hassh::live;
//!
//! for hassh in live::capture("en0").unwrap() {
//!     println!("{:x}", hassh.server_hash());
//! }
//! ```
#[macro_use]
extern crate log;

mod error;
mod hassh;
pub mod packet;

#[cfg(feature = "capi")]
pub mod capi;
#[cfg(feature = "live-capture")]
pub mod live;
#[cfg(feature = "pcap-file")]
pub mod pcap;

pub use self::error::Error;
pub use self::hassh::{Hassh, Hassher};
