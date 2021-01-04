//! Capture live traffic to analyze SSH fingerprinting

use std::time::Duration;

use pcap::{self, Active};

use crate::{
    hassh::{Hassh, Hassher},
    Error,
};

/// Capture live traffic
pub struct Capture {
    cap: pcap::Capture<Active>,
    hassher: Hassher,
}

impl Iterator for Capture {
    type Item = Hassh;

    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(packet) = self.cap.next() {
            let ts = Duration::from_secs(packet.header.ts.tv_sec as u64)
                + Duration::from_micros(packet.header.ts.tv_usec as u64);
            if let Some(hassh) = self.hassher.process_packet(packet.data, Some(ts)) {
                return Some(hassh);
            }
        }

        None
    }
}

impl Capture {
    /// Adds a filter to the capture using the given BPF program string.
    pub fn with_filter(&mut self, program: &str) -> Result<&mut Self, Error> {
        self.cap.filter(program)?;
        Ok(self)
    }
}

/// Capture live traffic on the device
pub fn capture(intf: &str) -> Result<Capture, Error> {
    let cap = pcap::Capture::from_device(intf)?
        .immediate_mode(true)
        .open()?;

    trace!(
        "open pcap device {}: {} ({})",
        intf,
        cap.get_datalink().get_name()?,
        cap.get_datalink().get_description()?
    );

    Ok(Capture {
        cap,
        hassher: Hassher::default(),
    })
}
