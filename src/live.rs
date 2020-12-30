use pcap::{Active, Capture};

use crate::{
    hassh::{Hassh, Hassher},
    packet, Error,
};

pub struct Live {
    cap: Capture<Active>,
    hassher: Hassher,
}

impl Iterator for Live {
    type Item = Hassh;

    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(packet) = self.cap.next() {
            if let Ok(Some(packet)) = packet::parse(packet.data) {
                if let Some(hassh) = self.hassher.process_packet(packet) {
                    return Some(hassh);
                }
            }
        }

        None
    }
}

impl Live {
    /// Adds a filter to the capture using the given BPF program string. Internally this is compiled using pcap_compile().
    pub fn with_filter(&mut self, program: &str) -> Result<&mut Self, Error> {
        self.cap.filter(program)?;
        Ok(self)
    }
}

pub fn capture(intf: &str) -> Result<Live, Error> {
    let cap = Capture::from_device(intf)?.immediate_mode(true).open()?;

    trace!(
        "open pcap device {}: {} ({})",
        intf,
        cap.get_datalink().get_name()?,
        cap.get_datalink().get_description()?
    );

    Ok(Live {
        cap,
        hassher: Hassher::default(),
    })
}
