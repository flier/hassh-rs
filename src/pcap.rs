//! Read a PCAP buffer or file to analyze SSH fingerprinting

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use pcap_parser::{
    create_reader, pcapng::Block, traits::PcapReaderIterator, PcapBlockOwned, PcapError,
};

use crate::{
    hassh::{Hassh, Hassher},
    Error,
};

const DEFAULT_IF_TSRESOL: u8 = 6;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct TimestampResolution(u8);

impl Default for TimestampResolution {
    fn default() -> Self {
        TimestampResolution(DEFAULT_IF_TSRESOL)
    }
}

impl TimestampResolution {
    pub fn resolve(&self, hi: u32, lo: u32) -> Duration {
        let ticks = (u64::from(hi) << 32) | u64::from(lo);

        match self.0 {
            9 => Duration::from_nanos(ticks),
            6 => Duration::from_micros(ticks),
            3 => Duration::from_millis(ticks),
            0 => Duration::from_secs(ticks),
            b => Duration::from_nanos(ticks.wrapping_mul(if (b & 0x80) == 0 {
                10u64.wrapping_pow(u32::from(b))
            } else {
                2u64.wrapping_pow(u32::from(b & 0x7F))
            })),
        }
    }
}

/// Read a PCAP buffer or file to analyze SSH fingerprinting
pub struct Reader<'a, R: Read + 'a> {
    reader: Box<dyn PcapReaderIterator<R> + 'a>,
    hassher: Hassher,
    if_tsresols: Vec<TimestampResolution>,
}

impl<'a, R: Read + 'a> Iterator for Reader<'a, R> {
    type Item = Hassh;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let (ts, data) = match block {
                        PcapBlockOwned::Legacy(packet) => (
                            Some(Duration::from_secs(u64::from(packet.ts_sec))),
                            packet.data,
                        ),
                        PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                            self.if_tsresols.clear();
                            continue;
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(intf)) => {
                            self.if_tsresols.push(TimestampResolution(intf.if_tsresol));
                            continue;
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => (
                            self.if_tsresols
                                .get(packet.if_id as usize)
                                .map(|if_tsresol| {
                                    if_tsresol.resolve(packet.ts_high, packet.ts_low)
                                }),
                            packet.data,
                        ),
                        PcapBlockOwned::NG(Block::SimplePacket(packet)) => (None, packet.data),
                        _ => continue,
                    };

                    let res = self.hassher.process_packet(data, ts);
                    self.reader.consume(offset);
                    if res.is_some() {
                        return res;
                    }
                }
                Err(PcapError::Incomplete) => {
                    self.reader.refill().unwrap();
                }
                _ => break,
            }
        }

        None
    }
}

/// Parse a PCAP buffer to analyze SSH fingerprinting
pub fn parse<'a, R>(buf: R) -> Result<Reader<'a, R>, Error>
where
    R: Read + 'static,
{
    Ok(Reader {
        reader: create_reader(65536, buf)?,
        hassher: Hassher::default(),
        if_tsresols: Vec::new(),
    })
}

/// Parse a PCAP file to analyze SSH fingerprinting
pub fn open<'a, P>(path: P) -> Result<Reader<'a, File>, Error>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    trace!("open pcap file {:?}", path);

    parse(File::open(path)?)
}
