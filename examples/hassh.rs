use std::fmt;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::{anyhow, Error};
use log::debug;
use serde::Serialize;
use structopt::StructOpt;

use hassh::{live, pcap, Hassh};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "hassh",
    about = "Extract fingerprinting to identify specific Client and Server SSH implementations."
)]
struct Opt {
    /// pcap file to process
    #[structopt(short, long, parse(from_os_str))]
    file: Vec<PathBuf>,

    /// directory of pcap files to process
    #[structopt(short, long, parse(from_os_str))]
    directory: Vec<PathBuf>,

    /// listen on interface
    #[structopt(short, long)]
    interface: Option<String>,

    /// client or server fingerprint.
    #[structopt(short = "p", long, default_value = "all")]
    fingerprint: Fingerprint,

    /// BPF capture filter to use (for live capture only).
    #[structopt(short, long, default_value = "tcp port 22 or tcp port 2222")]
    bpf_filter: String,

    /// specify the output log format: json, csv
    #[structopt(short, long)]
    log_format: Option<LogFormat>,

    /// "specify the output log file
    #[structopt(short, long, default_value = "hassh.log", parse(from_os_str))]
    output_file: PathBuf,

    /// save the live captured packets to this file
    #[structopt(short, long, parse(from_os_str))]
    write_pcap: Option<PathBuf>,

    /// don't print the output
    #[structopt(short, long)]
    silence: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fingerprint {
    All,
    Server,
    Client,
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "server" => Ok(Self::Server),
            "client" => Ok(Self::Client),
            _ => Err(anyhow!("unexpected finterprint: {}", s)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum LogFormat {
    JSON,
    CSV,
}

impl FromStr for LogFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(LogFormat::JSON),
            "csv" => Ok(LogFormat::CSV),
            _ => Err(anyhow!("unexpected log format: {}", s)),
        }
    }
}

const CL1: &str = "\u{001b}[38;5;81m";
const CL2: &str = "\u{001b}[38;5;220m";
const CL3: &str = "\u{001b}[38;5;181m";
const CL4: &str = "\u{001b}[38;5;208m";
const END: &str = "\x1b[0m";

trait IsServer {
    fn is_server(&self) -> bool;
}

impl IsServer for Hassh {
    fn is_server(&self) -> bool {
        self.src.port() < self.dest.port()
    }
}

#[repr(transparent)]
struct HasshFmt(Hassh);

impl fmt::Display for HasshFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_server() {
            write!(
                f,
                "
[+] Server SSH_MSG_KEXINIT detected
    {cl1}[ {sip}:{sport} -> {dip}:{dport} ]{end}
        [-] Identification String: {cl4}{proto}{end}
        [-] hasshServer: {cl4}{hassh:x}{end}
        [-] hasshServer Algorithms: {cl3}{algo}{end}",
                sip = self.0.src.ip(),
                sport = self.0.src.port(),
                dip = self.0.dest.ip(),
                dport = self.0.dest.port(),
                proto = self.0.version,
                hassh = self.0.server_hash(),
                algo = self.0.server_algo(),
                cl1 = CL1,
                cl3 = CL3,
                cl4 = CL4,
                end = END
            )
        } else {
            write!(
                f,
                "
[+] Client SSH_MSG_KEXINIT detected
    {cl1}[ {sip}:{sport} -> {dip}:{dport} ]{end}
        [-] Identification String: {cl2}{proto}{end}
        [-] hassh: {cl2}{hassh:x}{end}
        [-] hassh Algorithms: {cl3}{algo}{end}",
                sip = self.0.src.ip(),
                sport = self.0.src.port(),
                dip = self.0.dest.ip(),
                dport = self.0.dest.port(),
                proto = self.0.version,
                hassh = self.0.client_hash(),
                algo = self.0.client_algo(),
                cl1 = CL1,
                cl2 = CL2,
                cl3 = CL3,
                end = END
            )
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Row<'a> {
    pub timestamp: String,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub hassh_type: &'static str,
    pub identification_string: String,
    pub hassh: String,
    pub hassh_version: &'static str,
    pub hassh_algorithms: String,
    pub kex_algs: &'a str,
    pub enc_algs: &'a str,
    pub mac_algs: &'a str,
    pub cmp_algs: &'a str,
}

const HASSH_VERSION: &str = "1.0";

impl<'a> From<&'a Hassh> for Row<'a> {
    fn from(hassh: &Hassh) -> Row {
        let is_server = hassh.is_server();

        Row {
            timestamp: hassh
                .ts
                .map(|ts| humantime::format_rfc3339_millis(SystemTime::UNIX_EPOCH + ts).to_string())
                .unwrap_or_default(),
            source_ip: hassh.src.ip(),
            destination_ip: hassh.dest.ip(),
            source_port: hassh.src.port(),
            destination_port: hassh.dest.port(),
            hassh_type: if is_server { "server" } else { "client" },
            identification_string: hassh.version.to_string(),
            hassh: format!(
                "{:x}",
                if is_server {
                    hassh.server_hash()
                } else {
                    hassh.client_hash()
                }
            ),
            hassh_version: HASSH_VERSION,
            hassh_algorithms: if is_server {
                hassh.server_algo()
            } else {
                hassh.client_algo()
            },
            kex_algs: &hassh.kex_algs,
            enc_algs: if is_server {
                &hassh.encr_algs_server_to_client
            } else {
                &hassh.encr_algs_client_to_server
            },
            mac_algs: if is_server {
                &hassh.mac_algs_server_to_client
            } else {
                &hassh.mac_algs_client_to_server
            },
            cmp_algs: if is_server {
                &hassh.comp_algs_server_to_client
            } else {
                &hassh.comp_algs_client_to_server
            },
        }
    }
}

enum LogWriter<W: Write> {
    JSON(W),
    CSV(csv::Writer<W>),
}

impl<W: Write> LogWriter<W> {
    fn write(&mut self, row: Row) -> Result<(), Error> {
        match self {
            LogWriter::JSON(w) => {
                let mut w = LineWriter::new(w);
                serde_json::to_writer(&mut w, &row)?;
                w.write(b"\n")?;
            }
            LogWriter::CSV(w) => {
                w.serialize(&row)?;
                w.flush()?;
            }
        }
        Ok(())
    }
}

fn process_hassh<W: Write>(
    out: Option<&mut LogWriter<W>>,
    hassh: Hassh,
    fingerprint: Fingerprint,
    silence: bool,
) -> Result<(), Error> {
    let is_server = hassh.is_server();

    match fingerprint {
        Fingerprint::Client if is_server => Ok(()),
        Fingerprint::Server if !is_server => Ok(()),
        _ => {
            if let Some(writer) = out {
                writer.write(Row::from(&hassh))?;
            }

            if !silence {
                println!("{}", HasshFmt(hassh));
            }

            Ok(())
        }
    }
}

pub fn main() -> Result<(), Error> {
    pretty_env_logger::init_timed();

    let opt = Opt::from_args();
    debug!("{:#?}", opt);

    let mut out = {
        let output_file = &opt.output_file;
        let output_file = move || {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(output_file)
        };

        match opt.log_format {
            Some(LogFormat::CSV) => {
                let f = output_file()?;
                let w = csv::WriterBuilder::new()
                    .has_headers(f.metadata()?.len() == 0)
                    .from_writer(f);
                Some(LogWriter::CSV(w))
            }
            Some(LogFormat::JSON) => Some(LogWriter::JSON(output_file()?)),
            _ => None,
        }
    };

    let fingerprint = opt.fingerprint;
    let silence = opt.silence;
    let mut log_hassh = move |hassh| process_hassh(out.as_mut(), hassh, fingerprint, silence);

    for path in opt.file {
        for hassh in pcap::open(path).map(Box::new)? {
            log_hassh(hassh)?;
        }
    }
    for dir in opt.directory {
        for path in glob::glob(&dir.join("*").to_string_lossy())? {
            for hassh in pcap::open(path?)? {
                log_hassh(hassh)?;
            }
        }
    }
    if let Some(intf) = opt.interface {
        for hassh in live::capture(&intf)?.with_filter(&opt.bpf_filter)? {
            log_hassh(hassh)?;
        }
    }

    Ok(())
}
