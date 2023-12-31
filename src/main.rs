use clap::Parser;
use deku::prelude::*;
use std::fs::File;
use std::io::{Read, Write};
use xxhash_rust::xxh3::xxh3_64;

mod packets;
use crate::packets::Packet;

#[derive(Parser, Debug)]
struct Opt {
    /// Input pcap file to extract TCP streams from
    #[arg(short, long, required = true)]
    input: String,

    /// Output name template
    #[arg(short, long, default_value = "output.pcap")]
    output: String,

    /// Set window size in frames (Set to "0" for max window size)
    #[arg(short, long, default_value = "3")]
    window: usize,

    /// Set window time in seconds (Optional)
    #[arg(short, long)]
    time: Option<f64>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Select layer to compare
    #[command(subcommand)]
    layer: Option<Layer>,
}

#[derive(Parser, Debug, Clone, Copy)]
enum Layer {
    /// Ethernet layer (whole packet, lowest level)
    Mac,
    /// Logical Link Control (LLC, Vlan, Arp, etc)
    Llc,
    /// Network layer (IP)
    Network,
    /// Transport layer (TCP/UDP/IGMP/etc.)
    Transport,
    /// Session layer (Payload)
    Session,
}

const PCAP_HEADER_LEN: usize = 24;
const PCAP_MAGIC: u32 = 0xa1b2c3d4;

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct PcapHeader {
    magic: u32,
    major: u16,
    minor: u16,
    resv1: u32,
    resv2: u32,
    snaplen: u32,
    #[deku(bits = "3")]
    fcs: u8,
    #[deku(bits = "1")]
    f: u8,
    #[deku(bits = "28")]
    linktype: u32,
}

impl PcapHeader {
    fn read(reader: &[u8]) -> Option<Self> {
        let (_, header) = PcapHeader::from_bytes((reader, 0)).ok()?;
        if header.magic == PCAP_MAGIC {
            Some(header)
        } else {
            None
        }
    }

    fn out(&self) -> Vec<u8> {
        self.to_bytes().unwrap()
    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct PcapRecord {
    ts: u32,
    tn: u32,
    caplen: u32,
    origlen: u32,
    #[deku(count = "caplen")]
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct Duplicate {
    time: Option<f64>,
    frame: usize,
    data: Option<Vec<u8>>,
}

impl PcapRecord {
    fn read_all(mut cursor: &[u8]) -> Vec<Self> {
        let mut records = Vec::<Self>::new();
        while let Some(record) = Self::read(cursor) {
            cursor = &cursor[record.len()..];
            records.push(record);
        }
        records
    }

    fn read(reader: &[u8]) -> Option<Self> {
        let (_, record) = PcapRecord::from_bytes((reader, 0)).ok()?;
        Some(record)
    }

    fn write_all(records: &[Self]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        for r in records {
            out.append(&mut r.out());
        }
        out
    }

    fn out(&self) -> Vec<u8> {
        self.to_bytes().unwrap()
    }

    fn len(&self) -> usize {
        self.data.len() + 16
    }

    fn hash(&self) -> u64 {
        xxh3_64(&self.data)
    }

    fn hash_at(&self, layer: Layer) -> u64 {
        let offset = match layer {
            Layer::Mac => 0,
            Layer::Llc => Packet::get_llc_start(),
            Layer::Network => Packet::get_network_start(&self.data),
            Layer::Transport => Packet::get_transport_start(&self.data),
            Layer::Session => Packet::get_session_start(&self.data),
        };
        xxh3_64(&self.data[offset..])
    }

    fn filter_dup(records: Vec<PcapRecord>, opt: &Opt) -> Vec<PcapRecord> {
        let window = opt.window;
        let time = opt.time;
        let layer = opt.layer;

        let mut hash_list = Vec::<u64>::new();
        let mut out = Vec::<PcapRecord>::new();
        let mut prev_ts = 0f64;

        let mut dupes = Vec::<Duplicate>::new();

        for (n, rec) in records.into_iter().enumerate() {
            let hash = if let Some(layer) = layer {
                rec.hash_at(layer)
            } else {
                rec.hash()
            };
            if hash_list.contains(&hash) {
                if let Some(t) = time {
                    let cur_ts: f64 = rec.ts as f64 + (rec.tn as f64 / 1000000f64);
                    if cur_ts - prev_ts < t {
                        if opt.verbose {
                            dupes.push(Duplicate {
                                frame: n,
                                time: Some(cur_ts - prev_ts),
                                data: None,
                            });
                        }
                        prev_ts = cur_ts;
                        continue;
                    }
                } else {
                    if opt.verbose {
                        dupes.push(Duplicate {
                            frame: n,
                            ..Default::default()
                        });
                    }
                    continue;
                }
            }
            if hash_list.len() > window && window != 0 {
                hash_list.pop();
            }
            hash_list.push(hash);
            prev_ts = rec.ts as f64 + (rec.tn as f64 / 1000000f64);
            out.push(rec);
        }

        if opt.verbose {
            println!("Duplicates detected: {dupes:#?}");
        }

        out
    }
}

fn main() {
    let opt = Opt::parse();

    let mut file = File::open(&opt.input).expect("Error: Cannot open file");
    let mut reader = Vec::<u8>::new();
    let _ = file.read_to_end(&mut reader).expect("Cannot read file");

    if let Some(header) = PcapHeader::read(&reader) {
        println!("Loading {}...", opt.input);

        let records = PcapRecord::read_all(&reader[PCAP_HEADER_LEN..]);
        let rlen = records.len();

        let filtered = PcapRecord::filter_dup(records, &opt);
        println!(
            "original: {} filtered: {} window: {} removed: {}",
            rlen,
            filtered.len(),
            opt.window,
            rlen - filtered.len()
        );

        println!("Preparing data to write...");
        let mut data = header.out();
        data.append(&mut PcapRecord::write_all(&filtered));

        println!("Writing output to: {}", opt.output);
        let mut output = File::create(&opt.output).expect("Error: Cannot create output file");
        output
            .write_all(&data)
            .expect("Error writing to output file");
    } else {
        println!("Error: {} cannot be loaded as a pcap file", opt.input);
    }
}
