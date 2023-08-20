use clap::Parser;
use deku::prelude::*;
use std::fs::File;
use std::io::Read;
use xxhash_rust::xxh3::xxh3_64;

#[derive(Parser, Debug)]
struct Opt {
    /// Input pcap file to extract TCP streams from
    #[arg(short, long, required = true)]
    input: String,

    /// Output name template
    #[arg(short, long, default_value = "output.pcap")]
    output: String,

    /// Set window size in frames
    #[arg(short, long, default_value = "3")]
    window: usize,

    /// Set window time in seconds
    #[arg(short, long)]
    time: Option<f64>,
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

impl PcapRecord {
    fn read_all_records(mut cursor: &[u8]) -> Vec<Self> {
        let mut records = Vec::<Self>::new();
        while let Some(record) = Self::read_record(cursor) {
            cursor = &cursor[record.len()..];
            records.push(record);
        }
        records
    }

    fn read_record(reader: &[u8]) -> Option<Self> {
        let (_, record) = PcapRecord::from_bytes((reader, 0)).ok()?;
        Some(record)
    }

    fn len(&self) -> usize {
        self.data.len() + 16
    }

    fn hash(&self) -> u64 {
        xxh3_64(&self.data)
    }

    fn filter_dup(records: Vec<PcapRecord>, window: usize, time: Option<f64>) -> Vec<PcapRecord> {
        let mut hash_list = Vec::<u64>::new();
        let mut out = Vec::<PcapRecord>::new();
        let mut prev_ts = 0f64;

        for (n, rec) in records.into_iter().enumerate() {
            let hash = rec.hash();
            if hash_list.contains(&hash) {
                if let Some(t) = time {
                    let cur_ts: f64 = rec.ts as f64 + (rec.tn as f64 / 1000000f64);
                    if cur_ts - prev_ts < t {
                        println!(
                            "dupe detected within {:.3}sec! frame: {n}",
                            cur_ts - prev_ts
                        );
                        prev_ts = cur_ts;
                        continue;
                    }
                } else {
                    println!("dupe detected! frame: {n}");
                    continue;
                }
            }
            if hash_list.len() > window {
                hash_list.pop();
            }
            hash_list.push(hash);
            prev_ts = rec.ts as f64 + (rec.tn as f64 / 1000000f64);
            out.push(rec);
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

        let records = PcapRecord::read_all_records(&reader[PCAP_HEADER_LEN..]);
        let rlen = records.len();

        let filtered = PcapRecord::filter_dup(records, opt.window, opt.time);
        println!(
            "original: {} filtered: {} window: {} removed: {}",
            rlen,
            filtered.len(),
            opt.window,
            rlen - filtered.len()
        );
    } else {
        println!("Error: {} cannot be loaded as a pcap file", opt.input);
    }
}
