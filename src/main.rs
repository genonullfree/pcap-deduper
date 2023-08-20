use deku::prelude::*;
use std::fs::File;
use std::io::Read;

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
}

fn main() {
    let mut file = File::open("test.pcap").expect("Error: Cannot open file");
    let mut reader = Vec::<u8>::new();
    let _ = file.read_to_end(&mut reader).expect("Cannot read file");

    let header = PcapHeader::read(&reader);
    println!("{header:02x?}");

    let records = PcapRecord::read_all_records(&reader[PCAP_HEADER_LEN..]);
    println!("{}", records.len());
}
