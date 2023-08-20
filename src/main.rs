use std::fs::File;
use std::io;
use std::io::{BufReader, BufRead};
use deku::prelude::*;

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

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct RecordHeader {
    ts: u32,
    tn: u32,
    caplen: u32,
    origlen: u32,
    #[deku(count = "caplen")]
    data: Vec<u8>,
}

fn main() {
    let file =  File::open("test.pcap").expect("Error: Cannot open file");
    let mut reader = BufReader::new(file);

    let buf = reader.fill_buf().unwrap();
    let buflen = buf.len();
    let ((rest, _), header) = PcapHeader::from_bytes((buf, 0)).unwrap();
    let read = rest.len();
    reader.consume(buflen - read);

    println!("{header:02x?}");

    for _ in 0..3 {
        read_record(&mut reader);
    }
}

fn read_record(reader: &mut BufReader<File>) {
    let buf = reader.fill_buf().unwrap();
    let buflen = buf.len();
    let ((rest, _), record) = RecordHeader::from_bytes((buf, 0)).unwrap();
    let read = rest.len();
    println!("{record:02x?}");
    reader.consume(buflen - read);
}
