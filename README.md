# PCAP Deduplicator

This tool processes a PCAP file and will output a file with any duplicate records removed.

## Usage
```
Usage: pcap-deduper [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>    Input pcap file to extract TCP streams from
  -o, --output <OUTPUT>  Output name template [default: output.pcap]
  -w, --window <WINDOW>  Set window size in frames [default: 3], "0" for Maximum window size
  -t, --time <TIME>      Set window time in seconds (Optional)
  -h, --help             Print help
```
