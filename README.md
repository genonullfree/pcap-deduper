# PCAP Deduplicator

This tool processes a PCAP file and will output a file with any duplicate records removed.

## Usage
```
Usage: pcap-deduper [OPTIONS] --input <INPUT> [COMMAND]

Commands:
  mac        Ethernet layer (whole packet, lowest level)
  llc        Logical Link Control (LLC, Vlan, Arp, etc)
  network    Network layer (IP)
  transport  Transport layer (TCP/UDP/IGMP/etc.)
  session    Session layer (Payload)
  help       Print this message or the help of the given subcommand(s)

Options:
  -i, --input <INPUT>    Input pcap file to extract TCP streams from
  -o, --output <OUTPUT>  Output name template [default: output.pcap]
  -w, --window <WINDOW>  Set window size in frames (Set to "0" for max window size) [default: 3]
  -t, --time <TIME>      Set window time in seconds (Optional)
  -v, --verbose          Verbose output
  -h, --help             Print help
```

The commands allow for duplicate scanning to happen at various layers. Each scan will attempt to
scan at the inner-most layer requested, but if there is no additional layer it will compare with
the closest layer. For instance, if there is an ARP packet in the capture but the deduplication
command given was `transport`, that packet will be hashed at the `llc` layer, but compared with
other `transport` layer hashes.

This allows us to do some comparisons like the following:
```
[mac][llc (vlan)][network (ipv4)][transport (tcp)][session]
[mac][network (ipv4)][transport (tcp)][session]
```
If the above two packets are compared at the `mac` or `llc` levels, they will look like different
packets because they hash to different values. However if they are compared at the `network` layer
they may actually hash to the same thing. We can then use this to compare packets that have been
captured on both a vlan interface and an internal interface and deduplicate them.

Currently only the following are supported:
- llc: VLAN
- network: IPv4
- transport: TCP, UDP
