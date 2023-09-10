pub struct Packet {}

const MAC_LEN: usize = 14;

const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86dd;
const VLAN: u16 = 0x8100;
const ARP: u16 = 0x0806;

const TCP: u8 = 0x06;
const UDP: u8 = 0x11;

impl Packet {
    pub fn get_ethertype(input: &[u8]) -> u16 {
        (input[MAC_LEN - 2] as u16) << 8 | input[MAC_LEN - 1] as u16
    }

    pub fn get_llc_start() -> usize {
        MAC_LEN
    }

    pub fn get_network_start(input: &[u8]) -> usize {
        MAC_LEN
            + match Self::get_ethertype(input) {
                IPV4 => 0,
                VLAN => 4,
                IPV6 => 0, // UNSUPPORTED
                ARP => 0,  // UNSUPPORTED
                e => {
                    println!("Unsupported ethertype: {e:02x}");
                    0
                }
            }
    }

    pub fn get_transport_start(input: &[u8]) -> usize {
        if Self::get_ethertype(input) == IPV4 {
            let offset = Self::get_network_start(input);
            offset + ((input[offset] & 0x0f) * 4) as usize
        } else {
            Self::get_network_start(input)
        }
    }

    fn get_transport_type(input: &[u8]) -> u8 {
        if Self::get_ethertype(input) == IPV4 {
            let offset = Self::get_network_start(input);
            input[offset + 10]
        } else {
            // `255` is reserved, so we don't need to support it
            // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            255
        }
    }

    pub fn get_session_start(input: &[u8]) -> usize {
        let offset = Self::get_transport_start(input);
        if offset == 0 {
            return offset;
        }
        match Self::get_transport_type(input) {
            TCP => (input[offset + 12] >> 4) as usize * 4,
            UDP => offset + 4,
            _e => {
                //println!("Unsupported Transport Type: {_e:02x}");
                0
            }
        }
    }
}
