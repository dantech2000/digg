use serde::Serialize;
use std::net::IpAddr;

/// EDNS option code for NSID (RFC 5001).
pub const OPTION_NSID: u16 = 3;
/// EDNS option code for Client Subnet (RFC 7871).
pub const OPTION_CLIENT_SUBNET: u16 = 8;

/// A raw EDNS option: code plus opaque payload (RFC 6891 §6.1.2).
#[derive(Debug, Clone, Serialize)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EdnsOptions {
    pub udp_payload_size: u16,
    pub version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<EdnsOption>,
}

impl Default for EdnsOptions {
    fn default() -> Self {
        EdnsOptions {
            udp_payload_size: 4096,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }
}

/// Build the RFC 7871 Client Subnet option for a query. The address is
/// truncated to the prefix length with any trailing bits zeroed, and
/// SCOPE PREFIX-LENGTH is 0 as required on queries.
pub fn client_subnet_option(addr: IpAddr, source_prefix: u8) -> EdnsOption {
    let (family, octets): (u16, Vec<u8>) = match addr {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2, v6.octets().to_vec()),
    };

    let addr_len = source_prefix.div_ceil(8) as usize;
    let mut address = octets[..addr_len].to_vec();
    // Zero bits beyond the prefix in the final byte (RFC 7871 §6).
    let partial_bits = source_prefix % 8;
    if partial_bits != 0 {
        if let Some(last) = address.last_mut() {
            *last &= 0xFFu8 << (8 - partial_bits);
        }
    }

    let mut data = Vec::with_capacity(4 + address.len());
    data.extend_from_slice(&family.to_be_bytes());
    data.push(source_prefix);
    data.push(0); // scope prefix-length: always 0 on queries
    data.extend_from_slice(&address);

    EdnsOption {
        code: OPTION_CLIENT_SUBNET,
        data,
    }
}

/// Encode an OPT pseudo-record for the additional section.
pub fn encode_opt_record(opts: &EdnsOptions) -> Vec<u8> {
    let rdlength: usize = opts.options.iter().map(|o| 4 + o.data.len()).sum();

    let mut buf = Vec::with_capacity(11 + rdlength);
    buf.push(0); // root name
    buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    buf.extend_from_slice(&opts.udp_payload_size.to_be_bytes()); // CLASS = UDP payload size

    // TTL field: extended RCODE (8) + version (8) + flags (16)
    let mut ttl_bytes = [0u8; 4];
    ttl_bytes[0] = 0; // extended RCODE
    ttl_bytes[1] = opts.version;
    if opts.dnssec_ok {
        ttl_bytes[2] = 0x80; // DO bit
    }
    ttl_bytes[3] = 0;
    buf.extend_from_slice(&ttl_bytes);

    buf.extend_from_slice(&(rdlength as u16).to_be_bytes());
    for option in &opts.options {
        buf.extend_from_slice(&option.code.to_be_bytes());
        buf.extend_from_slice(&(option.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&option.data);
    }
    buf
}

/// A server identifier returned via the NSID option (RFC 5001). Operators
/// usually encode a printable instance name, but the payload is opaque
/// bytes, so both renderings are kept.
#[derive(Debug, Clone, Serialize)]
pub struct Nsid {
    pub hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl std::fmt::Display for Nsid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.text {
            Some(text) => write!(f, "{} (\"{}\")", self.hex, text),
            None => write!(f, "{}", self.hex),
        }
    }
}

fn parse_nsid(data: &[u8]) -> Nsid {
    let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
    let text = if !data.is_empty() && data.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        Some(String::from_utf8_lossy(data).to_string())
    } else {
        None
    };
    Nsid { hex, text }
}

/// A Client Subnet option parsed from a response (RFC 7871 §6).
#[derive(Debug, Clone, Serialize)]
pub struct ClientSubnet {
    pub family: u16,
    pub source_prefix: u8,
    pub scope_prefix: u8,
    pub address: String,
}

impl std::fmt::Display for ClientSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.address, self.source_prefix, self.scope_prefix
        )
    }
}

/// Parsed EDNS information from a response OPT record.
#[derive(Debug, Clone, Serialize)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<ClientSubnet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsid: Option<Nsid>,
}

/// Parse EDNS info from an OPT record's raw fields.
/// class_val = UDP payload size, ttl_val = extended RCODE + version + flags,
/// rdata = the option list.
pub fn decode_opt_record(class_val: u16, ttl_val: u32, rdata: &[u8]) -> EdnsInfo {
    let ttl_bytes = ttl_val.to_be_bytes();
    let mut info = EdnsInfo {
        udp_payload_size: class_val,
        extended_rcode: ttl_bytes[0],
        version: ttl_bytes[1],
        dnssec_ok: ttl_bytes[2] & 0x80 != 0,
        subnet: None,
        nsid: None,
    };

    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            break; // malformed option: stop parsing rather than misread
        }
        match code {
            OPTION_CLIENT_SUBNET => info.subnet = parse_client_subnet(&rdata[pos..pos + len]),
            OPTION_NSID => info.nsid = Some(parse_nsid(&rdata[pos..pos + len])),
            _ => {}
        }
        pos += len;
    }
    info
}

fn parse_client_subnet(data: &[u8]) -> Option<ClientSubnet> {
    if data.len() < 4 {
        return None;
    }
    let family = u16::from_be_bytes([data[0], data[1]]);
    let source_prefix = data[2];
    let scope_prefix = data[3];
    let addr_bytes = &data[4..];

    let address = match family {
        1 => {
            let mut octets = [0u8; 4];
            let n = addr_bytes.len().min(4);
            octets[..n].copy_from_slice(&addr_bytes[..n]);
            std::net::Ipv4Addr::from(octets).to_string()
        }
        2 => {
            let mut octets = [0u8; 16];
            let n = addr_bytes.len().min(16);
            octets[..n].copy_from_slice(&addr_bytes[..n]);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => return None,
    };

    Some(ClientSubnet {
        family,
        source_prefix,
        scope_prefix,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_subnet_option_encodes_rfc7871_wire_format() {
        let opt = client_subnet_option("96.112.0.0".parse().unwrap(), 16);
        assert_eq!(opt.code, OPTION_CLIENT_SUBNET);
        // family=1, source=16, scope=0, 2 address bytes
        assert_eq!(opt.data, vec![0x00, 0x01, 16, 0, 96, 112]);
    }

    #[test]
    fn client_subnet_zeroes_bits_beyond_the_prefix() {
        // /20 keeps 3 bytes; the third byte keeps only its top 4 bits.
        let opt = client_subnet_option("1.2.255.255".parse().unwrap(), 20);
        assert_eq!(&opt.data[4..], &[1, 2, 0xF0]);
    }

    #[test]
    fn client_subnet_zero_prefix_sends_no_address_bytes() {
        // RFC 7871 §7.1.2 privacy opt-out: family present, no address.
        let opt = client_subnet_option("0.0.0.0".parse().unwrap(), 0);
        assert_eq!(opt.data, vec![0x00, 0x01, 0, 0]);
    }

    #[test]
    fn client_subnet_ipv6_uses_family_two() {
        let opt = client_subnet_option("2001:db8::".parse().unwrap(), 48);
        assert_eq!(&opt.data[..4], &[0x00, 0x02, 48, 0]);
        assert_eq!(&opt.data[4..], &[0x20, 0x01, 0x0d, 0xb8, 0, 0]);
    }

    #[test]
    fn opt_record_rdlength_covers_options() {
        let opts = EdnsOptions {
            options: vec![client_subnet_option("192.0.2.0".parse().unwrap(), 24)],
            ..EdnsOptions::default()
        };
        let encoded = encode_opt_record(&opts);
        // name(1) + type(2) + class(2) + ttl(4) = 9 bytes, then rdlength.
        let rdlength = u16::from_be_bytes([encoded[9], encoded[10]]) as usize;
        assert_eq!(rdlength, 4 + 7); // option header + family/source/scope/3 addr bytes
        assert_eq!(encoded.len(), 11 + rdlength);
    }

    #[test]
    fn response_ecs_option_round_trips_through_decode() {
        // family=1, source=24, scope=18, addr 96.112.0
        let rdata = [0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 24, 18, 96, 112, 0];
        let info = decode_opt_record(1232, 0, &rdata);
        let subnet = info.subnet.expect("subnet parsed");
        assert_eq!(subnet.family, 1);
        assert_eq!(subnet.source_prefix, 24);
        assert_eq!(subnet.scope_prefix, 18);
        assert_eq!(subnet.address, "96.112.0.0");
        assert_eq!(subnet.to_string(), "96.112.0.0/24/18");
    }

    #[test]
    fn truncated_option_list_stops_without_panicking() {
        // Option claims 10 bytes of payload but only 2 follow.
        let rdata = [0x00, 0x08, 0x00, 0x0A, 0x00, 0x01];
        let info = decode_opt_record(1232, 0, &rdata);
        assert!(info.subnet.is_none());
    }

    #[test]
    fn unknown_options_are_skipped() {
        // NSID (code 3) followed by ECS — ECS still found.
        let rdata = [
            0x00, 0x03, 0x00, 0x02, 0xAB, 0xCD, // NSID
            0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0, 0, // ECS /0
        ];
        let info = decode_opt_record(512, 0, &rdata);
        assert!(info.subnet.is_some());
    }

    #[test]
    fn nsid_option_parses_printable_and_binary_payloads() {
        // Printable payload: hex plus quoted text.
        let rdata = [0x00, 0x03, 0x00, 0x04, b'l', b'a', b'x', b'3'];
        let info = decode_opt_record(1232, 0, &rdata);
        let nsid = info.nsid.expect("nsid parsed");
        assert_eq!(nsid.hex, "6c617833");
        assert_eq!(nsid.text.as_deref(), Some("lax3"));
        assert_eq!(nsid.to_string(), "6c617833 (\"lax3\")");

        // Binary payload: hex only.
        let rdata = [0x00, 0x03, 0x00, 0x02, 0x00, 0xFF];
        let info = decode_opt_record(1232, 0, &rdata);
        let nsid = info.nsid.expect("nsid parsed");
        assert_eq!(nsid.hex, "00ff");
        assert_eq!(nsid.text, None);
        assert_eq!(nsid.to_string(), "00ff");
    }

    #[test]
    fn nsid_request_option_encodes_with_empty_payload() {
        let opts = EdnsOptions {
            options: vec![EdnsOption {
                code: OPTION_NSID,
                data: vec![],
            }],
            ..EdnsOptions::default()
        };
        let encoded = encode_opt_record(&opts);
        let rdlength = u16::from_be_bytes([encoded[9], encoded[10]]);
        assert_eq!(rdlength, 4); // option code + zero length, no payload
        assert_eq!(&encoded[11..], &[0x00, 0x03, 0x00, 0x00]);
    }
}
