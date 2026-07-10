use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EdnsOptions {
    pub udp_payload_size: u16,
    pub version: u8,
    pub dnssec_ok: bool,
}

impl Default for EdnsOptions {
    fn default() -> Self {
        EdnsOptions {
            udp_payload_size: 4096,
            version: 0,
            dnssec_ok: false,
        }
    }
}

/// Encode an OPT pseudo-record for the additional section.
pub fn encode_opt_record(opts: &EdnsOptions) -> Vec<u8> {
    let mut buf = Vec::with_capacity(11);
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

    // RDLENGTH = 0 (no EDNS options)
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

/// Parsed EDNS information from a response OPT record.
#[derive(Debug, Clone, Serialize)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
}

/// Parse EDNS info from an OPT record's raw fields.
/// class_val = UDP payload size, ttl_val = extended RCODE + version + flags.
pub fn decode_opt_record(class_val: u16, ttl_val: u32) -> EdnsInfo {
    let ttl_bytes = ttl_val.to_be_bytes();
    EdnsInfo {
        udp_payload_size: class_val,
        extended_rcode: ttl_bytes[0],
        version: ttl_bytes[1],
        dnssec_ok: ttl_bytes[2] & 0x80 != 0,
    }
}
