use crate::error::DnsError;
use crate::protocol::name::decode_name;
use crate::protocol::types::{RecordClass, RecordType};
use base64::Engine;
use serde::Serialize;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    PTR(String),
    MX { preference: u16, exchange: String },
    TXT(Vec<String>),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    RRSIG {
        type_covered: RecordType,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: String,
        signature: Vec<u8>,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    NSEC {
        next_domain: String,
        type_bitmaps: Vec<RecordType>,
    },
    NSEC3 {
        algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed: Vec<u8>,
        type_bitmaps: Vec<RecordType>,
    },
    NSEC3PARAM {
        algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },
    SVCB {
        priority: u16,
        target: String,
        params: Vec<SvcParam>,
    },
    HTTPS {
        priority: u16,
        target: String,
        params: Vec<SvcParam>,
    },
    OPT(Vec<u8>),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
pub struct SvcParam {
    pub key: u16,
    pub value: Vec<u8>,
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect()
}

fn format_type_bitmaps(types: &[RecordType]) -> String {
    types.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(" ")
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(addr) => write!(f, "{}", addr),
            RData::AAAA(addr) => write!(f, "{}", addr),
            RData::NS(name) => write!(f, "{}", name),
            RData::CNAME(name) => write!(f, "{}", name),
            RData::PTR(name) => write!(f, "{}", name),
            RData::MX { preference, exchange } => write!(f, "{} {}", preference, exchange),
            RData::TXT(strings) => {
                let joined: Vec<String> = strings.iter().map(|s| format!("\"{}\"", s)).collect();
                write!(f, "{}", joined.join(" "))
            }
            RData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
                write!(f, "{} {} {} {} {} {} {}", mname, rname, serial, refresh, retry, expire, minimum)
            }
            RData::SRV { priority, weight, port, target } => {
                write!(f, "{} {} {} {}", priority, weight, port, target)
            }
            RData::CAA { flags, tag, value } => {
                write!(f, "{} {} \"{}\"", flags, tag, value)
            }
            RData::DS { key_tag, algorithm, digest_type, digest } => {
                write!(f, "{} {} {} {}", key_tag, algorithm, digest_type, hex(digest))
            }
            RData::RRSIG { type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer, signature } => {
                write!(f, "{} {} {} {} {} {} {} {} {}",
                    type_covered, algorithm, labels, original_ttl,
                    expiration, inception, key_tag, signer, base64_encode(signature))
            }
            RData::DNSKEY { flags, protocol, algorithm, public_key } => {
                write!(f, "{} {} {} {}", flags, protocol, algorithm, base64_encode(public_key))
            }
            RData::NSEC { next_domain, type_bitmaps } => {
                write!(f, "{} {}", next_domain, format_type_bitmaps(type_bitmaps))
            }
            RData::NSEC3 { algorithm, flags, iterations, salt, next_hashed, type_bitmaps } => {
                let salt_str = if salt.is_empty() { "-".to_string() } else { hex(salt) };
                write!(f, "{} {} {} {} {} {}", algorithm, flags, iterations, salt_str,
                    base32_encode_hex(next_hashed), format_type_bitmaps(type_bitmaps))
            }
            RData::NSEC3PARAM { algorithm, flags, iterations, salt } => {
                let salt_str = if salt.is_empty() { "-".to_string() } else { hex(salt) };
                write!(f, "{} {} {} {}", algorithm, flags, iterations, salt_str)
            }
            RData::SVCB { priority, target, params } | RData::HTTPS { priority, target, params } => {
                write!(f, "{} {}", priority, target)?;
                let formatted = format_svc_params(params);
                if !formatted.is_empty() {
                    write!(f, " {}", formatted)?;
                }
                Ok(())
            }
            RData::OPT(_) => write!(f, "<OPT>"),
            RData::Unknown(data) => {
                write!(f, "\\# {} {}", data.len(), hex(data))
            }
        }
    }
}

fn base32_encode_hex(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut num_bits = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        num_bits += 8;
        while num_bits >= 5 {
            num_bits -= 5;
            result.push(ALPHABET[((bits >> num_bits) & 0x1F) as usize] as char);
        }
    }
    if num_bits > 0 {
        result.push(ALPHABET[((bits << (5 - num_bits)) & 0x1F) as usize] as char);
    }
    result
}

impl RData {
    pub fn is_name(&self) -> bool {
        matches!(
            self,
            RData::NS(_) | RData::CNAME(_) | RData::PTR(_) | RData::MX { .. } | RData::SRV { .. }
            | RData::SVCB { .. } | RData::HTTPS { .. }
        )
    }

    pub fn is_text(&self) -> bool {
        matches!(self, RData::TXT(_) | RData::SOA { .. } | RData::Unknown(_))
    }

    pub fn is_dnssec(&self) -> bool {
        matches!(
            self,
            RData::RRSIG { .. } | RData::DNSKEY { .. } | RData::DS { .. }
            | RData::NSEC { .. } | RData::NSEC3 { .. } | RData::NSEC3PARAM { .. }
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: RecordType,
    pub rclass: RecordClass,
    pub ttl: u32,
    pub rdata: RData,
}

impl ResourceRecord {
    pub fn decode(buf: &[u8], offset: usize) -> Result<(Self, usize), DnsError> {
        let (name, name_len) = decode_name(buf, offset)?;
        let pos = offset + name_len;

        if pos + 10 > buf.len() {
            return Err(DnsError::Protocol("truncated resource record".into()));
        }

        let rtype = RecordType::from_u16(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        let rclass = RecordClass::from_u16(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;

        let rdata_start = pos + 10;
        if rdata_start + rdlength > buf.len() {
            return Err(DnsError::Protocol("truncated RDATA".into()));
        }

        let rdata = parse_rdata(buf, rdata_start, rdlength, rtype)?;
        let total_consumed = name_len + 10 + rdlength;

        Ok((
            ResourceRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            total_consumed,
        ))
    }
}

fn parse_rdata(
    buf: &[u8],
    offset: usize,
    rdlength: usize,
    rtype: RecordType,
) -> Result<RData, DnsError> {
    match rtype {
        RecordType::A => {
            if rdlength != 4 {
                return Err(DnsError::Protocol("invalid A record length".into()));
            }
            Ok(RData::A(Ipv4Addr::new(
                buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
            )))
        }
        RecordType::AAAA => {
            if rdlength != 16 {
                return Err(DnsError::Protocol("invalid AAAA record length".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            Ok(RData::AAAA(Ipv6Addr::from(octets)))
        }
        RecordType::NS => {
            let (name, _) = decode_name(buf, offset)?;
            Ok(RData::NS(name))
        }
        RecordType::CNAME => {
            let (name, _) = decode_name(buf, offset)?;
            Ok(RData::CNAME(name))
        }
        RecordType::PTR => {
            let (name, _) = decode_name(buf, offset)?;
            Ok(RData::PTR(name))
        }
        RecordType::MX => {
            if rdlength < 3 {
                return Err(DnsError::Protocol("invalid MX record length".into()));
            }
            let preference = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let (exchange, _) = decode_name(buf, offset + 2)?;
            Ok(RData::MX { preference, exchange })
        }
        RecordType::TXT => {
            let mut strings = Vec::new();
            let mut pos = offset;
            let end = offset + rdlength;
            while pos < end {
                if pos >= buf.len() {
                    return Err(DnsError::Protocol("truncated TXT record".into()));
                }
                let str_len = buf[pos] as usize;
                pos += 1;
                if pos + str_len > end {
                    return Err(DnsError::Protocol("TXT string extends beyond RDATA".into()));
                }
                let s = String::from_utf8_lossy(&buf[pos..pos + str_len]).to_string();
                strings.push(s);
                pos += str_len;
            }
            Ok(RData::TXT(strings))
        }
        RecordType::SOA => {
            let (mname, mname_len) = decode_name(buf, offset)?;
            let (rname, rname_len) = decode_name(buf, offset + mname_len)?;
            let soa_offset = offset + mname_len + rname_len;
            if soa_offset + 20 > buf.len() {
                return Err(DnsError::Protocol("truncated SOA record".into()));
            }
            let serial = u32::from_be_bytes([buf[soa_offset], buf[soa_offset + 1], buf[soa_offset + 2], buf[soa_offset + 3]]);
            let refresh = u32::from_be_bytes([buf[soa_offset + 4], buf[soa_offset + 5], buf[soa_offset + 6], buf[soa_offset + 7]]);
            let retry = u32::from_be_bytes([buf[soa_offset + 8], buf[soa_offset + 9], buf[soa_offset + 10], buf[soa_offset + 11]]);
            let expire = u32::from_be_bytes([buf[soa_offset + 12], buf[soa_offset + 13], buf[soa_offset + 14], buf[soa_offset + 15]]);
            let minimum = u32::from_be_bytes([buf[soa_offset + 16], buf[soa_offset + 17], buf[soa_offset + 18], buf[soa_offset + 19]]);
            Ok(RData::SOA { mname, rname, serial, refresh, retry, expire, minimum })
        }
        RecordType::SRV => {
            if rdlength < 7 {
                return Err(DnsError::Protocol("invalid SRV record length".into()));
            }
            let priority = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let weight = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let port = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]);
            let (target, _) = decode_name(buf, offset + 6)?;
            Ok(RData::SRV { priority, weight, port, target })
        }
        RecordType::CAA => {
            if rdlength < 2 {
                return Err(DnsError::Protocol("invalid CAA record length".into()));
            }
            let flags = buf[offset];
            let tag_len = buf[offset + 1] as usize;
            if offset + 2 + tag_len > offset + rdlength {
                return Err(DnsError::Protocol("CAA tag extends beyond RDATA".into()));
            }
            let tag = String::from_utf8_lossy(&buf[offset + 2..offset + 2 + tag_len]).to_string();
            let value = String::from_utf8_lossy(&buf[offset + 2 + tag_len..offset + rdlength]).to_string();
            Ok(RData::CAA { flags, tag, value })
        }
        RecordType::DS => {
            if rdlength < 4 {
                return Err(DnsError::Protocol("invalid DS record length".into()));
            }
            let key_tag = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let algorithm = buf[offset + 2];
            let digest_type = buf[offset + 3];
            let digest = buf[offset + 4..offset + rdlength].to_vec();
            Ok(RData::DS { key_tag, algorithm, digest_type, digest })
        }
        RecordType::RRSIG => {
            if rdlength < 18 {
                return Err(DnsError::Protocol("invalid RRSIG record length".into()));
            }
            let type_covered = RecordType::from_u16(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
            let algorithm = buf[offset + 2];
            let labels = buf[offset + 3];
            let original_ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
            let expiration = u32::from_be_bytes([buf[offset + 8], buf[offset + 9], buf[offset + 10], buf[offset + 11]]);
            let inception = u32::from_be_bytes([buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]]);
            let key_tag = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
            let (signer, signer_len) = decode_name(buf, offset + 18)?;
            let sig_start = offset + 18 + signer_len;
            let sig_end = offset + rdlength;
            let signature = if sig_start < sig_end {
                buf[sig_start..sig_end].to_vec()
            } else {
                Vec::new()
            };
            Ok(RData::RRSIG { type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer, signature })
        }
        RecordType::DNSKEY => {
            if rdlength < 4 {
                return Err(DnsError::Protocol("invalid DNSKEY record length".into()));
            }
            let flags = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let protocol = buf[offset + 2];
            let algorithm = buf[offset + 3];
            let public_key = buf[offset + 4..offset + rdlength].to_vec();
            Ok(RData::DNSKEY { flags, protocol, algorithm, public_key })
        }
        RecordType::NSEC => {
            let (next_domain, name_len) = decode_name(buf, offset)?;
            let bitmap_start = offset + name_len;
            let bitmap_len = rdlength.saturating_sub(name_len);
            let type_bitmaps = parse_type_bitmaps(buf, bitmap_start, bitmap_len);
            Ok(RData::NSEC { next_domain, type_bitmaps })
        }
        RecordType::NSEC3 => {
            if rdlength < 6 {
                return Err(DnsError::Protocol("invalid NSEC3 record length".into()));
            }
            let algorithm = buf[offset];
            let flags = buf[offset + 1];
            let iterations = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let salt_len = buf[offset + 4] as usize;
            let salt = buf[offset + 5..offset + 5 + salt_len].to_vec();
            let hash_offset = offset + 5 + salt_len;
            if hash_offset >= offset + rdlength {
                return Err(DnsError::Protocol("truncated NSEC3".into()));
            }
            let hash_len = buf[hash_offset] as usize;
            let next_hashed = buf[hash_offset + 1..hash_offset + 1 + hash_len].to_vec();
            let bitmap_start = hash_offset + 1 + hash_len;
            let bitmap_len = (offset + rdlength).saturating_sub(bitmap_start);
            let type_bitmaps = parse_type_bitmaps(buf, bitmap_start, bitmap_len);
            Ok(RData::NSEC3 { algorithm, flags, iterations, salt, next_hashed, type_bitmaps })
        }
        RecordType::NSEC3PARAM => {
            if rdlength < 5 {
                return Err(DnsError::Protocol("invalid NSEC3PARAM record length".into()));
            }
            let algorithm = buf[offset];
            let flags = buf[offset + 1];
            let iterations = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let salt_len = buf[offset + 4] as usize;
            let salt = buf[offset + 5..offset + 5 + salt_len].to_vec();
            Ok(RData::NSEC3PARAM { algorithm, flags, iterations, salt })
        }
        RecordType::SVCB => {
            let (priority, target, params) = parse_svcb_rdata(buf, offset, rdlength)?;
            Ok(RData::SVCB { priority, target, params })
        }
        RecordType::HTTPS => {
            let (priority, target, params) = parse_svcb_rdata(buf, offset, rdlength)?;
            Ok(RData::HTTPS { priority, target, params })
        }
        RecordType::OPT => {
            Ok(RData::OPT(buf[offset..offset + rdlength].to_vec()))
        }
        _ => {
            Ok(RData::Unknown(buf[offset..offset + rdlength].to_vec()))
        }
    }
}

fn parse_svcb_rdata(
    buf: &[u8],
    offset: usize,
    rdlength: usize,
) -> Result<(u16, String, Vec<SvcParam>), DnsError> {
    if rdlength < 3 {
        return Err(DnsError::Protocol("invalid SVCB/HTTPS record length".into()));
    }
    let priority = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let (target, name_len) = decode_name(buf, offset + 2)?;
    let mut params = Vec::new();
    let mut pos = offset + 2 + name_len;
    let end = offset + rdlength;
    while pos + 4 <= end {
        let key = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let value_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + value_len > end {
            return Err(DnsError::Protocol("SvcParam value extends beyond RDATA".into()));
        }
        let value = buf[pos..pos + value_len].to_vec();
        params.push(SvcParam { key, value });
        pos += value_len;
    }
    Ok((priority, target, params))
}

fn format_svc_params(params: &[SvcParam]) -> String {
    params
        .iter()
        .map(|p| format_svc_param(p))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_svc_param(param: &SvcParam) -> String {
    match param.key {
        0 => {
            // mandatory: list of u16 key IDs
            let mut keys = Vec::new();
            let mut i = 0;
            while i + 2 <= param.value.len() {
                let k = u16::from_be_bytes([param.value[i], param.value[i + 1]]);
                keys.push(svc_param_key_name(k));
                i += 2;
            }
            format!("mandatory={}", keys.join(","))
        }
        1 => {
            // alpn: length-prefixed protocol strings
            let mut alpns = Vec::new();
            let mut i = 0;
            while i < param.value.len() {
                let len = param.value[i] as usize;
                i += 1;
                if i + len <= param.value.len() {
                    alpns.push(String::from_utf8_lossy(&param.value[i..i + len]).to_string());
                }
                i += len;
            }
            format!("alpn=\"{}\"", alpns.join(","))
        }
        2 => {
            // no-default-alpn: empty
            "no-default-alpn".to_string()
        }
        3 => {
            // port: u16
            if param.value.len() >= 2 {
                let port = u16::from_be_bytes([param.value[0], param.value[1]]);
                format!("port={}", port)
            } else {
                format!("port=<invalid>")
            }
        }
        4 => {
            // ipv4hint: concatenated 4-byte IPv4 addrs
            let mut addrs = Vec::new();
            let mut i = 0;
            while i + 4 <= param.value.len() {
                let addr = Ipv4Addr::new(
                    param.value[i],
                    param.value[i + 1],
                    param.value[i + 2],
                    param.value[i + 3],
                );
                addrs.push(addr.to_string());
                i += 4;
            }
            format!("ipv4hint={}", addrs.join(","))
        }
        5 => {
            // ech: base64
            format!("ech=\"{}\"", base64_encode(&param.value))
        }
        6 => {
            // ipv6hint: concatenated 16-byte IPv6 addrs
            let mut addrs = Vec::new();
            let mut i = 0;
            while i + 16 <= param.value.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&param.value[i..i + 16]);
                let addr = Ipv6Addr::from(octets);
                addrs.push(addr.to_string());
                i += 16;
            }
            format!("ipv6hint={}", addrs.join(","))
        }
        n => {
            format!("key{}=\"{}\"", n, hex(&param.value))
        }
    }
}

fn svc_param_key_name(key: u16) -> String {
    match key {
        0 => "mandatory".to_string(),
        1 => "alpn".to_string(),
        2 => "no-default-alpn".to_string(),
        3 => "port".to_string(),
        4 => "ipv4hint".to_string(),
        5 => "ech".to_string(),
        6 => "ipv6hint".to_string(),
        n => format!("key{}", n),
    }
}

fn parse_type_bitmaps(buf: &[u8], offset: usize, length: usize) -> Vec<RecordType> {
    let mut types = Vec::new();
    let mut pos = offset;
    let end = offset + length;
    while pos + 2 <= end {
        let window = buf[pos] as u16;
        let bitmap_len = buf[pos + 1] as usize;
        pos += 2;
        if pos + bitmap_len > end {
            break;
        }
        for i in 0..bitmap_len {
            let byte = buf[pos + i];
            for bit in 0..8u16 {
                if byte & (0x80 >> bit) != 0 {
                    let type_num = window * 256 + (i as u16) * 8 + bit;
                    types.push(RecordType::from_u16(type_num));
                }
            }
        }
        pos += bitmap_len;
    }
    types
}
