use crate::error::DnsError;
use crate::protocol::name::decode_name;
use crate::protocol::types::{RecordClass, RecordType};
use base64::Engine;
use serde::Serialize;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[allow(clippy::upper_case_acronyms)] // DNS record type names are standardized uppercase acronyms.
#[derive(Debug, Clone, Serialize)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

fn format_type_bitmaps(types: &[RecordType]) -> String {
    types
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(addr) => write!(f, "{}", addr),
            RData::AAAA(addr) => write!(f, "{}", addr),
            RData::NS(name) => write!(f, "{}", name),
            RData::CNAME(name) => write!(f, "{}", name),
            RData::PTR(name) => write!(f, "{}", name),
            RData::MX {
                preference,
                exchange,
            } => write!(f, "{} {}", preference, exchange),
            RData::TXT(strings) => {
                let joined: Vec<String> = strings.iter().map(|s| format!("\"{}\"", s)).collect();
                write!(f, "{}", joined.join(" "))
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                write!(
                    f,
                    "{} {} {} {} {} {} {}",
                    mname, rname, serial, refresh, retry, expire, minimum
                )
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                write!(f, "{} {} {} {}", priority, weight, port, target)
            }
            RData::CAA { flags, tag, value } => {
                write!(f, "{} {} \"{}\"", flags, tag, value)
            }
            RData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                write!(
                    f,
                    "{} {} {} {}",
                    key_tag,
                    algorithm,
                    digest_type,
                    hex(digest)
                )
            }
            RData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            } => {
                write!(
                    f,
                    "{} {} {} {} {} {} {} {} {}",
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer,
                    base64_encode(signature)
                )
            }
            RData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                write!(
                    f,
                    "{} {} {} {}",
                    flags,
                    protocol,
                    algorithm,
                    base64_encode(public_key)
                )
            }
            RData::NSEC {
                next_domain,
                type_bitmaps,
            } => {
                write!(f, "{} {}", next_domain, format_type_bitmaps(type_bitmaps))
            }
            RData::NSEC3 {
                algorithm,
                flags,
                iterations,
                salt,
                next_hashed,
                type_bitmaps,
            } => {
                let salt_str = if salt.is_empty() {
                    "-".to_string()
                } else {
                    hex(salt)
                };
                write!(
                    f,
                    "{} {} {} {} {} {}",
                    algorithm,
                    flags,
                    iterations,
                    salt_str,
                    base32_encode_hex(next_hashed),
                    format_type_bitmaps(type_bitmaps)
                )
            }
            RData::NSEC3PARAM {
                algorithm,
                flags,
                iterations,
                salt,
            } => {
                let salt_str = if salt.is_empty() {
                    "-".to_string()
                } else {
                    hex(salt)
                };
                write!(f, "{} {} {} {}", algorithm, flags, iterations, salt_str)
            }
            RData::SVCB {
                priority,
                target,
                params,
            }
            | RData::HTTPS {
                priority,
                target,
                params,
            } => {
                write!(f, "{} {}", priority, target)?;
                let formatted = format_svc_params(params);
                if !formatted.is_empty() {
                    write!(f, " {}", formatted)?;
                }
                Ok(())
            }
            RData::OPT(_) => write!(f, "<OPT>"),
            RData::Unknown(data) => {
                if data.is_empty() {
                    write!(f, "\\# 0")
                } else {
                    write!(f, "\\# {} {}", data.len(), hex(data))
                }
            }
        }
    }
}

pub(crate) fn base32_encode_hex(data: &[u8]) -> String {
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
            RData::NS(_)
                | RData::CNAME(_)
                | RData::PTR(_)
                | RData::MX { .. }
                | RData::SRV { .. }
                | RData::SVCB { .. }
                | RData::HTTPS { .. }
        )
    }

    pub fn is_text(&self) -> bool {
        matches!(self, RData::TXT(_) | RData::SOA { .. } | RData::Unknown(_))
    }

    pub fn is_dnssec(&self) -> bool {
        matches!(
            self,
            RData::RRSIG { .. }
                | RData::DNSKEY { .. }
                | RData::DS { .. }
                | RData::NSEC { .. }
                | RData::NSEC3 { .. }
                | RData::NSEC3PARAM { .. }
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
    /// Raw RDATA bytes as received. DNSSEC validation needs the exact wire
    /// form (e.g. DNSKEY key-tag and DS digests are computed over it).
    /// Embedded names may be compressed, so name-bearing types must be
    /// re-encoded from the parsed form instead (see dnssec::canonical_rdata).
    #[serde(skip)]
    pub raw_rdata: Vec<u8>,
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
                raw_rdata: buf[rdata_start..rdata_start + rdlength].to_vec(),
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
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
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
            Ok(RData::MX {
                preference,
                exchange,
            })
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
            let serial = u32::from_be_bytes([
                buf[soa_offset],
                buf[soa_offset + 1],
                buf[soa_offset + 2],
                buf[soa_offset + 3],
            ]);
            let refresh = u32::from_be_bytes([
                buf[soa_offset + 4],
                buf[soa_offset + 5],
                buf[soa_offset + 6],
                buf[soa_offset + 7],
            ]);
            let retry = u32::from_be_bytes([
                buf[soa_offset + 8],
                buf[soa_offset + 9],
                buf[soa_offset + 10],
                buf[soa_offset + 11],
            ]);
            let expire = u32::from_be_bytes([
                buf[soa_offset + 12],
                buf[soa_offset + 13],
                buf[soa_offset + 14],
                buf[soa_offset + 15],
            ]);
            let minimum = u32::from_be_bytes([
                buf[soa_offset + 16],
                buf[soa_offset + 17],
                buf[soa_offset + 18],
                buf[soa_offset + 19],
            ]);
            Ok(RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }
        RecordType::SRV => {
            if rdlength < 7 {
                return Err(DnsError::Protocol("invalid SRV record length".into()));
            }
            let priority = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let weight = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let port = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]);
            let (target, _) = decode_name(buf, offset + 6)?;
            Ok(RData::SRV {
                priority,
                weight,
                port,
                target,
            })
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
            let value =
                String::from_utf8_lossy(&buf[offset + 2 + tag_len..offset + rdlength]).to_string();
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
            Ok(RData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            })
        }
        RecordType::RRSIG => {
            if rdlength < 18 {
                return Err(DnsError::Protocol("invalid RRSIG record length".into()));
            }
            let type_covered =
                RecordType::from_u16(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
            let algorithm = buf[offset + 2];
            let labels = buf[offset + 3];
            let original_ttl = u32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);
            let expiration = u32::from_be_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ]);
            let inception = u32::from_be_bytes([
                buf[offset + 12],
                buf[offset + 13],
                buf[offset + 14],
                buf[offset + 15],
            ]);
            let key_tag = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
            let (signer, signer_len) = decode_name(buf, offset + 18)?;
            let sig_start = offset + 18 + signer_len;
            let sig_end = offset + rdlength;
            let signature = if sig_start < sig_end {
                buf[sig_start..sig_end].to_vec()
            } else {
                Vec::new()
            };
            Ok(RData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            })
        }
        RecordType::DNSKEY => {
            if rdlength < 4 {
                return Err(DnsError::Protocol("invalid DNSKEY record length".into()));
            }
            let flags = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let protocol = buf[offset + 2];
            let algorithm = buf[offset + 3];
            let public_key = buf[offset + 4..offset + rdlength].to_vec();
            Ok(RData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            })
        }
        RecordType::NSEC => {
            let (next_domain, name_len) = decode_name(buf, offset)?;
            let bitmap_start = offset + name_len;
            let bitmap_len = rdlength.saturating_sub(name_len);
            let type_bitmaps = parse_type_bitmaps(buf, bitmap_start, bitmap_len);
            Ok(RData::NSEC {
                next_domain,
                type_bitmaps,
            })
        }
        RecordType::NSEC3 => {
            if rdlength < 6 {
                return Err(DnsError::Protocol("invalid NSEC3 record length".into()));
            }
            let rdata_end = offset + rdlength;
            let algorithm = buf[offset];
            let flags = buf[offset + 1];
            let iterations = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let salt_len = buf[offset + 4] as usize;
            let salt_end = offset + 5 + salt_len;
            if salt_end > rdata_end {
                return Err(DnsError::Protocol("NSEC3 salt exceeds RDATA".into()));
            }
            let salt = buf[offset + 5..salt_end].to_vec();
            let hash_offset = salt_end;
            if hash_offset >= rdata_end {
                return Err(DnsError::Protocol("truncated NSEC3".into()));
            }
            let hash_len = buf[hash_offset] as usize;
            let hash_end = hash_offset + 1 + hash_len;
            if hash_end > rdata_end {
                return Err(DnsError::Protocol("NSEC3 hash exceeds RDATA".into()));
            }
            let next_hashed = buf[hash_offset + 1..hash_end].to_vec();
            let bitmap_start = hash_end;
            let bitmap_len = (offset + rdlength).saturating_sub(bitmap_start);
            let type_bitmaps = parse_type_bitmaps(buf, bitmap_start, bitmap_len);
            Ok(RData::NSEC3 {
                algorithm,
                flags,
                iterations,
                salt,
                next_hashed,
                type_bitmaps,
            })
        }
        RecordType::NSEC3PARAM => {
            if rdlength < 5 {
                return Err(DnsError::Protocol(
                    "invalid NSEC3PARAM record length".into(),
                ));
            }
            let algorithm = buf[offset];
            let flags = buf[offset + 1];
            let iterations = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let salt_len = buf[offset + 4] as usize;
            let salt_end = offset + 5 + salt_len;
            if salt_end > offset + rdlength {
                return Err(DnsError::Protocol("NSEC3PARAM salt exceeds RDATA".into()));
            }
            let salt = buf[offset + 5..salt_end].to_vec();
            Ok(RData::NSEC3PARAM {
                algorithm,
                flags,
                iterations,
                salt,
            })
        }
        RecordType::SVCB => {
            let (priority, target, params) = parse_svcb_rdata(buf, offset, rdlength)?;
            Ok(RData::SVCB {
                priority,
                target,
                params,
            })
        }
        RecordType::HTTPS => {
            let (priority, target, params) = parse_svcb_rdata(buf, offset, rdlength)?;
            Ok(RData::HTTPS {
                priority,
                target,
                params,
            })
        }
        RecordType::OPT => Ok(RData::OPT(buf[offset..offset + rdlength].to_vec())),
        _ => Ok(RData::Unknown(buf[offset..offset + rdlength].to_vec())),
    }
}

fn parse_svcb_rdata(
    buf: &[u8],
    offset: usize,
    rdlength: usize,
) -> Result<(u16, String, Vec<SvcParam>), DnsError> {
    if rdlength < 3 {
        return Err(DnsError::Protocol(
            "invalid SVCB/HTTPS record length".into(),
        ));
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
            return Err(DnsError::Protocol(
                "SvcParam value extends beyond RDATA".into(),
            ));
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
        .map(format_svc_param)
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
                "port=<invalid>".to_string()
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
        let window = buf[pos] as u32;
        let bitmap_len = buf[pos + 1] as usize;
        pos += 2;
        if pos + bitmap_len > end {
            break;
        }
        // A window covers at most 256 types = 32 bitmap bytes (RFC 4034 §4.1.2).
        // A longer block is malformed; ignore the excess so the type number
        // (window*256 + bit index) can never exceed u16::MAX. Computing in u32
        // also avoids the overflow a hostile bitmap would otherwise cause.
        for i in 0..bitmap_len.min(32) {
            let byte = buf[pos + i];
            for bit in 0..8u32 {
                if byte & (0x80 >> bit) != 0 {
                    let type_num = window * 256 + (i as u32) * 8 + bit;
                    types.push(RecordType::from_u16(type_num as u16));
                }
            }
        }
        pos += bitmap_len;
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Simple address / name variants ===

    #[test]
    fn address_and_name_rdata_render_plainly() {
        assert_eq!(
            RData::A(Ipv4Addr::new(93, 184, 216, 34)).to_string(),
            "93.184.216.34"
        );
        assert_eq!(
            RData::AAAA("2606:2800:220:1::1946".parse().unwrap()).to_string(),
            "2606:2800:220:1::1946"
        );
        assert_eq!(
            RData::NS("ns1.example.com.".into()).to_string(),
            "ns1.example.com."
        );
        assert_eq!(
            RData::CNAME("www.example.com.".into()).to_string(),
            "www.example.com."
        );
        assert_eq!(
            RData::PTR("host.example.com.".into()).to_string(),
            "host.example.com."
        );
        assert_eq!(
            RData::MX {
                preference: 10,
                exchange: "mail.example.com.".into()
            }
            .to_string(),
            "10 mail.example.com."
        );
    }

    // === TXT quoting ===

    #[test]
    fn txt_strings_are_quoted_and_space_joined() {
        assert_eq!(
            RData::TXT(vec!["v=spf1 -all".into()]).to_string(),
            "\"v=spf1 -all\""
        );
        assert_eq!(
            RData::TXT(vec!["a".into(), "b".into()]).to_string(),
            "\"a\" \"b\""
        );
        assert_eq!(RData::TXT(vec!["".into()]).to_string(), "\"\"");
    }

    #[test]
    fn txt_embedded_quotes_are_not_escaped_yet() {
        // Pins current behavior: inner quotes pass through unescaped. If this
        // is ever changed to RFC 1035 \" escaping, update this test deliberately.
        assert_eq!(
            RData::TXT(vec!["say \"hi\"".into()]).to_string(),
            "\"say \"hi\"\""
        );
    }

    // === Structured variants ===

    #[test]
    fn soa_renders_all_seven_fields_in_order() {
        let soa = RData::SOA {
            mname: "ns1.example.com.".into(),
            rname: "hostmaster.example.com.".into(),
            serial: 2024010101,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 300,
        };
        assert_eq!(
            soa.to_string(),
            "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300"
        );
    }

    #[test]
    fn srv_renders_priority_weight_port_target() {
        let srv = RData::SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: "sip.example.com.".into(),
        };
        assert_eq!(srv.to_string(), "10 60 5060 sip.example.com.");
    }

    #[test]
    fn caa_renders_with_quoted_value() {
        let caa = RData::CAA {
            flags: 0,
            tag: "issue".into(),
            value: "letsencrypt.org".into(),
        };
        assert_eq!(caa.to_string(), "0 issue \"letsencrypt.org\"");
    }

    // === DNSSEC variants ===

    #[test]
    fn ds_digest_renders_uppercase_hex() {
        let ds = RData::DS {
            key_tag: 20326,
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(ds.to_string(), "20326 8 2 DEADBEEF");
    }

    #[test]
    fn rrsig_renders_signature_as_base64() {
        let rrsig = RData::RRSIG {
            type_covered: RecordType::A,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            expiration: 1700000000,
            inception: 1690000000,
            key_tag: 12345,
            signer: "example.com.".into(),
            signature: vec![1, 2, 3, 4],
        };
        assert_eq!(
            rrsig.to_string(),
            "A 13 2 3600 1700000000 1690000000 12345 example.com. AQIDBA=="
        );
    }

    #[test]
    fn dnskey_renders_key_as_base64() {
        let key = RData::DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![0xFF, 0x00],
        };
        assert_eq!(key.to_string(), "257 3 13 /wA=");
    }

    #[test]
    fn nsec_renders_next_domain_and_type_list() {
        let nsec = RData::NSEC {
            next_domain: "next.example.com.".into(),
            type_bitmaps: vec![RecordType::A, RecordType::AAAA, RecordType::RRSIG],
        };
        assert_eq!(nsec.to_string(), "next.example.com. A AAAA RRSIG");
    }

    #[test]
    fn nsec3_empty_salt_renders_as_dash() {
        let nsec3 = RData::NSEC3 {
            algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: vec![],
            next_hashed: vec![0x66],
            type_bitmaps: vec![RecordType::A],
        };
        assert_eq!(nsec3.to_string(), "1 0 10 - CO A");
    }

    #[test]
    fn nsec3_salt_renders_as_hex() {
        let nsec3 = RData::NSEC3 {
            algorithm: 1,
            flags: 1,
            iterations: 5,
            salt: vec![0xAB, 0xCD],
            next_hashed: vec![0x66, 0x6F],
            type_bitmaps: vec![],
        };
        assert_eq!(nsec3.to_string(), "1 1 5 ABCD CPNG ");
    }

    #[test]
    fn nsec3param_renders_salt_or_dash() {
        let with_salt = RData::NSEC3PARAM {
            algorithm: 1,
            flags: 0,
            iterations: 12,
            salt: vec![0x01, 0x02],
        };
        assert_eq!(with_salt.to_string(), "1 0 12 0102");
        let no_salt = RData::NSEC3PARAM {
            algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
        };
        assert_eq!(no_salt.to_string(), "1 0 0 -");
    }

    #[test]
    fn base32hex_matches_rfc4648_test_vectors() {
        // RFC 4648 §10, padding stripped.
        assert_eq!(base32_encode_hex(b""), "");
        assert_eq!(base32_encode_hex(b"f"), "CO");
        assert_eq!(base32_encode_hex(b"fo"), "CPNG");
        assert_eq!(base32_encode_hex(b"foo"), "CPNMU");
        assert_eq!(base32_encode_hex(b"foob"), "CPNMUOG");
        assert_eq!(base32_encode_hex(b"fooba"), "CPNMUOJ1");
        assert_eq!(base32_encode_hex(b"foobar"), "CPNMUOJ1E8");
    }

    // === SVCB / HTTPS (RFC 9460) ===

    fn param(key: u16, value: &[u8]) -> SvcParam {
        SvcParam {
            key,
            value: value.to_vec(),
        }
    }

    #[test]
    fn svcb_alias_mode_renders_priority_and_target_only() {
        let alias = RData::SVCB {
            priority: 0,
            target: "svc.example.com.".into(),
            params: vec![],
        };
        assert_eq!(alias.to_string(), "0 svc.example.com.");
    }

    #[test]
    fn https_params_render_each_known_key() {
        let https = RData::HTTPS {
            priority: 1,
            target: ".".into(),
            params: vec![
                param(0, &[0x00, 0x01, 0x00, 0x04]), // mandatory=alpn,ipv4hint
                param(1, &[2, b'h', b'3', 2, b'h', b'2']), // alpn="h3,h2"
                param(2, &[]),                       // no-default-alpn
                param(3, &[0x01, 0xBB]),             // port=443
                param(4, &[1, 2, 3, 4, 5, 6, 7, 8]), // two ipv4 hints
                param(5, &[0xAB, 0xCD]),             // ech base64
                param(6, &{
                    let mut v = vec![0u8; 16];
                    v[0] = 0x20;
                    v[1] = 0x01;
                    v[2] = 0x0d;
                    v[3] = 0xb8;
                    v[15] = 1;
                    v
                }), // ipv6hint
                param(667, &[0xFF]),                 // unknown key
            ],
        };
        assert_eq!(
            https.to_string(),
            "1 . mandatory=alpn,ipv4hint alpn=\"h3,h2\" no-default-alpn port=443 \
             ipv4hint=1.2.3.4,5.6.7.8 ech=\"q80=\" ipv6hint=2001:db8::1 key667=\"FF\""
        );
    }

    #[test]
    fn svc_param_port_too_short_renders_invalid_marker() {
        assert_eq!(format_svc_param(&param(3, &[0x01])), "port=<invalid>");
    }

    #[test]
    fn svc_param_truncated_lists_drop_partial_entries() {
        // 5 bytes is one full IPv4 hint plus a dangling byte — dangling ignored.
        assert_eq!(
            format_svc_param(&param(4, &[1, 2, 3, 4, 9])),
            "ipv4hint=1.2.3.4"
        );
        // Truncated alpn length prefix: entry dropped, no panic.
        assert_eq!(format_svc_param(&param(1, &[5, b'h'])), "alpn=\"\"");
        // Odd-length mandatory list: dangling byte ignored.
        assert_eq!(
            format_svc_param(&param(0, &[0x00, 0x03, 0xFF])),
            "mandatory=port"
        );
    }

    // === OPT / unknown ===

    #[test]
    fn opt_renders_placeholder() {
        assert_eq!(RData::OPT(vec![1, 2, 3]).to_string(), "<OPT>");
    }

    #[test]
    fn unknown_rdata_renders_rfc3597_generic_format() {
        assert_eq!(
            RData::Unknown(vec![0xDE, 0xAD, 0xBE, 0xEF]).to_string(),
            "\\# 4 DEADBEEF"
        );
    }

    #[test]
    fn unknown_rdata_empty_renders_rfc3597_without_trailing_space() {
        assert_eq!(RData::Unknown(vec![]).to_string(), "\\# 0");
    }

    // === Category predicates ===

    #[test]
    fn rdata_category_predicates_partition_variants() {
        assert!(RData::NS("a.".into()).is_name());
        assert!(RData::HTTPS {
            priority: 1,
            target: ".".into(),
            params: vec![]
        }
        .is_name());
        assert!(RData::TXT(vec![]).is_text());
        assert!(RData::Unknown(vec![]).is_text());
        assert!(RData::DS {
            key_tag: 0,
            algorithm: 0,
            digest_type: 0,
            digest: vec![]
        }
        .is_dnssec());
        assert!(RData::NSEC3PARAM {
            algorithm: 0,
            flags: 0,
            iterations: 0,
            salt: vec![]
        }
        .is_dnssec());
        assert!(!RData::A(Ipv4Addr::LOCALHOST).is_name());
        assert!(!RData::A(Ipv4Addr::LOCALHOST).is_text());
        assert!(!RData::A(Ipv4Addr::LOCALHOST).is_dnssec());
    }

    // === Wire-format fixture: decode + render round trip ===

    /// HTTPS record captured shape: root name, priority 1, target ".",
    /// alpn="h3,h2" port=443 ipv4hint=1.2.3.4
    #[test]
    fn https_record_decodes_from_wire_and_renders_like_dig() {
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            0x00,                   // owner: root
            0x00, 0x41,             // TYPE 65 (HTTPS)
            0x00, 0x01,             // CLASS IN
            0x00, 0x00, 0x0E, 0x10, // TTL 3600
            0x00, 0x1B,             // RDLENGTH 27
            0x00, 0x01,             // priority 1
            0x00,                   // target: root
            0x00, 0x01, 0x00, 0x06, 0x02, b'h', b'3', 0x02, b'h', b'2', // alpn
            0x00, 0x03, 0x00, 0x02, 0x01, 0xBB,                         // port 443
            0x00, 0x04, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,             // ipv4hint
        ];
        let (rr, consumed) = ResourceRecord::decode(&wire, 0).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(rr.rtype, RecordType::HTTPS);
        assert_eq!(rr.ttl, 3600);
        assert_eq!(
            rr.rdata.to_string(),
            "1 . alpn=\"h3,h2\" port=443 ipv4hint=1.2.3.4"
        );
    }

    #[test]
    fn svcb_param_value_beyond_rdata_is_an_error() {
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            0x00,
            0x00, 0x40,             // TYPE 64 (SVCB)
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x07,             // RDLENGTH 7
            0x00, 0x01,             // priority
            0x00,                   // target root
            0x00, 0x03, 0x00, 0x63, // port param claims 99-byte value
        ];
        assert!(ResourceRecord::decode(&wire, 0).is_err());
    }

    #[test]
    fn fixed_length_rdata_rejects_short_buffers() {
        // A record with rdlength 3.
        let bad_a: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x03, 1, 2, 3,
        ];
        assert!(ResourceRecord::decode(&bad_a, 0).is_err());
        // AAAA record with rdlength 4.
        let bad_aaaa: Vec<u8> = vec![
            0x00, 0x00, 0x1C, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x04, 1, 2, 3, 4,
        ];
        assert!(ResourceRecord::decode(&bad_aaaa, 0).is_err());
    }

    #[test]
    fn type_bitmap_window_beyond_window_zero_decodes_high_types() {
        // Window 1 covers types 256-511; bit 1 of first byte = type 257 (CAA).
        let buf = vec![0x01, 0x01, 0x40];
        let types = parse_type_bitmaps(&buf, 0, 3);
        assert_eq!(types, vec![RecordType::CAA]);
    }

    #[test]
    fn type_bitmap_oversized_block_does_not_overflow() {
        // Regression: window 255 with a bitmap block longer than 32 bytes
        // used to overflow the u16 type-number computation (panic in debug,
        // silent wrap in release). Found by cargo-fuzz. Must not panic and
        // must not emit nonsense wrapped type numbers.
        let mut buf = vec![0xFF, 40]; // window 255, claims 40 bitmap bytes
        buf.extend(std::iter::repeat_n(0xFFu8, 40));
        let types = parse_type_bitmaps(&buf, 0, buf.len());
        // Only the first 32 bytes (types 65280..=65535) are considered.
        assert!(types.iter().all(|t| t.to_u16() >= 65280));
    }

    #[test]
    fn type_bitmap_truncated_window_is_ignored_without_panic() {
        // Claims 4 bitmap bytes but only 1 present.
        let buf = vec![0x00, 0x04, 0x40];
        let types = parse_type_bitmaps(&buf, 0, 3);
        assert!(types.is_empty());
    }
}
