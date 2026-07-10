use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordType {
    A,
    AAAA,
    NS,
    CNAME,
    PTR,
    MX,
    TXT,
    SOA,
    SRV,
    OPT,
    DS,
    RRSIG,
    NSEC,
    DNSKEY,
    NSEC3,
    NSEC3PARAM,
    CAA,
    SVCB,
    HTTPS,
    AXFR,
    ANY,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            41 => RecordType::OPT,
            43 => RecordType::DS,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            64 => RecordType::SVCB,
            65 => RecordType::HTTPS,
            252 => RecordType::AXFR,
            255 => RecordType::ANY,
            257 => RecordType::CAA,
            n => RecordType::Unknown(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::AXFR => 252,
            RecordType::ANY => 255,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::CAA => 257,
            RecordType::Unknown(n) => n,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "NS" => Some(RecordType::NS),
            "CNAME" => Some(RecordType::CNAME),
            "PTR" => Some(RecordType::PTR),
            "MX" => Some(RecordType::MX),
            "TXT" => Some(RecordType::TXT),
            "SOA" => Some(RecordType::SOA),
            "SRV" => Some(RecordType::SRV),
            "DS" => Some(RecordType::DS),
            "RRSIG" => Some(RecordType::RRSIG),
            "NSEC" => Some(RecordType::NSEC),
            "DNSKEY" => Some(RecordType::DNSKEY),
            "NSEC3" => Some(RecordType::NSEC3),
            "NSEC3PARAM" => Some(RecordType::NSEC3PARAM),
            "CAA" => Some(RecordType::CAA),
            "SVCB" => Some(RecordType::SVCB),
            "HTTPS" => Some(RecordType::HTTPS),
            "AXFR" => Some(RecordType::AXFR),
            "ANY" => Some(RecordType::ANY),
            _ => None,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::NS => write!(f, "NS"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::OPT => write!(f, "OPT"),
            RecordType::DS => write!(f, "DS"),
            RecordType::RRSIG => write!(f, "RRSIG"),
            RecordType::NSEC => write!(f, "NSEC"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::NSEC3 => write!(f, "NSEC3"),
            RecordType::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            RecordType::CAA => write!(f, "CAA"),
            RecordType::SVCB => write!(f, "SVCB"),
            RecordType::HTTPS => write!(f, "HTTPS"),
            RecordType::AXFR => write!(f, "AXFR"),
            RecordType::ANY => write!(f, "ANY"),
            RecordType::Unknown(n) => write!(f, "TYPE{}", n),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordClass {
    IN,
    Unknown(u16),
}

impl RecordClass {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordClass::IN,
            n => RecordClass::Unknown(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::Unknown(n) => n,
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordClass::IN => write!(f, "IN"),
            RecordClass::Unknown(n) => write!(f, "CLASS{}", n),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Unknown(u8),
}

#[allow(dead_code)]
impl Rcode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            n => Rcode::Unknown(n),
        }
    }

    pub fn is_error(&self) -> bool {
        !matches!(self, Rcode::NoError)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rcode::NoError => write!(f, "NOERROR"),
            Rcode::FormErr => write!(f, "FORMERR"),
            Rcode::ServFail => write!(f, "SERVFAIL"),
            Rcode::NxDomain => write!(f, "NXDOMAIN"),
            Rcode::NotImp => write!(f, "NOTIMP"),
            Rcode::Refused => write!(f, "REFUSED"),
            Rcode::Unknown(n) => write!(f, "RCODE{}", n),
        }
    }
}
