use serde::Serialize;
use std::fmt;

#[allow(clippy::upper_case_acronyms)] // DNS record type names are standardized uppercase acronyms.
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

    pub fn parse_name(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        // RFC 3597 TYPE<N> syntax for arbitrary numeric types. Known numbers
        // normalize to their mnemonic variant so display stays consistent.
        if let Some(num) = upper.strip_prefix("TYPE") {
            if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
                return num.parse::<u16>().ok().map(RecordType::from_u16);
            }
        }
        match upper.as_str() {
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
            RecordType::A => f.pad("A"),
            RecordType::AAAA => f.pad("AAAA"),
            RecordType::NS => f.pad("NS"),
            RecordType::CNAME => f.pad("CNAME"),
            RecordType::PTR => f.pad("PTR"),
            RecordType::MX => f.pad("MX"),
            RecordType::TXT => f.pad("TXT"),
            RecordType::SOA => f.pad("SOA"),
            RecordType::SRV => f.pad("SRV"),
            RecordType::OPT => f.pad("OPT"),
            RecordType::DS => f.pad("DS"),
            RecordType::RRSIG => f.pad("RRSIG"),
            RecordType::NSEC => f.pad("NSEC"),
            RecordType::DNSKEY => f.pad("DNSKEY"),
            RecordType::NSEC3 => f.pad("NSEC3"),
            RecordType::NSEC3PARAM => f.pad("NSEC3PARAM"),
            RecordType::CAA => f.pad("CAA"),
            RecordType::SVCB => f.pad("SVCB"),
            RecordType::HTTPS => f.pad("HTTPS"),
            RecordType::AXFR => f.pad("AXFR"),
            RecordType::ANY => f.pad("ANY"),
            RecordType::Unknown(n) => f.pad(&format!("TYPE{}", n)),
        }
    }
}

#[allow(clippy::upper_case_acronyms)] // DNS class names are standardized uppercase mnemonics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordClass {
    IN,
    CH,
    HS,
    ANY,
    Unknown(u16),
}

impl RecordClass {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            255 => RecordClass::ANY,
            n => RecordClass::Unknown(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::ANY => 255,
            RecordClass::Unknown(n) => n,
        }
    }

    /// Parse a class mnemonic or RFC 3597 `CLASS<N>` numeric syntax.
    pub fn parse_name(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        if let Some(num) = upper.strip_prefix("CLASS") {
            if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
                return num.parse::<u16>().ok().map(RecordClass::from_u16);
            }
        }
        match upper.as_str() {
            "IN" => Some(RecordClass::IN),
            "CH" | "CHAOS" => Some(RecordClass::CH),
            "HS" | "HESIOD" => Some(RecordClass::HS),
            "ANY" => Some(RecordClass::ANY),
            _ => None,
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordClass::IN => write!(f, "IN"),
            RecordClass::CH => write!(f, "CH"),
            RecordClass::HS => write!(f, "HS"),
            RecordClass::ANY => write!(f, "ANY"),
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
    BadVers,
    Unknown(u16),
}

#[allow(dead_code)]
impl Rcode {
    /// Decode the 4-bit RCODE from the message header.
    pub fn from_u8(val: u8) -> Self {
        Self::from_u16((val & 0x0F) as u16)
    }

    /// Decode a full RCODE value, which may be up to 12 bits once the upper 8
    /// bits from an EDNS OPT record are folded in (RFC 6891). RCODE 16 is
    /// BADVERS/BADSIG.
    pub fn from_u16(val: u16) -> Self {
        match val {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            16 => Rcode::BadVers,
            n => Rcode::Unknown(n),
        }
    }

    /// The numeric RCODE value.
    pub fn code(self) -> u16 {
        match self {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NxDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::BadVers => 16,
            Rcode::Unknown(n) => n,
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
            Rcode::BadVers => write!(f, "BADVERS"),
            Rcode::Unknown(n) => write!(f, "RCODE{}", n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RecordType;

    #[test]
    fn type_n_syntax_parses_arbitrary_numeric_types() {
        assert_eq!(
            RecordType::parse_name("TYPE64512"),
            Some(RecordType::Unknown(64512))
        );
        assert_eq!(
            RecordType::parse_name("type64512"),
            Some(RecordType::Unknown(64512))
        );
        assert_eq!(
            RecordType::parse_name("TYPE0"),
            Some(RecordType::Unknown(0))
        );
        assert_eq!(
            RecordType::parse_name("TYPE65535"),
            Some(RecordType::Unknown(65535))
        );
    }

    #[test]
    fn type_n_syntax_normalizes_known_numbers_to_mnemonics() {
        assert_eq!(RecordType::parse_name("TYPE1"), Some(RecordType::A));
        assert_eq!(RecordType::parse_name("TYPE16"), Some(RecordType::TXT));
        assert_eq!(RecordType::parse_name("type65"), Some(RecordType::HTTPS));
    }

    #[test]
    fn type_n_syntax_rejects_out_of_range_and_malformed() {
        assert_eq!(RecordType::parse_name("TYPE65536"), None);
        assert_eq!(RecordType::parse_name("TYPE70000"), None);
        assert_eq!(RecordType::parse_name("TYPE"), None);
        assert_eq!(RecordType::parse_name("TYPE12X"), None);
        assert_eq!(RecordType::parse_name("TYPE-1"), None);
    }

    #[test]
    fn unknown_types_display_as_type_n() {
        assert_eq!(RecordType::Unknown(64512).to_string(), "TYPE64512");
    }

    #[test]
    fn record_class_mnemonics_and_class_n_parse() {
        use super::RecordClass;
        assert_eq!(RecordClass::parse_name("in"), Some(RecordClass::IN));
        assert_eq!(RecordClass::parse_name("CH"), Some(RecordClass::CH));
        assert_eq!(RecordClass::parse_name("chaos"), Some(RecordClass::CH));
        assert_eq!(RecordClass::parse_name("HS"), Some(RecordClass::HS));
        assert_eq!(RecordClass::parse_name("ANY"), Some(RecordClass::ANY));
        assert_eq!(RecordClass::parse_name("CLASS3"), Some(RecordClass::CH));
        assert_eq!(
            RecordClass::parse_name("CLASS42"),
            Some(RecordClass::Unknown(42))
        );
        assert_eq!(RecordClass::parse_name("CLASS70000"), None);
        assert_eq!(RecordClass::parse_name("XX"), None);
    }

    #[test]
    fn record_class_round_trips_wire_values() {
        use super::RecordClass;
        for val in [1u16, 3, 4, 255, 42] {
            assert_eq!(RecordClass::from_u16(val).to_u16(), val);
        }
        assert_eq!(RecordClass::CH.to_string(), "CH");
        assert_eq!(RecordClass::Unknown(42).to_string(), "CLASS42");
    }
}
