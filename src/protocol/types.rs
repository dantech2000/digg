use serde::Serialize;
use std::fmt;

/// Declare the record types from one table of (variant, wire number, mnemonic).
///
/// Those three facts used to live in four independent matches - `from_u16`,
/// `to_u16`, `parse_name` and `Display` - so adding a type meant four edits and
/// omitting one was silent. That had already happened: OPT was missing from the
/// mnemonic table while still reachable as TYPE41.
macro_rules! record_types {
    ($($variant:ident = $num:literal, $mnemonic:literal;)*) => {
        #[allow(clippy::upper_case_acronyms)] // DNS record type names are standardized uppercase acronyms.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
        pub enum RecordType {
            $($variant,)*
            Unknown(u16),
        }

        impl RecordType {
            pub fn from_u16(val: u16) -> Self {
                match val {
                    $($num => RecordType::$variant,)*
                    n => RecordType::Unknown(n),
                }
            }

            pub fn to_u16(self) -> u16 {
                match self {
                    $(RecordType::$variant => $num,)*
                    RecordType::Unknown(n) => n,
                }
            }

            /// The variant for an already-uppercased mnemonic. TYPE<N> syntax
            /// is handled by `parse_name`, which owns the input normalisation.
            fn from_mnemonic(upper: &str) -> Option<Self> {
                match upper {
                    $($mnemonic => Some(RecordType::$variant),)*
                    _ => None,
                }
            }

            /// Every named type, so tests can assert over the whole table
            /// rather than a hand-copied subset that can fall behind it.
            #[cfg(test)]
            pub const ALL: &'static [RecordType] = &[$(RecordType::$variant,)*];
        }

        impl fmt::Display for RecordType {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(RecordType::$variant => f.pad($mnemonic),)*
                    RecordType::Unknown(n) => f.pad(&format!("TYPE{}", n)),
                }
            }
        }
    };
}

// Ordered by wire number, matching the IANA registry.
record_types! {
    A          =   1, "A";
    NS         =   2, "NS";
    CNAME      =   5, "CNAME";
    SOA        =   6, "SOA";
    PTR        =  12, "PTR";
    MX         =  15, "MX";
    TXT        =  16, "TXT";
    AAAA       =  28, "AAAA";
    SRV        =  33, "SRV";
    OPT        =  41, "OPT";
    DS         =  43, "DS";
    RRSIG      =  46, "RRSIG";
    NSEC       =  47, "NSEC";
    DNSKEY     =  48, "DNSKEY";
    NSEC3      =  50, "NSEC3";
    NSEC3PARAM =  51, "NSEC3PARAM";
    SVCB       =  64, "SVCB";
    HTTPS      =  65, "HTTPS";
    AXFR       = 252, "AXFR";
    ANY        = 255, "ANY";
    CAA        = 257, "CAA";
}

impl RecordType {
    pub fn parse_name(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        // RFC 3597 TYPE<N> syntax for arbitrary numeric types. Known numbers
        // normalize to their mnemonic variant so display stays consistent.
        if let Some(num) = upper.strip_prefix("TYPE") {
            if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
                return num.parse::<u16>().ok().map(RecordType::from_u16);
            }
        }
        // OPT is a pseudo-RR that only ever appears in the additional section,
        // never as a query mnemonic, so `digg example.com OPT` treats OPT as a
        // hostname. TYPE41 still resolves to it. This was previously expressed
        // by leaving OPT out of the mnemonic match; the table has no such gap,
        // so the exclusion is stated here instead.
        if upper == "OPT" {
            return None;
        }
        RecordType::from_mnemonic(&upper)
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

    /// The whole point of the single table: these hold for every type, not
    /// just the handful someone remembered to list.
    #[test]
    fn every_record_type_round_trips_through_number_and_mnemonic() {
        for &rtype in RecordType::ALL {
            assert_eq!(
                RecordType::from_u16(rtype.to_u16()),
                rtype,
                "{} did not survive a u16 round trip",
                rtype
            );
            let mnemonic = rtype.to_string();
            assert_eq!(
                RecordType::from_mnemonic(&mnemonic),
                Some(rtype),
                "{} did not survive a mnemonic round trip",
                rtype
            );
        }
    }

    /// OPT is reachable numerically but not as a query mnemonic.
    #[test]
    fn opt_is_excluded_from_mnemonic_parsing_but_not_from_type41() {
        assert_eq!(RecordType::parse_name("OPT"), None);
        assert_eq!(RecordType::parse_name("opt"), None);
        assert_eq!(RecordType::parse_name("TYPE41"), Some(RecordType::OPT));
        assert_eq!(RecordType::OPT.to_string(), "OPT");
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
