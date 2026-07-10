use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    Usage(String),
    Protocol(String),
    Network(String),
}

impl DnsError {
    pub fn exit_code(&self) -> i32 {
        match self {
            DnsError::Usage(_) => 1,
            DnsError::Protocol(_) => 2,
            DnsError::Network(_) => 9,
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Usage(msg) => write!(f, "{}", msg),
            DnsError::Protocol(msg) => write!(f, "{}", msg),
            DnsError::Network(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::Network(e.to_string())
    }
}
