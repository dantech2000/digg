use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    Usage(String),
    Protocol(String),
    Network(String),
    Timeout(String),
}

impl DnsError {
    pub fn exit_code(&self) -> i32 {
        match self {
            DnsError::Usage(_) => 1,
            DnsError::Protocol(_) => 2,
            DnsError::Network(_) => 9,
            DnsError::Timeout(_) => 9,
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Usage(msg) => write!(f, "{}", msg),
            DnsError::Protocol(msg) => write!(f, "{}", msg),
            DnsError::Network(msg) => write!(f, "{}", msg),
            DnsError::Timeout(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::Network(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::DnsError;

    #[test]
    fn exit_codes_are_a_stable_contract() {
        // Scripts depend on these values; changing them is a breaking change.
        assert_eq!(DnsError::Usage("x".into()).exit_code(), 1);
        assert_eq!(DnsError::Protocol("x".into()).exit_code(), 2);
        assert_eq!(DnsError::Network("x".into()).exit_code(), 9);
        assert_eq!(DnsError::Timeout("x".into()).exit_code(), 9);
    }

    #[test]
    fn io_errors_convert_to_network_errors() {
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err: DnsError = io.into();
        assert_eq!(err.exit_code(), 9);
        assert_eq!(err.to_string(), "timed out");
    }
}
