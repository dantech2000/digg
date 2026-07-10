use crate::error::DnsError;
use std::fs;

/// Read /etc/resolv.conf and return the first nameserver IP.
pub fn system_nameserver() -> Result<String, DnsError> {
    let contents = fs::read_to_string("/etc/resolv.conf")
        .map_err(|e| DnsError::Network(format!("failed to read /etc/resolv.conf: {}", e)))?;

    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with("nameserver") {
            if let Some(addr) = line.split_whitespace().nth(1) {
                return Ok(addr.to_string());
            }
        }
    }

    Err(DnsError::Network(
        "no nameserver found in /etc/resolv.conf".into(),
    ))
}
