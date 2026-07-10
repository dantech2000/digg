use crate::error::DnsError;
use std::collections::HashSet;

/// Encode a domain name into DNS wire format (uncompressed).
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::new();
    let name = if name == "." { "" } else { name.trim_end_matches('.') };

    if name.is_empty() {
        buf.push(0);
        return Ok(buf);
    }

    for label in name.split('.') {
        let len = label.len();
        if len == 0 {
            return Err(DnsError::Protocol("empty label in domain name".into()));
        }
        if len > 63 {
            return Err(DnsError::Protocol(format!(
                "label '{}' exceeds 63 bytes",
                label
            )));
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);

    if buf.len() > 255 {
        return Err(DnsError::Protocol("domain name exceeds 255 bytes".into()));
    }

    Ok(buf)
}

/// Decode a DNS name from a message buffer at the given offset.
/// Returns the decoded name and the number of bytes consumed from `offset`.
pub fn decode_name(buf: &[u8], offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut bytes_consumed = 0;
    let mut visited: HashSet<usize> = HashSet::new();

    loop {
        if pos >= buf.len() {
            return Err(DnsError::Protocol("name extends beyond message".into()));
        }

        let len_byte = buf[pos];

        if len_byte == 0 {
            if !jumped {
                bytes_consumed = pos - offset + 1;
            }
            break;
        }

        // Compression pointer: top 2 bits are 11
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(DnsError::Protocol("truncated compression pointer".into()));
            }
            let ptr = ((len_byte as usize & 0x3F) << 8) | buf[pos + 1] as usize;

            if !jumped {
                bytes_consumed = pos - offset + 2;
                jumped = true;
            }

            if !visited.insert(ptr) {
                return Err(DnsError::Protocol("compression pointer loop detected".into()));
            }

            pos = ptr;
            continue;
        }

        // Normal label
        let label_len = len_byte as usize;
        if pos + 1 + label_len > buf.len() {
            return Err(DnsError::Protocol("label extends beyond message".into()));
        }

        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + label_len])
            .map_err(|_| DnsError::Protocol("invalid UTF-8 in label".into()))?;
        labels.push(label.to_string());

        pos += 1 + label_len;

        if !jumped {
            bytes_consumed = pos - offset;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };

    Ok((name, bytes_consumed))
}
