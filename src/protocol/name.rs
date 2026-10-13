use crate::error::DnsError;
use std::collections::HashSet;

/// Encode a domain name into DNS wire format (uncompressed).
///
/// The name is in presentation format (RFC 1035 §5.1): labels are separated
/// by dots, and a dot or backslash that is part of a label is written `\.`
/// or `\\`. `\DDD` gives a byte by its decimal value.
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::new();
    for label in split_labels(name)? {
        if label.len() > 63 {
            return Err(DnsError::Protocol(format!(
                "label '{}' exceeds 63 bytes",
                String::from_utf8_lossy(&label)
            )));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(&label);
    }
    buf.push(0);

    if buf.len() > 255 {
        return Err(DnsError::Protocol("domain name exceeds 255 bytes".into()));
    }

    Ok(buf)
}

/// Split a presentation-format name into its labels, resolving escapes. The
/// root, written "." or "", has none. Trailing dots are ignored.
fn split_labels(name: &str) -> Result<Vec<Vec<u8>>, DnsError> {
    // Drop the trailing dots that mark the root, but not an escaped dot that
    // ends the last label.
    let mut bytes = name.as_bytes();
    while let [rest @ .., b'.'] = bytes {
        let backslashes = rest.iter().rev().take_while(|&&b| b == b'\\').count();
        if backslashes % 2 == 1 {
            break;
        }
        bytes = rest;
    }

    let mut labels = Vec::new();
    if bytes.is_empty() {
        return Ok(labels);
    }
    let mut label = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let digits = bytes
                    .get(i + 1..i + 4)
                    .filter(|d| d.iter().all(u8::is_ascii_digit));
                if let Some(digits) = digits {
                    let value = digits
                        .iter()
                        .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'));
                    let byte = u8::try_from(value).map_err(|_| {
                        DnsError::Protocol("escape \\DDD exceeds 255 in domain name".into())
                    })?;
                    label.push(byte);
                    i += 4;
                } else if let Some(&escaped) = bytes.get(i + 1) {
                    label.push(escaped);
                    i += 2;
                } else {
                    return Err(DnsError::Protocol("domain name ends in a backslash".into()));
                }
            }
            b'.' => {
                if label.is_empty() {
                    return Err(DnsError::Protocol("empty label in domain name".into()));
                }
                labels.push(std::mem::take(&mut label));
                i += 1;
            }
            other => {
                label.push(other);
                i += 1;
            }
        }
    }
    if label.is_empty() {
        return Err(DnsError::Protocol("empty label in domain name".into()));
    }
    labels.push(label);
    Ok(labels)
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
                return Err(DnsError::Protocol(
                    "compression pointer loop detected".into(),
                ));
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
        // A dot or backslash inside a label is escaped, so the label
        // boundaries survive the trip through a string. Without this,
        // "first.last" as one label reads back as two, and anything rebuilt
        // from the string (the DNSSEC canonical form, for one) is a different
        // name.
        let mut escaped = String::with_capacity(label.len());
        for c in label.chars() {
            if c == '.' || c == '\\' {
                escaped.push('\\');
            }
            escaped.push(c);
        }
        labels.push(escaped);

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
