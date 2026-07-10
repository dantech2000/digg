use crate::error::DnsError;
use crate::protocol::name::{decode_name, encode_name};
use crate::protocol::types::{RecordClass, RecordType};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Question {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: RecordClass,
}

impl Question {
    pub fn new(name: &str, qtype: RecordType) -> Self {
        Question {
            name: name.to_string(),
            qtype,
            qclass: RecordClass::IN,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        let mut buf = encode_name(&self.name)?;
        buf.extend_from_slice(&self.qtype.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_u16().to_be_bytes());
        Ok(buf)
    }

    pub fn decode(buf: &[u8], offset: usize) -> Result<(Self, usize), DnsError> {
        let (name, name_len) = decode_name(buf, offset)?;
        let pos = offset + name_len;

        if pos + 4 > buf.len() {
            return Err(DnsError::Protocol("truncated question section".into()));
        }

        let qtype = RecordType::from_u16(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        let qclass = RecordClass::from_u16(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));

        Ok((
            Question {
                name,
                qtype,
                qclass,
            },
            name_len + 4,
        ))
    }
}
