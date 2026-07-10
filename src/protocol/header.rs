use crate::error::DnsError;
use crate::protocol::types::Rcode;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub id: u16,
    pub qr: bool,       // false = query, true = response
    pub opcode: u8,      // 4 bits
    pub aa: bool,        // authoritative answer
    pub tc: bool,        // truncated
    pub rd: bool,        // recursion desired
    pub ra: bool,        // recursion available
    pub ad: bool,        // authenticated data (DNSSEC)
    pub cd: bool,        // checking disabled (DNSSEC)
    pub rcode: Rcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn new_query(id: u16, rd: bool) -> Self {
        Header {
            id,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags1: u8 = 0;
        if self.qr {
            flags1 |= 0x80;
        }
        flags1 |= (self.opcode & 0x0F) << 3;
        if self.aa {
            flags1 |= 0x04;
        }
        if self.tc {
            flags1 |= 0x02;
        }
        if self.rd {
            flags1 |= 0x01;
        }
        buf.push(flags1);

        let mut flags2: u8 = 0;
        if self.ra {
            flags2 |= 0x80;
        }
        if self.ad {
            flags2 |= 0x20;
        }
        if self.cd {
            flags2 |= 0x10;
        }
        match self.rcode {
            Rcode::NoError => {}
            Rcode::FormErr => flags2 |= 1,
            Rcode::ServFail => flags2 |= 2,
            Rcode::NxDomain => flags2 |= 3,
            Rcode::NotImp => flags2 |= 4,
            Rcode::Refused => flags2 |= 5,
            Rcode::Unknown(n) => flags2 |= n & 0x0F,
        }
        buf.push(flags2);

        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < 12 {
            return Err(DnsError::Protocol("message too short for header".into()));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags1 = buf[2];
        let flags2 = buf[3];

        Ok(Header {
            id,
            qr: flags1 & 0x80 != 0,
            opcode: (flags1 >> 3) & 0x0F,
            aa: flags1 & 0x04 != 0,
            tc: flags1 & 0x02 != 0,
            rd: flags1 & 0x01 != 0,
            ra: flags2 & 0x80 != 0,
            ad: flags2 & 0x20 != 0,
            cd: flags2 & 0x10 != 0,
            rcode: Rcode::from_u8(flags2 & 0x0F),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}
