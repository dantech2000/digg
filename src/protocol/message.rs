use crate::error::DnsError;
use crate::protocol::edns::{self, EdnsInfo, EdnsOptions};
use crate::protocol::header::Header;
use crate::protocol::question::Question;
use crate::protocol::record::ResourceRecord;
use crate::protocol::types::{RecordClass, RecordType};
use rand::Rng;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DnsMessage {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
    pub edns: Option<EdnsInfo>,
}

impl DnsMessage {
    pub fn build_query(
        name: &str,
        qtype: RecordType,
        rd: bool,
        edns_opts: Option<&EdnsOptions>,
    ) -> Result<(Vec<u8>, u16), DnsError> {
        Self::build_query_with_class(name, qtype, RecordClass::IN, rd, false, edns_opts)
    }

    pub fn build_query_with_class(
        name: &str,
        qtype: RecordType,
        qclass: RecordClass,
        rd: bool,
        cd: bool,
        edns_opts: Option<&EdnsOptions>,
    ) -> Result<(Vec<u8>, u16), DnsError> {
        let mut rng = rand::thread_rng();
        let id: u16 = rng.gen();
        let mut header = Header::new_query(id, rd);
        header.cd = cd;

        if edns_opts.is_some() {
            header.arcount = 1;
        }

        let question = Question::new_with_class(name, qtype, qclass);

        let mut buf = header.encode();
        buf.extend(question.encode()?);

        if let Some(opts) = edns_opts {
            buf.extend(edns::encode_opt_record(opts));
        }

        Ok((buf, id))
    }

    pub fn parse(buf: &[u8]) -> Result<Self, DnsError> {
        let mut header = Header::decode(buf)?;
        let mut offset = 12;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            let (q, consumed) = Question::decode(buf, offset)?;
            questions.push(q);
            offset += consumed;
        }

        let mut answers = Vec::new();
        for _ in 0..header.ancount {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            answers.push(rr);
            offset += consumed;
        }

        let mut authority = Vec::new();
        for _ in 0..header.nscount {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            authority.push(rr);
            offset += consumed;
        }

        let mut additional = Vec::new();
        let mut edns_info: Option<EdnsInfo> = None;
        for _ in 0..header.arcount {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            // OPT pseudo-record: CLASS carries the payload size, TTL the
            // extended RCODE/version/flags, RDATA the option list. Extract
            // EDNS info instead of showing it in the additional section.
            if let crate::protocol::record::RData::OPT(ref rdata) = rr.rdata {
                edns_info = Some(edns::decode_opt_record(rr.rclass.to_u16(), rr.ttl, rdata));
            }
            if rr.rtype != RecordType::OPT {
                additional.push(rr);
            }
            offset += consumed;
        }

        // RFC 6891: the OPT record carries the upper 8 bits of a 12-bit RCODE.
        // Fold them into the header's 4-bit value so extended codes such as
        // BADVERS (16) are reported correctly instead of as their low nibble.
        if let Some(ref edns) = edns_info {
            if edns.extended_rcode != 0 {
                let full = ((edns.extended_rcode as u16) << 4) | (header.rcode.code() & 0x0F);
                header.rcode = crate::protocol::types::Rcode::from_u16(full);
            }
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
            authority,
            additional,
            edns: edns_info,
        })
    }
}
