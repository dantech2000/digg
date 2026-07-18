pub mod edns;
pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod record;
pub mod types;

#[cfg(test)]
mod tests {
    use super::edns::{decode_opt_record, encode_opt_record, EdnsOptions};
    use super::header::Header;
    use super::message::DnsMessage;
    use super::name::{decode_name, encode_name};
    use super::question::Question;
    use super::record::{RData, ResourceRecord};
    use super::types::{Rcode, RecordClass, RecordType};
    use crate::error::DnsError;
    use std::net::Ipv4Addr;

    #[test]
    fn domain_names_round_trip_and_follow_compression_pointers() {
        let encoded = encode_name("www.example.com").unwrap();
        assert_eq!(encoded, b"\x03www\x07example\x03com\x00");

        let (name, consumed) = decode_name(&encoded, 0).unwrap();
        assert_eq!(name, "www.example.com.");
        assert_eq!(consumed, encoded.len());

        let mut message = encode_name("example.com").unwrap();
        let alias_offset = message.len();
        message.extend_from_slice(b"\x05alias\xc0\x00");

        let (name, consumed) = decode_name(&message, alias_offset).unwrap();
        assert_eq!(name, "alias.example.com.");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn invalid_domain_names_return_protocol_errors() {
        assert!(matches!(
            encode_name("a..example"),
            Err(DnsError::Protocol(_))
        ));
        assert!(matches!(
            encode_name(&format!("{}.example", "a".repeat(64))),
            Err(DnsError::Protocol(_))
        ));
        assert!(matches!(
            decode_name(&[0xc0], 0),
            Err(DnsError::Protocol(_))
        ));
        assert!(matches!(
            decode_name(&[0xc0, 0x00], 0),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn headers_round_trip_all_flags_and_counts() {
        let header = Header {
            id: 0xbeef,
            qr: true,
            opcode: 2,
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ad: true,
            cd: true,
            rcode: Rcode::Refused,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };

        let decoded = Header::decode(&header.encode()).unwrap();
        assert_eq!(decoded.id, header.id);
        assert_eq!(decoded.qr, header.qr);
        assert_eq!(decoded.opcode, header.opcode);
        assert_eq!(decoded.aa, header.aa);
        assert_eq!(decoded.tc, header.tc);
        assert_eq!(decoded.rd, header.rd);
        assert_eq!(decoded.ra, header.ra);
        assert_eq!(decoded.ad, header.ad);
        assert_eq!(decoded.cd, header.cd);
        assert_eq!(decoded.rcode, header.rcode);
        assert_eq!(decoded.qdcount, header.qdcount);
        assert_eq!(decoded.ancount, header.ancount);
        assert_eq!(decoded.nscount, header.nscount);
        assert_eq!(decoded.arcount, header.arcount);
        assert!(matches!(
            Header::decode(&[0; 11]),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn questions_round_trip() {
        let question = Question::new("example.com", RecordType::AAAA);
        let encoded = question.encode().unwrap();
        let (decoded, consumed) = Question::decode(&encoded, 0).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.name, "example.com.");
        assert_eq!(decoded.qtype, RecordType::AAAA);
        assert_eq!(decoded.qclass, RecordClass::IN);
        assert!(matches!(
            Question::decode(&encoded[..encoded.len() - 1], 0),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn edns_opt_records_encode_and_decode() {
        let options = EdnsOptions {
            udp_payload_size: 1232,
            version: 3,
            dnssec_ok: true,
        };
        let wire = encode_opt_record(&options);

        assert_eq!(wire.len(), 11);
        assert_eq!(wire[0], 0);
        assert_eq!(&wire[1..3], &41u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), 1232);
        assert_eq!(&wire[9..11], &0u16.to_be_bytes());

        let info = decode_opt_record(
            u16::from_be_bytes([wire[3], wire[4]]),
            u32::from_be_bytes([wire[5], wire[6], wire[7], wire[8]]),
        );
        assert_eq!(info.udp_payload_size, options.udp_payload_size);
        assert_eq!(info.extended_rcode, 0);
        assert_eq!(info.version, options.version);
        assert!(info.dnssec_ok);
    }

    #[test]
    fn record_types_parse_and_round_trip_numeric_values() {
        let types = [
            ("A", RecordType::A),
            ("AAAA", RecordType::AAAA),
            ("NS", RecordType::NS),
            ("CNAME", RecordType::CNAME),
            ("PTR", RecordType::PTR),
            ("MX", RecordType::MX),
            ("TXT", RecordType::TXT),
            ("SOA", RecordType::SOA),
            ("SRV", RecordType::SRV),
            ("DS", RecordType::DS),
            ("RRSIG", RecordType::RRSIG),
            ("NSEC", RecordType::NSEC),
            ("DNSKEY", RecordType::DNSKEY),
            ("NSEC3", RecordType::NSEC3),
            ("NSEC3PARAM", RecordType::NSEC3PARAM),
            ("CAA", RecordType::CAA),
            ("SVCB", RecordType::SVCB),
            ("HTTPS", RecordType::HTTPS),
            ("AXFR", RecordType::AXFR),
            ("ANY", RecordType::ANY),
        ];

        for (name, record_type) in types {
            assert_eq!(
                RecordType::parse_name(&name.to_lowercase()),
                Some(record_type)
            );
            assert_eq!(RecordType::from_u16(record_type.to_u16()), record_type);
        }
        assert_eq!(RecordType::from_u16(65000), RecordType::Unknown(65000));
        assert_eq!(RecordType::parse_name("not-a-record"), None);
    }

    #[test]
    fn resource_records_decode_compressed_names_and_reject_truncated_rdata() {
        let mut message = encode_name("example.com").unwrap();
        let record_offset = message.len();
        message.extend_from_slice(&[
            0xc0, 0x00, // owner: pointer to example.com
            0x00, 0x01, // TYPE A
            0x00, 0x01, // CLASS IN
            0x00, 0x00, 0x01, 0x2c, // TTL 300
            0x00, 0x04, // RDLENGTH
            192, 0, 2, 1, // RDATA
        ]);

        let (record, consumed) = ResourceRecord::decode(&message, record_offset).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(record.name, "example.com.");
        assert_eq!(record.rtype, RecordType::A);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 300);
        assert!(matches!(
            record.rdata,
            RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 1)
        ));
        assert!(matches!(
            ResourceRecord::decode(&message[..message.len() - 1], record_offset),
            Err(DnsError::Protocol(_))
        ));
    }

    // Wrap RDATA in a full resource record (root owner name) for decoding.
    fn rr_with_rdata(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8]; // owner: root
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        buf.extend_from_slice(&0u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
        buf
    }

    #[test]
    fn nsec3_oversized_lengths_error_instead_of_panicking() {
        // salt_len = 255 but only 1 byte of RDATA follows it.
        let buf = rr_with_rdata(50, &[1, 0, 0, 0, 255, 0]);
        assert!(matches!(
            ResourceRecord::decode(&buf, 0),
            Err(DnsError::Protocol(_))
        ));

        // Valid salt (len 0) but hash_len = 255 with no bytes behind it.
        let buf = rr_with_rdata(50, &[1, 0, 0, 0, 0, 255]);
        assert!(matches!(
            ResourceRecord::decode(&buf, 0),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn ds_record_displays_uppercase_zero_padded_hex_digest() {
        // key_tag=0x0102 alg=8 digest_type=2 digest=[0x0a, 0xff, 0x00]
        let rdata = [0x01, 0x02, 8, 2, 0x0A, 0xFF, 0x00];
        let buf = rr_with_rdata(43, &rdata);
        let (record, _) = ResourceRecord::decode(&buf, 0).unwrap();
        assert_eq!(record.rdata.to_string(), "258 8 2 0AFF00");
    }

    #[test]
    fn nsec3param_oversized_salt_errors_instead_of_panicking() {
        let buf = rr_with_rdata(51, &[1, 0, 0, 0, 255]);
        assert!(matches!(
            ResourceRecord::decode(&buf, 0),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn nsec3_valid_record_still_decodes() {
        // alg=1 flags=0 iter=0 salt_len=2 salt=AABB hash_len=4 hash=01020304
        // bitmap: window 0, len 1, 0x40 (bit for type A = 1)
        let rdata = [1, 0, 0, 0, 2, 0xAA, 0xBB, 4, 1, 2, 3, 4, 0, 1, 0x40];
        let buf = rr_with_rdata(50, &rdata);
        let (record, _) = ResourceRecord::decode(&buf, 0).unwrap();
        match record.rdata {
            RData::NSEC3 {
                salt, next_hashed, ..
            } => {
                assert_eq!(salt, vec![0xAA, 0xBB]);
                assert_eq!(next_hashed, vec![1, 2, 3, 4]);
            }
            other => panic!("expected NSEC3, got {:?}", other),
        }
    }

    #[test]
    fn dns_messages_parse_answers_and_extract_edns() {
        let response = [
            0xbe, 0xef, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let message = DnsMessage::parse(&response).unwrap();

        assert_eq!(message.header.id, 0xbeef);
        assert!(message.header.qr);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name, "example.com.");
        assert_eq!(message.answers.len(), 1);
        assert!(matches!(
            message.answers[0].rdata,
            RData::A(address) if address == Ipv4Addr::new(93, 184, 216, 34)
        ));
        assert!(message.authority.is_empty());
        assert!(message.additional.is_empty());
        assert!(message.edns.is_none());

        let options = EdnsOptions {
            udp_payload_size: 1232,
            version: 0,
            dnssec_ok: true,
        };
        let (query, query_id) =
            DnsMessage::build_query("example.com", RecordType::A, true, Some(&options)).unwrap();
        let parsed_query = DnsMessage::parse(&query).unwrap();
        assert_eq!(parsed_query.header.id, query_id);
        assert_eq!(parsed_query.header.arcount, 1);
        assert!(parsed_query.additional.is_empty());
        let edns = parsed_query.edns.unwrap();
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(edns.dnssec_ok);

        assert!(matches!(
            DnsMessage::parse(&response[..response.len() - 1]),
            Err(DnsError::Protocol(_))
        ));
    }
}
