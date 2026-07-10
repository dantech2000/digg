use crate::error::DnsError;
use crate::protocol::message::DnsMessage;
use crate::protocol::record::ResourceRecord;
use crate::protocol::types::{RecordType, Rcode};
use crate::transport;
use std::net::TcpStream;
use std::time::Duration;

pub fn perform_axfr(
    server: &str,
    port: u16,
    name: &str,
    timeout: Duration,
) -> Result<Vec<ResourceRecord>, DnsError> {
    let (query, _query_id) = DnsMessage::build_query(name, RecordType::AXFR, false, None)?;

    let addr = format!("{}:{}", server, port);
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| DnsError::Network(format!("invalid address '{}': {}", addr, e)))?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| DnsError::Network(format!("AXFR TCP connect to {} failed: {}", addr, e)))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError::Network(format!("failed to set AXFR timeout: {}", e)))?;

    // Send query
    transport::tcp_send_raw(&mut stream, &query)?;

    let mut all_records: Vec<ResourceRecord> = Vec::new();
    let mut soa_count = 0;

    loop {
        let (message, _msg_len) = transport::tcp_read_message(&mut stream)?;

        if message.header.rcode != Rcode::NoError {
            return Err(DnsError::Protocol(format!(
                "AXFR failed: {}",
                message.header.rcode
            )));
        }

        for rr in message.answers {
            if rr.rtype == RecordType::SOA {
                soa_count += 1;
            }
            all_records.push(rr);
            if soa_count >= 2 {
                return Ok(all_records);
            }
        }

        // Safety: if we got no answers at all, something is wrong
        if all_records.is_empty() && soa_count == 0 {
            return Err(DnsError::Protocol("AXFR: empty response".into()));
        }
    }
}
