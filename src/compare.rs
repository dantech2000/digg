use crate::error::DnsError;
use crate::parallel;
use crate::protocol::edns::EdnsOptions;
use crate::protocol::message::DnsMessage;
use crate::protocol::types::RecordType;
use crate::transport::{self, QueryResult};
use std::time::Duration;

pub struct ComparisonResult {
    pub server: String,
    pub result: Result<QueryResult, DnsError>,
}

pub fn compare_servers(
    servers: &[String],
    name: &str,
    qtype: RecordType,
    port: u16,
    timeout: Duration,
    force_tcp: bool,
    dnssec: bool,
) -> Vec<ComparisonResult> {
    let edns = EdnsOptions {
        dnssec_ok: dnssec,
        ..EdnsOptions::default()
    };

    // One thread per server; the count comes from @args, so it is small.
    let answers = parallel::map(servers, usize::MAX, |server| {
        (|| -> Result<QueryResult, DnsError> {
            let (query, query_id) = DnsMessage::build_query(name, qtype, true, Some(&edns))?;
            transport::send_query(server, port, &query, force_tcp, timeout)?.verify_id(query_id)
        })()
    });

    servers
        .iter()
        .zip(answers)
        .map(|(server, answer)| ComparisonResult {
            server: server.clone(),
            result: answer
                .unwrap_or_else(|| Err(DnsError::Network("worker thread panicked".into()))),
        })
        .collect()
}
