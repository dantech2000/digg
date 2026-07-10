use crate::error::DnsError;
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

    // Query all servers in parallel using scoped threads
    let mut results = Vec::with_capacity(servers.len());

    std::thread::scope(|s| {
        let handles: Vec<_> = servers
            .iter()
            .map(|server| {
                let edns = &edns;
                s.spawn(move || {
                    let result = (|| -> Result<QueryResult, DnsError> {
                        let (query, query_id) =
                            DnsMessage::build_query(name, qtype, true, Some(edns))?;
                        let r =
                            transport::send_query(server, port, &query, force_tcp, timeout, 4096)?;
                        transport::verify_id(&r.message.header, query_id)?;
                        Ok(r)
                    })();
                    ComparisonResult {
                        server: server.clone(),
                        result,
                    }
                })
            })
            .collect();

        for h in handles {
            results.push(h.join().unwrap());
        }
    });

    results
}
