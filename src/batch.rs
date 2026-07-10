use crate::error::DnsError;
use crate::protocol::edns::EdnsOptions;
use crate::protocol::message::DnsMessage;
use crate::protocol::types::RecordType;
use crate::transport::{self, QueryResult};
use std::io::{self, BufRead};
use std::time::Duration;

pub struct BatchQuery {
    pub name: String,
    pub qtype: RecordType,
    pub server: Option<String>,
}

pub fn read_batch_queries(source: &str) -> Result<Vec<BatchQuery>, DnsError> {
    let reader: Box<dyn BufRead> = if source == "-" {
        Box::new(io::stdin().lock())
    } else {
        let file = std::fs::File::open(source)
            .map_err(|e| DnsError::Usage(format!("cannot open '{}': {}", source, e)))?;
        Box::new(io::BufReader::new(file))
    };

    let mut queries = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| DnsError::Usage(format!("read error: {}", e)))?;
        let line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        queries.push(parse_batch_line(&line));
    }
    Ok(queries)
}

fn parse_batch_line(line: &str) -> BatchQuery {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let mut name = ".".to_string();
    let mut qtype = RecordType::A;
    let mut server = None;

    for part in parts {
        if let Some(s) = part.strip_prefix('@') {
            server = Some(s.to_string());
        } else if let Some(rt) = RecordType::from_str(part) {
            qtype = rt;
        } else {
            name = part.to_string();
        }
    }
    BatchQuery { name, qtype, server }
}

pub fn run_batch(
    queries: &[BatchQuery],
    default_server: &str,
    port: u16,
    timeout: Duration,
    force_tcp: bool,
    dnssec: bool,
) -> Vec<(String, RecordType, Result<QueryResult, DnsError>)> {
    let max_threads = 8;
    let mut results = Vec::with_capacity(queries.len());

    let edns = EdnsOptions {
        dnssec_ok: dnssec,
        ..EdnsOptions::default()
    };

    for chunk in queries.chunks(max_threads) {
        std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|q| {
                    let edns = &edns;
                    s.spawn(move || {
                        let server = q.server.as_deref().unwrap_or(default_server);
                        let result = (|| -> Result<QueryResult, DnsError> {
                            let (query, query_id) =
                                DnsMessage::build_query(&q.name, q.qtype, true, Some(edns))?;
                            let r = transport::send_query(
                                server, port, &query, force_tcp, timeout, 4096,
                            )?;
                            transport::verify_id(&r.message.header, query_id)?;
                            Ok(r)
                        })();
                        (q.name.clone(), q.qtype, result)
                    })
                })
                .collect();

            for h in handles {
                results.push(h.join().unwrap());
            }
        });
    }
    results
}
