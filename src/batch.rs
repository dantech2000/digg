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
        if let Some(addr) = part.strip_prefix('@') {
            server = Some(addr.to_string());
        } else if let Some(rt) = RecordType::parse_name(part) {
            qtype = rt;
        } else {
            name = part.to_string();
        }
    }
    BatchQuery {
        name,
        qtype,
        server,
    }
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
                            let r =
                                transport::send_query(server, port, &query, force_tcp, timeout)?;
                            transport::verify_id(&r.message.header, query_id)?;
                            Ok(r)
                        })();
                        (q.name.clone(), q.qtype, result)
                    })
                })
                .collect();

            for (q, h) in chunk.iter().zip(handles) {
                match h.join() {
                    Ok(r) => results.push(r),
                    Err(_) => results.push((
                        q.name.clone(),
                        q.qtype,
                        Err(DnsError::Network("worker thread panicked".into())),
                    )),
                }
            }
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::{parse_batch_line, read_batch_queries};
    use crate::protocol::types::RecordType;

    #[test]
    fn batch_line_full_query_parses_all_fields() {
        let q = parse_batch_line("@8.8.8.8 example.com MX");
        assert_eq!(q.name, "example.com");
        assert_eq!(q.qtype, RecordType::MX);
        assert_eq!(q.server.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn batch_line_tokens_are_order_independent() {
        let a = parse_batch_line("@8.8.8.8 MX example.com");
        let b = parse_batch_line("example.com MX @8.8.8.8");
        let c = parse_batch_line("MX @8.8.8.8 example.com");
        for q in [a, b, c] {
            assert_eq!(q.name, "example.com");
            assert_eq!(q.qtype, RecordType::MX);
            assert_eq!(q.server.as_deref(), Some("8.8.8.8"));
        }
    }

    #[test]
    fn batch_line_missing_fields_use_defaults() {
        let q = parse_batch_line("example.com");
        assert_eq!(q.name, "example.com");
        assert_eq!(q.qtype, RecordType::A);
        assert_eq!(q.server, None);
    }

    #[test]
    fn batch_line_repeated_tokens_last_one_wins() {
        let q = parse_batch_line("a.example b.example A TXT @1.1.1.1 @9.9.9.9");
        assert_eq!(q.name, "b.example");
        assert_eq!(q.qtype, RecordType::TXT);
        assert_eq!(q.server.as_deref(), Some("9.9.9.9"));
    }

    #[test]
    fn batch_file_skips_comments_and_blank_lines() {
        let path = std::env::temp_dir().join(format!("digg_batch_test_{}.txt", std::process::id()));
        std::fs::write(
            &path,
            "# header comment\n\nexample.com A\n  \n# tail\nexample.org\n",
        )
        .unwrap();
        let queries = read_batch_queries(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].name, "example.com");
        assert_eq!(queries[1].name, "example.org");
    }

    #[test]
    fn batch_file_missing_is_a_usage_error() {
        assert!(read_batch_queries("/nonexistent/digg-batch.txt").is_err());
    }

    #[test]
    fn batch_line_accepts_type_n_syntax() {
        let q = parse_batch_line("example.com TYPE64512");
        assert_eq!(q.qtype, RecordType::Unknown(64512));
        assert_eq!(q.name, "example.com");
    }
}
