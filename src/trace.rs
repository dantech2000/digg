use crate::error::DnsError;
use crate::protocol::edns::EdnsOptions;
use crate::protocol::message::DnsMessage;
use crate::protocol::record::RData;
use crate::protocol::types::RecordType;
use crate::transport::{self, QueryResult};
use crate::resolver;
use std::time::Duration;

const ROOT_SERVERS: [&str; 13] = [
    "198.41.0.4",     // a.root-servers.net
    "170.247.170.2",  // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

pub struct TraceHop {
    pub server: String,
    pub result: QueryResult,
}

pub fn perform_trace(
    name: &str,
    qtype: RecordType,
    timeout: Duration,
) -> Result<Vec<TraceHop>, DnsError> {
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut current_servers: Vec<String> = ROOT_SERVERS.iter().map(|s| s.to_string()).collect();

    let edns = EdnsOptions::default();
    let max_depth = 20;

    for _ in 0..max_depth {
        // Try servers in order until one responds
        let mut winning_response: Option<QueryResult> = None;
        let mut used_server = String::new();

        for server in &current_servers {
            let query_result = (|| -> Result<QueryResult, DnsError> {
                let (query, query_id) =
                    DnsMessage::build_query(name, qtype, false, Some(&edns))?;
                let r = transport::send_query(server, 53, &query, false, timeout, 4096)?;
                transport::verify_id(&r.message.header, query_id)?;
                Ok(r)
            })();

            match query_result {
                Ok(r) => {
                    used_server = server.clone();
                    winning_response = Some(r);
                    break;
                }
                Err(_) => continue,
            }
        }

        let hop_result = match winning_response {
            Some(r) => r,
            None => {
                return Err(DnsError::Network(
                    "trace: no server responded".into(),
                ));
            }
        };

        // If we got an answer (non-referral), we're done
        let has_answers = !hop_result.message.answers.is_empty();
        let has_soa_authority = hop_result.message.authority.iter().any(|rr| rr.rtype == RecordType::SOA);

        hops.push(TraceHop {
            server: used_server,
            result: hop_result,
        });

        if has_answers || has_soa_authority {
            break;
        }

        // Extract NS names from authority section (referral)
        let last = hops.last().unwrap();
        let ns_names: Vec<String> = last
            .result
            .message
            .authority
            .iter()
            .filter(|rr| rr.rtype == RecordType::NS)
            .filter_map(|rr| match &rr.rdata {
                RData::NS(name) => Some(name.clone()),
                _ => None,
            })
            .collect();

        if ns_names.is_empty() {
            break;
        }

        // Look for glue records in additional section
        let mut next_servers: Vec<String> = Vec::new();
        for ns_name in &ns_names {
            for rr in &last.result.message.additional {
                if rr.name == *ns_name {
                    match &rr.rdata {
                        RData::A(addr) => next_servers.push(addr.to_string()),
                        _ => {}
                    }
                }
            }
        }

        // If no glue records, resolve the first NS name via system resolver
        if next_servers.is_empty() {
            let ns_name = ns_names[0].trim_end_matches('.');
            match resolve_ns_address(ns_name, timeout) {
                Ok(addrs) => next_servers = addrs,
                Err(_) => break,
            }
        }

        if next_servers.is_empty() {
            break;
        }

        current_servers = next_servers;
    }

    Ok(hops)
}

fn resolve_ns_address(ns_name: &str, timeout: Duration) -> Result<Vec<String>, DnsError> {
    let system_ns = resolver::system_nameserver()?;
    let (query, _id) = DnsMessage::build_query(ns_name, RecordType::A, true, None)?;
    let result = transport::send_query(&system_ns, 53, &query, false, timeout, 4096)?;

    let mut addrs = Vec::new();
    for rr in &result.message.answers {
        if let RData::A(addr) = &rr.rdata {
            addrs.push(addr.to_string());
        }
    }
    Ok(addrs)
}
