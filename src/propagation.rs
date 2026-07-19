use crate::error::DnsError;
use crate::protocol::edns::EdnsOptions;
use crate::protocol::message::DnsMessage;
use crate::protocol::types::RecordType;
use crate::transport::{self, QueryResult};
use std::time::Duration;

pub struct PropagationResolver {
    pub name: &'static str,
    pub ip: &'static str,
}

pub const PUBLIC_RESOLVERS: &[PropagationResolver] = &[
    PropagationResolver {
        name: "Google",
        ip: "8.8.8.8",
    },
    PropagationResolver {
        name: "Cloudflare",
        ip: "1.1.1.1",
    },
    PropagationResolver {
        name: "Quad9",
        ip: "9.9.9.9",
    },
    PropagationResolver {
        name: "OpenDNS",
        ip: "208.67.222.222",
    },
    PropagationResolver {
        name: "Level3",
        ip: "4.2.2.1",
    },
    PropagationResolver {
        name: "CleanBrowsing",
        ip: "185.228.168.9",
    },
    PropagationResolver {
        name: "AdGuard",
        ip: "94.140.14.14",
    },
    PropagationResolver {
        name: "Comodo",
        ip: "8.26.56.26",
    },
    PropagationResolver {
        name: "Verisign",
        ip: "64.6.64.6",
    },
    PropagationResolver {
        name: "Yandex",
        ip: "77.88.8.8",
    },
];

pub struct PropagationResult {
    pub resolver_name: &'static str,
    pub resolver_ip: &'static str,
    pub result: Result<QueryResult, DnsError>,
}

pub fn check_propagation(
    name: &str,
    qtype: RecordType,
    timeout: Duration,
    edns: EdnsOptions,
) -> Vec<PropagationResult> {
    let mut results = Vec::with_capacity(PUBLIC_RESOLVERS.len());

    std::thread::scope(|s| {
        let handles: Vec<_> = PUBLIC_RESOLVERS
            .iter()
            .map(|resolver| {
                let edns = &edns;
                s.spawn(move || {
                    let result = (|| -> Result<QueryResult, DnsError> {
                        let (query, query_id) =
                            DnsMessage::build_query(name, qtype, true, Some(edns))?;
                        let r = transport::send_query(resolver.ip, 53, &query, false, timeout)?;
                        transport::verify_id(&r.message.header, query_id)?;
                        Ok(r)
                    })();
                    PropagationResult {
                        resolver_name: resolver.name,
                        resolver_ip: resolver.ip,
                        result,
                    }
                })
            })
            .collect();

        for (resolver, h) in PUBLIC_RESOLVERS.iter().zip(handles) {
            match h.join() {
                Ok(r) => results.push(r),
                Err(_) => results.push(PropagationResult {
                    resolver_name: resolver.name,
                    resolver_ip: resolver.ip,
                    result: Err(DnsError::Network("worker thread panicked".into())),
                }),
            }
        }
    });

    results
}
