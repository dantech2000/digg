use crate::error::DnsError;
use crate::protocol::message::DnsMessage;
use crate::transport::{QueryResult, TransportProtocol};
use std::io::Read;
use std::time::{Duration, Instant};

pub fn resolve_doh_url(provider_or_url: &str) -> String {
    match provider_or_url.to_lowercase().as_str() {
        "" | "cloudflare" => "https://1.1.1.1/dns-query".to_string(),
        "google" => "https://dns.google/dns-query".to_string(),
        "quad9" => "https://dns.quad9.net:5053/dns-query".to_string(),
        url if url.starts_with("https://") => url.to_string(),
        other => format!("https://{}/dns-query", other),
    }
}

pub fn send_doh_query(
    url: &str,
    query: &[u8],
    timeout: Duration,
) -> Result<QueryResult, DnsError> {
    let start = Instant::now();

    let response = ureq::post(url)
        .set("Content-Type", "application/dns-message")
        .set("Accept", "application/dns-message")
        .timeout(timeout)
        .send_bytes(query)
        .map_err(|e| DnsError::Network(format!("DoH request to {} failed: {}", url, e)))?;

    let mut resp_buf = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut resp_buf)
        .map_err(|e| DnsError::Network(format!("failed to read DoH response: {}", e)))?;

    let elapsed = start.elapsed();
    let bytes = resp_buf.len();
    let message = DnsMessage::parse(&resp_buf)?;

    Ok(QueryResult {
        message,
        elapsed,
        bytes,
        protocol: TransportProtocol::DoH,
    })
}
