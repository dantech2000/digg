use crate::error::DnsError;
use crate::protocol::message::DnsMessage;
use crate::transport::{QueryResult, TransportProtocol};
use std::io::Read;
use std::time::{Duration, Instant};

/// A known public DoH provider. Adding one entry to PROVIDERS is the whole
/// change: name matching, URL resolution, and the --help/README provider
/// lists all derive from it.
pub struct DohProvider {
    /// Primary name, plus any aliases, all matched case-insensitively.
    pub names: &'static [&'static str],
    pub url: &'static str,
}

pub const PROVIDERS: &[DohProvider] = &[
    DohProvider {
        names: &["cloudflare", ""],
        url: "https://1.1.1.1/dns-query",
    },
    DohProvider {
        names: &["google"],
        url: "https://dns.google/dns-query",
    },
    DohProvider {
        // Quad9's :443 endpoint requires HTTP/2 (it returns 505 to HTTP/1.1
        // requests); ureq 2.x only speaks HTTP/1.1, so use the :5053 endpoint,
        // which accepts HTTP/1.1. Revisit if the HTTP client gains HTTP/2.
        names: &["quad9"],
        url: "https://dns.quad9.net:5053/dns-query",
    },
    DohProvider {
        names: &["opendns", "cisco"],
        url: "https://doh.opendns.com/dns-query",
    },
    DohProvider {
        names: &["adguard"],
        url: "https://dns.adguard-dns.com/dns-query",
    },
    // Mullvad (dns.mullvad.net) is deliberately absent: its endpoint is
    // HTTP/2-only, which ureq 2.x cannot speak — same constraint as
    // Quad9's :443 endpoint above.
    DohProvider {
        names: &["wikimedia"],
        url: "https://wikimedia-dns.org/dns-query",
    },
];

/// The primary name of every known provider, for help text.
pub fn provider_names() -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .filter_map(|p| p.names.iter().find(|n| !n.is_empty()).copied())
        .collect()
}

pub fn resolve_doh_url(provider_or_url: &str) -> String {
    let lower = provider_or_url.to_lowercase();
    if let Some(provider) = PROVIDERS.iter().find(|p| p.names.contains(&lower.as_str())) {
        return provider.url.to_string();
    }
    if lower.starts_with("https://") {
        return provider_or_url.to_string();
    }
    format!("https://{}/dns-query", provider_or_url)
}

pub fn send_doh_query(url: &str, query: &[u8], timeout: Duration) -> Result<QueryResult, DnsError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_providers_resolve_case_insensitively() {
        assert_eq!(resolve_doh_url(""), "https://1.1.1.1/dns-query");
        assert_eq!(resolve_doh_url("Cloudflare"), "https://1.1.1.1/dns-query");
        assert_eq!(resolve_doh_url("GOOGLE"), "https://dns.google/dns-query");
        assert_eq!(
            resolve_doh_url("quad9"),
            "https://dns.quad9.net:5053/dns-query"
        );
        assert_eq!(
            resolve_doh_url("opendns"),
            "https://doh.opendns.com/dns-query"
        );
        assert_eq!(
            resolve_doh_url("cisco"),
            "https://doh.opendns.com/dns-query"
        );
    }

    #[test]
    fn unknown_input_falls_back_to_url_or_host() {
        assert_eq!(
            resolve_doh_url("https://example.net/custom"),
            "https://example.net/custom"
        );
        assert_eq!(
            resolve_doh_url("doh.example.net"),
            "https://doh.example.net/dns-query"
        );
    }

    #[test]
    fn every_provider_has_a_primary_name_and_https_url() {
        for p in PROVIDERS {
            assert!(p.url.starts_with("https://"), "{}", p.url);
            assert!(p.names.iter().any(|n| !n.is_empty()));
        }
        assert_eq!(provider_names().len(), PROVIDERS.len());
    }
}
