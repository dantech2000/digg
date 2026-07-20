use crate::error::DnsError;
use crate::protocol::message::DnsMessage;
use crate::transport::{QueryResult, TransportProtocol};
use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn create_tls_config() -> Arc<rustls::ClientConfig> {
    // Ensure the default crypto provider is installed
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

fn resolve_dot_hostname(server: &str) -> &str {
    match server {
        "1.1.1.1" | "1.0.0.1" => "cloudflare-dns.com",
        "8.8.8.8" | "8.8.4.4" => "dns.google",
        "9.9.9.9" | "149.112.112.112" => "dns.quad9.net",
        _ => server,
    }
}

pub fn send_dot_query(
    server: &str,
    query: &[u8],
    timeout: Duration,
) -> Result<QueryResult, DnsError> {
    let addr = format!("{}:853", server);
    let socket_addr = crate::transport::resolve_socket_addr(&addr)?;

    let tcp_stream = TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| DnsError::Network(format!("DoT TCP connect failed: {}", e)))?;
    tcp_stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError::Network(format!("failed to set DoT timeout: {}", e)))?;

    let config = create_tls_config();
    let hostname = resolve_dot_hostname(server);
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| DnsError::Network(format!("invalid DoT server name '{}': {}", hostname, e)))?;

    let conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| DnsError::Network(format!("DoT TLS setup failed: {}", e)))?;

    let mut tls_stream = rustls::StreamOwned::new(conn, tcp_stream);

    let start = Instant::now();

    write_framed_query(&mut tls_stream, query)?;
    let resp_buf = read_framed_response(&mut tls_stream)?;

    let elapsed = start.elapsed();
    let bytes = resp_buf.len();
    let message = DnsMessage::parse(&resp_buf)?;

    Ok(QueryResult {
        message,
        elapsed,
        bytes,
        protocol: TransportProtocol::DoT,
    })
}

/// Write a query with the DNS-over-TCP 2-byte length prefix (RFC 7858 uses
/// the same framing as DNS-over-TCP). Generic over the stream so the framing
/// is testable without a TLS connection.
fn write_framed_query<W: Write>(stream: &mut W, query: &[u8]) -> Result<(), DnsError> {
    let len = (query.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .and_then(|_| stream.write_all(query))
        .map_err(|e| DnsError::Network(format!("DoT send failed: {}", e)))
}

/// Read a length-prefixed response. A short or truncated stream is a network
/// error, never a panic.
fn read_framed_response<R: Read>(stream: &mut R) -> Result<Vec<u8>, DnsError> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| DnsError::Network(format!("DoT read failed: {}", e)))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| DnsError::Network(format!("DoT read failed: {}", e)))?;
    Ok(resp_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn dot_hostname_maps_known_resolver_ips_to_sni() {
        assert_eq!(resolve_dot_hostname("1.1.1.1"), "cloudflare-dns.com");
        assert_eq!(resolve_dot_hostname("8.8.4.4"), "dns.google");
        assert_eq!(resolve_dot_hostname("9.9.9.9"), "dns.quad9.net");
        // Unknown servers pass through unchanged (used verbatim as the SNI).
        assert_eq!(resolve_dot_hostname("dns.example.net"), "dns.example.net");
    }

    #[test]
    fn framing_round_trips_through_an_in_memory_stream() {
        let query = b"\x12\x34hello-dns-payload";
        let mut wire = Vec::new();
        write_framed_query(&mut wire, query).unwrap();
        // 2-byte big-endian length prefix, then the payload.
        assert_eq!(&wire[..2], &(query.len() as u16).to_be_bytes());
        assert_eq!(&wire[2..], query);

        let mut reader = Cursor::new(wire);
        // The reader frames the *response*; feed our framed bytes back as if
        // they were a response and confirm we recover the payload exactly.
        let got = read_framed_response(&mut reader).unwrap();
        assert_eq!(got, query);
    }

    #[test]
    fn read_framed_response_errors_on_truncated_prefix() {
        let mut reader = Cursor::new(vec![0x00]); // only 1 of 2 length bytes
        assert!(read_framed_response(&mut reader).is_err());
    }

    #[test]
    fn read_framed_response_errors_when_body_shorter_than_prefix() {
        // Prefix claims 10 bytes, only 3 follow.
        let mut reader = Cursor::new(vec![0x00, 0x0A, 1, 2, 3]);
        assert!(read_framed_response(&mut reader).is_err());
    }

    #[test]
    fn read_framed_response_handles_zero_length_body() {
        let mut reader = Cursor::new(vec![0x00, 0x00]);
        assert_eq!(read_framed_response(&mut reader).unwrap(), Vec::<u8>::new());
    }
}
