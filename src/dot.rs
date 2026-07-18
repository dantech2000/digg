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

    // Same wire format as DNS-over-TCP: 2-byte length prefix
    let len = (query.len() as u16).to_be_bytes();
    tls_stream
        .write_all(&len)
        .map_err(|e| DnsError::Network(format!("DoT send failed: {}", e)))?;
    tls_stream
        .write_all(query)
        .map_err(|e| DnsError::Network(format!("DoT send failed: {}", e)))?;

    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    tls_stream
        .read_exact(&mut len_buf)
        .map_err(|e| DnsError::Network(format!("DoT read failed: {}", e)))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    // Read response
    let mut resp_buf = vec![0u8; resp_len];
    tls_stream
        .read_exact(&mut resp_buf)
        .map_err(|e| DnsError::Network(format!("DoT read failed: {}", e)))?;

    let elapsed = start.elapsed();
    let message = DnsMessage::parse(&resp_buf)?;

    Ok(QueryResult {
        message,
        elapsed,
        bytes: resp_len,
        protocol: TransportProtocol::DoT,
    })
}
