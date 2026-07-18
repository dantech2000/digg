use crate::error::DnsError;
use crate::protocol::header::Header;
use crate::protocol::message::DnsMessage;
use serde::Serialize;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// Resolve a "host:port" string to a socket address, accepting either an IP
/// literal or a hostname (unlike `SocketAddr::parse`, which only takes IPs).
pub fn resolve_socket_addr(addr: &str) -> Result<SocketAddr, DnsError> {
    addr.to_socket_addrs()
        .map_err(|e| DnsError::Network(format!("failed to resolve '{}': {}", addr, e)))?
        .next()
        .ok_or_else(|| DnsError::Network(format!("no addresses found for '{}'", addr)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TransportProtocol {
    Udp,
    Tcp,
    DoT,
    DoH,
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportProtocol::Udp => write!(f, "UDP"),
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::DoT => write!(f, "DoT"),
            TransportProtocol::DoH => write!(f, "DoH"),
        }
    }
}

pub struct QueryResult {
    pub message: DnsMessage,
    pub elapsed: Duration,
    pub bytes: usize,
    pub protocol: TransportProtocol,
}

fn format_addr(server: &str, port: u16) -> String {
    if server.contains(':') {
        // IPv6 address needs brackets
        format!("[{}]:{}", server, port)
    } else {
        format!("{}:{}", server, port)
    }
}

pub fn send_query(
    server: &str,
    port: u16,
    query: &[u8],
    force_tcp: bool,
    timeout: Duration,
) -> Result<QueryResult, DnsError> {
    let addr = format_addr(server, port);
    let start = Instant::now();

    if force_tcp {
        return send_tcp(&addr, query, start, timeout);
    }

    let result = send_udp(&addr, query, start, timeout)?;

    if result.message.header.tc {
        let start = Instant::now();
        return send_tcp(&addr, query, start, timeout);
    }

    Ok(result)
}

// A UDP DNS datagram can be as large as the IP payload allows; size the receive
// buffer to hold any of them so a large response is never silently truncated.
const UDP_RECV_BUF: usize = 65535;

fn send_udp(
    addr: &str,
    query: &[u8],
    start: Instant,
    timeout: Duration,
) -> Result<QueryResult, DnsError> {
    let socket_addr = resolve_socket_addr(addr)?;
    let bind_addr = if socket_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|e| DnsError::Network(format!("failed to bind UDP socket: {}", e)))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError::Network(format!("failed to set timeout: {}", e)))?;
    // Connect so the kernel only delivers datagrams from the queried server,
    // dropping stray/spoofed packets from other sources.
    socket.connect(socket_addr).map_err(|e| {
        DnsError::Network(format!("failed to connect UDP socket to {}: {}", addr, e))
    })?;

    socket
        .send(query)
        .map_err(|e| DnsError::Network(format!("failed to send UDP query to {}: {}", addr, e)))?;

    let mut resp_buf = vec![0u8; UDP_RECV_BUF];
    let size = socket
        .recv(&mut resp_buf)
        .map_err(|e| DnsError::Network(format!("failed to receive UDP response: {}", e)))?;

    let elapsed = start.elapsed();
    let message = DnsMessage::parse(&resp_buf[..size])?;

    Ok(QueryResult {
        message,
        elapsed,
        bytes: size,
        protocol: TransportProtocol::Udp,
    })
}

fn send_tcp(
    addr: &str,
    query: &[u8],
    start: Instant,
    timeout: Duration,
) -> Result<QueryResult, DnsError> {
    let socket_addr = resolve_socket_addr(addr)?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| DnsError::Network(format!("failed to connect TCP to {}: {}", addr, e)))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError::Network(format!("failed to set TCP timeout: {}", e)))?;

    let len = (query.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| DnsError::Network(format!("failed to send TCP length: {}", e)))?;
    stream
        .write_all(query)
        .map_err(|e| DnsError::Network(format!("failed to send TCP query: {}", e)))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| DnsError::Network(format!("failed to read TCP response length: {}", e)))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| DnsError::Network(format!("failed to read TCP response: {}", e)))?;

    let elapsed = start.elapsed();
    let message = DnsMessage::parse(&resp_buf)?;

    Ok(QueryResult {
        message,
        elapsed,
        bytes: resp_len,
        protocol: TransportProtocol::Tcp,
    })
}

/// Send a TCP query on an already-connected stream and return the raw response bytes.
/// Used by AXFR which needs to read multiple messages from one connection.
pub fn send_tcp_raw(stream: &mut TcpStream, query: &[u8]) -> Result<(), DnsError> {
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(query)?;
    Ok(())
}

/// Read one DNS message from a TCP stream (2-byte length prefix + message).
pub fn read_tcp_message(stream: &mut TcpStream) -> Result<(DnsMessage, usize), DnsError> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    let message = DnsMessage::parse(&resp_buf)?;
    Ok((message, resp_len))
}

pub fn verify_id(response: &Header, expected_id: u16) -> Result<(), DnsError> {
    if response.id != expected_id {
        return Err(DnsError::Protocol(format!(
            "response ID {} does not match query ID {}",
            response.id, expected_id
        )));
    }
    Ok(())
}
