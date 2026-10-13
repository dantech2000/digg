use crate::error::DnsError;
use crate::transport::{QueryResult, TransportProtocol};
use rustls::pki_types::ServerName;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex};
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

    QueryResult::from_wire(&resp_buf, start.elapsed(), TransportProtocol::DoT)
}

/// How long one blocking read on a shared connection may last before the
/// reading thread hands the role on. It bounds how late a waiting query
/// notices its own timeout; it is not the query timeout.
const READ_SLICE: Duration = Duration::from_millis(250);

/// One DoT connection for every query of a run.
///
/// A TLS handshake costs several round trips, and +validate follows the
/// answer with a batch of lookups. Opening a connection per lookup made that
/// batch pay for a handshake each. RFC 7766 §6.2.1.1 lets a client send many
/// queries on one connection and take the responses in any order, matching
/// them by ID, which is what this does.
///
/// Anything unexpected (the connection drops, two queries share an ID) falls
/// back to a connection of its own for that query, so sharing is only ever a
/// shortcut.
pub struct DotSession {
    server: String,
    timeout: Duration,
    link: Mutex<Option<Arc<Link<TlsChannel>>>>,
}

impl DotSession {
    /// Nothing is connected until the first query.
    pub fn new(server: &str, timeout: Duration) -> Self {
        DotSession {
            server: server.to_string(),
            timeout,
            link: Mutex::new(None),
        }
    }

    pub fn send(&self, query: &[u8]) -> Result<QueryResult, DnsError> {
        let start = Instant::now();
        let link = {
            let mut slot = self.link.lock().expect("DoT session poisoned");
            match slot.as_ref() {
                Some(link) => Arc::clone(link),
                None => {
                    let link =
                        Arc::new(Link::new(TlsChannel::connect(&self.server, self.timeout)?));
                    *slot = Some(Arc::clone(&link));
                    link
                }
            }
        };
        match link.exchange(query, self.timeout) {
            Exchange::Response(wire) => {
                QueryResult::from_wire(&wire, start.elapsed(), TransportProtocol::DoT)
            }
            Exchange::TimedOut => Err(DnsError::Network(format!(
                "no DoT response from {} within {:?}",
                self.server, self.timeout
            ))),
            // The shared connection cannot serve this query; give it its own.
            Exchange::Unavailable => send_dot_query(&self.server, query, self.timeout),
        }
    }
}

/// The two things a shared connection does: accept a framed query, and hand
/// back whatever complete response frames have arrived. Split out so the
/// matching of responses to queries can be tested without TLS.
trait Channel {
    fn write(&self, query: &[u8]) -> Result<(), String>;
    /// Block for at most READ_SLICE. An empty list means nothing complete
    /// arrived yet; an error means the connection is finished.
    fn read_frames(&self) -> Result<Vec<Vec<u8>>, String>;
}

enum Exchange {
    Response(Vec<u8>),
    TimedOut,
    Unavailable,
}

#[derive(Default)]
struct Inbox {
    /// IDs of queries sent and not yet answered.
    waiting: HashSet<u16>,
    /// Responses that arrived for a query another thread is waiting on.
    ready: HashMap<u16, Vec<u8>>,
    /// Set once the connection fails; nothing more will arrive.
    failed: bool,
}

struct Link<C: Channel> {
    channel: C,
    inbox: Mutex<Inbox>,
    /// Held by the one thread currently reading from the connection.
    reading: Mutex<()>,
    arrived: Condvar,
}

impl<C: Channel> Link<C> {
    fn new(channel: C) -> Self {
        Link {
            channel,
            inbox: Mutex::new(Inbox::default()),
            reading: Mutex::new(()),
            arrived: Condvar::new(),
        }
    }

    /// Send one query and wait for the response with its ID.
    fn exchange(&self, query: &[u8], timeout: Duration) -> Exchange {
        let Some(id) = query.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
            return Exchange::Unavailable;
        };
        {
            let mut inbox = self.inbox.lock().expect("DoT inbox poisoned");
            // A second query with an ID already in flight could not be told
            // apart from the first.
            if inbox.failed || !inbox.waiting.insert(id) {
                return Exchange::Unavailable;
            }
        }
        if self.channel.write(query).is_err() {
            self.fail(id);
            return Exchange::Unavailable;
        }

        let deadline = Instant::now() + timeout;
        loop {
            let mut inbox = self.inbox.lock().expect("DoT inbox poisoned");
            if let Some(wire) = inbox.ready.remove(&id) {
                inbox.waiting.remove(&id);
                return Exchange::Response(wire);
            }
            if inbox.failed {
                inbox.waiting.remove(&id);
                return Exchange::Unavailable;
            }
            if Instant::now() >= deadline {
                inbox.waiting.remove(&id);
                return Exchange::TimedOut;
            }
            // One thread reads for everyone; the rest wait to be told.
            match self.reading.try_lock() {
                Ok(_reading) => {
                    drop(inbox);
                    let frames = self.channel.read_frames();
                    let mut inbox = self.inbox.lock().expect("DoT inbox poisoned");
                    match frames {
                        Ok(frames) => {
                            for frame in frames {
                                let Some(frame_id) =
                                    frame.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
                                else {
                                    continue;
                                };
                                if inbox.waiting.contains(&frame_id) {
                                    inbox.ready.insert(frame_id, frame);
                                }
                            }
                        }
                        Err(_) => inbox.failed = true,
                    }
                    drop(inbox);
                    self.arrived.notify_all();
                }
                Err(_) => {
                    let _ = self
                        .arrived
                        .wait_timeout(inbox, Duration::from_millis(20))
                        .expect("DoT inbox poisoned");
                }
            }
        }
    }

    fn fail(&self, id: u16) {
        let mut inbox = self.inbox.lock().expect("DoT inbox poisoned");
        inbox.failed = true;
        inbox.waiting.remove(&id);
        drop(inbox);
        self.arrived.notify_all();
    }
}

/// Cut complete length-prefixed frames off the front of `plain`, leaving any
/// partial frame for the next read.
fn take_frames(plain: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while let Some(len) = plain
        .get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    {
        let Some(frame) = plain.get(pos + 2..pos + 2 + len) else {
            break;
        };
        frames.push(frame.to_vec());
        pos += 2 + len;
    }
    plain.drain(..pos);
    frames
}

/// The TLS connection behind a DotSession. Writing and reading are separate
/// locks: a thread blocked on the socket for a response must not keep
/// another from sending its query.
struct TlsChannel {
    /// TLS state and the socket handle used for writing.
    tls: Mutex<(rustls::ClientConnection, TcpStream)>,
    /// A second handle on the same socket, and decrypted bytes not yet framed.
    incoming: Mutex<(TcpStream, Vec<u8>)>,
}

impl TlsChannel {
    fn connect(server: &str, timeout: Duration) -> Result<Self, DnsError> {
        let addr = format!("{}:853", server);
        let socket_addr = crate::transport::resolve_socket_addr(&addr)?;
        let mut sock = TcpStream::connect_timeout(&socket_addr, timeout)
            .map_err(|e| DnsError::Network(format!("DoT TCP connect failed: {}", e)))?;
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| DnsError::Network(format!("failed to set DoT timeout: {}", e)))?;
        // Every write here is a complete message that should leave at once.
        // Left to itself the kernel holds a small write back while an earlier
        // one is unacknowledged; with this set, a single DoT query to 1.1.1.1
        // went from about 96 ms to about 51 ms.
        let _ = sock.set_nodelay(true);

        let hostname = resolve_dot_hostname(server);
        let server_name = ServerName::try_from(hostname.to_string()).map_err(|e| {
            DnsError::Network(format!("invalid DoT server name '{}': {}", hostname, e))
        })?;
        let mut conn = rustls::ClientConnection::new(create_tls_config(), server_name)
            .map_err(|e| DnsError::Network(format!("DoT TLS setup failed: {}", e)))?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock)
                .map_err(|e| DnsError::Network(format!("DoT TLS handshake failed: {}", e)))?;
        }

        let reader = sock
            .try_clone()
            .map_err(|e| DnsError::Network(format!("DoT socket setup failed: {}", e)))?;
        // Both handles are one socket, so this sets the timeout for the reads
        // that follow; the write handle is never read from.
        reader
            .set_read_timeout(Some(READ_SLICE))
            .map_err(|e| DnsError::Network(format!("failed to set DoT timeout: {}", e)))?;
        Ok(TlsChannel {
            tls: Mutex::new((conn, sock)),
            incoming: Mutex::new((reader, Vec::new())),
        })
    }
}

impl Channel for TlsChannel {
    fn write(&self, query: &[u8]) -> Result<(), String> {
        let mut framed = Vec::with_capacity(query.len() + 2);
        write_framed_query(&mut framed, query).map_err(|e| e.to_string())?;
        let mut tls = self.tls.lock().map_err(|_| "DoT connection poisoned")?;
        let (conn, sock) = &mut *tls;
        conn.writer()
            .write_all(&framed)
            .map_err(|e| e.to_string())?;
        while conn.wants_write() {
            conn.write_tls(sock).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn read_frames(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut incoming = self
            .incoming
            .lock()
            .map_err(|_| "DoT connection poisoned")?;
        let (reader, plain) = &mut *incoming;

        // Wait on the socket without holding the TLS state.
        let mut encrypted = [0u8; 16 * 1024];
        let n = match reader.read(&mut encrypted) {
            Ok(0) => return Err("connection closed".to_string()),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e.to_string()),
        };

        let mut tls = self.tls.lock().map_err(|_| "DoT connection poisoned")?;
        let (conn, sock) = &mut *tls;
        let mut rest = &encrypted[..n];
        while !rest.is_empty() {
            let taken = conn.read_tls(&mut rest).map_err(|e| e.to_string())?;
            conn.process_new_packets().map_err(|e| e.to_string())?;
            if taken == 0 {
                return Err("TLS input stalled".to_string());
            }
        }
        let mut chunk = [0u8; 4096];
        loop {
            match conn.reader().read(&mut chunk) {
                Ok(0) => break,
                Ok(k) => plain.extend_from_slice(&chunk[..k]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        // Whatever TLS itself has to say back (key updates and the like).
        while conn.wants_write() {
            conn.write_tls(sock).map_err(|e| e.to_string())?;
        }
        Ok(take_frames(plain))
    }
}

/// Write a query with the DNS-over-TCP 2-byte length prefix (RFC 7858 uses
/// the same framing as DNS-over-TCP). Generic over the stream so the framing
/// is testable without a TLS connection.
fn write_framed_query<W: Write>(stream: &mut W, query: &[u8]) -> Result<(), DnsError> {
    let len = u16::try_from(query.len())
        .map_err(|_| DnsError::Network("query too large for DoT framing (>65535 bytes)".into()))?;
    // One write, so the prefix and the query leave in one TLS record and one
    // segment; see transport::frame_query.
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream
        .write_all(&framed)
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

    /// A stand-in connection: it holds queries until `batch` of them have been
    /// written, then answers them all at once, newest first, each response
    /// being the query with a marker byte appended.
    struct FakeChannel {
        batch: usize,
        sent: Mutex<Vec<Vec<u8>>>,
        fail_reads: bool,
    }

    impl FakeChannel {
        fn new(batch: usize) -> Self {
            FakeChannel {
                batch,
                sent: Mutex::new(Vec::new()),
                fail_reads: false,
            }
        }
    }

    impl Channel for FakeChannel {
        fn write(&self, query: &[u8]) -> Result<(), String> {
            self.sent.lock().unwrap().push(query.to_vec());
            Ok(())
        }

        fn read_frames(&self) -> Result<Vec<Vec<u8>>, String> {
            if self.fail_reads {
                return Err("connection closed".to_string());
            }
            std::thread::sleep(Duration::from_millis(2));
            let mut sent = self.sent.lock().unwrap();
            if sent.len() < self.batch {
                return Ok(Vec::new());
            }
            Ok(sent
                .drain(..)
                .rev()
                .map(|mut query| {
                    query.push(0xEE);
                    query
                })
                .collect())
        }
    }

    fn query_with_id(id: u16) -> Vec<u8> {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(b"question");
        query
    }

    #[test]
    fn responses_are_matched_to_queries_by_id_whatever_order_they_arrive_in() {
        // Four threads share one connection. Nothing is answered until all
        // four queries are on the wire, and the answers come back reversed.
        let link = Link::new(FakeChannel::new(4));
        std::thread::scope(|scope| {
            for id in [0x1111u16, 0x2222, 0x3333, 0x4444] {
                let link = &link;
                scope.spawn(move || {
                    let query = query_with_id(id);
                    match link.exchange(&query, Duration::from_secs(5)) {
                        Exchange::Response(wire) => {
                            assert_eq!(&wire[..2], &id.to_be_bytes());
                            assert_eq!(&wire[..query.len()], &query[..]);
                            assert_eq!(wire.last(), Some(&0xEE));
                        }
                        _ => panic!("query {:#06x} got no response", id),
                    }
                });
            }
        });
        let inbox = link.inbox.lock().unwrap();
        assert!(inbox.waiting.is_empty() && inbox.ready.is_empty());
    }

    #[test]
    fn shared_connection_steps_aside_when_it_cannot_serve_a_query() {
        // A response that never comes: the query times out.
        let link = Link::new(FakeChannel::new(usize::MAX));
        assert!(matches!(
            link.exchange(&query_with_id(1), Duration::from_millis(30)),
            Exchange::TimedOut
        ));

        // The connection fails: the caller is told to use its own.
        let mut channel = FakeChannel::new(1);
        channel.fail_reads = true;
        let link = Link::new(channel);
        assert!(matches!(
            link.exchange(&query_with_id(2), Duration::from_secs(1)),
            Exchange::Unavailable
        ));
        // And every query after it.
        assert!(matches!(
            link.exchange(&query_with_id(3), Duration::from_secs(1)),
            Exchange::Unavailable
        ));

        // An ID already in flight cannot be told apart from the first.
        let link = Link::new(FakeChannel::new(usize::MAX));
        link.inbox.lock().unwrap().waiting.insert(7);
        assert!(matches!(
            link.exchange(&query_with_id(7), Duration::from_secs(1)),
            Exchange::Unavailable
        ));
        // Too short to carry an ID.
        assert!(matches!(
            link.exchange(&[0x01], Duration::from_secs(1)),
            Exchange::Unavailable
        ));
    }

    #[test]
    fn take_frames_leaves_a_partial_frame_for_the_next_read() {
        // Two whole frames, then the first three bytes of a 4-byte frame.
        let mut plain = vec![0, 2, b'a', b'b', 0, 1, b'c', 0, 4, b'd'];
        assert_eq!(take_frames(&mut plain), vec![b"ab".to_vec(), b"c".to_vec()]);
        assert_eq!(plain, vec![0, 4, b'd']);
        // The rest arrives.
        plain.extend_from_slice(b"efg");
        assert_eq!(take_frames(&mut plain), vec![b"defg".to_vec()]);
        assert!(plain.is_empty());
        // A lone length byte is not a frame yet.
        let mut plain = vec![0];
        assert!(take_frames(&mut plain).is_empty());
        assert_eq!(plain, vec![0]);
    }
}
