//! Hermetic transport integration tests: drive the compiled digg binary
//! against a programmable mock DNS responder on loopback. No external
//! network access, no external crates.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// What the mock returns for a protocol leg.
#[derive(Clone, Copy)]
enum Behavior {
    /// Well-formed answer with the given IPv4 rdata, one A record per address.
    Answer(&'static [[u8; 4]]),
    /// Empty answer with the TC bit set (tells the client to retry over TCP).
    Truncated,
    /// Answer whose transaction ID does not match the query's.
    WrongId,
    /// Never respond.
    Silent,
}

struct MockDns {
    port: u16,
}

impl MockDns {
    /// Bind TCP and UDP on the same loopback port and serve `udp`/`tcp`
    /// behaviors from background threads for the life of the test process.
    fn start(udp: Behavior, tcp: Behavior) -> Self {
        // Grab a TCP port first, then bind UDP to the same number. The two
        // namespaces are separate, so this succeeds unless another process
        // races us on the UDP side — retry a few times if so.
        for _ in 0..10 {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
            let port = listener.local_addr().unwrap().port();
            let Ok(socket) = UdpSocket::bind(("127.0.0.1", port)) else {
                continue;
            };

            let udp_socket = Arc::new(socket);
            let udp_behavior = udp;
            let udp_handle = Arc::clone(&udp_socket);
            thread::spawn(move || loop {
                let mut buf = [0u8; 65535];
                let Ok((len, peer)) = udp_handle.recv_from(&mut buf) else {
                    return;
                };
                if let Some(resp) = build_response(&buf[..len], udp_behavior) {
                    let _ = udp_handle.send_to(&resp, peer);
                }
            });

            let tcp_behavior = tcp;
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).is_err() {
                        continue;
                    }
                    let qlen = u16::from_be_bytes(len_buf) as usize;
                    let mut query = vec![0u8; qlen];
                    if stream.read_exact(&mut query).is_err() {
                        continue;
                    }
                    if let Some(resp) = build_response(&query, tcp_behavior) {
                        let _ = stream.write_all(&(resp.len() as u16).to_be_bytes());
                        let _ = stream.write_all(&resp);
                    }
                }
            });

            return MockDns { port };
        }
        panic!("could not bind matching TCP/UDP ports after 10 attempts");
    }
}

/// Build a DNS response for a raw query according to the behavior.
fn build_response(query: &[u8], behavior: Behavior) -> Option<Vec<u8>> {
    if let Behavior::Silent = behavior {
        return None;
    }

    // Echo the question section: labels until the zero byte, then QTYPE+QCLASS.
    let mut qend = 12;
    while query[qend] != 0 {
        qend += query[qend] as usize + 1;
    }
    qend += 5;
    let question = &query[12..qend];

    let mut id = [query[0], query[1]];
    if let Behavior::WrongId = behavior {
        id[1] = id[1].wrapping_add(1);
    }

    let (flags1, answers): (u8, &[[u8; 4]]) = match behavior {
        Behavior::Answer(addrs) => (0x81, addrs), // qr | rd
        Behavior::WrongId => (0x81, &[[9, 9, 9, 9]]),
        Behavior::Truncated => (0x83, &[]), // qr | tc | rd
        Behavior::Silent => unreachable!(),
    };

    let mut resp = Vec::new();
    resp.extend_from_slice(&id);
    resp.push(flags1);
    resp.push(0x80); // ra
    resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    resp.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
    resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
    resp.extend_from_slice(&0u16.to_be_bytes()); // arcount
    resp.extend_from_slice(question);

    for addr in answers {
        resp.extend_from_slice(&[0xC0, 0x0C]); // compression pointer to qname
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(addr);
    }
    Some(resp)
}

fn run_digg(port: u16, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "@127.0.0.1".to_string(),
        "-p".to_string(),
        port.to_string(),
        "example.com".to_string(),
        "+nocolor".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Command::new(env!("CARGO_BIN_EXE_digg"))
        .args(&args)
        // Isolate from any developer ~/.diggrc.
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("run digg")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn udp_answer_round_trips() {
    static ADDRS: [[u8; 4]; 1] = [[1, 2, 3, 4]];
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = run_digg(server.port, &["+short"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "1.2.3.4\n");
}

#[test]
fn standard_output_reports_udp_transport_and_rcode() {
    static ADDRS: [[u8; 4]; 1] = [[1, 2, 3, 4]];
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = run_digg(server.port, &[]);
    let text = stdout(&output);
    assert!(text.contains("(UDP)"), "missing transport: {}", text);
    assert!(text.contains("NOERROR"));
    assert!(text.contains("1.2.3.4"));
}

#[test]
fn tc_bit_triggers_tcp_retry_and_returns_tcp_answer() {
    static ADDRS: [[u8; 4]; 1] = [[5, 6, 7, 8]];
    let server = MockDns::start(Behavior::Truncated, Behavior::Answer(&ADDRS));
    let output = run_digg(server.port, &[]);
    let text = stdout(&output);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        text.contains("(TCP)"),
        "expected TCP fallback, got: {}",
        text
    );
    assert!(text.contains("5.6.7.8"));
}

#[test]
fn forced_tcp_uses_tcp_without_touching_udp() {
    static ADDRS: [[u8; 4]; 1] = [[5, 6, 7, 8]];
    // UDP is silent: if +tcp ever touched UDP, the query would hang/fail.
    let server = MockDns::start(Behavior::Silent, Behavior::Answer(&ADDRS));
    let output = run_digg(server.port, &["+tcp", "+timeout=5"]);
    let text = stdout(&output);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(text.contains("(TCP)"));
    assert!(text.contains("5.6.7.8"));
}

#[test]
fn mismatched_transaction_id_is_rejected() {
    let server = MockDns::start(Behavior::WrongId, Behavior::Silent);
    let output = run_digg(server.port, &[]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2), "protocol errors exit 2");
    assert!(
        stderr(&output).contains("does not match"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn udp_timeout_is_a_network_error_with_exit_code_9() {
    let server = MockDns::start(Behavior::Silent, Behavior::Silent);
    let output = run_digg(server.port, &["+timeout=1", "+notcp"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(9), "network errors exit 9");
    assert!(stderr(&output).contains("error"));
}

#[test]
fn large_udp_response_is_received_intact() {
    // 100 answers ≈ 1.6 KB — well past the classic 512-byte DNS limit.
    // Regression test for the receive-buffer fix in #28.
    static ADDRS: [[u8; 4]; 100] = {
        let mut addrs = [[0u8; 4]; 100];
        let mut i = 0;
        while i < 100 {
            addrs[i] = [10, 0, (i / 256) as u8, (i % 256) as u8];
            i += 1;
        }
        addrs
    };
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = run_digg(server.port, &["+short"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 100, "expected all 100 answers");
    assert_eq!(lines[0], "10.0.0.0");
    assert_eq!(lines[99], "10.0.0.99");
}

#[test]
fn tcp_answer_with_many_records_round_trips_framing() {
    static ADDRS: [[u8; 4]; 50] = {
        let mut addrs = [[0u8; 4]; 50];
        let mut i = 0;
        while i < 50 {
            addrs[i] = [172, 16, 0, i as u8];
            i += 1;
        }
        addrs
    };
    let server = MockDns::start(Behavior::Silent, Behavior::Answer(&ADDRS));
    let output = run_digg(server.port, &["+tcp", "+short"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output).lines().count(), 50);
}

#[test]
fn timeout_flag_bounds_wall_clock() {
    let server = MockDns::start(Behavior::Silent, Behavior::Silent);
    let start = std::time::Instant::now();
    let output = run_digg(server.port, &["+timeout=1", "+notcp"]);
    let elapsed = start.elapsed();
    assert!(!output.status.success());
    // Generous upper bound: 1s timeout should never take 5s.
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout took {:?}",
        elapsed
    );
}
