//! A programmable mock DNS responder on loopback, shared by the integration
//! tests. No external network access, no external crates.
//!
//! Integration tests are separate crates, so anything unused by one of them
//! looks dead to it; the allow keeps that from becoming a warning.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::thread;

/// What the mock returns for a protocol leg.
#[derive(Clone, Copy)]
pub enum Behavior {
    /// Well-formed answer with the given IPv4 rdata, one A record per address.
    Answer(&'static [[u8; 4]]),
    /// Ignore the first `drops` requests, then answer (exercises retries).
    AnswerAfterDrops(&'static [[u8; 4]], u32),
    /// Empty answer with the TC bit set (tells the client to retry over TCP).
    Truncated,
    /// Answer whose transaction ID does not match the query's.
    WrongId,
    /// Never respond.
    Silent,
}

pub struct MockDns {
    pub port: u16,
}

impl MockDns {
    /// Bind TCP and UDP on the same loopback port and serve `udp`/`tcp`
    /// behaviors from background threads for the life of the test process.
    pub fn start(udp: Behavior, tcp: Behavior) -> Self {
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
            thread::spawn(move || {
                let mut seen = 0u32;
                loop {
                    let mut buf = [0u8; 65535];
                    let Ok((len, peer)) = udp_handle.recv_from(&mut buf) else {
                        return;
                    };
                    seen += 1;
                    let effective = match udp_behavior {
                        Behavior::AnswerAfterDrops(addrs, drops) => {
                            if seen <= drops {
                                continue;
                            }
                            Behavior::Answer(addrs)
                        }
                        other => other,
                    };
                    if let Some(resp) = build_response(&buf[..len], effective) {
                        let _ = udp_handle.send_to(&resp, peer);
                    }
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
pub fn build_response(query: &[u8], behavior: Behavior) -> Option<Vec<u8>> {
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
        Behavior::Silent | Behavior::AnswerAfterDrops(..) => unreachable!(),
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
