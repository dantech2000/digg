//! Stable, CI-runnable randomized parser hardening.
//!
//! Not coverage-guided (that lives in `fuzz/`, nightly + cargo-fuzz). The
//! goal here is a deterministic, hermetic panic-hunt that runs on stable in
//! the normal test suite: feed thousands of hostile byte buffers to every
//! decoder and assert the parser *never panics* — malformed input must
//! surface as `Err`, never a slice-index or unwrap crash.

use crate::protocol::message::DnsMessage;
use crate::protocol::name::decode_name;
use crate::protocol::record::ResourceRecord;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `f(input)` with the panic hook silenced; on panic, return the input
/// hex so a failure is reproducible from the seed.
fn guard<F: FnOnce()>(input: &[u8], f: F) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    if result.is_err() {
        panic!(
            "parser panicked on {}-byte input: {}",
            input.len(),
            input
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }
}

/// Feed one buffer to every decoder entry point. All are allowed to return
/// Err; none may panic.
fn exercise(input: &[u8]) {
    guard(input, || {
        let _ = DnsMessage::parse(input);
    });
    guard(input, || {
        // decode_name is reached at many offsets during real parsing;
        // hit a spread of them directly, including near the tail.
        for &off in &[0usize, 1, 2, 11, 12, input.len().saturating_sub(1)] {
            if off < input.len() {
                let _ = decode_name(input, off);
            }
        }
    });
    guard(input, || {
        let _ = ResourceRecord::decode(input, 0);
        if input.len() > 12 {
            let _ = ResourceRecord::decode(input, 12);
        }
    });
}

#[test]
fn parser_survives_uniform_random_bytes() {
    let mut rng = StdRng::seed_from_u64(0xD166_5EED);
    for _ in 0..20_000 {
        let len = rng.gen_range(0..600);
        let buf: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        exercise(&buf);
    }
}

#[test]
fn parser_survives_structured_random_messages() {
    // Random bytes rarely produce a plausible header (counts that drive the
    // record loops). Bias toward well-formed-looking headers with hostile
    // section counts so the RR/name decoders get deep exercise.
    let mut rng = StdRng::seed_from_u64(0x0BAD_C0DE);
    for _ in 0..20_000 {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&rng.gen::<u16>().to_be_bytes()); // id
        buf.extend_from_slice(&rng.gen::<u16>().to_be_bytes()); // flags
                                                                // Small-ish counts so the loops iterate but stay bounded.
        for _ in 0..4 {
            buf.extend_from_slice(&(rng.gen_range(0u16..8)).to_be_bytes());
        }
        let body_len = rng.gen_range(0..500);
        for _ in 0..body_len {
            // Mix of label-length bytes, compression-pointer high bits, and
            // zeros so names sometimes decode and sometimes jump/loop.
            let b: u8 = match rng.gen_range(0..4) {
                0 => 0x00,
                1 => 0xC0 | rng.gen::<u8>() & 0x3F,
                2 => rng.gen_range(0..64),
                _ => rng.gen(),
            };
            buf.push(b);
        }
        exercise(&buf);
    }
}

#[test]
fn parser_survives_mutated_real_messages() {
    // Bit-flips, truncations, and extensions of genuine wire captures — the
    // mutations most likely to slip past length checks a fresh-random buffer
    // never reaches.
    let seeds: &[&[u8]] = &[CF_A, ROOT_DNSKEY, COMPRESSED_NAME_MSG];
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE);
    for seed in seeds {
        for _ in 0..10_000 {
            let mut buf = seed.to_vec();
            match rng.gen_range(0..4) {
                0 => {
                    // Flip a handful of random bits.
                    for _ in 0..rng.gen_range(1..6) {
                        if !buf.is_empty() {
                            let i = rng.gen_range(0..buf.len());
                            buf[i] ^= 1 << rng.gen_range(0..8);
                        }
                    }
                }
                1 => {
                    // Truncate to a random prefix.
                    let n = rng.gen_range(0..=buf.len());
                    buf.truncate(n);
                }
                2 => {
                    // Append garbage.
                    for _ in 0..rng.gen_range(1..40) {
                        buf.push(rng.gen());
                    }
                }
                _ => {
                    // Corrupt a section count in the header.
                    if buf.len() >= 12 {
                        let i = rng.gen_range(4..12);
                        buf[i] = rng.gen();
                    }
                }
            }
            exercise(&buf);
        }
    }
}

#[test]
fn parser_survives_adversarial_compression_and_lengths() {
    // Hand-built pathologies: pointer loops, pointers past EOF, label lengths
    // that overrun, and maximal section counts with no body.
    let cases: Vec<Vec<u8>> = vec![
        // Header claims 65535 answers, empty body.
        vec![0, 0, 0x81, 0x80, 0, 1, 0xFF, 0xFF, 0, 0, 0, 0],
        // A name that is a compression pointer to itself (offset 12).
        {
            let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
            m.extend_from_slice(&[0xC0, 0x0C]); // pointer -> 12 (self)
            m
        },
        // Two pointers forming a 2-cycle.
        {
            let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
            m.extend_from_slice(&[0xC0, 0x0E, 0xC0, 0x0C]); // 12->14, 14->12
            m
        },
        // Pointer past end of buffer.
        vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF],
        // Label length 63 with no following bytes.
        vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 63],
        // RR with rdlength far larger than the remaining buffer.
        {
            let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            m.extend_from_slice(&[0x00]); // root name
            m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
            m.extend_from_slice(&[0, 0, 0, 60]); // ttl
            m.extend_from_slice(&[0xFF, 0xFF]); // rdlength 65535
            m
        },
    ];
    for case in &cases {
        exercise(case);
    }
}

// --- fixtures: small genuine captures used as mutation seeds ---

// cloudflare.com A + RRSIG, captured for the DNSSEC tests (1.1.1.1).
const CF_A: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x63, 0x6C, 0x6F,
    0x75, 0x64, 0x66, 0x6C, 0x61, 0x72, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 0x68, 0x10, 0x84, 0xE5,
    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 0x68, 0x10, 0x85, 0xE5,
];

// Root DNSKEY (compression-heavy, RRSIG-bearing).
const ROOT_DNSKEY: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x30, 0x00,
    0x01, 0x00, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00, 0x00, 0x30, 0x00,
];

// A small message with a compression pointer in the answer name.
const COMPRESSED_NAME_MSG: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x05, 0x00,
    0x01, 0xC0, 0x10, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x02, 0xC0, 0x10,
];
