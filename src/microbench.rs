//! Micro-benchmarks for digg's own hot paths.
//!
//! Not to be confused with `bench.rs`, which is the user-facing `+bench`
//! feature for timing real DNS queries. This module times *digg's own code*,
//! so a refactor can be shown to be net positive rather than assumed to be.
//!
//! These are `#[ignore]`d so a normal `cargo test` stays fast. Run them with:
//!
//! ```text
//! cargo test --release --lib microbench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Release mode matters: a debug build is dominated by unoptimised formatting
//! and will not rank changes the way a real binary does.
//!
//! Two kinds of measurement live here, and they answer different questions:
//!
//! * **format** benches render into a `Vec<u8>`, so they isolate formatting and
//!   allocation cost with no syscalls. These are deterministic and are the ones
//!   to trust when comparing two implementations of a renderer.
//! * **sink** benches render to a real file descriptor (`/dev/null`) through
//!   both `LineWriter` and `BufWriter`, which is where write-syscall overhead
//!   shows up. These guard the buffering strategy in `output::emit`.

use crate::output::{self, Painter};
use crate::protocol::header::Header;
use crate::protocol::message::DnsMessage;
use crate::protocol::record::{RData, ResourceRecord};
use crate::protocol::types::{RecordClass, RecordType};
use crate::transport::{QueryResult, TransportProtocol};
use std::hint::black_box;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

// === Harness ===

struct Stats {
    min: Duration,
    median: Duration,
    mean: Duration,
}

/// Time `f` over `samples` runs after `warmup` untimed runs.
///
/// Reports the median as the headline figure rather than the mean: a stray
/// scheduler preemption skews the mean but leaves the median alone. The min is
/// kept as the best-case floor.
fn measure(warmup: usize, samples: usize, mut f: impl FnMut()) -> Stats {
    for _ in 0..warmup {
        f();
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f();
        times.push(start.elapsed());
    }
    times.sort_unstable();
    let total: Duration = times.iter().sum();
    Stats {
        min: times[0],
        median: times[samples / 2],
        mean: total / samples as u32,
    }
}

/// Print one result line. `items` is the unit count (records, calls) used for
/// the throughput column; pass 0 to omit it.
fn report(label: &str, stats: Stats, items: usize) {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let throughput = if items > 0 && !stats.median.is_zero() {
        format!(
            "{:>12.0} items/s",
            items as f64 / stats.median.as_secs_f64()
        )
    } else {
        String::new()
    };
    println!(
        "  {:<44} median {:>9.3} ms   min {:>9.3} ms   mean {:>9.3} ms{}",
        label,
        ms(stats.median),
        ms(stats.min),
        ms(stats.mean),
        throughput,
    );
}

// === Fixtures ===

/// A synthetic zone with a realistic spread of record types, so the renderer
/// exercises its per-type colouring and the varied rdata Display paths rather
/// than one hot branch.
fn zone(n: usize) -> Vec<ResourceRecord> {
    (0..n)
        .map(|i| {
            let (rtype, rdata) = match i % 5 {
                0 => (
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, (i % 256) as u8)),
                ),
                1 => (
                    RecordType::AAAA,
                    RData::AAAA(Ipv6Addr::new(
                        0x2001,
                        0xdb8,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (i % 65535) as u16,
                    )),
                ),
                2 => (
                    RecordType::MX,
                    RData::MX {
                        preference: (i % 50) as u16,
                        exchange: format!("mail{}.example.com.", i % 4),
                    },
                ),
                3 => (
                    RecordType::TXT,
                    RData::TXT(vec![format!(
                        "v=spf1 include:_spf{}.example.com ~all",
                        i % 3
                    )]),
                ),
                _ => (
                    RecordType::CNAME,
                    RData::CNAME(format!("alias{}.example.com.", i % 100)),
                ),
            };
            ResourceRecord {
                name: format!("host{:05}.example.com.", i),
                rtype,
                rclass: RecordClass::IN,
                // Spread across format_ttl's single- and multi-unit branches.
                ttl: [60, 3600, 86400, 90061, 45][i % 5],
                rdata,
                raw_rdata: Vec::new(),
            }
        })
        .collect()
}

fn response(answers: Vec<ResourceRecord>) -> QueryResult {
    let mut header = Header::new_query(0x1234, true);
    header.qr = true;
    header.ancount = answers.len() as u16;
    QueryResult {
        message: DnsMessage {
            header,
            questions: vec![],
            answers,
            authority: vec![],
            additional: vec![],
            edns: None,
        },
        elapsed: Duration::from_millis(23),
        bytes: 56,
        protocol: TransportProtocol::Udp,
    }
}

// === Formatting benches (no syscalls) ===

const ZONE_N: usize = 20_000;
const WARMUP: usize = 3;
const SAMPLES: usize = 15;

#[test]
#[ignore = "benchmark; run with --ignored"]
fn microbench_format_renderers() {
    let records = zone(ZONE_N);
    let result = response(zone(50));
    // Built once, outside the timed closures: cloning 20k records is far more
    // expensive than the rendering under test and would swamp the measurement.
    let big_result = response(zone(ZONE_N));
    let painter = Painter::with_color(false);
    let colored = Painter::with_color(true);

    println!("\nformatting into Vec<u8> (no syscalls), {ZONE_N} records:");

    let stats = measure(WARMUP, SAMPLES, || {
        let mut buf = Vec::with_capacity(1 << 20);
        output::write_axfr(&mut buf, &painter, &records);
        black_box(buf.len());
    });
    report("write_axfr (color off)", stats, ZONE_N);

    let stats = measure(WARMUP, SAMPLES, || {
        let mut buf = Vec::with_capacity(1 << 20);
        output::write_axfr(&mut buf, &colored, &records);
        black_box(buf.len());
    });
    report("write_axfr (color on)", stats, ZONE_N);

    let stats = measure(WARMUP, SAMPLES, || {
        let mut buf = Vec::with_capacity(1 << 20);
        output::write_tsv(&mut buf, &big_result);
        black_box(buf.len());
    });
    report("write_tsv", stats, ZONE_N);

    println!("\nsmall response (50 records), the common interactive path:");

    let stats = measure(WARMUP, SAMPLES * 20, || {
        let mut buf = Vec::with_capacity(8192);
        output::write_full(&mut buf, &painter, &result, "8.8.8.8", 53, true, true, true);
        black_box(buf.len());
    });
    report("write_full", stats, 50);

    let stats = measure(WARMUP, SAMPLES * 20, || {
        let mut buf = Vec::with_capacity(8192);
        output::write_json(&mut buf, &result);
        black_box(buf.len());
    });
    report("write_json", stats, 50);
}

#[test]
#[ignore = "benchmark; run with --ignored"]
fn microbench_format_ttl() {
    // format_ttl runs once per record per table, so its constant factor is
    // visible on large zone transfers.
    let ttls: Vec<u32> = (0..10_000)
        .map(|i| [60, 3600, 86400, 90061, 45][i % 5])
        .collect();
    let stats = measure(WARMUP, SAMPLES, || {
        for &t in &ttls {
            black_box(output::format_ttl(black_box(t)));
        }
    });
    println!("\nhelpers:");
    report("format_ttl x10k", stats, 10_000);
}

// === Wire-parsing benches ===

/// Append a name in uncompressed wire form (length-prefixed labels, root 0).
fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn push_record(out: &mut Vec<u8>, name: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
    encode_name(out, name);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// A wire buffer of `n` records spanning the parser's distinct shapes: fixed
/// width (A/AAAA), embedded name (MX), length-prefixed strings (TXT), and the
/// two-name-plus-five-u32 SOA, which is the heaviest byte-assembly arm.
fn wire_zone(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let name = format!("host{:05}.example.com.", i);
        match i % 5 {
            0 => push_record(&mut out, &name, 1, 3600, &[192, 0, 2, (i % 256) as u8]),
            1 => {
                let mut rd = [0u8; 16];
                rd[0..2].copy_from_slice(&[0x20, 0x01]);
                rd[15] = (i % 256) as u8;
                push_record(&mut out, &name, 28, 3600, &rd);
            }
            2 => {
                let mut rd = Vec::new();
                rd.extend_from_slice(&10u16.to_be_bytes());
                encode_name(&mut rd, "mail.example.com.");
                push_record(&mut out, &name, 15, 3600, &rd);
            }
            3 => {
                let text = format!("v=spf1 include:_spf{}.example.com ~all", i % 3);
                let mut rd = vec![text.len() as u8];
                rd.extend_from_slice(text.as_bytes());
                push_record(&mut out, &name, 16, 3600, &rd);
            }
            _ => {
                let mut rd = Vec::new();
                encode_name(&mut rd, "ns1.example.com.");
                encode_name(&mut rd, "hostmaster.example.com.");
                for v in [2024010101u32, 7200, 3600, 1209600, 300] {
                    rd.extend_from_slice(&v.to_be_bytes());
                }
                push_record(&mut out, &name, 6, 3600, &rd);
            }
        }
    }
    out
}

fn decode_all(wire: &[u8]) -> Vec<ResourceRecord> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let (rr, used) = ResourceRecord::decode(wire, offset).expect("fixture wire is well-formed");
        offset += used;
        records.push(rr);
    }
    records
}

#[test]
#[ignore = "benchmark; run with --ignored"]
fn microbench_record_decode() {
    let wire = wire_zone(ZONE_N);
    let records = decode_all(&wire);
    assert_eq!(records.len(), ZONE_N, "fixture should round-trip");

    println!("\nwire parsing, {ZONE_N} records:");

    let stats = measure(WARMUP, SAMPLES, || {
        black_box(decode_all(black_box(&wire)).len());
    });
    report("ResourceRecord::decode", stats, ZONE_N);

    // Display is what output.rs calls per record via rdata.to_string().
    let stats = measure(WARMUP, SAMPLES, || {
        for rr in &records {
            black_box(rr.rdata.to_string());
        }
    });
    report("RData Display (to_string)", stats, ZONE_N);
}

// === I/O strategy benches (real file descriptor) ===

/// Writing to a real fd is where the LineWriter-vs-BufWriter difference lives:
/// a bare `StdoutLock` is a `LineWriter` and issues one write syscall per line.
/// This guards the buffering that `output::emit` relies on.
#[cfg(unix)]
#[test]
#[ignore = "benchmark; run with --ignored"]
fn microbench_write_strategy_to_real_fd() {
    use std::fs::OpenOptions;
    use std::io::{BufWriter, LineWriter};

    let records = zone(ZONE_N);
    let painter = Painter::with_color(false);
    let devnull = || {
        OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null is writable on unix")
    };

    println!("\nwriting {ZONE_N} records to a real fd (/dev/null):");

    let stats = measure(WARMUP, SAMPLES, || {
        let mut out = LineWriter::new(devnull());
        output::write_axfr(&mut out, &painter, &records);
        let _ = out.flush();
    });
    report("LineWriter  (one syscall per line)", stats, ZONE_N);

    let stats = measure(WARMUP, SAMPLES, || {
        let mut out = BufWriter::new(devnull());
        output::write_axfr(&mut out, &painter, &records);
        let _ = out.flush();
    });
    report("BufWriter   (what output::emit uses)", stats, ZONE_N);
}
