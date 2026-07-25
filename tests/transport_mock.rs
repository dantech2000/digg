//! Hermetic transport integration tests: drive the compiled digg binary
//! against a programmable mock DNS responder on loopback. No external
//! network access, no external crates.

mod common;

use common::{build_response, Behavior, MockDns};
use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

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
    let output = run_digg(server.port, &["+timeout=1", "+notcp", "+retry=0"]);
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
    let output = run_digg(server.port, &["+timeout=1", "+notcp", "+retry=0"]);
    let elapsed = start.elapsed();
    assert!(!output.status.success());
    // Generous upper bound: 1s timeout should never take 5s.
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout took {:?}",
        elapsed
    );
}

#[test]
fn chaos_class_query_round_trips_through_transport() {
    static ADDRS: [[u8; 4]; 1] = [[127, 0, 0, 1]];
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = Command::new(env!("CARGO_BIN_EXE_digg"))
        .args([
            "@127.0.0.1",
            "-p",
            &server.port.to_string(),
            "-c",
            "CH",
            "version.bind",
            "TXT",
            "+nocolor",
        ])
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("run digg");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("NOERROR"));
}

#[test]
fn udp_retry_recovers_from_a_dropped_datagram() {
    static ADDRS: [[u8; 4]; 1] = [[4, 3, 2, 1]];
    // First request dropped; the retry gets the answer.
    let server = MockDns::start(Behavior::AnswerAfterDrops(&ADDRS, 1), Behavior::Silent);
    let output = run_digg(server.port, &["+timeout=1", "+retry=2", "+short"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "4.3.2.1\n");
}

#[test]
fn retry_zero_fails_on_a_single_dropped_datagram() {
    static ADDRS: [[u8; 4]; 1] = [[4, 3, 2, 1]];
    let server = MockDns::start(Behavior::AnswerAfterDrops(&ADDRS, 1), Behavior::Silent);
    let output = run_digg(server.port, &["+timeout=1", "+retry=0", "+notcp"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(9));
}

#[test]
fn exhausted_retries_report_attempt_count() {
    let server = MockDns::start(Behavior::Silent, Behavior::Silent);
    let output = run_digg(server.port, &["+timeout=1", "+retry=1", "+notcp"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("2 attempts"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn qr_prints_the_outgoing_query_before_the_answer() {
    static ADDRS: [[u8; 4]; 1] = [[1, 2, 3, 4]];
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = run_digg(server.port, &["+qr"]);
    let text = stdout(&output);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let query_pos = text.find("QUERY").expect("query section present");
    let answer_pos = text.find("ANSWER").expect("answer section present");
    assert!(query_pos < answer_pos);
    assert!(text.contains("example.com.  IN  A"));
}

#[test]
fn nostats_hides_the_status_footer() {
    static ADDRS: [[u8; 4]; 1] = [[1, 2, 3, 4]];
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = run_digg(server.port, &["+nostats", "+noauthority", "+noadditional"]);
    let text = stdout(&output);
    assert!(output.status.success());
    assert!(text.contains("1.2.3.4"));
    assert!(!text.contains("NOERROR"));
}

#[test]
fn tsv_output_is_stable_tab_separated_lines() {
    static ADDRS: [[u8; 4]; 2] = [[1, 2, 3, 4], [5, 6, 7, 8]];
    let server = MockDns::start(Behavior::Answer(&ADDRS), Behavior::Silent);
    let output = run_digg(server.port, &["+tsv"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "example.com.\t60\tIN\tA\t1.2.3.4\nexample.com.\t60\tIN\tA\t5.6.7.8\n"
    );
}

#[test]
fn cd_flag_sets_the_checking_disabled_bit_on_the_wire() {
    use std::sync::mpsc;
    // A one-shot capturing server: record the query's flags2 byte, then answer.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = socket.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (n, peer) = socket.recv_from(&mut buf).unwrap();
        // flags2 is byte index 3; CD is 0x10.
        let _ = tx.send(buf[3]);
        // Minimal NOERROR answer echoing the question.
        if let Some(resp) = build_response(&buf[..n], Behavior::Answer(&[[1, 2, 3, 4]])) {
            let _ = socket.send_to(&resp, peer);
        }
    });

    let out = Command::new(env!("CARGO_BIN_EXE_digg"))
        .args([
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "example.com",
            "+cd",
            "+noedns",
            "+nocolor",
            "+short",
        ])
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("run digg");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let flags2 = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("query captured");
    assert_eq!(
        flags2 & 0x10,
        0x10,
        "CD bit should be set (flags2=0x{:02x})",
        flags2
    );
}
