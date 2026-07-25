//! Differential tests for `+compat` against the real dig.
//!
//! `+compat` exists so that scripts written against BIND dig keep working, and
//! the README documents that as a compatibility contract. Everything verifying
//! it so far compared digg against digg — golden strings written from the same
//! understanding as the code. These point real dig and digg at the *same* mock
//! responder and compare what each produces, so the contract is checked against
//! the thing it is a contract with.
//!
//! Hermetic: the mock is on loopback, and both clients are told to use it. If
//! dig is not installed the tests skip rather than fail, since it is not a
//! build dependency.

mod common;

use common::{Behavior, MockDns};
use std::process::Command;

const ANSWERS: &[[u8; 4]] = &[[93, 184, 216, 34], [93, 184, 216, 35]];

/// dig is not a build dependency, so a machine without it skips these.
fn dig_available() -> bool {
    Command::new("dig")
        .arg("-v")
        .output()
        .map(|o| o.status.success() || !o.stderr.is_empty())
        .unwrap_or(false)
}

fn run(bin: &str, args: &[String]) -> String {
    let out = Command::new(bin)
        .args(args)
        .env("HOME", std::env::temp_dir())
        .output()
        .unwrap_or_else(|e| panic!("running {}: {}", bin, e));
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn dig(port: u16, extra: &[&str]) -> String {
    let mut args = vec![
        "@127.0.0.1".to_string(),
        "-p".to_string(),
        port.to_string(),
        "example.com".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    run("dig", &args)
}

fn digg_compat(port: u16, extra: &[&str]) -> String {
    let mut args = vec![
        "@127.0.0.1".to_string(),
        "-p".to_string(),
        port.to_string(),
        "example.com".to_string(),
        "+compat".to_string(),
        "+nocolor".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    run(env!("CARGO_BIN_EXE_digg"), &args)
}

/// The section header lines scripts grep for, and the answer records
/// themselves, should agree field for field.
#[test]
fn compat_answer_section_matches_dig_field_for_field() {
    if !dig_available() {
        eprintln!("skipping: dig not installed");
        return;
    }
    let mock = MockDns::start(Behavior::Answer(ANSWERS), Behavior::Answer(ANSWERS));

    // +noall +answer prints only the answer records, one per line.
    let dig_answer = dig(mock.port, &["+noall", "+answer"]);
    let digg_answer = digg_compat(mock.port, &[]);

    // Compare the answer records as whitespace-normalised fields, which is how
    // an awk or cut pipeline would read them.
    let fields =
        |line: &str| -> Vec<String> { line.split_whitespace().map(|s| s.to_string()).collect() };

    let dig_records: Vec<Vec<String>> = dig_answer
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with(';'))
        .map(fields)
        .collect();

    let digg_records: Vec<Vec<String>> = digg_answer
        .lines()
        .skip_while(|l| !l.starts_with(";; ANSWER SECTION:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .map(fields)
        .collect();

    assert!(
        !dig_records.is_empty(),
        "dig produced no answer records; mock may not have replied:\n{}",
        dig_answer
    );
    assert_eq!(
        dig_records.len(),
        digg_records.len(),
        "record count differs\ndig:\n{}\ndigg:\n{}",
        dig_answer,
        digg_answer
    );
    for (d, g) in dig_records.iter().zip(&digg_records) {
        // name, ttl, class, type, rdata
        assert_eq!(d.len(), 5, "unexpected dig record shape: {:?}", d);
        assert_eq!(g.len(), 5, "unexpected digg record shape: {:?}", g);
        assert_eq!(d[0], g[0], "owner name differs");
        assert_eq!(d[2], g[2], "class differs");
        assert_eq!(d[3], g[3], "type differs");
        assert_eq!(d[4], g[4], "rdata differs");
        // TTL is a number in both; the mock serves a fixed one.
        assert_eq!(d[1], g[1], "ttl differs");
    }
}

/// The header line scripts parse for status, and the flags line, should use the
/// same punctuation and keywords dig does.
#[test]
fn compat_header_and_flags_use_digs_punctuation() {
    if !dig_available() {
        eprintln!("skipping: dig not installed");
        return;
    }
    let mock = MockDns::start(Behavior::Answer(ANSWERS), Behavior::Answer(ANSWERS));
    let dig_out = dig(mock.port, &[]);
    let digg_out = digg_compat(mock.port, &[]);

    let header_of = |s: &str| -> String {
        s.lines()
            .find(|l| l.contains("->>HEADER<<-"))
            .unwrap_or_default()
            // The id varies per query; compare the rest.
            .split(", id:")
            .next()
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(
        header_of(&dig_out),
        header_of(&digg_out),
        "HEADER line differs\ndig:\n{}\ndigg:\n{}",
        dig_out,
        digg_out
    );

    // Flags line: dig prints ";; flags: qr aa rd; QUERY: 1, ANSWER: 2, ...".
    let flags_of = |s: &str| -> String {
        s.lines()
            .find(|l| l.trim_start().starts_with(";; flags:"))
            .unwrap_or_default()
            .to_string()
    };
    let (dig_flags, digg_flags) = (flags_of(&dig_out), flags_of(&digg_out));
    assert!(
        !dig_flags.is_empty() && !digg_flags.is_empty(),
        "missing flags line\ndig: {:?}\ndigg: {:?}",
        dig_flags,
        digg_flags
    );
    assert_eq!(
        dig_flags, digg_flags,
        "flags line differs\ndig:\n{}\ndigg:\n{}",
        dig_out, digg_out
    );
}

/// The classic `dig +short`-style pipeline: pull the rdata column out with awk.
/// This is the shape of script the compatibility contract exists to protect.
#[test]
fn compat_rdata_column_survives_an_awk_pipeline() {
    if !dig_available() {
        eprintln!("skipping: dig not installed");
        return;
    }
    let mock = MockDns::start(Behavior::Answer(ANSWERS), Behavior::Answer(ANSWERS));

    let awk_last_column = |text: &str| -> Vec<String> {
        text.lines()
            .skip_while(|l| !l.starts_with(";; ANSWER SECTION:"))
            .skip(1)
            .take_while(|l| !l.trim().is_empty())
            .filter_map(|l| l.split_whitespace().last().map(|s| s.to_string()))
            .collect()
    };

    let from_digg = awk_last_column(&digg_compat(mock.port, &[]));
    let expected: Vec<String> = ANSWERS
        .iter()
        .map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
        .collect();
    assert_eq!(from_digg, expected, "digg's answer column");

    // dig prints the same records; ordering from the mock is stable.
    let mut from_dig: Vec<String> = dig(mock.port, &["+noall", "+answer"])
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with(';'))
        .filter_map(|l| l.split_whitespace().last().map(|s| s.to_string()))
        .collect();
    from_dig.sort();
    let mut sorted_expected = expected.clone();
    sorted_expected.sort();
    assert_eq!(from_dig, sorted_expected, "dig's answer column");
}
