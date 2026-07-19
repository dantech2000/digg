use crate::bench::BenchResult;
use crate::compare::ComparisonResult;
use crate::propagation::PropagationResult;
use crate::protocol::record::{RData, ResourceRecord};
use crate::protocol::types::Rcode;
use crate::trace::TraceHop;
use crate::transport::QueryResult;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU8, Ordering};

// ANSI color codes
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const BOLD_RED: &str = "\x1b[1;31m";
const BOLD_CYAN: &str = "\x1b[1;36m";
const BOLD_WHITE: &str = "\x1b[1;37m";
const BOLD_GREEN: &str = "\x1b[1;32m";
const BOLD_YELLOW: &str = "\x1b[1;33m";

#[derive(Clone, Copy, Debug, Default)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

static COLOR_MODE: AtomicU8 = AtomicU8::new(0);

pub fn set_color_mode(mode: ColorMode) {
    let value = match mode {
        ColorMode::Auto => 0,
        ColorMode::Always => 1,
        ColorMode::Never => 2,
    };
    COLOR_MODE.store(value, Ordering::Relaxed);
}

pub fn stdout_color_enabled() -> bool {
    let mode = match COLOR_MODE.load(Ordering::Relaxed) {
        1 => ColorMode::Always,
        2 => ColorMode::Never,
        _ => ColorMode::Auto,
    };
    color_enabled(
        mode,
        io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
    )
}

fn color_enabled(mode: ColorMode, is_terminal: bool, no_color: bool) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => is_terminal && !no_color,
    }
}

pub struct Painter {
    color: bool,
}

impl Painter {
    fn new() -> Self {
        Painter {
            color: stdout_color_enabled(),
        }
    }

    /// Painter with an explicit color decision, independent of terminal
    /// detection. This is the seam tests use to render deterministically.
    #[allow(dead_code)] // only test code constructs this today
    pub fn with_color(color: bool) -> Self {
        Painter { color }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{}{}{}", code, text, RESET)
        } else {
            text.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::header::Header;
    use crate::protocol::message::DnsMessage;
    use crate::protocol::record::{RData, ResourceRecord};
    use crate::protocol::types::{RecordClass, RecordType};
    use crate::transport::TransportProtocol;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn color_mode_precedence_is_explicit_then_no_color_then_terminal() {
        assert!(color_enabled(ColorMode::Always, false, true));
        assert!(!color_enabled(ColorMode::Never, true, false));
        assert!(!color_enabled(ColorMode::Auto, true, true));
        assert!(color_enabled(ColorMode::Auto, true, false));
        assert!(!color_enabled(ColorMode::Auto, false, false));
    }

    #[test]
    fn painter_with_color_wraps_ansi_codes_and_without_passes_through() {
        let plain = Painter::with_color(false);
        assert_eq!(plain.paint(GREEN, "x"), "x");
        let colored = Painter::with_color(true);
        assert_eq!(colored.paint(GREEN, "x"), "\x1b[32mx\x1b[0m");
    }

    fn a_record(name: &str, ttl: u32, addr: [u8; 4]) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl,
            rdata: RData::A(Ipv4Addr::from(addr)),
        }
    }

    fn fixture_result(answers: Vec<ResourceRecord>) -> QueryResult {
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

    fn render<F: FnOnce(&mut Vec<u8>)>(f: F) -> String {
        let mut buf = Vec::new();
        f(&mut buf);
        String::from_utf8(buf).expect("output is valid UTF-8")
    }

    // === Golden tests (color off) ===

    #[test]
    fn write_short_emits_one_rdata_per_line() {
        let result = fixture_result(vec![
            a_record("example.com.", 3600, [93, 184, 216, 34]),
            a_record("example.com.", 3600, [93, 184, 216, 35]),
        ]);
        let text = render(|out| write_short(out, &result));
        assert_eq!(text, "93.184.216.34\n93.184.216.35\n");
    }

    #[test]
    fn write_full_golden_single_answer() {
        let result = fixture_result(vec![a_record("example.com.", 3600, [93, 184, 216, 34])]);
        let painter = Painter::with_color(false);
        let text =
            render(|out| write_full(out, &painter, &result, "8.8.8.8", 53, true, true, true));
        let expected = "\n ANSWER\n \
             TYPE   NAME           TTL   VALUE\n \
             A      example.com.   1h    93.184.216.34\n\
             \n \u{2500}\u{2500} 8.8.8.8:53 (UDP) \u{2500}\u{2500} NOERROR \u{2500}\u{2500} 23ms \u{2500}\u{2500} 56B \u{2500}\u{2500}\n";
        assert_eq!(text, expected);
    }

    #[test]
    fn write_full_contains_no_ansi_escapes_when_color_off() {
        let result = fixture_result(vec![a_record("example.com.", 60, [1, 2, 3, 4])]);
        let painter = Painter::with_color(false);
        let text =
            render(|out| write_full(out, &painter, &result, "1.1.1.1", 53, true, true, true));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn write_full_hides_sections_when_toggled_off() {
        let mut result = fixture_result(vec![a_record("example.com.", 60, [1, 2, 3, 4])]);
        result
            .message
            .authority
            .push(a_record("ns.example.com.", 60, [5, 6, 7, 8]));
        result
            .message
            .additional
            .push(a_record("glue.example.com.", 60, [9, 9, 9, 9]));

        let painter = Painter::with_color(false);
        let shown = render(|out| write_full(out, &painter, &result, "s", 53, true, true, true));
        assert!(shown.contains("AUTHORITY") && shown.contains("ADDITIONAL"));

        let hidden = render(|out| write_full(out, &painter, &result, "s", 53, false, false, true));
        assert!(!hidden.contains("AUTHORITY") && !hidden.contains("ADDITIONAL"));
    }

    #[test]
    fn write_full_renders_edns_and_dnssec_flag_lines() {
        let mut result = fixture_result(vec![a_record("example.com.", 60, [1, 2, 3, 4])]);
        result.message.edns = Some(crate::protocol::edns::EdnsInfo {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: true,
            subnet: None,
            nsid: None,
        });
        result.message.header.ad = true;
        let painter = Painter::with_color(false);
        let text = render(|out| write_full(out, &painter, &result, "s", 53, true, true, true));
        assert!(text.contains(" EDNS version 0; flags: do; udp: 1232"));
        assert!(text.contains(" flags: ad"));
    }

    #[test]
    fn write_full_appends_returned_client_subnet_scope() {
        let mut result = fixture_result(vec![a_record("cdn.example.com.", 60, [1, 2, 3, 4])]);
        result.message.edns = Some(crate::protocol::edns::EdnsInfo {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            subnet: Some(crate::protocol::edns::ClientSubnet {
                family: 1,
                source_prefix: 24,
                scope_prefix: 18,
                address: "96.112.0.0".to_string(),
            }),
            nsid: None,
        });
        let painter = Painter::with_color(false);
        let text = render(|out| write_full(out, &painter, &result, "s", 53, true, true, true));
        assert!(text.contains("udp: 1232; subnet: 96.112.0.0/24/18"));
    }

    #[test]
    fn write_full_appends_returned_nsid() {
        let mut result = fixture_result(vec![a_record("example.com.", 60, [1, 2, 3, 4])]);
        result.message.edns = Some(crate::protocol::edns::EdnsInfo {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            subnet: None,
            nsid: Some(crate::protocol::edns::Nsid {
                hex: "6c617833".to_string(),
                text: Some("lax3".to_string()),
            }),
        });
        let painter = Painter::with_color(false);
        let text = render(|out| write_full(out, &painter, &result, "s", 53, true, true, true));
        assert!(text.contains("udp: 1232; nsid: 6c617833 (\"lax3\")"));
    }

    #[test]
    fn write_batch_result_golden_success_and_error() {
        let result = fixture_result(vec![a_record("example.com.", 60, [93, 184, 216, 34])]);
        let painter = Painter::with_color(false);
        let ok = render(|out| {
            write_batch_result(out, &painter, "example.com", &RecordType::A, &Ok(result))
        });
        assert_eq!(ok, " A example.com NOERROR 23ms 93.184.216.34\n");

        let err: Result<QueryResult, crate::error::DnsError> =
            Err(crate::error::DnsError::Network("timed out".into()));
        let failed =
            render(|out| write_batch_result(out, &painter, "example.com", &RecordType::A, &err));
        assert_eq!(failed, " A example.com error: timed out\n");
    }

    #[test]
    fn write_json_is_valid_and_carries_timing_and_answers() {
        let result = fixture_result(vec![a_record("example.com.", 3600, [93, 184, 216, 34])]);
        let text = render(|out| write_json(out, &result));
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["query_time_ms"], 23);
        assert_eq!(value["response_size"], 56);
        assert_eq!(value["transport"], "UDP");
        assert_eq!(value["message"]["answers"][0]["ttl"], 3600);
    }

    #[test]
    fn write_yaml_is_valid_and_matches_json_shape() {
        let result = fixture_result(vec![a_record("example.com.", 3600, [93, 184, 216, 34])]);
        let text = render(|out| write_yaml(out, &result));
        let value: serde_yaml::Value = serde_yaml::from_str(&text).expect("valid YAML");
        assert_eq!(value["transport"], "UDP");
        assert_eq!(value["query_time_ms"], 23);
    }

    #[test]
    fn write_bench_reports_stats_and_histogram() {
        let bench = BenchResult {
            successful: 3,
            failed: 1,
            min_ms: 1.0,
            max_ms: 9.0,
            avg_ms: 4.0,
            p50_ms: 2.0,
            p90_ms: 8.0,
            p99_ms: 9.0,
            histogram: vec![(5.0, 2), (9.0, 1)],
        };
        let painter = Painter::with_color(false);
        let text = render(|out| write_bench(out, &painter, &bench, "8.8.8.8", "example.com", "A"));
        assert!(text.contains("BENCHMARK example.com A @8.8.8.8"));
        assert!(text.contains("queries: 3 successful, 1 failed"));
        assert!(text.contains("1.0     4.0     2.0     8.0     9.0     9.0"));
        assert!(text.contains("\u{2588}")); // histogram bars present
    }

    #[test]
    fn write_bench_with_zero_successes_short_circuits() {
        let bench = BenchResult {
            successful: 0,
            failed: 5,
            min_ms: 0.0,
            max_ms: 0.0,
            avg_ms: 0.0,
            p50_ms: 0.0,
            p90_ms: 0.0,
            p99_ms: 0.0,
            histogram: vec![],
        };
        let painter = Painter::with_color(false);
        let text = render(|out| write_bench(out, &painter, &bench, "s", "n", "A"));
        assert!(text.contains("no successful queries"));
        assert!(!text.contains("min"));
    }

    #[test]
    fn write_full_without_stats_omits_the_status_footer() {
        let result = fixture_result(vec![a_record("example.com.", 3600, [93, 184, 216, 34])]);
        let painter = Painter::with_color(false);
        let text =
            render(|out| write_full(out, &painter, &result, "8.8.8.8", 53, true, true, false));
        assert!(text.contains("93.184.216.34"));
        assert!(!text.contains("NOERROR"));
        assert!(!text.contains("\u{2500}"));
        assert!(!text.contains("ms"));
    }

    #[test]
    fn write_query_renders_parsed_outgoing_message() {
        // Build real query bytes, parse them back, render — same path +qr uses.
        let (bytes, _id) = DnsMessage::build_query(
            "example.com",
            RecordType::A,
            true,
            Some(&crate::protocol::edns::EdnsOptions {
                dnssec_ok: true,
                ..Default::default()
            }),
        )
        .unwrap();
        let message = DnsMessage::parse(&bytes).unwrap();
        let painter = Painter::with_color(false);
        let text = render(|out| write_query(out, &painter, &message, "8.8.8.8", 53));
        assert!(text.contains("QUERY \u{2192} 8.8.8.8:53"));
        assert!(text.contains("flags: rd; QUESTION: 1, ADDITIONAL: 1"));
        assert!(text.contains("example.com.  IN  A"));
        assert!(text.contains("EDNS version 0; flags: do; udp: 4096"));
    }

    // === TSV golden tests ===

    #[test]
    fn write_tsv_golden_one_record_per_line() {
        let result = fixture_result(vec![
            a_record("example.com.", 3600, [93, 184, 216, 34]),
            a_record("example.com.", 3600, [93, 184, 216, 35]),
        ]);
        let text = render(|out| write_tsv(out, &result));
        assert_eq!(
            text,
            "example.com.\t3600\tIN\tA\t93.184.216.34\n\
             example.com.\t3600\tIN\tA\t93.184.216.35\n"
        );
    }

    #[test]
    fn write_tsv_contains_no_ansi_and_no_headers() {
        let result = fixture_result(vec![a_record("example.com.", 60, [1, 2, 3, 4])]);
        let text = render(|out| write_tsv(out, &result));
        assert!(!text.contains('\x1b'));
        assert!(!text.contains("TYPE"));
        assert!(!text.contains("NOERROR"));
    }

    #[test]
    fn write_tsv_escapes_tabs_newlines_and_backslashes_in_rdata() {
        let mut result = fixture_result(vec![]);
        result.message.answers.push(ResourceRecord {
            name: "example.com.".to_string(),
            rtype: RecordType::TXT,
            rclass: RecordClass::IN,
            ttl: 60,
            rdata: RData::TXT(vec!["a\tb\nc\\d".to_string()]),
        });
        let text = render(|out| write_tsv(out, &result));
        let rdata_field = text.trim_end().split('\t').nth(4).unwrap().to_string();
        assert_eq!(rdata_field, "\"a\\tb\\nc\\\\d\"");
        // Exactly 5 fields — embedded separators never add columns.
        assert_eq!(text.trim_end().split('\t').count(), 5);
    }

    #[test]
    fn write_tsv_of_empty_answer_set_is_empty() {
        let result = fixture_result(vec![]);
        assert_eq!(render(|out| write_tsv(out, &result)), "");
    }

    // === format_ttl ===

    #[test]
    fn format_ttl_humanizes_and_keeps_two_largest_units() {
        assert_eq!(format_ttl(0), "0s");
        assert_eq!(format_ttl(59), "59s");
        assert_eq!(format_ttl(60), "1m");
        assert_eq!(format_ttl(3600), "1h");
        assert_eq!(format_ttl(3661), "1h 1m"); // seconds dropped by truncate(2)
        assert_eq!(format_ttl(86400), "1d");
        assert_eq!(format_ttl(90061), "1d 1h");
    }
}

// === Standard output ===

pub fn print_short(result: &QueryResult) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_short(&mut out, result);
}

pub fn write_short<W: Write>(out: &mut W, result: &QueryResult) {
    for rr in &result.message.answers {
        let _ = writeln!(out, "{}", rr.rdata);
    }
}

pub fn print_query(message: &crate::protocol::message::DnsMessage, server: &str, port: u16) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_query(&mut out, &painter, message, server, port);
}

/// Render the outgoing query (+qr). The message is the parsed form of the
/// exact bytes about to go on the wire, so this cannot drift from reality.
pub fn write_query<W: Write>(
    out: &mut W,
    painter: &Painter,
    message: &crate::protocol::message::DnsMessage,
    server: &str,
    port: u16,
) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {} {} {}:{}",
        painter.paint(BOLD_WHITE, "QUERY"),
        painter.paint(DIM, "\u{2192}"),
        server,
        port
    );

    let header = &message.header;
    let mut flags = Vec::new();
    if header.rd {
        flags.push("rd");
    }
    if header.cd {
        flags.push("cd");
    }
    let _ = writeln!(
        out,
        " {} {}; QUESTION: {}, ADDITIONAL: {}",
        painter.paint(DIM, "flags:"),
        flags.join(" "),
        header.qdcount,
        header.arcount
    );

    for q in &message.questions {
        let _ = writeln!(
            out,
            " {}  {}  {}",
            q.name,
            q.qclass,
            painter.paint(BOLD_CYAN, &q.qtype.to_string())
        );
    }

    if let Some(ref edns) = message.edns {
        let flags = if edns.dnssec_ok { "do" } else { "" };
        let _ = writeln!(
            out,
            " {} version {}; flags: {}; udp: {}",
            painter.paint(DIM, "EDNS"),
            edns.version,
            flags,
            edns.udp_payload_size
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub fn print_full(
    result: &QueryResult,
    server: &str,
    port: u16,
    show_authority: bool,
    show_additional: bool,
    show_stats: bool,
) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_full(
        &mut out,
        &painter,
        result,
        server,
        port,
        show_authority,
        show_additional,
        show_stats,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn write_full<W: Write>(
    out: &mut W,
    painter: &Painter,
    result: &QueryResult,
    server: &str,
    port: u16,
    show_authority: bool,
    show_additional: bool,
    show_stats: bool,
) {
    // Answer section
    if !result.message.answers.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ANSWER"));
        print_record_table(out, painter, &result.message.answers);
    }

    // Authority section
    if show_authority && !result.message.authority.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "AUTHORITY"));
        print_record_table(out, painter, &result.message.authority);
    }

    // Additional section
    if show_additional && !result.message.additional.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ADDITIONAL"));
        print_record_table(out, painter, &result.message.additional);
    }

    // EDNS info
    if let Some(ref edns) = result.message.edns {
        let _ = writeln!(out);
        let flags = if edns.dnssec_ok { "do" } else { "" };
        let subnet = edns
            .subnet
            .as_ref()
            .map(|s| format!("; subnet: {}", s))
            .unwrap_or_default();
        let nsid = edns
            .nsid
            .as_ref()
            .map(|n| format!("; nsid: {}", n))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            " {} version {}; flags: {}; udp: {}{}{}",
            painter.paint(DIM, "EDNS"),
            edns.version,
            flags,
            edns.udp_payload_size,
            subnet,
            nsid
        );
    }

    // DNSSEC flags
    let header = &result.message.header;
    if header.ad || header.cd {
        let mut flags = Vec::new();
        if header.ad {
            flags.push("ad");
        }
        if header.cd {
            flags.push("cd");
        }
        let _ = writeln!(out, " {} {}", painter.paint(DIM, "flags:"), flags.join(" "));
    }

    // Status line
    if !show_stats {
        return;
    }
    let _ = writeln!(out);
    let elapsed_ms = result.elapsed.as_millis();
    let rcode = &result.message.header.rcode;
    let rcode_str = format_rcode(painter, rcode);

    let sep = painter.paint(DIM, "\u{2500}\u{2500}");
    let server_info = painter.paint(DIM, &format!("{}:{} ({})", server, port, result.protocol));
    let timing = painter.paint(DIM, &format!("{}ms", elapsed_ms));
    let size = painter.paint(DIM, &format!("{}B", result.bytes));
    let _ = writeln!(
        out,
        " {} {} {} {} {} {} {} {} {}",
        sep, server_info, sep, rcode_str, sep, timing, sep, size, sep
    );
}

// === TSV output ===

pub fn print_tsv(result: &QueryResult) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_tsv(&mut out, result);
}

/// Stable machine-readable format: one answer record per line,
/// `name<TAB>ttl<TAB>class<TAB>type<TAB>rdata`. TTL is raw seconds. Field
/// order and separator are a documented compatibility contract (README);
/// do not change them within a major version. rdata embedded tabs,
/// newlines, and backslashes are escaped as \t, \n, \\.
pub fn write_tsv<W: Write>(out: &mut W, result: &QueryResult) {
    for rr in &result.message.answers {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            rr.name,
            rr.ttl,
            rr.rclass,
            rr.rtype,
            escape_tsv_field(&rr.rdata.to_string())
        );
    }
}

fn escape_tsv_field(value: &str) -> String {
    if !value.contains(['\t', '\n', '\r', '\\']) {
        return value.to_string();
    }
    let mut escaped = String::with_capacity(value.len() + 4);
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            other => escaped.push(other),
        }
    }
    escaped
}

// === JSON output ===

pub fn print_json(result: &QueryResult) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_json(&mut out, result);
}

pub fn write_json<W: Write>(out: &mut W, result: &QueryResult) {
    let output = JsonOutput::from_result(result);
    match serde_json::to_string_pretty(&output) {
        Ok(json) => {
            let _ = writeln!(out, "{}", json);
        }
        Err(e) => eprint_error(&format!("JSON serialization failed: {}", e)),
    }
}

// === YAML output ===

pub fn print_yaml(result: &QueryResult) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_yaml(&mut out, result);
}

pub fn write_yaml<W: Write>(out: &mut W, result: &QueryResult) {
    let output = JsonOutput::from_result(result);
    match serde_yaml::to_string(&output) {
        Ok(yaml) => {
            let _ = write!(out, "{}", yaml);
        }
        Err(e) => eprint_error(&format!("YAML serialization failed: {}", e)),
    }
}

#[derive(serde::Serialize)]
struct JsonOutput<'a> {
    query_time_ms: u128,
    response_size: usize,
    transport: String,
    message: &'a crate::protocol::message::DnsMessage,
}

impl<'a> JsonOutput<'a> {
    fn from_result(r: &'a QueryResult) -> Self {
        JsonOutput {
            query_time_ms: r.elapsed.as_millis(),
            response_size: r.bytes,
            transport: r.protocol.to_string(),
            message: &r.message,
        }
    }
}

// === Trace output ===

pub fn print_trace(hops: &[TraceHop]) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_trace(&mut out, &painter, hops);
}

pub fn write_trace<W: Write>(out: &mut W, painter: &Painter, hops: &[TraceHop]) {
    for (i, hop) in hops.iter().enumerate() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            " {} {} {}",
            painter.paint(BOLD_WHITE, &format!("HOP {}", i + 1)),
            painter.paint(DIM, "from"),
            painter.paint(BOLD_GREEN, &hop.server),
        );

        let elapsed = hop.result.elapsed.as_millis();
        let _ = writeln!(out, " {} {}ms", painter.paint(DIM, "time:"), elapsed);

        // Show answers if present
        if !hop.result.message.answers.is_empty() {
            let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ANSWER"));
            print_record_table(out, painter, &hop.result.message.answers);
        }

        // Show authority section
        if !hop.result.message.authority.is_empty() {
            let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "AUTHORITY"));
            print_record_table(out, painter, &hop.result.message.authority);
        }

        // Show additional section (glue records)
        if !hop.result.message.additional.is_empty() {
            let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ADDITIONAL"));
            print_record_table(out, painter, &hop.result.message.additional);
        }
    }
    let _ = writeln!(out);
}

// === Benchmark output ===

pub fn print_bench(result: &BenchResult, server: &str, name: &str, qtype: &str) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_bench(&mut out, &painter, result, server, name, qtype);
}

pub fn write_bench<W: Write>(
    out: &mut W,
    painter: &Painter,
    result: &BenchResult,
    server: &str,
    name: &str,
    qtype: &str,
) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {} {} {} @{}",
        painter.paint(BOLD_WHITE, "BENCHMARK"),
        painter.paint(CYAN, name),
        painter.paint(BOLD_CYAN, qtype),
        painter.paint(GREEN, server),
    );
    let _ = writeln!(
        out,
        " queries: {} successful, {} failed",
        painter.paint(GREEN, &result.successful.to_string()),
        if result.failed > 0 {
            painter.paint(RED, &result.failed.to_string())
        } else {
            painter.paint(DIM, "0")
        },
    );

    if result.successful == 0 {
        let _ = writeln!(out, " {}", painter.paint(RED, "no successful queries"));
        return;
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {}",
        painter.paint(DIM, "  min     avg     p50     p90     p99     max")
    );
    let _ = writeln!(
        out,
        "   {:<7.1} {:<7.1} {:<7.1} {:<7.1} {:<7.1} {:<7.1}",
        result.min_ms, result.avg_ms, result.p50_ms, result.p90_ms, result.p99_ms, result.max_ms
    );

    // Histogram
    if !result.histogram.is_empty() {
        let _ = writeln!(out);
        let max_count = result.histogram.iter().map(|(_, c)| *c).max().unwrap_or(1);
        let bar_width = 30;

        for (upper, count) in &result.histogram {
            let bar_len = count
                .saturating_mul(bar_width)
                .checked_div(max_count)
                .unwrap_or(0);
            let bar: String = "\u{2588}".repeat(bar_len);
            let label = format!("{:>7.1}ms", upper);
            let _ = writeln!(
                out,
                " {} {} {}",
                painter.paint(DIM, &label),
                painter.paint(GREEN, &format!("{:<width$}", bar, width = bar_width)),
                painter.paint(DIM, &count.to_string()),
            );
        }
    }
    let _ = writeln!(out);
}

// === AXFR output ===

pub fn print_axfr(records: &[ResourceRecord]) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_axfr(&mut out, &painter, records);
}

pub fn write_axfr<W: Write>(out: &mut W, painter: &Painter, records: &[ResourceRecord]) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {} ({} records)",
        painter.paint(BOLD_WHITE, "ZONE TRANSFER"),
        records.len()
    );
    let _ = writeln!(out);

    print_record_table(out, painter, records);
    let _ = writeln!(out);
}

// === Comparison output ===

pub fn print_comparison(results: &[ComparisonResult], name: &str, qtype: &str) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_comparison(&mut out, &painter, results, name, qtype);
}

pub fn write_comparison<W: Write>(
    out: &mut W,
    painter: &Painter,
    results: &[ComparisonResult],
    name: &str,
    qtype: &str,
) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {} {} {}",
        painter.paint(BOLD_WHITE, "COMPARING"),
        painter.paint(CYAN, name),
        painter.paint(BOLD_CYAN, qtype),
    );

    // Collect answer strings for diff comparison
    let mut answer_sets: Vec<(String, Vec<String>, Option<u128>)> = Vec::new();

    for comparison in results {
        let _ = writeln!(out);
        match &comparison.result {
            Ok(r) => {
                let elapsed = r.elapsed.as_millis();
                let _ = writeln!(
                    out,
                    " {} {} ({}ms)",
                    painter.paint(BOLD_YELLOW, &format!("@{}", comparison.server)),
                    format_rcode(painter, &r.message.header.rcode),
                    elapsed,
                );

                if !r.message.answers.is_empty() {
                    print_record_table(out, painter, &r.message.answers);
                }

                let answers: Vec<String> = r
                    .message
                    .answers
                    .iter()
                    .map(|rr| format!("{} {} {}", rr.rtype, rr.name, rr.rdata))
                    .collect();
                answer_sets.push((comparison.server.clone(), answers, Some(elapsed)));
            }
            Err(e) => {
                let _ = writeln!(
                    out,
                    " {} {}",
                    painter.paint(BOLD_YELLOW, &format!("@{}", comparison.server)),
                    painter.paint(RED, &format!("error: {}", e)),
                );
                answer_sets.push((comparison.server.clone(), Vec::new(), None));
            }
        }
    }

    // Summary
    if answer_sets.len() >= 2 {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "SUMMARY"));

        // Check if all answers are identical
        let first_answers = &answer_sets[0].1;
        let all_identical = answer_sets.iter().all(|(_, a, _)| a == first_answers);
        if all_identical {
            let _ = writeln!(out, " answers: {}", painter.paint(GREEN, "identical"));
        } else {
            let _ = writeln!(out, " answers: {}", painter.paint(YELLOW, "differ"));
        }

        // Find fastest
        let mut times: Vec<(&str, u128)> = answer_sets
            .iter()
            .filter_map(|(s, _, t)| t.map(|t| (s.as_str(), t)))
            .collect();
        times.sort_by_key(|(_, t)| *t);
        if let Some((fastest, ms)) = times.first() {
            let _ = writeln!(
                out,
                " fastest: {} ({}ms)",
                painter.paint(GREEN, &format!("@{}", fastest)),
                ms,
            );
        }
    }
    let _ = writeln!(out);
}

// === Batch output ===

pub fn print_batch_result(
    name: &str,
    qtype: &crate::protocol::types::RecordType,
    result: &Result<QueryResult, crate::error::DnsError>,
) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_batch_result(&mut out, &painter, name, qtype, result);
}

pub fn write_batch_result<W: Write>(
    out: &mut W,
    painter: &Painter,
    name: &str,
    qtype: &crate::protocol::types::RecordType,
    result: &Result<QueryResult, crate::error::DnsError>,
) {
    match result {
        Ok(r) => {
            let elapsed = r.elapsed.as_millis();
            let rcode = format_rcode(painter, &r.message.header.rcode);
            let _ = write!(
                out,
                " {} {} {} {}ms ",
                painter.paint(BOLD_CYAN, &qtype.to_string()),
                name,
                rcode,
                elapsed,
            );
            let values: Vec<String> = r
                .message
                .answers
                .iter()
                .map(|rr| rr.rdata.to_string())
                .collect();
            let _ = writeln!(out, "{}", painter.paint(GREEN, &values.join(", ")));
        }
        Err(e) => {
            let _ = writeln!(
                out,
                " {} {} {}",
                painter.paint(BOLD_CYAN, &qtype.to_string()),
                name,
                painter.paint(RED, &format!("error: {}", e)),
            );
        }
    }
}

// === Propagation output ===

pub fn print_propagation(results: &[PropagationResult], name: &str, qtype: &str) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_propagation(&mut out, &painter, results, name, qtype);
}

pub fn write_propagation<W: Write>(
    out: &mut W,
    painter: &Painter,
    results: &[PropagationResult],
    name: &str,
    qtype: &str,
) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {} {} {}",
        painter.paint(BOLD_WHITE, "PROPAGATION CHECK"),
        painter.paint(CYAN, name),
        painter.paint(BOLD_CYAN, qtype),
    );

    let mut answer_groups: std::collections::HashMap<String, Vec<&str>> =
        std::collections::HashMap::new();
    let mut errors = 0usize;

    // Find max resolver name length for alignment
    let name_width = results
        .iter()
        .map(|r| r.resolver_name.len())
        .max()
        .unwrap_or(8);

    for propagation_result in results {
        let _ = writeln!(out);
        let label = format!(
            "{:<width$} ({})",
            propagation_result.resolver_name,
            propagation_result.resolver_ip,
            width = name_width
        );
        match &propagation_result.result {
            Ok(r) => {
                let elapsed = r.elapsed.as_millis();
                let rcode_str = format_rcode(painter, &r.message.header.rcode);
                let _ = writeln!(
                    out,
                    " {} {} {}ms",
                    painter.paint(BOLD_YELLOW, &label),
                    rcode_str,
                    elapsed,
                );

                if !r.message.answers.is_empty() {
                    for rr in &r.message.answers {
                        let _ = writeln!(
                            out,
                            "   {} {}",
                            painter.paint(BOLD_CYAN, &rr.rtype.to_string()),
                            format_rdata_colored(painter, &rr.rdata),
                        );
                    }
                }

                let answer_key: String = r
                    .message
                    .answers
                    .iter()
                    .map(|rr| format!("{} {}", rr.rtype, rr.rdata))
                    .collect::<Vec<_>>()
                    .join("; ");
                answer_groups
                    .entry(answer_key)
                    .or_default()
                    .push(propagation_result.resolver_name);
            }
            Err(e) => {
                let _ = writeln!(
                    out,
                    " {} {}",
                    painter.paint(BOLD_YELLOW, &label),
                    painter.paint(RED, &format!("error: {}", e)),
                );
                errors += 1;
            }
        }
    }

    // Summary
    let _ = writeln!(out);
    let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "SUMMARY"));

    let total = results.len();
    let successful = total - errors;
    if answer_groups.len() == 1 && errors == 0 {
        let _ = writeln!(
            out,
            " {}/{} resolvers agree {} propagation complete",
            successful,
            total,
            painter.paint(GREEN, "\u{2014}"),
        );
    } else if answer_groups.len() == 1 && errors > 0 {
        let _ = writeln!(
            out,
            " {}/{} resolvers agree {} propagation complete",
            successful,
            total,
            painter.paint(GREEN, "\u{2014}"),
        );
        let _ = writeln!(
            out,
            " {} resolver(s) unreachable",
            painter.paint(RED, &errors.to_string()),
        );
    } else {
        // Find the largest group
        let max_group = answer_groups.values().map(|v| v.len()).max().unwrap_or(0);
        let _ = writeln!(
            out,
            " {}/{} resolvers agree {} {}",
            max_group,
            total,
            painter.paint(YELLOW, "\u{2014}"),
            painter.paint(YELLOW, "propagation incomplete"),
        );
        if errors > 0 {
            let _ = writeln!(
                out,
                " {} resolver(s) unreachable",
                painter.paint(RED, &errors.to_string()),
            );
        }
    }
    let _ = writeln!(out);
}

// === Shared helpers ===

fn print_record_table<W: Write>(out: &mut W, painter: &Painter, records: &[ResourceRecord]) {
    let type_width = records
        .iter()
        .map(|r| r.rtype.to_string().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let name_width = records
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let ttl_width = records
        .iter()
        .map(|r| format_ttl(r.ttl).len())
        .max()
        .unwrap_or(3)
        .max(3);

    // Header row
    let type_hdr = format!("{:<1$}", "TYPE", type_width);
    let name_hdr = format!("{:<1$}", "NAME", name_width);
    let ttl_hdr = format!("{:<1$}", "TTL", ttl_width);
    let _ = writeln!(
        out,
        " {}   {}   {}   {}",
        painter.paint(DIM, &type_hdr),
        painter.paint(DIM, &name_hdr),
        painter.paint(DIM, &ttl_hdr),
        painter.paint(DIM, "VALUE"),
    );

    for rr in records {
        let type_pad = format!("{:<1$}", rr.rtype, type_width);
        let name_pad = format!("{:<1$}", rr.name, name_width);
        let ttl_pad = format!("{:<1$}", format_ttl(rr.ttl), ttl_width);
        let type_str = painter.paint(BOLD_CYAN, &type_pad);
        let name_str = name_pad;
        let ttl_str = painter.paint(DIM, &ttl_pad);
        let value_str = format_rdata_colored(painter, &rr.rdata);

        let _ = writeln!(
            out,
            " {}   {}   {}   {}",
            type_str, name_str, ttl_str, value_str,
        );
    }
}

fn format_rdata_colored(painter: &Painter, rdata: &RData) -> String {
    let text = rdata.to_string();
    if matches!(rdata, RData::A(_) | RData::AAAA(_)) {
        painter.paint(GREEN, &text)
    } else if rdata.is_name() {
        painter.paint(YELLOW, &text)
    } else if rdata.is_dnssec() {
        painter.paint(BLUE, &text)
    } else if rdata.is_text() {
        painter.paint(MAGENTA, &text)
    } else {
        text
    }
}

fn format_rcode(painter: &Painter, rcode: &Rcode) -> String {
    let text = rcode.to_string();
    match rcode {
        Rcode::NoError => painter.paint(GREEN, &text),
        Rcode::NxDomain | Rcode::ServFail => painter.paint(BOLD_RED, &text),
        _ => painter.paint(RED, &text),
    }
}

pub fn format_ttl(seconds: u32) -> String {
    if seconds == 0 {
        return "0s".to_string();
    }

    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 {
        parts.push(format!("{}s", secs));
    }

    parts.truncate(2);
    parts.join(" ")
}

pub fn eprint_error(msg: &str) {
    if io::stderr().is_terminal() {
        eprintln!("{}error:{} {}", RED, RESET, msg);
    } else {
        eprintln!("error: {}", msg);
    }
}
