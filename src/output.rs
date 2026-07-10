use crate::bench::BenchResult;
use crate::compare::ComparisonResult;
use crate::propagation::PropagationResult;
use crate::protocol::record::{RData, ResourceRecord};
use crate::protocol::types::Rcode;
use crate::trace::TraceHop;
use crate::transport::QueryResult;
use std::io::{self, IsTerminal, Write};

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

struct Painter {
    color: bool,
}

impl Painter {
    fn new() -> Self {
        Painter {
            color: io::stdout().is_terminal(),
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{}{}{}", code, text, RESET)
        } else {
            text.to_string()
        }
    }
}

// === Standard output ===

pub fn print_short(result: &QueryResult) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for rr in &result.message.answers {
        let _ = writeln!(out, "{}", rr.rdata);
    }
}

pub fn print_full(
    result: &QueryResult,
    server: &str,
    port: u16,
    show_authority: bool,
    show_additional: bool,
) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Answer section
    if !result.message.answers.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ANSWER"));
        print_record_table(&mut out, &painter, &result.message.answers);
    }

    // Authority section
    if show_authority && !result.message.authority.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "AUTHORITY"));
        print_record_table(&mut out, &painter, &result.message.authority);
    }

    // Additional section
    if show_additional && !result.message.additional.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ADDITIONAL"));
        print_record_table(&mut out, &painter, &result.message.additional);
    }

    // EDNS info
    if let Some(ref edns) = result.message.edns {
        let _ = writeln!(out);
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
    let _ = writeln!(out);
    let elapsed_ms = result.elapsed.as_millis();
    let rcode = &result.message.header.rcode;
    let rcode_str = format_rcode(&painter, rcode);

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

// === JSON output ===

pub fn print_json(result: &QueryResult) {
    let output = JsonOutput::from_result(result);
    let json = serde_json::to_string_pretty(&output).expect("JSON serialization failed");
    println!("{}", json);
}

// === YAML output ===

pub fn print_yaml(result: &QueryResult) {
    let output = JsonOutput::from_result(result);
    let yaml = serde_yaml::to_string(&output).expect("YAML serialization failed");
    print!("{}", yaml);
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
            print_record_table(&mut out, &painter, &hop.result.message.answers);
        }

        // Show authority section
        if !hop.result.message.authority.is_empty() {
            let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "AUTHORITY"));
            print_record_table(&mut out, &painter, &hop.result.message.authority);
        }

        // Show additional section (glue records)
        if !hop.result.message.additional.is_empty() {
            let _ = writeln!(out, " {}", painter.paint(BOLD_WHITE, "ADDITIONAL"));
            print_record_table(&mut out, &painter, &hop.result.message.additional);
        }
    }
    let _ = writeln!(out);
}

// === Benchmark output ===

pub fn print_bench(result: &BenchResult, server: &str, name: &str, qtype: &str) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();

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
            let bar_len = if max_count > 0 {
                (*count * bar_width) / max_count
            } else {
                0
            };
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

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        " {} ({} records)",
        painter.paint(BOLD_WHITE, "ZONE TRANSFER"),
        records.len()
    );
    let _ = writeln!(out);

    print_record_table(&mut out, &painter, records);
    let _ = writeln!(out);
}

// === Comparison output ===

pub fn print_comparison(results: &[ComparisonResult], name: &str, qtype: &str) {
    let painter = Painter::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();

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
                    format_rcode(&painter, &r.message.header.rcode),
                    elapsed,
                );

                if !r.message.answers.is_empty() {
                    print_record_table(&mut out, &painter, &r.message.answers);
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

    match result {
        Ok(r) => {
            let elapsed = r.elapsed.as_millis();
            let rcode = format_rcode(&painter, &r.message.header.rcode);
            let _ = write!(
                out,
                " {} {} {} {}ms ",
                painter.paint(BOLD_CYAN, &qtype.to_string()),
                name,
                rcode,
                elapsed,
            );
            let values: Vec<String> = r.message.answers.iter().map(|rr| rr.rdata.to_string()).collect();
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
        let label = format!("{:<width$} ({})", propagation_result.resolver_name, propagation_result.resolver_ip, width = name_width);
        match &propagation_result.result {
            Ok(r) => {
                let elapsed = r.elapsed.as_millis();
                let rcode_str = format_rcode(&painter, &r.message.header.rcode);
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
                            format_rdata_colored(&painter, &rr.rdata),
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
