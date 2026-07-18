use crate::error::DnsError;
use crate::output;
use crate::protocol::edns::EdnsOptions;
use crate::protocol::message::DnsMessage;
use crate::protocol::types::RecordType;
use crate::transport;
use std::io::IsTerminal;
use std::time::{Duration, Instant};

#[allow(clippy::too_many_arguments)]
pub fn run_watch(
    server: &str,
    port: u16,
    name: &str,
    qtype: RecordType,
    interval_secs: u64,
    timeout: Duration,
    force_tcp: bool,
    dnssec: bool,
    short: bool,
) -> Result<i32, DnsError> {
    let edns = EdnsOptions {
        dnssec_ok: dnssec,
        ..EdnsOptions::default()
    };
    let is_tty = std::io::stdout().is_terminal();
    let start = Instant::now();
    let mut query_num = 0u64;
    let mut changes = 0u64;
    let mut prev_answers: Option<Vec<String>> = None;

    loop {
        query_num += 1;

        // Clear screen if TTY
        if is_tty {
            print!("\x1b[2J\x1b[H");
        }

        // Header
        let uptime = format_duration(start.elapsed());
        println!(
            " WATCH {} {} @{} \u{2014} query #{}, uptime {}, {} change(s)",
            name, qtype, server, query_num, uptime, changes,
        );
        println!();

        // Execute query
        let result = (|| -> Result<transport::QueryResult, DnsError> {
            let (query, query_id) = DnsMessage::build_query(name, qtype, true, Some(&edns))?;
            let r = transport::send_query(server, port, &query, force_tcp, timeout)?;
            transport::verify_id(&r.message.header, query_id)?;
            Ok(r)
        })();

        match result {
            Ok(r) => {
                // Collect current answers for comparison
                let current_answers: Vec<String> = r
                    .message
                    .answers
                    .iter()
                    .map(|rr| format!("{} {}", rr.rtype, rr.rdata))
                    .collect();

                // Check for changes
                if let Some(ref prev) = prev_answers {
                    if *prev != current_answers {
                        changes += 1;
                        println!(" >>> CHANGE DETECTED <<<");
                        println!();
                    }
                }
                prev_answers = Some(current_answers);

                // Display results
                if short {
                    output::print_short(&r);
                } else {
                    output::print_full(&r, server, port, false, false);
                }
            }
            Err(e) => {
                eprintln!(" error: {}", e);
            }
        }

        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{}h{}m{}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m{}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}
