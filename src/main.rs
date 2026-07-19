mod axfr;
mod batch;
mod bench;
mod cli;
mod compare;
mod doh;
mod dot;
mod error;
mod output;
mod propagation;
mod protocol;
mod resolver;
mod trace;
mod transport;
mod watch;

use error::DnsError;
use protocol::edns::EdnsOptions;
use protocol::message::DnsMessage;
use protocol::types::Rcode;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            output::eprint_error(&e.to_string());
            std::process::exit(e.exit_code());
        }
    }
}

fn run(args: &[String]) -> Result<i32, DnsError> {
    let config_args = cli::load_config_file();
    let mut all_args = config_args;
    all_args.extend_from_slice(args);
    let opts = cli::parse_args(&all_args)?;
    output::set_color_mode(opts.color);
    let timeout = Duration::from_secs(opts.timeout);

    // Build EDNS options
    let edns = if opts.edns {
        let mut edns_opts = EdnsOptions {
            dnssec_ok: opts.dnssec,
            ..EdnsOptions::default()
        };
        if let Some((addr, prefix)) = opts.subnet {
            edns_opts
                .options
                .push(protocol::edns::client_subnet_option(addr, prefix));
        }
        if opts.nsid {
            edns_opts.options.push(protocol::edns::EdnsOption {
                code: protocol::edns::OPTION_NSID,
                data: Vec::new(),
            });
        }
        Some(edns_opts)
    } else {
        None
    };

    // Resolve server
    let resolve_server = || -> Result<String, DnsError> {
        if let Some(s) = opts.server() {
            Ok(s.to_string())
        } else {
            resolver::system_nameserver()
        }
    };

    // === Mode dispatch ===

    // Batch mode
    if let Some(ref file) = opts.batch_file {
        let queries = batch::read_batch_queries(file)?;
        let server = resolve_server()?;
        let results = batch::run_batch(
            &queries,
            &server,
            opts.port,
            timeout,
            opts.tcp.unwrap_or(false),
            opts.dnssec,
        );
        for (name, qtype, result) in &results {
            output::print_batch_result(name, qtype, result);
        }
        return Ok(0);
    }

    // AXFR mode
    if opts.axfr {
        let server = resolve_server()?;
        let (_, name) = &opts.queries[0];
        let records = axfr::perform_axfr(&server, opts.port, name, timeout)?;
        output::print_axfr(&records);
        return Ok(0);
    }

    // Trace mode
    if opts.trace {
        let (qtype, name) = &opts.queries[0];
        let hops = trace::perform_trace(name, *qtype, timeout)?;
        output::print_trace(&hops);
        return Ok(0);
    }

    // Bench mode
    if let Some(count) = opts.bench {
        let server = resolve_server()?;
        let (qtype, name) = &opts.queries[0];
        let result = bench::run_benchmark(
            &server,
            opts.port,
            name,
            *qtype,
            count,
            timeout,
            opts.tcp.unwrap_or(false),
            opts.dnssec,
        );
        output::print_bench(&result, &server, name, &qtype.to_string());
        return Ok(0);
    }

    // Server comparison mode
    if opts.servers.len() > 1 {
        let (qtype, name) = &opts.queries[0];
        let results = compare::compare_servers(
            &opts.servers,
            name,
            *qtype,
            opts.port,
            timeout,
            opts.tcp.unwrap_or(false),
            opts.dnssec,
        );
        output::print_comparison(&results, name, &qtype.to_string());
        return Ok(0);
    }

    // Propagation mode
    if opts.propagation {
        let (qtype, name) = &opts.queries[0];
        let results =
            propagation::check_propagation(name, *qtype, timeout, edns.clone().unwrap_or_default());
        output::print_propagation(&results, name, &qtype.to_string());
        return Ok(0);
    }

    // Watch mode
    if let Some(interval) = opts.watch {
        let server = resolve_server()?;
        let (qtype, name) = &opts.queries[0];
        return watch::run_watch(
            &server,
            opts.port,
            name,
            *qtype,
            interval,
            timeout,
            opts.tcp.unwrap_or(false),
            opts.dnssec,
            opts.short,
        );
    }

    // Resolve DoH URL if specified
    let doh_url = opts.doh.as_ref().map(|spec| doh::resolve_doh_url(spec));

    // Standard query mode
    let server = resolve_server()?;
    let mut exit_code = 0;

    for (i, (qtype, name)) in opts.queries.iter().enumerate() {
        if i > 0 {
            println!();
        }

        let (query, query_id) = DnsMessage::build_query_with_class(
            name,
            *qtype,
            opts.qclass,
            opts.recurse,
            edns.as_ref(),
        )?;

        let result = if opts.dot {
            dot::send_dot_query(&server, &query, timeout)?
        } else if let Some(ref url) = doh_url {
            doh::send_doh_query(url, &query, timeout)?
        } else {
            let force_tcp = opts.tcp.unwrap_or(false);
            transport::send_query_with_retries(
                &server, opts.port, &query, force_tcp, timeout, opts.retry,
            )?
        };

        transport::verify_id(&result.message.header, query_id)?;

        if opts.json {
            output::print_json(&result);
        } else if opts.yaml {
            output::print_yaml(&result);
        } else if opts.short {
            output::print_short(&result);
        } else {
            output::print_full(
                &result,
                &server,
                opts.port,
                opts.show_authority,
                opts.show_additional,
            );
        }

        match result.message.header.rcode {
            Rcode::NoError => {}
            Rcode::NxDomain => exit_code = exit_code.max(1),
            _ => exit_code = exit_code.max(2),
        }
    }

    Ok(exit_code)
}
