use crate::error::DnsError;
use crate::output::ColorMode;
use crate::protocol::types::{RecordClass, RecordType};

pub fn load_config_file() -> Vec<String> {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let path = format!("{}/.diggrc", home);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    contents
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

#[derive(Debug)]
pub struct Options {
    pub servers: Vec<String>,
    pub name: String,
    pub qtype: RecordType,
    pub qclass: RecordClass,
    pub port: u16,
    pub short: bool,
    pub color: ColorMode,
    pub tcp: Option<bool>,
    pub recurse: bool,
    pub show_authority: bool,
    pub show_additional: bool,
    pub reverse: Option<String>,
    // New features
    pub timeout: u64,
    pub trace: bool,
    pub json: bool,
    pub yaml: bool,
    pub tsv: bool,
    pub compat: bool,
    pub bench: Option<usize>,
    pub batch_file: Option<String>,
    pub dnssec: bool,
    pub edns: bool,
    pub doh: Option<String>,
    pub dot: bool,
    pub axfr: bool,
    pub propagation: bool,
    pub watch: Option<u64>,
    pub subnet: Option<(std::net::IpAddr, u8)>,
    pub nsid: bool,
    pub retry: u32,
    pub qr: bool,
    pub stats: bool,
    pub queries: Vec<(RecordType, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            servers: Vec::new(),
            name: ".".to_string(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
            port: 53,
            short: false,
            color: ColorMode::Auto,
            tcp: None,
            recurse: true,
            show_authority: true,
            show_additional: true,
            reverse: None,
            timeout: 5,
            trace: false,
            json: false,
            yaml: false,
            tsv: false,
            compat: false,
            bench: None,
            batch_file: None,
            dnssec: false,
            edns: true,
            doh: None,
            dot: false,
            axfr: false,
            propagation: false,
            watch: None,
            subnet: None,
            nsid: false,
            retry: 2,
            qr: false,
            stats: true,
            queries: Vec::new(),
        }
    }
}

impl Options {
    pub fn server(&self) -> Option<&str> {
        self.servers.first().map(|s| s.as_str())
    }
}

pub fn parse_args(args: &[String]) -> Result<Options, DnsError> {
    let mut opts = Options::default();
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        if arg == "--help" || arg == "-h" {
            crate::output::set_color_mode(opts.color);
            print_usage();
            std::process::exit(0);
        }

        if arg == "--version" || arg == "-V" {
            println!("digg {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }

        if arg == "-x" {
            i += 1;
            if i >= args.len() {
                return Err(DnsError::Usage("-x requires an address argument".into()));
            }
            opts.reverse = Some(args[i].clone());
            i += 1;
            continue;
        }

        if arg == "-p" {
            i += 1;
            if i >= args.len() {
                return Err(DnsError::Usage("-p requires a port argument".into()));
            }
            opts.port = args[i]
                .parse()
                .map_err(|_| DnsError::Usage(format!("invalid port: {}", args[i])))?;
            i += 1;
            continue;
        }

        if arg == "-c" {
            i += 1;
            if i >= args.len() {
                return Err(DnsError::Usage("-c requires a class argument".into()));
            }
            opts.qclass = RecordClass::parse_name(&args[i]).ok_or_else(|| {
                DnsError::Usage(format!(
                    "invalid class: {} (expected IN, CH, HS, ANY, or CLASS<N>)",
                    args[i]
                ))
            })?;
            i += 1;
            continue;
        }

        if arg == "-f" {
            i += 1;
            if i >= args.len() {
                return Err(DnsError::Usage("-f requires a filename argument".into()));
            }
            opts.batch_file = Some(args[i].clone());
            i += 1;
            continue;
        }

        if let Some(server) = arg.strip_prefix('@') {
            opts.servers.push(server.to_string());
            i += 1;
            continue;
        }

        if arg.starts_with('+') {
            parse_plus_option(&mut opts, arg)?;
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            return Err(DnsError::Usage(format!("unknown option: {}", arg)));
        }

        positionals.push(arg.clone());
        i += 1;
    }

    // Handle reverse lookup
    if let Some(ref addr) = opts.reverse {
        opts.name = reverse_name(addr)?;
        opts.qtype = RecordType::PTR;
        opts.queries.push((opts.qtype, opts.name.clone()));
        return Ok(opts);
    }

    opts.queries = resolve_queries_from_positionals(&positionals)?;

    // If no queries found, use defaults
    if opts.queries.is_empty() {
        opts.queries.push((opts.qtype, opts.name.clone()));
    }

    // Set primary name/qtype from first query for backward compat
    if let Some((qtype, name)) = opts.queries.first() {
        opts.qtype = *qtype;
        opts.name = name.clone();
    }

    // Detect AXFR
    if opts.qtype == RecordType::AXFR {
        opts.axfr = true;
    }

    if opts.subnet.is_some() && !opts.edns {
        return Err(DnsError::Usage(
            "+subnet requires EDNS; remove +noedns".into(),
        ));
    }

    if opts.nsid && !opts.edns {
        return Err(DnsError::Usage(
            "+nsid requires EDNS; remove +noedns".into(),
        ));
    }

    Ok(opts)
}

// Support both: "name type" and "type1 name1 type2 name2"
fn resolve_queries_from_positionals(
    positionals: &[String],
) -> Result<Vec<(RecordType, String)>, DnsError> {
    let mut has_explicit_type = false;
    let mut pending_type: Option<RecordType> = None;
    let mut names_found = Vec::new();
    let mut types_found = Vec::new();
    let mut queries: Vec<(RecordType, String)> = Vec::new();

    for pos in positionals {
        if let Some(rtype) = RecordType::parse_name(pos) {
            has_explicit_type = true;
            if let Some(pending_type) = pending_type.take() {
                // Two types in a row: the first one gets paired with whatever name comes next
                types_found.push(pending_type);
            }
            pending_type = Some(rtype);
        } else if is_numeric_type_syntax(pos) {
            // Looks like RFC 3597 TYPE<N> but didn't parse: the number is out
            // of range. Erroring beats silently querying it as a hostname.
            return Err(DnsError::Usage(format!(
                "invalid record type: {} (TYPE value must be 0-65535)",
                pos
            )));
        } else if let Some(pending_type) = pending_type.take() {
            // Type followed by name -> pair them
            queries.push((pending_type, pos.clone()));
        } else {
            names_found.push(pos.clone());
        }
    }

    // Handle remaining pending type
    if let Some(pending_type) = pending_type {
        if !names_found.is_empty() {
            // Pair with first unpaired name
            let name = names_found.remove(0);
            queries.push((pending_type, name));
        } else {
            // Type alone: query root or the default name
            types_found.push(pending_type);
        }
    }

    // Handle remaining unpaired names
    for name in &names_found {
        // Auto-reverse: if it looks like an IP and no explicit type was set
        if !has_explicit_type
            && (name.parse::<std::net::Ipv4Addr>().is_ok()
                || name.parse::<std::net::Ipv6Addr>().is_ok())
        {
            let rev = reverse_name(name)?;
            queries.push((RecordType::PTR, rev));
        } else {
            queries.push((RecordType::A, name.clone()));
        }
    }

    // Handle remaining unpaired types (apply to first name or root)
    for rtype in &types_found {
        if let Some(first_query) = queries.first() {
            let name = first_query.1.clone();
            queries.push((*rtype, name));
        } else {
            queries.push((*rtype, ".".to_string()));
        }
    }

    Ok(queries)
}

fn parse_plus_option(opts: &mut Options, arg: &str) -> Result<(), DnsError> {
    match arg {
        "+short" => opts.short = true,
        "+color" => opts.color = ColorMode::Always,
        "+nocolor" => opts.color = ColorMode::Never,
        "+tcp" => opts.tcp = Some(true),
        "+notcp" => opts.tcp = Some(false),
        "+recurse" => opts.recurse = true,
        "+norecurse" => opts.recurse = false,
        "+authority" => opts.show_authority = true,
        "+noauthority" => opts.show_authority = false,
        "+additional" => opts.show_additional = true,
        "+noadditional" => opts.show_additional = false,
        "+trace" => opts.trace = true,
        "+dnssec" => opts.dnssec = true,
        "+json" => opts.json = true,
        "+yaml" => opts.yaml = true,
        "+tsv" => opts.tsv = true,
        "+compat" => opts.compat = true,
        "+dot" => opts.dot = true,
        "+edns" => opts.edns = true,
        "+noedns" => opts.edns = false,
        "+bench" => opts.bench = Some(100),
        "+propagation" | "+prop" => opts.propagation = true,
        "+nsid" => opts.nsid = true,
        "+qr" => opts.qr = true,
        "+noqr" => opts.qr = false,
        "+stats" => opts.stats = true,
        "+nostats" => opts.stats = false,
        "+watch" => opts.watch = Some(2),
        "+doh" => opts.doh = Some(String::new()),
        s if s.starts_with("+timeout=") => {
            let timeout_str = &s[9..];
            opts.timeout = timeout_str
                .parse::<u64>()
                .map_err(|_| DnsError::Usage(format!("invalid timeout: {}", timeout_str)))?;
            if opts.timeout == 0 {
                return Err(DnsError::Usage("timeout must be > 0".into()));
            }
        }
        s if s.starts_with("+bench=") => {
            let bench_str = &s[7..];
            let n = bench_str
                .parse::<usize>()
                .map_err(|_| DnsError::Usage(format!("invalid bench count: {}", bench_str)))?;
            if n == 0 {
                return Err(DnsError::Usage("bench count must be > 0".into()));
            }
            opts.bench = Some(n);
        }
        s if s.starts_with("+watch=") => {
            let watch_str = &s[7..];
            let n = watch_str
                .parse::<u64>()
                .map_err(|_| DnsError::Usage(format!("invalid watch interval: {}", watch_str)))?;
            if n == 0 {
                return Err(DnsError::Usage("watch interval must be > 0".into()));
            }
            opts.watch = Some(n);
        }
        s if s.starts_with("+doh=") => {
            opts.doh = Some(s[5..].to_string());
        }
        s if s.starts_with("+retry=") => {
            let retry_str = &s[7..];
            opts.retry = retry_str
                .parse::<u32>()
                .map_err(|_| DnsError::Usage(format!("invalid retry count: {}", retry_str)))?;
        }
        s if s.starts_with("+subnet=") => {
            opts.subnet = Some(parse_subnet(&s[8..])?);
        }
        _ => {
            return Err(DnsError::Usage(format!("unknown option: {}", arg)));
        }
    }
    Ok(())
}

/// Parse `+subnet=` values: an IP with optional /prefix (defaults: /24 for
/// IPv4, /56 for IPv6, matching dig), or `0` as shorthand for the RFC 7871
/// privacy opt-out `0.0.0.0/0`.
fn parse_subnet(spec: &str) -> Result<(std::net::IpAddr, u8), DnsError> {
    if spec == "0" {
        return Ok((std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
    }

    let (addr_str, prefix_str) = match spec.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (spec, None),
    };

    let addr: std::net::IpAddr = addr_str
        .parse()
        .map_err(|_| DnsError::Usage(format!("invalid subnet address: {}", spec)))?;

    let max_prefix: u8 = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_str {
        Some(p) => p
            .parse::<u8>()
            .ok()
            .filter(|&n| n <= max_prefix)
            .ok_or_else(|| {
                DnsError::Usage(format!(
                    "invalid subnet prefix: {} (max /{} for this family)",
                    spec, max_prefix
                ))
            })?,
        None => {
            if addr.is_ipv4() {
                24
            } else {
                56
            }
        }
    };

    Ok((addr, prefix))
}

/// True when a token is shaped like RFC 3597 `TYPE<N>` syntax (used to
/// distinguish an out-of-range type number from an ordinary hostname).
fn is_numeric_type_syntax(token: &str) -> bool {
    let upper = token.to_uppercase();
    match upper.strip_prefix("TYPE") {
        Some(num) => !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

fn reverse_name(addr: &str) -> Result<String, DnsError> {
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        let octets = v4.octets();
        return Ok(format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        ));
    }

    if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        let segments = v6.octets();
        let nibbles: Vec<String> = segments
            .iter()
            .rev()
            .flat_map(|b| {
                let lo = b & 0x0F;
                let hi = (b >> 4) & 0x0F;
                vec![format!("{:x}", lo), format!("{:x}", hi)]
            })
            .collect();
        return Ok(format!("{}.ip6.arpa", nibbles.join(".")));
    }

    Err(DnsError::Usage(format!(
        "invalid address for reverse lookup: {}",
        addr
    )))
}

pub fn print_usage() {
    let color = crate::output::stdout_color_enabled();

    let (bold, dim, cyan, green, yellow, reset) = if color {
        (
            "\x1b[1m", "\x1b[2m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "")
    };

    println!(
        "\
{bold}digg{reset} {dim}- modern DNS lookup utility{reset}

{bold}USAGE:{reset}
    {green}digg{reset} {dim}[@server]{reset} {dim}[name]{reset} {dim}[type]{reset} {dim}[options]{reset}

{bold}ARGUMENTS:{reset}
    {cyan}@server{reset}         DNS server IP {dim}(default: system resolver){reset}
                    Multiple @server args enable comparison mode
    {cyan}name{reset}            Domain name to query {dim}(default: .){reset}
                    IP addresses auto-detect as reverse PTR lookups
    {cyan}type{reset}            Record type: A AAAA NS MX CNAME TXT SOA PTR SRV CAA
                    HTTPS SVCB DS RRSIG DNSKEY NSEC NSEC3 AXFR ANY
                    TYPE{dim}N{reset} queries an arbitrary numeric type (RFC 3597)
                    {dim}(default: A, case-insensitive){reset}

{bold}OPTIONS:{reset}
    {yellow}-x{reset} addr         Reverse DNS lookup (builds PTR query automatically)
    {yellow}-p{reset} port         DNS server port {dim}(default: 53){reset}
    {yellow}-c{reset} class        Query class: IN CH HS ANY {dim}(default: IN){reset}
    {yellow}-f{reset} file         Batch mode: read queries from file ({dim}use - for stdin{reset})
    {yellow}-h{reset}, {yellow}--help{reset}      Show this help message
    {yellow}-V{reset}, {yellow}--version{reset}   Show version

{bold}QUERY OPTIONS:{reset}
    {yellow}+short{reset}          Terse output (one value per line)
    {yellow}+json{reset}           JSON output
    {yellow}+yaml{reset}           YAML output
    {yellow}+tsv{reset}            Tab-separated output: name ttl class type rdata
    {yellow}+compat{reset}         Classic dig-style output for legacy parsers
    {yellow}+tcp{reset}            Force TCP transport
    {yellow}+notcp{reset}          Force UDP transport
    {yellow}+recurse{reset}        Enable recursion {dim}(default){reset}
    {yellow}+norecurse{reset}      Disable recursion
    {yellow}+timeout=N{reset}      Per-try query timeout in seconds {dim}(default: 5){reset}
    {yellow}+retry=N{reset}        UDP retries after a timeout {dim}(default: 2, +retry=0 disables){reset}
    {yellow}+edns{reset}           Enable EDNS(0) {dim}(default){reset}
    {yellow}+noedns{reset}         Disable EDNS(0)
    {yellow}+subnet=IP[/N]{reset}  Send EDNS Client Subnet {dim}(RFC 7871; default /24, /56 v6){reset}
    {yellow}+subnet=0{reset}       Ask the resolver not to forward any subnet
    {yellow}+nsid{reset}           Request the server identifier {dim}(RFC 5001){reset}

{bold}SECURITY:{reset}
    {yellow}+dnssec{reset}         Request DNSSEC records (sets DO bit)
    {yellow}+dot{reset}            Use DNS-over-TLS (port 853)
    {yellow}+doh{reset}            Use DNS-over-HTTPS {dim}(Cloudflare){reset}
    {yellow}+doh=google{reset}     Use DNS-over-HTTPS via Google
    {yellow}+doh=URL{reset}        Use DNS-over-HTTPS via custom URL

{bold}DISPLAY:{reset}
    {yellow}+qr{reset}             Print the outgoing query before sending
    {yellow}+nostats{reset}        Hide the server/rcode/time/size footer
    {yellow}+color{reset}          Force color output
    {yellow}+nocolor{reset}        Disable color output
    {yellow}+authority{reset}      Show authority section {dim}(default){reset}
    {yellow}+noauthority{reset}    Hide authority section
    {yellow}+additional{reset}     Show additional section {dim}(default){reset}
    {yellow}+noadditional{reset}   Hide additional section

{bold}ADVANCED:{reset}
    {yellow}+trace{reset}          Trace delegation from root servers
    {yellow}+bench{reset}          Benchmark: query 100 times, show latency stats
    {yellow}+bench=N{reset}        Benchmark with N queries
    {yellow}+propagation{reset}    Check DNS propagation across 10 public resolvers
    {yellow}+prop{reset}           Alias for +propagation
    {yellow}+watch{reset}          Re-query every 2s, Ctrl+C to stop
    {yellow}+watch=N{reset}        Re-query every N seconds

{bold}CONFIG:{reset}
    ~/.diggrc           {dim}One option per line, applied before CLI args{reset}
                        {dim}Lines starting with # are ignored{reset}

{bold}EXAMPLES:{reset}
    {dim}${reset} {green}digg{reset} example.com                   {dim}# A record via system resolver{reset}
    {dim}${reset} {green}digg{reset} example.com AAAA              {dim}# AAAA record{reset}
    {dim}${reset} {green}digg{reset} @8.8.8.8 example.com MX      {dim}# MX via Google DNS{reset}
    {dim}${reset} {green}digg{reset} 8.8.8.8                       {dim}# auto-reverse PTR lookup{reset}
    {dim}${reset} {green}digg{reset} example.com +short             {dim}# terse output{reset}
    {dim}${reset} {green}digg{reset} example.com +json              {dim}# JSON output{reset}
    {dim}${reset} {green}digg{reset} example.com +dnssec            {dim}# show DNSSEC records{reset}
    {dim}${reset} {green}digg{reset} example.com +trace             {dim}# trace delegation chain{reset}
    {dim}${reset} {green}digg{reset} example.com +dot               {dim}# DNS-over-TLS{reset}
    {dim}${reset} {green}digg{reset} example.com +doh               {dim}# DNS-over-HTTPS{reset}
    {dim}${reset} {green}digg{reset} example.com +doh=google        {dim}# DoH via Google{reset}
    {dim}${reset} {green}digg{reset} example.com @8.8.8.8 @1.1.1.1 {dim}# compare servers{reset}
    {dim}${reset} {green}digg{reset} example.com +bench=50          {dim}# latency benchmark{reset}
    {dim}${reset} {green}digg{reset} A example.com AAAA example.com {dim}# multiple queries{reset}
    {dim}${reset} {green}digg{reset} -f domains.txt                 {dim}# batch from file{reset}
    {dim}${reset} echo \"example.com\" | {green}digg{reset} -f -    {dim}# batch from stdin{reset}
    {dim}${reset} {green}digg{reset} AXFR example.com @ns1.example.com {dim}# zone transfer{reset}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::ColorMode;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn parse(list: &[&str]) -> Options {
        parse_args(&args(list)).expect("expected successful parse")
    }

    fn parse_err(list: &[&str]) -> String {
        match parse_args(&args(list)) {
            Err(DnsError::Usage(msg)) => msg,
            Err(other) => panic!("expected usage error, got {:?}", other),
            Ok(_) => panic!("expected parse to fail"),
        }
    }

    // === Positional query resolution ===

    #[test]
    fn no_positionals_defaults_to_root_a_query() {
        let opts = parse(&[]);
        assert_eq!(opts.queries, vec![(RecordType::A, ".".to_string())]);
    }

    #[test]
    fn bare_name_defaults_to_a_query() {
        let opts = parse(&["example.com"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::A, "example.com".to_string())]
        );
        assert_eq!(opts.name, "example.com");
        assert_eq!(opts.qtype, RecordType::A);
    }

    #[test]
    fn name_then_type_pairs() {
        let opts = parse(&["example.com", "AAAA"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::AAAA, "example.com".to_string())]
        );
    }

    #[test]
    fn type_then_name_pairs() {
        let opts = parse(&["AAAA", "example.com"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::AAAA, "example.com".to_string())]
        );
    }

    #[test]
    fn record_type_is_case_insensitive() {
        let opts = parse(&["example.com", "mx"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::MX, "example.com".to_string())]
        );
    }

    #[test]
    fn multi_query_type_name_pairs_resolve_in_order() {
        let opts = parse(&["A", "example.com", "AAAA", "example.org"]);
        assert_eq!(
            opts.queries,
            vec![
                (RecordType::A, "example.com".to_string()),
                (RecordType::AAAA, "example.org".to_string()),
            ]
        );
    }

    #[test]
    fn two_types_in_a_row_apply_to_the_next_name() {
        // First type is deferred, second pairs with the name, deferred type
        // then reuses the first query's name.
        let opts = parse(&["A", "AAAA", "example.com"]);
        assert_eq!(
            opts.queries,
            vec![
                (RecordType::AAAA, "example.com".to_string()),
                (RecordType::A, "example.com".to_string()),
            ]
        );
    }

    #[test]
    fn type_alone_queries_root() {
        let opts = parse(&["NS"]);
        assert_eq!(opts.queries, vec![(RecordType::NS, ".".to_string())]);
    }

    #[test]
    fn bare_ipv4_becomes_ptr_query() {
        let opts = parse(&["192.0.2.1"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::PTR, "1.2.0.192.in-addr.arpa".to_string())]
        );
    }

    #[test]
    fn bare_ipv6_becomes_ptr_query() {
        let opts = parse(&["2001:db8::567:89ab"]);
        assert_eq!(
            opts.queries,
            vec![(
                RecordType::PTR,
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
                    .to_string()
            )]
        );
    }

    #[test]
    fn explicit_type_disables_ip_auto_reverse() {
        // "8.8.8.8 A" means query the literal name, not a PTR lookup.
        let opts = parse(&["8.8.8.8", "A"]);
        assert_eq!(opts.queries, vec![(RecordType::A, "8.8.8.8".to_string())]);
    }

    #[test]
    fn multiple_bare_names_each_get_a_query() {
        let opts = parse(&["example.com", "example.org"]);
        assert_eq!(
            opts.queries,
            vec![
                (RecordType::A, "example.com".to_string()),
                (RecordType::A, "example.org".to_string()),
            ]
        );
    }

    #[test]
    fn axfr_type_sets_axfr_mode() {
        let opts = parse(&["AXFR", "example.com"]);
        assert!(opts.axfr);
        assert_eq!(opts.qtype, RecordType::AXFR);
    }

    // === Server and flag arguments ===

    #[test]
    fn at_servers_accumulate_in_order() {
        let opts = parse(&["@8.8.8.8", "example.com", "@1.1.1.1"]);
        assert_eq!(opts.servers, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(opts.server(), Some("8.8.8.8"));
    }

    #[test]
    fn port_flag_parses() {
        let opts = parse(&["-p", "5353", "example.com"]);
        assert_eq!(opts.port, 5353);
    }

    #[test]
    fn port_flag_rejects_non_numeric_and_out_of_range() {
        assert!(parse_err(&["-p", "abc"]).contains("invalid port"));
        assert!(parse_err(&["-p", "99999"]).contains("invalid port"));
        assert!(parse_err(&["-p"]).contains("requires a port"));
    }

    #[test]
    fn batch_flag_requires_filename() {
        let opts = parse(&["-f", "domains.txt"]);
        assert_eq!(opts.batch_file.as_deref(), Some("domains.txt"));
        assert!(parse_err(&["-f"]).contains("requires a filename"));
    }

    #[test]
    fn reverse_flag_builds_ptr_query() {
        let opts = parse(&["-x", "192.0.2.1"]);
        assert_eq!(opts.qtype, RecordType::PTR);
        assert_eq!(opts.name, "1.2.0.192.in-addr.arpa");
        assert_eq!(
            opts.queries,
            vec![(RecordType::PTR, "1.2.0.192.in-addr.arpa".to_string())]
        );
        assert!(parse_err(&["-x"]).contains("requires an address"));
        assert!(parse_err(&["-x", "not-an-ip"]).contains("invalid address"));
    }

    #[test]
    fn unknown_dash_option_is_a_usage_error() {
        assert!(parse_err(&["-z"]).contains("unknown option"));
    }

    #[test]
    fn unknown_plus_option_is_a_usage_error() {
        assert!(parse_err(&["+bogus"]).contains("unknown option"));
    }

    // === Plus options ===

    #[test]
    fn paired_toggles_last_one_wins() {
        assert_eq!(parse(&["+tcp", "+notcp"]).tcp, Some(false));
        assert_eq!(parse(&["+notcp", "+tcp"]).tcp, Some(true));
        assert!(!parse(&["+recurse", "+norecurse"]).recurse);
        assert!(!parse(&["+authority", "+noauthority"]).show_authority);
        assert!(!parse(&["+additional", "+noadditional"]).show_additional);
        assert!(!parse(&["+edns", "+noedns"]).edns);
        assert!(matches!(
            parse(&["+color", "+nocolor"]).color,
            ColorMode::Never
        ));
    }

    #[test]
    fn simple_flags_set_their_options() {
        assert!(parse(&["+short"]).short);
        assert!(parse(&["+trace"]).trace);
        assert!(parse(&["+dnssec"]).dnssec);
        assert!(parse(&["+json"]).json);
        assert!(parse(&["+yaml"]).yaml);
        assert!(parse(&["+dot"]).dot);
        assert!(parse(&["+propagation"]).propagation);
        assert!(parse(&["+prop"]).propagation);
    }

    #[test]
    fn timeout_parses_and_rejects_zero_or_garbage() {
        assert_eq!(parse(&["+timeout=30"]).timeout, 30);
        assert!(parse_err(&["+timeout=0"]).contains("timeout must be > 0"));
        assert!(parse_err(&["+timeout=abc"]).contains("invalid timeout"));
        assert!(parse_err(&["+timeout="]).contains("invalid timeout"));
    }

    #[test]
    fn bench_defaults_to_100_and_rejects_zero_or_garbage() {
        assert_eq!(parse(&["+bench"]).bench, Some(100));
        assert_eq!(parse(&["+bench=50"]).bench, Some(50));
        assert!(parse_err(&["+bench=0"]).contains("bench count must be > 0"));
        assert!(parse_err(&["+bench=abc"]).contains("invalid bench count"));
    }

    #[test]
    fn watch_defaults_to_2s_and_rejects_zero_or_garbage() {
        assert_eq!(parse(&["+watch"]).watch, Some(2));
        assert_eq!(parse(&["+watch=10"]).watch, Some(10));
        assert!(parse_err(&["+watch=0"]).contains("watch interval must be > 0"));
        assert!(parse_err(&["+watch=abc"]).contains("invalid watch interval"));
    }

    #[test]
    fn doh_variants_parse() {
        assert_eq!(parse(&["+doh"]).doh.as_deref(), Some(""));
        assert_eq!(parse(&["+doh=google"]).doh.as_deref(), Some("google"));
        assert_eq!(
            parse(&["+doh=https://example.net/dns-query"])
                .doh
                .as_deref(),
            Some("https://example.net/dns-query")
        );
    }

    // === reverse_name ===

    #[test]
    fn reverse_name_ipv4_reverses_octets() {
        assert_eq!(reverse_name("192.0.2.1").unwrap(), "1.2.0.192.in-addr.arpa");
        assert_eq!(reverse_name("8.8.8.8").unwrap(), "8.8.8.8.in-addr.arpa");
    }

    #[test]
    fn reverse_name_ipv6_expands_nibbles_like_dig() {
        // Known-good value cross-checked against `dig -x 2001:db8::567:89ab`.
        assert_eq!(
            reverse_name("2001:db8::567:89ab").unwrap(),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            reverse_name("::1").unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn reverse_name_rejects_invalid_input() {
        assert!(reverse_name("example.com").is_err());
        assert!(reverse_name("").is_err());
        assert!(reverse_name("256.1.1.1").is_err());
    }

    // === RFC 3597 TYPE<N> syntax ===

    #[test]
    fn type_n_positional_queries_arbitrary_type() {
        let opts = parse(&["example.com", "TYPE64512"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::Unknown(64512), "example.com".to_string())]
        );
    }

    #[test]
    fn type_n_works_in_multi_query_mode() {
        let opts = parse(&["TYPE64512", "example.com", "A", "example.org"]);
        assert_eq!(
            opts.queries,
            vec![
                (RecordType::Unknown(64512), "example.com".to_string()),
                (RecordType::A, "example.org".to_string()),
            ]
        );
    }

    #[test]
    fn type_n_out_of_range_is_a_usage_error_not_a_hostname() {
        assert!(parse_err(&["example.com", "TYPE70000"]).contains("invalid record type"));
        assert!(parse_err(&["TYPE65536"]).contains("invalid record type"));
    }

    #[test]
    fn hostnames_starting_with_type_are_still_names() {
        let opts = parse(&["typefoo.example.com"]);
        assert_eq!(
            opts.queries,
            vec![(RecordType::A, "typefoo.example.com".to_string())]
        );
        // Bare "TYPE" with no digits is a hostname, not type syntax.
        let opts = parse(&["type"]);
        assert_eq!(opts.queries, vec![(RecordType::A, "type".to_string())]);
    }

    // === Query class (-c) ===

    #[test]
    fn class_flag_parses_mnemonics_and_class_n() {
        assert_eq!(
            parse(&["-c", "CH", "version.bind", "TXT"]).qclass,
            RecordClass::CH
        );
        assert_eq!(parse(&["-c", "in", "example.com"]).qclass, RecordClass::IN);
        assert_eq!(
            parse(&["-c", "CLASS4", "example.com"]).qclass,
            RecordClass::HS
        );
        assert_eq!(parse(&["example.com"]).qclass, RecordClass::IN);
    }

    #[test]
    fn class_flag_rejects_unknown_and_missing_values() {
        assert!(parse_err(&["-c", "XX"]).contains("invalid class"));
        assert!(parse_err(&["-c"]).contains("requires a class"));
    }

    // === EDNS Client Subnet (+subnet) ===

    #[test]
    fn subnet_parses_with_and_without_prefix() {
        use std::net::IpAddr;
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            parse(&["e.com", "+subnet=192.0.2.1"]).subnet,
            Some((v4, 24))
        );
        assert_eq!(
            parse(&["e.com", "+subnet=192.0.2.1/16"]).subnet,
            Some((v4, 16))
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            parse(&["e.com", "+subnet=2001:db8::1"]).subnet,
            Some((v6, 56))
        );
        assert_eq!(
            parse(&["e.com", "+subnet=2001:db8::1/48"]).subnet,
            Some((v6, 48))
        );
    }

    #[test]
    fn subnet_zero_is_the_privacy_opt_out() {
        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            parse(&["e.com", "+subnet=0"]).subnet,
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        );
        assert_eq!(
            parse(&["e.com", "+subnet=0.0.0.0/0"]).subnet,
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        );
    }

    #[test]
    fn subnet_rejects_bad_addresses_and_prefixes() {
        assert!(parse_err(&["e.com", "+subnet=notanip"]).contains("invalid subnet address"));
        assert!(parse_err(&["e.com", "+subnet=1.2.3.4/33"]).contains("invalid subnet prefix"));
        assert!(parse_err(&["e.com", "+subnet=2001:db8::/129"]).contains("invalid subnet prefix"));
        assert!(parse_err(&["e.com", "+subnet="]).contains("invalid subnet address"));
    }

    #[test]
    fn subnet_conflicts_with_noedns_in_either_order() {
        assert!(
            parse_err(&["e.com", "+subnet=1.2.3.4", "+noedns"]).contains("+subnet requires EDNS")
        );
        assert!(
            parse_err(&["e.com", "+noedns", "+subnet=1.2.3.4"]).contains("+subnet requires EDNS")
        );
    }

    // === NSID (+nsid) ===

    #[test]
    fn nsid_flag_parses_and_conflicts_with_noedns() {
        assert!(parse(&["e.com", "+nsid"]).nsid);
        assert!(!parse(&["e.com"]).nsid);
        assert!(parse_err(&["e.com", "+nsid", "+noedns"]).contains("+nsid requires EDNS"));
        assert!(parse_err(&["e.com", "+noedns", "+nsid"]).contains("+nsid requires EDNS"));
    }

    // === UDP retries (+retry) ===

    #[test]
    fn retry_defaults_to_two_and_parses_explicit_values() {
        assert_eq!(parse(&["e.com"]).retry, 2);
        assert_eq!(parse(&["e.com", "+retry=0"]).retry, 0);
        assert_eq!(parse(&["e.com", "+retry=5"]).retry, 5);
        assert!(parse_err(&["e.com", "+retry=abc"]).contains("invalid retry count"));
        assert!(parse_err(&["e.com", "+retry="]).contains("invalid retry count"));
    }

    // === +qr and +stats toggles ===

    #[test]
    fn qr_and_stats_toggles_parse_with_last_wins() {
        assert!(parse(&["e.com", "+qr"]).qr);
        assert!(!parse(&["e.com", "+qr", "+noqr"]).qr);
        assert!(!parse(&["e.com"]).qr);
        assert!(parse(&["e.com"]).stats);
        assert!(!parse(&["e.com", "+nostats"]).stats);
        assert!(parse(&["e.com", "+nostats", "+stats"]).stats);
    }

    // === +tsv ===

    #[test]
    fn tsv_flag_parses() {
        assert!(parse(&["e.com", "+tsv"]).tsv);
        assert!(!parse(&["e.com"]).tsv);
    }

    #[test]
    fn compat_flag_parses() {
        assert!(parse(&["e.com", "+compat"]).compat);
        assert!(!parse(&["e.com"]).compat);
    }
}
