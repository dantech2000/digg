use crate::error::DnsError;
use crate::protocol::types::RecordType;

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
    pub port: u16,
    pub short: bool,
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
    pub bench: Option<usize>,
    pub batch_file: Option<String>,
    pub dnssec: bool,
    pub edns: bool,
    pub doh: Option<String>,
    pub dot: bool,
    pub axfr: bool,
    pub propagation: bool,
    pub watch: Option<u64>,
    pub queries: Vec<(RecordType, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            servers: Vec::new(),
            name: ".".to_string(),
            qtype: RecordType::A,
            port: 53,
            short: false,
            tcp: None,
            recurse: true,
            show_authority: true,
            show_additional: true,
            reverse: None,
            timeout: 5,
            trace: false,
            json: false,
            yaml: false,
            bench: None,
            batch_file: None,
            dnssec: false,
            edns: true,
            doh: None,
            dot: false,
            axfr: false,
            propagation: false,
            watch: None,
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

        if arg == "-f" {
            i += 1;
            if i >= args.len() {
                return Err(DnsError::Usage("-f requires a filename argument".into()));
            }
            opts.batch_file = Some(args[i].clone());
            i += 1;
            continue;
        }

        if arg.starts_with('@') {
            opts.servers.push(arg[1..].to_string());
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
        "+dot" => opts.dot = true,
        "+edns" => opts.edns = true,
        "+noedns" => opts.edns = false,
        "+bench" => opts.bench = Some(100),
        "+propagation" | "+prop" => opts.propagation = true,
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
        _ => {
            return Err(DnsError::Usage(format!("unknown option: {}", arg)));
        }
    }
    Ok(())
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
    let color = std::io::IsTerminal::is_terminal(&std::io::stdout());

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
                    {dim}(default: A, case-insensitive){reset}

{bold}OPTIONS:{reset}
    {yellow}-x{reset} addr         Reverse DNS lookup (builds PTR query automatically)
    {yellow}-p{reset} port         DNS server port {dim}(default: 53){reset}
    {yellow}-f{reset} file         Batch mode: read queries from file ({dim}use - for stdin{reset})
    {yellow}-h{reset}, {yellow}--help{reset}      Show this help message
    {yellow}-V{reset}, {yellow}--version{reset}   Show version

{bold}QUERY OPTIONS:{reset}
    {yellow}+short{reset}          Terse output (one value per line)
    {yellow}+json{reset}           JSON output
    {yellow}+yaml{reset}           YAML output
    {yellow}+tcp{reset}            Force TCP transport
    {yellow}+notcp{reset}          Force UDP transport
    {yellow}+recurse{reset}        Enable recursion {dim}(default){reset}
    {yellow}+norecurse{reset}      Disable recursion
    {yellow}+timeout=N{reset}      Query timeout in seconds {dim}(default: 5){reset}
    {yellow}+edns{reset}           Enable EDNS(0) {dim}(default){reset}
    {yellow}+noedns{reset}         Disable EDNS(0)

{bold}SECURITY:{reset}
    {yellow}+dnssec{reset}         Request DNSSEC records (sets DO bit)
    {yellow}+dot{reset}            Use DNS-over-TLS (port 853)
    {yellow}+doh{reset}            Use DNS-over-HTTPS {dim}(Cloudflare){reset}
    {yellow}+doh=google{reset}     Use DNS-over-HTTPS via Google
    {yellow}+doh=URL{reset}        Use DNS-over-HTTPS via custom URL

{bold}DISPLAY:{reset}
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
