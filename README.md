# digg

A modern DNS lookup CLI tool written in Rust. Like `dig`, but with built-in support for DNS-over-TLS, DNS-over-HTTPS, DNSSEC, tracing, benchmarking, and more.

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## Install

```sh
cargo build --release
cp target/release/digg /usr/local/bin/
```

Once a release is published, you can install the prebuilt macOS binary with
Homebrew:

```sh
brew install --cask dantech2000/tap/digg
```

### Release maintainer setup

The tag-triggered release workflow updates the Homebrew Cask after publishing
the GitHub Release. Before cutting the first release, create a fine-grained
personal access token with **Contents: Read and write** access limited to
[`dantech2000/homebrew-tap`](https://github.com/dantech2000/homebrew-tap), and
save it as the `HOMEBREW_TAP_TOKEN` Actions secret in this repository. The tag
must use the `vX.Y.Z` form and match the version in `Cargo.toml`.

After the initial release, Release Please derives semantic version bumps from
conventional commits (`fix:` for a patch, `feat:` for a minor, and `!` for a
breaking change). It maintains a release PR that updates `Cargo.toml` and
`CHANGELOG.md`; merging that PR creates the tag and starts the release workflow.

## Usage

```
digg [@server] [name] [type] [options]
```

| Argument   | Description                                           |
|------------|-------------------------------------------------------|
| `@server`  | DNS server IP (default: system resolver)              |
| `name`     | Domain to query (default: `.`). IPs auto-reverse      |
| `type`     | Record type: A, AAAA, MX, NS, TXT, SOA, CNAME, etc. |

## Quick Examples

```sh
# Basic lookups
digg example.com                        # A record
digg example.com AAAA                   # AAAA record
digg @8.8.8.8 example.com MX           # MX via Google DNS

# Reverse DNS (auto-detected from IP)
digg 8.8.8.8                            # PTR lookup
digg -x 2001:4860:4860::8888           # Explicit reverse

# Output formats
digg example.com +short                 # Terse output
digg example.com +json                  # JSON output
digg example.com +yaml                  # YAML output

# Color control
NO_COLOR=1 digg example.com              # Disable color using the standard convention
digg example.com +nocolor                # Disable color for one invocation
digg example.com +color | less -R        # Preserve color through a compatible pipe
```

## Features

### DNS-over-TLS

Query over an encrypted TLS connection on port 853.

```sh
digg example.com +dot
digg example.com +dot @1.1.1.1
```

### DNS-over-HTTPS

Query over HTTPS. Defaults to Cloudflare, or pick a provider.

```sh
digg example.com +doh                   # Cloudflare
digg example.com +doh=google            # Google
digg example.com +doh=quad9             # Quad9
digg example.com +doh=https://my.resolver/dns-query
```

### DNSSEC

Request DNSSEC records by setting the DO (DNSSEC OK) bit.

```sh
digg example.com +dnssec               # Shows RRSIG, DNSKEY, DS, etc.
```

### Trace

Follow the delegation chain from root servers down to the authoritative nameserver, like `dig +trace`.

```sh
digg example.com +trace
```

### Server Comparison

Compare responses from multiple servers side-by-side.

```sh
digg example.com @8.8.8.8 @1.1.1.1 @9.9.9.9
```

### Benchmarking

Measure query latency with min/avg/p50/p90/p99/max stats and a histogram.

```sh
digg example.com +bench                 # 100 queries (default)
digg example.com +bench=500             # 500 queries
digg @1.1.1.1 example.com +bench=50    # Benchmark a specific server
```

### Multiple Queries

Run several queries in one invocation.

```sh
digg A example.com AAAA example.com MX example.com
```

### Batch Mode

Read queries from a file (one per line) or stdin. Lines starting with `#` are comments.

```sh
digg -f domains.txt
echo "example.com" | digg -f -
```

File format:
```
example.com
example.com AAAA
example.com MX @8.8.8.8
# this is a comment
```

### Zone Transfer (AXFR)

Attempt a full zone transfer (requires a permissive nameserver).

```sh
digg AXFR example.com @ns1.example.com
```

### DNS Propagation

Check whether a record has propagated across 10 public resolvers at once.

```sh
digg example.com +propagation
digg example.com +prop            # alias
```

### Watch Mode

Re-query on an interval and highlight changes between runs. Stop with Ctrl+C.

```sh
digg example.com +watch           # every 2s (default)
digg example.com +watch=10        # every 10s
```

### Config File

Put default options in `~/.diggrc`, one per line, applied before CLI args. Lines starting with `#` are ignored.

```
# ~/.diggrc
+short
+timeout=3
```

## Options Reference

| Option         | Description                              |
|----------------|------------------------------------------|
| `+short`       | Terse output (one value per line)        |
| `+json`        | JSON output                              |
| `+yaml`        | YAML output                              |
| `+color`       | Force color output                       |
| `+nocolor`     | Disable color output                     |
| `+tcp`         | Force TCP                                |
| `+timeout=N`   | Timeout in seconds (default: 5)          |
| `+dot`         | DNS-over-TLS                             |
| `+doh[=NAME]`  | DNS-over-HTTPS                           |
| `+dnssec`      | Request DNSSEC records                   |
| `+trace`       | Trace delegation from root               |
| `+bench[=N]`   | Benchmark with N queries (default: 100)  |
| `+noedns`      | Disable EDNS(0)                          |
| `+norecurse`   | Disable recursion                        |
| `+noauthority` | Hide authority section                   |
| `+noadditional`| Hide additional section                  |
| `+propagation` / `+prop` | Check propagation across 10 public resolvers |
| `+watch[=N]`   | Re-query every N seconds (default: 2)    |
| `-x addr`      | Explicit reverse lookup                  |
| `-p port`      | Server port (default: 53)                |
| `-f file`      | Batch mode (use `-` for stdin)           |

## Supported Record Types

A, AAAA, NS, MX, CNAME, TXT, SOA, PTR, SRV, CAA, HTTPS, SVCB, DS, RRSIG, DNSKEY, NSEC, NSEC3, NSEC3PARAM, OPT, AXFR, ANY

## License

No license specified yet.
