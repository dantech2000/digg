# digg

A modern DNS lookup CLI tool written in Rust. Like `dig`, but with built-in support for DNS-over-TLS, DNS-over-HTTPS, DNSSEC, tracing, benchmarking, and more.

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## Changed in v0.6.0

> [!IMPORTANT]
> `+validate` is stricter in this release. Some answers that reported `SECURE` before now report `INSECURE` or `BOGUS`. The old result was wrong in each case.

**Changed**

- **`+validate` follows the answer from the name you asked for.** Earlier versions validated only the last RRset in the answer and ignored any CNAME in front of it. Now every CNAME in the chain must be signed, and every zone that signed a step is validated to the root. A name whose CNAME points into an unsigned zone (a CDN, for example) now reports `INSECURE` where it could report `SECURE`.
- **`+validate` checks who signed.** A signature counts only if it comes from the zone that holds the record. Anything else is `BOGUS` (exit code `2`).
- **Missing signatures are `BOGUS`, not `INSECURE`.** An unsigned answer is `INSECURE` only when a signed parent zone proves that the delegation is unsigned. Earlier versions reported `INSECURE` for any answer without signatures, so an attacker could hide a forgery by deleting them. A resolver that strips DNSSEC records now makes every signed name `BOGUS`; point `digg` at one that returns them (`@1.1.1.1`, `@8.8.8.8`, `@9.9.9.9`).
- **Every DS record must be signed by the parent zone.** Earlier versions accepted a DS with no signature as the link between a zone and its parent, so a forged key and a matching forged DS could validate as `SECURE`. Such a chain is now `BOGUS`.
- **Zones signed only with an algorithm `digg` does not implement are `INSECURE`, not `BOGUS`.** `digg` verifies RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384, and Ed25519 (algorithms 8, 10, 13, 14, 15), with RSA keys from 1024 bits. A zone on RSA/SHA-1 or Ed448, or with RSA keys under 1024 bits, is treated as unsigned, as RFC 4035 requires, and the report says why.
- **RSA/SHA-512 zones with 1024-bit keys validate.** Earlier versions rejected RSA/SHA-512 signatures from keys under 2048 bits and reported such zones `BOGUS`. This affected several TLDs and many `.edu`, `.fi` and `.nl` zones.
- **A filtered answer says so.** When the resolver reports that it replaced the answer (extended DNS error 15 to 18, as Quad9 does for blocked names), `+validate` reports `BOGUS` with that reason. Extended DNS errors also appear in `+json` and `+yaml` output.
- **`+validate` warns when it cannot run.** `+json`, `+yaml` and `+tsv` have no validation report; combined with `+validate` they now print a warning on stderr.
- **An unusable reply is an error, not a verdict.** If the resolver keeps returning a truncated reply or one without EDNS for a record `+validate` needs, `digg` asks again and then stops with an error that names the record. It no longer reads an empty reply as missing keys.
- **`+validate` keeps to the transport you chose.** With `+dot` or `+doh`, the lookups `+validate` makes for keys and proofs now go over that transport too. Earlier versions sent them as plain DNS to the server on port 53.
- **`SERVFAIL` is reported as a resolver failure.** It shows `INSECURE (resolver answered SERVFAIL; ...)`. Use `+cd` to get the data a validating resolver refused.
- **Negative answers are checked in full.** An `NXDOMAIN` is `SECURE` only if the proof also shows that no wildcard would have answered; a `NODATA` served from a wildcard must show that the wildcard lacks the type. In zones that use NSEC3 opt-out (`com`, `net` and many other TLDs), a name with no DS cannot be proven absent, so `NXDOMAIN` for it now reports `INSECURE` where it reported `SECURE`.
- **Wildcard answers need their proof.** An answer synthesized from a wildcard is `SECURE` only with the `NSEC` / `NSEC3` proof that the name itself does not exist. Without it the answer is `BOGUS`.

**Added**

- **DNAME.** `DNAME` records are decoded and can be queried by name. `+validate` validates a DNAME redirection: the DNAME must be signed, and the unsigned CNAME that comes with it must be the one the DNAME produces.

## Changed in v0.5.0

> [!IMPORTANT]
> One behavior difference from v0.4.0 that existing `+validate` users will notice. See [CHANGELOG.md](CHANGELOG.md) for the full history.

**Changed**

- **`+validate` now validates negative answers.** An `NXDOMAIN` or `NODATA` response is checked against its `NSEC` / `NSEC3` denial-of-existence proof. Earlier versions could only report `INSECURE (no answer to validate)` for these; now they report `SECURE` when the denial is proven, or `BOGUS` (exit code `2`) when it fails. Scripts that keyed off the old `INSECURE` string for negative answers should be updated.

**Added**

- **`+cd`** — set the DNSSEC checking-disabled bit so a validating resolver returns bogus data for `+validate` to diagnose, instead of `SERVFAIL`.

**Fixed**

- Malformed `NSEC` / `NSEC3` type bitmaps (oversized per-window blocks) are now parsed defensively, instead of producing wrapped record-type numbers in release builds.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, testing conventions, and fuzzing (`cargo +nightly fuzz run`).

## Shell completions

Completion scripts for bash, zsh, and fish live in [`completions/`](completions/)
and are bundled with release tarballs.

```sh
# bash (add to ~/.bashrc)
source /path/to/completions/digg.bash

# zsh (any directory on $fpath)
cp completions/_digg ~/.zsh/completions/_digg

# fish
cp completions/digg.fish ~/.config/fish/completions/
```

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
digg example.com +tsv                   # Tab-separated, parse-stable output

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

## Machine-readable output (`+tsv`)

`+tsv` emits one answer record per line with tab-separated fields:

```
name<TAB>ttl<TAB>class<TAB>type<TAB>rdata
```

```sh
$ digg example.com MX +tsv
example.com.	3600	IN	MX	10 mail.example.com.

$ digg example.com +tsv | awk -F'\t' '{print $5}'
93.184.216.34
```

**Stability contract:** the field order, tab separator, and raw-seconds TTL
will not change within a major version. TTLs are numeric (not humanized),
output contains no headers, colors, or footer regardless of terminal, and
tabs/newlines/backslashes inside rdata are escaped as `\t`, `\n`, `\\` so a
line always has exactly five fields. In batch mode (`-f`), answers go to
stdout and per-query failures to stderr, so pipelines see clean data.

## Options Reference

| Option         | Description                              |
|----------------|------------------------------------------|
| `+short`       | Terse output (one value per line)        |
| `+json`        | JSON output                              |
| `+yaml`        | YAML output                              |
| `+tsv`         | Tab-separated output (parse-stable; see above) |
| `+qr`          | Print the outgoing query before sending  |
| `+nostats`     | Hide the server/rcode/time/size footer   |
| `+color`       | Force color output                       |
| `+nocolor`     | Disable color output                     |
| `+tcp`         | Force TCP                                |
| `+timeout=N`   | Per-try timeout in seconds (default: 5)  |
| `+retry=N`     | UDP retries after timeout (default: 2)   |
| `+dot`         | DNS-over-TLS                             |
| `+doh[=NAME]`  | DNS-over-HTTPS (cloudflare, google, quad9, opendns, adguard, wikimedia, or a URL) |
| `+dnssec`      | Request DNSSEC records                   |
| `+validate`    | Validate the DNSSEC chain locally (incl. CNAME/DNAME chains, wildcards, NSEC/NSEC3 negative answers) |
| `+cd`          | Checking disabled (fetch DNSSEC-bogus data) |
| `+subnet=IP[/N]` | EDNS Client Subnet (RFC 7871); `+subnet=0` opts out |
| `+nsid`        | Request the server identifier (RFC 5001) |
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
| `-c class`     | Query class: IN, CH, HS, ANY (default: IN) |
| `-f file`      | Batch mode (use `-` for stdin)           |

## Supported Record Types

A, AAAA, NS, MX, CNAME, DNAME, TXT, SOA, PTR, SRV, CAA, HTTPS, SVCB, DS, RRSIG, DNSKEY, NSEC, NSEC3, NSEC3PARAM, OPT, AXFR, ANY — plus any numeric type via RFC 3597 `TYPE<N>` syntax (e.g. `digg example.com TYPE64512`)

## License

No license specified yet.
