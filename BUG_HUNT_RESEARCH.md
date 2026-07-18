# Digg — Bug Hunt Research

Reviewer: Senior Rust maintainer pass over the full tree (`src/`, ~4,200 LOC).
Method: read every source file, ran `cargo clippy --all-targets` (clean) and
`cargo test` (all pass), wrote a throwaway repro test for the parser panic, and
exercised the built binary against live resolvers. External claims were
validated against authoritative sources (RustSec, Quad9 docs).

Status legend:
- **CONFIRMED** — reproduced locally or proven by direct code path.
- **VALIDATED** — cross-checked against an external authority.
- Severity: Critical / High / Medium / Low.

---

## C1. Unchecked slice on attacker-controlled length in NSEC3 / NSEC3PARAM → panic (remote DoS)
**Severity: Critical — CONFIRMED (repro) + VALIDATED (RUSTSEC class)**

`src/protocol/record.rs`, `parse_rdata`:

```rust
// NSEC3 (line ~616)
let salt_len = buf[offset + 4] as usize;
let salt = buf[offset + 5..offset + 5 + salt_len].to_vec();   // salt_len is a wire byte, 0..=255
...
let hash_len = buf[hash_offset] as usize;
let next_hashed = buf[hash_offset + 1..hash_offset + 1 + hash_len].to_vec();  // unchecked

// NSEC3PARAM (line ~645)
let salt_len = buf[offset + 4] as usize;
let salt = buf[offset + 5..offset + 5 + salt_len].to_vec();   // unchecked
```

The only guard is `rdlength < 6` (NSEC3) / `< 5` (NSEC3PARAM). `salt_len` and
`hash_len` are read straight from the packet and used as slice bounds without
checking them against `rdlength` **or** `buf.len()`. A malicious response whose
`salt_len` exceeds the remaining buffer makes the slice index out of range and
the process panics.

Every other rdata parser in the file validates its length fields (A, AAAA, TXT,
CAA, DS, DNSKEY, SVCB, etc.). NSEC3 and NSEC3PARAM are the two that don't.

**Reproduced locally**: a hand-crafted NSEC3 record with `salt_len = 255` and a
1-byte body panicked `ResourceRecord::decode` (verified with a
`std::panic::catch_unwind` test, since removed).

**Blast radius is worse than a single query.** The parallel modes join worker
threads with `handles.join().unwrap()` (see C2). A panic inside a
propagation/compare/batch worker re-panics the main thread and aborts the whole
program. Any one hostile/ misbehaving resolver in `+propagation` can take the
run down.

**Validation**: parser panics / OOB reads on untrusted DNS packets are a
recognized DoS vulnerability class — e.g. RUSTSEC-2018-0007 (trust-dns-proto),
and CVE-2026-24028 (OOB read parsing DNS responses). DNS clients must treat every
length byte in a response as hostile.
Sources: https://rustsec.org/advisories/RUSTSEC-2018-0007.html ,
https://rustsec.org/categories/denial-of-service.html

**Fix sketch**: after reading each length byte, bound-check before slicing, e.g.
```rust
let salt_end = offset + 5 + salt_len;
if salt_end > offset + rdlength { return Err(DnsError::Protocol("NSEC3 salt exceeds RDATA".into())); }
```
and the same for `hash_len`. Prefer `buf.get(range)` returning `Option` over
raw indexing throughout `parse_rdata`.

---

## C2. Worker panics propagate to a whole-process abort via `join().unwrap()`
**Severity: High — CONFIRMED (code path)**

`src/batch.rs:97`, `src/compare.rs:53`, `src/propagation.rs:99`:

```rust
for h in handles {
    results.push(h.join().unwrap());   // re-panics the main thread if a worker panicked
}
```

Each worker already returns a `Result<QueryResult, DnsError>`, so network errors
are handled gracefully — but a *panic* (today reachable via C1, or any future
parser bug) is not a `DnsError`; it unwinds the thread and `join().unwrap()`
turns that into a main-thread panic. The intended "one resolver failing doesn't
sink the batch" guarantee is silently broken for panics.

**Fix sketch**: treat a joined `Err` as a per-item failure —
`match h.join() { Ok(r) => results.push(r), Err(_) => results.push(/* synthesize a DnsError::Network("worker panicked") item */) }`.
The clean fix is C1 (remove the panic source); C2 is defense in depth.

---

## H1. Hostname server arguments are rejected — `@dns.google`, `@one.one.one.one` fail
**Severity: High — CONFIRMED (live)**

`src/transport.rs` (`send_udp`, `send_tcp`), `src/dot.rs`, `src/axfr.rs` all do:

```rust
let socket_addr: std::net::SocketAddr = addr.parse()...   // requires an IP literal
```

`SocketAddr::parse` does **not** resolve hostnames, so any `@name` server that
isn't a bare IP fails. Live repro:

```
$ digg @dns.google example.com
error: invalid address 'dns.google:53': invalid socket address syntax   (exit 9)
$ digg @8.8.8.8 example.com          # works
```

`dig`/`drill` accept hostnames for `@server`. This also breaks `+dot @dns.google`
and `AXFR ... @ns1.example.com` (the README example on `cli.rs:439` literally
shows `@ns1.example.com`, which cannot work today). DoH is unaffected because
`ureq` resolves the URL host itself.

**Fix sketch**: replace `str::parse::<SocketAddr>()` with
`(host, port).to_socket_addrs()` (from `std::net::ToSocketAddrs`) and take the
first address, or resolve the name first. Applies to `send_udp`, `send_tcp`,
`send_dot_query`, and `perform_axfr`.

---

## M1. UDP socket is unconnected and unfiltered — accepts responses from any source
**Severity: Medium — CONFIRMED (code path)**

`src/transport.rs:send_udp` binds, `send_to`, then `recv_from` without ever
calling `socket.connect(addr)` and without checking the responder's address:

```rust
let (size, _) = socket.recv_from(&mut resp_buf)?;   // source address discarded
```

Any datagram arriving on the ephemeral port is accepted; only the 16-bit
transaction ID is later checked (`verify_id`). For a diagnostic CLI this is
low-risk, but it's the textbook off-path/spoofing surface and is trivially
tightened.

**Fix sketch**: `socket.connect(&socket_addr)?` before `send`, then use
`recv` and rely on the kernel to drop foreign sources. (Also lets `send`/`recv`
replace `send_to`/`recv_from`.)

---

## M2. UDP receive buffer can silently truncate large datagrams (non-EDNS path)
**Severity: Medium — CONFIRMED (code path)**

`src/main.rs:52` sets `udp_size = if opts.edns { 4096 } else { 512 }`, passed to
`send_udp` which allocates `vec![0u8; udp_payload_size]`. `recv_from` silently
discards any bytes of a datagram beyond the buffer. With `+noedns`, a legitimate
> 512-byte UDP answer (some servers still send it if TC isn't set) is truncated
and then fails to parse or parses partially, rather than being retried over TCP.
A conservative buffer (e.g. 65535 for the receive side regardless of advertised
size) avoids surprises.

---

## M3. `+trace` only follows IPv4 glue / A records — breaks on IPv6-only delegations
**Severity: Medium — CONFIRMED (code path)**

`src/trace.rs:112` and `resolve_ns_address` (`:145`) collect next-hop servers
only from `RData::A`:

```rust
if let RData::A(addr) = &rr.rdata { next_servers.push(addr.to_string()); }
```

AAAA glue and AAAA-only nameservers are ignored, so a trace through an
IPv6-only delegation dead-ends. Add an `RData::AAAA` arm (and note the transport
must handle v6 literals — it already does via `format_addr`).

---

## M4. Extended DNS RCODE (upper 8 bits from OPT) is parsed but never surfaced
**Severity: Medium — CONFIRMED (code path)**

`src/protocol/edns.rs` parses `extended_rcode` from the OPT TTL field into
`EdnsInfo`, but nothing ever combines it with the 4-bit header rcode. RCODEs ≥ 16
(e.g. `BADVERS`/`BADSIG`, RFC 6891) are therefore misreported as their low
nibble. `main.rs` exit-code logic and `format_rcode` both look only at
`header.rcode`. Compose the full 12-bit value:
`full = (edns.extended_rcode as u16) << 4 | header.rcode_low`.

---

## M5. Quad9 DoH uses the non-standard `:5053` endpoint as its default
**Severity: Low/Medium — VALIDATED**

`src/doh.rs:11`:

```rust
"quad9" => "https://dns.quad9.net:5053/dns-query".to_string(),
```

Quad9's documented **primary** DoH endpoint is `https://dns.quad9.net/dns-query`
(port 443). `:5053` is a documented *alternate* (unauthenticated/no-blocklist
variant on some deployments) and is a surprising default — networks that only
allow 443 egress will see this fail. Recommend defaulting to the 443 endpoint.
Source: https://quad9.net/support/faq/ , https://docs.quad9.net (Services).

---

## L1. `partial_cmp().unwrap()` when sorting benchmark latencies
**Severity: Low — CONFIRMED (latent)**

`src/bench.rs:57`: `latencies.sort_by(|a, b| a.partial_cmp(b).unwrap())`.
Latencies derive from `Duration` and are never NaN today, so it can't fire — but
it's a landmine if the source of these f64s ever changes. Use
`sort_by(|a, b| a.total_cmp(b))` (`f64::total_cmp`, stable since 1.62) to make it
NaN-safe and drop the unwrap.

---

## L2. `serde` (de)serialization `.expect(...)` in output paths
**Severity: Low — CONFIRMED (latent)**

`src/output.rs:190,198`: `serde_json::to_string_pretty(...).expect("JSON serialization failed")`
and the YAML equivalent. Serializing our own owned types effectively never
fails, so this is cosmetic, but a `+json`/`+yaml` path that panics instead of
returning a `DnsError` is inconsistent with the rest of the codebase. Low
priority.

---

## L3. AXFR "empty response" guard is positioned so it can misfire mid-stream
**Severity: Low — CONFIRMED (code path)**

`src/axfr.rs:55`: the `if all_records.is_empty() && soa_count == 0` check runs on
every loop iteration. It's only meaningful for the *first* message; a legitimate
mid-transfer message that happens to carry zero answer records would trip the
"empty response" error. Minor, but the guard should apply only to the first read.

---

## Non-issues verified (so we don't re-flag them)
- **Compression-pointer infinite loop** (the RUSTSEC-2018-0007 bug): *handled*.
  `decode_name` tracks a `visited` set and returns a protocol error on a repeated
  pointer target (`src/protocol/name.rs:76`).
- **IPv6 reverse (`-x`) nibble ordering**: correct — live query for `2001:db8::1`
  resolved to the proper `...8.b.d.0.1.0.0.2.ip6.arpa` zone.
- **Header opcode/rcode bit packing**: correct and round-trips (covered by tests).
- **`resolve_queries_from_positionals`** two-type/one-name permutations: walked
  through the branches; produces sensible pairings.
- **CAA / TXT / SVCB / DS / DNSKEY / RRSIG length checks**: all bounded correctly.
- **`cli.rs` byte-slicing** of `+timeout=`, `+bench=`, `+doh=` prefixes: safe
  (prefixes are ASCII).

---

## Proposed fix candidates (ranked)

| # | Finding | Severity | Effort | Recommendation |
|---|---------|----------|--------|----------------|
| 1 | **C1** NSEC3/NSEC3PARAM unchecked slice panic | Critical | S | **Fix now.** Bound-check `salt_len`/`hash_len`; move `parse_rdata` to `buf.get(..)`. Add regression tests with oversized length bytes. |
| 2 | **C2** `join().unwrap()` aborts on worker panic | High | S | **Fix now**, alongside C1 — convert joined panics into per-item `DnsError` failures. |
| 3 | **H1** Hostname `@server` rejected | High | S–M | **Fix now.** Swap `SocketAddr::parse` for `ToSocketAddrs` in udp/tcp/dot/axfr. Fixes a documented example that can't run. |
| 4 | **M3** `+trace` ignores IPv6 glue | Medium | S | Fix soon — add `RData::AAAA` handling. |
| 5 | **M4** Extended RCODE not surfaced | Medium | S | Fix soon — compose 12-bit rcode for display + exit code. |
| 6 | **M1** Unconnected UDP socket | Medium | S | Fix soon — `socket.connect()` + `recv`. |
| 7 | **M2** UDP truncation on `+noedns` | Medium | S | Fix soon — enlarge receive buffer. |
| 8 | **M5** Quad9 DoH `:5053` default | Low/Med | XS | Quick win — default to the 443 endpoint. |
| 9 | **L1** bench `partial_cmp().unwrap()` | Low | XS | Quick win — `total_cmp`. |
| 10 | **L3** AXFR empty-guard placement | Low | XS | Tidy-up. |
| 11 | **L2** serde `.expect` in output | Low | XS | Optional — return `DnsError` instead. |

**Suggested first PR** (tightly scoped, all "correctness/robustness of untrusted
input"): C1 + C2 + H1, with regression tests. These are the three that are either
a security bug or a user-visible functional break, and they cluster naturally.
