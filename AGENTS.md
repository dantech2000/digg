# AGENTS.md

Instructions for AI coding agents working in this repo.

## What this is

`digg` is a modern DNS lookup CLI (like `dig`), written in Rust from scratch — no
`trust-dns`/`hickory-dns` crate, wire-format parsing is hand-rolled. Edition 2021,
no async runtime (blocking I/O + `std::thread::scope` for parallelism).

## Build / run / check

```sh
cargo build --release
cargo check
cargo clippy
cargo run -- example.com A
```

There is no test suite yet (`cargo test` finds nothing). Verify changes by running
`digg` against real queries (e.g. `cargo run -- example.com`, `+trace`, `+json`, etc.)
rather than assuming correctness from compilation alone.

## Architecture

- `src/cli.rs` — manual CLI arg parser, `Options` struct holds all feature flags.
- `src/main.rs` — mode dispatcher, priority order: batch > axfr > trace > bench >
  compare > propagation > watch > standard.
- `src/transport.rs` — UDP/TCP transport, IPv4/IPv6, `TransportProtocol` enum.
- `src/doh.rs` / `src/dot.rs` — DNS-over-HTTPS / DNS-over-TLS transports.
- `src/output.rs` — colored terminal output via `Painter`, plus JSON/YAML/trace/
  bench/comparison formatters.
- `src/protocol/` — wire-format DNS: `header.rs`, `question.rs`, `record.rs`,
  `message.rs`, `name.rs`, `edns.rs`, `types.rs`.
- `src/resolver.rs` — system resolver discovery.
- `src/trace.rs`, `src/axfr.rs`, `src/batch.rs`, `src/bench.rs`, `src/compare.rs`,
  `src/propagation.rs`, `src/watch.rs` — one module per major mode/feature.

## Conventions and gotchas

- IPv6 transport: `format_addr()` wraps IPv6 addresses in brackets; UDP bind uses
  `[::]:0` for IPv6 sockets.
- EDNS(0) is on by default; `+noedns` disables it. `+dnssec` sets the DO bit.
- OPT records are parsed specially in `message.rs` — extracted into
  `edns: Option<EdnsInfo>`, not left in the additional section.
- rustls requires `aws_lc_rs::default_provider().install_default()` to be called
  once before any TLS use (DoT/DoH).
- Positional arg parsing in `cli.rs` supports both `name type` and
  `type1 name1 type2 name2` interleaved patterns — be careful not to break either
  when touching arg parsing.
- Config file support via `~/.diggrc`.

## Commit / release policy

- Do **not** add the Claude Code co-authoring trailer (or any AI co-authoring
  trailer/footer) to commits, PRs, or release notes in this repo.
