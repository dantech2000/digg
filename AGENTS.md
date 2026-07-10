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

There is no test suite yet (`cargo test` finds nothing; tracked in #9). Verify
changes by running `digg` against real queries (e.g. `cargo run -- example.com`,
`+trace`, `+json`, etc.) rather than assuming correctness from compilation alone.

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

## GitHub workflow

- File an issue before starting non-trivial work; reference it in the commit
  message and PR body (`Fixes #N`). Commit/PR titles use conventional-commit
  prefixes matching the issue title (`fix:`, `feat:`, `chore:`, `docs:`,
  `refactor:`, `test:`, `ci:`).
- Labels: GitHub's defaults (`bug`, `enhancement`, `documentation`, ...) plus
  two repo-specific additions — `ci` (build/release tooling, GitHub Actions)
  and `chore` (maintenance / dev-experience work with no user-facing behavior
  change). Reuse existing labels; only add a new one if nothing fits.
- No CI is configured yet (tracked in #5), so "all good" before merging means
  a clean local `cargo build --release`, `cargo test --release`, and a
  manual smoke test of whatever code paths the change touches — see the
  commits for #1/#3 for the level of manual verification expected.
- PRs are squash-merged with the branch deleted (`gh pr merge --squash
  --delete-branch`).
- Use the `/backlog` skill (`.claude/skills/backlog/`) to run a backlog
  grooming session and turn accepted ideas into properly-structured issues.

## GitHub wiki

- Docs live at https://github.com/dantech2000/digg/wiki (git-backed, not
  built from this repo).
- Bootstrap gotcha: `digg.wiki.git` isn't clonable until a page has been
  created at least once via the web UI (Wiki tab → "Create the first
  page") — there's no API to initialize it. If `git clone
  git@github.com:dantech2000/digg.wiki.git` fails with "Repository not
  found" on a brand-new wiki, that's why.

## Working in this workspace (Conductor)

- This directory is a git worktree; `main` may already be checked out in a
  sibling worktree, so `git checkout main` will fail with "already used by
  worktree". Start new work with `git checkout -b <branch> origin/main`
  instead.
