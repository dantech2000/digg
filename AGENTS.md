# AGENTS.md

Instructions for AI coding agents working in this repo.

## What this is

`digg` is a modern DNS lookup CLI (like `dig`), written in Rust from scratch — no
`trust-dns`/`hickory-dns` crate, wire-format parsing is hand-rolled. Edition 2021,
no async runtime (blocking I/O + `std::thread::scope` for parallelism).

## Build / run / check

```sh
cargo build --release
cargo test
cargo clippy
cargo run -- example.com A
```

### Run what CI runs, before pushing

CI blocks merges on these, and `cargo test` alone is not enough — plain `cargo
test` passes while `clippy -D warnings` fails, which has bitten us:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --release
cargo build --release
./scripts/man-check.sh            # every +flag documented in docs/digg.1
./scripts/completions-check.sh    # ...and in the shell completions
cargo llvm-cov --fail-under-lines 78 --ignore-filename-regex 'microbench\.rs'
```

Tests are not a substitute for driving the binary. Run the real thing against
the paths you touched — `+trace`, `+json`, `+validate`, `+compat` — because
several classes of bug here only appear against live DNS.

### Benchmarks

`src/microbench.rs` times digg's own hot paths (not to be confused with
`bench.rs`, which is the user-facing `+bench` feature). Benches are `#[ignore]`d
so `cargo test` stays fast:

```sh
cargo test --release --lib microbench -- --ignored --nocapture --test-threads=1
```

Measure before and after when claiming a performance change, and interleave the
two binaries rather than running one set then the other — network and cache
state drift between batches and will hand you a wrong number.

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

### Conventional commits drive releases

Release Please reads commit subjects off `main` to decide the next version and
to write `CHANGELOG.md`. The prefix is not decoration — it decides whether a
release happens at all.

| Prefix | Version | In changelog |
| --- | --- | --- |
| `feat:` | minor (`0.5.1` → `0.6.0`) | Features |
| `fix:` | patch (`0.5.1` → `0.5.2`) | Bug Fixes |
| `perf:` | patch | Performance Improvements |
| `refactor:` `test:` `ci:` `chore:` `docs:` | none | not listed |
| `feat!:` or `BREAKING CHANGE:` footer | major | Breaking |

So pick the prefix by what the change *does to users*, not by how much work it
was. A large refactor that changes no behaviour is `refactor:` and cuts no
release; a one-line `fix:` does.

Use a scope where it narrows things usefully: `perf(dnssec):`, `fix(output):`,
`refactor(protocol):`.

**Write the body for someone reading `git log` in a year.** Say what was wrong
and why the change is right, not just what it does. Include the measurement for
anything claiming a performance win, and note what you verified — those bodies
are the record of *why*, and this repo's history leans on them heavily.

### How a release actually ships

1. A `feat:`/`fix:`/`perf:` commit lands on `main`.
2. Release Please opens (or updates) a `chore(main): release X.Y.Z` PR,
   accumulating everything since the last release.
3. `.github/workflows/scheduled-release.yml` merges that PR **Mondays 08:00
   UTC**, so releases batch rather than one firing per merged PR. Run that
   workflow from the Actions tab to ship early.
4. Merging it tags `vX.Y.Z`, which triggers `release.yml`: builds the darwin
   binaries, uploads them, and pushes an updated cask to
   `dantech2000/homebrew-tap`.

That last step means **merging the release PR ships to `brew upgrade` users**.
Treat it as such — check the changelog reads correctly first, and if a release
carries a user-visible behaviour change, note it in the README the way #90 did
for v0.5.0.

Do not hand-edit the version in `Cargo.toml` or write `CHANGELOG.md` entries
yourself; Release Please owns both, and edits will be overwritten.

## GitHub workflow

- File an issue before starting non-trivial work; reference it in the commit
  message and PR body (`Fixes #N`). Commit/PR titles use conventional-commit
  prefixes matching the issue title (`fix:`, `feat:`, `chore:`, `docs:`,
  `refactor:`, `test:`, `ci:`).
- Labels: GitHub's defaults (`bug`, `enhancement`, `documentation`, ...) plus
  two repo-specific additions — `ci` (build/release tooling, GitHub Actions)
  and `chore` (maintenance / dev-experience work with no user-facing behavior
  change). Reuse existing labels; only add a new one if nothing fits.
- `main` is protected: **`check` and `coverage` must pass**, and the branch must
  be up to date, before anything merges. Admins are not exempted from the checks
  by policy, but `enforce_admins` is off so there is an escape hatch in a real
  emergency. Run the CI commands above locally first — a red PR wastes a
  two-minute LTO build.
- **Choosing a merge strategy:**
  - `--rebase` when the commits are individually meaningful — one commit per
    finding, each independently reviewable and revertable. This preserves the
    granular changelog entries Release Please generates. Prefer this for
    multi-commit work.
  - `--squash` when the PR is one logical change that happened to take several
    commits, and for Release Please's own release PRs.
  - Branches are deleted automatically on merge (`delete_branch_on_merge`).
- Keep each commit self-consistent: a commit that leaves `fmt`, `clippy` or the
  build broken makes `git bisect` useless, even if the PR is green overall.
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
