# Contributing to digg

## Dev loop

```sh
just check       # fmt --check, clippy -D warnings, release tests, drift checks
just test        # test suite
just run <args>  # e.g. just run example.com +short
```

`just check` mirrors CI exactly. Every CLI flag must appear in the man page
(`docs/digg.1`) and all three completion scripts (`completions/`) — the
`man-check.sh` / `completions-check.sh` drift checks enforce this and run in CI.

## Testing conventions

- Every bug fix ships with a regression test in the same PR.
- Tests are hermetic: no live network. Transport tests use the loopback mock
  server in `tests/transport_mock.rs`; DNSSEC and protocol tests use captured
  byte fixtures with a fixed timestamp.
- Coverage is a ratchet (`.github/workflows/ci.yml`): raise the threshold in
  the same PR that raises coverage, never above the measured floor.

## Fuzzing

The wire parser is fuzzed two ways:

1. **Stable, always-on** — `src/fuzz_tests.rs` runs ~100k hostile inputs through
   the decoders on every `cargo test`. Deterministic and hermetic.
2. **Coverage-guided** — `fuzz/` holds cargo-fuzz (libFuzzer) targets, run on
   nightly Rust and weekly in CI (`.github/workflows/fuzz.yml`).

```sh
cargo +nightly fuzz run parse_message   # or decode_name, decode_record
cargo +nightly fuzz run parse_message -- -max_total_time=60
```

A reproducing input for a crash lands in `fuzz/artifacts/<target>/`; re-run
`cargo +nightly fuzz run <target> <path>` to replay it. When a fuzzer finds a
bug, fix it and add a minimized regression test to the relevant unit-test
module (see `type_bitmap_oversized_block_does_not_overflow` in
`src/protocol/record.rs`).
