# Common dev commands for digg. `just` with no args lists recipes.

_default:
    @just --list

# Build debug binary
build:
    cargo build

# Build optimized release binary
release:
    cargo build --release

# Run the full test suite (release, matching CI)
test:
    cargo test --release

# Format check (matches CI)
fmt:
    cargo fmt --check

# Auto-format the tree
fmt-fix:
    cargo fmt

# Lint with CI's exact flags
lint:
    cargo clippy --all-targets -- -D warnings

# Format + lint + test — mirrors the CI `check` job exactly
check: fmt lint test man-check completions-check
    cargo build --release

# Verify every CLI flag is documented in the man page
man-check:
    ./scripts/man-check.sh

# Verify every CLI flag appears in the shell completions
completions-check:
    ./scripts/completions-check.sh

# Coverage summary (requires cargo-llvm-cov; matches the CI ratchet)
coverage:
    cargo llvm-cov --fail-under-lines 78 --summary-only

# Run digg, e.g. `just run example.com +short`
run *ARGS:
    cargo run --release -- {{ARGS}}

# Install to /usr/local/bin
install: release
    cp target/release/digg /usr/local/bin/

clean:
    cargo clean
