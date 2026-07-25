#!/usr/bin/env bash
# Shared flag extraction for the drift checks (man-check.sh, completions-check.sh).
#
# parse_plus_option matches on a (name, value) tuple, so the arms look like:
#
#   ("short", None)                 a bare flag
#   ("propagation" | "prop", None)  a flag with aliases
#   ("timeout", Some(spec))         a flag that takes a value
#
# We pull the quoted names out of those arms. Note this deliberately does NOT
# match the leading '+': the parser strips it before matching, so searching for
# a literal "+flag" in the source finds nothing.

# Echo every +flag name the parser accepts, one per line.
extract_plus_flags() {
    local cli_src=$1
    local flags
    flags=$(grep -oE '\("[a-z]+"( \| "[a-z]+")*, (None|Some)' <<<"$cli_src" |
        grep -oE '"[a-z]+"' | tr -d '"' | sort -u || true)

    # Finding nothing means the parser was restructured and this pattern no
    # longer matches. Fail loudly: a silent empty list turns both drift checks
    # into no-ops that pass while protecting nothing, which is how this broke
    # the first time.
    if [ -z "$flags" ]; then
        echo "drift check: no +flags found in src/cli.rs" >&2
        echo "The parser's match-arm shape has changed; update extract_plus_flags in scripts/flags.sh." >&2
        return 1
    fi

    printf '%s\n' "$flags"
}
