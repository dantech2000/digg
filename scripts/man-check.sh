#!/usr/bin/env bash
# Fail when a flag accepted by the parser is missing from the man page.
# Cheap grep-based drift protection: extracts every "+flag" match arm and
# dash flag from src/cli.rs and looks for the flag name in docs/digg.1.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=0
# Only scan production code — the test module contains deliberately bogus flags.
cli_src=$(awk '/#\[cfg\(test\)\]/{exit} {print}' src/cli.rs)
# +flags: literal arms like "+short" and prefix arms like "+timeout=".
flags=$(grep -oE '"\+[a-z]+=?"' <<<"$cli_src" | tr -d '"+=' | sort -u)
# Prefix arms: s.starts_with("+subnet=") style.
flags+=" $(grep -oE 'starts_with\("\+[a-z]+=' <<<"$cli_src" | sed -E 's/.*\+([a-z]+)=/\1/' | sort -u)"
for flag in $flags; do
    if ! grep -q "$flag" docs/digg.1; then
        echo "man page missing +$flag" >&2
        missing=1
    fi
done
for flag in x p c f; do
    if ! grep -qE "^\.It Fl $flag" docs/digg.1; then
        echo "man page missing -$flag" >&2
        missing=1
    fi
done
exit $missing
