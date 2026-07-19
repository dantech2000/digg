#!/usr/bin/env bash
# Fail when a flag accepted by the parser is missing from any completion
# script — same drift protection as scripts/man-check.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=0
cli_src=$(awk '/#\[cfg\(test\)\]/{exit} {print}' src/cli.rs)
flags=$(grep -oE '"\+[a-z]+=?"' <<<"$cli_src" | tr -d '"+=' | sort -u)
flags+=" $(grep -oE 'starts_with\("\+[a-z]+=' <<<"$cli_src" | sed -E 's/.*\+([a-z]+)=/\1/' | sort -u)"
for file in completions/digg.bash completions/_digg completions/digg.fish; do
    for flag in $flags; do
        if ! grep -q "$flag" "$file"; then
            echo "$file missing +$flag" >&2
            missing=1
        fi
    done
done
exit $missing
