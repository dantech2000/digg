#!/usr/bin/env bash
# Fail when a flag accepted by the parser is missing from any completion
# script — same drift protection as scripts/man-check.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/flags.sh
source scripts/flags.sh

missing=0
cli_src=$(awk '/#\[cfg\(test\)\]/{exit} {print}' src/cli.rs)
flags=$(extract_plus_flags "$cli_src")
for file in completions/digg.bash completions/_digg completions/digg.fish; do
    for flag in $flags; do
        if ! grep -q "$flag" "$file"; then
            echo "$file missing +$flag" >&2
            missing=1
        fi
    done
done
exit $missing
