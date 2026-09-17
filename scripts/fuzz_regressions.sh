#!/usr/bin/env bash
# Run every fuzz target over the inputs that once broke it.
#
#   scripts/fuzz_regressions.sh [target-triple]
#
# `fuzz/regressions/<target>/` holds minimized inputs at boundaries a target
# reached: each one is a defect that was repaired, and a campaign that starts
# from a fresh corpus need not find it again. This runs each target's binary
# over its own directory, which is quick — libFuzzer executes the named inputs
# and exits — and reports the first that fails.
#
# The binaries come from `cargo +nightly fuzz build`, which this always runs:
# incremental when nothing changed, and never trusting a directory left over
# from an older tree. A failure here means a repair was lost.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
binaries=$root/fuzz/target/$target/release

cd "$root"
# Always build: an existing directory says nothing about when its binaries
# were made, and a stale one turns a repaired defect into a false alarm.
echo "building the fuzz targets for $target"
cargo +nightly fuzz build --target "$target"

failed=0
checked=0
for directory in fuzz/regressions/*/; do
    name=$(basename "$directory")
    inputs=$(find "$directory" -type f | sort)
    [ -n "$inputs" ] || continue
    if [ ! -x "$binaries/$name" ]; then
        echo "$name: no binary in $binaries" >&2
        failed=1
        continue
    fi
    count=$(printf '%s\n' "$inputs" | grep -c .)
    if output=$("$binaries/$name" $inputs 2>&1); then
        echo "$name: $count input(s) ran clean"
        checked=$((checked + count))
    else
        echo "$name: FAILED" >&2
        printf '%s\n' "$output" | tail -20 >&2
        failed=1
    fi
done

echo
if [ "$failed" -eq 0 ]; then
    echo "$checked repaired input(s) still run clean"
else
    echo "a repaired input broke its target again" >&2
    exit 1
fi
