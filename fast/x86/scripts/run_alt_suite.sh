#!/usr/bin/env bash
# Run all x86 go-fast comparators and store a dated report.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESULT_DIR="$ROOT_DIR/fast/x86/results"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="$RESULT_DIR/alt_suite_${STAMP}.md"

mkdir -p "$RESULT_DIR"

{
    echo "# x86 Go-Fast Alternative Suite"
    echo
    echo "- Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    echo "- Host: $(hostname)"
    echo
    echo "- Promotion gate: publish-only kernels must be >=5x over baseline/reference."
    echo

    run_case() {
        local title="$1"
        local cmd="$2"
        echo "## ${title}"
        echo
        echo '```text'
        eval "$cmd"
        echo '```'
        echo
    }

    run_case "AES-128" "bash fast/x86/scripts/compare_aes128_alt.sh 2000"
    run_case "AES-256" "bash fast/x86/scripts/compare_aes256_alt.sh 2000"
    run_case "GHASH" "bash fast/x86/scripts/compare_ghash_alt.sh 5000"
} | tee "$OUT_FILE"

echo
echo "Saved: $OUT_FILE"
