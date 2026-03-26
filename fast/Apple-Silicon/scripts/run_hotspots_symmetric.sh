#!/usr/bin/env bash
# Run symmetric Ct-gap hotspots only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

OUT_FILE="$RESULT_DIR/hotspots_symmetric_${STAMP}.md"
mkdir -p "$RESULT_DIR"
build_bins symmetric

{
    emit_header "symmetric"
    echo "## Ct Gap Pairs (MB/s)"
    echo
    echo "| Pair | Fast MB/s | Fast ±CI | Fast Runs | Ct MB/s | Ct ±CI | Ct Runs | Fast/Ct |"
    echo "|---|---:|---:|---:|---:|---:|---:|---:|"

    while read -r fast ct; do
        IFS='|' read -r f_mean f_ci f_runs <<<"$(measure_cipher "$fast")"
        IFS='|' read -r c_mean c_ci c_runs <<<"$(measure_cipher "$ct")"
        ratio=$(awk -v f="$f_mean" -v c="$c_mean" 'BEGIN { if (c == 0) { print "inf" } else { printf "%.2fx", f / c } }')
        printf "| \`%s\` vs \`%s\` | %s | ±%s | %s | %s | ±%s | %s | %s |\n" \
            "$fast" "$ct" "$f_mean" "$f_ci" "$f_runs" "$c_mean" "$c_ci" "$c_runs" "$ratio"
    done <<'PAIRS'
aes128 aes128ct
camellia128 camellia128ct
sm4 sm4ct
seed seedct
twofish256 twofish256ct
present80 present80ct
snow3g snow3gct
zuc128 zuc128ct
PAIRS
} | tee "$OUT_FILE"

echo
echo "Wrote $OUT_FILE"
