#!/usr/bin/env bash
# Run public-key hotspots only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

OUT_FILE="$RESULT_DIR/hotspots_pk_${STAMP}.md"
mkdir -p "$RESULT_DIR"
build_bins pk

{
    emit_header "public-key"
    echo "## Public-Key Hotspots (ms/op)"
    echo
    echo "| Operation | ms/op | ±CI (95%) | Runs |"
    echo "|---|---:|---:|---:|"
    for op in \
        rsa_keygen_2048 rsa_decrypt_2048 rsa_sign_2048 \
        ecdsa_verify ed25519_verify ecies_encrypt ec_elgamal_encrypt \
        edwards_elgamal_decrypt
    do
        IFS='|' read -r mean ci runs <<<"$(measure_pk "$op")"
        printf "| \`%s\` | %s | ±%s | %s |\n" "$op" "$mean" "$ci" "$runs"
    done
} | tee "$OUT_FILE"

echo
echo "Wrote $OUT_FILE"
