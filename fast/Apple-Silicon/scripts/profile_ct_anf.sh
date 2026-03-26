#!/usr/bin/env bash
# Profile Ct ANF helper activity and estimated time-share by cipher.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

OUT_FILE="$RESULT_DIR/ct_anf_profile_${STAMP}.md"
mkdir -p "$RESULT_DIR"

(
    cd "$ROOT_DIR"
    cargo run --release --features ct_profile --bin profile_ct_anf
) | tee "$OUT_FILE"

echo
echo "Wrote $OUT_FILE"
