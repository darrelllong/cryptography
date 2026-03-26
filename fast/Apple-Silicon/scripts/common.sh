#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
CIPHER_BIN="${PILOT_CIPHER_BIN:-$ROOT_DIR/target/release/pilot_cipher}"
PK_BIN="${PILOT_PK_BIN:-$ROOT_DIR/target/release/pilot_pk}"
PRESET="${PILOT_PRESET:-quick}"
RESULT_DIR="$ROOT_DIR/fast/Apple-Silicon/results"
STAMP="$(date +%Y%m%d_%H%M%S)"

build_bins() {
    local scope=${1:-all}
    local needs_cipher=0
    local needs_pk=0

    case "$scope" in
        symmetric)
            needs_cipher=1
            ;;
        pk)
            needs_pk=1
            ;;
        all)
            needs_cipher=1
            needs_pk=1
            ;;
        *)
            echo "unknown build scope: $scope" >&2
            return 1
            ;;
    esac

    if [[ "$needs_cipher" == "1" ]]; then
        if [[ "${FAST_NATIVE:-0}" == "1" ]]; then
            (
                cd "$ROOT_DIR"
                RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native" \
                    cargo build --release --bin pilot_cipher
            )
        else
            (
                cd "$ROOT_DIR"
                cargo build --release --bin pilot_cipher
            )
        fi
    fi

    if [[ "$needs_pk" == "1" ]]; then
        if [[ "${FAST_NATIVE:-0}" == "1" ]]; then
            (
                cd "$ROOT_DIR"
                RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native" \
                    cargo build --release --bin pilot_pk
            )
        else
            (
                cd "$ROOT_DIR"
                cargo build --release --bin pilot_pk
            )
        fi
    fi
}

measure_cipher() {
    local name=$1
    local out mean ci rounds
    out=$("$BENCH" run_program --preset "$PRESET" \
          --pi "${name},MB/s,0,1,1" \
          -- "$CIPHER_BIN" "$name" 2>&1)
    mean=$(echo "$out" | awk '/Reading mean/{print $5; exit}')
    ci=$(echo "$out" | awk '/Reading CI/{print $5; exit}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2; exit}')
    printf "%s|%s|%s\n" "$mean" "$ci" "$rounds"
}

measure_pk() {
    local op=$1
    local out mean ci rounds
    out=$("$BENCH" run_program --preset "$PRESET" \
          --pi "${op},ms/op,0,1,1" \
          -- "$PK_BIN" "$op" 2>&1)
    mean=$(echo "$out" | awk '/Reading mean/{print $5; exit}')
    ci=$(echo "$out" | awk '/Reading CI/{print $5; exit}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2; exit}')
    printf "%s|%s|%s\n" "$mean" "$ci" "$rounds"
}

emit_header() {
    local scope=$1
    local host native_mode
    host="$(hostname -s || hostname)"
    native_mode="off"
    if [[ "${FAST_NATIVE:-0}" == "1" ]]; then
        native_mode="on"
    fi
    echo "# Apple-Silicon Hotspots (${scope})"
    echo
    echo "- Date: $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    echo "- Host: \`$host\`"
    echo "- Pilot preset: \`$PRESET\`"
    echo "- Native tuning (\`-C target-cpu=native\`): \`$native_mode\`"
    echo
}
