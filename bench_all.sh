#!/usr/bin/env bash
# Run every cipher through pilot-bench and emit a Markdown table.
# Columns: cipher, block bits, key bits, MB/s mean, ±CI (95%), runs-to-CI
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
CIPHER="${PILOT_CIPHER_BIN:-$ROOT_DIR/target/release/pilot_cipher}"

measure() {
    local name=$1 block=$2 key=$3
    local out mean ci rounds
    out=$("$BENCH" run_program --preset quick \
          --pi "${name},MB/s,0,1,1" \
          -- "$CIPHER" "$name" 2>&1)
    mean=$(echo  "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo    "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    printf "| %-20s | %5s | %5s | %8s | %8s | %5s |\n" \
           "$name" "$block" "$key" "$mean" "±$ci" "$rounds"
}

sep() { echo "|----------------------|-------|-------|----------|----------|-------|"; }

hdr() {
    echo ""
    echo "### $1"
    echo ""
    echo "| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |"
    sep
}

hdr "AES"
measure aes128    128 128
measure aes128ct  128 128
measure aes192    128 192
measure aes192ct  128 192
measure aes256    128 256
measure aes256ct  128 256

hdr "Camellia"
measure camellia128    128 128
measure camellia128ct  128 128
measure camellia192    128 192
measure camellia192ct  128 192
measure camellia256    128 256
measure camellia256ct  128 256

hdr "CAST-128"
measure cast128    64 128
measure cast128ct  64 128

hdr "DES / 3DES"
measure des    64  56
measure desct  64  56
measure 3des   64 168

hdr "Grasshopper (GOST R 34.12-2015)"
measure grasshopper    128 256
measure grasshopperct  128 256

hdr "Magma (GOST R 34.12-2015)"
measure magma    64 256
measure magmact  64 256

hdr "PRESENT"
measure present80     64  80
measure present80ct   64  80
measure present128    64 128
measure present128ct  64 128

hdr "SEED"
measure seed    128 128
measure seedct  128 128

hdr "Serpent"
measure serpent128    128 128
measure serpent128ct  128 128
measure serpent192    128 192
measure serpent192ct  128 192
measure serpent256    128 256
measure serpent256ct  128 256

hdr "SM4"
measure sm4    128 128
measure sm4ct  128 128

hdr "Twofish"
measure twofish128    128 128
measure twofish128ct  128 128
measure twofish192    128 192
measure twofish192ct  128 192
measure twofish256    128 256
measure twofish256ct  128 256

hdr "Simon"
measure simon32_64    32  64
measure simon48_72    48  72
measure simon48_96    48  96
measure simon64_96    64  96
measure simon64_128   64 128
measure simon96_96    96  96
measure simon96_144   96 144
measure simon128_128 128 128
measure simon128_192 128 192
measure simon128_256 128 256

hdr "Speck"
measure speck32_64    32  64
measure speck48_72    48  72
measure speck48_96    48  96
measure speck64_96    64  96
measure speck64_128   64 128
measure speck96_96    96  96
measure speck96_144   96 144
measure speck128_128 128 128
measure speck128_192 128 192
measure speck128_256 128 256

echo ""
echo "### Stream ciphers"
echo ""
echo "| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |"
sep
measure chacha20  stream 256
measure xchacha20 stream 256
measure salsa20   stream 256
measure rabbit    stream 128
measure snow3g    stream 128
measure snow3gct  stream 128
measure zuc128    stream 128
measure zuc128ct  stream 128
