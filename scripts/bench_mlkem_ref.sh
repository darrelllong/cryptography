#!/usr/bin/env bash
# Portable wall-clock benchmark for vendored Kyber reference code.
# Uses deterministic *_derand APIs so no RNG backend is required.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF_DIR="${REF_DIR:-$ROOT_DIR/third_party/ml-kem/kyber-ref/ref}"
CC_BIN="${CC:-cc}"

if [[ ! -d "$REF_DIR" ]]; then
  echo "missing reference directory: $REF_DIR" >&2
  exit 1
fi

TMP_C="$(mktemp -t mlkem_ref_wall)"
trap 'rm -f "$TMP_C" /tmp/mlkem_ref_wall_2 /tmp/mlkem_ref_wall_3 /tmp/mlkem_ref_wall_4' EXIT

cat >"$TMP_C" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "kem.h"

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: mlkem_ref_wall <keygen|encaps|decaps> <rounds>\n");
    return 2;
  }

  const char *op = argv[1];
  unsigned long rounds = strtoul(argv[2], NULL, 10);
  if (rounds == 0) {
    fprintf(stderr, "rounds must be > 0\n");
    return 2;
  }

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss[CRYPTO_BYTES];
  uint8_t coins32[32];
  uint8_t coins64[64];
  volatile uint8_t sink = 0;

  for (size_t i = 0; i < sizeof(coins32); i++) {
    coins32[i] = (uint8_t)(i + 1);
  }
  for (size_t i = 0; i < sizeof(coins64); i++) {
    coins64[i] = (uint8_t)(i + 17);
  }

  crypto_kem_keypair_derand(pk, sk, coins64);
  crypto_kem_enc_derand(ct, ss, pk, coins32);

  double t0 = now_ms();
  if (strcmp(op, "keygen") == 0) {
    for (unsigned long i = 0; i < rounds; i++) {
      crypto_kem_keypair_derand(pk, sk, coins64);
      sink ^= pk[0] ^ sk[0];
    }
  } else if (strcmp(op, "encaps") == 0) {
    for (unsigned long i = 0; i < rounds; i++) {
      crypto_kem_enc_derand(ct, ss, pk, coins32);
      sink ^= ct[0] ^ ss[0];
    }
  } else if (strcmp(op, "decaps") == 0) {
    for (unsigned long i = 0; i < rounds; i++) {
      crypto_kem_dec(ss, ct, sk);
      sink ^= ss[0];
    }
  } else {
    fprintf(stderr, "unknown operation: %s\n", op);
    return 2;
  }
  double t1 = now_ms();

  printf("%.6f\n", (t1 - t0) / (double)rounds + (double)(sink & 0) * 0.0);
  return 0;
}
EOF

build_ref_wall_bench() {
  local k="$1"
  local out="/tmp/mlkem_ref_wall_${k}"
  if ! (
    cd "$REF_DIR"
    "$CC_BIN" \
      -O3 -fomit-frame-pointer "-DKYBER_K=${k}" \
      -I"$REF_DIR" \
      kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
      fips202.c symmetric-shake.c randombytes.c -x c "$TMP_C" \
      -o "$out"
  ); then
    return 1
  fi
  echo "$out"
}

measure() {
  local bin="$1"
  local op="$2"
  local rounds="$3"
  "$bin" "$op" "$rounds"
}

printf "| %-16s | %-14s | %12s |\n" "Parameter Set" "Operation" "ms/op"
printf "|------------------|----------------|-------------|\n"

for k in 2 3 4; do
  if ! bin="$(build_ref_wall_bench "$k")"; then
    echo "failed to build reference benchmark for k=$k" >&2
    exit 1
  fi
  case "$k" in
    2) p="mlkem512"; rounds=400 ;;
    3) p="mlkem768"; rounds=250 ;;
    4) p="mlkem1024"; rounds=150 ;;
    *) echo "unexpected k=$k" >&2; exit 1 ;;
  esac

  printf "| %-16s | %-14s | %12s |\n" "$p" "keygen_ref" "$(measure "$bin" keygen "$rounds")"
  printf "| %-16s | %-14s | %12s |\n" "$p" "encaps_ref" "$(measure "$bin" encaps "$rounds")"
  printf "| %-16s | %-14s | %12s |\n" "$p" "decaps_ref" "$(measure "$bin" decaps "$rounds")"
done
