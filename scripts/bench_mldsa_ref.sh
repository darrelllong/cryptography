#!/usr/bin/env bash
# Pilot-driven benchmark for vendored Dilithium reference code.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
PILOT_PRESET="${PILOT_PRESET:-quick}"
REF_DIR="${REF_DIR:-$ROOT_DIR/third_party/ml-dsa/dilithium-ref/ref}"
CC_BIN="${CC:-cc}"

if [[ ! -d "$REF_DIR" ]]; then
  echo "missing reference directory: $REF_DIR" >&2
  exit 1
fi

TMP_C="$(mktemp -t mldsa_ref_wall)"
trap 'rm -f "$TMP_C" /tmp/mldsa_ref_wall_2 /tmp/mldsa_ref_wall_3 /tmp/mldsa_ref_wall_5' EXIT

cat >"$TMP_C" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "sign.h"
#include "fips202.h"

/* The reference calls `randombytes` for key-generation seeds and hedged
 * signing. For a timing benchmark any fixed, fast byte stream will do, so this
 * harness supplies its own: SplitMix64 (Steele, Lea and Flood, "Fast
 * splittable pseudorandom number generators", OOPSLA 2014), emitted
 * little-endian eight bytes at a time. It is not a cryptographic generator. */
static uint64_t bench_rng_state = 0x6d6c6473612d7265ULL;

static uint64_t bench_splitmix64(void) {
  uint64_t z = (bench_rng_state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

void randombytes(uint8_t *out, size_t outlen) {
  while (outlen > 0) {
    uint64_t word = bench_splitmix64();
    for (int i = 0; i < 8 && outlen > 0; i++, outlen--) {
      *out++ = (uint8_t)(word >> (8 * i));
    }
  }
}

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: mldsa_ref_wall <keygen|sign|verify> <rounds>\n");
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
  uint8_t sig[CRYPTO_BYTES];
  uint8_t msg[32];
  size_t siglen = 0;
  volatile uint8_t sink = 0;

  memset(msg, 0x42, sizeof(msg));
  crypto_sign_keypair(pk, sk);
  crypto_sign_signature(sig, &siglen, msg, sizeof(msg), NULL, 0, sk);

  double t0 = now_ms();
  if (strcmp(op, "keygen") == 0) {
    for (unsigned long i = 0; i < rounds; i++) {
      crypto_sign_keypair(pk, sk);
      sink ^= pk[0] ^ sk[0];
    }
  } else if (strcmp(op, "sign") == 0) {
    for (unsigned long i = 0; i < rounds; i++) {
      crypto_sign_signature(sig, &siglen, msg, sizeof(msg), NULL, 0, sk);
      sink ^= sig[0];
    }
  } else if (strcmp(op, "verify") == 0) {
    for (unsigned long i = 0; i < rounds; i++) {
      int ok = crypto_sign_verify(sig, siglen, msg, sizeof(msg), NULL, 0, pk);
      sink ^= (uint8_t)(ok == 0);
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
  local mode="$1"
  local out="/tmp/mldsa_ref_wall_${mode}"
  if ! (
    cd "$REF_DIR"
    "$CC_BIN" -O3 -fomit-frame-pointer "-DDILITHIUM_MODE=${mode}" -I"$REF_DIR" \
      sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c \
      fips202.c symmetric-shake.c -x c "$TMP_C" -o "$out"
  ); then
    return 1
  fi
  echo "$out"
}

measure() {
  local bin="$1" op="$2" rounds="$3" set_name="$4" op_name="$5"
  local out mean ci reps
  out=$("$BENCH" run_program --preset "$PILOT_PRESET" \
        --pi "${set_name}_${op_name},ms/op,0,1,1" \
        -- "$bin" "$op" "$rounds" 2>&1)
  mean=$(echo "$out" | awk '/Reading mean/{print $5}')
  ci=$(echo "$out" | awk '/Reading CI/{print $5}')
  reps=$(echo "$out" | awk '/^Rounds:/{print $2}')
  if [[ -z "$mean" || -z "$ci" || -z "$reps" ]]; then
    echo "pilot-bench output for ${set_name}_${op_name} carried no mean, CI or round count:" >&2
    echo "$out" >&2
    exit 1
  fi
  printf "| %-16s | %-14s | %12s | %12s | %5s |\n" "$set_name" "${op_name}_ref" "$mean" "±$ci" "$reps"
}

printf "| %-16s | %-14s | %12s | %12s | %5s |\n" "Parameter Set" "Operation" "ms/op" "±CI (95%)" "Runs"
printf "|------------------|----------------|-------------:|------------:|------:|\n"

for mode in 2 3 5; do
  if ! bin="$(build_ref_wall_bench "$mode")"; then
    echo "failed to build reference benchmark for mode=$mode" >&2
    exit 1
  fi
  case "$mode" in
    2) name="mldsa44"; rounds=80 ;;
    3) name="mldsa65"; rounds=50 ;;
    5) name="mldsa87"; rounds=30 ;;
    *) echo "unexpected mode=$mode" >&2; exit 1 ;;
  esac
  measure "$bin" keygen "$rounds" "$name" "keygen"
  measure "$bin" sign "$rounds" "$name" "sign"
  measure "$bin" verify "$rounds" "$name" "verify"
done
