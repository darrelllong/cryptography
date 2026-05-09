#!/usr/bin/env bash
# Run the full publication-facing public-key suite through pilot-bench and emit
# Markdown tables for CI-backed numbers in ASYMMETRIC.md.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
PK="${PILOT_PK_BIN:-$ROOT_DIR/target/release/pilot_pk}"
PILOT_PRESET="${PILOT_PRESET:-quick}"
PILOT_PK_ITERS_PERCENT="${PILOT_PK_ITERS_PERCENT:-25}"
PILOT_CONFIDENCE_LEVEL="${PILOT_CONFIDENCE_LEVEL:-}"
export PILOT_PK_ITERS_PERCENT

measure() {
    local name=$1
    local out mean ci rounds
    local extra=()
    if [[ -n "${PILOT_CONFIDENCE_LEVEL}" ]]; then
        extra+=(--confidence-level "${PILOT_CONFIDENCE_LEVEL}")
    fi
    out=$("$BENCH" run_program --preset "$PILOT_PRESET" "${extra[@]}" \
          --pi "${name},ms/op,0,1,1" \
          -- "$PK" "$name" 2>&1)
    mean=$(echo "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    printf "| %-32s | %10s | %10s | %5s |\n" \
           "$name" "$mean" "±$ci" "$rounds"
}

sep() { echo "|----------------------------------|------------|------------|-------|"; }

hdr() {
    echo ""
    echo "### $1"
    echo ""
    echo "| Operation                        |   ms/op    | ±CI (95%)  | Runs  |"
    sep
}

hdr "Finite-field public key (1024-bit)"
measure rsa_keygen_1024
measure rsa_encrypt_1024
measure rsa_decrypt_1024
measure rsa_sign_1024
measure rsa_verify_1024
measure elgamal_keygen_1024
measure elgamal_encrypt_1024
measure elgamal_decrypt_1024
measure dsa_keygen_1024
measure dsa_sign_1024
measure dsa_verify_1024
measure paillier_keygen_1024
measure paillier_encrypt_1024
measure paillier_decrypt_1024
measure paillier_rerandomize_1024
measure paillier_add_1024
measure cocks_keygen_1024
measure cocks_encrypt_1024
measure cocks_decrypt_1024
measure rabin_keygen_1024
measure rabin_encrypt_1024
measure rabin_decrypt_1024
measure schmidt_samoa_keygen_1024
measure schmidt_samoa_encrypt_1024
measure schmidt_samoa_decrypt_1024

hdr "RSA (2048-bit)"
measure rsa_keygen_2048
measure rsa_encrypt_2048
measure rsa_decrypt_2048
measure rsa_sign_2048
measure rsa_verify_2048

hdr "ECDSA / ECDH (P-256)"
measure ecdsa_keygen
measure ecdsa_sign
measure ecdsa_verify
measure ecdh_keygen
measure ecdh_agree
measure ecdh_serialize

hdr "ECIES / EC ElGamal (P-256)"
measure ecies_keygen
measure ecies_encrypt
measure ecies_decrypt
measure ec_elgamal_keygen
measure ec_elgamal_encrypt
measure ec_elgamal_decrypt

hdr "Ed25519 / Edwards DH / Edwards ElGamal"
measure ed25519_keygen
measure ed25519_sign
measure ed25519_verify
measure edwards_dh_keygen
measure edwards_dh_agree
measure edwards_dh_serialize
measure edwards_elgamal_keygen
measure edwards_elgamal_encrypt
measure edwards_elgamal_decrypt

hdr "X25519 / X448 (RFC 7748)"
measure x25519_keygen
measure x25519_agree
measure x25519_scalar_mult_base
measure x25519_scalar_mult
measure x448_keygen
measure x448_agree
measure x448_scalar_mult_base
measure x448_scalar_mult

hdr "ML-KEM (FIPS 203)"
measure mlkem512_keygen
measure mlkem512_encaps
measure mlkem512_decaps
measure mlkem768_keygen
measure mlkem768_encaps
measure mlkem768_decaps
measure mlkem1024_keygen
measure mlkem1024_encaps
measure mlkem1024_decaps

hdr "ML-DSA (FIPS 204)"
measure mldsa44_keygen
measure mldsa44_sign
measure mldsa44_verify
measure mldsa65_keygen
measure mldsa65_sign
measure mldsa65_verify
measure mldsa87_keygen
measure mldsa87_sign
measure mldsa87_verify

hdr "NTRU (NIST PQC round 3)"
measure ntruhps509_keygen
measure ntruhps509_encaps
measure ntruhps509_decaps
measure ntruhps677_keygen
measure ntruhps677_encaps
measure ntruhps677_decaps
measure ntruhps821_keygen
measure ntruhps821_encaps
measure ntruhps821_decaps
measure ntruhrss701_keygen
measure ntruhrss701_encaps
measure ntruhrss701_decaps

hdr "NTRUEncrypt (IEEE Std 1363.1-2008)"
measure ntruees401ep1_keygen
measure ntruees401ep1_encrypt
measure ntruees401ep1_decrypt
measure ntruees443ep1_keygen
measure ntruees443ep1_encrypt
measure ntruees443ep1_decrypt
measure ntruees449ep1_keygen
measure ntruees449ep1_encrypt
measure ntruees449ep1_decrypt
measure ntruees541ep1_keygen
measure ntruees541ep1_encrypt
measure ntruees541ep1_decrypt
measure ntruees677ep1_keygen
measure ntruees677ep1_encrypt
measure ntruees677ep1_decrypt
measure ntruees1087ep1_keygen
measure ntruees1087ep1_encrypt
measure ntruees1087ep1_decrypt
measure ntruees1087ep2_keygen
measure ntruees1087ep2_encrypt
measure ntruees1087ep2_decrypt
measure ntruees1171ep1_keygen
measure ntruees1171ep1_encrypt
measure ntruees1171ep1_decrypt
measure ntruees1499ep1_keygen
measure ntruees1499ep1_encrypt
measure ntruees1499ep1_decrypt

echo ""
