#!/usr/bin/env bash
# Run the full publication-facing public-key suite through pilot-bench and emit
# Markdown tables. This keeps the legacy bench_public_key binary available, but
# makes Pilot the preferred path for CI-backed numbers in ASYMMETRIC.md.
set -euo pipefail

BENCH=~/pilot-bench/build/cli/bench
PK=~/cryptography/target/release/pilot_pk

measure() {
    local name=$1
    local out mean ci rounds
    out=$("$BENCH" run_program --preset quick \
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
    echo "| Operation                        |   ms/op    |    ±CI     | Runs  |"
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

echo ""
