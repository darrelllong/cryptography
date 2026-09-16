#!/usr/bin/env bash
# Regenerate tests/vectors/ml_dsa_ref_kat.txt and tests/vectors/ml_kem_ref_kat.txt
# by running the pq-crystals reference implementations as oracles.
#
# The references are fetched (gitignored) by scripts/fetch_mldsa_refs.sh and
# scripts/fetch_mlkem_refs.sh. Nothing from them is copied anywhere; the
# harnesses under scripts/pq_ref_vectors/ only link against them and call
# their public API. The output is byte-for-byte reproducible: run this twice
# and `git diff tests/vectors` stays empty.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="${ROOT_DIR}/scripts/pq_ref_vectors"
DILITHIUM_REF="${ROOT_DIR}/third_party/ml-dsa/dilithium-ref/ref"
KYBER_REF="${ROOT_DIR}/third_party/ml-kem/kyber-ref/ref"
OUT_DIR="${ROOT_DIR}/tests/vectors"

# Commits pinned by the fetch scripts; recorded in the vector-file headers.
DILITHIUM_COMMIT="$(sed -n 's/^DILITHIUM_COMMIT="\(.*\)"$/\1/p' "${ROOT_DIR}/scripts/fetch_mldsa_refs.sh")"
KYBER_COMMIT="$(sed -n 's/^KYBER_COMMIT="\(.*\)"$/\1/p' "${ROOT_DIR}/scripts/fetch_mlkem_refs.sh")"

for dir in "${DILITHIUM_REF}" "${KYBER_REF}"; do
    if [[ ! -f "${dir}/fips202.c" ]]; then
        echo "missing reference tree ${dir}; run scripts/fetch_mldsa_refs.sh and scripts/fetch_mlkem_refs.sh" >&2
        exit 1
    fi
done

CC="${CC:-cc}"
CFLAGS="-O2 -Wall -Wextra -std=c99"
BUILD_DIR="$(mktemp -d -t pq_ref_vectors.XXXXXX)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

# The reference's own randombytes.c is deliberately not compiled: each harness
# defines randombytes() itself (deterministic, recorded).
DILITHIUM_SOURCES=(sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c fips202.c symmetric-shake.c)
KYBER_SOURCES=(kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c fips202.c symmetric-shake.c)

dilithium_srcs=()
for s in "${DILITHIUM_SOURCES[@]}"; do dilithium_srcs+=("${DILITHIUM_REF}/${s}"); done
kyber_srcs=()
for s in "${KYBER_SOURCES[@]}"; do kyber_srcs+=("${KYBER_REF}/${s}"); done

mldsa_out="${OUT_DIR}/ml_dsa_ref_kat.txt"
{
    cat <<HDR
# ML-DSA (FIPS 204) known-answer vectors produced by running the
# pq-crystals/dilithium reference implementation as an oracle.
#   reference: https://github.com/pq-crystals/dilithium commit ${DILITHIUM_COMMIT}
#   harness:   scripts/pq_ref_vectors/gen_mldsa.c (original code; links the
#              reference and calls only its public API)
#   regenerate: scripts/gen_pq_ref_vectors.sh
# The reference was used solely as an oracle to obtain these outputs; no code
# from it was transcribed into this crate.
#
# Per parameter set: XI is the 32-byte key-generation seed handed to the
# reference; PK/SK are its FIPS 204 encodings (rho||t1 and rho||K||tr||s1||s2||t0);
# MSGi/SIGi are three messages (0, 33, 200 bytes) and their signatures in the
# deterministic variant (rnd = 0^32) with an empty context string.
HDR
    for mode in 2 3 5; do
        bin="${BUILD_DIR}/gen_mldsa${mode}"
        "${CC}" ${CFLAGS} -I"${DILITHIUM_REF}" -DDILITHIUM_MODE="${mode}" \
            "${dilithium_srcs[@]}" "${HARNESS_DIR}/gen_mldsa.c" -o "${bin}"
        echo
        "${bin}"
    done
} > "${mldsa_out}"

mlkem_out="${OUT_DIR}/ml_kem_ref_kat.txt"
{
    cat <<HDR
# ML-KEM (FIPS 203) known-answer vectors produced by running the
# pq-crystals/kyber reference implementation ("standard" ML-KEM build) as an oracle.
#   reference: https://github.com/pq-crystals/kyber commit ${KYBER_COMMIT}
#   harness:   scripts/pq_ref_vectors/gen_mlkem.c (original code; links the
#              reference and calls only its public API)
#   regenerate: scripts/gen_pq_ref_vectors.sh
# The reference was used solely as an oracle to obtain these outputs; no code
# from it was transcribed into this crate.
#
# Per parameter set: D||Z is the key-generation seed; PK/SK are the FIPS 203
# encapsulation and decapsulation keys; M is the encapsulation randomness; CT/SS
# the resulting ciphertext and shared secret. CTBAD_INDEX/CTBAD_XOR describe a
# corrupted ciphertext ct' = ct with byte [index] XORed by the mask, and SSBAD is
# the implicit-rejection output J(Z || ct') that decapsulating ct' must yield.
HDR
    for k in 2 3 4; do
        bin="${BUILD_DIR}/gen_mlkem${k}"
        "${CC}" ${CFLAGS} -I"${KYBER_REF}" -DKYBER_K="${k}" \
            "${kyber_srcs[@]}" "${HARNESS_DIR}/gen_mlkem.c" -o "${bin}"
        echo
        "${bin}"
    done
} > "${mlkem_out}"

echo "wrote ${mldsa_out} ($(wc -c < "${mldsa_out}" | tr -d ' ') bytes)"
echo "wrote ${mlkem_out} ($(wc -c < "${mlkem_out}" | tr -d ' ') bytes)"
