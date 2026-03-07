#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBS_DIR="${ROOT_DIR}/pubs"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party/ml-kem"

FIPS203_URL="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf"
SP800_227_URL="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf"

KYBER_COMMIT="4768bd37c02f9c40a46cb49d4d1f4d5e612bb882"
KYBER_TARBALL_URL="https://github.com/pq-crystals/kyber/archive/${KYBER_COMMIT}.tar.gz"

mkdir -p "${PUBS_DIR}" "${THIRD_PARTY_DIR}"

echo "[ml-kem] Fetching NIST docs..."
curl -fsSL "${FIPS203_URL}" -o "${PUBS_DIR}/fips203-ml-kem.pdf"
curl -fsSL "${SP800_227_URL}" -o "${PUBS_DIR}/sp800-227-kem-properties.pdf"

echo "[ml-kem] Fetching pq-crystals/kyber reference source at ${KYBER_COMMIT}..."
tmp_tar="$(mktemp -t kyber_ref.XXXXXX.tar.gz)"
tmp_dir="$(mktemp -d -t kyber_ref.XXXXXX)"
trap 'rm -f "${tmp_tar}"; rm -rf "${tmp_dir}"' EXIT

curl -fsSL "${KYBER_TARBALL_URL}" -o "${tmp_tar}"
tar -xzf "${tmp_tar}" -C "${tmp_dir}"

ref_dst="${THIRD_PARTY_DIR}/kyber-ref"
rm -rf "${ref_dst}"
mv "${tmp_dir}/kyber-${KYBER_COMMIT}" "${ref_dst}"

echo "[ml-kem] Done."
echo "  - ${PUBS_DIR}/fips203-ml-kem.pdf"
echo "  - ${PUBS_DIR}/sp800-227-kem-properties.pdf"
echo "  - ${ref_dst}"
