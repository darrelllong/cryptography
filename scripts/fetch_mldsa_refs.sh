#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBS_DIR="${ROOT_DIR}/pubs"
THIRD_PARTY_DIR="${ROOT_DIR}/third_party/ml-dsa"

FIPS204_URL="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf"

DILITHIUM_COMMIT="6e00625c5b29f516c6de973fe2ee2fbb150973f9"
DILITHIUM_TARBALL_URL="https://github.com/pq-crystals/dilithium/archive/${DILITHIUM_COMMIT}.tar.gz"

mkdir -p "${PUBS_DIR}" "${THIRD_PARTY_DIR}"

echo "[ml-dsa] Fetching NIST docs..."
curl -fsSL "${FIPS204_URL}" -o "${PUBS_DIR}/fips204-ml-dsa.pdf"

echo "[ml-dsa] Fetching pq-crystals/dilithium reference source at ${DILITHIUM_COMMIT}..."
tmp_tar="$(mktemp -t dilithium_ref.XXXXXX.tar.gz)"
tmp_dir="$(mktemp -d -t dilithium_ref.XXXXXX)"
trap 'rm -f "${tmp_tar}"; rm -rf "${tmp_dir}"' EXIT

curl -fsSL "${DILITHIUM_TARBALL_URL}" -o "${tmp_tar}"
tar -xzf "${tmp_tar}" -C "${tmp_dir}"

ref_dst="${THIRD_PARTY_DIR}/dilithium-ref"
rm -rf "${ref_dst}"
mv "${tmp_dir}/dilithium-${DILITHIUM_COMMIT}" "${ref_dst}"

echo "[ml-dsa] Done."
echo "  - ${PUBS_DIR}/fips204-ml-dsa.pdf"
echo "  - ${ref_dst}"
