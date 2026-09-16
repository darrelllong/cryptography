#!/usr/bin/env bash
# Regenerate tests/vectors/ntru_ees_sves3_reference.txt, the NTRUEncrypt
# SVES-3 interoperability vectors, and re-run both interoperability checks.
#
#   scripts/ees_ref_vectors/generate.sh
#   WORK=/some/dir scripts/ees_ref_vectors/generate.sh    # keep build products
#
# 1. Fetch Security Innovation's reference implementation of IEEE Std
#    1363.1-2008 / ANSI X9.98 NTRUEncrypt (libntruencrypt 1.1.0, CC0) at a
#    pinned commit and build it as a static library. It is run only as a
#    black-box oracle; the crate uses none of it.
# 2. Build ees_ref_vectors.c against it and write the ORIGIN=reference blocks.
# 3. Run the crate's ignored emitter test, which encrypts under the reference
#    key pairs and under key pairs from the crate's own keygen, then have the
#    oracle decrypt every such ciphertext and accept every such key pair.
# 3b. If third_party/ntru-crypto-upstream2 is present (the reference sources as
#    archived by Software Heritage), build a second oracle from its NTRUEncrypt
#    sources over the 1.1.0 headers, hash and DRBG, have it check every record
#    and regenerate the reference blocks, and record whether they match.
# 4. Build a copy of third_party/libntru (if present) and run
#    libntru_crosscheck.c on the reference blocks, recording whether libntru
#    interoperates with them.
# 5. Assemble the vector file with a header recording both outcomes, and run
#    the crate's EES tests against it.
#
# Requires cc, ar, curl, python3 and cargo; make for step 4.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/scripts/ees_ref_vectors"
VECTORS="$ROOT/tests/vectors/ntru_ees_sves3_reference.txt"
WORK=${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ees_ref_vectors.XXXXXX")}
REPO=jschanck-si/NTRUEncrypt
COMMIT=3d36004274308feef0701bf9473e5b0775e1bf6f
LIBNTRU="$ROOT/third_party/libntru"
UPSTREAM2="$ROOT/third_party/ntru-crypto-upstream2/reference-code/C/Encrypt/src"

echo "work directory: $WORK"
REF="$WORK/libntruencrypt"
mkdir -p "$REF/src" "$REF/include" "$REF/obj"

# ---- 1. the oracle ---------------------------------------------------------
for dir in src include; do
    curl -fsS "https://api.github.com/repos/$REPO/contents/$dir?ref=$COMMIT" |
        python3 -c 'import json, sys; print("\n".join(e["name"] for e in json.load(sys.stdin)))' |
        while read -r name; do
            curl -fsS -o "$REF/$dir/$name" \
                "https://raw.githubusercontent.com/$REPO/$COMMIT/$dir/$name"
        done
done
for source in "$REF"/src/*.c; do
    case "$source" in
        *_simd.c | *_32.c | *_64.c) continue ;; # portable multiplication only
    esac
    cc -O2 -std=gnu99 -w -I"$REF/include" -I"$REF/src" -c "$source" \
        -o "$REF/obj/$(basename "${source%.c}").o"
done
ar rcs "$REF/libntruencrypt.a" "$REF"/obj/*.o
cc -O2 -std=gnu99 -Wall -Wextra -I"$REF/include" "$HERE/ees_ref_vectors.c" \
    "$REF/libntruencrypt.a" -o "$WORK/ees_ref_vectors"

# ---- 2. reference blocks ---------------------------------------------------
"$WORK/ees_ref_vectors" gen "$WORK/reference.txt"
"$WORK/ees_ref_vectors" check "$WORK/reference.txt" | tail -n 1

# ---- 3. crate blocks, checked by the oracle ----------------------------------
# The emitter reads the reference blocks from the vector file at compile time.
# The emitter reads the vector file at compile time, so the reference blocks
# must be installed now; the committed file is restored if any later step
# fails, so a half-run never leaves a headerless fixture behind.
BACKUP="$WORK/committed_vectors.txt"
cp "$VECTORS" "$BACKUP"
restore_committed() {
    cp "$BACKUP" "$VECTORS"
    echo "generate.sh failed; the committed vector file was restored" >&2
}
trap restore_committed ERR
cp "$WORK/reference.txt" "$VECTORS"
cargo test --manifest-path "$ROOT/Cargo.toml" --lib -- --ignored --exact \
    public_key::ntru_ees_core::tests::emit_crate_vector_blocks --nocapture \
    >"$WORK/emit.txt" 2>"$WORK/emit.err"
python3 - "$WORK" <<'EOF'
import re, sys
work = sys.argv[1]
text = open(f"{work}/emit.txt").read()
m = re.search(r"-----BEGIN CRATE BLOCKS-----(.*)-----END CRATE BLOCKS-----", text, re.S)
if not m:
    sys.exit("emitter output markers missing; see emit.txt / emit.err")
open(f"{work}/crate.txt", "w").write(m.group(1))
EOF
if ! "$WORK/ees_ref_vectors" check "$WORK/crate.txt" >"$WORK/crate_check.txt"; then
    cat "$WORK/crate_check.txt"
    echo "the reference implementation rejected crate output" >&2
    exit 1
fi
tail -n 1 "$WORK/crate_check.txt"

# ---- 3b. second oracle: Software Heritage sources ---------------------------------
: >"$WORK/upstream2_result.txt"
if [ -d "$UPSTREAM2" ]; then
    SWH="$WORK/upstream2"
    rm -rf "$SWH"
    cp -R "$REF" "$SWH"
    rm -rf "$SWH/obj" && mkdir -p "$SWH/obj"
    cp "$UPSTREAM2"/*.c "$SWH/src/"
    for source in "$SWH"/src/*.c; do
        case "$source" in
            *_simd.c | *_32.c | *_64.c) continue ;;
        esac
        cc -O2 -std=gnu99 -w -I"$SWH/include" -I"$SWH/src" -c "$source" \
            -o "$SWH/obj/$(basename "${source%.c}").o"
    done
    ar rcs "$SWH/libntruencrypt.a" "$SWH"/obj/*.o
    cc -O2 -std=gnu99 -w -I"$SWH/include" "$HERE/ees_ref_vectors.c" \
        "$SWH/libntruencrypt.a" -o "$WORK/ees_ref_vectors_swh"
    cat "$WORK/reference.txt" "$WORK/crate.txt" >"$WORK/all.txt"
    "$WORK/ees_ref_vectors_swh" check "$WORK/all.txt" >"$WORK/swh_check.txt" || true
    "$WORK/ees_ref_vectors_swh" gen "$WORK/reference_swh.txt"
    if grep '^[A-Z_]*=' "$WORK/reference.txt" | grep -v '^ORIGIN=' >"$WORK/a.txt" &&
        grep '^[A-Z_]*=' "$WORK/reference_swh.txt" | grep -v '^ORIGIN=' >"$WORK/b.txt" &&
        cmp -s "$WORK/a.txt" "$WORK/b.txt"; then
        same=identical
    else
        same=different
    fi
    printf '%s\n%s\n' "$(tail -n 1 "$WORK/swh_check.txt")" "$same" >"$WORK/upstream2_result.txt"
    cat "$WORK/upstream2_result.txt"
fi

# ---- 4. libntru cross-check ------------------------------------------------
: >"$WORK/libntru_check.txt"
LIBNTRU_COMMIT=unavailable
if [ -d "$LIBNTRU/src" ]; then
    LIBNTRU_COMMIT=$(git -C "$LIBNTRU" rev-parse HEAD 2>/dev/null || echo unknown)
    rm -rf "$WORK/libntru"
    cp -R "$LIBNTRU" "$WORK/libntru"
    case "$(uname -s)" in
        Darwin) makefile=Makefile.osx ;;
        *) makefile=Makefile.linux ;;
    esac
    make -C "$WORK/libntru" -f "$makefile" SIMD=none CFLAGS="-O2 -w" lib >/dev/null
    cc -O1 -w -I"$WORK/libntru/src" "$HERE/libntru_crosscheck.c" \
        -L"$WORK/libntru" -lntru -o "$WORK/libntru_crosscheck"
    DYLD_LIBRARY_PATH="$WORK/libntru" LD_LIBRARY_PATH="$WORK/libntru" \
        "$WORK/libntru_crosscheck" "$WORK/reference.txt" >"$WORK/libntru_check.txt"
    cat "$WORK/libntru_check.txt"
fi

# ---- 5. assemble -----------------------------------------------------------
python3 - "$WORK" "$VECTORS" "$COMMIT" "$LIBNTRU_COMMIT" "$(date +%Y-%m-%d)" <<'EOF'
import sys
work, vectors, commit, libntru_commit, today = sys.argv[1:6]
reference = open(f"{work}/reference.txt").read()
reference_body = reference[reference.index("\nSET="):].rstrip("\n") + "\n"
crate = open(f"{work}/crate.txt").read()
crate_result = open(f"{work}/crate_check.txt").read().strip().splitlines()[-1]
swh = open(f"{work}/upstream2_result.txt").read().split("\n")
if len(swh) >= 2 and swh[0]:
    records = swh[0].split(" records")[0]
    verdict = ("accepted all " + records + " records" if swh[0].endswith(" 0 failures")
               else "reported: " + swh[0])
    regen = "byte-identically" if swh[1] == "identical" else "with DIFFERENT output"
    upstream2 = f"""#
# Second oracle: Security Innovation's reference sources as archived by Software Heritage
# (NTRUOpenSourceProject/ntru-crypto snapshot 14e6716f, reference-code/NTRUEncrypt rev
# 76b5bd11; its seven NTRUEncrypt sources built over the 1.1.0 headers, hash and DRBG).
# It {verdict} and regenerated the reference blocks {regen}.
"""
else:
    upstream2 = ""

rows = [line.split() for line in open(f"{work}/libntru_check.txt").read().splitlines()[1:] if line.strip()]
if rows:
    total, own, decrypts, matches = (sum(int(r[i]) for r in rows) for i in (1, 2, 3, 4))
    if decrypts == total and matches == total:
        verdict = "libntru interoperates with the reference implementation on these records."
    elif decrypts == 0 and matches == 0:
        verdict = ("libntru does not interoperate with the standard; these vectors follow the "
                   "reference\n# implementation and the specification.")
    else:
        verdict = (f"libntru interoperates on {decrypts}/{total} records only; these vectors follow "
                   "the reference\n# implementation and the specification.")
    libntru = f"""#
# Discrepancy record: tbuktu/libntru, commit
# {libntru_commit}, describes itself as following IEEE P1363.1.
# scripts/ees_ref_vectors/libntru_crosscheck.c ran it on the {total} reference records: it
# round-trips its own ciphertexts under the converted keys ({own}/{total}), decrypts
# {decrypts}/{total} reference ciphertexts and reproduces {matches}/{total} of them from the recorded b.
# {verdict}
"""
else:
    libntru = "#\n# The libntru cross-check was not run (third_party/libntru absent).\n"
header = f"""# NTRUEncrypt SVES-3 interoperability vectors: the IEEE Std 1363.1-2008 / ANSI X9.98
# parameter sets ees401ep1 ees449ep1 ees677ep1 ees1087ep2 ees541ep1 ees1171ep1 ees1087ep1
# ees1499ep1 and the EESS #1 v3.1 product-form set ees443ep1. Read by
# src/public_key/ntru_ees_core.rs (test_vectors) and checked by every per-set test module.
# Regenerate with scripts/ees_ref_vectors/generate.sh.
#
# ORIGIN=reference: produced by scripts/ees_ref_vectors/ees_ref_vectors.c driving Security
# Innovation's reference implementation of the standard (libntruencrypt 1.1.0, CC0,
# github.com/jschanck-si/NTRUEncrypt commit {commit}),
# used solely as a behavioural oracle. PK / SK are the key blobs from its keygen; MSG is
# 0, 1, max-1 and max octets long; ENC_RNG is every octet the oracle drew while encrypting
# (the random component b, bLen octets per attempt, repeated when the dm0 check rejected);
# CT is the packed ciphertext. The oracle decrypted every CT back to MSG.
#
# ORIGIN=crate-encrypt: this crate's ciphertexts under the reference key pair.
# ORIGIN=crate-keygen: a key pair from this crate's keygen seeded with
# CtrDrbgAes256(KEYGEN_SEED), and this crate's ciphertexts under it. Both were produced by
# the ignored test ntru_ees_core::tests::emit_crate_vector_blocks and fed to
# `ees_ref_vectors check` on {today}: the oracle decrypted every CT to MSG and accepted
# every PK and SK blob as a matching pair ({crate_result}).
{upstream2}{libntru}"""
open(vectors, "w").write(header + reference_body + crate)
EOF
trap - ERR
cargo test --manifest-path "$ROOT/Cargo.toml" --lib -- ntru_ees 2>&1 | tail -n 3
