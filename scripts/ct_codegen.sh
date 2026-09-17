#!/usr/bin/env bash
# Emit the machine code behind the crate's tag comparison and report the
# conditional branches in it.
#
#   scripts/ct_codegen.sh [target-triple]
#
# `Hmac::<Sha256>::verify` is the shortest public path to
# `ct::constant_time_eq_mask`, the helper every AEAD tag check and MAC
# verification uses. A probe crate calls it through an `#[inline(never)]`
# wrapper so the comparison keeps a symbol of its own, the release assembly of
# that symbol is extracted, and every conditional branch in it is listed.
#
# What to look for: the only conditional branches must be the loops over the
# tag's length, which is public. A branch that reads a tag or digest byte, or
# an early exit out of the comparison loop, is a secret-dependent branch and
# the claim in src/ct.rs no longer holds for that target and compiler.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
probe=$root/scripts/ct_probe
out=${CT_CODEGEN_OUT:-$root/target/ct-codegen}
mkdir -p "$out"

cargo build --release --manifest-path "$probe/Cargo.toml" --target "$target" \
    -q --target-dir "$out/target"
RUSTFLAGS="--emit asm" cargo rustc --release --manifest-path "$probe/Cargo.toml" \
    --target "$target" -q --target-dir "$out/target" -- --emit asm >/dev/null

asm=$(find "$out/target/$target/release" -name 'ct_probe*.s' -print -quit)
[ -n "$asm" ] || { echo "no assembly emitted for $target" >&2; exit 1; }

symbol=$(sed -n 's/^\([._a-zA-Z0-9$]*verify_tag[._a-zA-Z0-9$]*\):.*/\1/p' "$asm" | head -1)
[ -n "$symbol" ] || { echo "probe symbol not found in $asm" >&2; exit 1; }

body=$out/$target-verify_tag.s
awk -v sym="$symbol" '
    index($0, sym ":") == 1 { printing = 1 }
    printing { print }
    printing && /\.cfi_endproc/ { exit }
' "$asm" > "$body"
[ -s "$body" ] || { echo "no body extracted for $symbol" >&2; exit 1; }

case $target in
    aarch64*) branches='\b(b\.[a-z]+|cbn?z|tbn?z)\b' ;;
    x86_64*)  branches='\bj(n?[abegloszcp]|n?[ab]e|n?ge|n?le)\b' ;;
    *)        branches='\b(b\.[a-z]+|cbn?z|tbn?z|j[a-z]+)\b' ;;
esac

echo "target:      $target"
echo "compiler:    $(rustc -vV | sed -n 's/^release: /rustc /p')"
echo "symbol:      $symbol"
echo "instructions: $(grep -cE '^\s+[a-z]' "$body")"
echo "conditional branches:"
grep -nE "^\s+$branches" "$body" || echo "  (none)"
echo "assembly:    $body"
