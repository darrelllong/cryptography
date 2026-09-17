#!/usr/bin/env bash
# Emit the machine code behind the crate's constant-time claims and classify
# the conditional branches in it.
#
#   scripts/ct_codegen.sh [target-triple]
#
# The probe crate wraps each claim in an `#[inline(never)]` function, so each
# keeps a symbol of its own: the tag comparison behind every MAC and AEAD
# check, the bitsliced AES-128, and the X25519 and X448 ladders. The release
# assembly of each symbol is extracted and every conditional branch in it is
# listed under one of three kinds:
#
#   loop back-edge  branches to a label above it, so it closes a loop whose
#                   trip count the source fixes;
#   failure guard   branches to a panic, a slice-index failure, the
#                   allocation-error handler or a trap, so it checks an index,
#                   a length or an allocation;
#   unclassified    everything else, which a person must read.
#
# What to look for: every branch must be over a public value, which here means
# lengths, fixed loop counts and indices derived from them. A branch that
# tests a key, a secret scalar, a tag or a plaintext byte is a secret-dependent
# branch, and the claim for that function no longer holds on that target and
# compiler. The first two kinds are public by construction; the unclassified
# ones are the reading list, and `src/ct.rs`, `src/ciphers/aes.rs` and the two
# ladder modules record what they turned out to be.
#
# Each claim carries the number of unclassified branches that reading covers,
# and the script fails when a target or a compiler produces more than that, so
# a new branch is read before the claim is repeated.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
probe=$root/scripts/ct_probe
out=${CT_CODEGEN_OUT:-$root/target/ct-codegen}
mkdir -p "$out"

# The probe carries the generic paths, which are instantiated in it; the
# library carries the rest, so both are emitted and both are searched.
RUSTFLAGS="--emit asm" cargo build --release --manifest-path "$probe/Cargo.toml" \
    --target "$target" -q --target-dir "$out/target"

asm=$(find "$out/target/$target/release" -name '*.s')
[ -n "$asm" ] || { echo "no assembly emitted for $target" >&2; exit 1; }

case $target in
    aarch64*) branches='\b(b\.[a-z]+|cbn?z|tbn?z)\b' ;;
    x86_64*)  branches='\bj(n?[abegloszcp]|n?[ab]e|n?ge|n?le)\b' ;;
    *)        branches='\b(b\.[a-z]+|cbn?z|tbn?z|j[a-z]+)\b' ;;
esac

# classify <branch-line-numbers> <assembly>: name each branch by where it goes.
# A branch to a label above it closes a loop. A branch whose target reaches a
# diverging failure — a panic, a slice-index failure, the allocation-error
# handler, a trap — guards an index, a length or an allocation. The rest is
# for a person to read.
classify() {
    awk -v countfile="$3" '
        # The call, jump or return that decides what the block at `at` does,
        # following unconditional jumps to where they land.
        function fate(at,   hops, j, fields, field, target) {
            for (hops = 0; hops < 4; hops++) {
                for (j = at + 1; j <= lines; j++)
                    if (line[j] ~ /^[ \t]+(bl|call|ret|b|jmp|brk|ud2)q?([ \t]|$)/) break
                if (j > lines) return ""
                if (line[j] !~ /^[ \t]+(b|jmp)q?([ \t]|$)/) return line[j]
                fields = split(line[j], field, /[ \t,]+/)
                target = field[fields]
                if (!(target in label)) return line[j]
                at = label[target]
            }
            return ""
        }

        NR == FNR { branch[$1]; next }
        { line[FNR] = $0; lines = FNR }
        /^[._A-Za-z0-9$]+:/ { label[substr($0, 1, index($0, ":") - 1)] = FNR }
        END {
            for (i = 1; i <= lines; i++) {
                if (!(i in branch)) continue
                fields = split(line[i], field, /[ \t,]+/)
                target = field[fields]
                kind = "unclassified"
                if (target in label) {
                    if (label[target] < i)
                        kind = "loop back-edge"
                    else if (fate(label[target]) ~ /panic|_fail|handle_error|abort|brk|ud2/)
                        kind = "failure guard"
                }
                seen[kind]++
                total++
                text = line[i]
                sub(/^[ \t]+/, "", text)
                gsub(/[ \t]+/, " ", text)
                listing = listing sprintf("    %6d  %-28s %s\n", i, text, kind)
            }
            summary = ""
            split("loop back-edge,failure guard,unclassified", kinds, ",")
            for (k = 1; k <= 3; k++)
                if (kinds[k] in seen)
                    summary = summary sprintf("%s%d %s", summary == "" ? "" : ", ", \
                                              seen[kinds[k]], kinds[k])
            printf "  branches: %d (%s)\n%s", total, summary, listing
            print seen["unclassified"] + 0 > countfile
        }
    ' "$1" "$2"
}

echo "target:   $target"
echo "compiler: $(rustc -vV | sed -n 's/^release: /rustc /p')"

# Each claim: its name, a pattern matching the symbol that carries it — the
# probe's own wrapper where the code is generic and instantiated there, the
# library's mangled symbol otherwise — and the unclassified branches the
# modules have read and accounted for.
claims=(
    "tag-comparison:verify_tag:2"
    "aes128-ct:Aes128Ct.*encrypt_block:0"
    "x25519-ladder:X255196scalar|X25519.*scalar_mult:1"
    "x448-ladder:X4486scalar|X448.*scalar_mult:2"
    "x25519-agree:x25519_agree|X25519PrivateKey.*agree:1"
    "chacha20poly1305-open:chacha20poly1305_open|ChaCha20Poly1305.*decrypt_in_place:4"
)
unread=0
for entry in "${claims[@]}"; do
    claim=${entry%%:*}
    rest=${entry#*:}
    pattern=${rest%:*}
    budget=${rest##*:}
    file=$(grep -lE "^[._a-zA-Z0-9\$]*($pattern)[._a-zA-Z0-9\$]*:" $asm | head -1)
    [ -n "$file" ] || { echo "$claim: no symbol matching $pattern" >&2; exit 1; }
    symbol=$(grep -oE "^[._a-zA-Z0-9\$]*($pattern)[._a-zA-Z0-9\$]*:" "$file" | head -1 | tr -d ':')
    body=$out/$target-$claim.s
    extract() {
        awk -v sym="$1" '
            index($0, sym ":") == 1 { printing = 1 }
            printing { print }
            printing && /\.cfi_endproc/ { exit }
        ' "$2"
    }
    extract "$symbol" "$file" > "$body"
    [ -s "$body" ] || { echo "$claim: no body extracted for $symbol" >&2; exit 1; }
    # A wrapper is a body that branches nowhere and hands the work to exactly
    # one callee, by tail jump or by call; follow it to the code that does the
    # work, wherever that was emitted.
    for _ in 1 2 3 4; do
        grep -qE "^[[:space:]]+$branches" "$body" && break
        # A call may go through the GOT, which spells the symbol with a `*`
        # and a relocation suffix; the name in between is the callee.
        callee=$(grep -oE '^[[:space:]]+(b|bl|jmp|jmpq|call|callq)[[:space:]]+\*?[._a-zA-Z0-9$]+(@GOTPCREL\(%rip\))?$' "$body" \
                 | awk '{print $2}' | sed 's/@GOTPCREL(%rip)$//; s/^\*//' | sort -u)
        [ "$(printf '%s' "$callee" | grep -c .)" -eq 1 ] || break
        callee_file=$(grep -lE "^${callee}:" $asm | head -1 || true)
        [ -n "$callee_file" ] || break
        extract "$callee" "$callee_file" > "$body.next"
        [ -s "$body.next" ] || { rm -f "$body.next"; break; }
        mv "$body.next" "$body"
        symbol=$callee
    done
    if ! grep -qE "^[[:space:]]+$branches" "$body" \
       && grep -qE '^[[:space:]]+(bl|call|callq)[[:space:]]' "$body"; then
        echo "$claim: $symbol branches nowhere but calls out; the work is in a" >&2
        echo "  callee this script could not follow, so nothing was inspected." >&2
        exit 1
    fi
    echo
    echo "$claim: $(grep -cE '^[[:space:]]+[a-z]' "$body") instructions in $symbol"
    grep -nE "^[[:space:]]+$branches" "$body" | cut -d: -f1 > "$body.branches" || true
    if [ -s "$body.branches" ]; then
        classify "$body.branches" "$body" "$body.unread"
    else
        echo "  no conditional branches"
        echo 0 > "$body.unread"
    fi
    echo "  assembly: $body"
    if [ "$(cat "$body.unread")" -gt "$budget" ]; then
        echo "  UNREAD: $(cat "$body.unread") unclassified branches, $budget accounted for" >&2
        unread=1
    fi
done

[ "$unread" -eq 0 ] || {
    echo >&2
    echo "A claim gained a branch this script cannot name. Read it, and either" >&2
    echo "record it with the claim or fix the code it came from." >&2
    exit 1
}
