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

# Arguments: a target triple, and `--accept` to record what this run found as
# the counts a reading accounts for.
accept=no
target_arg=""
for arg in "$@"; do
    case $arg in
        --accept) accept=yes ;;
        *) target_arg=$arg ;;
    esac
done
target=${target_arg:-$(rustc -vV | sed -n 's/^host: //p')}
probe=$root/scripts/ct_probe
out=${CT_CODEGEN_OUT:-$root/target/ct-codegen}
mkdir -p "$out"

# The probe carries the generic paths, which are instantiated in it; the
# library carries the rest, so both are emitted and both are searched.
RUSTFLAGS="--emit asm" cargo build --release --manifest-path "$probe/Cargo.toml" \
    --target "$target" -q --target-dir "$out/target"

asm=$(find "$out/target/$target/release" -name '*.s')
[ -n "$asm" ] || { echo "no assembly emitted for $target" >&2; exit 1; }

# A wrapper's whole body is the register shuffling around one call, which is
# tens of instructions at most; anything longer computes something itself.
WRAPPER_INSTRUCTIONS=40

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
# library's mangled symbol otherwise — and the unclassified branches a reading
# has accounted for. What those readings found:
#
#   tag comparison       the key length against the block, the tag length
#                        against the digest
#   CAST-128             the round count (12 or 16, from the key length), the
#                        round index mod 3 selecting F1/F2/F3, and the flag
#                        that selects the constant-time S-box path
#   Twofish              the key length in 64-bit words, and the same flag
#   ChaCha20 keystream   the message length and the buffered offset, at block
#                        boundaries
#   Poly1305             the message length, whole blocks and the tail
#   X25519, X448         the ladder's loop over the scalar's bits
#   X25519 agreement     RFC 7748 §6.1's all-zero shared-secret test, which is
#                        the value the function returns
#   AEAD open            the §2.8 length bound, two zero-size tests before the
#                        MAC input is freed, and the authentication result
#
# None of them tests a key, a scalar, a tag or a plaintext byte.
claims=(
    "tag-comparison:verify_tag"
    "aes128-ct:Aes128Ct.*encrypt_block"
    "camellia128-ct:camellia128_ct_encrypt_block|Camellia128Ct.*encrypt_block"
    "cast128-ct:cast128_ct_encrypt_block|Cast128Ct.*encrypt_block"
    "des-ct:des_ct_encrypt_block|DesCt.*encrypt_block"
    "grasshopper-ct:grasshopper_ct_encrypt_block|GrasshopperCt.*encrypt_block"
    "magma-ct:magma_ct_encrypt_block|MagmaCt.*encrypt_block"
    "present80-ct:present80_ct_encrypt_block|Present80Ct.*encrypt_block"
    "seed-ct:seed_ct_encrypt_block|SeedCt.*encrypt_block"
    "sm4-ct:sm4_ct_encrypt_block|Sm4Ct.*encrypt_block"
    "twofish128-ct:twofish128_ct_encrypt_block|Twofish128Ct.*encrypt_block"
    "serpent128:serpent128_encrypt_block|Serpent128.*encrypt_block"
    "x25519-ladder:X255196scalar|X25519.*scalar_mult"
    "x448-ladder:X4486scalar|X448.*scalar_mult"
    "x25519-agree:x25519_agree|X25519PrivateKey.*agree:d0"
    "chacha20-keystream:chacha20_keystream|ChaCha2015apply_keystream"
    "poly1305-mac:poly1305_one_shot|modes8poly130512poly1305_mac"
    "chacha20poly1305-open:chacha20poly1305_open|ChaCha20Poly1305.*decrypt_in_place:d0"
)
# What a reading accounted for, per target: how a compiler lays the same source
# out differs, so the counts are recorded per triple and `--accept` rewrites
# them after a person has read the listing.
budgets=$root/scripts/ct_budgets/$target.txt
expected() {
    [ -f "$budgets" ] || { echo 0; return; }
    awk -v claim="$1" '$1 == claim { print $2; found = 1 } END { if (!found) print 0 }' "$budgets"
}
unread=0
rm -f "$out/$target.budgets"
for entry in "${claims[@]}"; do
    claim=${entry%%:*}
    rest=${entry#*:}
    # name:pattern[:dN], where dN is how far to follow this claim's own calls.
    # A composite operation whose parts are claims of their own takes d0, so
    # each piece is read once, where it is made.
    depth=${rest##*:}
    case $depth in
        d[0-9]) depth=${depth#d}; pattern=${rest%:*} ;;
        *) depth=3; pattern=$rest ;;
    esac
    budget=$(expected "$claim")
    # `set -o pipefail` would make a no-match exit the script before the
    # message below is printed.
    file=$(grep -lE "^[._a-zA-Z0-9\$]*($pattern)[._a-zA-Z0-9\$]*:" $asm | head -1 || true)
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
    # A wrapper is a short body that branches nowhere and hands the work to
    # exactly one callee, by tail jump or by call; follow it to the code that
    # does the work, wherever that was emitted. A body that does work of its
    # own, even if it calls one helper, is the claim itself and is kept.
    for _ in 1 2 3 4; do
        [ "$(grep -cE '^[[:space:]]+[a-z]' "$body" || true)" -le "$WRAPPER_INSTRUCTIONS" ] || break
        grep -qE "^[[:space:]]+$branches" "$body" && break
        # A call may go through the GOT, which spells the symbol with a `*`
        # and a relocation suffix; the name in between is the callee.
        callee=$(grep -oE '^[[:space:]]+(b|bl|jmp|jmpq|call|callq)[[:space:]]+\*?[._a-zA-Z0-9$]+(@GOTPCREL\(%rip\))?$' "$body" \
                 | awk '{print $2}' | sed 's/@GOTPCREL(%rip)$//; s/^\*//' | sort -u || true)
        [ "$(printf '%s' "$callee" | grep -c .)" -eq 1 ] || break
        callee_file=$(grep -lE "^${callee}:" $asm | head -1 || true)
        [ -n "$callee_file" ] || break
        extract "$callee" "$callee_file" > "$body.next"
        [ -s "$body.next" ] || { rm -f "$body.next"; break; }
        mv "$body.next" "$body"
        symbol=$callee
    done
    # The claim is the code this operation runs, so a function it calls is
    # part of it: append each callee's body, and each of theirs, so a branch
    # in a helper is not missed by looking only at the caller. Only this
    # crate's own functions are followed — a call into the allocator or a
    # panicking function ends a path the classification already names.
    callees_of() {
        grep -oE '^[[:space:]]+(bl|call|callq|b|jmp|jmpq)[[:space:]]+\*?[._a-zA-Z0-9$]+(@GOTPCREL\(%rip\))?$' "$1" \
            | awk '{print $2}' | sed 's/@GOTPCREL(%rip)$//; s/^\*//' \
            | grep -E 'cryptography|rump' | sort -u || true
    }
    seen=" $symbol "
    queue=$(callees_of "$body")
    hop=0
    while [ "$hop" -lt "$depth" ]; do
        hop=$((hop + 1))
        next=""
        for callee in $queue; do
            case $seen in *" $callee "*) continue ;; esac
            seen="$seen$callee "
            callee_file=$(grep -lE "^${callee}:" $asm | head -1 || true)
            [ -n "$callee_file" ] || continue
            extract "$callee" "$callee_file" > "$body.part"
            [ -s "$body.part" ] || continue
            cat "$body.part" >> "$body"
            next="$next $(callees_of "$body.part")"
        done
        rm -f "$body.part"
        [ -n "$next" ] || break
        queue=$next
    done
    reached=$(( $(printf '%s' "$seen" | wc -w) - 1 ))
    echo
    echo "$claim: $(grep -cE '^[[:space:]]+[a-z]' "$body" || true) instructions in $symbol"
    [ "$reached" -eq 0 ] || echo "  with $reached function(s) it calls"
    grep -nE "^[[:space:]]+$branches" "$body" | cut -d: -f1 > "$body.branches" || true
    if [ -s "$body.branches" ]; then
        classify "$body.branches" "$body" "$body.unread"
    else
        echo "  no conditional branches"
        echo 0 > "$body.unread"
    fi
    echo "  assembly: $body"
    found=$(cat "$body.unread")
    printf '%s %s\n' "$claim" "$found" >> "$out/$target.budgets"
    if [ "$found" -gt "$budget" ]; then
        echo "  UNREAD: $found unclassified branches, $budget accounted for" >&2
        unread=1
    fi
done

if [ "$accept" = yes ]; then
    mkdir -p "$(dirname "$budgets")"
    mv "$out/$target.budgets" "$budgets"
    echo
    echo "recorded $(grep -c . "$budgets") claims in $budgets"
    exit 0
fi
rm -f "$out/$target.budgets"

[ "$unread" -eq 0 ] || {
    echo >&2
    echo "A claim gained a branch this script cannot name. Read it, and either" >&2
    echo "record it with the claim or fix the code it came from." >&2
    exit 1
}
