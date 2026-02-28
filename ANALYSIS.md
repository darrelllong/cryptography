# ANALYSIS — Algorithms, Design Decisions, and Performance

Explains why each cipher family is structured as it is: the algorithmic
background, key design choices, and measured throughput, including the
software fast-vs-constant-time tradeoff for the ciphers that expose separate
`Ct` variants.

---

## Common API

Every cipher struct implements the `BlockCipher` trait:

```rust
pub trait BlockCipher {
    const BLOCK_LEN: usize;
    fn encrypt(&self, block: &mut [u8]);
    fn decrypt(&self, block: &mut [u8]);
}
```

The `encrypt_block` / `decrypt_block` methods taking typed `&[u8; N]` arrays
remain on each struct for callers that know the block size at compile time.
The trait methods provide a uniform interface for generic code such as the
throughput benchmarks.

---

## Simon

Simon (Beaulieu et al., NSA 2013) is a Feistel cipher optimised for hardware.
Its round function is:

```
f(x) = (S¹x & S⁸x) ⊕ S²x
```

where `Sⁿ` denotes left-rotation by n bits.  The AND of two rotations is the
intentional hardware-friendly nonlinearity.  Each encrypt round reads one
64-bit round key and performs five rotation-and-XOR operations — cheap on any
64-bit ALU but expensive in software relative to the equivalent circuit area.

### Key schedule

The key schedule expands `m` key words into `T` round keys using the recurrence

```
kᵢ = (~k_{i-m}) ⊕ (I ⊕ S⁻¹)(S⁻³(k_{i-1})) ⊕ zⱼ[(i-m) mod 62] ⊕ 3
```

where `zⱼ` is one of five 62-bit LFSR constants tabulated in the paper.  Five
Z sequences cover all ten variants; `j` is chosen to provide maximum algebraic
separation between the subkey stream and the plain constant `3`.

The round-key array is a compile-time fixed-size `[u64; T]` stack allocation,
avoiding any heap use.  Key expansion runs once at construction time and is not
included in the throughput measurements.

### Implementation notes

Byte convention follows the NSA C reference: the two block words are stored
little-endian with `x` (the word entering `f`) first; key words are stored
little-endian with `k₀` first.  This matches the paper's Appendix B test
vectors exactly.

The `simon_variant!` macro instantiates all ten structs from a single
parameterised definition.  A `z`-sequence index is a macro argument because
it selects a compile-time constant expression; no runtime dispatch occurs.

---

## Speck

Speck (Beaulieu et al., NSA 2013) is an Add-Rotate-XOR (ARX) cipher whose
round function is:

```
x ← (S^{-α}(x) + y) ⊕ k       right-rotate x by α, add y mod 2ⁿ, XOR k
y ← S^β(y) ⊕ x                 left-rotate y by β, XOR new x
```

For Speck32/64 the rotation constants are `(α,β) = (7,2)`; for all other
variants they are `(8,3)`.  Addition, rotation, and XOR map to exactly three
native 64-bit instructions — the tightest possible round function.

### Why Speck is faster than Simon

Simon's round function requires two rotations plus an AND before the final
XOR, and AND is not invertible, so the inverse round differs structurally
from the forward round.  Speck's ARX round is self-inverse with only sign
changes; the compiler produces nearly identical code for encrypt and decrypt.
More importantly, 64-bit add/rotate/XOR fully exploit the integer execution
units of modern 64-bit CPUs.  At 128-bit block size (64-bit word), Speck
exceeds 1 GiB/s on Apple M4; no other cipher in this suite reaches that rate
without hardware acceleration.

### Key schedule

The Speck key schedule uses a 40-entry stack `ℓ`-array (the theoretical
maximum across all variants) and no heap allocation.  `ℓ` stores only the
`m−1` "side" words needed for the next round, overwritten in place.

---

## AES

AES (FIPS 197) uses a byte-substitution, row-shift, column-mix, and key-add
round structure operating in GF(2⁸).

### T-table implementation

The standard software optimisation fuses SubBytes, ShiftRows, and MixColumns
into four 256-entry 32-bit lookup tables `TE0–TE3` (encryption) and
`TD0–TD3` (decryption).  Each table entry precomputes, for one byte input
value `v`, the full 32-bit column contribution after mixing:

```
TE0[v] = {mul2(S[v]),  S[v],       S[v],       mul3(S[v])}  (big-endian)
```

Processing four 8-bit byte lanes in parallel with table lookups reduces a
round to 16 table reads and 12 XOR operations per 128-bit block.  All
GF(2⁸) multiplications are precomputed at compile time; none occur at
encryption time.

Decryption uses the inverse tables `TD0–TD3` constructed from `INV_SBOX`
and the inverse MixColumns coefficients `{0x0e, 0x0b, 0x0d, 0x09}`.

### Key expansion

Key expansion produces round keys at construction time.  The 10/12/14-round
schedules for AES-128/192/256 are precomputed into fixed-size arrays
`[u32; 44]`, `[u32; 52]`, `[u32; 60]` respectively.  Separate encryption
and decryption round-key arrays are stored so that neither encrypt nor
decrypt requires runtime inversion.

### No hardware AES-NI

The implementation is pure portable Rust.  It does not emit AES-NI
instructions.  On Apple M4, hardware AES (via ARM cryptography extensions)
would be faster, but that would require unsafe intrinsics or a separate
dependency.  The T-table implementation achieves 537 MiB/s for AES-128 — a
useful baseline for the cost of a portable implementation.

---

## DES and Triple-DES

DES (FIPS PUB 46-3) is a 16-round Feistel cipher operating on 64-bit blocks
with a 56-bit effective key.  Each round applies the f-function:

```
f(R, K) = P(S(E(R) ⊕ K))
```

where E expands 32 bits to 48, S passes 8 × 6-bit groups through eight
4×16 S-boxes, and P permutes the resulting 32 bits.

Triple-DES (TDEA, NIST SP 800-67) wraps three DES operations in
Encrypt-Decrypt-Encrypt order:

```
Encrypt:  C = E(K3, D(K2, E(K1, P)))
Decrypt:  P = D(K1, E(K2, D(K3, C)))
```

Keying option 1 (3TDEA): K1, K2, K3 independent (24-byte key, 112-bit
effective security).  Keying option 2 (2TDEA): K1 = K3 ≠ K2 (16-byte key,
80-bit effective security).

### Why DES is slow in software

DES was designed for efficient 1970s *hardware* implementation, not software.
Every round includes three bit permutations:

- **E (expansion)**: 32 → 48 bits by replicating boundary bits
- **P (P-box)**: 32-bit permutation of S-box output
- **IP / FP**: 64-bit initial and final permutations on the entire block

The implementation follows FIPS 46-3 exactly, computing each permutation bit
by bit via a loop over the specification table.  For the 16 Feistel rounds,
this amounts to 1408 individual bit-extract-and-place operations per block:

```
IP   (64)  +  16 × [E (48) + P (32)]  +  FP (64)  =  1408 bit ops
```

These operations do not map to native instructions on any common ISA.  The
compiler unrolls and pipelines them, but cannot eliminate the fundamental
serial data dependency: each output bit depends on a different input bit,
preventing SIMD or word-parallel execution.

The implementation uses precomputed byte-level lookup tables for IP, FP, and E
— the same technique AES uses for MixColumns.  Each 64-bit permutation becomes
8 table lookups; the 48-bit expansion becomes 4.  The tables are computed once
at compile time via `const fn` and stored in `.rodata`; none of the 1408
bit-level loop iterations appear in the hot path.  The byte-table step alone
gives a 2.6× speedup over bit-by-bit permutations (18 → 47 MiB/s).

The further optimisation — fusing the 8 S-boxes and the 32-bit P permutation
into a single `SP_TABLE[8][64]` — eliminates the separate P step entirely.
Because P is a linear bit permutation, it distributes over OR:

```
P(s₀ | s₁ | … | s₇) = P(s₀) | P(s₁) | … | P(s₇)
```

Each `SP_TABLE[i][b6]` entry stores the P-permuted contribution of S-box i for
6-bit input `b6`, precomputed at compile time by `build_sp()` (a `const fn`
that calls `apply_p_to_partial` for every entry).  The f-function becomes 1
expand + 8 SP lookups per round — 8 KiB for E_TABLE plus 2 KiB for SP_TABLE,
both comfortably in L1 cache.  The 43 NIST CAVP vectors still pass unchanged.

---

## Magma

Magma (GOST R 34.12-2015, RFC 8891) is a 32-round Feistel cipher with a 64-bit
block and 256-bit key.  It is standardised from the earlier GOST 28147-89 cipher,
differing primarily in having published, fixed S-boxes rather than secret ones.

### Round function

The round function `g[k](a)` operates on a 32-bit half-block:

```
g[k](a) = rotl₁₁(t(a + k mod 2³²))
```

where `t` applies eight independent 4-bit S-boxes (`Pi'_0 .. Pi'_7`) to the eight
nibbles of the 32-bit word, and `rotl₁₁` rotates the result left by 11 bits.

Each Feistel step is:

```
G[k](a₁, a₀) = (a₀,  g[k](a₀) ⊕ a₁)       — swap after applying g
G*[k](a₁, a₀) = (g[k](a₀) ⊕ a₁) ‖ a₀      — no swap; used for the final round
```

Both encryption and decryption apply 31 rounds of `G` followed by one `G*`;
the only difference is the round-key order.

### Key schedule

The 256-bit key is split into eight 32-bit subkeys `k[0]..k[7]` (big-endian).
The 32 encryption round keys repeat the subkeys in a fixed pattern:

```
Rounds  1–8:  k[0], k[1], …, k[7]   (forward)
Rounds  9–16: k[0], k[1], …, k[7]   (forward, again)
Rounds 17–24: k[0], k[1], …, k[7]   (forward, again)
Rounds 25–32: k[7], k[6], …, k[0]   (reversed)
```

Decryption uses the exact reverse of this sequence — equivalent to applying
`k[0..8]` once then `k[7..0]` three times — which the implementation builds by
reversing the encryption array.

### Why Magma is slower than DES

Magma has 32 rounds while DES has 16.  Magma's individual round is cheaper — one
wrapping add, 8 nibble table lookups, and one rotate — whereas DES includes the
E-expansion and P-box bit permutations even with SP-table fusion.  The net effect
is comparable throughput (Magma ~64 MiB/s, DES ~78 MiB/s), with Magma's 2×
round count roughly offsetting its simpler round function.

---

## Performance benchmarks

### Measurement methodology

Benchmarks use Criterion 0.5 (`cargo bench --bench cipher_bench`).
Each cipher encrypts a 1 MiB buffer in ECB mode; the buffer is prepared by
`iter_batched` so allocation and fill are excluded from the timed region.
The reported figure is the median throughput across 100 samples.  All
measurements are on Apple M4, 10-core, 32 GiB, macOS 15.

**1 GiB time** is computed as `1024 MiB / throughput` and represents
the projected time to encrypt 1 GiB at the measured rate.

### Fast vs Ct software variants

The crate now exposes separate software-only `Ct` variants for AES, DES,
Magma, and Grasshopper. These are intentionally measured separately from the
long-run baseline tables above: the goal here is relative cost, not an
absolute "best possible" throughput number.

The figures below come from the short Criterion sanity runs used during the
implementation work:

```text
cargo bench --manifest-path benchmarks/Cargo.toml --bench cipher_bench -- \
  --sample-size 10 --measurement-time 0.2 --warm-up-time 0.1 '<group>/'
```

Each row reports the midpoint throughput from that short run over the same
1 MiB ECB harness used by the main benchmark.

| Cipher | Fast path | Ct path | Slowdown |
|--------|----------:|--------:|---------:|
| AES-128 | 529.4 MiB/s | 61.5 MiB/s | 8.6x |
| AES-192 | 435.4 MiB/s | 49.7 MiB/s | 8.8x |
| AES-256 | 368.8 MiB/s | 41.9 MiB/s | 8.8x |
| DES | 79.5 MiB/s | 8.2 MiB/s | 9.7x |
| Magma-256 | 61.9 MiB/s | 14.1 MiB/s | 4.4x |
| Grasshopper-256 | 25.6 MiB/s | 4.1 MiB/s | 6.3x |

These ratios line up with the implementation strategy:

- `Aes*Ct` keeps the bytewise AES round structure, but each S-box is a
  Boyar-Peralta straight-line boolean circuit instead of a T-table lookup.
- `DesCt` keeps the normal DES round function, but evaluates E/P with fixed
  loops and the S-boxes through packed ANF bitsets instead of the byte tables
  and fused `SP_TABLE`.
- `MagmaCt` only changes the eight 4-bit S-boxes, so it pays the smallest
  penalty of the four.
- `GrasshopperCt` removes both the table-driven S-box and the `L_TABLES`
  shortcuts, so it remains the slowest of the Ct variants in absolute terms.

### Simon

| Variant | Block | Key | Throughput | 1 GiB |
|---------|------:|----:|-----------:|------:|
| Simon32/64 | 32 b | 64 b | 84 MiB/s | 12.2 s |
| Simon48/72 | 48 b | 72 b | 109 MiB/s | 9.4 s |
| Simon48/96 | 48 b | 96 b | 109 MiB/s | 9.4 s |
| Simon64/96 | 64 b | 96 b | 141 MiB/s | 7.3 s |
| Simon64/128 | 64 b | 128 b | 134 MiB/s | 7.6 s |
| Simon96/96 | 96 b | 96 b | 140 MiB/s | 7.3 s |
| Simon96/144 | 96 b | 144 b | 133 MiB/s | 7.7 s |
| Simon128/128 | 128 b | 128 b | 253 MiB/s | 4.0 s |
| Simon128/192 | 128 b | 192 b | 248 MiB/s | 4.1 s |
| Simon128/256 | 128 b | 256 b | 235 MiB/s | 4.4 s |

Simon throughput increases with word size, because the same three
rotation-and-XOR operations process more bits per instruction as `n` grows
from 16 to 64.  The 128-bit variants (64-bit words) are 3× faster than the
32-bit variant (16-bit words).  Extra key words (Simon64/96 vs Simon64/128:
42 vs 44 rounds) cause a modest throughput penalty.

### Speck

| Variant | Block | Key | Throughput | 1 GiB |
|---------|------:|----:|-----------:|------:|
| Speck32/64 | 32 b | 64 b | 209 MiB/s | 4.9 s |
| Speck48/72 | 48 b | 72 b | 306 MiB/s | 3.3 s |
| Speck48/96 | 48 b | 96 b | 269 MiB/s | 3.8 s |
| Speck64/96 | 64 b | 96 b | 323 MiB/s | 3.2 s |
| Speck64/128 | 64 b | 128 b | 308 MiB/s | 3.3 s |
| Speck96/96 | 96 b | 96 b | 397 MiB/s | 2.6 s |
| Speck96/144 | 96 b | 144 b | 378 MiB/s | 2.7 s |
| Speck128/128 | 128 b | 128 b | 1002 MiB/s | 1.0 s |
| Speck128/192 | 128 b | 192 b | 981 MiB/s | 1.0 s |
| Speck128/256 | 128 b | 256 b | 945 MiB/s | 1.1 s |

Speck is uniformly 2–4× faster than Simon at the same block/key size.  The
ARX round function uses no AND operations and compiles to three instructions
on a 64-bit target; Simon's `f` requires two extra rotations and an AND.
Speck128/128 exceeds 1 GiB/s, reflecting that the M4's 64-bit integer
pipeline can sustain roughly one ARX round per cycle at 32 rounds depth.

### AES (pure Rust, T-table)

| Variant | Block | Key | Rounds | Throughput | 1 GiB |
|---------|------:|----:|-------:|-----------:|------:|
| AES-128 | 128 b | 128 b | 10 | 537 MiB/s | 1.9 s |
| AES-192 | 128 b | 192 b | 12 | 441 MiB/s | 2.3 s |
| AES-256 | 128 b | 256 b | 14 | 375 MiB/s | 2.7 s |

AES throughput decreases linearly with round count (10/12/14): the T-table
implementation is round-dominated, with each round costing roughly the same
16 lookups + 12 XORs regardless of variant.  AES-128 is 43% faster than
AES-256 (537 vs 375 MiB/s), close to the 14/10 = 1.4 ratio predicted by
round-count scaling.

AES-128 at 537 MiB/s is 2.1× faster than Simon128/128 (253 MiB/s) and
2× slower than Speck128/128 (1002 MiB/s).  These relative positions reflect
the cost of the 256-entry table lookups (with potential cache pressure at 4
tables × 1 KiB = 4 KiB): the table-driven nonlinearity costs more than Speck's
arithmetic nonlinearity but far less than Simon's multi-rotation AND structure.

### DES / Triple-DES

| Variant | Block | Effective key | Throughput | 1 GiB |
|---------|------:|--------------:|-----------:|------:|
| DES | 64 b | 56 b | 78 MiB/s | 13.1 s |
| 3DES-2key (EDE) | 64 b | 80 b | 23 MiB/s | 44 s |
| 3DES-3key (EDE) | 64 b | 112 b | 23 MiB/s | 44 s |

DES at 78 MiB/s is the result of two successive compile-time table optimisations:

1. **Byte-level permutation tables** for IP, FP, and E reduce 1408 bit-by-bit
   operations to table lookups (18 → 47 MiB/s, 2.6×).
2. **Fused S+P table** (`SP_TABLE[8][64]`) combines all eight S-boxes and the
   P permutation into a single 2 KiB table: 8 lookups per round instead of
   8 S-box + 4 P lookups (47 → 78 MiB/s, 1.66×).

Both sets of tables are computed at compile time via `const fn`; neither adds
runtime allocation or unsafe code.  The total speedup from raw bit-by-bit is
78 / 18 ≈ 4.3×.

3DES-2key and 3DES-3key run at the same throughput (23 MiB/s) because both
perform exactly three DES block operations per plaintext block regardless of
key option.  The 3× overhead gives approximately 1/3 the DES rate
(78 / 3 ≈ 26 MiB/s theoretical; measured 23 MiB/s).

### Magma

| Variant | Block | Key | Rounds | Throughput | 1 GiB |
|---------|------:|----:|-------:|-----------:|------:|
| Magma-256 | 64 b | 256 b | 32 | 64 MiB/s | 16.0 s |

Magma achieves ~64 MiB/s — comparable to DES (78 MiB/s) despite a 256-bit key
and 32 rounds.  The round function has no bit permutations: just a wrapping add,
8 nibble-level table lookups, and a 32-bit rotate.  The 2× round count relative
to DES is nearly offset by the simpler per-round work.

### Summary

| Cipher | Best throughput | Worst throughput |
|--------|----------------:|-----------------:|
| Speck | 1002 MiB/s (128/128) | 209 MiB/s (32/64) |
| AES | 537 MiB/s (128) | 375 MiB/s (256) |
| Simon | 253 MiB/s (128/128) | 84 MiB/s (32/64) |
| DES | 78 MiB/s | — |
| Magma | 64 MiB/s | — |
| 3DES | — | 23 MiB/s (2-key or 3-key) |

Speck128/128 is the fastest cipher in the suite.  DES, Magma, and 3DES are
13–44× slower than the best Speck variants because both DES's bit permutations
and Magma's 32 rounds are inherently expensive in software.  For applications
requiring 64-bit blocks and high throughput, Speck64/128 (308 MiB/s) is the
natural choice.

---

## References

- R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, and L. Wingers.
  The SIMON and SPECK Families of Lightweight Block Ciphers.
  *IACR Cryptology ePrint Archive*, Report 2013/404, 2013.

- National Institute of Standards and Technology.
  *Advanced Encryption Standard (AES)*.
  Federal Information Processing Standard FIPS 197, November 2001.

- National Institute of Standards and Technology.
  *Data Encryption Standard (DES)*.
  Federal Information Processing Standard FIPS 46-3, October 1999.

- National Institute of Standards and Technology.
  *Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher*.
  NIST Special Publication 800-67 Revision 2, November 2017.

- N.J. Daemen and V. Rijmen.
  *The Design of Rijndael: AES — The Advanced Encryption Standard*.
  Springer, 2002.

- V. Dolmatov and A. Degtyarev.
  *GOST R 34.12-2015: Block Cipher "Magma"*.
  RFC 8891, IETF, September 2020.
