# SYMMETRIC

The symmetric side follows the same project-wide implementation rule as the
rest of the crate: pure idiomatic Rust, no C/FFI, and as few dependencies as
possible. Architecture intrinsics are intentionally avoided in the cipher
cores; the only intrinsic path in the in-tree library is an aarch64
`FEAT_SHA3` Keccak-f[1600] fast path, gated on runtime feature detection,
with the portable scalar Keccak as the always-correct fallback. Where a fast
table-driven path and a portable software constant-time path pull in
different directions, the crate keeps both visible rather than hiding the
tradeoff.

## Common Block-Cipher API

Every block cipher implements:

```rust
pub trait BlockCipher {
    const BLOCK_LEN: usize;
    fn encrypt(&self, block: &mut [u8]);
    fn decrypt(&self, block: &mut [u8]);
}
```

Most block-cipher types also expose typed `encrypt_block` / `decrypt_block`
helpers for callers that know the block size at compile time.

The dedicated `Ct` types are the software constant-time variants. They exist
only where the portable fast implementation would otherwise rely on
secret-indexed table lookups or similarly awkward software tradeoffs. `SIMON`
and `SPECK` do not have separate `Ct` types because their shipped round
functions are already table-free ARX / bitwise designs.

## Modes, Hashes, and MACs

### Recent Additions

The following primitives were completed during the most recent round of work.
The focus was filling in missing hash and mode surface APIs rather than adding
new block-cipher families.

- Hashes completed for compatibility: `Md5`, `Sha1`
- Stream-cipher extended-nonce variant: `XChaCha20`
- AEAD and misuse-resistant modes:
  `Eax`, `Ocb`, `Siv`, `AesGcmSiv<C>` (aliases `Aes128GcmSiv`, `Aes256GcmSiv`
  on the T-table AES and `Aes128GcmSivCt`, `Aes256GcmSivCt` on the
  constant-time AES), `ChaCha20Poly1305`
- AES key wrapping surface: `AesKeyWrap`

### Modes

The generic mode layer in `src/modes/` supplies:

- SP 800-38A: `Ecb`, `Cbc`, `Cfb`, `Cfb8`, `Ofb`, `Ctr`
- SP 800-38B: `Cmac`
- SP 800-38C: `Ccm`
- SP 800-38D: `Gcm`, `GcmVt`, `Gmac`, `GmacVt`
- SP 800-38E: `Xts`
- SP 800-38F / RFC 3394: `AesKeyWrap` (no-padding AES key wrap)
- RFC 5297: `Siv`
- RFC 7253: `Ocb`
- Bellare-Rogaway-Wagner EAX: `Eax`
- RFC 8452: `AesGcmSiv<C>` (`Aes128GcmSiv`, `Aes256GcmSiv`, `Aes128GcmSivCt`, `Aes256GcmSivCt`)
- RFC 8439: `Poly1305`, `ChaCha20Poly1305`

Reference set for the newly added mode paths:

- `Ccm`: NIST SP 800-38C (`pubs/sp800-38c.pdf`)
- `AesKeyWrap`: RFC 3394 and NIST SP 800-38F
  (`pubs/rfc3394-aes-key-wrap.pdf`, `pubs/sp800-38f.pdf`)
- `Siv`: RFC 5297 (`pubs/rfc5297-siv.pdf`)
- `Ocb`: RFC 7253 (`pubs/rfc7253-ocb.pdf`)
- `AesGcmSiv<C>`: RFC 8452 (`pubs/rfc8452-aes-gcm-siv.pdf`); POLYVAL constant-time,
  the AES calls those of `C`
- GCM test cases 3–18: McGrew & Viega, *The Galois/Counter Mode of Operation
  (GCM)*, revised 2005-05-31 (`pubs/mcgrew-viega-2005-gcm-revised-spec.pdf`,
  Internet Archive capture of the NIST-hosted file; Appendix B)
- `Poly1305` / `ChaCha20Poly1305`: RFC 8439 (`pubs/rfc8439-chacha20-poly1305.pdf`)

These wrappers are generic over any `BlockCipher`, so the same mode code works
across AES, DES, Camellia, PRESENT, CAST-128, and the other block ciphers.

Operational caveats:

- `ECB` is included for completeness and test coverage, not because it is a
  good default.
- `CBC`, `CFB`, `OFB`, and block-cipher `CTR` require correct IV / counter
  discipline from the caller.
- `GCM` requires nonce uniqueness and enforces the SP 800-38D per-call payload
  bound of $(2^{32}-2)$ counter blocks (`68_719_476_704` bytes) to prevent
  counter wrap. `Gcm`/`Gmac` are the default constant-time GHASH path and
  `GcmVt`/`GmacVt` are explicit variable-time reference paths whose GHASH
  is variable-time in both operands (the data and the hash subkey `H`).
- `XTS` is for storage-style sector encryption, not general message transport.
  Data units are 1 to 2^20 blocks (`XTS_MAX_DATA_UNIT_BLOCKS`, SP 800-38E §4).
- `Siv` (RFC 5297) accepts at most 2^36 − 16 bytes per message (32-bit counter
  addition, §2.5) and 126 associated-data components (§7); `decrypt` returns
  `false` beyond either bound.

### Hashes and XOFs

Implemented hash families:

- MD5 (`Md5`) for legacy compatibility
- RIPEMD-160 (`Ripemd160`) for legacy compatibility
- SHA-1
- SHA-2: `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`
- SHA-3: `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`
- XOFs: `Shake128`, `Shake256`

Reference set for the newly added hash paths:

- MD5: RFC 1321 (`pubs/rfc1321-md5.pdf`)
- RIPEMD-160: Dobbertin/Bosselaers/Preneel, FSE 1996
  (`pubs/ripemd-160-a-strengthened-version-of-ripemd.pdf`)

SHA-1 / SHA-2 are Merkle-Damgard constructions and therefore inherit the usual
length-extension caveat when used as raw keyed digests. For keyed integrity:

- use `Hmac<H>`
- or prefer SHA-3 / SHAKE if sponge semantics are the better fit

### MACs

Implemented message-authentication layers:

- `Hmac<H>` over any in-tree `Digest`
- `Cmac`
- `Gmac`

These provide integrity and authenticity, not signatures or non-repudiation.

## CSPRNGs

Implemented generators:

- `CtrDrbgAes256` (`CtrDrbg<Aes256>`, T-table AES, variable-time)
- `CtrDrbgAes256Ct` (`CtrDrbg<Aes256Ct>`, constant-time AES)

The shipped generator is `CtrDrbg<C>`, which follows SP 800-90A Rev. 1
CTR_DRBG with AES-256 and keys an encrypt-only schedule once per update; the
two aliases produce identical output and differ only in whether the DRBG key
can leak through the cache.

## Cipher Families

### Block Ciphers

Implemented block-cipher families:

- DES / Triple-DES
- AES
- CAST-128 / CAST5
- Camellia
- Serpent
- Twofish
- SEED
- PRESENT
- Magma
- Grasshopper
- SM4
- SIMON
- SPECK

Design philosophy by family:

- `DES / Triple-DES`: the classic U.S. IBM / NIST line. It is a Feistel design
  from the hardware-centric 1970s, so the tiny S-boxes and heavy bit
  permutations reflect gate-count and wiring concerns more than modern software
  taste. The implementation preserves the traditional fast table-driven shape
  because the whole point of DES in software is how far that old design can be
  pushed, while `DesCt` and `TripleDesCt` make the constant-time tradeoff
  explicit instead of pretending the two goals coincide.
- `AES`: the U.S. federal standard selected by NIST, but designed in Belgium
  as Rijndael. Its SP-network structure is a software/hardware compromise: fast
  table-driven software on one hand, compact byte-oriented hardware on the
  other. The crate keeps both views visible: the fast path for ordinary
  software benchmarking, and a separate Boyar-Peralta-style `Ct` path so the
  constant-time cost is concrete.
- `CAST-128 / CAST5`: a Canadian design from Carlisle Adams and Stafford
  Tavares. It is a round-function-heavy Feistel cipher built around large keyed
  S-boxes, sitting between DES-era Feistel design and the later AES finalists.
  The implementation keeps the keyed-round shape obvious rather than hiding it
  behind abstractions.
- `Camellia`: a Japanese design (NTT and Mitsubishi) from the AES era. It
  deliberately blends an SP-network core with Feistel-style `FL` / `FLINV`
  layers, reflecting a design culture that wanted AES-class performance without
  abandoning older structural ideas. The writeup and code keep that hybrid
  structure visible because that split personality is the whole design.
- `Serpent`: a European AES finalist (Anderson, Biham, Knudsen) built as the
  conservative answer to AES selection. Its philosophy is “simple boolean
  layers, many rounds, wide security margin,” so the implementation keeps the
  bitslice round structure explicit rather than chasing table speed tricks.
- `Twofish`: the U.S. AES-finalist line from Schneier and collaborators. Its
  design mixes key-dependent S-boxes, an MDS layer, and whitening, reflecting a
  software-first philosophy that squeezes complexity into precomputation and
  linear algebra instead of just adding rounds. The code keeps the `q`
  permutations, RS/MDS layers, and keyed `h()` transform visible because
  Twofish’s design is about the interaction of those components, not just the
  Feistel shell around them.
- `SEED`: the Korean national standard. It is a Feistel cipher that leans on
  large 8-bit S-boxes and a compact algebraic round mix, closer in feel to the
  1990s national-standard school than to the later ARX stream ciphers. The
  implementation favors readability of the round algebra and the key schedule
  over trying to disguise it as “just another AES-like block cipher.”
- `PRESENT`: a lightweight European academic design aimed at tiny hardware. Its
  philosophy is minimum area and simple logic, so the code keeps the 4-bit
  S-box / bit permutation structure direct and simple.
- `Magma`: the older Russian standard line (GOST 28147-89). It is a 32-round
  Feistel design with 4-bit substitution and a single rotate, intentionally
  small and regular in the style of older Soviet/Russian block-cipher design.
  The implementation keeps the nibble structure obvious and treats the `Ct`
  path as a software side-channel concession rather than a redesign.
- `Grasshopper`: the newer Russian standard (Kuznyechik / GOST R 34.12-2015).
  It is a byte-oriented SP-network whose identity is its linear $L$ transform
  over $GF(2^8)$. Compared to `Magma`, it reflects a much more modern
  byte-oriented design style. The code emphasizes that linear layer because it
  is the part that makes Grasshopper look and cost different from AES.
- `SM4`: the Chinese national standard. Its round function is a compact
  “S-box then linear diffusion” transform, a pragmatic software/hardware middle
  ground that looks closer to the East Asian national-standard family than to
  the Bernstein ARX line. The implementation keeps the
  $T = L(\tau(\cdot))$
  structure front and center because that is the design’s defining rhythm.
- `SIMON`: the U.S. NSA minimalist bitwise line. Its philosophy is “only the
  operations hardware and software both like”: rotates, AND, XOR. That is why
  there is no separate `Ct` split; the native round function is already close
  to the ideal constant-time software shape.
- `SPECK`: the U.S. NSA ARX counterpart to `SIMON`. Its design philosophy is
  software-first simplicity: add, rotate, XOR, and nothing else. The
  implementation therefore focuses on exactness and endianness rather than
  alternate `Ct` variants.

### Stream Ciphers

Implemented stream-cipher families:

- Rabbit
- Salsa20
- ChaCha20
- XChaCha20
- SNOW 3G
- ZUC-128

Design philosophy by family:

- `Rabbit`: an eSTREAM-era software stream cipher built around eight coupled
  counters and a nonlinear integer `g`-function rather than a pure ARX quarter
  round. Its design philosophy is software throughput with a more structured
  internal state than the Bernstein line, and the implementation keeps that
  counter/state split explicit because that is what makes Rabbit distinct.
- `Salsa20`: the U.S. Bernstein line, built around a fast ARX core. The
  quarter-round structure is intentionally simple and pipeline-friendly, so the
  implementation keeps the core word-mixing visible.
- `ChaCha20`: also Bernstein’s work, and explicitly a refinement of Salsa20
  rather than a different design family. It pushes for better diffusion per
  round while keeping the same ARX spirit. The code keeps the quarter-round and
  state layout explicit because ChaCha’s design is evolutionary.
- `XChaCha20`: not a new core cipher, but a longer-nonce construction around
  ChaCha20. Its design philosophy is operational robustness: keep ChaCha20’s
  fast core, but fix nonce-management pain by stretching a 24-byte nonce into a
  subkey plus ordinary ChaCha20 state.
- `SNOW 3G`: the 3GPP telecom stream-cipher core used underneath UEA2/UIA2.
  Like ZUC, it is state-machine-centric rather than ARX-centric: a 16-word
  LFSR feeds a three-register FSM and two byte-oriented S-box layers. The
  crate keeps both the fast table-driven path and a separate `Ct` path because
  the secret-indexed nonlinear steps are exactly where the software side-
  channel tradeoff lives.
- `ZUC-128`: the Chinese mobile-stream-cipher line (standardized through the
  3GPP / LTE world). It is very different from the ARX family: a word-structured
  LFSR plus a nonlinear filter and S-box layer, reflecting a telecom-stream-
  cipher tradition rather than the Bernstein ARX line. The implementation leaves
  that contrast obvious, because the cost profile comes from that architectural
  choice.

## Symmetric Performance

> **What is and is not current.** The cipher and hash tables below are the
> 2026-09-17 sweep and post-date every rewrite of this year's audit round: the
> SNOW 3G and ZUC arithmetic, the GHASH/POLYVAL multiply, and the MD5, SHA-1
> and SHA-2 compression functions. The go-fast comparison sections further
> down are older single-host snapshots, and their GHASH baseline is the one
> that multiply replaced, so their speedup figures are against a comparator
> this crate no longer ships.

Measured with [pilot-bench](https://github.com/darrelllong/pilot-bench)
driving `pilot_cipher`, a dedicated Rust binary that encrypts a fixed
workload per round and prints MB/s to stdout. Pilot repeats the round until
the chosen confidence interval is achieved, correcting for autocorrelation
and startup transients.

Columns: **Block** and **Key** in bits; **MB/s** mean; **±CI** half-width at
**90%**; **Runs** rounds required to reach CI. The 2026-09-17 sweep was run
with `PILOT_PRESET=normal --confidence-level 0.90` (10% CI half-width target,
autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample size) and
`PILOT_SESSION_LIMIT=300`, one case at a time on each of:

- Intel Core i5-8259U (`dmz`, Linux, idle)
- Apple M1 (`tolkien`, macOS; no Mac is idle, and its background load is
  recorded with the run)
- Arm Cortex-X925 (`baase`, Linux, idle)
- Arm Cortex-A76 (`darby`, Raspberry Pi 5, Linux, idle)

The raw per-host tables, the host notes and the merge commands are in
[bench/sweep-2026-09-17](bench/sweep-2026-09-17/README.md). The compilers
differ with the hosts, which is part of what each column measures.

### AES

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aes128 | 128 | 128 | 215 | ±1.643 | 80 | 392.5 | ±0.4886 | 140 | 494.8 | ±11.82 | 267 | 186.4 | ±1.442 | 50 |
| aes128ct | 128 | 128 | 37.18 | ±0.1773 | 140 | 48.28 | ±0.06194 | 50 | 64.31 | ±2.188 | 80 | 25.2 | ±0.08274 | 83 |
| aes192 | 128 | 192 | 183 | ±2.119 | 144 | 329.6 | ±0.1671 | 200 | 408.9 | ±19.46 | 50 | 158.8 | ±1.324 | 110 |
| aes192ct | 128 | 192 | 31.17 | ±0.08466 | 110 | 39.79 | ±0.03657 | 50 | 53.47 | ±1.818 | 170 | 20.96 | ±0.07426 | 55 |
| aes256 | 128 | 256 | 161.3 | ±1.211 | 50 | 286.6 | ±0.1047 | 50 | 329.2 | ±21.63 | 85 | 138.8 | ±0.702 | 53 |
| aes256ct | 128 | 256 | 26.62 | ±0.05391 | 110 | 33.84 | ±0.03596 | 80 | 46.28 | ±0.07804 | 175 | 17.93 | ±0.06138 | 118 |

### Camellia

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| camellia128 | 128 | 128 | 92.31 | ±0.8526 | 50 | 102.4 | ±0.6168 | 350 | 136.4 | ±5.104 | 50 | 71.98 | ±0.1416 | 50 |
| camellia128ct | 128 | 128 | 6.635 | ±0.03416 | 50 | 9.29 | ±0.2193 | 50 | 11.44 | ±0.2584 | 380 | 4.291 | ±0.003072 | 171 |
| camellia192 | 128 | 192 | 69.8 | ±0.3937 | 117 | 75.33 | ±0.05319 | 350 | 100.5 | ±4.419 | 80 | 42.76 | ±0.06733 | 140 |
| camellia192ct | 128 | 192 | 4.97 | ±0.03365 | 113 | 6.851 | ±0.2617 | 80 | 8.582 | ±0.1589 | 50 | 3.205 | ±0.0445 | 50 |
| camellia256 | 128 | 256 | 65.27 | ±0.1394 | 80 | 75.46 | ±0.01832 | 380 | 101 | ±4.035 | 80 | 54.03 | ±0.08136 | 50 |
| camellia256ct | 128 | 256 | 4.969 | ±0.03223 | 50 | 6.412 | ±0.337 | 55 | 8.626 | ±0.01044 | 140 | 3.205 | ±0.0438 | 144 |

### CAST-128

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cast128 | 64 | 128 | 112 | ±1.343 | 80 | 167.3 | ±0.1133 | 140 | 180.4 | ±3.636 | 209 | 86.57 | ±0.2769 | 50 |
| cast128ct | 64 | 128 | 1.834 | ±0.007179 | 80 | 3.309 | ±0.0002772 | 100 | 3.924 | ±0.2381 | 80 | 1.29 | ±0.01116 | 50 |

### DES / 3DES

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| des | 64 | 56 | 59.6 | ±0.2939 | 50 | 60.68 | ±0.01401 | 380 | 80.13 | ±0.09811 | 140 | 40.36 | ±0.0657 | 80 |
| desct | 64 | 56 | 3.144 | ±0.1183 | 50 | 6.917 | ±0.0003662 | 350 | 9.666 | ±0.003761 | 1370 | 3.379 | ±0.0006071 | 121 |
| 3des | 64 | 168 | 19.69 | ±0.07952 | 80 | 18.66 | ±0.001731 | 110 | 24.88 | ±1.061 | 54 | 13.65 | ±0.005685 | 50 |
| 3desct | 64 | 168 | 1.069 | ±0.002881 | 81 | 2.296 | ±7.436e-05 | 100 | 2.984 | ±0.1253 | 83 | 1.124 | ±0.005318 | 76 |

### Grasshopper (GOST R 34.12-2015)

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| grasshopper | 128 | 256 | 103.4 | ±0.6639 | 58 | 200.7 | ±0.1343 | 80 | 223.1 | ±7.559 | 110 | 86.12 | ±0.394 | 51 |
| grasshopperct | 128 | 256 | 3.893 | ±0.02015 | 110 | 4.831 | ±0.001922 | 50 | 5.421 | ±0.3374 | 50 | 2.668 | ±0.01675 | 100 |

### Magma (GOST R 34.12-2015)

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| magma | 64 | 256 | 47.48 | ±0.1832 | 50 | 38.64 | ±0.1288 | 740 | 61.42 | ±4.653 | 50 | 37.11 | ±0.0326 | 50 |
| magmact | 64 | 256 | 6.479 | ±0.06809 | 51 | 9.005 | ±0.0005405 | 153 | 14.77 | ±0.8489 | 200 | 4.419 | ±0.0005261 | 50 |

### PRESENT

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| present80 | 64 | 80 | 2.64 | ±0.006397 | 57 | 8.855 | ±0.001497 | 81 | 10.28 | ±0.01819 | 950 | 2.704 | ±0.0371 | 50 |
| present80ct | 64 | 80 | 1.28 | ±0.003532 | 113 | 3.272 | ±0.0001727 | 100 | 2.91 | ±0.1008 | 110 | 1.013 | ±0.005164 | 50 |
| present128 | 64 | 128 | 2.626 | ±0.006265 | 142 | 8.856 | ±0.0007118 | 350 | 9.428 | ±0.7864 | 265 | 2.711 | ±0.01749 | 100 |
| present128ct | 64 | 128 | 1.277 | ±0.003169 | 110 | 3.272 | ±0.0001444 | 138 | 2.946 | ±0.1209 | 50 | 1.013 | ±0.003551 | 100 |

### SEED

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| seed | 128 | 128 | 49.59 | ±0.2736 | 56 | 49.66 | ±0.01877 | 80 | 80.29 | ±1.973 | 50 | 39.64 | ±0.03707 | 110 |
| seedct | 128 | 128 | 4.871 | ±0.04322 | 50 | 6.542 | ±0.1079 | 50 | 7.017 | ±0.4815 | 50 | 3.219 | ±0.05128 | 50 |

### Serpent

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| serpent128 | 128 | 128 | 24.51 | ±0.1194 | 59 | 23.46 | ±0.01514 | 80 | 30.22 | ±2.464 | 110 | 14.8 | ±0.03645 | 54 |
| serpent192 | 128 | 192 | 24.21 | ±0.4652 | 50 | 23.47 | ±0.01368 | 80 | 32.98 | ±0.04135 | 110 | 14.84 | ±0.06683 | 50 |
| serpent256 | 128 | 256 | 24.36 | ±0.6582 | 50 | 23.44 | ±0.02014 | 50 | 32.66 | ±0.7887 | 143 | 14.86 | ±0.05158 | 50 |

### SM4

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sm4 | 128 | 128 | 117.5 | ±0.5034 | 50 | 158 | ±0.05036 | 327 | 163.1 | ±11.47 | 52 | 74.31 | ±0.1896 | 264 |
| sm4ct | 128 | 128 | 7.366 | ±0.06728 | 50 | 9.604 | ±0.1499 | 54 | 11.05 | ±0.6641 | 1256 | 4.732 | ±0.0126 | 268 |

### Twofish

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| twofish128 | 128 | 128 | 201.1 | ±1.241 | 110 | 250.6 | ±0.2087 | 140 | 317.1 | ±1.327 | 110 | 116.7 | ±0.3953 | 140 |
| twofish128ct | 128 | 128 | 1.469 | ±0.005947 | 50 | 1.616 | ±0.0006938 | 50 | 1.864 | ±0.04868 | 80 | 0.8623 | ±0.005618 | 50 |
| twofish192 | 128 | 192 | 201.7 | ±1.874 | 80 | 251 | ±0.2701 | 80 | 310.5 | ±10.07 | 80 | 117 | ±0.4351 | 380 |
| twofish192ct | 128 | 192 | 1.13 | ±0.003674 | 51 | 1.207 | ±0.0002876 | 50 | 1.427 | ±0.02895 | 113 | 0.6784 | ±0.003772 | 50 |
| twofish256 | 128 | 256 | 195.5 | ±0.6249 | 140 | 248.7 | ±3.338 | 50 | 315.4 | ±4.751 | 170 | 155.9 | ±0.8715 | 50 |
| twofish256ct | 128 | 256 | 0.9225 | ±0.002703 | 50 | 0.9479 | ±0.000138 | 75 | 1.144 | ±0.01616 | 51 | 0.5661 | ±0.002297 | 50 |

### Simon

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| simon32_64 | 32 | 64 | 47.63 | ±0.3644 | 80 | 61.32 | ±0.06612 | 1471 | 83.05 | ±5.62 | 260 | 45.61 | ±0.04618 | 53 |
| simon48_72 | 48 | 72 | 69.12 | ±0.6314 | 50 | 79.29 | ±0.01561 | 2452 | 114.5 | ±0.2088 | 80 | 59.34 | ±0.1102 | 50 |
| simon48_96 | 48 | 96 | 69.96 | ±0.4104 | 80 | 79.3 | ±0.01593 | 688 | 108.8 | ±6.734 | 80 | 59.41 | ±0.1409 | 145 |
| simon64_96 | 64 | 96 | 78.07 | ±0.6907 | 50 | 102.5 | ±0.03629 | 687 | 154.3 | ±0.569 | 171 | 78.74 | ±0.3719 | 50 |
| simon64_128 | 64 | 128 | 70.19 | ±0.1231 | 170 | 97.13 | ±0.0292 | 470 | 140.4 | ±7.907 | 116 | 75.75 | ±0.1303 | 140 |
| simon96_96 | 96 | 96 | 79.03 | ±0.179 | 110 | 101.7 | ±0.01953 | 80 | 141.1 | ±10.65 | 50 | 78.94 | ±0.4631 | 50 |
| simon96_144 | 96 | 144 | 82.58 | ±0.9264 | 290 | 97.54 | ±0.007028 | 55 | 139 | ±9.099 | 140 | 60.4 | ±0.1841 | 50 |
| simon128_128 | 128 | 128 | 116.4 | ±0.9202 | 50 | 188.5 | ±0.09627 | 233 | 293.2 | ±24.18 | 81 | 112.3 | ±0.438 | 320 |
| simon128_192 | 128 | 192 | 130.3 | ±0.6393 | 235 | 184.9 | ±0.1102 | 140 | 319.5 | ±2.522 | 110 | 110.1 | ±0.4905 | 260 |
| simon128_256 | 128 | 256 | 123.3 | ±0.3557 | 54 | 175.4 | ±0.07212 | 110 | 299.2 | ±11.82 | 80 | 107.1 | ±0.3118 | 354 |

### Speck

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| speck32_64 | 32 | 64 | 116.8 | ±0.3077 | 80 | 148.8 | ±0.05921 | 140 | 146.4 | ±9.354 | 80 | 57.5 | ±0.1238 | 80 |
| speck48_72 | 48 | 72 | 166.3 | ±0.9249 | 144 | 225.3 | ±0.07528 | 110 | 215.4 | ±14.18 | 140 | 79.66 | ±0.1681 | 260 |
| speck48_96 | 48 | 96 | 162 | ±1.366 | 110 | 182.7 | ±0.0446 | 50 | 230.8 | ±15.63 | 50 | 84.69 | ±0.2344 | 350 |
| speck64_96 | 64 | 96 | 245.8 | ±2.419 | 80 | 204.5 | ±0.1298 | 59 | 253 | ±1.032 | 80 | 90.79 | ±0.2266 | 170 |
| speck64_128 | 64 | 128 | 238.4 | ±2.034 | 80 | 194.2 | ±0.1098 | 81 | 237.8 | ±6.007 | 140 | 87.19 | ±0.2212 | 320 |
| speck96_96 | 96 | 96 | 236.5 | ±2.293 | 175 | 266.9 | ±0.1776 | 50 | 333.2 | ±26.78 | 50 | 129.2 | ±0.74 | 140 |
| speck96_144 | 96 | 144 | 207.6 | ±0.7088 | 111 | 255.6 | ±0.1443 | 80 | 341.8 | ±14.23 | 50 | 125.4 | ±0.6833 | 80 |
| speck128_128 | 128 | 128 | 412.4 | ±3.947 | 112 | 764.4 | ±0.4849 | 50 | 984.4 | ±12.01 | 260 | 218.4 | ±1.929 | 50 |
| speck128_192 | 128 | 192 | 405.2 | ±4.826 | 57 | 731.8 | ±0.313 | 88 | 935.6 | ±38.3 | 260 | 220 | ±1.503 | 290 |
| speck128_256 | 128 | 256 | 392.2 | ±3.52 | 148 | 700.6 | ±0.5227 | 80 | 904.1 | ±15.97 | 50 | 217.1 | ±1.569 | 260 |

### Stream ciphers

| Cipher | Block | Key | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| chacha20 | stream | 256 | 346.3 | ±2.082 | 80 | 673.3 | ±0.1012 | 80 | 910.7 | ±33.23 | 140 | 298.7 | ±2.158 | 416 |
| xchacha20 | stream | 256 | 235.2 | ±0.6852 | 320 | 673.1 | ±0.08714 | 80 | 892.8 | ±54.22 | 110 | 299.7 | ±1.551 | 230 |
| salsa20 | stream | 256 | 216.7 | ±0.8704 | 50 | 586.6 | ±0.4194 | 50 | 1184 | ±59.54 | 80 | 331.5 | ±4.533 | 50 |
| rabbit | stream | 128 | 273 | ±1.679 | 80 | 977.8 | ±4.558 | 170 | 1125 | ±30.16 | 80 | 256.2 | ±2.548 | 118 |
| snow3g | stream | 128 | 162.7 | ±1.155 | 52 | 350.3 | ±0.3478 | 80 | 536.1 | ±35.75 | 140 | 188 | ±4.362 | 115 |
| snow3gct | stream | 128 | 26.8 | ±0.2158 | 500 | 41.49 | ±0.01389 | 80 | 50.5 | ±0.03687 | 230 | 18.06 | ±0.01411 | 80 |
| zuc128 | stream | 128 | 267.5 | ±7.473 | 50 | 390.9 | ±0.5177 | 260 | 516.2 | ±12.24 | 140 | 271.8 | ±1.864 | 50 |
| zuc128ct | stream | 128 | 28.31 | ±0.09849 | 80 | 41.31 | ±1.132 | 50 | 49.16 | ±3.202 | 50 | 18.67 | ±0.02217 | 80 |

### What a keystream costs below a megabyte

The table above is a megabyte in one call, which is the best case: whole
blocks, one construction amortised over sixteen thousand of them. What a
caller actually asks for is often a record or a word.
`benchmarks/benches/keystream_sizes.rs` measures the other shapes; these are
`baase` (Cortex-X925, idle), criterion's median of each estimate.

| Request | One call | A word at a time | Offset by one byte |
|---|---:|---:|---:|
| 4 B | 89.5 ns | 90.4 ns | — |
| 16 B | 89.2 ns | 95.5 ns | 90.3 ns |
| 64 B | 91.9 ns | 134.0 ns | 92.6 ns |
| 480 B | 571 ns | 926 ns | 567 ns |
| 512 B | 574 ns | 951 ns | 568 ns |
| 4 KiB | 4.39 µs | 7.40 µs | 4.38 µs |
| 1 MiB | 1.114 ms | — | 1.115 ms |

Construction alone is 34.0 ns, and a construction plus one block is 91.2 ns.
Three things follow:

- **Below one block, the cost is the setup.** A four-byte request costs the
  same as a sixty-four-byte one, and 38% of it is the constructor. A caller
  that needs a word at a time should hold one cipher, not build one per call.
- **Holding the cipher is worth 1.7×.** Asking for a page a word at a time
  costs 7.40 µs against 4.39 µs in one call, because each call re-enters and
  re-checks rather than because the keystream costs more. The penalty is 1.07×
  at sixteen bytes, where the setup still dominates, and settles at 1.68× by a
  page.
- **Alignment does not matter here.** A buffer starting one byte into its
  allocation measures the same as an aligned one at every size, within the
  intervals. The XOR is byte-wise and the block generation does not touch the
  caller's buffer.

The marginal cost of a whole block, from the 64-to-512-byte span, is 68.9 ns,
which is 933 MB/s at a page and 942 MB/s at a megabyte: the keystream reaches
its asymptote well before the megabyte the table above uses.

### Hash and XOF throughput

`pilot_hash` reports the same MB/s shape as `pilot_cipher`, absorbing a
fixed input per round and finalizing into a hash digest or squeezing a
fixed-size XOF output. SHAKE128 / SHAKE256 squeeze 32 bytes per round so the
per-byte input cost dominates.

### MD5 / SHA-1 / RIPEMD-160 (legacy)

| Hash | Out | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| md5 | 128 | 549.5 | ±2.582 | 170 | 649.8 | ±0.2112 | 110 | 774.5 | ±25.84 | 50 | 460.8 | ±3.487 | 51 |
| sha1 | 160 | 245.2 | ±1.078 | 80 | 219.5 | ±0.1571 | 50 | 426.7 | ±4.301 | 80 | 170.7 | ±0.8454 | 328 |
| ripemd160 | 160 | 125.5 | ±0.4776 | 50 | 287.3 | ±0.3605 | 81 | 415.1 | ±29.97 | 110 | 98.97 | ±0.4661 | 50 |

### SHA-2 (FIPS 180-4)

| Hash | Out | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sha224 | 224 | 204.6 | ±0.9379 | 50 | 200.5 | ±0.119 | 50 | 339.9 | ±9.039 | 110 | 164.4 | ±0.79 | 89 |
| sha256 | 256 | 186.8 | ±0.8505 | 230 | 200.5 | ±0.09441 | 82 | 344.3 | ±2.065 | 230 | 164.7 | ±0.8369 | 170 |
| sha384 | 384 | 283.3 | ±1.462 | 55 | 311.7 | ±0.1644 | 80 | 494.5 | ±23.53 | 239 | 186.1 | ±0.9009 | 261 |
| sha512 | 512 | 283.8 | ±1.142 | 230 | 311.5 | ±0.1449 | 80 | 508.8 | ±17.27 | 50 | 185.9 | ±0.9029 | 148 |
| sha512_224 | 224 | 283.6 | ±1.824 | 110 | 311.7 | ±0.1766 | 50 | 498.7 | ±20.88 | 80 | 185.9 | ±1.19 | 110 |
| sha512_256 | 256 | 283 | ±1.822 | 50 | 311.5 | ±0.2108 | 170 | 510.1 | ±12.52 | 110 | 186 | ±0.9143 | 143 |

### SHA-3 (FIPS 202)

| Hash | Out | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sha3_224 | 224 | 159.7 | ±0.5975 | 50 | 484.8 | ±0.3438 | 50 | 722.1 | ±9.895 | 200 | 86.39 | ±0.3054 | 170 |
| sha3_256 | 256 | 150.1 | ±0.4682 | 50 | 456.5 | ±0.3299 | 80 | 663.9 | ±34.88 | 110 | 81.66 | ±0.258 | 110 |
| sha3_384 | 384 | 114.9 | ±0.4533 | 50 | 347.7 | ±0.3337 | 52 | 525.1 | ±6.035 | 230 | 62.65 | ±0.3901 | 200 |
| sha3_512 | 512 | 90.55 | ±0.375 | 170 | 242.5 | ±0.2849 | 80 | 353.9 | ±21.73 | 80 | 54.97 | ±0.1783 | 80 |

### SHAKE XOFs (FIPS 202; 32-byte squeeze)

| Hash | Out | i5-8259U MB/s | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 MB/s | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 MB/s | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 MB/s | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| shake128 | xof | 208.8 | ±2.39 | 110 | 565.6 | ±0.4784 | 80 | 808.7 | ±50.1 | 470 | 127 | ±0.5039 | 50 |
| shake256 | xof | 168.8 | ±2.604 | 144 | 455.9 | ±0.4095 | 50 | 675.3 | ±25.88 | 110 | 103.2 | ±0.3278 | 53 |

Cross-platform summary Kiviat diagrams (radar charts; log-radial axis,
outer ring = faster):

![Symmetric throughput Kiviat (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-symmetric-radar.svg)

![Hash throughput Kiviat (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-hash-radar.svg)
The Kiviat diagram (radar chart) below compares representative fast-vs-`Ct`
pairs across
table-driven ciphers. Simon and Speck are absent because their designs are
already table-free bitwise/ARX, so there is no software `Ct` variant to compare.

![Fast vs Ct throughput Kiviat diagram (radar chart)](assets/fast-vs-ct-radar.svg)

### Apple-Silicon Go-Fast Alternative (`fast/Apple-Silicon`)

These numbers come from the isolated Apple-Silicon alternative kernels in
`fast/Apple-Silicon/aarch64-alt`, using the local comparator binaries after
correctness checks against baseline/reference outputs. Unlike the Pilot tables
above, this section is a focused single-host microbenchmark snapshot on M4 Pro.

| Primitive | Comparator | Unit | Go-fast Throughput | Baseline/Reference Throughput | Speedup |
|---|---|---|---:|---:|---:|
| AES-128 encrypt | `compare_aes128` | MiB/s | 9803.92 | 502.88 | 19.50x |
| AES-256 encrypt | `compare_aes256` | MiB/s | 6040.76 | 264.80 | 22.81x |
| SHA-256 digest | `compare_sha256` | MiB/s | 2417.54 | 364.57 | 6.63x |
| GHASH multiply | `compare_ghash` | Mops/s | 117.79 | 9.23 (`ct_ref`) | 12.75x |

Promotion gate for the published go-fast set is $\ge 5\times$ speedup.
Exploratory results below that bar (not promoted):

- `compare_chacha20`: `1.53x`
- `compare_shake` (ML-KEM+ML-DSA-like): `1.07x`

Apple go-fast throughput Kiviat diagram (radar chart, two curves; per-axis normalized):

![Apple go-fast throughput Kiviat diagram (radar chart)](assets/apple-go-fast-radar.svg)

### x86 Go-Fast Alternative (`fast/x86`, moore.soe.ucsc.edu)

These numbers come from the isolated x86 alternative kernels in
`fast/x86/x86-alt`, measured on `moore.soe.ucsc.edu` (AMD EPYC 7452) after
correctness checks against baseline/reference outputs.
Source run log:
[fast/x86/results/alt_suite_20260310_061035.md](fast/x86/results/alt_suite_20260310_061035.md)

| Primitive | Comparator | Unit | Go-fast Throughput | Baseline/Reference Throughput | Speedup |
|---|---|---|---:|---:|---:|
| AES-128 encrypt | `compare_aes128` | MiB/s | 2557.36 | 248.95 | 10.27x |
| AES-256 encrypt | `compare_aes256` | MiB/s | 2043.97 | 185.42 | 11.02x |
| GHASH multiply | `compare_ghash` | Mops/s | 42.39 | 2.54 (`ct_ref`) | 16.71x |

All published x86 go-fast kernels currently clear the $\ge 5\times$ promotion gate.

x86 go-fast throughput Kiviat diagram (radar chart, two curves; per-axis normalized):

![x86 go-fast throughput Kiviat diagram (radar chart)](assets/x86-go-fast-radar.svg)

## References

The primary standards and papers are stored in `pubs/`. The BibTeX index is in
[README.md](README.md).
