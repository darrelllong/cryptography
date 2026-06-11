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
  `Eax`, `Ocb`, `Siv`, `Aes128GcmSiv`, `Aes256GcmSiv`, `ChaCha20Poly1305`
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
- RFC 8452: `Aes128GcmSiv`, `Aes256GcmSiv`
- RFC 8439: `Poly1305`, `ChaCha20Poly1305`

Reference set for the newly added mode paths:

- `Ccm`: NIST SP 800-38C (`pubs/sp800-38c.pdf`)
- `AesKeyWrap`: RFC 3394 and NIST SP 800-38F
  (`pubs/rfc3394-aes-key-wrap.pdf`, `pubs/sp800-38f.pdf`)
- `Siv`: RFC 5297 (`pubs/rfc5297-siv.pdf`)
- `Ocb`: RFC 7253 (`pubs/rfc7253-ocb.pdf`)
- `Aes128GcmSiv` / `Aes256GcmSiv`: RFC 8452 (`pubs/rfc8452-aes-gcm-siv.pdf`)
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
  `GcmVt`/`GmacVt` are explicit variable-time reference paths.
- `XTS` is for storage-style sector encryption, not general message transport.

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

- `CtrDrbgAes256`

The shipped generator is `CtrDrbgAes256`, which follows SP 800-90A Rev. 1
CTR_DRBG with AES-256.

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
  pushed, while `DesCt` makes the constant-time tradeoff explicit instead of
  pretending the two goals coincide.
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

Measured with [pilot-bench](https://github.com/darrelllong/pilot-bench)
driving `pilot_cipher`, a dedicated Rust binary that encrypts a fixed
workload per round and prints MB/s to stdout. Pilot repeats the round until
the chosen confidence interval is achieved, correcting for autocorrelation
and startup transients.

Columns: **Block** and **Key** in bits; **MB/s** mean; **±CI** half-width at
**90%**; **Runs** rounds required to reach CI. The 2026-06-11 sweep was run
with `PILOT_PRESET=normal --confidence-level 0.90` (10% CI half-width target,
autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample size) against
crate v0.7.0 (commit `1aae1df`). The tables below are parallel runs on:

- Apple M1 (`tolkien`, macOS)
- AMD EPYC 7452 (`dennard.soe.ucsc.edu`, single-core slice)
- NVIDIA Jetson (`heinlein.local`, aarch64)

### AES

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| aes128 | 128 | 128 | 331.4 | ±0.8148 | 321 | 208.1 | ±7.3 | 50 | 90.35 | ±7.473 | 6388 |
| aes128ct | 128 | 128 | 44.65 | ±0.1916 | 87 | 35.23 | ±0.1357 | 89 | 15.19 | ±0.5082 | 230 |
| aes192 | 128 | 192 | 292.6 | ±0.9843 | 140 | 183.4 | ±1.429 | 50 | 86.81 | ±6.894 | 5609 |
| aes192ct | 128 | 192 | 37.03 | ±0.1972 | 141 | 29.42 | ±0.1271 | 111 | 12.7 | ±0.3536 | 50 |
| aes256 | 128 | 256 | 243.1 | ±1.302 | 890 | 162.9 | ±1.012 | 50 | 76.15 | ±6.351 | 7588 |
| aes256ct | 128 | 256 | 31.71 | ±0.1045 | 57 | 25.29 | ±0.09249 | 80 | 11.05 | ±0.2853 | 230 |

### Camellia

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| camellia128 | 128 | 128 | 95.48 | ±0.5059 | 53 | 82.63 | ±0.4945 | 50 | 38.42 | ±2.908 | 50 |
| camellia128ct | 128 | 128 | 9.211 | ±0.01902 | 51 | 5.799 | ±0.01197 | 54 | 2.944 | ±0.02098 | 50 |
| camellia192 | 128 | 192 | 69.95 | ±0.3813 | 170 | 61.94 | ±0.6963 | 50 | 29.69 | ±2.028 | 50 |
| camellia192ct | 128 | 192 | 6.892 | ±0.01383 | 50 | 4.351 | ±0.007133 | 110 | 2.241 | ±0.01375 | 55 |
| camellia256 | 128 | 256 | 69.43 | ±0.3038 | 200 | 62.02 | ±0.3191 | 50 | 29.12 | ±2.399 | 51 |
| camellia256ct | 128 | 256 | 6.893 | ±0.01519 | 110 | 4.353 | ±0.007219 | 50 | 2.236 | ±0.01142 | 110 |

### CAST-128

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| cast128 | 64 | 128 | 149.1 | ±0.1225 | 170 | 98.86 | ±0.7563 | 59 | 46.64 | ±3.78 | 59 |
| cast128ct | 64 | 128 | 3.14 | ±0.002884 | 140 | 1.774 | ±0.006342 | 50 | 0.8697 | ±0.001223 | 50 |

### DES / 3DES

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| des | 64 | 56 | 56.99 | ±0.1843 | 80 | 53.45 | ±0.3116 | 50 | 23.31 | ±1.06 | 110 |
| desct | 64 | 56 | 6.649 | ±0.009946 | 260 | 3.424 | ±0.006416 | 50 | 2.249 | ±0.01122 | 50 |
| 3des | 64 | 168 | 17.67 | ±0.05124 | 1103 | 17.49 | ±0.08911 | 82 | 8.597 | ±0.1488 | 57 |

### Grasshopper (GOST R 34.12-2015)

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| grasshopper | 128 | 256 | 21.16 | ±0.01513 | 110 | 12.53 | ±0.09348 | 50 | 5.696 | ±0.0786 | 140 |
| grasshopperct | 128 | 256 | 4.755 | ±0.05184 | 53 | 3.33 | ±0.005137 | 50 | 1.848 | ±0.009802 | 50 |

### Magma (GOST R 34.12-2015)

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| magma | 64 | 256 | 36.82 | ±0.02677 | 110 | 40.31 | ±0.1761 | 54 | 20.39 | ±1.145 | 50 |
| magmact | 64 | 256 | 8.587 | ±0.002342 | 110 | 6.309 | ±0.01318 | 110 | 3.498 | ±0.03009 | 52 |

### PRESENT

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| present80 | 64 | 80 | 8.454 | ±0.001569 | 50 | 2.711 | ±0.005232 | 80 | 1.928 | ±0.009072 | 141 |
| present80ct | 64 | 80 | 3.095 | ±0.002144 | 206 | 1.297 | ±0.002073 | 50 | 0.6636 | ±0.001045 | 50 |
| present128 | 64 | 128 | 8.447 | ±0.006071 | 50 | 2.712 | ±0.004831 | 50 | 1.924 | ±0.008547 | 50 |
| present128ct | 64 | 128 | 3.097 | ±0.002885 | 50 | 1.298 | ±0.001778 | 50 | 0.6644 | ±0.0009077 | 80 |

### SEED

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| seed | 128 | 128 | 47.23 | ±0.08011 | 50 | 44.86 | ±0.1409 | 83 | 20.55 | ±1.006 | 50 |
| seedct | 128 | 128 | 6.505 | ±0.006343 | 80 | 4.068 | ±0.009125 | 50 | 2.184 | ±0.01194 | 50 |

### Serpent

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| serpent128 | 128 | 128 | 7.986 | ±0.005284 | 50 | 4.699 | ±0.01364 | 50 | 2.433 | ±0.0153 | 50 |
| serpent128ct | 128 | 128 | 5.818 | ±0.002268 | 81 | 1.823 | ±0.003141 | 58 | 1.565 | ±0.005114 | 110 |
| serpent192 | 128 | 192 | 7.984 | ±0.004522 | 471 | 4.696 | ±0.00828 | 50 | 2.441 | ±0.0142 | 50 |
| serpent192ct | 128 | 192 | 5.821 | ±0.003559 | 50 | 1.826 | ±0.002755 | 50 | 1.561 | ±0.004187 | 59 |
| serpent256 | 128 | 256 | 7.986 | ±0.00375 | 200 | 4.699 | ±0.01032 | 80 | 2.43 | ±0.0154 | 110 |
| serpent256ct | 128 | 256 | 5.817 | ±0.003501 | 110 | 1.827 | ±0.002513 | 50 | 1.561 | ±0.003214 | 84 |

### SM4

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sm4 | 128 | 128 | 149.3 | ±0.5177 | 1079 | 120.9 | ±1.025 | 50 | 50.35 | ±4.167 | 142 |
| sm4ct | 128 | 128 | 9.499 | ±0.01158 | 50 | 6.386 | ±0.01314 | 110 | 3.173 | ±0.02603 | 80 |

### Twofish

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| twofish128 | 128 | 128 | 9.679 | ±0.03363 | 50 | 8.577 | ±0.04337 | 50 | 2.571 | ±0.01555 | 50 |
| twofish128ct | 128 | 128 | 1.897 | ±0.003274 | 50 | 1.063 | ±0.009289 | 50 | 0.5139 | ±0.0008311 | 50 |
| twofish192 | 128 | 192 | 9.455 | ±0.001209 | 80 | 7.529 | ±0.06608 | 50 | 2.493 | ±0.0159 | 80 |
| twofish192ct | 128 | 192 | 1.672 | ±0.008048 | 110 | 0.813 | ±0.001481 | 81 | 0.4037 | ±0.0004001 | 127 |
| twofish256 | 128 | 256 | 9.196 | ±0.008706 | 50 | 6.533 | ±0.04008 | 83 | 2.398 | ±0.01493 | 80 |
| twofish256ct | 128 | 256 | 1.488 | ±0.0004584 | 299 | 0.653 | ±0.003624 | 50 | 0.332 | ±0.0002243 | 93 |

### Simon

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| simon32_64 | 32 | 64 | 58.23 | ±0.1054 | 54 | 50.3 | ±0.2092 | 53 | 26.47 | ±1.451 | 80 |
| simon48_72 | 48 | 72 | 75.17 | ±0.1529 | 50 | 66.18 | ±0.2902 | 50 | 33.13 | ±2.705 | 50 |
| simon48_96 | 48 | 96 | 75.23 | ±0.145 | 350 | 66.07 | ±0.2619 | 110 | 33.31 | ±2.422 | 50 |
| simon64_96 | 64 | 96 | 97.17 | ±0.2174 | 50 | 83.1 | ±1.146 | 50 | 38.69 | ±3.204 | 84 |
| simon64_128 | 64 | 128 | 91.98 | ±0.1247 | 80 | 80.97 | ±0.4001 | 50 | 39.94 | ±2.695 | 110 |
| simon96_96 | 96 | 96 | 96.36 | ±0.06035 | 80 | 87.37 | ±0.5467 | 50 | 48.77 | ±2.243 | 50 |
| simon96_144 | 96 | 144 | 92.25 | ±0.1166 | 88 | 84.17 | ±0.3726 | 59 | 50.06 | ±2.691 | 50 |
| simon128_128 | 128 | 128 | 170.2 | ±0.3255 | 740 | 137.8 | ±1.024 | 50 | 98.61 | ±5.828 | 50 |
| simon128_192 | 128 | 192 | 166.8 | ±0.7618 | 860 | 137.1 | ±1.175 | 350 | 95.73 | ±5.326 | 80 |
| simon128_256 | 128 | 256 | 158.5 | ±0.5673 | 620 | 129.8 | ±0.9313 | 80 | 91.71 | ±6.075 | 110 |

### Speck

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| speck32_64 | 32 | 64 | 141 | ±0.3748 | 958 | 97.64 | ±0.6028 | 50 | 45.09 | ±1.719 | 50 |
| speck48_72 | 48 | 72 | 212 | ±0.1515 | 1310 | 143.1 | ±0.8356 | 50 | 67.69 | ±3.602 | 50 |
| speck48_96 | 48 | 96 | 172.4 | ±0.3479 | 1100 | 133 | ±0.8569 | 80 | 69.47 | ±4.938 | 590 |
| speck64_96 | 64 | 96 | 191.9 | ±0.6116 | 836 | 194.5 | ±1.463 | 80 | 73.42 | ±2.002 | 80 |
| speck64_128 | 64 | 128 | 183.4 | ±0.325 | 1340 | 190.1 | ±1.663 | 52 | 70.99 | ±2.371 | 50 |
| speck96_96 | 96 | 96 | 217.1 | ±1.502 | 110 | 189.9 | ±1.408 | 50 | 109.7 | ±3.763 | 50 |
| speck96_144 | 96 | 144 | 239.2 | ±2.161 | 1044 | 186.9 | ±1.491 | 80 | 103.1 | ±4.707 | 140 |
| speck128_128 | 128 | 128 | 564.7 | ±1.858 | 680 | 394.9 | ±3.407 | 50 | 219.9 | ±10.95 | 110 |
| speck128_192 | 128 | 192 | 586.7 | ±0.6879 | 1250 | 390.6 | ±2.526 | 80 | 218.1 | ±11.05 | 53 |
| speck128_256 | 128 | 256 | 559.9 | ±1.196 | 1130 | 378.7 | ±3.099 | 50 | 209.5 | ±9.208 | 325 |

### Stream ciphers

| Cipher | Block | Key | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| chacha20 | stream | 256 | 462 | ±1.997 | 415 | 409.2 | ±2.265 | 83 | 195.7 | ±9.495 | 143 |
| xchacha20 | stream | 256 | 462.3 | ±1.965 | 1010 | 406.6 | ±3.29 | 50 | 194 | ±14.28 | 55 |
| salsa20 | stream | 256 | 521.5 | ±3.769 | 1071 | 396.4 | ±3.476 | 50 | 242.2 | ±16.6 | 50 |
| rabbit | stream | 128 | 853.3 | ±1.216 | 140 | 454.4 | ±3.574 | 50 | 225.4 | ±16.89 | 80 |
| snow3g | stream | 128 | 271.5 | ±0.5142 | 447 | 254.1 | ±2.246 | 50 | 117.8 | ±9.74 | 1919 |
| snow3gct | stream | 128 | 40.28 | ±0.01064 | 230 | 23.65 | ±0.07317 | 110 | 11.55 | ±0.241 | 50 |
| zuc128 | stream | 128 | 363 | ±1.455 | 920 | 254.3 | ±2.217 | 50 | 107.2 | ±8.861 | 628 |
| zuc128ct | stream | 128 | 41.47 | ±0.01106 | 200 | 24.48 | ±0.06694 | 50 | 11.3 | ±0.327 | 51 |

### Hash and XOF throughput

`pilot_hash` reports the same MB/s shape as `pilot_cipher`, absorbing a
fixed input per round and finalizing into a hash digest or squeezing a
fixed-size XOF output. SHAKE128 / SHAKE256 squeeze 32 bytes per round so the
per-byte input cost dominates.

### MD5 / SHA-1 / RIPEMD-160 (legacy)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| md5 | 128 | 206.5 | ±0.8391 | 207 | 360.7 | ±5.679 | 50 | 115.2 | ±9.586 | 3265 |
| sha1 | 160 | 182 | ±0.8126 | 200 | 275.1 | ±3.627 | 56 | 152.6 | ±9.664 | 800 |
| ripemd160 | 160 | 212.2 | ±0.6193 | 800 | 161.9 | ±1.378 | 80 | 95.99 | ±4.79 | 55 |

### SHA-2 (FIPS 180-4)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| sha224 | 224 | 193.6 | ±0.5624 | 890 | 206 | ±1.588 | 80 | 96.93 | ±7.222 | 4734 |
| sha256 | 256 | 193.7 | ±0.3768 | 770 | 206.1 | ±3.116 | 80 | 97.1 | ±6.566 | 5873 |
| sha384 | 384 | 238.9 | ±0.1269 | 475 | 318.8 | ±1.86 | 80 | 149.4 | ±12.45 | 955 |
| sha512 | 512 | 293.2 | ±2.198 | 740 | 318.6 | ±1.851 | 50 | 153.4 | ±12.79 | 58 |
| sha512_224 | 224 | 256.2 | ±1.097 | 292 | 318.4 | ±1.736 | 55 | 154.8 | ±11.4 | 50 |
| sha512_256 | 256 | 256.3 | ±0.3129 | 561 | 317.5 | ±2.736 | 87 | 143.7 | ±11.89 | 355 |

### SHA-3 (FIPS 202)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| sha3_224 | 224 | 238 | ±13.84 | 625 | 307 | ±1.939 | 80 | 189.4 | ±15.7 | 177 |
| sha3_256 | 256 | 226.7 | ±7.664 | 80 | 286.8 | ±1.796 | 50 | 179.5 | ±14.84 | 50 |
| sha3_384 | 384 | 176.5 | ±7.119 | 478 | 223.1 | ±1.908 | 140 | 124.9 | ±10.4 | 2577 |
| sha3_512 | 512 | 134.5 | ±0.8357 | 920 | 156.9 | ±1.103 | 50 | 95.47 | ±6.359 | 5903 |

### SHAKE XOFs (FIPS 202; 32-byte squeeze)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| shake128 | xof | 262.4 | ±8.668 | 175 | 351.5 | ±1.199 | 50 | 209.8 | ±16.86 | 170 |
| shake256 | xof | 234.4 | ±1.655 | 770 | 286.6 | ±2.071 | 110 | 186.6 | ±14.84 | 53 |

Cross-platform summary Kiviat diagrams (radar charts; log-radial axis,
outer ring = faster):

![Symmetric throughput Kiviat (Tolkien / Dennard / Heinlein)](assets/sweep-2026-06-11-symmetric-radar.svg)

![Hash throughput Kiviat (Tolkien / Dennard / Heinlein)](assets/sweep-2026-06-11-hash-radar.svg)
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
