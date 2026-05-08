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
**90%**; **Runs** rounds required to reach CI. The 2026-05-08 sweep was run
with `PILOT_PRESET=normal --confidence-level 0.90` (10% CI half-width target,
autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample size). The tables
below are parallel runs on:

- Apple M1 Max (`wigner.local`)
- AMD EPYC 7452 (`moore.soe.ucsc.edu`, single-core slice)
- Broadcom BCM2712 / Cortex-A76 (`darby.local`, Raspberry Pi 5)

### AES

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| aes128 | 128 | 128 | 356.4 | ±0.9831 | 80 | 235.7 | ±1.829 | 140 | 139.8 | ±0.8045 | 82 |
| aes128ct | 128 | 128 | 46.17 | ±0.1039 | 320 | 34.02 | ±0.1248 | 50 | 24.23 | ±0.1035 | 170 |
| aes192 | 128 | 192 | 315.5 | ±0.4863 | 110 | 202.1 | ±2.235 | 50 | 160 | ±0.9786 | 141 |
| aes192ct | 128 | 192 | 38.12 | ±0.06481 | 80 | 28.54 | ±0.09537 | 50 | 20.21 | ±0.07067 | 50 |
| aes256 | 128 | 256 | 250.6 | ±0.7166 | 50 | 177.1 | ±2.168 | 50 | 138.8 | ±0.7857 | 50 |
| aes256ct | 128 | 256 | 32.4 | ±0.04632 | 410 | 24.56 | ±0.08353 | 50 | 17.29 | ±0.01844 | 50 |

### Camellia

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| camellia128 | 128 | 128 | 97.47 | ±0.09227 | 50 | 86.53 | ±0.5178 | 50 | 67.81 | ±0.1235 | 110 |
| camellia128ct | 128 | 128 | 6.931 | ±0.009323 | 50 | 5.597 | ±0.03744 | 50 | 4.069 | ±0.04814 | 89 |
| camellia192 | 128 | 192 | 72.04 | ±0.03742 | 110 | 64.47 | ±0.4882 | 50 | 51.04 | ±0.1498 | 111 |
| camellia192ct | 128 | 192 | 5.186 | ±0.01478 | 268 | 4.21 | ±0.03525 | 50 | 3.062 | ±0.03578 | 53 |
| camellia256 | 128 | 256 | 71.88 | ±0.05252 | 80 | 64.65 | ±0.3383 | 85 | 51.1 | ±0.4869 | 50 |
| camellia256ct | 128 | 256 | 5.194 | ±0.01374 | 291 | 4.22 | ±0.07457 | 50 | 3.072 | ±0.004415 | 50 |

### CAST-128

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| cast128 | 64 | 128 | 159.3 | ±0.1357 | 110 | 105.2 | ±1.108 | 50 | 82.47 | ±0.2638 | 50 |
| cast128ct | 64 | 128 | 3.177 | ±0.001347 | 260 | 1.793 | ±0.01978 | 50 | 1.232 | ±0.007739 | 50 |

### DES / 3DES

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| des | 64 | 56 | 57.25 | ±0.4965 | 50 | 55.1 | ±0.9686 | 50 | 30.34 | ±0.03162 | 170 |
| desct | 64 | 56 | 6.725 | ±0.02042 | 140 | 3.431 | ±0.02564 | 110 | 3.244 | ±0.05373 | 50 |
| 3des | 64 | 168 | 17.88 | ±0.008375 | 140 | 17.79 | ±0.09266 | 80 | 12.98 | ±0.004598 | 50 |

### Grasshopper (GOST R 34.12-2015)

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| grasshopper | 128 | 256 | 21.29 | ±0.02079 | 170 | 12.72 | ±0.0412 | 50 | 8.468 | ±0.01668 | 85 |
| grasshopperct | 128 | 256 | 4.651 | ±0.00615 | 230 | 3.284 | ±0.01514 | 50 | 2.539 | ±0.0008846 | 138 |

### Magma (GOST R 34.12-2015)

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| magma | 64 | 256 | 37.02 | ±0.0281 | 322 | 41.59 | ±0.1462 | 50 | 35.3 | ±0.02601 | 50 |
| magmact | 64 | 256 | 8.633 | ±0.003988 | 264 | 6.355 | ±0.008156 | 50 | 4.207 | ±0.004817 | 50 |

### PRESENT

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| present80 | 64 | 80 | 8.504 | ±0.001738 | 140 | 2.715 | ±0.01966 | 50 | 2.591 | ±0.002261 | 231 |
| present80ct | 64 | 80 | 3.136 | ±0.005488 | 266 | 1.298 | ±0.006678 | 81 | 0.9516 | ±0.006601 | 50 |
| present128 | 64 | 128 | 8.49 | ±0.01227 | 382 | 2.721 | ±0.003386 | 50 | 2.588 | ±0.0168 | 100 |
| present128ct | 64 | 128 | 3.141 | ±0.0007753 | 110 | 1.299 | ±0.00775 | 53 | 0.9535 | ±0.004759 | 50 |

### SEED

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| seed | 128 | 128 | 47.61 | ±0.05084 | 50 | 46.36 | ±0.1403 | 58 | 37.62 | ±0.02907 | 80 |
| seedct | 128 | 128 | 5.891 | ±0.2516 | 57 | 4.112 | ±0.03756 | 80 | 3.082 | ±0.0006498 | 212 |

### Serpent

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| serpent128 | 128 | 128 | 8.632 | ±0.01872 | 290 | 4.743 | ±0.007977 | 110 | 3.494 | ±0.0109 | 50 |
| serpent128ct | 128 | 128 | 5.83 | ±0.02114 | 144 | 1.844 | ±0.001824 | 81 | 2.207 | ±0.02392 | 84 |
| serpent192 | 128 | 192 | 8.643 | ±0.002149 | 110 | 4.736 | ±0.008116 | 82 | 3.495 | ±0.004474 | 80 |
| serpent192ct | 128 | 192 | 5.842 | ±0.002745 | 200 | 1.844 | ±0.001803 | 50 | 2.214 | ±0.00753 | 113 |
| serpent256 | 128 | 256 | 8.621 | ±0.03315 | 204 | 4.737 | ±0.006896 | 81 | 3.496 | ±0.004042 | 170 |
| serpent256ct | 128 | 256 | 5.838 | ±0.01326 | 117 | 1.849 | ±0.001933 | 50 | 2.217 | ±0.00282 | 54 |

### SM4

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sm4 | 128 | 128 | 151.1 | ±0.1664 | 110 | 127 | ±0.4938 | 50 | 92.68 | ±0.3086 | 50 |
| sm4ct | 128 | 128 | 6.969 | ±0.004205 | 119 | 6.51 | ±0.01012 | 50 | 4.518 | ±0.002819 | 50 |

### Twofish

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| twofish128 | 128 | 128 | 9.738 | ±0.005917 | 110 | 8.534 | ±0.05697 | 50 | 3.008 | ±0.03873 | 265 |
| twofish128ct | 128 | 128 | 1.559 | ±0.005333 | 50 | 1.114 | ±0.004214 | 84 | 0.8263 | ±0.00348 | 50 |
| twofish192 | 128 | 192 | 8.932 | ±0.003328 | 110 | 7.491 | ±0.04178 | 50 | 2.967 | ±0.0009436 | 50 |
| twofish192ct | 128 | 192 | 1.252 | ±0.001759 | 140 | 0.8459 | ±0.002061 | 50 | 0.6786 | ±0.005858 | 50 |
| twofish256 | 128 | 256 | 8.189 | ±0.03009 | 170 | 6.355 | ±0.03226 | 80 | 2.911 | ±0.001273 | 50 |
| twofish256ct | 128 | 256 | 1.045 | ±0.004595 | 194 | 0.6793 | ±0.005783 | 50 | 0.5782 | ±0.001756 | 50 |

### Simon

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| simon32_64 | 32 | 64 | 58.66 | ±0.0704 | 170 | 52.11 | ±0.1861 | 52 | 43.36 | ±0.03966 | 110 |
| simon48_72 | 48 | 72 | 75.62 | ±0.1634 | 50 | 68.91 | ±0.3342 | 53 | 44.61 | ±0.2145 | 80 |
| simon48_96 | 48 | 96 | 75.72 | ±0.05977 | 110 | 68.84 | ±0.2542 | 110 | 56.34 | ±0.09593 | 590 |
| simon64_96 | 64 | 96 | 97.83 | ±0.1002 | 50 | 89.19 | ±0.4715 | 50 | 74.96 | ±0.2704 | 50 |
| simon64_128 | 64 | 128 | 92.56 | ±0.07547 | 80 | 85.35 | ±0.3437 | 80 | 71.72 | ±0.175 | 80 |
| simon96_96 | 96 | 96 | 96.89 | ±0.1023 | 200 | 91.99 | ±0.4026 | 50 | 74.97 | ±0.1697 | 110 |
| simon96_144 | 96 | 144 | 92.97 | ±0.05825 | 140 | 85.64 | ±0.5421 | 50 | 72.31 | ±0.1722 | 50 |
| simon128_128 | 128 | 128 | 179 | ±0.1919 | 50 | 139.7 | ±0.9062 | 84 | 141.2 | ±0.7199 | 80 |
| simon128_192 | 128 | 192 | 174.4 | ±0.9633 | 50 | 139.5 | ±0.5422 | 50 | 139.1 | ±0.6279 | 80 |
| simon128_256 | 128 | 256 | 166.5 | ±0.3014 | 50 | 132.4 | ±0.5397 | 83 | 134.4 | ±0.5315 | 58 |

### Speck

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| speck32_64 | 32 | 64 | 141.9 | ±0.1727 | 50 | 103.2 | ±0.4277 | 51 | 68.43 | ±0.1763 | 50 |
| speck48_72 | 48 | 72 | 213 | ±0.4183 | 260 | 153.7 | ±1.497 | 50 | 100 | ±0.3182 | 110 |
| speck48_96 | 48 | 96 | 173.2 | ±0.3022 | 170 | 142.6 | ±1.391 | 50 | 106.7 | ±0.3557 | 86 |
| speck64_96 | 64 | 96 | 193.5 | ±0.2764 | 80 | 213.1 | ±1.807 | 50 | 113.8 | ±0.4108 | 50 |
| speck64_128 | 64 | 128 | 184.7 | ±0.2486 | 81 | 208.3 | ±2.982 | 50 | 109.6 | ±0.4366 | 54 |
| speck96_96 | 96 | 96 | 252.2 | ±0.3605 | 50 | 209.6 | ±1.315 | 80 | 161.7 | ±0.9923 | 173 |
| speck96_144 | 96 | 144 | 241.7 | ±0.3399 | 50 | 205.5 | ±1.838 | 140 | 156.3 | ±2.924 | 175 |
| speck128_128 | 128 | 128 | 700.8 | ±0.8438 | 50 | 413.3 | ±7.241 | 50 | 207.2 | ±1.591 | 200 |
| speck128_192 | 128 | 192 | 669 | ±2.187 | 80 | 401.4 | ±6.254 | 50 | 202.9 | ±3.498 | 290 |
| speck128_256 | 128 | 256 | 642.9 | ±0.901 | 140 | 392.9 | ±9.408 | 50 | 200.4 | ±1.628 | 230 |

### Stream ciphers

| Cipher | Block | Key | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| chacha20 | stream | 256 | 537.6 | ±8.841 | 170 | 416.5 | ±13.17 | 55 | 229.3 | ±2.632 | 141 |
| xchacha20 | stream | 256 | 565.9 | ±0.8631 | 110 | 421.4 | ±9.901 | 50 | 229.7 | ±3.133 | 85 |
| salsa20 | stream | 256 | 544.3 | ±0.8385 | 230 | 414.9 | ±5.487 | 50 | 387.5 | ±3.457 | 621 |
| rabbit | stream | 128 | 998.2 | ±1.742 | 80 | 498.1 | ±24.29 | 50 | 343.6 | ±5.432 | 50 |
| snow3g | stream | 128 | 336.8 | ±0.5364 | 50 | 277.2 | ±2.431 | 140 | 224.7 | ±4.484 | 294 |
| snow3gct | stream | 128 | 39.37 | ±0.7302 | 170 | 24.05 | ±0.05734 | 80 | 17.31 | ±0.01423 | 80 |
| zuc128 | stream | 128 | 366.2 | ±0.228 | 410 | 262.8 | ±7.309 | 50 | 229.1 | ±1.296 | 507 |
| zuc128ct | stream | 128 | 39.65 | ±0.09218 | 170 | 25.08 | ±0.1789 | 80 | 17.76 | ±0.02297 | 50 |
### Hash and XOF throughput

`pilot_hash` reports the same MB/s shape as `pilot_cipher`, absorbing a
fixed input per round and finalizing into a hash digest or squeezing a
fixed-size XOF output. SHAKE128 / SHAKE256 squeeze 32 bytes per round so the
per-byte input cost dominates.

### MD5 / SHA-1 / RIPEMD-160 (legacy)

| Hash | Out | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| md5 | 128 | 265.5 | ±0.4472 | 80 | 407.6 | ±9.286 | 50 | 171.7 | ±0.8412 | 110 |
| sha1 | 160 | 212.6 | ±0.3821 | 50 | 276 | ±10.76 | 52 | 127.9 | ±0.6307 | 115 |
| ripemd160 | 160 | 276.1 | ±0.6673 | 85 | 135.1 | ±2.878 | 50 | 69.97 | ±0.2279 | 290 |

### SHA-2 (FIPS 180-4)

| Hash | Out | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| sha224 | 224 | 194.5 | ±0.3132 | 50 | 210.8 | ±4.164 | 80 | 115.7 | ±0.5723 | 50 |
| sha256 | 256 | 183.4 | ±9.603 | 170 | 213.4 | ±3.165 | 50 | 115.7 | ±0.4852 | 170 |
| sha384 | 384 | 296.2 | ±0.2573 | 143 | 331.8 | ±5.48 | 80 | 183.3 | ±0.8976 | 140 |
| sha512 | 512 | 295.7 | ±0.4227 | 50 | 330.8 | ±5.068 | 140 | 183.2 | ±1.346 | 50 |
| sha512_224 | 224 | 282.5 | ±3.542 | 50 | 327.5 | ±10.29 | 50 | 183.2 | ±1.086 | 142 |
| sha512_256 | 256 | 294.3 | ±2.018 | 170 | 332.5 | ±2.884 | 80 | 182.7 | ±1.394 | 80 |

### SHA-3 (FIPS 202)

| Hash | Out | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| sha3_224 | 224 | 355.4 | ±1.02 | 140 | 321.1 | ±6.156 | 55 | 79.26 | ±0.2791 | 80 |
| sha3_256 | 256 | 334.7 | ±0.5567 | 50 | 299.9 | ±6.291 | 54 | 94.73 | ±0.4218 | 170 |
| sha3_384 | 384 | 258.5 | ±0.387 | 50 | 233.4 | ±4.093 | 80 | 72.56 | ±0.2045 | 200 |
| sha3_512 | 512 | 180.7 | ±0.3678 | 50 | 164.3 | ±2.234 | 51 | 50.33 | ±0.1565 | 50 |

### SHAKE XOFs (FIPS 202; 32-byte squeeze)

| Hash | Out | Wigner (M1 Max) MB/s | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) MB/s | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) MB/s | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| shake128 | xof | 413 | ±1.212 | 50 | 370.7 | ±4.559 | 140 | 116.2 | ±1.12 | 50 |
| shake256 | xof | 336.3 | ±0.7572 | 50 | 302.2 | ±5.264 | 140 | 94.53 | ±0.5017 | 50 |
Cross-platform summary Kiviat diagrams (radar charts; log-radial axis,
outer ring = faster):

![Symmetric throughput Kiviat (Wigner / Moore / Darby)](assets/sweep-2026-05-08-symmetric-radar.svg)

![Hash throughput Kiviat (Wigner / Moore / Darby)](assets/sweep-2026-05-08-hash-radar.svg)
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
