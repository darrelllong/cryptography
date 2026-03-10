# SYMMETRIC

The symmetric side follows the same project-wide implementation rule as the
rest of the crate: pure idiomatic Rust, no architecture intrinsics, no C/FFI,
and as few dependencies as possible. Where a fast table-driven path and a
portable software constant-time path pull in different directions, the crate
keeps both visible rather than hiding the tradeoff.

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

To make the delta explicit: this pass mainly filled in missing hash and mode
surface APIs, not new block-cipher families.

- Hashes completed for compatibility: `Md5`, `Sha1`
- Stream-cipher extended-nonce variant: `XChaCha20`
- Newly documented AEAD/misuse-resistant mode surface:
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
- `GCM` requires nonce uniqueness. `Gcm`/`Gmac` are the default constant-time
  GHASH path and `GcmVt`/`GmacVt` are explicit variable-time reference paths.
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
  It is a byte-oriented SP-network whose identity is its linear `L` transform
  over `GF(2^8)`. Compared to `Magma`, it reflects a much more modern
  byte-oriented design style. The code emphasizes that linear layer because it
  is the part that makes Grasshopper look and cost different from AES.
- `SM4`: the Chinese national standard. Its round function is a compact
  “S-box then linear diffusion” transform, a pragmatic software/hardware middle
  ground that looks closer to the East Asian national-standard family than to
  the Bernstein ARX line. The implementation keeps the `T = L(tau(...))`
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

Measured with [pilot-bench](https://github.com/ascar-io/pilot-bench) driving
`pilot_cipher`, a dedicated Rust binary that encrypts 1 MiB per round and
prints MB/s to stdout.  Pilot repeats the round until a 20 % confidence
interval is achieved, correcting for autocorrelation and startup transients.
Columns: **Block** and **Key** in bits; **MB/s** mean; **±CI** half-width at
95 %; **Runs** rounds required to reach CI. The tables below are parallel runs
on:

- Apple M4 Pro (`Dyson.local`)
- AMD EPYC 7452 (`moore.soe.ucsc.edu`, single-core slice)

### AES

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| aes128 | 128 | 128 | 480.2 | ±5 | 57 | 230.6 | ±7.088 | 30 |
| aes128ct | 128 | 128 | 61.85 | ±1.897 | 40 | 33.75 | ±0.1116 | 67 |
| aes192 | 128 | 192 | 398.6 | ±5.201 | 75 | 199 | ±1.453 | 77 |
| aes192ct | 128 | 192 | 51.23 | ±0.2163 | 30 | 28.36 | ±0.09374 | 45 |
| aes256 | 128 | 256 | 334.5 | ±5.208 | 61 | 174.4 | ±1.294 | 60 |
| aes256ct | 128 | 256 | 43.34 | ±0.2367 | 30 | 24.41 | ±0.05811 | 58 |

### Camellia

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| camellia128 | 128 | 128 | 140.1 | ±1.296 | 31 | 85.6 | ±0.3457 | 117 |
| camellia128ct | 128 | 128 | 6.266 | ±0.0719 | 30 | 2.004 | ±0.003011 | 30 |
| camellia192 | 128 | 192 | 101.9 | ±0.537 | 79 | 63.83 | ±0.2938 | 30 |
| camellia192ct | 128 | 192 | 4.689 | ±0.06366 | 30 | 1.504 | ±0.002087 | 48 |
| camellia256 | 128 | 256 | 101.8 | ±0.7546 | 45 | 63.65 | ±0.2809 | 31 |
| camellia256ct | 128 | 256 | 4.687 | ±0.06364 | 30 | 1.504 | ±0.003277 | 60 |

### CAST-128

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| cast128 | 64 | 128 | 310.1 | ±2.876 | 36 | 103.7 | ±0.5374 | 58 |
| cast128ct | 64 | 128 | 3.965 | ±0.0415 | 30 | 1.825 | ±0.01507 | 30 |

### DES / 3DES

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| des | 64 | 56 | 78.2 | ±0.3919 | 30 | 54.64 | ±0.7965 | 30 |
| desct | 64 | 56 | 7.743 | ±0.02073 | 30 | 3.448 | ±0.008777 | 30 |
| 3des | 64 | 168 | 22.57 | ±0.6182 | 32 | 17.44 | ±0.0762 | 31 |

### Grasshopper (GOST R 34.12-2015)

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| grasshopper | 128 | 256 | 25.62 | ±0.09658 | 95 | 12.74 | ±0.05128 | 60 |
| grasshopperct | 128 | 256 | 4.059 | ±0.05462 | 30 | 1.577 | ±0.002743 | 30 |

### Magma (GOST R 34.12-2015)

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| magma | 64 | 256 | 60.38 | ±0.3278 | 90 | 41.29 | ±0.112 | 57 |
| magmact | 64 | 256 | 14.09 | ±0.1227 | 42 | 6.367 | ±0.01607 | 30 |

### PRESENT

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| present80 | 64 | 80 | 12.37 | ±0.07412 | 36 | 2.735 | ±0.003738 | 37 |
| present80ct | 64 | 80 | 3.977 | ±0.01763 | 30 | 1.308 | ±0.003027 | 30 |
| present128 | 64 | 128 | 12.35 | ±0.2248 | 30 | 2.734 | ±0.004611 | 49 |
| present128ct | 64 | 128 | 3.966 | ±0.03544 | 30 | 1.306 | ±0.003018 | 60 |

### SEED

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| seed | 128 | 128 | 73.57 | ±0.2741 | 150 | 46.13 | ±0.1755 | 30 |
| seedct | 128 | 128 | 4.589 | ±0.02159 | 61 | 1.491 | ±0.002914 | 45 |

### Serpent

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| serpent128 | 128 | 128 | 10.83 | ±0.04038 | 30 | 4.751 | ±0.01487 | 30 |
| serpent128ct | 128 | 128 | 7.03 | ±0.02025 | 32 | 1.851 | ±0.003566 | 88 |
| serpent192 | 128 | 192 | 10.86 | ±0.03361 | 51 | 4.73 | ±0.01376 | 30 |
| serpent192ct | 128 | 192 | 7.008 | ±0.1108 | 30 | 1.848 | ±0.00389 | 70 |
| serpent256 | 128 | 256 | 10.83 | ±0.04685 | 44 | 4.733 | ±0.01293 | 60 |
| serpent256ct | 128 | 256 | 6.991 | ±0.01398 | 104 | 1.849 | ±0.002784 | 50 |

### SM4

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sm4 | 128 | 128 | 184 | ±1.413 | 128 | 128.2 | ±0.9843 | 30 |
| sm4ct | 128 | 128 | 6.738 | ±0.06807 | 30 | 2.24 | ±0.005738 | 30 |

### Twofish

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| twofish128 | 128 | 128 | 14.55 | ±0.09168 | 31 | 9.156 | ±0.171 | 30 |
| twofish128ct | 128 | 128 | 2.702 | ±0.005262 | 30 | 1.12 | ±0.00286 | 60 |
| twofish192 | 128 | 192 | 14.34 | ±0.2681 | 90 | 8.111 | ±0.07719 | 45 |
| twofish192ct | 128 | 192 | 2.323 | ±0.02819 | 165 | 0.8461 | ±0.01275 | 31 |
| twofish256 | 128 | 256 | 13.97 | ±0.3346 | 60 | 7.167 | ±0.06002 | 55 |
| twofish256ct | 128 | 256 | 2.062 | ±0.009726 | 60 | 0.6832 | ±0.001777 | 37 |

### Simon

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| simon32_64 | 32 | 64 | 82.52 | ±0.3267 | 32 | 51.64 | ±0.1995 | 32 |
| simon48_72 | 48 | 72 | 105.3 | ±0.5297 | 60 | 68.16 | ±0.2938 | 31 |
| simon48_96 | 48 | 96 | 105.8 | ±0.5125 | 60 | 68.34 | ±0.3193 | 30 |
| simon64_96 | 64 | 96 | 138.7 | ±0.882 | 61 | 88.03 | ±0.4782 | 39 |
| simon64_128 | 64 | 128 | 131.2 | ±0.6786 | 60 | 84.18 | ±0.4384 | 30 |
| simon96_96 | 96 | 96 | 134 | ±0.626 | 48 | 90.93 | ±0.4078 | 34 |
| simon96_144 | 96 | 144 | 128.6 | ±0.5692 | 33 | 87.8 | ±0.4553 | 30 |
| simon128_128 | 128 | 128 | 244.3 | ±1.738 | 30 | 137.6 | ±0.7216 | 113 |
| simon128_192 | 128 | 192 | 239.5 | ±1.748 | 30 | 137.3 | ±0.8945 | 30 |
| simon128_256 | 128 | 256 | 228.2 | ±1.336 | 54 | 129.7 | ±0.7399 | 30 |

### Speck

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| speck32_64 | 32 | 64 | 202.6 | ±1.301 | 66 | 102.4 | ±0.4766 | 47 |
| speck48_72 | 48 | 72 | 296.7 | ±1.755 | 30 | 150.6 | ±1.134 | 30 |
| speck48_96 | 48 | 96 | 260.5 | ±1.68 | 36 | 140.6 | ±0.8969 | 40 |
| speck64_96 | 64 | 96 | 311.8 | ±2.333 | 60 | 208.6 | ±1.478 | 47 |
| speck64_128 | 64 | 128 | 297.5 | ±1.487 | 57 | 204.9 | ±1.873 | 35 |
| speck96_96 | 96 | 96 | 379.4 | ±2.337 | 41 | 204.3 | ±1.833 | 30 |
| speck96_144 | 96 | 144 | 362.9 | ±2.695 | 46 | 201.9 | ±1.551 | 60 |
| speck128_128 | 128 | 128 | 925.5 | ±7.761 | 55 | 407.8 | ±6.654 | 128 |
| speck128_192 | 128 | 192 | 895.7 | ±6.574 | 84 | 394.8 | ±6.199 | 60 |
| speck128_256 | 128 | 256 | 866.1 | ±9.775 | 30 | 383.3 | ±5.291 | 36 |

### Stream ciphers

| Cipher | Block | Key | M4 Pro MB/s | M4 Pro ±CI | M4 Pro Runs | AMD EPYC 7452 MB/s | AMD EPYC 7452 ±CI | AMD EPYC 7452 Runs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| chacha20 | stream | 256 | 775.9 | ±8.859 | 39 | 414.6 | ±7.206 | 31 |
| xchacha20 | stream | 256 | 778.9 | ±11.46 | 30 | 417.9 | ±5.124 | 38 |
| salsa20 | stream | 256 | 790.5 | ±10.37 | 35 | 406.6 | ±6.389 | 43 |
| rabbit | stream | 128 | 1401 | ±49.8 | 37 | 400.1 | ±5.626 | 30 |
| snow3g | stream | 128 | 480.1 | ±6.975 | 31 | 272.7 | ±2.918 | 30 |
| snow3gct | stream | 128 | 21.2 | ±0.4156 | 47 | 6.921 | ±0.0157 | 120 |
| zuc128 | stream | 128 | 520.7 | ±4.06 | 63 | 266 | ±1.998 | 120 |
| zuc128ct | stream | 128 | 27.65 | ±0.06046 | 30 | 8.859 | ±0.02948 | 30 |
Cross-platform summary Kiviat diagram (radar chart):

![Symmetric platform Kiviat diagram (radar chart)](assets/symmetric-platform-radar.svg)

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
| AES-128 encrypt | `compare_aes128` | MiB/s | 7033.98 | 421.95 | 16.67x |
| AES-256 encrypt | `compare_aes256` | MiB/s | 6966.60 | 347.10 | 20.07x |
| SHA-256 digest | `compare_sha256` | MiB/s | 2461.32 | 370.32 | 6.65x |
| ChaCha20 keystream | `compare_chacha20` | MiB/s | 1249.47 | 837.89 | 1.49x |
| GHASH multiply | `compare_ghash` | Mops/s | 154.84 | 9.07 (`ct_ref`) | 17.07x |

Apple go-fast speedup Kiviat diagram (radar chart, log scale):

![Apple go-fast speedup Kiviat diagram (radar chart)](assets/apple-go-fast-radar.svg)

## References

The primary standards and papers are stored in `pubs/`. The BibTeX index is in
[README.md](README.md).
