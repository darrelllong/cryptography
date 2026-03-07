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

### Modes

The generic mode layer in `src/modes/` supplies:

- SP 800-38A: `Ecb`, `Cbc`, `Cfb`, `Ofb`, `Ctr`
- SP 800-38B: `Cmac`
- SP 800-38D: `Gcm`, `Gmac`
- SP 800-38E: `Xts`

These wrappers are generic over any `BlockCipher`, so the same mode code works
across AES, DES, Camellia, PRESENT, CAST-128, and the other block ciphers.

Operational caveats:

- `ECB` is included for completeness and test coverage, not because it is a
  good default.
- `CBC`, `CFB`, `OFB`, and block-cipher `CTR` require correct IV / counter
  discipline from the caller.
- `GCM` requires nonce uniqueness, and the portable `GHASH` path is documented
  as not constant-time.
- `XTS` is for storage-style sector encryption, not general message transport.

### Hashes and XOFs

Implemented hash families:

- SHA-1
- SHA-2: `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`
- SHA-3: `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`
- XOFs: `Shake128`, `Shake256`

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

- `BlumBlumShub`
- `BlumMicali`
- `CtrDrbgAes256`

The first two are intentionally historical / reference generators. The
standards-track generator is `CtrDrbgAes256`, which follows SP 800-90A Rev. 1
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
95 %; **Runs** rounds required to reach CI.

### AES

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| aes128               |   128 |   128 |    464.1 |  ±15.67 |    31 |
| aes128ct             |   128 |   128 |    61.68 |  ±0.381 |   181 |
| aes192               |   128 |   192 |    402.9 |  ±7.027 |    30 |
| aes192ct             |   128 |   192 |     51.3 | ±0.3285 |   120 |
| aes256               |   128 |   256 |    333.7 |  ±4.566 |   753 |
| aes256ct             |   128 |   256 |    43.66 | ±0.2142 |    90 |

### Camellia

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| camellia128          |   128 |   128 |    140.7 |  ±0.843 |    60 |
| camellia128ct        |   128 |   128 |     6.26 | ±0.04426 |    90 |
| camellia192          |   128 |   192 |    101.2 | ±0.5437 |   120 |
| camellia192ct        |   128 |   192 |    4.708 | ±0.01722 |    31 |
| camellia256          |   128 |   256 |    102.2 | ±0.7348 |    31 |
| camellia256ct        |   128 |   256 |      4.7 | ±0.01893 |    30 |

### CAST-128

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| cast128              |    64 |   128 |    311.3 |  ±4.439 |   122 |
| cast128ct            |    64 |   128 |    3.995 | ±0.01505 |   270 |

### DES / 3DES

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| des                  |    64 |    56 |    78.49 | ±0.5123 |    92 |
| desct                |    64 |    56 |    7.769 | ±0.02268 |    30 |
| 3des                 |    64 |   168 |    22.29 | ±0.3726 |   156 |

### Grasshopper (GOST R 34.12-2015)

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| grasshopper          |   128 |   256 |    25.07 | ±0.09917 |   186 |
| grasshopperct        |   128 |   256 |    4.126 | ±0.04036 |   930 |

### Magma (GOST R 34.12-2015)

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| magma                |    64 |   256 |    61.66 | ±0.2394 |    71 |
| magmact              |    64 |   256 |     14.4 | ±0.01923 |   210 |

### PRESENT

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| present80            |    64 |    80 |    12.62 | ±0.06932 |   185 |
| present80ct          |    64 |    80 |    4.002 | ±0.02374 |   930 |
| present128           |    64 |   128 |    12.41 | ±0.1149 |   750 |
| present128ct         |    64 |   128 |    4.008 | ±0.02577 |    30 |

### SEED

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| seed                 |   128 |   128 |    72.11 |  ±0.523 |    36 |
| seedct               |   128 |   128 |     4.64 | ±0.03265 |    36 |

### Serpent

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| serpent128           |   128 |   128 |    10.91 | ±0.07563 |  1650 |
| serpent128ct         |   128 |   128 |    7.105 | ±0.05186 |   255 |
| serpent192           |   128 |   192 |    10.88 | ±0.08161 |   120 |
| serpent192ct         |   128 |   192 |     7.11 | ±0.05882 |    30 |
| serpent256           |   128 |   256 |    10.85 | ±0.1621 |   450 |
| serpent256ct         |   128 |   256 |    7.111 | ±0.06822 |    91 |

### SM4

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| sm4                  |   128 |   128 |      190 | ±0.5491 |    54 |
| sm4ct                |   128 |   128 |    6.903 | ±0.04886 |   150 |

### Twofish

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| twofish128           |   128 |   128 |    14.83 | ±0.09612 |   210 |
| twofish128ct         |   128 |   128 |    2.777 | ±0.007437 |    79 |
| twofish192           |   128 |   192 |    14.82 | ±0.1313 |    30 |
| twofish192ct         |   128 |   192 |    2.405 | ±0.007695 |    30 |
| twofish256           |   128 |   256 |    14.58 | ±0.1141 |   150 |
| twofish256ct         |   128 |   256 |    2.098 | ±0.005549 |    47 |

### Simon

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| simon32_64           |    32 |    64 |    84.37 | ±0.1127 |   690 |
| simon48_72           |    48 |    72 |    107.6 | ±0.6129 |    60 |
| simon48_96           |    48 |    96 |    106.3 | ±0.6814 |   120 |
| simon64_96           |    64 |    96 |    140.7 |  ±0.704 |    30 |
| simon64_128          |    64 |   128 |    133.7 | ±0.2722 |    60 |
| simon96_96           |    96 |    96 |    135.1 |  ±1.183 |    60 |
| simon96_144          |    96 |   144 |    131.4 | ±0.1556 |    90 |
| simon128_128         |   128 |   128 |    248.7 |  ±1.569 |   207 |
| simon128_192         |   128 |   192 |    243.2 |  ±1.642 |   120 |
| simon128_256         |   128 |   256 |    230.3 |   ±1.41 |   157 |

### Speck

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| speck32_64           |    32 |    64 |    208.5 | ±0.1665 |   390 |
| speck48_72           |    48 |    72 |    306.2 | ±0.5724 |   102 |
| speck48_96           |    48 |    96 |    266.1 |  ±3.143 |    42 |
| speck64_96           |    64 |    96 |    320.4 |  ±0.577 |    42 |
| speck64_128          |    64 |   128 |    305.9 | ±0.4533 |    60 |
| speck96_96           |    96 |    96 |    391.5 | ±0.5875 |    30 |
| speck96_144          |    96 |   144 |    375.8 | ±0.5743 |    37 |
| speck128_128         |   128 |   128 |    963.7 |  ±4.422 |    33 |
| speck128_192         |   128 |   192 |    925.7 |   ±4.53 |    67 |
| speck128_256         |   128 |   256 |    899.6 |  ±4.159 |    90 |

### Stream ciphers

| Cipher               | Block |   Key |   MB/s   | ±CI (95%) | Runs  |
|----------------------|-------|-------|----------|----------|-------|
| chacha20             | stream |   256 |    804.2 |  ±6.319 |    99 |
| xchacha20            | stream |   256 |    800.5 |  ±18.44 |    30 |
| salsa20              | stream |   256 |    821.1 |  ±5.454 |    45 |
| rabbit               | stream |   128 |     1467 |  ±53.13 |    36 |
| snow3g               | stream |   128 |    518.1 |  ±1.487 |   103 |
| snow3gct             | stream |   128 |    21.79 | ±0.03249 |    30 |
| zuc128               | stream |   128 |    541.8 | ±0.9094 |   105 |
| zuc128ct             | stream |   128 |    27.99 | ±0.1396 |   125 |

The radar below compares representative fast-vs-`Ct` pairs across the
table-driven ciphers. Simon and Speck are absent because their designs are
already table-free bitwise/ARX, so there is no software `Ct` variant to
compare.

![Fast vs Ct throughput radar chart](assets/fast-vs-ct-radar.svg)

## References

The primary standards and papers are stored in `pubs/`. The BibTeX index is in
[README.md](README.md).
