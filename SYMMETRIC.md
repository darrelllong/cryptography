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

- `DES / Triple-DES`: classic Feistel structure with tiny S-boxes and heavy
  bit-permutation machinery. The implementation preserves the traditional fast
  table-driven shape because the whole point of DES in software is how far that
  old design can be pushed, while `DesCt` makes the constant-time tradeoff
  explicit instead of pretending the two goals coincide.
- `AES`: optimized software wants T-tables; side-channel discipline wants a
  table-free nonlinear layer. The crate keeps both views visible: the fast path
  for ordinary software benchmarking, and a separate Boyar-Peralta-style `Ct`
  path so the constant-time cost is concrete.
- `CAST-128 / CAST5`: a round-function-heavy Feistel cipher built around large
  keyed S-boxes. It is historically interesting because it sits between DES-era
  Feistel design and the later AES finalists, so the implementation keeps the
  keyed-round shape obvious rather than hiding it behind abstractions.
- `Camellia`: an AES-era design that deliberately blends an SP-network core
  with Feistel-style `FL` / `FLINV` layers. The writeup and code keep that
  hybrid structure visible because that split personality is the whole design.
- `Serpent`: brute-force conservative design. Its philosophy is “simple boolean
  layers, many rounds, wide security margin,” so the implementation keeps the
  bitslice round structure explicit rather than chasing table speed tricks.
- `Twofish`: key-dependent S-boxes plus an MDS layer and whitening. The code
  keeps the `q` permutations, RS/MDS layers, and keyed `h()` transform visible
  because Twofish’s design is about the interaction of those components, not
  just the Feistel shell around them.
- `SEED`: a national-standard Feistel cipher that leans on large 8-bit S-boxes
  and a compact algebraic round mix. The implementation favors readability of
  the round algebra and the key schedule over trying to disguise it as “just
  another AES-like block cipher.”
- `PRESENT`: ultra-lightweight substitution-permutation design. Its philosophy
  is minimum hardware footprint, so the code keeps the 4-bit S-box / bit
  permutation structure direct and simple.
- `Magma`: 32-round Feistel design with 4-bit substitution and a single rotate.
  It is intentionally small and regular, so the implementation keeps the nibble
  structure obvious and treats the `Ct` path as a software side-channel
  concession rather than a redesign.
- `Grasshopper`: byte-oriented SP-network whose identity is its linear `L`
  transform over `GF(2^8)`. The code emphasizes that linear layer because it is
  the part that makes Grasshopper look and cost different from AES.
- `SM4`: a pragmatic byte-oriented national standard whose round function is a
  compact “S-box then linear diffusion” transform. The implementation keeps the
  `T = L(tau(...))` structure front and center because that is the design’s
  defining rhythm.
- `SIMON`: minimalist bitwise Feistel design. Its philosophy is “only the
  operations hardware and software both like”: rotates, AND, XOR. That is why
  there is no separate `Ct` split; the native round function is already close
  to the ideal constant-time software shape.
- `SPECK`: ARX counterpart to `SIMON`. Its design philosophy is software-first
  simplicity: add, rotate, XOR, and nothing else. The implementation therefore
  focuses on exactness and endianness rather than alternate `Ct` variants.

### Stream Ciphers

Implemented stream-cipher families:

- Salsa20
- ChaCha20
- XChaCha20
- ZUC-128

Design philosophy by family:

- `Salsa20`: Bernstein’s original “make a stream cipher out of a fast ARX
  core” design. The quarter-round structure is intentionally simple and
  pipeline-friendly, so the implementation keeps the core word-mixing visible.
- `ChaCha20`: a refinement of Salsa20 that pushes for better diffusion per
  round while keeping the same ARX spirit. The code keeps the quarter-round and
  state layout explicit because ChaCha’s design is evolutionary, not a totally
  different cipher.
- `XChaCha20`: not a new core cipher, but a longer-nonce construction around
  ChaCha20. Its design philosophy is operational robustness: keep ChaCha20’s
  fast core, but fix nonce-management pain by stretching a 24-byte nonce into a
  subkey plus ordinary ChaCha20 state.
- `ZUC-128`: very different from the ARX family. It is built around a
  word-structured LFSR plus a nonlinear filter and S-box layer, reflecting the
  mobile-stream-cipher design tradition rather than the Bernstein ARX line. The
  implementation leaves that contrast obvious, because the cost profile comes
  from that architectural choice.

## Symmetric Performance

Performance is measured with:

- `cipher_bench` for broad family coverage
- `aes_bench` for focused AES comparisons

Representative figures on this host:

| Primitive | Throughput |
|-----------|-----------:|
| Salsa20 | `833.0 MiB/s` |
| XChaCha20 | `825.6 MiB/s` |
| ChaCha20 | `829.7 MiB/s` |
| ZUC-128 | `549.2 MiB/s` |
| AES-128 | `539.9 MiB/s` |
| CAST-128 | `236.9 MiB/s` |
| Camellia-128 | `128.6 MiB/s` |
| SM4-128 | `118.3 MiB/s` |
| DES | `78.6 MiB/s` |
| SEED-128 | `70.8 MiB/s` |
| Magma-256 | `60.6 MiB/s` |
| Grasshopper-256 | `26.1 MiB/s` |
| Twofish-128 | `13.5 MiB/s` |
| PRESENT-80 | `12.7 MiB/s` |

The radar below compares representative fast-vs-`Ct` pairs. `SIMON` and
`SPECK` are intentionally absent because their shipped round functions are
already table-free bitwise/ARX designs, so there is no separate software `Ct`
variant to compare.

![Fast vs Ct throughput radar chart](assets/fast-vs-ct-radar.svg)

Focused AES measurements:

| AES path | Throughput |
|----------|-----------:|
| AES-128 (single block) | `388.6 MiB/s` |
| AES-192 (single block) | `378.0 MiB/s` |
| AES-256 (single block) | `329.7 MiB/s` |
| AES-256 (1 KiB) | `281.2 MiB/s` |
| AESCt-128 (single block) | `43.4 MiB/s` |
| AESCt-192 (single block) | `41.9 MiB/s` |
| AESCt-256 (single block) | `34.7 MiB/s` |
| AESCt-256 (1 KiB) | `41.5 MiB/s` |
| libsodium XSalsa20-Poly1305 (16 B) | `59.0 MiB/s` |
| libsodium XSalsa20-Poly1305 (1 KiB) | `544.4 MiB/s` |

## References

The primary standards and papers are stored in `pubs/`. The BibTeX index is in
[README.md](README.md).
