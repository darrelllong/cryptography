# SYMMETRIC

This document covers the symmetric half of the crate:

- block ciphers
- stream ciphers
- modes of operation
- hash functions and XOFs
- MACs
- CSPRNGs
- symmetric throughput measurements

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

Design notes:

- AES uses a fast T-table path plus a separate Boyar-Peralta-based software
  constant-time path.
- DES keeps the fast SP-table path and a separate `DesCt` path.
- Magma, Grasshopper, Camellia, SEED, PRESENT, CAST-128, Serpent, and Twofish
  all follow the same principle where the `Ct` variant exists: preserve the
  fast path, and keep the table-free path explicit and separate.
- `SIMON` and `SPECK` are already close to the ideal software shape for
  side-channel discipline and portability, so the focus there is correctness and
  interoperability rather than a fast-vs-`Ct` split.

### Stream Ciphers

Implemented stream-cipher families:

- Salsa20
- ChaCha20
- XChaCha20
- ZUC-128

Design notes:

- Salsa20 / ChaCha20 / XChaCha20 are pure ARX designs and are naturally strong
  software fits.
- ZUC is heavier because it combines a 16-word 31-bit LFSR with a nonlinear
  filter and S-boxes; it is still fast, but it has a very different cost shape
  from the ARX stream ciphers.

## Symmetric Performance

The throughput story is tracked by:

- `cipher_bench` for broad family coverage
- `aes_bench` for focused AES comparisons

Representative figures on this host:

| Primitive | Throughput |
|-----------|-----------:|
| Salsa20 | `856.7 MiB/s` |
| XChaCha20 | `840.6 MiB/s` |
| ChaCha20 | `838.1 MiB/s` |
| ZUC-128 | `552.3 MiB/s` |
| AES-128 | `522.7 MiB/s` |
| CAST-128 | `244.3 MiB/s` |
| Camellia-128 | `123.0 MiB/s` |
| SM4-128 | `113.0 MiB/s` |
| DES | `78.9 MiB/s` |
| Magma-256 | `59.1 MiB/s` |
| Grasshopper-256 | `24.0 MiB/s` |
| Twofish-128 | `14.6 MiB/s` |
| PRESENT-80 | `12.2 MiB/s` |

The fast-vs-`Ct` comparison still belongs to the existing radar chart in
`assets/fast-vs-ct-radar.svg`. That chart intentionally excludes `SIMON` and
`SPECK`, because there is no distinct software `Ct` split to plot for those
two families.

## References

The primary standards and papers are stored in `pubs/`. The BibTeX index is in
[README.md](README.md).
