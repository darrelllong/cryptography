# ciphers

Block and stream cipher primitive implementations.

Each file in this directory covers one cipher family: key schedule, encrypt,
decrypt, and the optional software constant-time (`Ct`) variant.  Higher-level
concerns — operating modes, authenticated encryption, MAC construction — live in
`../modes/` and `../hash/`.

## Block ciphers

| File | Cipher | Key sizes | Block |
|------|--------|-----------|-------|
| `aes.rs` | AES (FIPS 197) | 128 / 192 / 256 bit | 128 bit |
| `camellia.rs` | Camellia (RFC 3713) | 128 / 192 / 256 bit | 128 bit |
| `cast128.rs` | CAST-128 / CAST5 (RFC 2144) | 40–128 bit | 64 bit |
| `des.rs` | DES and Triple-DES (FIPS 46-3) | 56 / 112 / 168 bit | 64 bit |
| `grasshopper.rs` | Grasshopper (RFC 7801 / GOST R 34.12-2015) | 256 bit | 128 bit |
| `magma.rs` | Magma (RFC 8891 / GOST R 34.12-2015) | 256 bit | 64 bit |
| `present.rs` | PRESENT (ISO/IEC 29192-2) | 80 / 128 bit | 64 bit |
| `seed.rs` | SEED (RFC 4269 / KS X 1213) | 128 bit | 128 bit |
| `serpent.rs` | Serpent (AES finalist) | 128 / 192 / 256 bit | 128 bit |
| `simon.rs` | SIMON (NSA, 10 variants) | varies | 32–128 bit |
| `sm4.rs` | SM4 / SMS4 (GM/T 0002-2012) | 128 bit | 128 bit |
| `speck.rs` | SPECK (NSA, 10 variants) | varies | 32–128 bit |
| `twofish.rs` | Twofish (AES finalist) | 128 / 192 / 256 bit | 128 bit |

## Stream ciphers and PRNG-based ciphers

| File | Cipher | Standard |
|------|--------|----------|
| `chacha20.rs` | ChaCha20 and XChaCha20 | RFC 8439 |
| `rabbit.rs` | Rabbit | RFC 4503 |
| `salsa20.rs` | Salsa20 | eSTREAM |
| `snow3g.rs` | SNOW 3G | ETSI TS 135 202 |
| `zuc.rs` | ZUC-128 | 3GPP TS 35.221 |

## Naming conventions

- Plain struct (e.g., `Aes128`) — reference implementation; may use
  table-driven paths that are not hardened against cache-timing attacks.
- `Ct` suffix (e.g., `Aes128Ct`) — software constant-time variant using ANF
  S-box evaluation from `crate::ct`; access pattern is independent of key and
  plaintext data.

## Shared utilities

`simon_speck_util.rs` — shared round-function helpers factored out of
`simon.rs` and `speck.rs` to avoid duplication.
