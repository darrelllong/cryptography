# public_key

Public-key cryptography: arithmetic foundations, classical schemes, elliptic
curves, and post-quantum primitives.

All implementations are written from published specifications in pure Rust.
**These operations are currently variable-time** and are intentionally exported
under `crate::vt` to make that side-channel property explicit at the API
boundary.

## Arithmetic foundations

| File | Purpose |
|------|---------|
| `bigint.rs` | Limb-based arbitrary-precision integers; Montgomery multiplication |
| `primes.rs` | Primality testing (Miller-Rabin), safe prime generation |
| `gf2m.rs` | Binary-field arithmetic for binary-curve implementations (private) |

## Classical schemes

| File | Scheme | Standard |
|------|--------|----------|
| `rsa.rs` | RSA textbook arithmetic | FIPS 186 |
| `rsa_pkcs1.rs` | OAEP encryption, PSS signatures | PKCS #1 v2.2 / RFC 8017 |
| `rsa_io.rs` | Key serialization: PKCS #1, PKCS #8, SPKI, flat XML | RFC 3447 / RFC 5958 |
| `dh.rs` | Finite-field Diffie-Hellman | RFC 3526 |
| `dsa.rs` | Digital Signature Algorithm | FIPS 186 |
| `elgamal.rs` | ElGamal encryption over a prime-order group | Taher ElGamal 1985 |
| `cocks.rs` | Cocks IBE (identity-based encryption) | Clifford Cocks 2001 |
| `paillier.rs` | Paillier homomorphic encryption | Pascal Paillier 1999 |
| `rabin.rs` | Rabin encryption | Michael Rabin 1979 |
| `schmidt_samoa.rs` | Schmidt-Samoa encryption | Katja Schmidt-Samoa 2006 |

## Elliptic-curve schemes (Weierstrass)

| File | Scheme |
|------|--------|
| `ec.rs` | Weierstrass-form affine/projective arithmetic; named curves (P-192/224/256/384/521, secp256k1) |
| `ecdh.rs` | Elliptic-curve Diffie-Hellman |
| `ecdsa.rs` | ECDSA (FIPS 186) |
| `ec_elgamal.rs` | ElGamal encryption over an elliptic-curve group |
| `ecies.rs` | ECIES hybrid encryption |

## Elliptic-curve schemes (Edwards / Montgomery)

| File | Scheme |
|------|--------|
| `ec_edwards.rs` | Twisted Edwards-form arithmetic; Ed25519 / Ed448 curves |
| `ed25519.rs` | Ed25519 signing (RFC 8032) |
| `eddsa.rs` | Generic EdDSA over Edwards curves |
| `edwards_dh.rs` | X25519 / X448 Diffie-Hellman (RFC 7748) |
| `edwards_elgamal.rs` | ElGamal encryption on Edwards curves |

## Post-quantum schemes

| File | Scheme | Standard |
|------|--------|----------|
| `ml_kem.rs` | ML-KEM (Kyber) key encapsulation | FIPS 203 |
| `ml_dsa.rs` | ML-DSA (Dilithium) signatures | FIPS 204 |

## Key serialization (`io.rs`, `rsa_io.rs`)

Non-RSA keys use a crate-defined DER encoding (a `SEQUENCE` of positive
`INTEGER`s) plus optional PEM armor and a flat XML form for human-readable
dumps.  RSA keys additionally support standard PKCS #1 and PKCS #8 / SPKI
encodings for interoperability with OpenSSL and other tooling.

## Naming conventions

- `*_with_nonce` — deterministic entry point that takes external randomness
- `to_wire_bytes` / `from_wire_bytes` — compact standard encoding (no curve/algorithm parameters)
- `to_key_blob` / `from_key_blob` — self-describing binary format defined by this crate
