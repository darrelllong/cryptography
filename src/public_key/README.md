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
| `rsa.rs` | RSA textbook arithmetic | RFC 8017 / PKCS #1 v2.2 |
| `rsa_pkcs1.rs` | OAEP encryption, PSS signatures | PKCS #1 v2.2 / RFC 8017 |
| `rsa_io.rs` | Key serialization: PKCS #1, PKCS #8, SPKI, flat XML | RFC 8017 / RFC 5958 |
| `dh.rs` | Finite-field Diffie-Hellman (prime-order subgroup) | NIST SP 800-56A |
| `dsa.rs` | Digital Signature Algorithm | FIPS 186-5 |
| `elgamal.rs` | ElGamal encryption over a prime-order group | Taher ElGamal 1985 |
| `cocks.rs` | Cocks "Note on Non-Secret Encryption" (predecessor of RSA) | Clifford Cocks 1973 |
| `paillier.rs` | Paillier additively homomorphic encryption | Pascal Paillier 1999 |
| `rabin.rs` | Rabin encryption (square-root trapdoor) | Michael Rabin 1979 |
| `schmidt_samoa.rs` | Schmidt-Samoa encryption | Katja Schmidt-Samoa 2005 |

## Elliptic-curve schemes (Weierstrass)

| File | Scheme |
|------|--------|
| `ec.rs` | Weierstrass-form affine/projective arithmetic; named curves (P-192/224/256/384/521, secp256k1) |
| `ecdh.rs` | Elliptic-curve Diffie-Hellman |
| `ecdsa.rs` | ECDSA (FIPS 186) |
| `ec_elgamal.rs` | ElGamal encryption over an elliptic-curve group |
| `ecies.rs` | ECIES hybrid encryption |

## Elliptic-curve schemes (twisted Edwards)

| File | Scheme |
|------|--------|
| `ec_edwards.rs` | Twisted Edwards arithmetic; built-in `ed25519()` curve constructor |
| `ed25519.rs` | Ed25519 signing (RFC 8032) |
| `eddsa.rs` | Generic EdDSA over any twisted Edwards curve |
| `edwards_dh.rs` | Edwards-curve Diffie-Hellman (compressed-point shared secret) |
| `edwards_elgamal.rs` | ElGamal encryption on Edwards curves |

## Montgomery-curve ECDH (RFC 7748, constant-time)

| File | Scheme | Standard |
|------|--------|----------|
| `x25519.rs` | X25519 ECDH on Curve25519, Montgomery ladder | RFC 7748 §5 |
| `x448.rs` | X448 ECDH on Curve448, Montgomery ladder | RFC 7748 §5 |

Unlike the rest of this directory (which uses the variable-time `BigUint`
backend), `x25519.rs` and `x448.rs` carry their own fixed-radix limb
implementations (5×51 and 8×56 respectively) and drive the ladder with
mask-based `cswap`. They are the only public-key primitives in the crate
that aim for constant-time execution.

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
