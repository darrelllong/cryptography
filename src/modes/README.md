# modes

Generic block-cipher modes of operation and AEAD constructions.

The adapters here are generic over any `BlockCipher` exported by the crate, so
the same wrapper works with AES, Camellia, DES, PRESENT, and the other block
ciphers in `../ciphers/`.  The point is to separate primitive choice from mode
choice: one cipher implementation can be dropped into several standardized
modes without duplicating the mode logic in every cipher module.

## Confidentiality modes (NIST SP 800-38A)

| Mode | Type | Notes |
|------|------|-------|
| ECB | unauthenticated | Deterministic; never use for more than one block |
| CBC | unauthenticated | Standard; requires random IV |
| CFB | unauthenticated | Full-block (CFB128) feedback |
| OFB | unauthenticated | Output feedback; keystream mode |
| CTR | unauthenticated | Counter mode; nonce must never repeat |

## Authentication and authenticated encryption

| Mode / Algorithm | Standard | Notes |
|------------------|----------|-------|
| CMAC | SP 800-38B | Block-cipher-based MAC; constant-time tag comparison |
| GCM / GMAC | SP 800-38D | Authenticated encryption with associated data |
| XTS | SP 800-38E | Narrow-block tweakable encryption for storage (128-bit ciphers only) |
| ChaCha20-Poly1305 | RFC 8439 | Stream-cipher AEAD; lives in `chacha20_poly1305.rs` |

## Safety rules

- **Nonce/IV reuse breaks security in CTR, OFB, GCM, and ChaCha20-Poly1305.**
  Never use the same (key, nonce) pair for more than one message.
- **ECB is almost never appropriate** for messages longer than one block; it
  leaks repeated plaintext blocks directly in the ciphertext.
- **Tag comparison must be constant-time.**  The `Gmac` and `Cmac` types use
  `crate::ct::constant_time_eq_mask` for verification.

## Variable-time paths

`GcmVt` and `GmacVt` are explicitly named variable-time variants retained for
benchmarking and reference purposes.  Do not use them where a side-channel
adversary is a concern.
