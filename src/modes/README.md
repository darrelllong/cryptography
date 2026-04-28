# modes

Generic block-cipher modes of operation and AEAD constructions.

The adapters here are generic over any `BlockCipher` exported by the crate, so
the same wrapper works with AES, Camellia, DES, PRESENT, and the other block
ciphers in `../ciphers/`.  The point is to separate primitive choice from mode
choice: one cipher implementation can be dropped into several standardized
modes without duplicating the mode logic in every cipher module.

The basic modes (ECB, CBC, CFB, CFB8, OFB, CTR, CMAC, CCM, GCM/GMAC, XTS, AES
Key Wrap) are defined directly in `mod.rs`. The standalone AEADs each get
their own file:

| File | Construction | Standard |
|------|--------------|----------|
| `chacha20_poly1305.rs` | ChaCha20-Poly1305 (and `Poly1305` MAC re-export) | RFC 8439 |
| `eax.rs` | EAX authenticated mode | Bellare-Rogaway-Wagner 2003 |
| `gcm_siv.rs` | `Aes128GcmSiv` / `Aes256GcmSiv` (POLYVAL-based misuse-resistant AEAD) | RFC 8452 |
| `ocb.rs` | OCB3 authenticated mode | RFC 7253 |
| `poly1305.rs` | `Poly1305` one-time authenticator | RFC 8439 |
| `siv.rs` | SIV (deterministic / misuse-resistant AEAD) | RFC 5297 |

## Confidentiality modes (NIST SP 800-38A)

| Mode | Type | Notes |
|------|------|-------|
| ECB | unauthenticated | Deterministic; never use for more than one block |
| CBC | unauthenticated | Standard; requires random IV |
| CFB | unauthenticated | Full-block (CFB128) feedback |
| CFB8 | unauthenticated | Single-byte CFB feedback |
| OFB | unauthenticated | Output feedback; keystream mode |
| CTR | unauthenticated | Counter mode; nonce must never repeat |

## Authentication and authenticated encryption

| Mode / Algorithm | Standard | Notes |
|------------------|----------|-------|
| CMAC | SP 800-38B | Block-cipher-based MAC; constant-time tag comparison |
| CCM | SP 800-38C | Counter + CBC-MAC AEAD |
| GCM / GMAC | SP 800-38D | Authenticated encryption with associated data; `Gcm`/`Gmac` are constant-time GHASH, `GcmVt`/`GmacVt` are explicit variable-time variants |
| XTS | SP 800-38E | Narrow-block tweakable encryption for storage (128-bit ciphers only) |
| AES Key Wrap | SP 800-38F / RFC 3394 | `AesKeyWrap` (no padding) |
| EAX | Bellare-Rogaway-Wagner 2003 | Lives in `eax.rs` |
| OCB3 | RFC 7253 | Lives in `ocb.rs` |
| SIV | RFC 5297 | Deterministic / nonce-misuse-resistant; lives in `siv.rs` |
| AES-GCM-SIV | RFC 8452 | `Aes128GcmSiv`, `Aes256GcmSiv` in `gcm_siv.rs` |
| ChaCha20-Poly1305 | RFC 8439 | Lives in `chacha20_poly1305.rs` |

## Safety rules

- **Nonce/IV reuse breaks security in CTR, OFB, GCM, EAX, OCB, and
  ChaCha20-Poly1305.** Never use the same (key, nonce) pair for more than
  one message. SIV and AES-GCM-SIV are misuse-resistant by construction;
  they degrade gracefully under nonce reuse but should still receive unique
  nonces when one is available.
- **ECB is almost never appropriate** for messages longer than one block; it
  leaks repeated plaintext blocks directly in the ciphertext.
- **Tag comparison must be constant-time.**  The `Gmac` and `Cmac` types use
  `crate::ct::constant_time_eq_mask` for verification.

## Variable-time paths

`GcmVt` and `GmacVt` are explicitly named variable-time variants retained for
benchmarking and reference purposes.  Do not use them where a side-channel
adversary is a concern.
