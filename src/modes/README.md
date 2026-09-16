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
| `chacha20_poly1305.rs` | `ChaCha20Poly1305` | RFC 8439 |
| `eax.rs` | `Eax` authenticated mode | Bellare-Rogaway-Wagner 2003 |
| `gcm_siv.rs` | `AesGcmSiv<C>` (POLYVAL-based misuse-resistant AEAD), aliased `Aes128GcmSiv`, `Aes256GcmSiv`, `Aes128GcmSivCt`, `Aes256GcmSivCt` | RFC 8452 |
| `ghash.rs` | GHASH block multiplication (constant-time table and printed-algorithm variants) and POLYVAL | SP 800-38D §6.3, RFC 8452 §3 |
| `ocb.rs` | `Ocb<C, TAG_LEN>` (OCB3, TAGLEN 128/96/64) | RFC 7253 |
| `poly1305.rs` | `Poly1305` one-time authenticator | RFC 8439 |
| `siv.rs` | `Siv<C>` (deterministic / misuse-resistant AEAD) | RFC 5297 |

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
| CMAC | SP 800-38B | `Cmac<C>` for 64- and 128-bit block ciphers; full-block tags only |
| CCM | SP 800-38C / RFC 3610 | `Ccm<C, TAG_LEN>`, nonces of 7 to 13 bytes (L = 8 down to 2), tags of 4 to 16 bytes |
| GCM / GMAC | SP 800-38D | `Gcm`/`Gmac` use the constant-time GHASH; `GcmVt`/`GmacVt` are the printed Algorithm 1, variable-time in both operands. Payload at most 2^32 − 2 blocks per call |
| XTS | SP 800-38E | `Xts<C>`, 128-bit ciphers only; data units of 1 to 2^20 blocks (§4) |
| AES Key Wrap | SP 800-38F / RFC 3394 | `AesKeyWrap` (no padding) |
| EAX | Bellare-Rogaway-Wagner 2003 | Lives in `eax.rs` |
| OCB3 | RFC 7253 | Lives in `ocb.rs`; TAGLEN is part of the type |
| SIV | RFC 5297 | Lives in `siv.rs`; at most 2^36 − 16 bytes per message (32-bit counter addition, §2.5) and 126 associated-data components (§7) |
| AES-GCM-SIV | RFC 8452 | `AesGcmSiv<C>` in `gcm_siv.rs`; `C` is one of the four AES types and fixes the AES timing |
| ChaCha20-Poly1305 | RFC 8439 | Lives in `chacha20_poly1305.rs`; at most 2^38 − 64 bytes per message (§2.8) |

## Safety rules

- **Nonce/IV reuse breaks security in CTR, OFB, CCM, GCM, EAX, OCB, and
  ChaCha20-Poly1305.** Never use the same (key, nonce) pair for more than
  one message. SIV and AES-GCM-SIV are misuse-resistant by construction;
  they degrade gracefully under nonce reuse but should still receive unique
  nonces when one is available.
- **ECB is almost never appropriate** for messages longer than one block; it
  leaks repeated plaintext blocks directly in the ciphertext.
- **Tag comparison is constant-time everywhere.** Every verifier in this
  directory compares through `crate::ct::constant_time_eq_mask`, which reads
  every byte of both tags and rejects a tag of the wrong length outright.
  Where a verifier takes a `&[u8]` tag (`Gcm`, `Gmac`, `Cmac`), only the full
  tag length is accepted; truncated tags are never matched as prefixes.
- **Decrypt paths refuse, they do not panic, on sender-controlled shapes.**
  A ciphertext longer than the mode's bound (GCM, CCM, SIV,
  ChaCha20-Poly1305) or an SIV component count over 126 returns `false`
  with the buffer untouched; the same bound is a panic on the encrypt side,
  where the length is the caller's own.
- **Secrets are wiped.** Key schedules, CMAC subkeys, GHASH tables, OCB
  offsets, Poly1305 state, GCM-SIV per-nonce keys and speculative plaintext
  are zeroized on drop or before return, in every build.

## Variable-time paths

`GcmVt` and `GmacVt` are explicitly named variable-time variants retained for
benchmarking and reference purposes; their GHASH branches on the data and on
the hash subkey.  `Aes128GcmSiv`/`Aes256GcmSiv` run RFC 8452 on the T-table
AES, whose table indices are secret; `Aes128GcmSivCt`/`Aes256GcmSivCt` run it
on the constant-time AES.  Do not use a variable-time path where a
side-channel adversary is a concern.
