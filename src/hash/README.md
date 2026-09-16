# hash

Hash functions, extendable-output functions (XOFs), and keyed constructions.

## Implemented algorithms

| File | Algorithm | Standard |
|------|-----------|----------|
| `md5.rs` | MD5 (legacy) | RFC 1321 |
| `ripemd160.rs` | RIPEMD-160 (legacy) | Dobbertin-Bosselaers-Preneel 1996 |
| `sha1.rs` | SHA-1 | FIPS 180-4 |
| `sha2.rs` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS 180-4 |
| `sha3.rs` | SHA3-224/256/384/512, SHAKE128, SHAKE256 | FIPS 202 |
| `hmac.rs` | HMAC (`Hmac<H>`) | FIPS 198-1 / RFC 2104 |
| `hkdf.rs` | HKDF (`Hkdf<H>`) | RFC 5869 |

## Design

The `Digest` trait (defined in `mod.rs`) is the common interface that lets one
`Hmac<H>` implementation work across all fixed-output hash families without
duplicating the HMAC state machine. The `Xof` trait is the interface of the
extendable-output functions; the SHAKE types implement `Xof`, not `Digest`.

```
Digest trait
  ├── Md5
  ├── Ripemd160
  ├── Sha1
  ├── Sha224 / Sha256 / Sha384 / Sha512 / Sha512_224 / Sha512_256
  └── Sha3_224 / Sha3_256 / Sha3_384 / Sha3_512

Xof trait
  └── Shake128 / Shake256

Hmac<H: Digest>   ← wraps any Digest implementor
Hkdf<H: Digest>   ← wraps any Digest implementor (extract + expand phases)
```

Every `Digest` offers `new`, `update`, `finalize_into`, `finalize_reset` and
`zeroize`. `finalize_reset` writes the digest, scrubs the state that produced
it, and leaves the hasher indistinguishable from `new()`, so it can absorb a
second message; `Hmac<H>` relies on that scrub to drop key-derived chaining
values as soon as a tag is produced. Every hash in this directory also wipes
its state on drop.

## Length-extension caveat

MD5, RIPEMD-160, SHA-1 and SHA-2 are Merkle-Damgård constructions. Their raw
outputs are vulnerable to length-extension attacks — an attacker who knows
`H(secret ‖ msg)` and the length of `secret` can compute
`H(secret ‖ msg ‖ padding ‖ extra)` without knowing `secret`. Use `Hmac<H>`
for keyed authentication, or prefer SHA-3 / SHAKE when you want sponge
semantics that are structurally immune to length extension.

## XOF usage

`Shake128` and `Shake256` implement the `Xof` trait: `update(&[u8])` absorbs,
and `squeeze(&mut [u8])` fills the caller's buffer with the next output bytes.
The first `squeeze` pads and permutes the sponge in place; later calls continue
the same output stream, so any number of bytes may be drawn in pieces of any
size, and a longer output begins with the bytes of a shorter one. Calling
`update` after the first `squeeze` panics. The one-shot helper
`Shake128::digest(data, &mut out)` absorbs `data` and fills `out`. The output
length is whatever the caller asks for, which is what makes the SHAKE
functions usable as key-derivation or mask-generation functions.
