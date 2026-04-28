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
`Hmac<H>` implementation work across all hash families without duplicating the
HMAC state machine.

```
Digest trait
  ├── Md5
  ├── Ripemd160
  ├── Sha1
  ├── Sha224 / Sha256 / Sha384 / Sha512 / Sha512_224 / Sha512_256
  └── Sha3_224 / Sha3_256 / Sha3_384 / Sha3_512

Hmac<H: Digest>   ← wraps any Digest implementor
Hkdf<H: Digest>   ← wraps any Digest implementor (extract + expand phases)
```

## Length-extension caveat

SHA-1 and SHA-2 are Merkle-Damgård constructions.  Their raw outputs are
vulnerable to length-extension attacks — an attacker who knows `H(secret ‖ msg)`
can compute `H(secret ‖ msg ‖ padding ‖ extra)` without knowing `secret`.  Use
`Hmac<H>` for keyed authentication, or prefer SHA-3 / SHAKE when you want
sponge semantics that are structurally immune to length extension.

## XOF usage

`Shake128` and `Shake256` expose `squeeze(n)` in addition to the standard
`Digest` interface, allowing arbitrary-length output for use as a key-derivation
or mask-generation function.
