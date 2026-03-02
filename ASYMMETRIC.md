# ASYMMETRIC

This document covers the public-key half of the crate:

- bigint and number-theory support
- public-key primitives
- standards-based and crate-defined wrappers
- key serialization
- public-key latency measurements

## Arithmetic Foundation

The public-key layer is built on:

- `BigUint`
- `BigInt`
- `MontgomeryCtx`
- shared number-theory helpers in `src/public_key/primes.rs`

The in-tree bigint backend stores `u64` limbs in little-endian limb order and
uses Montgomery multiplication for repeated modular arithmetic under odd
moduli. That is the common case for every currently implemented public-key
scheme here.

The design goal is:

- keep the arithmetic visible and auditable
- make the scheme logic match the companion Python code
- keep open the option of swapping the arithmetic backend later if larger-key
  performance demands it

## Three-Level API

Every implemented public-key scheme follows the same layering:

1. Arithmetic maps such as `encrypt_raw` / `decrypt_raw`, which operate
   directly on the integer domain.
2. Typed wrappers such as `encrypt` / `decrypt`, which accept message bytes and
   return the scheme-native ciphertext representation.
3. Byte wrappers such as `encrypt_bytes` / `decrypt_bytes`, which serialize the
   ciphertext so the scheme can be used as a byte-to-byte API.

Level 3 is the normal entry point for callers who just want to encrypt or
decrypt byte strings. Level 2 exists for schemes such as `Paillier` and
`ElGamal`, where callers may want to work with the structured ciphertext form
directly. Level 1 remains useful for arithmetic tests and direct cross-checks.

## Public-Key Surface

Implemented schemes:

- `Rsa`
- `Cocks`
- `ElGamal`
- `Rabin`
- `Paillier`
- `SchmidtSamoa`

Wrapper layers:

- `RsaOaep<H>` for `RSAES-OAEP`
- `RsaPss<H>` for `RSASSA-PSS`

Every implemented scheme now has:

- explicit key construction from mathematical parameters
- built-in key generation
- key serialization
- byte-oriented encrypt/decrypt helpers where encryption is defined

Only `RSA` currently has a standards-based message-formatting layer. The other
schemes expose explicit crate-defined message and serialization wrappers, which
is the honest thing to do because there is no equally universal RFC/NIST
padding story for those primitive forms.

## Serialization

### RSA

`RSA` uses real modern standards:

- public keys:
  - PKCS #1
  - SubjectPublicKeyInfo (SPKI)
- private keys:
  - PKCS #1
  - PKCS #8
- containers:
  - DER
  - PEM

RSA also has an optional XML export/import path purely for orthogonality and
debugging convenience; the canonical interoperable formats remain PKCS / X.509.

### Non-RSA Schemes

`Cocks`, `ElGamal`, `Rabin`, `Paillier`, and `SchmidtSamoa` use crate-defined
formats:

- binary: DER `SEQUENCE` of positive `INTEGER`s
- text:
  - scheme-specific PEM labels
  - a simple fixed-schema XML form

This deliberately copies the structural simplicity of the RSA key material
without pretending that those schemes have standard OIDs or a real PKCS/X.509
profile.

## Scheme Notes

### RSA

Core arithmetic:

```math
c = m^e \bmod n,\qquad m = c^d \bmod n
```

with:

```math
n = pq,\qquad d \equiv e^{-1} \pmod{\lambda(n)}
```

The practical RSA layer is the most complete in the crate:

- standards-based OAEP encryption
- standards-based PSS signatures
- standard key serialization
- generated or imported keys

### ElGamal

Core arithmetic:

```math
\gamma = g^k \bmod p,\qquad \delta = m \cdot y^k \bmod p,\qquad y = g^a \bmod p
```

The key-generation path uses a prime-order subgroup construction instead of the
older safe-prime search. That keeps the subgroup structure explicit while
avoiding the pathological key-generation cost that came from insisting on
`p = 2q + 1`.

The public key stores the real ephemeral bound used for encryption, so the
random ephemeral exponent is sampled from the right range instead of from the
full `p - 1` interval.

### Cocks

Core arithmetic:

```math
c = m^n \bmod n,\qquad n = pq,\qquad \pi \equiv n^{-1} \pmod{q - 1}
```

with the private recovery map:

```math
m = c^\pi \bmod q
```

This is here because it is historically important: Clifford Cocks proposed it
in 1973, five years before RSA. The scheme is unusual because the public
exponent is the modulus itself. The crate keeps that arithmetic intact and adds
the byte-level serialization layer on top instead of inventing a modernized
padding story that the literature does not standardize.

### Rabin

Core arithmetic:

```math
c = m^2 \bmod n,\qquad n = pq
```

Decryption computes square roots modulo `p` and `q`, then recombines them with
the Chinese remainder theorem to recover the four square roots modulo `n`.
Because plain Rabin is ambiguous, this crate uses a tagged-message variant: the
tag is carried inside the encoded plaintext and is used to select the intended
root deterministically at decrypt time.

Rabin is historically important because it is one of the earliest public-key
trapdoor constructions with a tight reduction story: in the plain setting,
inverting the squaring map modulo `n = pq` is essentially equivalent to
factoring `n`. That direct connection is part of why the scheme still matters
pedagogically even though modern deployments usually prefer RSA.

### Paillier

Core arithmetic:

```math
c = g^m r^n \bmod n^2
```

with decryption:

```math
m = L(c^\lambda \bmod n^2)\,\mu \bmod n,\qquad L(u) = \frac{u - 1}{n}
```

`Paillier` exposes both encryption/decryption and the natural homomorphic
operations:

- ciphertext rerandomization
- ciphertext multiplication modulo `n^2`, corresponding to plaintext addition

That homomorphic surface is a real part of the scheme, not an extra trick, so
it is intentionally part of the usable API.

That is also the reason to use `Paillier` at all: it is the cleanest additive
homomorphic primitive in this crate. If `c_1` encrypts `m_1` and `c_2`
encrypts `m_2`, then:

```math
c_1 c_2 \bmod n^2
```

decrypts to:

```math
m_1 + m_2 \pmod n
```

The wrapper keeps that property visible through
`PaillierPublicKey::add_ciphertexts(...)`, and `rerandomize(...)` preserves the
same plaintext while refreshing the random factor so identical messages do not
stay linkable across ciphertext refreshes.

### Schmidt-Samoa

Core arithmetic:

```math
c = m^n \bmod n,\qquad n = p^2 q,\qquad \gamma = pq
```

with the private exponent chosen so that:

```math
d \equiv n^{-1} \pmod{\mathrm{lcm}(p - 1, q - 1)}
```

and decryption:

```math
m = c^d \bmod \gamma
```

Like Cocks, Schmidt-Samoa uses the modulus itself as the public exponent. It
is mathematically neat and implemented faithfully here, but it does not have
the same standards ecosystem or deployment relevance as RSA.

## Byte-Oriented APIs

The public-key wrappers now distinguish clearly between:

- the arithmetic interfaces (`encrypt_raw`, `decrypt_raw`, typed ciphertexts)
- the usable byte-to-byte helpers

Examples:

- `CocksPublicKey::encrypt_bytes` / `CocksPrivateKey::decrypt_bytes`
- `ElGamalPublicKey::encrypt_bytes` / `ElGamalPrivateKey::decrypt_bytes`
- `PaillierPublicKey::encrypt_bytes` / `PaillierPrivateKey::decrypt_bytes`
- `RabinPublicKey::encrypt_bytes` / `RabinPrivateKey::decrypt_bytes`
- `SchmidtSamoaPublicKey::encrypt_bytes` / `SchmidtSamoaPrivateKey::decrypt_bytes`

For the schemes whose native ciphertext is a bigint or a pair of bigints, these
helpers serialize the ciphertext into the same crate-defined binary framing used
throughout the non-RSA key formats.

## Public-Key Performance

Public-key timing is measured by:

```text
cargo run --release --bin bench_public_key -- 1024
```

Representative current 1024-bit latencies on this host:

| Operation | Latency |
|-----------|--------:|
| RSA-1024 keygen | `22.1 ms` |
| RSA-1024 OAEP encrypt | `0.071 ms` |
| RSA-1024 OAEP decrypt | `1.08 ms` |
| RSA-1024 PSS sign | `1.00 ms` |
| RSA-1024 PSS verify | `0.048 ms` |
| ElGamal-1024 keygen | `101 ms` |
| ElGamal-1024 encrypt | `0.429 ms` |
| ElGamal-1024 decrypt | `0.729 ms` |
| Paillier-1024 keygen | `15.9 ms` |
| Paillier-1024 encrypt | `6.57 ms` |
| Paillier-1024 decrypt | `2.29 ms` |
| Paillier-1024 rerandomize | `4.21 ms` |
| Paillier-1024 ciphertext add | `0.082 ms` |
| Cocks-1024 keygen | `15.4 ms` |
| Cocks-1024 encrypt | `0.782 ms` |
| Cocks-1024 decrypt | `0.142 ms` |
| Rabin-1024 keygen | `19.0 ms` |
| Rabin-1024 encrypt | `0.039 ms` |
| Rabin-1024 decrypt | `1.44 ms` |
| Schmidt-Samoa-1024 keygen | `5.21 ms` |
| Schmidt-Samoa-1024 encrypt | `0.753 ms` |
| Schmidt-Samoa-1024 decrypt | `0.228 ms` |

The table above is measured in milliseconds per operation. The radar chart
below uses the reciprocal view — operations per second on a log scale — so the
faster operations sit farther from the center.

The existing chart is the public-key encrypt/decrypt radar:

![Public-key encrypt/decrypt radar chart](assets/public-key-encdec-radar.svg)

## Practical Guidance

- Use `RSA` when you need the standards-backed path today.
- Use the other implemented schemes when you explicitly want those primitives
  and understand their wrapper model.
- Use `CtrDrbgAes256` (or another strong `Csprng`) for all randomized public-key
  operations.
- Keep an eye on 2048-bit and larger timings; the in-tree bigint backend is now
  respectable, but it is still an implementation detail that may be replaced by
  `num-bigint` if larger practical workloads demand it.

## References

The primary public-key papers and standards are stored in `pubs/`. The
top-level [README.md](README.md) remains the canonical BibTeX index.
