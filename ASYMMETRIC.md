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
\gamma = g^k \bmod p,\qquad \delta = m \cdot y^k \bmod p
```

The key-generation path uses a prime-order subgroup construction instead of the
older safe-prime search. That keeps the subgroup structure explicit while
avoiding the pathological key-generation cost that came from insisting on
`p = 2q + 1`.

The public key stores the real ephemeral bound used for encryption, so the
random ephemeral exponent is sampled from the right range instead of from the
full `p - 1` interval.

### Rabin

`Rabin` is implemented as a tagged-message variant, not as a bare “square and
hope you pick the right root” demonstration. The tagging step is what makes the
byte-oriented decrypt path deterministic.

### Paillier

`Paillier` exposes both encryption/decryption and the natural homomorphic
operations:

- ciphertext rerandomization
- ciphertext multiplication modulo `n^2`, corresponding to plaintext addition

That homomorphic surface is a real part of the scheme, not an extra trick, so
it is intentionally part of the usable API.

### Cocks and Schmidt-Samoa

These two are the least conventional public-key primitives in the crate. They
remain implemented and usable, but they do not have the same ecosystem support,
standardized wrapper story, or deployment relevance as RSA. Their wrappers are
there so the algorithms are usable and testable, not to imply modern protocol
adoption.

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

The existing chart is the public-key encrypt/decrypt radar:

![Public-key encrypt/decrypt radar chart](/Users/darrell/cryptography/assets/public-key-encdec-radar.svg)

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

