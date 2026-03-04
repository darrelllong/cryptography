# ASYMMETRIC

## Arithmetic Foundation

The public-key layer is built on:

- `BigUint`
- `BigInt`
- `MontgomeryCtx`
- shared number-theory helpers in `src/public_key/primes.rs`

The in-tree bigint backend stores `u64` limbs in little-endian limb order and
uses Montgomery multiplication for repeated modular arithmetic under odd
moduli. That is the common case for every implemented public-key
scheme here.

The design goal is:

- keep the arithmetic visible and auditable
- keep the scheme logic close to the published arithmetic
- keep open the option of swapping the arithmetic backend later if larger-key
  performance demands it

The broader implementation policy matches the rest of the crate:

- pure idiomatic Rust
- no architecture intrinsics
- no C/FFI escape hatches
- minimal dependencies unless they clearly improve interoperability or
  maintainability

That is why the bigint and Montgomery code live in-tree, while XML parsing uses
`quick-xml` and RSA key persistence uses standard DER/PEM structures where that
buys real compatibility.

## Three-Level API

The public-key layer uses a common pattern, but it is not literally identical
across every scheme:

1. Arithmetic maps such as `encrypt_raw`, `encrypt_with_nonce`,
   `encrypt_point_with_k`, or `sign_with_k`, which keep the underlying math
   explicit.
2. Typed wrappers such as `encrypt`, `decrypt`, `sign_message`, and
   `verify_message`, which work with the scheme's natural ciphertext or
   signature type.
3. Byte wrappers such as `encrypt_bytes`, `decrypt_bytes`,
   `verify_message_bytes`, standard compact wire encodings, and crate-defined
   key blobs.

Not every scheme exposes all three layers, and that is intentional:

- key-agreement schemes return shared-secret material, not ciphertexts
- signature schemes expose signing and verification rather than encryption
- hybrid schemes such as `ECIES` are naturally byte-oriented at the top layer

The consistency target for new APIs is:

- use `*_with_nonce` for deterministic or caller-supplied randomness entry points
- use `to_wire_bytes` / `from_wire_bytes` for compact standard encodings that
  omit curve or algorithm parameters
- use `to_key_blob` / `from_key_blob` for the crate-defined self-describing
  binary formats
- keep legacy `to_binary` / `from_binary` names as compatibility aliases where
  they already exist

Level 1 remains the right place for arithmetic tests and direct cross-checks.
Level 2 is the normal typed interface. Level 3 is the byte-oriented convenience
layer for schemes that naturally have one.

## Public-Key Surface

### Integer and finite-field schemes

- `Rsa` — encryption and signatures
- `Dsa` — signatures (FIPS 186-5)
- `Cocks` — encryption (historical; 1973)
- `ElGamal` — encryption
- `Rabin` — encryption
- `Paillier` — additively homomorphic encryption
- `SchmidtSamoa` — encryption
- `Dh` — finite-field Diffie-Hellman key exchange

### Short-Weierstrass elliptic-curve schemes

- `Ecdh` — EC Diffie-Hellman key exchange (ANSI X9.63 / SEC 1)
- `Ecdsa` — EC Digital Signature Algorithm (FIPS 186-5)
- `EcElGamal` — EC-ElGamal encryption with additive homomorphism
- `Ecies` — Elliptic Curve Integrated Encryption Scheme (ephemeral ECDH + AES-256-GCM)

### Twisted Edwards schemes

- `EdwardsDh` — Edwards-curve Diffie-Hellman key agreement
- `EdDsa` — generic Edwards-curve Schnorr/EdDSA-style signatures
- `Ed25519` — RFC 8032 Edwards-curve signatures
- `EdwardsElGamal` — Edwards-curve ElGamal encryption

The Edwards arithmetic is generic over `TwistedEdwardsCurve`, but the only
built-in named Edwards domain currently shipped in-tree is `ed25519()`.

### Wrapper layers

- `RsaOaep<H>` for `RSAES-OAEP`
- `RsaPss<H>` for `RSASSA-PSS`

Every implemented scheme has:

- explicit key construction from mathematical parameters
- built-in key generation
- key serialization
- byte-oriented encrypt/decrypt helpers where encryption is defined
- byte-oriented sign/verify helpers where signatures are defined

`RSA` has the richest standards surface because RFC 8017 defines both
encryption and signature encodings. `DSA` and `ECDSA` are the standard
signature constructions; they do not need extra padding profiles. The other
schemes expose crate-defined message and serialization wrappers, which is the
honest thing to do because there is no equally universal RFC/NIST padding story
for those primitive forms.

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

`Dsa`, `Cocks`, `ElGamal`, `Rabin`, `Paillier`, `SchmidtSamoa`, `Dh`,
`Ecdsa`, `EcElGamal`, `Ecies`, `Ecdh`, `EdwardsDh`, `EdwardsElGamal`,
`EdDsa`, and `Ed25519` use crate-defined formats:

- binary: DER `SEQUENCE` of positive `INTEGER`s
- text:
  - scheme-specific PEM labels
  - a simple fixed-schema XML form

This deliberately copies the structural simplicity of the RSA key material
without pretending that those schemes have standard OIDs or a real PKCS/X.509
profile.

The short-Weierstrass EC public key types (`EcdhPublicKey`, `EcdsaPublicKey`,
`EciesPublicKey`, `EcElGamalPublicKey`) encode the curve domain parameters
`(p, a, b, n, h, Gx, Gy)` alongside the public point `(Qx, Qy)`, so
deserialization can reconstruct the `CurveParams` without a separate OID lookup
or parameter database. The Edwards key types do the same job for
`TwistedEdwardsCurve`, carrying the Edwards parameters together with the
compressed public point.

## Scheme Notes

### Integer and finite-field schemes

#### RSA

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

#### ElGamal

Core arithmetic:

```math
\gamma = g^k \bmod p,\qquad \delta = m \cdot y^k \bmod p,\qquad y = g^a \bmod p
```

The key-generation path uses a prime-order subgroup construction instead of the
older safe-prime search. A safe prime is a modulus of the form `p = 2q + 1`
with `q` prime; it gives simple subgroup structure, but searching for those
moduli is much slower than generating `p = kq + 1` directly. The
implementation keeps the subgroup structure explicit while avoiding that
pathological key-generation cost.

The public key stores the real ephemeral bound used for encryption, so the
random ephemeral exponent is sampled from the right range instead of from the
full `p - 1` interval. Generated keys use the actual subgroup order `q` for
that bound; explicitly constructed keys fall back to `p - 1` when the subgroup
order is not derivable from the supplied parameters.

#### DSA

Reference: FIPS 186-5, Digital Signature Standard (see
`pubs/fips186-5.pdf` and the matching BibTeX entry in
the top-level references).

Core arithmetic:

```math
r = (g^k \bmod p) \bmod q,\qquad
s = k^{-1}(z + xr) \bmod q
```

with verification:

```math
w = s^{-1} \bmod q,\qquad
u_1 = zw \bmod q,\qquad
u_2 = rw \bmod q
```

and acceptance when:

```math
\bigl(g^{u_1} y^{u_2} \bmod p\bigr) \bmod q = r
```

The implementation reuses the same prime-order subgroup generation shape as
`ElGamal`: generated keys store `(p, q, g)` explicitly, and signatures sample
their per-message nonce from `[1, q)`. The digest representative is reduced to
the leftmost `N = \mathrm{bits}(q)` bits before signing and verification,
matching the Digital Signature Standard's treatment of hash outputs that are
wider than the subgroup order.

For generated keys, the implementation uses

```math
N = \mathrm{clamp}(\lfloor L / 4 \rfloor, 16, 256)
```

for a modulus size `L = bits(p)`. That is not the exact FIPS menu of `(L, N)`
pairs (`(1024, 160)`, `(2048, 224)`, `(2048, 256)`, `(3072, 256)`), but it
keeps the subgroup order conservative for the representative benchmark sizes
used here while staying within the same finite-field `DSA` structure.

#### Cocks

Core arithmetic:

```math
c = m^n \bmod n,\qquad n = pq,\qquad \pi \equiv p^{-1} \pmod{q - 1}
```

with the private recovery map:

```math
m = c^\pi \bmod q
```

Cocks is historically important: Clifford Cocks proposed it
in 1973, five years before RSA. The scheme is unusual because the public
exponent is the modulus itself. The crate keeps that arithmetic intact and adds
the byte-level serialization layer on top instead of inventing a modernized
padding story that the literature does not standardize.

The private exponent is:

```math
\pi \equiv p^{-1} \pmod{q - 1}
```

and the key observation is the CRT reduction modulo `q`: when
`c = m^{pq} \bmod n`, raising `c` to `\pi` modulo `q` reduces the exponent
from `pq\pi` to `q`, so Fermat brings the result back to `m`.

#### Rabin

Core arithmetic:

```math
c = m^2 \bmod n,\qquad n = pq
```

Decryption computes square roots modulo `p` and `q`, then recombines them with
the Chinese remainder theorem to recover the four square roots modulo `n`.
Because plain Rabin is ambiguous, the implementation uses a tagged-message variant: the
tag is carried inside the encoded plaintext and is used to select the intended
root deterministically at decrypt time.

The implementation requires Blum primes:

```math
p \equiv q \equiv 3 \pmod 4
```

That condition makes square-root extraction cheap, because a square root of
`c` modulo `p` can be written directly as:

```math
c^{(p + 1)/4} \bmod p
```

and likewise modulo `q`, avoiding a heavier general-purpose square-root
algorithm during decryption.

Rabin is historically important because it is one of the earliest public-key
trapdoor constructions with a tight reduction story: in the plain setting,
inverting the squaring map modulo `n = pq` is essentially equivalent to
factoring `n`. The fixed disambiguation tag used here is what lets the code
identify the intended root among the four CRT roots and turn the raw squaring
trapdoor into a deterministic decryptor. That direct connection is part of why
the scheme still matters pedagogically even though modern deployments usually
prefer RSA.

#### Paillier

Core arithmetic:

```math
c = \zeta^m r^n \bmod n^2
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

#### Schmidt-Samoa

Reference: Katja Schmidt-Samoa (2005); see `pubs/schmidt-samoa.pdf` and the
matching BibTeX entry in the repository references.

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

The unusual choice `n = p^2 q` is the point of the construction: it gives the
scheme enough structure to choose `d = n^{-1} mod lcm(p-1, q-1)` and recover
the plaintext modulo `\gamma = pq`, rather than modulo the full public
modulus.

Like Cocks, Schmidt-Samoa uses the modulus itself as the public exponent. It
is mathematically neat and implemented faithfully here, but it does not have
the same standards ecosystem or deployment relevance as RSA.

#### Diffie-Hellman

Core arithmetic:

```math
y = g^x \bmod p
```

with shared secret:

```math
s = y_{\mathrm{peer}}^x \bmod p
```

`DH` uses a prime-order subgroup construction identical to `DSA` and `ElGamal`: a
Sophie-Germain-style group with explicit subgroup order `q`. The public key stores
`(p, q, g, y)` so the receiver can validate that the peer's contribution actually
lies in the correct subgroup before computing the shared secret. The validation
check is:

```math
1 < y < p \qquad \text{and} \qquad y^q \equiv 1 \pmod{p}
```

`DhPrivateKey::agree` returns `None` when the peer key belongs to a different group
or fails the subgroup check. The raw shared secret is returned as a `BigUint`; callers
are expected to apply their own KDF before using it as keying material.

### Short-Weierstrass elliptic-curve schemes

#### ECDH

Reference: SEC 1 v2.0, SEC 2 v2.0, and NIST SP 800-56A Rev. 3 (see
`pubs/sec1-v2-elliptic-curve-cryptography.pdf`,
`pubs/sec2-v2-recommended-elliptic-curve-domain-parameters.pdf`, and
`pubs/sp800-56a-r3.pdf`).

Shared secret:

```math
S = d \cdot Q_{\mathrm{peer}}, \qquad \text{secret} = S_x
```

`ECDH` follows SEC 1 v2.0: the shared secret is the x-coordinate of the point product,
zero-padded to the curve's coordinate length. `EcdhPrivateKey::agree` returns `None`
when the product is the point at infinity.

`EcdhPublicKey` and `EcdhPrivateKey` carry the full `CurveParams` so both sides can
use any of the named curves (`p256`, `p384`, `p521`, `secp256k1`, etc.) without a
separate curve-identifier negotiation layer.

#### ECIES

Reference: SEC 1 v2.0 and NIST SP 800-56A Rev. 3 for the EC key-establishment
model and point encodings (see `pubs/sec1-v2-elliptic-curve-cryptography.pdf`
and `pubs/sp800-56a-r3.pdf`).

`ECIES` is the standard way to encrypt arbitrary byte strings to a static EC public key.
It combines ephemeral ECDH with a symmetric encryption step, so the per-message overhead
is a single scalar multiplication by the sender and a single scalar multiplication by the
receiver.

**Encryption:**

1. Generate an ephemeral key pair `(k, R)` where `R = k · G`.
2. Compute the shared point `S = k · Q`.
3. Derive symmetric key and nonce from `S_x`:

```math
\text{key}   = \mathrm{SHA\text{-}256}(\mathtt{0x01} \mathbin\| S_x)
\qquad
\text{nonce} = \mathrm{SHA\text{-}256}(\mathtt{0x02} \mathbin\| S_x)_{[0..12]}
```

4. Encrypt the message with AES-256-GCM, using `R_{\text{bytes}}` as the additional
   authenticated data (AAD). The AAD binding prevents `R` from being silently swapped
   without triggering a tag failure.

**Wire format:**

```text
R_bytes  (1 + 2·coord_len bytes, SEC 1 uncompressed)
ciphertext  (same length as plaintext)
tag  (16 bytes, GCM authentication tag)
```

**Decryption:**

1. Parse `R_bytes` from the front of the ciphertext.
2. Compute `S = d · R`.
3. Re-derive key and nonce from `S_x`.
4. AES-256-GCM decrypt; return `None` if the tag fails.

The GCM tag simultaneously authenticates the ciphertext and the ephemeral public key,
so no separate MAC layer is needed.

#### EC-ElGamal

Reference: the ElGamal paper for the discrete-logarithm construction and SEC 1
v2.0 / SEC 2 v2.0 for the elliptic-curve group and point encodings (see
`pubs/elgamal-1985.pdf`,
`pubs/sec1-v2-elliptic-curve-cryptography.pdf`, and
`pubs/sec2-v2-recommended-elliptic-curve-domain-parameters.pdf`).

EC-ElGamal has three distinct plaintext layers stacked on the same key pair:

**Point layer** — encrypt an arbitrary curve point `M`:

```math
(C_1, C_2) = (k \cdot G,\; M + k \cdot Q)
```

Decryption recovers `M` via:

```math
M = C_2 - d \cdot C_1
```

**Byte layer** — encrypt arbitrary bytes via Koblitz embedding: the message bytes are
padded and placed into an x-coordinate candidate; `decode_point` is called with the
`0x02` compressed prefix until a valid curve point is found. The last byte of the
padded x-coordinate is an iteration counter `j ∈ [0, 255]`; the first byte of the
decoded x-coordinate is stripped during recovery, leaving the original message bytes.
This approach works on every named curve in this crate because all have `p ≡ 3 (mod 4)`,
which means the compressed-point square root exists and the iteration succeeds quickly
in practice.

The message capacity per ciphertext is `coord_len − 1` bytes.

**Integer layer** — additively homomorphic encryption of a small integer `m`:

```math
\text{encrypt\_int}(m) = \text{encrypt\_point}(m \cdot G)
```

Homomorphic addition of two ciphertexts:

```math
(C_1 + C_1',\; C_2 + C_2') \;\xrightarrow{\text{decrypt}}\; (m_1 + m_2) \cdot G
```

The integer `m` is recovered from `m · G` via baby-step giant-step (BSGS) with
`O(\sqrt{\text{max\_m}})` precomputation.

#### ECDSA

Reference: FIPS 186-5 and the local elliptic-curve standards in SEC 1 / SEC 2
(see `pubs/fips186-5.pdf`,
`pubs/sec1-v2-elliptic-curve-cryptography.pdf`, and
`pubs/sec2-v2-recommended-elliptic-curve-domain-parameters.pdf`).

Core arithmetic (FIPS 186-5):

```math
r = (k \cdot G)_x \bmod n,\qquad
s = k^{-1}(z + rd) \bmod n
```

with verification:

```math
w = s^{-1} \bmod n,\qquad
u_1 = zw \bmod n,\qquad
u_2 = rw \bmod n
```

and acceptance when:

```math
(u_1 \cdot G + u_2 \cdot Q)_x \bmod n = r
```

The per-message nonce `k` is generated from the crate's `Csprng`. The digest
representative `z` is the leftmost `bits(n)` bits of the hash output, matching
the FIPS 186-5 truncation rule for hash functions wider than the group order.

The key types (`EcdsaPublicKey`, `EcdsaPrivateKey`) carry the full `CurveParams`
and work with any named curve.

### Twisted Edwards schemes

#### Edwards DH

Reference: NIST SP 800-56A Rev. 3 for the DH model, with the Edwards-group
arithmetic and compressed-point conventions used in this crate anchored by the
same local curve references (`pubs/sec1-v2-elliptic-curve-cryptography.pdf`,
`pubs/sec2-v2-recommended-elliptic-curve-domain-parameters.pdf`,
`pubs/fips186-5.pdf`).

`EdwardsDh` provides the same core operation on a twisted Edwards curve:

```math
S = d \cdot Q_{\mathrm{peer}}
```

The difference is the wire representation. `EdwardsDhPrivateKey::agree`
returns the compressed Edwards encoding of the shared point, so the output is a
canonical 32-byte value on the built-in Ed25519 curve instead of a bare
x-coordinate. That matches the way the Edwards side of the crate already treats
points as compressed byte strings.

The implementation is generic over `TwistedEdwardsCurve`, but the in-tree named
fixture and benchmark path today is the built-in `ed25519()` domain.

#### Edwards ElGamal

Reference: the ElGamal paper for the encryption law, with the Edwards-curve
group and encoding choices in this crate tied to the same local curve
references used for `Ed25519` and `EdwardsDh` (see `pubs/elgamal-1985.pdf`,
`pubs/sec2-v2-recommended-elliptic-curve-domain-parameters.pdf`, and
`pubs/fips186-5.pdf`).

`EdwardsElGamal` mirrors the same ElGamal construction on a twisted Edwards
group:

```math
(C_1, C_2) = (k \cdot B,\; M + k \cdot Q)
```

with decryption:

```math
M = C_2 - d \cdot C_1
```

As with the short-Weierstrass variant, the module exposes:

- point encryption
- integer encryption via `m \cdot B`
- homomorphic ciphertext addition

The main distinction is representation: the Edwards wrapper uses compressed
Edwards point encodings throughout, which makes ciphertext serialization more
compact and keeps it aligned with the `Ed25519` / `EdDsa` side of the crate.

As with `EdwardsDh`, the machinery accepts any caller-supplied
`TwistedEdwardsCurve`, but the in-tree deterministic fixtures and benchmarks
currently target the built-in `ed25519()` domain.

#### Ed25519

Reference: FIPS 186-5 for EdDSA and the local elliptic-curve references for
the underlying group and parameter conventions (see `pubs/fips186-5.pdf`,
`pubs/sec2-v2-recommended-elliptic-curve-domain-parameters.pdf`).

`Ed25519` is the fixed-curve RFC 8032 signature construction built on the
Edwards arithmetic in this crate. Unlike the generic `EdDsa` layer, it follows
the standard seed-hash-and-clamp flow exactly:

```math
h = \mathrm{SHA\text{-}512}(\text{seed})
```

Clamp the lower 32 bytes of `h` to derive the secret scalar `a`, and use the
upper 32 bytes as the deterministic nonce prefix. Signing then computes:

```math
r = H(\text{prefix} \parallel M) \bmod n
```

```math
R = r \cdot B,\qquad
k = H(\mathrm{enc}(R) \parallel \mathrm{enc}(A) \parallel M) \bmod n
```

```math
S = r + ka \bmod n
```

The standard 64-byte signature is:

```math
\sigma = \mathrm{enc}(R) \parallel \mathrm{enc}_{\mathrm{LE}}(S)
```

Verification checks:

```math
S \cdot B = R + kA
```

The API exposes the real RFC shapes directly:

- private key: 32-byte seed
- public key: 32-byte compressed point
- signature: 64-byte `R || S`

So this is the standards-conformant Edwards path, while `EdDsa` remains the
more explicit curve-generic signature layer for callers who want direct scalar
control.

The test coverage for this module now includes the full RFC 8032 section 7.1
Ed25519 vector set, along with strict parsing and rejection checks for malformed
public keys and signatures.

## Byte-Oriented APIs

The public-key wrappers now distinguish clearly between:

- the arithmetic interfaces (`encrypt_raw`, `decrypt_raw`, typed ciphertexts)
- the usable byte-to-byte helpers

Examples:

- `CocksPublicKey::encrypt_bytes` / `CocksPrivateKey::decrypt_bytes`
- `DsaPrivateKey::sign_message_bytes::<H>` / `DsaPublicKey::verify_message_bytes::<H>`
- `EcElGamalPublicKey::encrypt` / `EcElGamalPrivateKey::decrypt` (Koblitz byte layer)
- `EciesPublicKey::encrypt` / `EciesPrivateKey::decrypt` (arbitrary-length bytes)
- `EcdsaPrivateKey::sign_message::<H>` / `EcdsaPublicKey::verify_message::<H>`
- `ElGamalPublicKey::encrypt_bytes` / `ElGamalPrivateKey::decrypt_bytes`
- `PaillierPublicKey::encrypt_bytes` / `PaillierPrivateKey::decrypt_bytes`
- `RabinPublicKey::encrypt_bytes` / `RabinPrivateKey::decrypt_bytes`
- `SchmidtSamoaPublicKey::encrypt_bytes` / `SchmidtSamoaPrivateKey::decrypt_bytes`

For the schemes whose native ciphertext is a bigint or a pair of bigints, these
helpers serialize the ciphertext into the same crate-defined binary framing used
throughout the non-RSA key formats.

## Public-Key Performance

Public-key timing is measured with [pilot-bench](https://github.com/ascar-io/pilot-bench)
driving `pilot_pk` through:

```text
bash bench_all_pk_full.sh
```

The legacy `bench_public_key` binary remains useful as a fixed-iteration
fallback, but the publication-facing numbers below come from Pilot and report
milliseconds per operation, 95% confidence-interval half-width, and rounds
required to hit the stop rule.

### Integer and finite-field schemes

#### RSA (1024-bit)

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      16.02 |   ±0.4013 |    43 |
| rsa_encrypt_1024                 |    0.03228 | ±0.0002007 |    76 |
| rsa_decrypt_1024                 |      0.681 |  ±0.02365 |    56 |
| rsa_sign_1024                    |     0.6933 |  ±0.02252 |    90 |
| rsa_verify_1024                  |     0.0324 | ±0.0005347 |    60 |

#### Prime-order subgroup over `Z_p^*` (1024-bit)

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| elgamal_keygen_1024              |      48.63 |   ±0.4083 |    30 |
| elgamal_encrypt_1024             |     0.4124 | ±0.003134 |    60 |
| elgamal_decrypt_1024             |     0.2212 | ±0.005175 |    33 |
| dsa_keygen_1024                  |      54.07 |    ±1.199 |    30 |
| dsa_sign_1024                    |       0.32 |  ±0.00196 |    53 |
| dsa_verify_1024                  |     0.5129 | ±0.004096 |    99 |

#### Composite-modulus schemes (1024-bit)

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| paillier_keygen_1024             |      16.78 |  ±0.07887 |    96 |
| paillier_encrypt_1024            |      6.383 |  ±0.03973 |    30 |
| paillier_decrypt_1024            |      2.327 |   ±0.0179 |    34 |
| paillier_rerandomize_1024        |      4.113 |  ±0.05597 |    47 |
| paillier_add_1024                |    0.07652 | ±0.0005136 |    90 |
| cocks_keygen_1024                |      13.63 |   ±0.3646 |    30 |
| cocks_encrypt_1024               |     0.7711 | ±0.005889 |    60 |
| cocks_decrypt_1024               |     0.1401 | ±0.008111 |    30 |
| rabin_keygen_1024                |      20.79 |   ±0.0954 |    39 |
| rabin_encrypt_1024               |    0.02683 | ±0.0002364 |    60 |
| rabin_decrypt_1024               |      1.089 |  ±0.01946 |    48 |
| schmidt_samoa_keygen_1024        |      6.333 |   ±0.1508 |    30 |
| schmidt_samoa_encrypt_1024       |     0.7847 | ±0.009299 |    30 |
| schmidt_samoa_decrypt_1024       |     0.2311 |  ±0.01224 |    30 |

#### RSA (2048-bit)

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      160.8 |    ±6.852 |    30 |
| rsa_encrypt_2048                 |      0.104 | ±0.003918 |    30 |
| rsa_decrypt_2048                 |       4.97 |   ±0.1465 |   107 |
| rsa_sign_2048                    |      5.139 |   ±0.3859 |    30 |
| rsa_verify_2048                  |     0.1031 |   ±0.0016 |    60 |

### Short-Weierstrass elliptic-curve schemes

#### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |       2.04 |  ±0.07303 |    66 |
| ecdsa_sign                       |      2.091 | ±0.009643 |    54 |
| ecdsa_verify                     |      3.937 |  ±0.03526 |    30 |
| ecdh_keygen                      |      2.018 |  ±0.05056 |    85 |
| ecdh_agree                       |      2.064 |   ±0.1501 |    30 |
| ecdh_serialize                   |  7.507e-05 | ±9.361e-06 |    56 |

#### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      2.034 |  ±0.06731 |    84 |
| ecies_encrypt                    |      3.903 |  ±0.02181 |    93 |
| ecies_decrypt                    |      1.962 |  ±0.01575 |    79 |
| ec_elgamal_keygen                |      2.033 |  ±0.08416 |    60 |
| ec_elgamal_encrypt               |      4.061 |  ±0.02283 |    94 |
| ec_elgamal_decrypt               |      1.984 |  ±0.01803 |    30 |

### Twisted Edwards schemes

#### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    |    ±CI     | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      2.006 |  ±0.02327 |    30 |
| ed25519_sign                     |      1.017 |  ±0.01166 |    33 |
| ed25519_verify                   |      3.333 |  ±0.02346 |    30 |
| edwards_dh_keygen                |      1.984 |   ±0.0103 |    57 |
| edwards_dh_agree                 |      0.994 |  ±0.01259 |    30 |
| edwards_dh_serialize             |   5.75e-05 | ±7.701e-06 |    30 |
| edwards_elgamal_keygen           |      1.983 |  ±0.01137 |   174 |
| edwards_elgamal_encrypt          |      2.084 |  ±0.01445 |    37 |
| edwards_elgamal_decrypt          |      1.608 |  ±0.01821 |    30 |

The tables above are measured in milliseconds per operation. The radar charts
below use the reciprocal view, plotting operations per second on a log scale so
the faster operations sit farther from the center.

The integer-arithmetic chart plots 1024-bit encrypt/decrypt throughput for the
mixed integer-based public-key schemes. Signature-only and rerandomization/addition
rows stay in the tables because they do not have matching encrypt/decrypt axes:

![Public-key encrypt/decrypt radar chart](assets/public-key-encdec-radar.svg)

The elliptic-curve code benefits from lower-constant-factor group operations, so
the EC families are easier to compare in separate charts. The key-agreement
chart keeps serialization in the plot, which pushes that chart onto a much
wider radial scale than the signature and encryption charts.

### EC Signature Throughput

These charts also use operations per second on a log scale.

![EC signature radar chart](assets/ec-signature-radar.svg)

### EC Key Agreement Throughput

![EC key-agreement radar chart](assets/ec-key-agreement-radar.svg)

### EC Encryption Throughput

![EC encryption radar chart](assets/ec-encryption-radar.svg)

## Practical Guidance

- Use `RSA` when you need standards-backed encryption or signatures.
- Use `DSA`, `ECDSA`, or `Ed25519` when you need a standards-backed digital signature.
- Use `ECIES` when you need public-key encryption over an elliptic curve.
- Use `ECDH` or `DH` when you need key agreement without a full encryption layer.
- Use the other implemented schemes when you explicitly want those primitives
  and understand their wrapper model.
- Use `CtrDrbgAes256` (or another strong `Csprng`) for all randomized public-key
  operations.
- Keep an eye on 2048-bit and larger timings; the in-tree bigint backend is now
  respectable, but it is still an implementation detail that may be replaced by
  `num-bigint` if larger practical workloads demand it.

## References

The primary public-key papers and standards are stored in `pubs/`. The BibTeX
index is in [README.md](README.md).
