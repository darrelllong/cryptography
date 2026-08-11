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

Implementation references for multiplication-kernel upgrades are tracked in
`pubs/comba-1990-exponentiation-cryptosystems-on-the-ibm-pc.pdf` and
`pubs/karatsuba-ofman-1963-multiplication-of-multidigit-numbers-on-automata.pdf`.

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

That is why the bigint and Montgomery code carry no external arithmetic
backend: they live in the sibling [rump](https://github.com/darrelllong/rump)
crate — extracted from this tree, same author, same pure-Rust and
scrub-on-drop policies — while RSA key persistence uses standard DER/PEM
structures where that buys real compatibility.

## Three-Level API

The public-key layer uses a common pattern, but it is not literally identical
across every scheme:

1. Arithmetic maps such as `encrypt_raw`, `encrypt_with_nonce`,
   `encrypt_point_with_nonce`, or `sign_digest_with_nonce`, which keep the underlying math
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

Level 1 remains the right place for arithmetic tests and direct cross-checks.
Level 2 is the normal typed interface. Level 3 is the byte-oriented convenience
layer for schemes that naturally have one.

## Naming Conventions

Naming follows explicit intent throughout:

- Serialization distinguishes compact from self-describing formats:
  `to_key_blob` / `from_key_blob` for the crate-defined binary blob,
  `to_wire_bytes` / `from_wire_bytes` for compact standard encodings.
- Deterministic or caller-supplied randomness entry points use
  `sign_digest_with_nonce` rather than generic `sign_with_k`.
- Verification of precomputed digests uses `verify_digest_scalar`.
- DH agreement methods name the returned form explicitly:
  - finite-field DH: `agree_element`
  - short-Weierstrass ECDH: `agree_x_coordinate`
  - Edwards DH: `agree_compressed_point`

Public-key exports are grouped under `cryptography::vt` to make variable-time
behavior explicit at import sites.

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

### Post-quantum lattice schemes

- `MlKem` (`ML-KEM-512/768/1024`) — key encapsulation mechanism
- `MlDsa` (`ML-DSA-44/65/87`) — digital signatures
- Details, usage notes, and PQ-specific benchmarks are documented in
  [POSTQUANTUM.md](POSTQUANTUM.md).

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

### Montgomery-curve ECDH (RFC 7748)

- `X25519` — Curve25519 ECDH, constant-time Montgomery ladder
- `X448` — Curve448 ECDH, constant-time Montgomery ladder

These two are the only public-key primitives in the crate that aim for
constant-time execution; see the [Curve25519 / Curve448 ECDH section
below](#curve25519--curve448-ecdh-rfc-7748) for details.

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

Most non-RSA key types use the crate-defined integer-sequence framing for
`to_key_blob()` / `from_key_blob()`. `Ed25519` is the main exception: its
canonical fixed-width forms are exposed as `to_raw_bytes()` /
`from_raw_bytes()` (32-byte compressed public key or 32-byte seed), matching
RFC 8032.

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

Reference: PKCS #1 v2.2 (RFC 8017) for OAEP, PSS, and the conventional key
formats used by the interoperable RSA layer in this crate.

Core arithmetic:

```math
c = m^e \bmod n,\qquad m = c^d \bmod n
```

with:

```math
n = pq,\qquad d \equiv e^{-1} \pmod{\lambda(n)}
```

The default key-generation path deliberately chooses the standard sparse public
exponent:

```math
e = 65{,}537
```

That keeps the public operation cheap while preserving the conventional RSA
shape. The matching private exponent `d` is the full modular inverse modulo
`\lambda(n)`, so the raw private operation is much heavier than the raw public
operation.

The practical RSA layer is the most complete in the crate:

- standards-based OAEP encryption
- standards-based PSS signatures
- standard key serialization
- generated or imported keys

So RSA is the "real protocol" path in the integer family: the raw arithmetic is
still present, but the intended surface is padded OAEP/PSS rather than textbook
RSA on caller-supplied integers.

The serialization story is also distinct from the other public-key families.
RSA uses PKCS#1, PKCS#8, and SPKI-compatible encodings, so it interoperates
with external tooling instead of relying on the crate-defined integer-sequence
format used elsewhere.

One practical caveat matters for the benchmark tables: private operations use
CRT recombination ($d_P$, $d_Q$, $q_{\text{Inv}}$), which substantially reduces
`decrypt`/`sign` latency, but the public side remains much faster because
it uses the standard sparse $e = 65{,}537$.

#### ElGamal

Reference: Taher ElGamal, "A Public Key Cryptosystem and a Signature Scheme
Based on Discrete Logarithms" (1985); see `pubs/elgamal-1985.pdf`.

Core arithmetic:

```math
\gamma = g^k \bmod p,\qquad \delta = m \cdot y^k \bmod p,\qquad y = g^a \bmod p
```

The key-generation path uses a prime-order subgroup construction instead of the
older safe-prime search. A safe prime is a modulus of the form $p = 2q + 1$
with `q` prime; it gives simple subgroup structure, but searching for those
moduli is much slower than generating $p = kq + 1$ directly. The
implementation keeps the subgroup structure explicit while avoiding that
pathological key-generation cost.

The public key stores the real ephemeral bound used for encryption, so the
random ephemeral exponent is sampled from the right range instead of from the
full `p - 1` interval. Generated keys use the actual subgroup order `q` for
that bound; explicitly constructed keys fall back to `p - 1` when the subgroup
order is not derivable from the supplied parameters.

The API follows the same layered pattern as the EC and Edwards ElGamal wrappers:

- an explicit-nonce entry point for deterministic fixtures
- a randomized ciphertext layer over the raw group element
- byte helpers that frame the bigint ciphertext pair into the crate-defined
  binary format

So the finite-field ElGamal path is still useful for reproducible KATs and
in-repo byte-oriented tests even though its wire format is crate-specific.

This is still multiplicative ElGamal, not one of the additive homomorphic
variants. The native plaintext group law is multiplication modulo `p`; the byte
helpers are only a serialization layer over that arithmetic.

#### DSA

Reference: FIPS 186-5, Digital Signature Standard (see
`pubs/fips186-5.pdf` and the matching BibTeX entry in the top-level
references).

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
the leftmost $N = \mathrm{bits}(q)$ bits before signing and verification,
matching the Digital Signature Standard's treatment of hash outputs that are
wider than the subgroup order.

For generated keys, the implementation uses:

```math
N = \mathrm{clamp}(\lfloor L / 4 \rfloor, 16, 256)
```

for a modulus size $L = \mathrm{bits}(p)$. That is not the exact FIPS menu of $(L, N)$
pairs (`(1024, 160)`, `(2048, 224)`, `(2048, 256)`, `(3072, 256)`), but it
keeps the subgroup order conservative for the representative benchmark sizes
used here while staying within the same finite-field `DSA` structure.

The public API is intentionally parallel to `ECDSA`:

- digest-level signing and verification for callers who already own the hash
- message-level helpers parameterized by a `Digest`
- an explicit-nonce signing entry point for deterministic tests and fixtures

The important distinction from `EdDsa` and `Ed25519` is that `DSA` signs a
digest representative `z`; it does not hash internally unless the caller uses
the message-level wrapper.

Like `ElGamal` and `Dh`, generated `DSA` keys carry the full subgroup domain
parameters `(p, q, g)` in the key object and in the crate-defined key blob.
That keeps key import self-contained instead of depending on an external
parameter registry.

#### Cocks

Reference: the historical Clifford Cocks construction; the implementation here
keeps the original arithmetic rather than wrapping it in a modern standards
profile.

Core arithmetic:

```math
c = m^n \bmod n,\qquad n = pq,\qquad \pi \equiv p^{-1} \pmod{q - 1}
```

with the private recovery map:

```math
m = c^\pi \bmod q
```

Cocks is historically important: Clifford Cocks proposed it in 1973, five
years before RSA. The scheme is unusual because the public exponent is the
modulus itself. The crate keeps that arithmetic intact and adds the byte-level
serialization layer on top instead of inventing a modernized padding story
that the literature does not standardize.

The private exponent is:

```math
\pi \equiv p^{-1} \pmod{q - 1}
```

and the key observation is the CRT reduction modulo $q$: when
$c = m^{pq} \bmod n$, raising $c$ to $\pi$ modulo $q$ reduces the exponent
from $pq\pi$ to $q$, so Fermat brings the result back to $m$.

From an API perspective, `Cocks` stays intentionally narrow:

- raw arithmetic on the integer plaintext representative
- byte helpers for the crate-defined framed encoding
- no attempt at standards-style padding or interoperable key containers

That restraint is deliberate. This is an educational historical primitive in
the repo, not a recommendation for modern deployment.

#### Rabin

Reference: the classic Rabin trapdoor permutation; the implementation keeps the
core squaring trapdoor visible and adds only the minimal disambiguation layer
needed for practical decryption.

Core arithmetic:

```math
c = m^2 \bmod n,\qquad n = pq
```

Decryption computes square roots modulo `p` and `q`, then recombines them with
the Chinese remainder theorem to recover the four square roots modulo `n`.
Because plain Rabin is ambiguous, the implementation uses a tagged-message
variant: the tag is carried inside the encoded plaintext and is used to select
the intended root deterministically at decrypt time.

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
inverting the squaring map modulo $n = pq$ is essentially equivalent to
factoring $n$. The fixed disambiguation tag used here is what lets the code
identify the intended root among the four CRT roots and turn the raw squaring
trapdoor into a deterministic decryptor.

The API follows that same philosophy:

- raw encryption over the integer representative
- byte wrappers that carry the tagged plaintext encoding
- key generation that enforces the Blum-prime precondition directly

So the practical wrapper is small, but it is enough to make the square-root
ambiguity explicit and auditable rather than leaving that selection logic to
callers.

#### Paillier

Reference: Pascal Paillier, "Public-Key Cryptosystems Based on Composite
Degree Residuosity Classes" (1999); see `pubs/paillier-1999.pdf`.

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
- ciphertext multiplication modulo $n^2$, corresponding to plaintext addition

That homomorphic surface is a real part of the scheme, not an extra trick, so
it is intentionally part of the usable API.

If `c_1` encrypts `m_1` and `c_2` encrypts `m_2`, then:

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

That is the intended way to read the API surface:

- the raw ciphertext type is still just the integer modulo $n^2$
- the byte helpers serialize that integer into a crate-defined framing
- the homomorphic operations are first-class because they are part of the
  reason to choose the scheme at all

Among the integer schemes, this is the clearest "use it for its special
algebra" path rather than for generic public-key encryption.

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

The unusual choice $n = p^2 q$ is the point of the construction: it gives the
scheme enough structure to choose
$d \equiv n^{-1} \pmod{\mathrm{lcm}(p-1, q-1)}$ and recover the plaintext
modulo $\gamma = pq$, rather than modulo the full public
modulus.

Like Cocks, Schmidt-Samoa uses the modulus itself as the public exponent. It
is mathematically neat and implemented faithfully here, but it does not have
the same standards ecosystem or deployment relevance as RSA.

The wrapper therefore stays minimal:

- raw arithmetic for the underlying construction
- byte helpers for crate-local usability
- no attempt to present it as a standards-grade interoperable scheme

This keeps the scheme available for study and comparison without pretending it
belongs in the same operational category as the RSA layer.

#### Diffie-Hellman

Reference: the classic finite-field Diffie-Hellman model, with subgroup
validation handled in the same prime-order subgroup framework used for `DSA`
and `ElGamal`.

Core arithmetic:

```math
y = g^x \bmod p
```

with shared secret:

```math
s = y_{\mathrm{peer}}^x \bmod p
```

`DH` uses a prime-order subgroup construction identical to `DSA` and
`ElGamal`: a Sophie-Germain-style group with explicit subgroup order `q`. The
public key stores `(p, q, g, y)` so the receiver can validate that the peer's
contribution actually lies in the correct subgroup before computing the shared
secret. The validation check is:

```math
1 < y < p \qquad \text{and} \qquad y^q \equiv 1 \pmod{p}
```

`DhPrivateKey::agree` returns `None` when the peer key belongs to a different
group or fails the subgroup check. The raw shared secret is returned as a
`BigUint`; callers are expected to apply their own KDF before using it as
keying material.

That return shape is intentionally lower-level than the EC variants. `DH`
returns the shared group element itself, not a byte-oriented KDF input chosen
by the library. The crate leaves that derivation step to the caller rather than
quietly committing to a KDF policy here.

Like `DSA`, the key blobs carry `(p, q, g)` explicitly. That makes `DhParams`
and the generated keys self-contained and avoids any hidden dependency on an
external parameter database.

### Short-Weierstrass elliptic-curve schemes

#### ECDH

Reference: SEC 1 v2.0, SEC 2 v2.0, and NIST SP 800-56A Rev. 3 (these are
external standards; no local PDFs are checked into `pubs/`).

Shared secret:

```math
S = d \cdot Q_{\mathrm{peer}}, \qquad \text{secret} = S_x
```

`ECDH` follows SEC 1 v2.0: the shared secret is the x-coordinate of the point
product, zero-padded to the curve's coordinate length.
`EcdhPrivateKey::agree` returns `None` when the product is the point at
infinity.

`EcdhPublicKey` and `EcdhPrivateKey` carry the full `CurveParams` so both sides
can use any of the named curves (`p256`, `p384`, `p521`, `secp256k1`, etc.)
without a separate curve-identifier negotiation layer.

On the representation side, the short-Weierstrass public key types now expose
both of the forms the Edwards writeup already calls out:

- compact SEC 1 point encodings via `to_wire_bytes` / `from_wire_bytes`
- the crate-defined self-describing key blob that carries the full curve
  parameters

That split is deliberate. The compact form is what a peer would normally place
on the wire when the curve is already known; the self-describing blob is what
the repo uses when it wants a standalone serialized key without an external OID
or curve registry.

As with `DH`, `EcdhPrivateKey::agree` returns raw shared-secret material, not a
KDF output. The returned bytes are the padded x-coordinate and should be fed
through a KDF before use as a symmetric key.

#### ECIES

Reference: SEC 1 v2.0 and NIST SP 800-56A Rev. 3 for the EC key-establishment
model and point encodings (external standards; no local PDFs are checked into
`pubs/`).

`ECIES` is the standard way to encrypt arbitrary byte strings to a static EC
public key. It combines ephemeral ECDH with a symmetric encryption step, so the
per-message overhead is a single scalar multiplication by the sender and a
single scalar multiplication by the receiver.

**Encryption:**

1. Generate an ephemeral key pair $(k, R)$ where $R = k \cdot G$.
2. Compute the shared point $S = k \cdot Q$.
3. Derive symmetric key and nonce from $S_x$:

```math
\text{key}   = \mathrm{SHA\text{-}256}(\mathtt{0x01} \mathbin\| S_x)
\qquad
\text{nonce} = \mathrm{SHA\text{-}256}(\mathtt{0x02} \mathbin\| S_x)_{[0..12]}
```

4. Encrypt the message with AES-256-GCM, using $R_{\text{bytes}}$ as the
   additional authenticated data (AAD). The AAD binding prevents `R` from being
   silently swapped without triggering a tag failure.

**Wire format:**

```text
R_bytes  (1 + 2·coord_len bytes, SEC 1 uncompressed)
ciphertext  (same length as plaintext)
tag  (16 bytes, GCM authentication tag)
```

**Decryption:**

1. Parse `R_bytes` from the front of the ciphertext.
2. Compute $S = d \cdot R$.
3. Re-derive key and nonce from $S_x$.
4. AES-256-GCM decrypt; return `None` if the tag fails.

The GCM tag simultaneously authenticates the ciphertext and the ephemeral
public key, so no separate MAC layer is needed.

This makes `ECIES` the practical "encrypt arbitrary bytes to an EC key" path
in the short-Weierstrass family. Unlike `EC-ElGamal`, it does not try to expose
the group law of the plaintext space; it uses the EC operation only for key
establishment, then hands the real data path to AES-256-GCM.

The key objects follow the same representation pattern as `ECDH` and `ECDSA`:
they can be serialized either as compact SEC 1 points when the curve is known
out-of-band or as the crate-defined self-describing blob when the curve
parameters need to travel with the key.

#### EC-ElGamal

Reference: the ElGamal paper for the discrete-logarithm construction
(`pubs/elgamal-1985.pdf`); SEC 1 v2.0 and SEC 2 v2.0 for the elliptic-curve
group and point encodings (external standards; no local PDFs are checked into
`pubs/`).

EC-ElGamal has three distinct plaintext layers stacked on the same key pair.

**Point layer** — encrypt an arbitrary curve point `M`:

```math
(C_1, C_2) = (k \cdot G,\; M + k \cdot Q)
```

Decryption recovers `M` via:

```math
M = C_2 - d \cdot C_1
```

**Byte layer** — encrypt arbitrary bytes via Koblitz embedding: the message
bytes are padded and placed into an x-coordinate candidate; `decode_point` is
called with the `0x02` compressed prefix until a valid curve point is found.
The last byte of the padded x-coordinate is an iteration counter
$j \in [0, 255]$; the first byte of the decoded x-coordinate is stripped
during recovery, leaving the original message bytes. This approach works on
every named curve in this crate because all have $p \equiv 3 \pmod{4}$, which means the
compressed-point square root exists and the iteration succeeds quickly in
practice.

The message capacity per ciphertext is `coord_len - 1` bytes.

**Integer layer** — additively homomorphic encryption of a small integer `m`:

```math
\text{encrypt\_int}(m) = \text{encrypt\_point}(m \cdot G)
```

Homomorphic addition of two ciphertexts:

```math
(C_1 + C_1',\; C_2 + C_2') \;\xrightarrow{\text{decrypt}}\; (m_1 + m_2) \cdot G
```

The integer $m$ is recovered from $m \cdot G$ via baby-step giant-step
(BSGS) with $O\left(\sqrt{m_{\max}}\right)$ precomputation.

So `EC-ElGamal` is intentionally the arithmetic-rich counterpart to `ECIES`:

- point encryption for direct group-element work
- byte encryption for bounded arbitrary payloads via Koblitz embedding
- additive homomorphism on the integer layer

The practical constraint is capacity. Because the byte layer embeds the payload
into an x-coordinate candidate, each ciphertext can carry only `coord_len - 1`
bytes. That is why `ECIES` exists alongside it: `ECIES` is the general-purpose
byte-encryption path, while `EC-ElGamal` is the path that preserves the group
structure when that algebra matters.

As with the other short-Weierstrass public key types, the public key can be
serialized either as a compact SEC 1 point or as the crate-defined blob that
embeds the full curve parameters.

#### ECDSA

Reference: FIPS 186-5 (`pubs/fips186-5.pdf`); SEC 1 v2.0 and SEC 2 v2.0 for the
underlying elliptic-curve point encodings (external standards; no local PDFs are
checked into `pubs/`).

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

The API mirrors the `DSA` surface closely:

- digest-level signing and verification
- message-level helpers parameterized by a `Digest`
- an explicit-nonce signing path for deterministic tests and vectors

So the short-Weierstrass and finite-field signature families line up on the
same caller model even though their underlying groups differ.

Like the other short-Weierstrass key types, `EcdsaPublicKey` supports both
compact SEC 1 point encodings and the self-describing crate-defined key blob.
That matches the Edwards writeup's clearer separation between "wire point" and
"standalone serialized key" forms.

The important practical caveat is the same one called out for the Edwards side:
the arithmetic is generic and variable-time. The implementation is correct and
well tested, but it is not a hardened constant-time signing engine.

### Twisted Edwards schemes

#### Edwards DH

Reference: NIST SP 800-56A Rev. 3 for the DH model (external standard) with
Edwards-group arithmetic and compressed-point conventions matching FIPS 186-5
(`pubs/fips186-5.pdf`).

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

Reference: the ElGamal paper for the encryption law (`pubs/elgamal-1985.pdf`)
with Edwards-curve group and encoding choices matching the Ed25519 / EdDSA
side of the crate (`pubs/fips186-5.pdf`; SEC 2 v2.0 is an external standard
with no local PDF).

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

Reference: FIPS 186-5 for EdDSA (`pubs/fips186-5.pdf`); SEC 2 v2.0 for the
underlying elliptic-curve parameter conventions is an external standard with
no local PDF.

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

### Curve25519 / Curve448 ECDH (RFC 7748)

Reference: RFC 7748, "Elliptic Curves for Security", §5 (X25519, X448) and
§5.2 (test vectors).

`X25519` and `X448` are the Montgomery-form ECDH primitives:

```math
\text{X25519}: \quad y^2 = x^3 + 486662\,x^2 + x \quad \text{over } \mathrm{GF}(2^{255} - 19)
```

```math
\text{X448}: \quad y^2 = x^3 + 156326\,x^2 + x \quad \text{over } \mathrm{GF}(2^{448} - 2^{224} - 1)
```

The crate ships these as a constant-time exception within `cryptography::vt`.
Unlike the rest of the public-key surface (which uses the variable-time
in-tree `BigUint`), X25519 and X448 use dedicated fixed-radix limb
representations:

- X25519: 5 limbs of radix $2^{51}$, two-pass carry reduction with the
  `2^{255} \equiv 19 \pmod p` wrap-around factor.
- X448: 8 limbs of radix $2^{56}$, two-pass carry reduction with the
  `2^{448} \equiv 2^{224} + 1 \pmod p` wrap-around factor.

In both cases the Montgomery ladder uses mask-driven `cswap` so the access
pattern depends on the loop index, not on the secret scalar bit. Field
multiply, square, conditional subtract, and final canonicalisation are
written without data-dependent branches or table lookups.

Scalar clamping follows RFC 7748 §5 exactly:

- X25519: `k[0] &= 248; k[31] &= 127; k[31] |= 64`
- X448: `k[0] &= 252; k[55] |= 128`

The encoded `u`-coordinate inputs likewise follow the spec:

- X25519: high bit of `u[31]` is masked off before decoding
- X448: full 448-bit `u`-coordinate, no masking

The shared-secret API (`agree`) returns `Option<[u8; N]>` and rejects the
all-zero output, as RFC 7748 §6 recommends for low-order point detection.
The raw `scalar_mult` function exposes the unconditional RFC 7748 mapping
(useful for KAT validation and protocol layers that prefer to do their own
low-order check).

Example (X25519):

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::X25519;

let mut rng = CtrDrbgAes256::new(&[0x33u8; 48]);
let (pub_a, priv_a) = X25519::generate(&mut rng);
let (pub_b, priv_b) = X25519::generate(&mut rng);
let shared_a = priv_a.agree(&pub_b).expect("non-low-order");
let shared_b = priv_b.agree(&pub_a).expect("non-low-order");
assert_eq!(shared_a, shared_b);
```

Test coverage in `cargo test`:

- RFC 7748 §5.2 single-step vectors for X25519 and X448
- iterated tests at 1 and 1000 iterations (run by default)
- iterated tests at 1 000 000 iterations (gated `#[ignore]`; run with
  `cargo test --release -- --ignored rfc7748_section5_2_iter_1m`)
- ECDH symmetry round-trip (`A * (B * G) == B * (A * G)`)
- low-order rejection by `agree`
- field-arithmetic sanity (`x * x^{-1} = 1`)

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

Public-key timing is measured with [pilot-bench](https://github.com/darrelllong/pilot-bench)
driving `pilot_pk` through:

```text
bash scripts/bench_all_pk_full.sh
```

The publication-facing numbers below come from Pilot and report milliseconds
per operation, **90%** confidence-interval half-width, and rounds required to
hit the stop rule. The 2026-08-11 sweep was run with
`PILOT_PRESET=normal --confidence-level 0.90` (10% CI half-width target,
autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample size) against
commit `e7e4825`, taken after the multiprecision layer moved to the sibling
[rump](https://github.com/darrelllong/rump) crate and prime-curve scalar
multiplication moved fully into the Montgomery domain. The tables below are
parallel runs on:

- Apple M1 (`tolkien`, macOS)
- AMD EPYC 7452 (`twilight.soe.ucsc.edu`, single-core slice — the same silicon
  as the 2026-06-11 sweep's `dennard`, which had lost its Boost runtime to an
  OS upgrade)
- NVIDIA Jetson (`heinlein`, aarch64)

Versus the 2026-06-11 v0.7.0 baseline, RSA/finite-field and ML-KEM/ML-DSA
throughput reflect the intervening optimization work, while prime-curve
ECDSA/ECDH are ~1.2–1.3× faster than that baseline: the Montgomery-domain
rewrite recovered a regression that a windowed-scalar-mult commit had left on
top of encode/decode-bound field arithmetic. See `bench/sweep-2026-08-11/`
for the raw per-host captures and provenance.

For RSA specifically, the timing gap between `encrypt`/`verify` and
`decrypt`/`sign` is still expected: the private side now uses CRT, but the
public side continues to benefit from the sparse default exponent
$e = 65{,}537$.

### Finite-field public key (1024-bit)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| rsa_keygen_1024 | 39.35 | ±0.9959 | 50 | 46.71 | ±0.1011 | 113 | 62.49 | ±0.2912 | 50 |
| rsa_encrypt_1024 | 0.01186 | ±0.0002774 | 50 | 0.01562 | ±8.584e-05 | 50 | 0.02056 | ±2.636e-05 | 82 |
| rsa_decrypt_1024 | 0.2263 | ±0.0003833 | 50 | 0.2663 | ±0.001074 | 170 | 0.337 | ±0.0005036 | 110 |
| rsa_sign_1024 | 0.2248 | ±0.0003607 | 50 | 0.2677 | ±0.00127 | 81 | 0.3364 | ±0.0005865 | 80 |
| rsa_verify_1024 | 0.0123 | ±0.0003969 | 50 | 0.01608 | ±7.856e-05 | 50 | 0.02097 | ±1.722e-05 | 80 |
| elgamal_keygen_1024 | 54.54 | ±0.04681 | 50 | 80.54 | ±0.157 | 110 | 112.3 | ±0.4498 | 50 |
| elgamal_encrypt_1024 | 0.2778 | ±0.0002598 | 50 | 0.4151 | ±0.003516 | 50 | 0.5472 | ±0.0005604 | 50 |
| elgamal_decrypt_1024 | 0.1351 | ±9.838e-05 | 50 | 0.1998 | ±0.0009846 | 80 | 0.2721 | ±0.0001705 | 50 |
| dsa_keygen_1024 | 39.32 | ±0.03666 | 50 | 58.02 | ±0.07967 | 177 | 80.61 | ±0.3098 | 50 |
| dsa_sign_1024 | 0.1717 | ±0.0001504 | 50 | 0.2449 | ±0.0007453 | 110 | 0.3218 | ±0.0002066 | 50 |
| dsa_verify_1024 | 0.2977 | ±0.000195 | 144 | 0.4383 | ±0.001041 | 56 | 0.5831 | ±0.0004643 | 50 |
| paillier_keygen_1024 | 25.95 | ±0.02531 | 50 | 31.7 | ±0.04297 | 59 | 42.53 | ±0.1171 | 50 |
| paillier_encrypt_1024 | 2.586 | ±0.0008652 | 50 | 3.787 | ±0.0108 | 50 | 5.342 | ±0.02866 | 57 |
| paillier_decrypt_1024 | 1.906 | ±0.0006735 | 110 | 2.823 | ±0.01299 | 82 | 4.006 | ±0.0257 | 50 |
| paillier_rerandomize_1024 | 2.004 | ±0.0007385 | 50 | 2.941 | ±0.005214 | 50 | 4.13 | ±0.01559 | 50 |
| paillier_add_1024 | 0.01017 | ±3.376e-06 | 51 | 0.01502 | ±4.216e-05 | 50 | 0.02156 | ±0.0003708 | 50 |
| cocks_keygen_1024 | 23.89 | ±0.02534 | 80 | 28.73 | ±0.02814 | 85 | 38.46 | ±0.1417 | 50 |
| cocks_encrypt_1024 | 0.6689 | ±0.01354 | 55 | 0.9546 | ±0.001463 | 112 | 1.257 | ±0.00613 | 50 |
| cocks_decrypt_1024 | 0.1062 | ±7.949e-05 | 86 | 0.1242 | ±0.0002001 | 80 | 0.1586 | ±0.0006257 | 50 |
| rabin_keygen_1024 | 28.04 | ±0.02633 | 50 | 33.97 | ±0.05819 | 52 | 44.87 | ±0.169 | 50 |
| rabin_encrypt_1024 | 0.003209 | ±2.12e-05 | 110 | 0.004378 | ±1.581e-05 | 80 | 0.005968 | ±4.322e-05 | 110 |
| rabin_decrypt_1024 | 0.2203 | ±0.0002371 | 53 | 0.2612 | ±0.000761 | 80 | 0.3448 | ±0.004771 | 50 |
| schmidt_samoa_keygen_1024 | 10.16 | ±0.01139 | 50 | 12.52 | ±0.0172 | 50 | 17.41 | ±0.2047 | 140 |
| schmidt_samoa_encrypt_1024 | 0.6543 | ±0.001639 | 50 | 0.9898 | ±0.001367 | 53 | 1.322 | ±0.005045 | 50 |
| schmidt_samoa_decrypt_1024 | 0.1886 | ±0.00225 | 110 | 0.2736 | ±0.0005841 | 50 | 0.3704 | ±0.001875 | 50 |

### RSA (2048-bit)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| rsa_keygen_2048 | 322.6 | ±2.772 | 50 | 472.6 | ±0.4037 | 50 | 642.2 | ±0.7072 | 50 |
| rsa_encrypt_2048 | 0.03541 | ±1.736e-05 | 50 | 0.04928 | ±0.0001883 | 50 | 0.06935 | ±6.586e-05 | 50 |
| rsa_decrypt_2048 | 1.119 | ±0.001223 | 50 | 1.648 | ±0.004805 | 50 | 2.203 | ±0.001736 | 52 |
| rsa_sign_2048 | 1.118 | ±0.00106 | 50 | 1.672 | ±0.006769 | 80 | 2.204 | ±0.001965 | 50 |
| rsa_verify_2048 | 0.03498 | ±3.27e-05 | 50 | 0.04927 | ±0.0002926 | 51 | 0.06941 | ±6.195e-05 | 50 |

### ECDSA / ECDH (P-256)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| ecdsa_keygen | 0.6922 | ±0.001523 | 50 | 0.9112 | ±0.0007293 | 80 | 1.013 | ±0.00425 | 50 |
| ecdsa_sign | 0.7178 | ±0.002061 | 50 | 0.9439 | ±0.000494 | 50 | 1.049 | ±0.001983 | 88 |
| ecdsa_verify | 1.393 | ±0.002277 | 50 | 1.838 | ±0.001949 | 80 | 2.032 | ±0.006031 | 57 |
| ecdh_keygen | 0.6934 | ±0.001522 | 50 | 0.9113 | ±0.0007938 | 50 | 1.015 | ±0.002807 | 50 |
| ecdh_agree | 0.6853 | ±0.0006186 | 50 | 0.9009 | ±0.000773 | 50 | 0.9976 | ±0.002104 | 50 |
| ecdh_serialize | 0.0001048 | ±2.272e-06 | 117 | 0.0001103 | ±2.205e-06 | 100 | 0.0001734 | ±1.329e-05 | 202 |

### ECIES / EC ElGamal (P-256)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| ecies_keygen | 0.6931 | ±0.0007416 | 50 | 0.912 | ±0.0009402 | 110 | 1.015 | ±0.003916 | 50 |
| ecies_encrypt | 1.377 | ±0.0008156 | 172 | 1.814 | ±0.00204 | 50 | 2.01 | ±0.006467 | 50 |
| ecies_decrypt | 0.6865 | ±0.0006979 | 140 | 0.9016 | ±0.001106 | 110 | 1.043 | ±0.006307 | 80 |
| ec_elgamal_keygen | 0.692 | ±0.0007007 | 53 | 0.9114 | ±0.0007747 | 50 | 1.014 | ±0.003035 | 53 |
| ec_elgamal_encrypt | 1.45 | ±0.003029 | 50 | 1.911 | ±0.001484 | 110 | 2.117 | ±0.00688 | 50 |
| ec_elgamal_decrypt | 0.7066 | ±0.0006953 | 57 | 0.9304 | ±0.001067 | 170 | 1.07 | ±0.004876 | 179 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| ed25519_keygen | 0.8009 | ±0.001653 | 50 | 1.091 | ±0.0009148 | 140 | 1.202 | ±0.001979 | 50 |
| ed25519_sign | 0.3994 | ±0.0009579 | 80 | 0.5233 | ±0.0005169 | 86 | 0.5984 | ±0.004293 | 50 |
| ed25519_verify | 1.328 | ±0.003209 | 50 | 1.756 | ±0.001222 | 110 | 1.885 | ±0.003486 | 54 |
| edwards_dh_keygen | 0.7813 | ±0.001639 | 50 | 1.055 | ±0.0008103 | 50 | 1.171 | ±0.004122 | 140 |
| edwards_dh_agree | 0.3966 | ±0.0008523 | 86 | 0.5215 | ±0.0004529 | 80 | 0.5899 | ±0.001329 | 50 |
| edwards_dh_serialize | 7.418e-05 | ±1.721e-06 | 147 | 6.002e-05 | ±2.406e-06 | 185 | 8.984e-05 | ±7.406e-06 | 516 |
| edwards_elgamal_keygen | 0.7819 | ±0.002504 | 50 | 1.055 | ±0.0009573 | 50 | 1.171 | ±0.003214 | 110 |
| edwards_elgamal_encrypt | 0.8429 | ±0.002014 | 50 | 1.111 | ±0.001037 | 50 | 1.264 | ±0.006536 | 50 |
| edwards_elgamal_decrypt | 0.6706 | ±0.004337 | 50 | 0.8869 | ±0.0009629 | 52 | 1.032 | ±0.004787 | 80 |

### X25519 / X448 (RFC 7748)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| x25519_keygen | 0.03524 | ±2.244e-06 | 119 | 0.06613 | ±0.0001387 | 80 | 0.09355 | ±0.001335 | 110 |
| x25519_agree | 0.03438 | ±1.076e-05 | 80 | 0.06484 | ±0.0001384 | 50 | 0.09251 | ±0.001412 | 50 |
| x25519_scalar_mult_base | 0.03442 | ±1.523e-05 | 50 | 0.06486 | ±0.0001734 | 50 | 0.09293 | ±0.001243 | 50 |
| x25519_scalar_mult | 0.03442 | ±9.549e-06 | 80 | 0.06486 | ±0.0001528 | 80 | 0.09223 | ±0.001218 | 80 |
| x448_keygen | 0.2387 | ±4.219e-05 | 80 | 0.3645 | ±0.0005598 | 80 | 0.5539 | ±0.004547 | 110 |
| x448_agree | 0.2377 | ±6.014e-05 | 80 | 0.363 | ±0.0005443 | 50 | 0.5468 | ±0.004638 | 50 |
| x448_scalar_mult_base | 0.2378 | ±0.0001122 | 80 | 0.3635 | ±0.0006108 | 50 | 0.5543 | ±0.005977 | 83 |
| x448_scalar_mult | 0.2379 | ±0.0002164 | 50 | 0.3631 | ±0.0006711 | 53 | 0.5531 | ±0.004619 | 50 |

### ML-KEM (FIPS 203)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| mlkem512_keygen | 0.01414 | ±2.029e-05 | 80 | 0.02626 | ±0.0002278 | 54 | 0.04194 | ±0.003268 | 831 |
| mlkem512_encaps | 0.00867 | ±7.29e-06 | 86 | 0.0196 | ±0.0002527 | 57 | 0.03105 | ±0.002565 | 565 |
| mlkem512_decaps | 0.009044 | ±9.17e-06 | 50 | 0.02242 | ±0.0001954 | 112 | 0.03444 | ±0.002122 | 1190 |
| mlkem768_keygen | 0.02318 | ±2.805e-05 | 170 | 0.04404 | ±0.0004195 | 50 | 0.07032 | ±0.00586 | 717 |
| mlkem768_encaps | 0.01126 | ±1.085e-05 | 140 | 0.02688 | ±0.0003154 | 50 | 0.04245 | ±0.003537 | 1469 |
| mlkem768_decaps | 0.012 | ±1.403e-05 | 260 | 0.03127 | ±0.0002772 | 80 | 0.04795 | ±0.004002 | 839 |
| mlkem1024_keygen | 0.03638 | ±5.638e-05 | 82 | 0.06712 | ±0.0007828 | 50 | 0.11 | ±0.008793 | 320 |
| mlkem1024_encaps | 0.01519 | ±2.392e-05 | 50 | 0.03732 | ±0.0004799 | 82 | 0.05832 | ±0.004074 | 560 |
| mlkem1024_decaps | 0.01632 | ±1.882e-05 | 171 | 0.04288 | ±0.0003611 | 50 | 0.06589 | ±0.00413 | 835 |

### ML-DSA (FIPS 204)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| mldsa44_keygen | 0.05243 | ±7.969e-05 | 110 | 0.0954 | ±0.0005087 | 52 | 0.1705 | ±0.01357 | 80 |
| mldsa44_sign | 0.14 | ±6.97e-05 | 50 | 0.3109 | ±0.001191 | 80 | 0.471 | ±0.034 | 50 |
| mldsa44_verify | 0.01552 | ±1.605e-05 | 80 | 0.03446 | ±0.0003605 | 50 | 0.05488 | ±0.004006 | 530 |
| mldsa65_keygen | 0.09676 | ±0.0001117 | 118 | 0.1706 | ±0.0009733 | 50 | 0.291 | ±0.02428 | 59 |
| mldsa65_sign | 0.2387 | ±6.914e-05 | 80 | 0.5395 | ±0.001742 | 50 | 0.7905 | ±0.03576 | 50 |
| mldsa65_verify | 0.02192 | ±1.633e-05 | 82 | 0.04874 | ±0.0005093 | 110 | 0.07849 | ±0.006465 | 263 |
| mldsa87_keygen | 0.1352 | ±0.0001214 | 50 | 0.2482 | ±0.001166 | 170 | 0.4118 | ±0.03407 | 55 |
| mldsa87_sign | 0.1514 | ±7.512e-05 | 80 | 0.3418 | ±0.001506 | 50 | 0.5075 | ±0.02972 | 50 |
| mldsa87_verify | 0.03367 | ±2.656e-05 | 53 | 0.07422 | ±0.0007261 | 50 | 0.1144 | ±0.004208 | 260 |

### NTRU (NIST PQC round 3)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| ntruhps509_keygen | 0.9711 | ±0.001772 | 81 | 1.308 | ±0.004394 | 80 | 2.56 | ±0.03695 | 50 |
| ntruhps509_encaps | 0.0818 | ±0.0001429 | 81 | 0.1094 | ±0.0006578 | 80 | 0.2252 | ±0.01171 | 50 |
| ntruhps509_decaps | 0.1382 | ±0.0003768 | 50 | 0.1592 | ±0.000874 | 50 | 0.3502 | ±0.005051 | 80 |
| ntruhps677_keygen | 1.128 | ±0.04444 | 50 | 1.865 | ±0.004605 | 50 | 3.382 | ±0.03239 | 110 |
| ntruhps677_encaps | 0.08611 | ±0.002355 | 50 | 0.1381 | ±0.0008496 | 80 | 0.2623 | ±0.003471 | 50 |
| ntruhps677_decaps | 0.09966 | ±0.003664 | 50 | 0.1686 | ±0.002402 | 82 | 0.3432 | ±0.02239 | 50 |
| ntruhps821_keygen | 2.42 | ±0.004594 | 59 | 2.883 | ±0.005111 | 50 | 5.398 | ±0.08901 | 54 |
| ntruhps821_encaps | 0.1623 | ±0.0004615 | 50 | 0.2015 | ±0.001515 | 50 | 0.3856 | ±0.02795 | 50 |
| ntruhps821_decaps | 0.292 | ±0.000697 | 50 | 0.2903 | ±0.001444 | 116 | 0.599 | ±0.04948 | 50 |
| ntruhrss701_keygen | 1.167 | ±0.03213 | 50 | 1.89 | ±0.003288 | 50 | 3.698 | ±0.04872 | 80 |
| ntruhrss701_encaps | 0.04679 | ±0.002884 | 50 | 0.06998 | ±0.0007069 | 140 | 0.1468 | ±0.00231 | 50 |
| ntruhrss701_decaps | 0.1152 | ±0.007519 | 80 | 0.1738 | ±0.0008715 | 50 | 0.3748 | ±0.004132 | 50 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation | Tolkien (M1) ms/op | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Twilight (EPYC 7452) ms/op | Twilight (EPYC 7452) ±CI (90%) | Twilight (EPYC 7452) Runs | Heinlein (Jetson) ms/op | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|
| ntruees401ep1_keygen | 0.7537 | ±0.000746 | 80 | 0.9664 | ±0.01377 | 50 | 1.831 | ±0.04926 | 110 |
| ntruees401ep1_encrypt | 0.09678 | ±8.825e-05 | 86 | 0.1106 | ±0.001106 | 113 | 0.2963 | ±0.02016 | 50 |
| ntruees401ep1_decrypt | 0.1333 | ±0.0001171 | 50 | 0.1615 | ±0.008727 | 50 | 0.4827 | ±0.03273 | 80 |
| ntruees443ep1_keygen | 0.7005 | ±0.0008643 | 50 | 0.8692 | ±0.002609 | 50 | 1.712 | ±0.02397 | 80 |
| ntruees443ep1_encrypt | 0.04115 | ±3.726e-05 | 87 | 0.04498 | ±0.0004609 | 170 | 0.1017 | ±0.007294 | 140 |
| ntruees443ep1_decrypt | 0.04026 | ±5.079e-05 | 50 | 0.04995 | ±0.000548 | 50 | 0.1371 | ±0.0113 | 116 |
| ntruees449ep1_keygen | 0.8905 | ±0.001233 | 171 | 1.13 | ±0.004091 | 50 | 2.184 | ±0.05105 | 50 |
| ntruees449ep1_encrypt | 0.1358 | ±0.0001282 | 230 | 0.1556 | ±0.001178 | 170 | 0.4387 | ±0.02869 | 50 |
| ntruees449ep1_decrypt | 0.1658 | ±0.0002389 | 50 | 0.1974 | ±0.001387 | 50 | 0.6227 | ±0.05111 | 53 |
| ntruees541ep1_keygen | 0.6922 | ±0.001709 | 50 | 1.058 | ±0.004782 | 80 | 1.962 | ±0.1165 | 50 |
| ntruees541ep1_encrypt | 0.0697 | ±6.839e-05 | 50 | 0.07611 | ±0.0008384 | 51 | 0.1971 | ±0.01619 | 83 |
| ntruees541ep1_decrypt | 0.0839 | ±5.857e-05 | 140 | 0.1028 | ±0.004942 | 80 | 0.3105 | ±0.02535 | 80 |
| ntruees677ep1_keygen | 1.126 | ±0.02177 | 50 | 1.621 | ±0.005894 | 114 | 3.337 | ±0.2777 | 53 |
| ntruees677ep1_encrypt | 0.174 | ±0.0002022 | 50 | 0.2017 | ±0.001649 | 81 | 0.5875 | ±0.02286 | 50 |
| ntruees677ep1_decrypt | 0.267 | ±9.053e-05 | 50 | 0.3252 | ±0.002043 | 140 | 1.023 | ±0.01056 | 80 |
| ntruees1087ep1_keygen | 1.788 | ±0.02263 | 50 | 2.687 | ±0.006388 | 50 | 5.066 | ±0.1294 | 50 |
| ntruees1087ep1_encrypt | 0.138 | ±0.0002103 | 50 | 0.1564 | ±0.001568 | 110 | 0.4467 | ±0.005431 | 50 |
| ntruees1087ep1_decrypt | 0.1845 | ±0.0001204 | 50 | 0.2307 | ±0.001816 | 80 | 0.7537 | ±0.01328 | 80 |
| ntruees1087ep2_keygen | 1.888 | ±0.02881 | 83 | 2.812 | ±0.009131 | 80 | 5.416 | ±0.2621 | 50 |
| ntruees1087ep2_encrypt | 0.2139 | ±0.0002769 | 50 | 0.2483 | ±0.002281 | 84 | 0.7621 | ±0.009195 | 50 |
| ntruees1087ep2_decrypt | 0.3237 | ±0.0001201 | 174 | 0.4009 | ±0.002749 | 50 | 1.37 | ±0.01687 | 52 |
| ntruees1171ep1_keygen | 2.07 | ±0.04132 | 80 | 3.015 | ±0.01813 | 110 | 6.106 | ±0.4724 | 50 |
| ntruees1171ep1_encrypt | 0.2066 | ±0.00017 | 80 | 0.2412 | ±0.002981 | 140 | 0.7426 | ±0.04789 | 50 |
| ntruees1171ep1_decrypt | 0.3095 | ±0.0001289 | 54 | 0.3806 | ±0.003106 | 170 | 1.289 | ±0.02434 | 50 |
| ntruees1499ep1_keygen | 3.17 | ±0.06417 | 50 | 4.374 | ±0.01748 | 50 | 9.638 | ±0.1622 | 290 |
| ntruees1499ep1_encrypt | 0.2129 | ±0.0001693 | 111 | 0.2413 | ±0.002655 | 53 | 0.7198 | ±0.01159 | 51 |
| ntruees1499ep1_decrypt | 0.3038 | ±0.0007624 | 530 | 0.3775 | ±0.003951 | 50 | 1.27 | ±0.01801 | 80 |


Cross-platform summary Kiviat diagrams (radar charts; log-radial ops/sec
axis, outer ring = faster):

![RSA / DSA / EC ops/sec Kiviat (Tolkien / Twilight / Heinlein)](assets/sweep-2026-08-11-pk-rsa-ec-radar.svg)

![Post-quantum ops/sec Kiviat — ML-KEM / ML-DSA / NTRU (Tolkien / Twilight / Heinlein)](assets/sweep-2026-08-11-pk-pq-radar.svg)

The integer-arithmetic chart above plots ops/sec for the mixed integer-based
public-key schemes (RSA, DSA, ECDSA, ECDH, Ed25519, X25519, X448).
Signature-only and rerandomization/addition rows stay in the tables because
they do not have matching encrypt/decrypt axes.

The post-quantum chart blends representative axes from ML-KEM, ML-DSA, and
NTRU. Per-scheme breakdown radars live in
[POSTQUANTUM.md](POSTQUANTUM.md).

## Practical Guidance

- Use `RSA` when you need standards-backed encryption or signatures.
- Use `DSA`, `ECDSA`, or `Ed25519` when you need a standards-backed digital signature.
- Use `ECIES` when you need public-key encryption over an elliptic curve.
- Use `ECDH` or `DH` when you need key agreement without a full encryption layer.
- Use the other implemented schemes when you explicitly want those primitives
  and understand their wrapper model.
- Use `CtrDrbgAes256` (or another strong `Csprng`) for all randomized public-key
  operations.
- Keep an eye on 2048-bit and larger timings; the in-tree bigint backend is
  respectable but not a tuned industrial multiprecision library. The crate-wide
  policy is to keep the arithmetic kernels pure Rust and in-tree.

## References

The primary public-key papers and standards are stored in `pubs/`. The BibTeX
index is in [README.md](README.md).
