# ASYMMETRIC

## Arithmetic Foundation

The public-key layer is built on:

- `BigUint`
- `BigInt`
- `MontgomeryCtx`
- number theory from `rump`, plus the cryptographic policy layered on it in
  `src/public_key/primes.rs`

The bigint backend (the sibling `rump` crate) stores `u64` limbs in
little-endian limb order and uses Montgomery multiplication for repeated
modular arithmetic under odd moduli. That is the common case for every implemented public-key
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

That is why the bigint and Montgomery code depend on no third-party
arithmetic: they live in the sibling [rump](https://github.com/darrelllong/rump)
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
- `Dsa` — signatures (FIPS 186-4; FIPS 186-5 keeps DSA for verification only)
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
- `Ecies` — Elliptic Curve Integrated Encryption Scheme (SEC 1 v2.0 §5.1)

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

Points encode in the RFC 8032 `b`-bit form, `⌈(bits(p) + 1)/8⌉` octets with
the sign of `x` in the top bit of the last octet: 32 octets for Ed25519 and
57 for an Ed448-sized field (RFC 8032 §5.1.2, §5.2.2). Decoding refuses a
`y ≥ p` and any set bit between `bits(p)` and the sign bit, so every point has
one encoding.

Explicit Edwards parameters arriving in an EdDsa, Edwards-DH or
Edwards-ElGamal blob, PEM or XML document go through
`TwistedEdwardsCurve::from_explicit` before any expensive work: Ed25519's
parameters are accepted by comparison; any others must have `p` of at most
`MAX_EXPLICIT_FIELD_BITS` (1024) bits and `n` of at most `bits(p) + 1`, every
coefficient and coordinate reduced, `p` and `n` prime by the hardened test,
`a` a square and `d` a non-square (the completeness condition of the addition
law), `G` on the curve, a Hasse cofactor `h = ⌊(√p + 1)²/n⌋` that is even and
at most `MAX_EXPLICIT_COFACTOR` (8), no embedding degree below 100, and
`[n]G` neutral. EdDsa verification requires `R` to be canonical, on the curve
and non-neutral, and lets the equation `S·G = R + e·A` fix its order, since
`A` is validated into the prime-order subgroup on import.

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

Every DER reader — the integer-sequence blobs and the RSA PKCS #1 / PKCS #8 /
SPKI containers alike — is one strict X.690 DER parser: definite lengths in
the fewest octets, `INTEGER`s in the fewest octets, non-negative, no trailing
bytes. BER-style encodings (a long-form length below 128, a redundant leading
`00` on an integer, an indefinite length) are rejected, so every key and
signature has exactly one accepted encoding.

Parsing also validates, under one policy for every scheme (stated in full in
the `public_key` module docs): a private key is validated completely —
hardened primality on every prime it carries, the scheme's algebraic
relations, derived values recomputed rather than trusted — while a public key
is validated structurally — ranges, parity, subgroup membership
(`y^q ≡ 1 (mod p)` for `DSA` and `DH`), and one fixed-base primality test per
public prime, so loading someone else's key never costs the 76-round hardened
test. `DhParams` and `DsaParams` are the exceptions in the public-looking
direction: a group the crate will generate a secret over is validated as
private material, and parameters that carry a FIPS 186-4 seed record are also
validated against it (Appendix A.1.1.3 and A.2.4).

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

The paper works with a large prime `p` and a primitive element of
$\mathbb{Z}_p^*$, and `ElGamal::from_secret_exponent` requires exactly that.
Recognizing a primitive root needs the factorization of $p - 1$, so `p` must
be a safe prime $p = 2q + 1$ (both hardened probable primes, at most 16 384
bits); then `g` is primitive exactly when $1 < g < p - 1$ and $g^q \ne 1$.
The secret must satisfy $1 \le a \le p - 2$ and $a \ne q$, since $a = q$
gives $y = p - 1$; and the one nonce $k = q$, which gives $\gamma = p - 1$
and $y^k = \pm 1$, is refused, because both would make $\delta = \pm m$.
Every parser of a key with bound $p - 1$ applies the same checks. Generated
keys work in a prime-order subgroup instead, with $p = kq + 1$ for a large
cofactor `k` (a safe prime $p = 2q + 1$ would be far slower to find).
`ElGamal::generate(rng, size, hash)` takes that group from FIPS 186-4
Appendix A — `p` and `q` by A.1.1.2 at one of the four §4.2 `(L, N)` pairs,
`g` by A.2.3 — and `ElGamal::generate_toy(rng, bits)` makes groups below 1024
bits for tests, following no standard. No NIST standard specifies ElGamal
encryption itself, and the key formats have no place for the FIPS 186-4 seed
record, so a key's group cannot be revalidated from the key.

The public key stores the real ephemeral bound used for encryption, so the
random ephemeral exponent is sampled from the right range instead of from the
full `p - 1` interval. Generated keys use the subgroup order `q` for that
bound; keys over a safe prime with a primitive `g` use `p - 1`.

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

It is raw ElGamal and not a message-encryption scheme: it is malleable
($(\gamma, c\delta)$ decrypts to $cm$), and every ciphertext publishes a class
of the message. Under a subgroup key $\delta^q = m^q$ gives the message's coset
of the order-$q$ subgroup; under a safe-prime key the public quadratic
characters give $\chi(m) = \chi(\delta)$ when $\chi(y) = 1$ and
$\chi(m) = \chi(\delta)\chi(\gamma)$ otherwise. Protecting messages needs a
specified KEM, KDF and AEAD composition, which the crate does not provide; the
test `raw_ciphertexts_publish_the_message_class` pins both identities.

#### DSA

Reference: FIPS 186-4, Digital Signature Standard (`pubs/fips186-4.pdf`).
FIPS 186-5 (`pubs/fips186-5.pdf`) no longer approves DSA for generating
signatures, allows it only for verifying signatures made earlier, and no longer
contains its specification.

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

Domain parameters are generated apart from key pairs, as FIPS 186-4 §4.3
describes. `Dsa::generate_params(rng, size, hash)` runs Appendix A.1.1.2 for
`p` and `q` at one of the §4.2 pairs — `(1024, 160)`, `(2048, 224)`,
`(2048, 256)`, `(3072, 256)` — with a SHA-2 hash at least `N` bits long, and
A.2.3 for `g` with index 1. Its Miller-Rabin rounds are Table C.1's (bases from
the caller's RNG), followed by a Lucas test. The resulting `DsaParams` keeps
the seed record (`FfcSeed`: hash, `domain_parameter_seed`, `counter`, `index`)
and serializes it, and `DsaParams::with_seed` validates third-party parameters
by A.1.1.3 and A.2.4. Validation has no RNG to draw bases from, so its
primality test is the crate's hardened one (64 SHAKE256-derived bases after
twelve fixed ones) rather than C.3.1's random bases. Both routines are checked
against NIST's CAVP `PQGGen.rsp` and `PQGVer.rsp` vectors
(`tests/vectors/fips186_4_ffc_domain_parameters.txt`).
`Dsa::generate(&params, rng)` then draws `x` uniformly from `[1, q)`, the
distribution of Appendix B.1.2. `Dsa::generate_toy_params(rng, bits)` makes
groups below 1024 bits for tests and follows no standard.

`sign_digest_with_rng` samples the per-message nonce uniformly from `[1, q)`,
the distribution of Appendix B.2.2, drawing again when `r = 0` or `s = 0` as
§4.6 directs and giving up with `None` after `MAX_NONCE_DRAWS = 64` such
draws in a row (about `(2/q)^64` for a working source; a source stuck on the
one `k` that zeroes `s` fails every draw, and a stalled source is reported by
`rump`'s own 256-rejection panic before the bound matters); `sign_digest`
derives `k` by RFC 6979, which FIPS 186-4 does not list among its approved
methods, and stops at the same bound. Every DSA, DH and ElGamal group must
have `q ≥ 2^15`, `p ≤ 16 384` bits and `q ≤ 512` bits, checked before any
primality test. Signing leaks the bit length of `k` through the variable-time
exponentiation; DH and ElGamal exponentiate a peer-chosen base with the static
secret. ElGamal decryption refuses `γ` or `δ` outside `[1, p)` and, when the
key carries `q`, a `γ` outside the order-`q` subgroup; the encryptor refuses
`m = 0`. The digest
representative is the leftmost $\min(N, \mathrm{outlen})$ bits of the hash,
with $N = \mathrm{bits}(q)$ (§4.6).

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
parameter registry. The key blobs do not carry the seed record; `DsaParams`
does, in an eight-field form beside the original three-field one.

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

Cocks is historically important: Clifford Cocks described it in a CESG
memorandum in November 1973, declassified by GCHQ in December 1997; RSA was
published independently in 1977. The scheme is unusual because the public
exponent is the modulus itself. The crate keeps that arithmetic intact and
adds the byte-level serialization layer on top instead of inventing a
modernized padding story that the literature does not standardize. The map is
deterministic (equal messages give equal ciphertexts) and carries no
OAEP-like layer, so it is not IND-CPA; and its private exponentiation runs in
variable time on the secret exponent, as the module documentation states.

The private exponent is:

```math
\pi \equiv p^{-1} \pmod{q - 1}
```

and the key observation is what happens modulo $q$: $c^\pi \equiv m^{pq\pi}
\pmod q$, and since $p\pi \equiv 1 \pmod{q-1}$, $pq\pi \equiv q \equiv 1
\pmod{q-1}$, so Fermat gives $m^{pq\pi} \equiv m \pmod q$.

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
variant: a fixed 128-bit tag occupies the low bits of the encoded plaintext
(`m·2^128 + tag`, then shifted into the upper half of the residues) and
selects the intended root at decrypt time. The scheme is deterministic and
not IND-CPA, and the tag is the only thing between a decryption oracle and
the factorization: a chosen ciphertext whose root is accepted with the wrong
sign yields a factor of `n` through a gcd, which the tag makes a `2^-126`
event per query.

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
factoring $n$. The fixed 128-bit disambiguation tag used here is what lets
the code identify the intended root among the four CRT roots and turn the raw
squaring trapdoor into a deterministic decryptor; decryption reports the first
matching root in the order `x, −x, y, −y`.

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
the same standards ecosystem or deployment relevance as RSA. Like Cocks it is
a deterministic map with no padding layer (not IND-CPA), and its private
exponentiation runs in variable time on the secret exponent.

The wrapper therefore stays minimal:

- raw arithmetic for the underlying construction
- byte helpers for crate-local usability
- no attempt to present it as a standards-grade interoperable scheme

This keeps the scheme available for study and comparison without pretending it
belongs in the same operational category as the RSA layer.

#### Diffie-Hellman

Reference: NIST SP 800-56A Rev. 3 (`pubs/sp800-56a-r3.pdf`) — the FFC DH
primitive (§5.7.1.1), FFC full public-key validation (§5.6.2.3.1), and FIPS
186-type domain parameters (§5.5.1.1). The key-agreement schemes of its §6
(key derivation, key confirmation) are not implemented.

Core arithmetic:

```math
y = g^x \bmod p
```

with shared secret:

```math
s = y_{\mathrm{peer}}^x \bmod p
```

`DH` works in a prime-order subgroup, as `DSA` and `ElGamal` do, with an
explicit subgroup order `q`. The public key stores `(p, q, g, y)` so the receiver can validate that the peer's
contribution actually lies in the correct subgroup before computing the shared
secret. The validation check is:

```math
1 < y < p \qquad \text{and} \qquad y^q \equiv 1 \pmod{p}
```

For odd `q` that is SP 800-56A §5.6.2.3.1, whose bound $y \le p - 2$ follows
because $p - 1$ has order 2.

`DhPrivateKey::agree_element` returns `None` when the peer key belongs to a
different group or fails the subgroup check, and when the result is
$z \le 1$ or $z = p - 1$ (§5.7.1.1 step 2); the public-key parsers apply the
same membership check, so a blob whose `y` lies outside the subgroup never
becomes a `DhPublicKey`. The raw shared secret is returned as a
`BigUint`; callers are expected to apply their own KDF before using it as
keying material. SP 800-56A's shared secret `Z` is that integer encoded at the
byte length of `p` (its Appendix C.1), which `to_be_bytes` is not: it drops
leading zero bytes.

That return shape is intentionally lower-level than the EC variants. `DH`
returns the shared group element itself, not a byte-oriented KDF input chosen
by the library. The crate leaves that derivation step to the caller rather than
quietly committing to a KDF policy here.

Like `DSA`, the key blobs carry `(p, q, g)` explicitly. That makes `DhParams`
and the generated keys self-contained and avoids any hidden dependency on an
external parameter database. `DhParams` has no public fields: it is built by
`Dh::generate_params`, `Dh::generate_toy_params`, `DhParams::new(p, q, g)`,
`DhParams::with_seed(p, q, g, seed)`, or the parsers, and each validates,
because these are the groups the crate generates fresh secrets over (a
composite `p` that survives fixed Miller-Rabin bases would split `Z_p^*` into
components where a discrete logarithm is cheap). `DhPublicKey::params()`
therefore returns `Option<DhParams>`, re-validating a peer's group under that
rule before it can be reused for key generation.

`Dh::generate_params(rng, size, hash)` generates FIPS 186-type parameters the
way SP 800-56A §5.5.1.1 requires — FIPS 186-4 A.1.1.2 and A.2.3, with index 2,
keeping the seed record — and only at that section's parameter-size sets FB
`(2048, 224)` and FC `(2048, 256)`; it refuses the other two FIPS 186-4 pairs.
The same section says FIPS 186-type parameters should be used only for backward
compatibility and requires an approved safe-prime group (its Appendix D) above
112 bits of security; those groups are not implemented.
`DhParams::with_seed` validates third-party parameters by FIPS 186-4 A.1.1.3
and A.2.4, and `Dh::generate_toy_params(rng, bits)` makes groups below 1024
bits for tests, following no standard.

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

Because the blob and the XML form carry the curve itself, their decoders (in
ECDSA, ECDH, ECIES and EC-ElGamal alike) build it through
`CurveParams::from_explicit`, which accepts the parameters on one of the two
grounds SEC 1 v2.0 §3.1.1.2 and §3.1.2.2 give a party that did not generate
them: they equal a named curve of this crate, or they pass the validation
primitive of §3.1.1.2.1 (prime fields) or §3.1.2.2.1 (binary fields) in full,
available on its own as `CurveParams::validate_domain_parameters`. The
primitive fixes the field sizes it admits, $\lceil \log_2 p \rceil \in \{192,
224, 256, 384, 521\}$ and $m \in \{163, 233, 239, 283, 409, 571\}$ under a
Table 1 reduction polynomial, and then requires $p$ and $n$ prime, reduced
coefficients and base point, a non-singular curve with $G$ on it, the
cofactor $h = \lfloor (\sqrt{q} + 1)^2 / n \rfloor$ with $h \le 2^{t/8}$,
$n G = \mathcal{O}$, and neither an anomalous curve nor an embedding degree
below 100 (over $\mathbb{F}_{2^m}$ the primitive bounds $\mathrm{ord}_n(2) \ge 100m$,
which implies it). A sound curve no name
covers, P-256 with $-G$ as base point say, decodes; a 160-bit curve does not,
whatever its merits, because the primitive has no security level for it.
`CurveParams::new` and `new_binary` remain the constructors for parameters the
caller vouches for.

As with `DH`, `EcdhPrivateKey::agree` returns raw shared-secret material, not a
KDF output. The returned bytes are the padded x-coordinate and should be fed
through a KDF before use as a symmetric key.

#### ECIES

Reference: SEC 1 v2.0, "SEC 1: Elliptic Curve Cryptography", §5.1
(`pubs/sec1-v2-elliptic-curve-cryptography.pdf`), with its components in §2.3
(octet conversions), §3.3 (Diffie–Hellman primitives), §3.6.1
(ANSI-X9.63-KDF), §3.7 (MAC schemes) and §3.8 (symmetric encryption schemes).
Known answers: GEC 2 v0.3 §3 (`pubs/gec2-v0.3-test-vectors-for-sec1.pdf`), and
NIST CAVP's ANS X9.63 KDF and ECC CDH primitive vectors (`tests/vectors/`).

`ECIES` encrypts arbitrary byte strings to a static EC public key. Ephemeral
Diffie–Hellman yields a shared field element, a KDF expands it into an
encryption key and a MAC key, and the message is encrypted and then tagged.
Encryption costs two scalar multiplications (`k·G` and `k·Q`); decryption costs
one, plus `n·R` under the standard primitive.

SEC 1 makes ECIES a family. The recipient chooses five options, and
`EciesSetup` carries them explicitly:

| SEC 1 §5.1.1 | Type | Options |
|---|---|---|
| KDF (§3.6) | `EciesKdf` | ANSI-X9.63-KDF with SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 |
| MAC (§3.7) | `EciesMac` | HMAC-SHA-1-160/80, HMAC-SHA-224-112/224, HMAC-SHA-256-128/256, HMAC-SHA-384-192/384, HMAC-SHA-512-256/512, CMAC-AES-128/192/256 |
| ENC (§3.8) | `EciesEncryption` | XOR (SEC 1 v2.0 key layout, or v1.0 backwards compatibility), 3-key TDES-CBC, AES-128/192/256-CBC, AES-128/192/256-CTR |
| primitive (§3.3) | `EciesDhPrimitive` | standard, cofactor |
| point compression (§2.3.3) | `EciesPointFormat` | uncompressed, compressed |

`EciesSetup::RECOMMENDED` is ANSI-X9.63-KDF with SHA-256, AES-128-CTR,
HMAC-SHA-256-256, cofactor Diffie–Hellman and uncompressed points, aimed at
the 128-bit level of P-256.

**Encryption (§5.1.3):**

1. Generate an ephemeral key pair $(k, R)$ with $R = k \cdot G$, and encode $R$
   (§2.3.3).
2. Compute $z = x(k \cdot Q)$, or $z = x(h \cdot k \cdot Q)$ under the cofactor
   primitive; the point at infinity is "invalid". Encode $z$ as the octet
   string $Z$ (§2.3.5).
3. Derive $\mathit{enckeylen} + \mathit{mackeylen}$ octets of keying data:

```math
K = \mathrm{Hash}(Z \mathbin\| \mathtt{00000001} \mathbin\| \mathit{SharedInfo}_1)
    \mathbin\| \mathrm{Hash}(Z \mathbin\| \mathtt{00000002} \mathbin\| \mathit{SharedInfo}_1)
    \mathbin\| \cdots
```

4. Split $K$: $EK$ is the leftmost $\mathit{enckeylen}$ octets and $MK$ the
   rightmost $\mathit{mackeylen}$, except that XOR outside backwards
   compatibility mode takes $MK$ from the left.
5. Encrypt $EM = \mathrm{ENC}_{EK}(M)$. The CBC IV and the CTR initial counter
   block are zero and are not transmitted.
6. Tag $D = \mathrm{MAC}_{MK}(EM \mathbin\| \mathit{SharedInfo}_2)$.

**Ciphertext:**

```text
R   04 || X || Y   (1 + 2·coord_len octets)  or  02/03 || X   (1 + coord_len octets)
EM  as long as the message
D   maclen octets: x/8 for HMAC-Hash-x, 16 for CMAC-AES-x
```

**Decryption (§5.1.4):** parse `R` by its leading octet (either encoding is
accepted), decode it, require full validation (including `n·R = O`) under the
standard primitive or partial validation under the cofactor primitive,
recompute $Z$, $K$, $EK$ and $MK$, check $D$ in constant time, and only then
decrypt. Every failure returns `None`.

Three consequences come from the standard, not from this crate:

- `R` is not authenticated. `−R`, the other encoding of `R`, and under the
  cofactor primitive `R` plus a point whose order divides `h` all decrypt to
  the same plaintext; Appendix B.4.1 calls this benign malleability. Put `R`
  into SharedInfo₁ if ciphertexts must be unique.
- The MAC covers `EM ‖ SharedInfo₂` with no separator, so SharedInfo₂ needs a
  suffix-free format (§5.1.1 step 8). Without one, moving octets between the
  end of `EM` and SharedInfo₂ keeps the tag valid and truncates the plaintext.
- The CBC schemes take whole blocks only: SEC 1 defines no padding, and SP
  800-38A Appendix A (`pubs/sp800-38a.pdf`) leaves padding outside its scope.

This makes `ECIES` the practical "encrypt arbitrary bytes to an EC key" path
in the short-Weierstrass family. Unlike `EC-ElGamal`, it does not try to expose
the group law of the plaintext space; it uses the EC operation only for key
establishment, then hands the data path to the symmetric scheme and MAC the
setup names.

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
during recovery, leaving the original message bytes. The square root is
`rump`'s general Tonelli–Shanks, so every prime field (P-224 included) and, by
the half-trace, every binary field decompresses; on the cofactor curves the
index is retried until the point lies in the subgroup of order `n`, so every
ciphertext decrypts.

The message capacity per ciphertext is `⌊(bits − 1)/8⌋ − 1` bytes, `bits`
being `⌈log2 p⌉` on a prime field and `m` on `F_2^m` (30 bytes on P-256, 19
on B-163), so that `message ‖ j` is always a field element.

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
into an x-coordinate candidate, each ciphertext can carry only `⌊(bits − 1)/8⌋ − 1`
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

The per-message nonce `k` is derived deterministically (RFC 6979) or drawn
from the crate's `Csprng`. The digest representative `z` is the leftmost
`bits(n)` bits of the hash output, matching the FIPS 186-5 truncation rule for
hash functions wider than the group order.

Verification is exactly the FIPS 186-5 / SEC 1 predicate: any `1 ≤ s < n` is
accepted. The signer emits `s = k⁻¹(z + r·d) mod n` exactly as FIPS 186-5
§6.4.1 computes it, so deterministic signatures reproduce the RFC 6979 vectors
digit for digit. Because `(r, n − s)` verifies whenever `(r, s)` does,
protocols that forbid malleable signatures fix the representative with
`EcdsaSignature::to_low_s(curve)` (`s ≤ n/2`); that is a protocol rule, not a
verification requirement — a verifier that rejected high-`s` would refuse
about half of the conforming signatures other implementations produce. Empty
digests are refused by sign and verify. `EcdsaSignature::to_der` / `from_der`
are the X9.62 / RFC 3279 §2.2.3
`ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`), and the test suite
cross-checks both directions against the installed OpenSSL when one is
present.

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

Public keys are stored in canonical form: an imported `u` at or above `p` is
reduced on import, so `to_raw_bytes` and the SPKI encoding emit the reduced
coordinate and equality compares coordinates, not octet strings.

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
- `EciesPublicKey::encrypt` / `EciesPrivateKey::decrypt` (arbitrary-length bytes under XOR or CTR setups)
- `EcdsaPrivateKey::sign_message::<H>` / `EcdsaPublicKey::verify_message::<H>`
- `ElGamalPublicKey::encrypt_bytes` / `ElGamalPrivateKey::decrypt_bytes`
- `PaillierPublicKey::encrypt_bytes` / `PaillierPrivateKey::decrypt_bytes`
- `RabinPublicKey::encrypt_bytes` / `RabinPrivateKey::decrypt_bytes`
- `SchmidtSamoaPublicKey::encrypt_bytes` / `SchmidtSamoaPrivateKey::decrypt_bytes`

For the schemes whose native ciphertext is a bigint or a pair of bigints, these
helpers serialize the ciphertext into the same crate-defined binary framing used
throughout the non-RSA key formats.

## Public-Key Performance

> **Three rows stop at a time limit.** `elgamal_keygen_1024`,
> `dsa_keygen_1024` and `rsa_keygen_2048` search for primes, so their timing
> has a tail long enough that the 10% confidence target need never be reached.
> Each case stops after five minutes and is marked `(limit)`: its mean is of
> what was measured and its interval is as wide as the tail made it — ±31%,
> ±21% and ±22% of the mean after thousands of rounds.

Public-key timing is measured with [pilot-bench](https://github.com/darrelllong/pilot-bench)
driving `pilot_pk` through:

```text
bash scripts/bench_all_pk_full.sh
```

The publication-facing numbers below come from Pilot and report milliseconds
per operation, **90%** confidence-interval half-width, and rounds required to
hit the stop rule. The 2026-09-17 sweep was run with
`PILOT_PRESET=normal --confidence-level 0.90` (10% CI half-width target,
autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample size) and
`PILOT_SESSION_LIMIT=300`, one case at a time on each of:

- Intel Core i5-8259U (`dmz`, Linux, idle)
- Apple M1 (`tolkien`, macOS; no Mac is idle, and its background load is
  recorded with the run)
- Arm Cortex-X925 (`baase`, Linux, idle)
- Arm Cortex-A76 (`darby`, Raspberry Pi 5, Linux, idle)

This is the first sweep to post-date the audit round's rewrites, so the
`dsa_keygen` and `elgamal_keygen` rows include FIPS 186-4 domain-parameter
generation, the `ecies_*` rows measure SEC 1 §5.1, and the ML-KEM, ML-DSA,
NTRU and NTRUEncrypt rows are the clean-room implementations rather than what
preceded them. The raw per-host captures, the host notes and the merge
commands are in [bench/sweep-2026-09-17](bench/sweep-2026-09-17/README.md).

For RSA specifically, the timing gap between `encrypt`/`verify` and
`decrypt`/`sign` is still expected: the private side now uses CRT, but the
public side continues to benefit from the sparse default exponent
$e = 65{,}537$.

### Finite-field public key (1024-bit)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rsa_keygen_1024 | 43 | ±3.241 | 52 | 33.53 | ±2.681 | 50 | 20.42 | ±1.6 | 53 | 70.84 | ±4.538 | 50 |
| rsa_encrypt_1024 | 0.01624 | ±0.0001133 | 50 | 0.01209 | ±2.697e-05 | 144 | 0.009443 | ±0.0007801 | 89 | 0.03152 | ±3.491e-05 | 50 |
| rsa_decrypt_1024 | 0.2875 | ±0.001011 | 110 | 0.2277 | ±0.0005103 | 50 | 0.1321 | ±0.007622 | 50 | 0.5262 | ±0.002321 | 50 |
| rsa_sign_1024 | 0.2893 | ±0.001961 | 110 | 0.2272 | ±0.0005024 | 50 | 0.1281 | ±0.0002746 | 50 | 0.5287 | ±0.009559 | 50 |
| rsa_verify_1024 | 0.01627 | ±0.0001978 | 50 | 0.0119 | ±3.212e-05 | 111 | 0.008909 | ±4.995e-05 | 50 | 0.03129 | ±0.0002794 | 50 |
| elgamal_keygen_1024 | 58.21 | ±17.09 | 2327 (limit) | 38.74 | ±8.091 | 3638 (limit) | 30.32 | ±9.278 | 4245 (limit) | 101.6 | ±30.58 | 1243 (limit) |
| elgamal_encrypt_1024 | 0.2854 | ±0.00173 | 50 | 0.1794 | ±0.0002359 | 50 | 0.1495 | ±0.01058 | 200 | 0.5722 | ±0.0007027 | 50 |
| elgamal_decrypt_1024 | 0.2843 | ±0.004471 | 50 | 0.1749 | ±0.0005056 | 50 | 0.1478 | ±0.01229 | 54 | 0.5707 | ±0.001685 | 54 |
| dsa_keygen_1024 | 59.71 | ±9.344 | 1605 (limit) | 39.53 | ±9.132 | 2504 (limit) | 30.96 | ±6.551 | 2868 (limit) | 116.9 | ±25.46 | 831 (limit) |
| dsa_sign_1024 | 0.1518 | ±0.001521 | 80 | 0.09978 | ±0.002102 | 52 | 0.07792 | ±0.004707 | 50 | 0.299 | ±0.00222 | 51 |
| dsa_verify_1024 | 0.2857 | ±0.001529 | 80 | 0.1762 | ±0.0006772 | 50 | 0.1461 | ±0.01066 | 50 | 0.5752 | ±0.005124 | 55 |
| paillier_keygen_1024 | 38.14 | ±2.48 | 53 | 28.12 | ±0.92 | 57 | 19.78 | ±0.9909 | 53 | 66.52 | ±2.589 | 50 |
| paillier_encrypt_1024 | 3.983 | ±0.01101 | 87 | 2.445 | ±0.003191 | 80 | 2.188 | ±0.02521 | 50 | 8.256 | ±0.1483 | 50 |
| paillier_decrypt_1024 | 3.126 | ±0.0107 | 80 | 1.915 | ±0.01385 | 50 | 1.713 | ±0.04414 | 50 | 6.484 | ±0.09507 | 50 |
| paillier_rerandomize_1024 | 3.153 | ±0.009303 | 50 | 1.937 | ±0.005928 | 50 | 1.728 | ±0.003801 | 50 | 6.542 | ±0.09722 | 50 |
| paillier_add_1024 | 0.01016 | ±7.151e-05 | 50 | 0.006452 | ±6.372e-06 | 50 | 0.005912 | ±1.982e-05 | 80 | 0.02212 | ±0.0003873 | 50 |
| cocks_keygen_1024 | 34.5 | ±1.495 | 50 | 25.65 | ±1.018 | 50 | 17.6 | ±1.016 | 50 | 60.81 | ±2.081 | 50 |
| cocks_encrypt_1024 | 0.8586 | ±0.001719 | 260 | 0.5342 | ±0.001066 | 51 | 0.4296 | ±0.003012 | 50 | 1.736 | ±0.01881 | 50 |
| cocks_decrypt_1024 | 0.1344 | ±0.0003767 | 51 | 0.1066 | ±0.0003514 | 50 | 0.0576 | ±0.0003874 | 80 | 0.2464 | ±0.002794 | 50 |
| rabin_keygen_1024 | 47.68 | ±3.14 | 50 | 36.89 | ±2.782 | 80 | 25.82 | ±1.994 | 50 | 83.11 | ±5.58 | 82 |
| rabin_encrypt_1024 | 0.00429 | ±9.026e-05 | 80 | 0.003374 | ±1.705e-05 | 50 | 0.002482 | ±9.103e-05 | 80 | 0.008019 | ±0.0001483 | 140 |
| rabin_decrypt_1024 | 0.2806 | ±0.0009707 | 50 | 0.2215 | ±0.0004683 | 50 | 0.1239 | ±0.0002735 | 50 | 0.5188 | ±0.009001 | 50 |
| schmidt_samoa_keygen_1024 | 14.2 | ±0.4935 | 58 | 10.29 | ±0.3408 | 56 | 7.6 | ±0.5851 | 85 | 22.39 | ±0.7031 | 81 |
| schmidt_samoa_encrypt_1024 | 0.8561 | ±0.00254 | 50 | 0.5405 | ±0.0104 | 84 | 0.4522 | ±0.01941 | 50 | 1.725 | ±0.00316 | 50 |
| schmidt_samoa_decrypt_1024 | 0.3024 | ±0.01323 | 50 | 0.1903 | ±0.006931 | 80 | 0.1491 | ±0.007306 | 50 | 0.5693 | ±0.005995 | 50 |

### RSA (2048-bit)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rsa_keygen_2048 | 357.2 | ±73.98 | 850 (limit) | 206.3 | ±40.91 | 1350 (limit) | 179.3 | ±39.92 | 1626 (limit) | 652.7 | ±149.7 | 431 (limit) |
| rsa_encrypt_2048 | 0.05312 | ±0.0003177 | 170 | 0.03688 | ±0.0004508 | 148 | 0.0309 | ±4.758e-05 | 82 | 0.1099 | ±0.002679 | 50 |
| rsa_decrypt_2048 | 1.768 | ±0.003334 | 80 | 1.121 | ±0.00151 | 80 | 0.9003 | ±0.002201 | 50 | 3.578 | ±0.02131 | 50 |
| rsa_sign_2048 | 1.775 | ±0.01206 | 82 | 1.12 | ±0.001555 | 50 | 0.8998 | ±0.001308 | 85 | 3.573 | ±0.004182 | 50 |
| rsa_verify_2048 | 0.05248 | ±0.0004302 | 50 | 0.0362 | ±0.0004882 | 80 | 0.03042 | ±4.763e-05 | 50 | 0.1074 | ±0.0001115 | 110 |

### ECDSA / ECDH (P-256)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ecdsa_keygen | 0.9997 | ±0.009314 | 57 | 0.837 | ±0.0007773 | 140 | 0.4921 | ±0.01129 | 170 | 1.455 | ±0.02536 | 55 |
| ecdsa_sign | 1.003 | ±0.006963 | 85 | 0.8465 | ±0.002616 | 80 | 0.4939 | ±0.01299 | 140 | 1.444 | ±0.01255 | 50 |
| ecdsa_verify | 2.012 | ±0.0133 | 50 | 1.691 | ±0.009689 | 50 | 0.9684 | ±0.07068 | 50 | 2.915 | ±0.02458 | 50 |
| ecdh_keygen | 1.004 | ±0.01601 | 320 | 0.8375 | ±0.001055 | 50 | 0.4855 | ±0.03488 | 113 | 1.445 | ±0.01544 | 50 |
| ecdh_agree | 0.9902 | ±0.01081 | 50 | 0.8315 | ±0.002594 | 80 | 0.4786 | ±0.01194 | 50 | 1.44 | ±0.03039 | 50 |
| ecdh_serialize | 0.0001399 | ±8.228e-06 | 94 | 0.0001858 | ±9.469e-07 | 148 | 7.68e-05 | ±1.067e-06 | 140 | 0.0002236 | ±5.205e-06 | 50 |

### ECIES / EC ElGamal (P-256)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ecies_keygen | 1.006 | ±0.04803 | 140 | 0.8373 | ±0.0009133 | 110 | 0.4961 | ±0.01202 | 50 | 1.453 | ±0.0274 | 50 |
| ecies_encrypt | 1.962 | ±0.02617 | 80 | 1.668 | ±0.002696 | 173 | 0.9768 | ±0.02333 | 50 | 2.874 | ±0.04801 | 50 |
| ecies_decrypt | 0.9917 | ±0.00633 | 140 | 0.8392 | ±0.009481 | 50 | 0.505 | ±0.02291 | 50 | 1.435 | ±0.01021 | 50 |
| ec_elgamal_keygen | 0.995 | ±0.008908 | 178 | 0.8376 | ±0.001266 | 50 | 0.4906 | ±0.03389 | 50 | 1.446 | ±0.0203 | 51 |
| ec_elgamal_encrypt | 2.99 | ±0.01701 | 50 | 2.528 | ±0.008849 | 80 | 1.49 | ±0.07167 | 110 | 4.355 | ±0.03258 | 50 |
| ec_elgamal_decrypt | 2.912 | ±0.0163 | 50 | 2.472 | ±0.01183 | 50 | 1.414 | ±0.02652 | 110 | 4.236 | ±0.05458 | 50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ed25519_keygen | 0.4932 | ±0.002516 | 170 | 0.4515 | ±0.0004833 | 50 | 0.2683 | ±0.003251 | 80 | 0.8327 | ±0.01452 | 80 |
| ed25519_sign | 0.4889 | ±0.00157 | 112 | 0.4482 | ±0.001666 | 140 | 0.2636 | ±0.004634 | 260 | 0.8282 | ±0.009464 | 56 |
| ed25519_verify | 1.207 | ±0.04742 | 50 | 1.058 | ±0.007348 | 140 | 0.6503 | ±0.009822 | 54 | 1.979 | ±0.02374 | 50 |
| edwards_dh_keygen | 0.9782 | ±0.004717 | 53 | 0.8855 | ±0.001035 | 50 | 0.5239 | ±0.004858 | 110 | 1.648 | ±0.01029 | 50 |
| edwards_dh_agree | 0.4884 | ±0.002878 | 110 | 0.4459 | ±0.001948 | 50 | 0.2794 | ±0.02325 | 55 | 0.8296 | ±0.01354 | 50 |
| edwards_dh_serialize | 4.926e-05 | ±1.361e-06 | 50 | 4.33e-05 | ±1.548e-06 | 50 | 2.437e-05 | ±2.026e-06 | 123 | 6.336e-05 | ±1.487e-06 | 50 |
| edwards_elgamal_keygen | 0.9785 | ±0.004101 | 80 | 0.885 | ±0.0008794 | 80 | 0.5507 | ±0.01294 | 50 | 1.675 | ±0.04462 | 80 |
| edwards_elgamal_encrypt | 1.039 | ±0.004375 | 50 | 0.9495 | ±0.007062 | 50 | 0.6182 | ±0.05141 | 82 | 1.771 | ±0.03868 | 50 |
| edwards_elgamal_decrypt | 0.8457 | ±0.002579 | 85 | 0.7323 | ±0.0009783 | 80 | 0.4479 | ±0.01768 | 140 | 1.392 | ±0.01458 | 50 |

### X25519 / X448 (RFC 7748)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| x25519_keygen | 0.05353 | ±0.0001646 | 230 | 0.03554 | ±2.514e-06 | 80 | 0.02921 | ±0.002307 | 50 | 0.2193 | ±3.633e-05 | 200 |
| x25519_agree | 0.0534 | ±0.0002378 | 50 | 0.035 | ±2.191e-06 | 110 | 0.0283 | ±0.00163 | 260 | 0.2192 | ±0.002929 | 290 |
| x25519_scalar_mult_base | 0.05287 | ±0.0002485 | 80 | 0.035 | ±2.879e-06 | 80 | 0.02831 | ±0.001631 | 50 | 0.2193 | ±0.002479 | 50 |
| x25519_scalar_mult | 0.05305 | ±0.000246 | 80 | 0.035 | ±2.551e-06 | 89 | 0.02908 | ±0.002395 | 298 | 0.2185 | ±2.057e-05 | 50 |
| x448_keygen | 0.4211 | ±0.001211 | 110 | 0.2325 | ±4.865e-05 | 80 | 0.1972 | ±0.01283 | 59 | 1.076 | ±0.01134 | 80 |
| x448_agree | 0.4194 | ±0.001215 | 140 | 0.2318 | ±4.624e-05 | 80 | 0.1869 | ±0.0001616 | 1790 | 1.072 | ±0.0001152 | 230 |
| x448_scalar_mult_base | 0.4201 | ±0.002044 | 50 | 0.2318 | ±3.627e-05 | 110 | 0.1867 | ±0.0001127 | 290 | 1.075 | ±0.0118 | 140 |
| x448_scalar_mult | 0.4219 | ±0.001834 | 328 | 0.2319 | ±8.278e-05 | 50 | 0.1969 | ±0.01452 | 50 | 1.08 | ±0.0175 | 57 |

### ML-KEM (FIPS 203)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mlkem512_keygen | 0.1871 | ±0.0008895 | 82 | 0.08829 | ±6.326e-05 | 83 | 0.06768 | ±8.45e-05 | 80 | 0.2678 | ±0.0001713 | 80 |
| mlkem512_encaps | 0.04269 | ±0.0002437 | 80 | 0.01885 | ±7.105e-06 | 89 | 0.01405 | ±9.193e-05 | 380 | 0.05945 | ±0.0001419 | 50 |
| mlkem512_decaps | 0.05674 | ±0.0002279 | 200 | 0.02376 | ±1.705e-05 | 80 | 0.0183 | ±0.001454 | 230 | 0.0746 | ±0.0001208 | 204 |
| mlkem768_keygen | 0.3002 | ±0.001253 | 260 | 0.14 | ±0.0001843 | 110 | 0.1127 | ±0.007714 | 140 | 0.4271 | ±0.001196 | 50 |
| mlkem768_encaps | 0.06158 | ±0.0002377 | 140 | 0.02455 | ±9.881e-06 | 200 | 0.01863 | ±0.000168 | 170 | 0.07864 | ±0.0002274 | 174 |
| mlkem768_decaps | 0.07932 | ±0.0001851 | 80 | 0.03113 | ±1.166e-05 | 111 | 0.02464 | ±0.001892 | 82 | 0.09907 | ±0.0002195 | 50 |
| mlkem1024_keygen | 0.4507 | ±0.001826 | 80 | 0.2111 | ±0.0001812 | 80 | 0.1726 | ±0.01085 | 80 | 0.6492 | ±0.01782 | 50 |
| mlkem1024_encaps | 0.1082 | ±0.0006697 | 358 | 0.03195 | ±1.619e-05 | 238 | 0.02486 | ±0.002023 | 80 | 0.1297 | ±0.0007908 | 230 |
| mlkem1024_decaps | 0.1234 | ±0.0002595 | 80 | 0.0405 | ±2.208e-05 | 80 | 0.03143 | ±0.0002111 | 80 | 0.1288 | ±0.0003208 | 140 |

### ML-DSA (FIPS 204)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mldsa44_keygen | 0.1429 | ±0.0009877 | 119 | 0.06244 | ±5.137e-05 | 55 | 0.04558 | ±0.003758 | 89 | 0.2163 | ±0.0002564 | 83 |
| mldsa44_sign | 0.4862 | ±0.02274 | 50 | 0.1838 | ±0.006897 | 50 | 0.1595 | ±0.00639 | 170 | 0.7288 | ±0.03143 | 110 |
| mldsa44_verify | 0.0537 | ±0.0004983 | 88 | 0.02118 | ±2.543e-05 | 80 | 0.01765 | ±0.0002555 | 80 | 0.07575 | ±0.0002229 | 50 |
| mldsa65_keygen | 0.2559 | ±0.001288 | 80 | 0.1159 | ±9.602e-05 | 80 | 0.08235 | ±0.004982 | 85 | 0.385 | ±0.0004955 | 50 |
| mldsa65_sign | 0.7712 | ±0.03275 | 50 | 0.2902 | ±0.01529 | 81 | 0.2521 | ±0.01287 | 110 | 1.125 | ±0.05218 | 110 |
| mldsa65_verify | 0.07649 | ±0.0008272 | 80 | 0.02918 | ±2.876e-05 | 170 | 0.02471 | ±0.0002269 | 200 | 0.1052 | ±0.0003283 | 50 |
| mldsa87_keygen | 0.3972 | ±0.001913 | 50 | 0.1693 | ±0.0001286 | 140 | 0.1195 | ±0.00793 | 82 | 0.6127 | ±0.000744 | 80 |
| mldsa87_sign | 0.8101 | ±0.04629 | 80 | 0.3039 | ±0.01665 | 50 | 0.2602 | ±0.01361 | 80 | 1.18 | ±0.06751 | 80 |
| mldsa87_verify | 0.1162 | ±0.0003239 | 110 | 0.04249 | ±5.373e-05 | 80 | 0.036 | ±0.002789 | 110 | 0.1545 | ±0.0006319 | 146 |

### NTRU (NIST PQC round 3)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ntruhps509_keygen | 2.273 | ±0.006223 | 80 | 1.899 | ±0.001022 | 50 | 1.176 | ±0.03927 | 50 | 3.689 | ±0.04466 | 145 |
| ntruhps509_encaps | 0.1028 | ±0.002729 | 50 | 0.07319 | ±4.764e-05 | 80 | 0.04606 | ±0.000221 | 350 | 0.1439 | ±0.000243 | 620 |
| ntruhps509_decaps | 0.1668 | ±0.0005277 | 50 | 0.1285 | ±8.205e-05 | 50 | 0.08181 | ±0.005714 | 380 | 0.2577 | ±0.0004326 | 80 |
| ntruhps677_keygen | 2.178 | ±0.009497 | 110 | 1.227 | ±0.001081 | 58 | 1.04 | ±0.0004504 | 80 | 3.333 | ±0.0004348 | 80 |
| ntruhps677_encaps | 0.1383 | ±0.001108 | 116 | 0.08563 | ±8.291e-05 | 290 | 0.06004 | ±0.004047 | 50 | 0.1922 | ±0.0003309 | 620 |
| ntruhps677_decaps | 0.1757 | ±0.00322 | 110 | 0.09114 | ±9.64e-05 | 80 | 0.08065 | ±0.006574 | 140 | 0.2595 | ±0.0003151 | 50 |
| ntruhps821_keygen | 3.778 | ±0.0137 | 290 | 3.629 | ±0.00147 | 50 | 1.885 | ±0.1254 | 50 | 5.977 | ±0.002638 | 115 |
| ntruhps821_encaps | 0.1809 | ±0.001215 | 56 | 0.144 | ±7.791e-05 | 1161 | 0.07959 | ±0.0003806 | 350 | 0.2567 | ±0.00046 | 85 |
| ntruhps821_decaps | 0.2886 | ±0.01354 | 50 | 0.2552 | ±7.016e-05 | 260 | 0.1324 | ±0.00816 | 593 | 0.4345 | ±0.001431 | 50 |
| ntruhrss701_keygen | 2.594 | ±0.007373 | 143 | 1.432 | ±0.0008151 | 50 | 1.263 | ±0.001043 | 230 | 4.035 | ±0.001072 | 50 |
| ntruhrss701_encaps | 0.08754 | ±0.0007937 | 412 | 0.0462 | ±4.588e-05 | 200 | 0.04117 | ±0.002256 | 200 | 0.1248 | ±0.0003064 | 50 |
| ntruhrss701_decaps | 0.1988 | ±0.001434 | 80 | 0.1037 | ±9.147e-05 | 80 | 0.09187 | ±0.005147 | 170 | 0.2985 | ±0.0002326 | 110 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ntruees401ep1_keygen | 0.6887 | ±0.001179 | 175 | 0.5246 | ±0.0004164 | 50 | 0.3487 | ±0.01619 | 200 | 0.8404 | ±0.001428 | 52 |
| ntruees401ep1_encrypt | 0.1859 | ±0.006327 | 50 | 0.07951 | ±0.002991 | 50 | 0.0585 | ±0.004474 | 80 | 0.1745 | ±0.005168 | 50 |
| ntruees401ep1_decrypt | 0.2731 | ±0.008649 | 141 | 0.1275 | ±0.0001506 | 80 | 0.09865 | ±0.007037 | 80 | 0.2877 | ±0.0006532 | 50 |
| ntruees443ep1_keygen | 0.6744 | ±0.001221 | 81 | 0.5126 | ±0.0003972 | 54 | 0.3319 | ±0.0003822 | 110 | 0.8674 | ±0.0008467 | 55 |
| ntruees443ep1_encrypt | 0.03703 | ±0.0002395 | 50 | 0.02425 | ±0.0001174 | 50 | 0.0171 | ±0.0002855 | 115 | 0.04812 | ±0.000345 | 51 |
| ntruees443ep1_decrypt | 0.06392 | ±0.0005043 | 50 | 0.0354 | ±8.65e-05 | 80 | 0.02665 | ±0.002204 | 388 | 0.07573 | ±0.0004536 | 50 |
| ntruees449ep1_keygen | 0.9161 | ±0.001308 | 80 | 0.6229 | ±0.0005313 | 530 | 0.441 | ±0.03344 | 50 | 1.046 | ±0.001349 | 80 |
| ntruees449ep1_encrypt | 0.1897 | ±0.01125 | 50 | 0.1152 | ±0.007062 | 50 | 0.08333 | ±0.005972 | 200 | 0.2541 | ±0.01469 | 50 |
| ntruees449ep1_decrypt | 0.2983 | ±0.001335 | 140 | 0.1644 | ±0.0001591 | 350 | 0.121 | ±0.006894 | 50 | 0.3814 | ±0.001281 | 110 |
| ntruees541ep1_keygen | 0.6865 | ±0.001502 | 81 | 0.438 | ±0.0004614 | 88 | 0.4069 | ±0.02818 | 176 | 0.7641 | ±0.001555 | 50 |
| ntruees541ep1_encrypt | 0.07362 | ±0.0004721 | 171 | 0.04595 | ±5.644e-05 | 114 | 0.03321 | ±0.001745 | 86 | 0.1028 | ±0.0004595 | 230 |
| ntruees541ep1_decrypt | 0.1631 | ±0.001077 | 50 | 0.0765 | ±0.0001244 | 110 | 0.05759 | ±0.004498 | 50 | 0.1777 | ±0.001108 | 50 |
| ntruees677ep1_keygen | 1.201 | ±0.001724 | 50 | 0.7067 | ±0.0004068 | 111 | 0.6008 | ±0.04595 | 230 | 1.433 | ±0.001552 | 140 |
| ntruees677ep1_encrypt | 0.2973 | ±0.0008163 | 200 | 0.1475 | ±0.0001222 | 85 | 0.1052 | ±0.00866 | 115 | 0.3513 | ±0.0005818 | 80 |
| ntruees677ep1_decrypt | 0.5705 | ±0.00425 | 170 | 0.2684 | ±0.0002338 | 56 | 0.2185 | ±0.01801 | 202 | 0.6391 | ±0.001865 | 50 |
| ntruees1087ep1_keygen | 1.516 | ±0.006869 | 110 | 0.9854 | ±0.00113 | 80 | 1.171 | ±0.09561 | 80 | 1.801 | ±0.002088 | 110 |
| ntruees1087ep1_encrypt | 0.1931 | ±0.002727 | 53 | 0.09963 | ±8.105e-05 | 80 | 0.07491 | ±0.00362 | 178 | 0.2237 | ±0.001594 | 80 |
| ntruees1087ep1_decrypt | 0.3882 | ±0.003003 | 50 | 0.1936 | ±0.0005642 | 50 | 0.1352 | ±0.007618 | 170 | 0.4255 | ±0.001437 | 80 |
| ntruees1087ep2_keygen | 1.638 | ±0.005439 | 170 | 1.043 | ±0.002625 | 50 | 1.033 | ±0.0843 | 56 | 1.897 | ±0.00293 | 84 |
| ntruees1087ep2_encrypt | 0.3456 | ±0.002335 | 54 | 0.1755 | ±0.0001843 | 50 | 0.1359 | ±0.01081 | 200 | 0.3984 | ±0.00244 | 50 |
| ntruees1087ep2_decrypt | 0.7466 | ±0.003554 | 50 | 0.3552 | ±0.0007278 | 110 | 0.2521 | ±0.01964 | 80 | 0.7834 | ±0.002712 | 80 |
| ntruees1171ep1_keygen | 1.882 | ±0.01217 | 50 | 1.114 | ±0.001566 | 140 | 1.041 | ±0.06569 | 110 | 2.254 | ±0.002825 | 1250 |
| ntruees1171ep1_encrypt | 0.3446 | ±0.001458 | 80 | 0.1685 | ±0.0002223 | 50 | 0.1354 | ±0.006482 | 140 | 0.4011 | ±0.003179 | 80 |
| ntruees1171ep1_decrypt | 0.7648 | ±0.004506 | 50 | 0.3112 | ±0.0004232 | 50 | 0.2515 | ±0.02092 | 81 | 0.7468 | ±0.003089 | 57 |
| ntruees1499ep1_keygen | 3.138 | ±0.03615 | 140 | 1.771 | ±0.001282 | 110 | 1.548 | ±0.06714 | 143 | 4.254 | ±0.005327 | 51 |
| ntruees1499ep1_encrypt | 0.3272 | ±0.007406 | 50 | 0.1629 | ±0.0002058 | 50 | 0.1307 | ±0.00626 | 80 | 0.3812 | ±0.00372 | 50 |
| ntruees1499ep1_decrypt | 0.5475 | ±0.004155 | 170 | 0.3071 | ±0.0003582 | 86 | 0.2431 | ±0.02006 | 599 | 0.6982 | ±0.002581 | 83 |


Cross-platform summary Kiviat diagrams (radar charts; log-radial ops/sec
axis, outer ring = faster):

![RSA / DSA / EC ops/sec Kiviat (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-pk-rsa-ec-radar.svg)

![Post-quantum ops/sec Kiviat — ML-KEM / ML-DSA / NTRU (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-pk-pq-radar.svg)

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
- Keep an eye on 2048-bit and larger timings; the `rump` bigint backend is
  respectable but not a tuned industrial multiprecision library. The policy
  shared by both crates is to keep the arithmetic kernels pure Rust.

## References

The primary public-key papers and standards are stored in `pubs/`. The BibTeX
index is in [README.md](README.md).
