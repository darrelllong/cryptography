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

> **Stale figures (2026-09-10).** Several tables below predate changes made on
> 2026-09-10 and have not been re-swept. The `dsa_keygen` and `elgamal_keygen`
> workloads now include FIPS 186-4 domain-parameter generation. The `ecies_*`
> rows measure the former construction, not SEC 1 §5.1. X25519 uses a rewritten
> field inversion. The ML-KEM, ML-DSA, NTRU, and NTRUEncrypt rows predate the
> clean-room rewrites; on the development machine those made ML-KEM-768
> 1.38–1.73× slower, ML-DSA-65 signing 1.30× slower, and NTRU round-3 key
> generation about 2× slower.

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

The `ecies_*` rows predate the SEC 1 §5.1 rewrite and measure the former
AES-256-GCM construction; the next sweep measures `EciesSetup::RECOMMENDED`.

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
- Keep an eye on 2048-bit and larger timings; the `rump` bigint backend is
  respectable but not a tuned industrial multiprecision library. The policy
  shared by both crates is to keep the arithmetic kernels pure Rust.

## References

The primary public-key papers and standards are stored in `pubs/`. The BibTeX
index is in [README.md](README.md).
