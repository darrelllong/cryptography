# public_key

Public-key cryptography written from the published specifications in pure
Rust: classical schemes over the integers, elliptic-curve schemes in
short-Weierstrass, twisted-Edwards and Montgomery form, lattice schemes, and
the PKIX layer that carries every family's keys in the standard containers.

Multiprecision arithmetic (`BigUint`, `BigInt`, Montgomery contexts and
residues, GF(2^m)) comes from the sibling
[rump](https://github.com/darrelllong/rump) crate; this directory holds only
the arithmetic that is specific to a scheme.

## Timing

The `crate::vt` namespace, through which these types are exported, is a
label, not a gate: it states that a type's secret-key operations are to be
assumed variable-time, and nothing in it changes how a type runs. Two groups
sit under the label.

Variable-time, and documented as such: RSA, DSA, Diffie-Hellman, ElGamal,
Paillier, Rabin, Cocks and Schmidt-Samoa run `rump` big-integer arithmetic
whose timing depends on the operands; every Weierstrass and Edwards scheme
(ECDSA, ECDH, EC-ElGamal, ECIES, Ed25519, EdDSA, Edwards DH and ElGamal) runs
curve arithmetic on the same numbers; the NTRUEncrypt SVES-3 parameter sets
run their ring arithmetic the same way.

Written to keep secret-dependent branches, table indices and divisions out of
their secret-key operations, each stating the extent of it in its own module
documentation:

- `x25519.rs` and `x448.rs`: fixed-radix limbs (5×51 and 8×56 bits) and a
  mask-driven conditional swap in the RFC 7748 Montgomery ladder.
- `ml_kem.rs`: data-independent arithmetic on the secret polynomials, and
  decapsulation, including the implicit-rejection selection, by masks.
- `ml_dsa.rs`: data-independent arithmetic on the secret values, masked
  rejection tests and hint counting, `sample_in_ball` by masked scans, and
  the same work on every signing attempt whichever rejection test fails; the
  rejection sampling FIPS 204 itself specifies with data-dependent loops
  stays as specified.
- The round-3 NTRU KEMs (`ntru_hps*.rs`, `ntru_hrss701.rs`): the
  constant-time sort of the specification's §1.10.5 and masked integer
  helpers.
- Private keys of ML-KEM, ML-DSA, X448 and the Ed25519 seed compare in
  constant time, so `==` on a private key does not leak where two keys
  differ. Ed25519's arithmetic is still the variable-time Edwards arithmetic.

## PKIX layer

Every family's keys travel in the same standard containers, built and
checked by one set of modules.

| File | Contents |
|------|----------|
| `pkix.rs` | `AlgorithmIdentifier` (RFC 5280 §4.1.1.2), `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7), `OneAsymmetricKey` / PKCS #8 `PrivateKeyInfo` (RFC 5958 §2, RFC 5208 §5), compile-time `ObjectIdentifier`s, the RFC 7468 `PUBLIC KEY` and `PRIVATE KEY` text forms, and the BER receivers RFC 5958 §2 and RFC 7468 §10 and §13 require, which bring any BER encoding of a container to DER in front of the strict decoders |
| `io.rs` | The strict X.690 DER reader and encoders; the BER-to-DER converter; the RFC 7468 §2 text parser and RFC 4648 §4 base64; the crate-defined `SEQUENCE OF INTEGER` blob and flat XML form and the macros that derive `to_key_blob` / `from_key_blob` / `to_pem` / `from_pem` / `to_xml` / `from_xml` from a schema |
| `rsa_io.rs` | RSA in PKCS #1 (`RSAPublicKey`, `RSAPrivateKey`), PKCS #8 and `SubjectPublicKeyInfo` under `rsaEncryption` |
| `ec_pkix.rs` | Short-Weierstrass keys: `SubjectPublicKeyInfo` under `id-ecPublicKey` / `id-ecDH` with `namedCurve` (RFC 5480), RFC 5915 `ECPrivateKey` alone and inside `OneAsymmetricKey`, shared by ECDSA, ECDH, EC-ElGamal and ECIES |
| `ec_io.rs` | The crate-defined blob, PEM and XML encodings of short-Weierstrass keys, shared by the same four schemes |
| `ffc_pkix.rs` | DSA under `id-dsa` with `Dss-Parms`, Diffie-Hellman under `dhpublicnumber` with `DomainParameters` (RFC 3279 §2.3.2, §2.3.3), in `SubjectPublicKeyInfo` and `OneAsymmetricKey` |
| `curve_pkix.rs` | X25519, X448 and Ed25519 under RFC 8410: the key bytes themselves in the BIT STRING, `CurvePrivateKey` in the OCTET STRING, the optional version 2 public key |
| `ml_pkix.rs` | The private-key `CHOICE` (seed, expanded key, or both) of ML-KEM (RFC 9935 §6) and ML-DSA (RFC 9881 §6) |
| `rfc6979.rs` | Deterministic nonce derivation shared by DSA and ECDSA (RFC 6979 §3.2), with the `bits2int` rule of §2.3.2 |

Decoders named for DER accept strict DER only. Where a standard requires a
receiver to accept BER, a `*_ber` entry point or the text decoder converts
first and the DER decoder then reads the result, so BER support adds nothing
inside the strict parsers. Which key contents an algorithm's specification
itself requires in DER, and are therefore left alone by the converter, is
tabulated in `pkix.rs`.

## Arithmetic policy

| File | Purpose |
|------|---------|
| `primes.rs` | Cryptographic policy over `rump`'s number theory: the SHAKE256-hardened primality test for untrusted inputs, DSA-style group construction, and the CSPRNG bridge to `rump::random::RandomSource` |

## Classical schemes

| File | Scheme | Specification |
|------|--------|---------------|
| `rsa.rs` | RSA primitive with CRT decryption | RFC 8017 |
| `rsa_pkcs1.rs` | RSAES-OAEP and RSASSA-PSS | RFC 8017 |
| `dh.rs` | Finite-field Diffie-Hellman over a prime-order subgroup | NIST SP 800-56A |
| `dsa.rs` | DSA with FIPS 186-4 Appendix A domain parameters | FIPS 186-4 |
| `elgamal.rs` | ElGamal encryption over a prime-order group | ElGamal 1985 |
| `cocks.rs` | Cocks's non-secret encryption | Cocks 1973 |
| `paillier.rs` | Paillier additively homomorphic encryption | Paillier 1999 |
| `rabin.rs` | Rabin encryption | Rabin 1979 |
| `schmidt_samoa.rs` | Schmidt-Samoa encryption | Schmidt-Samoa 2005 |

## Short-Weierstrass curves

| File | Contents |
|------|----------|
| `ec.rs` | Prime-field and binary-field curve arithmetic, Jacobian ladders on Montgomery residues; NIST P-192/224/256/384/521, secp256k1, and the binary curves B-163…B-571 and K-163…K-571 |
| `ecdsa.rs` | ECDSA (FIPS 186-5), with RFC 6979 nonces |
| `ecdh.rs` | Elliptic-curve Diffie-Hellman |
| `ec_elgamal.rs` | ElGamal encryption over a curve group |
| `ecies.rs` | ECIES (SEC 1 v2.0 §5.1) |

## Twisted Edwards curves

| File | Contents |
|------|----------|
| `ec_edwards.rs` | Twisted Edwards arithmetic over prime fields, with the general-`a` addition law and fixed-base tables |
| `ed25519.rs` | Ed25519 (RFC 8032) |
| `eddsa.rs` | EdDSA-style signatures over any twisted Edwards curve |
| `edwards_dh.rs` | Diffie-Hellman over twisted Edwards curves |
| `edwards_elgamal.rs` | ElGamal encryption over twisted Edwards curves |

## Montgomery curves

| File | Contents |
|------|----------|
| `x25519.rs` | X25519 (RFC 7748 §5) |
| `x448.rs` | X448 (RFC 7748 §5) |

## Lattice schemes

| File | Contents |
|------|----------|
| `ml_kem.rs` | ML-KEM-512/768/1024 (FIPS 203) |
| `ml_dsa.rs` | ML-DSA-44/65/87 (FIPS 204) |
| `ntru_pqc_shared.rs` | The round-3 NTRU KEM shared by its four parameter sets: sampling, packing, the constant-time sort, encapsulation and decapsulation |
| `ntru_poly_mul.rs` | Polynomial multiplication shared by the NTRU KEM modules |
| `ntru_hps509.rs`, `ntru_hps677.rs`, `ntru_hps821.rs`, `ntru_hrss701.rs` | ntruhps2048509, ntruhps2048677, ntruhps4096821, ntruhrss701 |
| `ntru_ees_core.rs` | NTRUEncrypt SVES-3 (IEEE Std 1363.1-2008, ANSI X9.98), shared by the nine parameter-set modules |
| `ntru_ees401ep1.rs`, `ntru_ees443ep1.rs`, `ntru_ees449ep1.rs`, `ntru_ees541ep1.rs`, `ntru_ees677ep1.rs`, `ntru_ees1087ep1.rs`, `ntru_ees1087ep2.rs`, `ntru_ees1171ep1.rs`, `ntru_ees1499ep1.rs` | One `define_ees_set!` invocation each, binding the parameter constants and the ring degree |

## Naming conventions

- `*_with_nonce` — a deterministic entry point that takes its randomness
  from the caller.
- `to_wire_bytes` / `from_wire_bytes` — the compact encoding a scheme's own
  specification defines, without algorithm parameters.
- `to_key_blob` / `from_key_blob`, `to_pem` / `from_pem`, `to_xml` /
  `from_xml` — the crate-defined encodings of `io.rs`, positional and
  schema-shaped; the PEM label and the XML root tag name the type.
- `to_spki_der` / `from_spki_der`, `to_pkcs8_der` / `from_pkcs8_der`,
  `from_pkcs8_ber`, `to_spki_pem` / `from_spki_pem`, `to_pkcs8_pem` /
  `from_pkcs8_pem` — the PKIX containers, for every family that has a
  registered algorithm identifier.
- `to_sec1_der` / `from_sec1_der` / `from_sec1_ber` / `from_sec1_pem` and
  the PKCS #1 `to_pkcs1_*` / `from_pkcs1_*` — the bare key structures of
  RFC 5915 and RFC 8017.
