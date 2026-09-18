//! Public-key building blocks.
//!
//! The multiprecision arithmetic under these schemes — limb-based big
//! integers, the Montgomery toolkit, and the deterministic number theory —
//! lives in the sibling [`rump`] crate (re-exported through [`crate::vt`]);
//! this module keeps the cryptographic policy layered on top of it. The goal
//! is fidelity to the published arithmetic in pure idiomatic Rust, not a
//! replacement for industrial multiprecision libraries or a wrapper around
//! external C code.
//!
//! The public-key APIs are layered, but not every scheme exposes every layer
//! with the same shape:
//! - arithmetic maps such as `encrypt_raw`, `encrypt_with_nonce`,
//!   `encrypt_point_with_nonce`, or `sign_digest_with_nonce`
//! - typed wrappers such as `encrypt`, `decrypt`, `sign_message`, and
//!   `verify_message`, which operate on the scheme's natural plaintext,
//!   ciphertext, or signature representation
//! - byte wrappers such as `encrypt_bytes`, `decrypt_bytes`,
//!   `verify_message_bytes`, standard wire encodings, and crate-defined key
//!   blobs
//!
//! The important design rule is that the math stays visible. The exact method
//! set depends on what the underlying construction naturally supports:
//! signature schemes do not grow encryption wrappers, key-agreement schemes do
//! not pretend to be byte-to-byte encryption APIs, and schemes such as `ECIES`
//! intentionally present a direct byte-oriented wrapper because the primitive
//! is already hybrid encryption.
//!
//! The arithmetic primitives remain directly accessible, and the wrapper layer
//! adds:
//! - `rsa_pkcs1` for OAEP encryption and PSS signatures
//! - `rsa_io` for standard RSA key serialization (`PKCS #1`, `PKCS #8`,
//!   `SPKI`) plus an optional flat XML export for symmetry with the other
//!   schemes
//! - internal `pkix` containers under every standard key encoding: RFC 5280
//!   `SubjectPublicKeyInfo`, RFC 5958 `OneAsymmetricKey` (PKCS #8), and the
//!   RFC 7468 textual encoding
//! - internal `io` helpers for the crate-defined non-RSA key formats: a DER
//!   `SEQUENCE` of positive `INTEGER`s, custom PEM armor, and the shared flat
//!   XML form
//!
//! Public-key naming is normalized crate-wide:
//! - prefer `*_with_nonce` for deterministic/external-randomness entry points
//! - prefer `to_wire_bytes` / `from_wire_bytes` for standard compact encodings
//!   that omit curve or algorithm parameters
//! - prefer `to_key_blob` / `from_key_blob` for crate-defined schema-shaped
//!   binary formats (the PEM label or XML root tag names the type); the same
//!   pair names the crate-defined blob of a signature or ciphertext, since the
//!   framing is identical and the type, not the method, says what it holds
//! - prefer `to_der` / `from_der` where a standard names the DER structure
//!   (`EcdsaSignature` and `DsaSignature` are the X9.62 / RFC 3279
//!   `Dss-Sig-Value` and RFC 3279 §2.2.3 `ECDSA-Sig-Value`)
//!
//! ## Parse-time validation policy
//!
//! Every parser — `from_key_blob`, `from_pem`, `from_xml`, and the standard
//! containers (SPKI, PKCS #8, SEC 1, PKCS #1) — validates before it returns a
//! key, and the amount of work depends only on whether the material is private
//! or public:
//!
//! Every finite-field group modulus and subgroup order is size-checked
//! (`q ≥ 2^15`, `p ≤ 16 384` bits, `q ≤ 512` bits) before any primality test
//! runs, so a blob cannot buy arbitrary work.
//!
//! - **Private keys are validated completely.** Every prime the blob carries
//!   passes the hash-hardened Miller-Rabin test
//!   ([`primes::is_probable_prime_untrusted`]), the scheme's algebraic
//!   relations are checked (`n = p·q`, Rabin `p ≡ q ≡ 3 (mod 4)`, RSA CRT
//!   exponents and coefficient, `q | p − 1` and `g^q ≡ 1`, exponent ranges),
//!   and derived values are recomputed rather than trusted. A blob that omits
//!   the primes (Cocks `[pi, q]`, Paillier `[n, lambda, u]`, Schmidt-Samoa
//!   `[d, gamma]`) is checked for the internal consistency its fields allow,
//!   documented on each `from_serial_fields`.
//! - **Public keys are validated structurally.** Ranges (`1 < y < p`,
//!   `3 ≤ e < n`), parity and size constraints, subgroup membership where a
//!   prime-order subgroup exists (`y^q ≡ 1 (mod p)` for DSA and DH), and one
//!   fixed-base primality test per public prime
//!   ([`rump::number_theory::is_probable_prime`]). The hardened test is not
//!   used on public parameters: a forged pseudoprime in someone else's
//!   public key weakens only that key, while re-running 76 modular
//!   exponentiations on every load would make key parsing an amplification
//!   vector.
//! - **Groups this crate will generate a key pair over are validated as
//!   private material.** `DhParams` and `DsaParams` are the public-looking
//!   types that take the hardened test, and FIPS 186-4 A.1.1.3 and A.2.4 when
//!   the domain-parameter seed is present: a composite modulus that fools fixed
//!   bases splits `Z_p^*` by the Chinese remainder theorem into components
//!   modulo its smaller prime factors, where the discrete logarithm of *our*
//!   freshly generated secret is far cheaper. `DhPublicKey::params` and `DsaPublicKey::params` therefore re-validate
//!   under that rule before handing out parameters.
//!
//! Every check has a negative test in its module: a tampered blob that must
//! fail to parse.
//!
//! This follows the crate-wide design rule: keep the implementation in Rust,
//! avoid intrinsics and FFI, and add dependencies only where they materially
//! improve interoperability or maintenance.

pub mod cocks;
mod curve_pkix;
pub mod dh;
pub mod dsa;
pub mod ec;
pub mod ec_edwards;
pub mod ec_elgamal;
mod ec_io;
mod ec_pkix;
pub mod ecdh;
pub mod ecdsa;
mod ed25519_group;

/// The field of `2^255 - 19`, shared by the X25519 ladder and edwards25519.
mod fe25519;

/// Arithmetic modulo the order of edwards25519's prime-order subgroup.
mod sc25519;

pub mod ecies;
pub mod ed25519;
pub mod eddsa;
pub mod edwards_dh;
pub mod edwards_elgamal;
pub mod elgamal;
mod ffc_pkix;
pub mod hpke;
mod io;
pub mod ml_dsa;
pub mod ml_kem;
mod ml_pkix;
pub(crate) mod ntru_ees1087ep1;
pub(crate) mod ntru_ees1087ep2;
pub(crate) mod ntru_ees1171ep1;
pub(crate) mod ntru_ees1499ep1;
pub(crate) mod ntru_ees401ep1;
pub(crate) mod ntru_ees443ep1;
pub(crate) mod ntru_ees449ep1;
pub(crate) mod ntru_ees541ep1;
pub(crate) mod ntru_ees677ep1;
pub(crate) mod ntru_ees_core;
pub(crate) mod ntru_hps509;
pub(crate) mod ntru_hps677;
pub(crate) mod ntru_hps821;
pub(crate) mod ntru_hrss701;
mod ntru_poly_mul;
mod ntru_pqc_shared;
pub mod paillier;
mod pkix;
pub mod primes;
pub mod rabin;
mod rfc6979;
pub mod rsa;
pub mod rsa_io;
pub mod rsa_pkcs1;
pub mod schmidt_samoa;
pub mod x25519;
pub mod x448;
