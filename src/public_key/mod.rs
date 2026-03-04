//! Public-key building blocks.
//!
//! This module starts with the arithmetic foundation needed by the public-key
//! schemes here: a simple limb-based bigint representation, a reusable
//! Montgomery toolkit, plus primality and modular-arithmetic helpers. The goal
//! is fidelity to the published arithmetic in pure idiomatic Rust, not a
//! replacement for industrial multiprecision libraries or a wrapper around
//! external C code.
//!
//! The public-key APIs are layered, but not every scheme exposes every layer
//! with the same shape:
//! - arithmetic maps such as `encrypt_raw`, `encrypt_with_nonce`,
//!   `encrypt_point_with_k`, or `sign_with_k`
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
//! - internal `io` helpers for the crate-defined non-RSA key formats: a DER
//!   `SEQUENCE` of positive `INTEGER`s, custom PEM armor, and the shared flat
//!   XML form
//!
//! For new APIs, keep the naming consistent even when legacy methods remain:
//! - prefer `*_with_nonce` for deterministic/external-randomness entry points
//! - prefer `to_wire_bytes` / `from_wire_bytes` for standard compact encodings
//!   that omit curve or algorithm parameters
//! - prefer `to_key_blob` / `from_key_blob` for crate-defined self-describing
//!   binary formats
//! - keep legacy `to_binary` / `from_binary` as compatibility aliases where
//!   they already exist
//!
//! This follows the crate-wide design rule: keep the implementation in Rust,
//! avoid intrinsics and FFI, and add dependencies only where they materially
//! improve interoperability or maintenance.

pub mod bigint;
pub mod cocks;
pub mod dh;
pub mod dsa;
pub mod ec;
pub mod ec_edwards;
pub mod ec_elgamal;
pub mod ecdh;
pub mod ecdsa;
pub mod ecies;
pub mod ed25519;
pub mod eddsa;
pub mod edwards_dh;
pub mod edwards_elgamal;
pub mod elgamal;
mod gf2m;
mod io;
pub mod paillier;
pub mod primes;
pub mod rabin;
pub mod rsa;
pub mod rsa_io;
pub mod rsa_pkcs1;
pub mod schmidt_samoa;
