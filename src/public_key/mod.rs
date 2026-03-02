//! Public-key building blocks.
//!
//! This module starts with the arithmetic foundation needed by the public-key
//! schemes here: a simple limb-based bigint representation, a reusable
//! Montgomery toolkit, plus primality and modular-arithmetic helpers. The goal
//! is fidelity to the published arithmetic in pure idiomatic Rust, not a
//! replacement for industrial multiprecision libraries or a wrapper around
//! external C code.
//!
//! The public-key APIs are intentionally layered:
//! - arithmetic maps such as `encrypt_raw` / `decrypt_raw`
//! - typed wrappers such as `encrypt` / `decrypt`, which return the
//!   scheme-native ciphertext representation
//! - byte wrappers such as `encrypt_bytes` / `decrypt_bytes`, which serialize
//!   ciphertexts so callers can work directly with byte strings
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
//! This follows the crate-wide design rule: keep the implementation in Rust,
//! avoid intrinsics and FFI, and add dependencies only where they materially
//! improve interoperability or maintenance.

pub mod bigint;
pub mod cocks;
pub mod dsa;
pub mod elgamal;
mod io;
pub mod paillier;
pub mod primes;
pub mod rabin;
pub mod rsa;
pub mod rsa_io;
pub mod rsa_pkcs1;
pub mod schmidt_samoa;
