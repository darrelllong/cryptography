//! Public-key building blocks.
//!
//! This module starts with the arithmetic foundation needed by the public-key
//! schemes in the companion Python repository: a simple limb-based bigint
//! representation, a reusable Montgomery toolkit, plus primality and
//! modular-arithmetic helpers. The goal is fidelity to the hand-written
//! algorithms, not a replacement for industrial multiprecision libraries.
//!
//! The arithmetic primitives remain directly accessible, and the wrapper layer
//! now adds:
//! - `rsa_pkcs1` for OAEP encryption and PSS signatures
//! - `rsa_io` for standard RSA key serialization (`PKCS #1`, `PKCS #8`,
//!   `SPKI`) plus an optional flat XML export for symmetry with the other
//!   schemes
//! - internal `io` helpers for the crate-defined non-RSA key formats: a DER
//!   `SEQUENCE` of positive `INTEGER`s, custom PEM armor, and the shared flat
//!   XML form

pub mod bigint;
pub mod cocks;
pub mod elgamal;
mod io;
pub mod paillier;
pub mod primes;
pub mod rabin;
pub mod rsa;
pub mod rsa_io;
pub mod rsa_pkcs1;
pub mod schmidt_samoa;
