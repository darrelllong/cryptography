//! Public-key building blocks.
//!
//! This module starts with the arithmetic foundation needed by the public-key
//! schemes in the companion Python repository: a simple limb-based bigint
//! representation, a reusable Montgomery toolkit, plus primality and
//! modular-arithmetic helpers. The goal is fidelity to the hand-written
//! algorithms, not a replacement for industrial multiprecision libraries.
//!
//! The raw schemes remain available directly, and RSA now also has
//! standards-facing layers:
//! - `rsa_pkcs1` for OAEP encryption and PSS signatures
//! - `rsa_io` for PKCS #8 / SPKI key serialization
//! - internal `io` helpers for the crate-defined binary / PEM key format used
//!   by the non-RSA public-key schemes

pub mod bigint;
pub mod cocks;
pub mod elgamal;
mod io;
pub mod paillier;
pub mod primes;
pub mod rabin;
pub mod rsa;
pub mod rsa_pkcs1;
pub mod rsa_io;
pub mod schmidt_samoa;
