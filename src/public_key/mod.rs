//! Public-key building blocks.
//!
//! This module starts with the arithmetic foundation needed by the public-key
//! schemes in the companion Python repository: a simple limb-based bigint
//! representation, a reusable Montgomery toolkit, plus primality and
//! modular-arithmetic helpers. The goal is fidelity to the hand-written
//! algorithms, not a replacement for industrial multiprecision libraries.
//!
//! The raw schemes remain available directly, and RSA now also has a
//! standards-facing wrapper layer in `rsa_pkcs1` for OAEP encryption and PSS
//! signatures.

pub mod bigint;
pub mod cocks;
pub mod elgamal;
pub mod paillier;
pub mod primes;
pub mod rabin;
pub mod rsa;
pub mod rsa_pkcs1;
pub mod schmidt_samoa;
