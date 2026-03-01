//! Public-key building blocks.
//!
//! This module starts with the arithmetic foundation needed by the public-key
//! schemes in the companion Python repository: a simple limb-based bigint
//! representation plus primality and modular-arithmetic helpers. The goal is
//! fidelity to the hand-written algorithms, not a replacement for industrial
//! multiprecision libraries.

pub mod bigint;
pub mod cocks;
pub mod primes;
