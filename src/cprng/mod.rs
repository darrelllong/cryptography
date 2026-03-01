//! Cryptographically motivated pseudorandom generators and DRBGs.
//!
//! This module includes both historical reference constructions
//! (`BlumBlumShub`, `BlumMicali`) and a modern standardized generator
//! (`CtrDrbgAes256` from NIST SP 800-90A Rev. 1).
//!
//! `BlumBlumShub` and `BlumMicali` are intentionally small, `u128`-bounded
//! toy/reference implementations for study and experimentation. They are not
//! practical secure generators at real parameter sizes. `CtrDrbgAes256` is the
//! practical entry point in this module.

pub mod blum_blum_shub;
pub mod blum_micali;
pub mod ctr_drbg;
pub(crate) mod primes;
