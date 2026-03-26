//! x86/x86_64 acceleration crate.
//!
//! This crate currently ships the x86 backends with clear wins on our target
//! machines (AES-NI and PCLMUL-backed GHASH). It is narrower than the ARM
//! crate by design today; the public API remains stable and additional kernels
//! can be added as they clear correctness and performance gates.

pub mod aes128_x86;
pub mod aes256_x86;
pub mod ghash_x86;
