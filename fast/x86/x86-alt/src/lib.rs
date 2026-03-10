//! x86 alternative implementations.
//!
//! This crate is an opt-in acceleration path for x86/x86_64 users.
//! It must stay behavior-compatible with the baseline `cryptography` crate.

pub mod aes128_x86;
pub mod aes256_x86;
pub mod ghash_x86;
