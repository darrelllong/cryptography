//! Apple-Silicon alternative implementations.
//!
//! This crate is an opt-in acceleration path for macOS/aarch64 users.
//! It must stay behavior-compatible with the baseline `cryptography` crate.

pub mod aes128_armv8;
pub mod aes256_armv8;
pub mod chacha20_armv8;
pub mod ghash_armv8;
pub mod sha256_armv8;
pub mod shake_armv8;
