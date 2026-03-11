//! Apple-Silicon acceleration crate.
//!
//! This crate contains architecture-specific alternatives for selected
//! primitives (AES, GHASH, SHA-256) on `aarch64`.
//! It is strictly opt-in and must remain bit-compatible with the baseline
//! pure-Rust implementations in the main `cryptography` crate.

pub mod aes128_armv8;
pub mod aes256_armv8;
pub mod ghash_armv8;
pub mod sha256_armv8;
