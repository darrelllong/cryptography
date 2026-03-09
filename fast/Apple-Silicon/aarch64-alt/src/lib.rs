//! Apple-Silicon alternative implementations.
//!
//! This crate is an opt-in acceleration path for macOS/aarch64 users.
//! It must stay behavior-compatible with the baseline `cryptography` crate.

pub mod aes128_armv8;
