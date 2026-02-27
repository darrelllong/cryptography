//! Classical and modern block ciphers implemented in pure, safe, portable Rust
//! directly from their NIST/FIPS specifications.

pub mod aes;
pub mod des;

pub use aes::{Aes128, Aes192, Aes256};
pub use des::{Des, KeySchedule, TDesMode, TripleDes, key_schedule};
