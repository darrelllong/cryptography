//! Classical and modern block ciphers implemented in pure, safe, portable Rust
//! directly from their NIST/FIPS specifications.

pub mod aes;
pub mod des;
pub mod simon;
pub mod speck;

pub use aes::{Aes128, Aes192, Aes256};
pub use des::{Des, KeySchedule, TDesMode, TripleDes, key_schedule};
pub use simon::{
    Simon32_64, Simon48_72, Simon48_96,
    Simon64_96, Simon64_128,
    Simon96_96, Simon96_144,
    Simon128_128, Simon128_192, Simon128_256,
};
pub use speck::{
    Speck32_64, Speck48_72, Speck48_96,
    Speck64_96, Speck64_128,
    Speck96_96, Speck96_144,
    Speck128_128, Speck128_192, Speck128_256,
};
