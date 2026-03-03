//! Block and stream ciphers.
//!
//! The crate keeps primitive implementations grouped here and layers higher
//! level composition (`modes`, `hash`, `cprng`) on top. This separation keeps
//! the cipher modules focused on the algorithm cores and their direct key
//! schedules rather than mixing protocol or framing concerns into each file.

mod simon_speck_util;

pub mod aes;
pub mod camellia;
pub mod cast128;
pub mod chacha20;
pub mod des;
pub mod grasshopper;
pub mod magma;
pub mod present;
pub mod rabbit;
pub mod salsa20;
pub mod seed;
pub mod serpent;
pub mod simon;
pub mod sm4;
pub mod speck;
pub mod twofish;
pub mod zuc;
