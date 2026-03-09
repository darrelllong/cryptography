//! Block and stream ciphers.
//!
//! The crate keeps primitive implementations grouped here and layers higher
//! level composition (`modes`, `hash`, `cprng`) on top. This separation keeps
//! the cipher modules focused on the algorithm cores and their direct key
//! schedules rather than mixing protocol or framing concerns into each file.
//!
//! Ct policy:
//! - new table-based cipher implementations must ship a corresponding `Ct`
//!   variant in the same module.
//! - table-free designs (for example pure ARX/bitwise constructions) may be
//!   exempt, but the exemption must be explicitly recorded in `src/scrub.rs`.

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
pub mod snow3g;
pub mod speck;
pub mod twofish;
pub mod zuc;
