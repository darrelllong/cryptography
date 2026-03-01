//! Classical and modern block ciphers and stream ciphers implemented in pure,
//! safe, portable Rust directly from their NIST/FIPS/RFC specifications.

mod ct;

pub mod aes;
pub mod camellia;
pub mod des;
pub mod grasshopper;
pub mod magma;
pub mod present;
pub mod seed;
pub mod simon;
pub mod sm4;
pub mod speck;
pub mod zuc;

/// Common interface for block ciphers.
///
/// Every cipher exposes in-place `encrypt` / `decrypt` operating on a byte
/// slice whose length must equal `Self::BLOCK_LEN`.
pub trait BlockCipher {
    /// Block length in bytes.
    const BLOCK_LEN: usize;
    /// Encrypt one block in-place.  Panics if `block.len() != BLOCK_LEN`.
    fn encrypt(&self, block: &mut [u8]);
    /// Decrypt one block in-place.  Panics if `block.len() != BLOCK_LEN`.
    fn decrypt(&self, block: &mut [u8]);
}

pub use aes::{Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct};
pub use camellia::{
    Camellia, Camellia128, Camellia128Ct, Camellia192, Camellia192Ct, Camellia256, Camellia256Ct,
    CamelliaCt,
};
pub use des::{key_schedule, Des, DesCt, KeySchedule, TDesMode, TripleDes};
pub use grasshopper::{Grasshopper, GrasshopperCt};
pub use magma::{Magma, MagmaCt};
pub use present::{Present, Present128, Present128Ct, Present80, Present80Ct, PresentCt};
pub use seed::{Seed, SeedCt};
pub use simon::{
    Simon128_128, Simon128_192, Simon128_256, Simon32_64, Simon48_72, Simon48_96, Simon64_128,
    Simon64_96, Simon96_144, Simon96_96,
};
pub use sm4::{Sm4, Sm4Ct, Sms4, Sms4Ct};
pub use speck::{
    Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96, Speck64_128,
    Speck64_96, Speck96_144, Speck96_96,
};
pub use zuc::{Zuc128, Zuc128Ct};
