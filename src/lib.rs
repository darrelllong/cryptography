//! Classical and modern block ciphers, stream ciphers, and historical CSPRNGs
//! implemented in pure, safe, portable Rust directly from their published
//! specifications.

mod ct;

pub mod ciphers;
pub mod cprng;
pub mod hash;
pub mod modes;

pub use ciphers::{
    aes, camellia, cast128, des, grasshopper, magma, present, seed, serpent, simon, sm4, speck,
    twofish, zuc,
};

/// Common interface for block ciphers.
///
/// Every cipher exposes in-place `encrypt` / `decrypt` operating on a byte
/// slice whose length must equal `Self::BLOCK_LEN`.
pub trait BlockCipher {
    /// Block length in bytes.
    const BLOCK_LEN: usize;
    /// Encrypt one block in-place. Panics if `block.len() != BLOCK_LEN`.
    fn encrypt(&self, block: &mut [u8]);
    /// Decrypt one block in-place. Panics if `block.len() != BLOCK_LEN`.
    fn decrypt(&self, block: &mut [u8]);
}

/// Common interface for byte-oriented CSPRNGs.
///
/// Historical generators like Blum Blum Shub and Blum-Micali naturally emit
/// one bit at a time, but the public API is byte-oriented so later generators
/// can share the same trait.
pub trait Csprng {
    /// Fill `out` with pseudorandom bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// Convenience helper for consumers that want one machine word at a time.
    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill_bytes(&mut out);
        u64::from_be_bytes(out)
    }
}

pub use ciphers::aes::{Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct};
pub use ciphers::camellia::{
    Camellia, Camellia128, Camellia128Ct, Camellia192, Camellia192Ct, Camellia256, Camellia256Ct,
    CamelliaCt,
};
pub use ciphers::cast128::{Cast128, Cast128Ct, Cast5, Cast5Ct};
pub use ciphers::des::{key_schedule, Des, DesCt, KeySchedule, TDesMode, TripleDes};
pub use ciphers::grasshopper::{Grasshopper, GrasshopperCt};
pub use ciphers::magma::{Magma, MagmaCt};
pub use ciphers::present::{Present, Present128, Present128Ct, Present80, Present80Ct, PresentCt};
pub use ciphers::seed::{Seed, SeedCt};
pub use ciphers::serpent::{
    Serpent, Serpent128, Serpent128Ct, Serpent192, Serpent192Ct, Serpent256, Serpent256Ct,
    SerpentCt,
};
pub use ciphers::simon::{
    Simon128_128, Simon128_192, Simon128_256, Simon32_64, Simon48_72, Simon48_96, Simon64_128,
    Simon64_96, Simon96_144, Simon96_96,
};
pub use ciphers::sm4::{Sm4, Sm4Ct, Sms4, Sms4Ct};
pub use ciphers::speck::{
    Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96, Speck64_128,
    Speck64_96, Speck96_144, Speck96_96,
};
pub use ciphers::twofish::{
    Twofish, Twofish128, Twofish128Ct, Twofish192, Twofish192Ct, Twofish256, Twofish256Ct,
    TwofishCt,
};
pub use ciphers::zuc::{Zuc128, Zuc128Ct};

pub use cprng::blum_blum_shub::BlumBlumShub;
pub use cprng::blum_micali::BlumMicali;
pub use cprng::ctr_drbg::CtrDrbgAes256;
pub use hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
pub use hash::Xof;
pub use modes::{Cbc, Cfb, Cmac, Ctr, Ecb, Gcm, Gmac, Ofb, Xts};
