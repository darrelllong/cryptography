#![allow(
    clippy::doc_markdown,
    clippy::inline_always,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

//! CTR_DRBG from NIST SP 800-90A Rev. 1 using AES-256 without a derivation
//! function.
//!
//! This implementation intentionally starts with the simplest approved AES
//! instantiation:
//!
//! - block cipher: AES-256
//! - derivation function: disabled
//! - seed length: `keylen + outlen = 32 + 16 = 48` bytes
//!
//! Because the derivation function is omitted, callers must supply exactly
//! 48 bytes of already-conditioned seed material for instantiation, reseeding,
//! and optional additional input.

use crate::ct::zeroize_slice;
use crate::{Aes256, BlockCipher, Csprng};

const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 16;
const SEED_LEN: usize = KEY_LEN + BLOCK_LEN;
const MAX_REQUEST_BYTES: usize = 1 << 16; // 2^19 bits
const RESEED_INTERVAL: u64 = 1 << 48;

#[inline(always)]
fn increment_be(counter: &mut [u8; BLOCK_LEN]) {
    for b in counter.iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

/// CTR_DRBG with AES-256 and no derivation function.
pub struct CtrDrbgAes256 {
    key: [u8; KEY_LEN],
    v: [u8; BLOCK_LEN],
    reseed_counter: u64,
}

impl CtrDrbgAes256 {
    /// Instantiate from exactly 48 bytes of seed material.
    ///
    /// This is the SP 800-90A "no derivation function" form, so the seed
    /// material must already be fully conditioned to the required seed length.
    pub fn new(seed_material: &[u8; SEED_LEN]) -> Self {
        let mut out = Self {
            key: [0u8; KEY_LEN],
            v: [0u8; BLOCK_LEN],
            reseed_counter: 1,
        };
        out.update(Some(seed_material));
        out
    }

    /// Instantiate and wipe the caller-provided seed buffer.
    pub fn new_wiping(seed_material: &mut [u8; SEED_LEN]) -> Self {
        let out = Self::new(seed_material);
        zeroize_slice(seed_material.as_mut_slice());
        out
    }

    /// Reseed from fresh 48-byte seed material.
    pub fn reseed(&mut self, seed_material: &[u8; SEED_LEN]) {
        self.update(Some(seed_material));
        self.reseed_counter = 1;
    }

    /// Reseed and wipe the caller-provided seed buffer.
    pub fn reseed_wiping(&mut self, seed_material: &mut [u8; SEED_LEN]) {
        self.reseed(seed_material);
        zeroize_slice(seed_material.as_mut_slice());
    }

    /// Generate output, optionally mixing in 48 bytes of additional input.
    ///
    /// The optional additional input uses the same "no derivation function"
    /// rule as instantiate and reseed: if present, it must already be exactly
    /// one seed-length block of conditioned material.
    ///
    /// Panics if the request exceeds the SP 800-90A per-call limit or if the
    /// reseed counter has reached the mandated reseed interval.
    pub fn generate(&mut self, out: &mut [u8], additional_input: Option<&[u8; SEED_LEN]>) {
        assert!(
            self.reseed_counter <= RESEED_INTERVAL,
            "CTR_DRBG reseed required"
        );
        assert!(out.len() <= MAX_REQUEST_BYTES, "CTR_DRBG request too large");

        if let Some(additional_input) = additional_input {
            self.update(Some(additional_input));
        }

        let cipher = Aes256::new(&self.key);
        let mut offset = 0usize;
        while offset < out.len() {
            increment_be(&mut self.v);
            let mut block = self.v;
            cipher.encrypt(&mut block);
            let take = (out.len() - offset).min(BLOCK_LEN);
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }

        self.update(additional_input);
        self.reseed_counter += 1;
    }

    /// Current reseed counter.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    fn update(&mut self, provided_data: Option<&[u8; SEED_LEN]>) {
        let cipher = Aes256::new(&self.key);
        let mut temp = [0u8; SEED_LEN];
        let mut offset = 0usize;

        while offset < SEED_LEN {
            increment_be(&mut self.v);
            let mut block = self.v;
            cipher.encrypt(&mut block);
            temp[offset..offset + BLOCK_LEN].copy_from_slice(&block);
            offset += BLOCK_LEN;
        }

        if let Some(data) = provided_data {
            for (t, d) in temp.iter_mut().zip(data.iter()) {
                *t ^= *d;
            }
        }

        self.key.copy_from_slice(&temp[..KEY_LEN]);
        self.v.copy_from_slice(&temp[KEY_LEN..]);
        zeroize_slice(temp.as_mut_slice());
    }
}

impl Csprng for CtrDrbgAes256 {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.generate(out, None);
    }
}

impl Drop for CtrDrbgAes256 {
    fn drop(&mut self) {
        zeroize_slice(self.key.as_mut_slice());
        zeroize_slice(self.v.as_mut_slice());
        self.reseed_counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let seed = core::array::from_fn::<u8, SEED_LEN, _>(|i| i as u8);
        let mut a = CtrDrbgAes256::new(&seed);
        let mut b = CtrDrbgAes256::new(&seed);

        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        a.fill_bytes(&mut out_a);
        b.fill_bytes(&mut out_b);

        assert_eq!(out_a, out_b);
    }

    #[test]
    fn additional_input_changes_stream() {
        let seed = core::array::from_fn::<u8, SEED_LEN, _>(|i| i as u8);
        let add = core::array::from_fn::<u8, SEED_LEN, _>(|i| (255 - i) as u8);

        let mut plain = CtrDrbgAes256::new(&seed);
        let mut mixed = CtrDrbgAes256::new(&seed);

        let mut out_plain = [0u8; 32];
        let mut out_mixed = [0u8; 32];
        plain.generate(&mut out_plain, None);
        mixed.generate(&mut out_mixed, Some(&add));

        assert_ne!(out_plain, out_mixed);
    }

    #[test]
    fn nist_cavs_count0_no_df_kat() {
        let seed = [
            0xdf, 0x5d, 0x73, 0xfa, 0xa4, 0x68, 0x64, 0x9e, 0xdd, 0xa3, 0x3b, 0x5c, 0xca, 0x79,
            0xb0, 0xb0, 0x56, 0x00, 0x41, 0x9c, 0xcb, 0x7a, 0x87, 0x9d, 0xdf, 0xec, 0x9d, 0xb3,
            0x2e, 0xe4, 0x94, 0xe5, 0x53, 0x1b, 0x51, 0xde, 0x16, 0xa3, 0x0f, 0x76, 0x92, 0x62,
            0x47, 0x4c, 0x73, 0xbe, 0xc0, 0x10,
        ];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let mut discard = [0u8; 64];
        drbg.fill_bytes(&mut discard);
        let mut out = [0u8; 64];
        drbg.fill_bytes(&mut out);

        assert_eq!(
            out,
            [
                0xd1, 0xc0, 0x7c, 0xd9, 0x5a, 0xf8, 0xa7, 0xf1, 0x10, 0x12, 0xc8, 0x4c, 0xe4, 0x8b,
                0xb8, 0xcb, 0x87, 0x18, 0x9e, 0x99, 0xd4, 0x0f, 0xcc, 0xb1, 0x77, 0x1c, 0x61, 0x9b,
                0xdf, 0x82, 0xab, 0x22, 0x80, 0xb1, 0xdc, 0x2f, 0x25, 0x81, 0xf3, 0x91, 0x64, 0xf7,
                0xac, 0x0c, 0x51, 0x04, 0x94, 0xb3, 0xa4, 0x3c, 0x41, 0xb7, 0xdb, 0x17, 0x51, 0x4c,
                0x87, 0xb1, 0x07, 0xae, 0x79, 0x3e, 0x01, 0xc5,
            ]
        );
    }
}
