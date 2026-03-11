//! AES-256 backend for Apple Silicon (`aarch64` + FEAT_AES).
//!
//! Uses the same round structure as the baseline AES implementation but maps
//! rounds to AESE/AESMC intrinsics and precomputes inverse round keys for
//! AESD/AESIMC decryption.
//! As with the AES-128 ARM path, this exposes block operations only; the
//! x86-only buffer API exists because AES-NI benefits more from one-time round-key
//! loading across long buffers.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint8x16_t, vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8,
};

use crate::aes128_armv8::{RCON, SBOX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes256Armv8Error {
    MissingAesFeature,
}

pub struct Aes256Armv8 {
    // Keep both forward and inverse schedules so encrypt/decrypt stay branch-free.
    round_keys: [[u8; 16]; 15],
    inv_round_keys: [[u8; 16]; 15],
}

impl Aes256Armv8 {
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_arch = "aarch64")]
        {
            return std::arch::is_aarch64_feature_detected!("aes");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            false
        }
    }

    pub fn new(key: &[u8; 32]) -> Result<Self, Aes256Armv8Error> {
        if !Self::is_supported() {
            return Err(Aes256Armv8Error::MissingAesFeature);
        }
        let round_keys = expand_key_256(key);
        // Precompute inverse round keys once to avoid per-block AESIMC overhead.
        #[cfg(target_arch = "aarch64")]
        let inv_round_keys = unsafe { build_inverse_round_keys(&round_keys) };
        #[cfg(not(target_arch = "aarch64"))]
        let inv_round_keys = round_keys;
        Ok(Self {
            round_keys,
            inv_round_keys,
        })
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Aes256Armv8Error> {
        if !Self::is_supported() {
            return Err(Aes256Armv8Error::MissingAesFeature);
        }
        // Feature check stays at API boundary; the inner kernel is straight-line.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            encrypt_block_hw(block, &self.round_keys);
        }
        Ok(())
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Aes256Armv8Error> {
        if !Self::is_supported() {
            return Err(Aes256Armv8Error::MissingAesFeature);
        }
        // Same policy as encrypt_block: no dynamic branching in the hot loop.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            decrypt_block_hw(block, &self.inv_round_keys);
        }
        Ok(())
    }
}

fn expand_key_256(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut words = [[0u8; 4]; 60];
    for i in 0..8 {
        words[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 8..60 {
        let mut temp = words[i - 1];
        if i % 8 == 0 {
            // FIPS 197 AES-256 schedule core:
            // RotWord -> SubWord -> xor Rcon every 8th word.
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for b in &mut temp {
                *b = SBOX[*b as usize];
            }
            temp[0] ^= RCON[(i / 8) - 1];
        } else if i % 8 == 4 {
            // AES-256 extra SubWord step on word positions 4 mod 8.
            for b in &mut temp {
                *b = SBOX[*b as usize];
            }
        }
        let prev = words[i - 8];
        for j in 0..4 {
            words[i][j] = prev[j] ^ temp[j];
        }
    }

    let mut round_keys = [[0u8; 16]; 15];
    for round in 0..15 {
        for word in 0..4 {
            round_keys[round][word * 4..word * 4 + 4].copy_from_slice(&words[round * 4 + word]);
        }
    }
    round_keys
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn build_inverse_round_keys(forward: &[[u8; 16]; 15]) -> [[u8; 16]; 15] {
    // AESD expects decryption subkeys transformed by AESIMC.
    let mut inv = [[0u8; 16]; 15];
    inv[0] = forward[14];
    inv[14] = forward[0];
    for i in 1..14 {
        let f = vld1q_u8(forward[14 - i].as_ptr());
        let mixed = vaesimcq_u8(f);
        vst1q_u8(inv[i].as_mut_ptr(), mixed);
    }
    inv
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn load(ptr: *const u8) -> uint8x16_t {
    vld1q_u8(ptr)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn encrypt_block_hw(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    // ARM maps one AES round to AESE + AESMC. Final round omits MixColumns.
    let mut state = load(block.as_ptr());
    for rk in round_keys.iter().take(13) {
        let k = load(rk.as_ptr());
        state = vaeseq_u8(state, k);
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, load(round_keys[13].as_ptr()));
    state = veorq_u8(state, load(round_keys[14].as_ptr()));
    vst1q_u8(block.as_mut_ptr(), state);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn decrypt_block_hw(block: &mut [u8; 16], inv_round_keys: &[[u8; 16]; 15]) {
    // Decryption mirrors encryption with AESD + AESIMC.
    let mut state = load(block.as_ptr());
    for rk in inv_round_keys.iter().take(13) {
        let k = load(rk.as_ptr());
        state = vaesdq_u8(state, k);
        state = vaesimcq_u8(state);
    }
    state = vaesdq_u8(state, load(inv_round_keys[13].as_ptr()));
    state = veorq_u8(state, load(inv_round_keys[14].as_ptr()));
    vst1q_u8(block.as_mut_ptr(), state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::{Aes256, BlockCipher};

    #[test]
    fn nist_aes256_encrypt_kat() {
        if !Aes256Armv8::is_supported() {
            return;
        }

        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected = [
            0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49,
            0x60, 0x89,
        ];

        let aes = Aes256Armv8::new(&key).expect("ARM AES support required");
        aes.encrypt_block(&mut block).expect("encrypt");
        assert_eq!(block, expected);

        aes.decrypt_block(&mut block).expect("decrypt");
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF
            ]
        );
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn fill_bytes(state: &mut u64, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = xorshift64(state).to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    #[test]
    fn random_parity_with_baseline() {
        if !Aes256Armv8::is_supported() {
            return;
        }

        let mut seed = 0x7e57_c0de_f00d_beefu64;
        for _ in 0..1000 {
            let mut key = [0u8; 32];
            let mut block = [0u8; 16];
            fill_bytes(&mut seed, &mut key);
            fill_bytes(&mut seed, &mut block);

            let mut arm_block = block;
            let mut baseline_block = block;

            let arm = Aes256Armv8::new(&key).expect("arm init");
            let baseline = Aes256::new(&key);

            arm.encrypt_block(&mut arm_block).expect("arm enc");
            baseline.encrypt(&mut baseline_block);
            assert_eq!(arm_block, baseline_block);

            arm.decrypt_block(&mut arm_block).expect("arm dec");
            baseline.decrypt(&mut baseline_block);
            assert_eq!(arm_block, baseline_block);
            assert_eq!(arm_block, block);
        }
    }
}
