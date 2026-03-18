//! AES-256 backend for x86/x86_64 (AES-NI).
//!
//! Mirrors the baseline AES-256 schedule/round semantics while mapping rounds
//! to AES-NI intrinsics and offering both single-block and buffer encryption.

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
};

use crate::aes128_x86::{RCON, SBOX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes256X86Error {
    MissingAesFeature,
    InvalidLength,
}

pub struct Aes256X86 {
    round_keys: [[u8; 16]; 15],
    inv_round_keys: [[u8; 16]; 15],
}

impl Drop for Aes256X86 {
    fn drop(&mut self) {
        // Zeroize both schedules so key material does not linger after drop.
        for b in self.round_keys.iter_mut().flatten()
            .chain(self.inv_round_keys.iter_mut().flatten())
        {
            unsafe { std::ptr::write_volatile(b, 0u8) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256X86 {
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return std::arch::is_x86_feature_detected!("aes");
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            false
        }
    }

    pub fn new(key: &[u8; 32]) -> Result<Self, Aes256X86Error> {
        if !Self::is_supported() {
            return Err(Aes256X86Error::MissingAesFeature);
        }
        let round_keys = expand_key_256(key);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let inv_round_keys = unsafe { build_inverse_round_keys(&round_keys) };
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let inv_round_keys = round_keys;
        Ok(Self {
            round_keys,
            inv_round_keys,
        })
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Aes256X86Error> {
        // Hot path: avoid per-block feature detection. Construction already
        // enforces AES-NI availability.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            encrypt_block_hw(block, &self.round_keys);
            return Ok(());
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = (&self.round_keys, &self.inv_round_keys);
            let _ = block;
            Err(Aes256X86Error::MissingAesFeature)
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Aes256X86Error> {
        // Same policy as encrypt_block: keep the inner path branch-free.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            decrypt_block_hw(block, &self.inv_round_keys);
            return Ok(());
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = (&self.round_keys, &self.inv_round_keys);
            let _ = block;
            Err(Aes256X86Error::MissingAesFeature)
        }
    }

    pub fn encrypt_buffer(&self, buffer: &mut [u8]) -> Result<(), Aes256X86Error> {
        if !buffer.len().is_multiple_of(16) {
            return Err(Aes256X86Error::InvalidLength);
        }
        // Batch mode is where AES-NI wins most: one call, one bounds check.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            encrypt_buffer_hw(buffer, &self.round_keys);
            return Ok(());
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = (&self.round_keys, &self.inv_round_keys);
            let _ = buffer;
            Err(Aes256X86Error::MissingAesFeature)
        }
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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn build_inverse_round_keys(forward: &[[u8; 16]; 15]) -> [[u8; 16]; 15] {
    // AESDEC expects decryption round keys transformed through AESIMC.
    let mut inv = [[0u8; 16]; 15];
    inv[0] = forward[14];
    inv[14] = forward[0];
    for i in 1..14 {
        let f = _mm_loadu_si128(forward[14 - i].as_ptr() as *const __m128i);
        let mixed = _mm_aesimc_si128(f);
        _mm_storeu_si128(inv[i].as_mut_ptr() as *mut __m128i, mixed);
    }
    inv
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn encrypt_block_hw(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let rk0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, rk0);
    for rk in round_keys.iter().take(14).skip(1) {
        let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
        state = _mm_aesenc_si128(state, k);
    }
    state = _mm_aesenclast_si128(
        state,
        _mm_loadu_si128(round_keys[14].as_ptr() as *const __m128i),
    );
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn decrypt_block_hw(block: &mut [u8; 16], inv_round_keys: &[[u8; 16]; 15]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let rk0 = _mm_loadu_si128(inv_round_keys[0].as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, rk0);
    for rk in inv_round_keys.iter().take(14).skip(1) {
        let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
        state = _mm_aesdec_si128(state, k);
    }
    state = _mm_aesdeclast_si128(
        state,
        _mm_loadu_si128(inv_round_keys[14].as_ptr() as *const __m128i),
    );
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn encrypt_buffer_hw(buffer: &mut [u8], round_keys: &[[u8; 16]; 15]) {
    // Load round keys once per buffer instead of once per block.
    let mut rk: [__m128i; 15] = core::mem::zeroed();
    for (i, key) in round_keys.iter().enumerate() {
        rk[i] = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    }

    // Pointer-walk avoids repeated slice/index bounds checks in the hot loop.
    let mut ptr = buffer.as_mut_ptr();
    let end = ptr.add(buffer.len());
    while ptr < end {
        let mut state = _mm_loadu_si128(ptr as *const __m128i);
        state = _mm_xor_si128(state, rk[0]);
        for k in rk.iter().take(14).skip(1) {
            state = _mm_aesenc_si128(state, *k);
        }
        state = _mm_aesenclast_si128(state, rk[14]);
        _mm_storeu_si128(ptr as *mut __m128i, state);
        ptr = ptr.add(16);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::{Aes256, BlockCipher};

    #[test]
    fn nist_aes256_encrypt_kat() {
        if !Aes256X86::is_supported() {
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

        let aes = Aes256X86::new(&key).expect("x86 AES support required");
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
        if !Aes256X86::is_supported() {
            return;
        }

        let mut seed = 0x7e57_c0de_f00d_beefu64;
        for _ in 0..1000 {
            let mut key = [0u8; 32];
            let mut block = [0u8; 16];
            fill_bytes(&mut seed, &mut key);
            fill_bytes(&mut seed, &mut block);

            let mut x86_block = block;
            let mut baseline_block = block;

            let x86 = Aes256X86::new(&key).expect("x86 init");
            let baseline = Aes256::new(&key);

            x86.encrypt_block(&mut x86_block).expect("x86 enc");
            baseline.encrypt(&mut baseline_block);
            assert_eq!(x86_block, baseline_block);

            x86.decrypt_block(&mut x86_block).expect("x86 dec");
            baseline.decrypt(&mut baseline_block);
            assert_eq!(x86_block, baseline_block);
            assert_eq!(x86_block, block);
        }
    }
}
