//! AES-128 alternative path for x86/x86_64 (AES-NI intrinsics).
//!
//! This module is intentionally isolated from the baseline crate implementation.
//! It is an opt-in acceleration path, and callers should validate output parity
//! with the baseline implementation.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes128X86Error {
    MissingAesFeature,
    InvalidLength,
}

#[cfg_attr(not(any(target_arch = "x86", target_arch = "x86_64")), allow(dead_code))]
pub struct Aes128X86 {
    round_keys: [[u8; 16]; 11],
    inv_round_keys: [[u8; 16]; 11],
}

impl Aes128X86 {
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

    pub fn new(key: &[u8; 16]) -> Result<Self, Aes128X86Error> {
        if !Self::is_supported() {
            return Err(Aes128X86Error::MissingAesFeature);
        }
        let round_keys = expand_key_128(key);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let inv_round_keys = unsafe { build_inverse_round_keys(&round_keys) };
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let inv_round_keys = round_keys;
        Ok(Self {
            round_keys,
            inv_round_keys,
        })
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Aes128X86Error> {
        // Hot path: avoid per-block feature detection. Construction already
        // enforces AES-NI availability.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            encrypt_block_hw(block, &self.round_keys);
            return Ok(());
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = block;
            Err(Aes128X86Error::MissingAesFeature)
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) -> Result<(), Aes128X86Error> {
        // Same policy as encrypt_block: keep the inner path branch-free.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            decrypt_block_hw(block, &self.inv_round_keys);
            return Ok(());
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = block;
            Err(Aes128X86Error::MissingAesFeature)
        }
    }

    pub fn encrypt_buffer(&self, buffer: &mut [u8]) -> Result<(), Aes128X86Error> {
        if !buffer.len().is_multiple_of(16) {
            return Err(Aes128X86Error::InvalidLength);
        }
        // Batch mode is where AES-NI wins most: one call, one bounds check.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            encrypt_buffer_hw(buffer, &self.round_keys);
            return Ok(());
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = buffer;
            Err(Aes128X86Error::MissingAesFeature)
        }
    }
}

pub(crate) const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

pub(crate) fn expand_key_128(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut words = [[0u8; 4]; 44];
    for i in 0..4 {
        words[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 4..44 {
        let mut temp = words[i - 1];
        if i % 4 == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for b in &mut temp {
                *b = SBOX[*b as usize];
            }
            temp[0] ^= RCON[(i / 4) - 1];
        }
        let prev = words[i - 4];
        for j in 0..4 {
            words[i][j] = prev[j] ^ temp[j];
        }
    }

    let mut round_keys = [[0u8; 16]; 11];
    for round in 0..11 {
        for word in 0..4 {
            round_keys[round][word * 4..word * 4 + 4].copy_from_slice(&words[round * 4 + word]);
        }
    }
    round_keys
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn build_inverse_round_keys(forward: &[[u8; 16]; 11]) -> [[u8; 16]; 11] {
    // AESDEC expects decryption round keys transformed through AESIMC.
    let mut inv = [[0u8; 16]; 11];
    inv[0] = forward[10];
    inv[10] = forward[0];
    for i in 1..10 {
        let f = _mm_loadu_si128(forward[10 - i].as_ptr() as *const __m128i);
        let mixed = _mm_aesimc_si128(f);
        _mm_storeu_si128(inv[i].as_mut_ptr() as *mut __m128i, mixed);
    }
    inv
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn encrypt_block_hw(block: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let rk0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, rk0);
    for rk in round_keys.iter().take(10).skip(1) {
        let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
        state = _mm_aesenc_si128(state, k);
    }
    state = _mm_aesenclast_si128(
        state,
        _mm_loadu_si128(round_keys[10].as_ptr() as *const __m128i),
    );
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn decrypt_block_hw(block: &mut [u8; 16], inv_round_keys: &[[u8; 16]; 11]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let rk0 = _mm_loadu_si128(inv_round_keys[0].as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, rk0);
    for rk in inv_round_keys.iter().take(10).skip(1) {
        let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
        state = _mm_aesdec_si128(state, k);
    }
    state = _mm_aesdeclast_si128(
        state,
        _mm_loadu_si128(inv_round_keys[10].as_ptr() as *const __m128i),
    );
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
unsafe fn encrypt_buffer_hw(buffer: &mut [u8], round_keys: &[[u8; 16]; 11]) {
    // Load round keys once per buffer instead of once per block.
    let mut rk: [__m128i; 11] = core::mem::zeroed();
    for (i, key) in round_keys.iter().enumerate() {
        rk[i] = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    }

    // Pointer-walk avoids repeated slice/index bounds checks in the hot loop.
    let mut ptr = buffer.as_mut_ptr();
    let end = ptr.add(buffer.len());
    while ptr < end {
        let mut state = _mm_loadu_si128(ptr as *const __m128i);
        state = _mm_xor_si128(state, rk[0]);
        for k in rk.iter().take(10).skip(1) {
            state = _mm_aesenc_si128(state, *k);
        }
        state = _mm_aesenclast_si128(state, rk[10]);
        _mm_storeu_si128(ptr as *mut __m128i, state);
        ptr = ptr.add(16);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::{Aes128, BlockCipher};

    #[test]
    fn nist_aes128_encrypt_kat() {
        if !Aes128X86::is_supported() {
            return;
        }

        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4,
            0xC5, 0x5A,
        ];

        let aes = Aes128X86::new(&key).expect("x86 AES support required");
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
            let v = xorshift64(state).to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }

    #[test]
    fn random_parity_with_baseline() {
        if !Aes128X86::is_supported() {
            return;
        }

        let mut seed = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..2000 {
            let mut key = [0u8; 16];
            let mut block = [0u8; 16];
            fill_bytes(&mut seed, &mut key);
            fill_bytes(&mut seed, &mut block);

            let mut x86_block = block;
            let mut baseline_block = block;

            let x86 = Aes128X86::new(&key).expect("x86");
            let baseline = Aes128::new(&key);

            x86.encrypt_block(&mut x86_block).expect("enc");
            baseline.encrypt(&mut baseline_block);
            assert_eq!(x86_block, baseline_block, "encrypt mismatch");

            x86.decrypt_block(&mut x86_block).expect("dec");
            baseline.decrypt(&mut baseline_block);
            assert_eq!(x86_block, baseline_block, "decrypt mismatch");
            assert_eq!(x86_block, block, "round-trip mismatch");
        }
    }
}
