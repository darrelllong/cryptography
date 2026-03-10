//! ChaCha20 alternative path for Apple Silicon (ARM NEON intrinsics).
//!
//! This module is intentionally isolated from the baseline crate implementation.
//! It is an opt-in acceleration path, and callers should validate output parity
//! with the baseline implementation.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vorrq_u32, vsetq_lane_u32, vshlq_n_u32,
    vshrq_n_u32, vst1q_u32,
};

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaCha20Armv8Error {
    MissingNeonFeature,
}

pub struct ChaCha20Armv8 {
    state: [u32; 16],
    // Four-block cache amortizes the cost of the vectorized core.
    block: [u8; 256],
    offset: usize,
}

impl ChaCha20Armv8 {
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_arch = "aarch64")]
        {
            return std::arch::is_aarch64_feature_detected!("neon");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            false
        }
    }

    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self, ChaCha20Armv8Error> {
        Self::with_counter(key, nonce, 0)
    }

    pub fn with_counter(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
    ) -> Result<Self, ChaCha20Armv8Error> {
        if !Self::is_supported() {
            return Err(ChaCha20Armv8Error::MissingNeonFeature);
        }

        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&CONSTANTS);

        for i in 0..8 {
            let j = i * 4;
            state[4 + i] = u32::from_le_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        }

        state[12] = counter;
        state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

        Ok(Self {
            state,
            block: [0u8; 256],
            offset: 256,
        })
    }

    #[inline]
    fn refill(&mut self) {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // Compute four independent ChaCha blocks in parallel (SIMD lanes).
            let words4 = chacha20_block4_words(self.state);
            for block_idx in 0..4 {
                let base = block_idx * 64;
                for word_idx in 0..16 {
                    let out = words4[block_idx][word_idx].to_le_bytes();
                    let off = base + word_idx * 4;
                    self.block[off..off + 4].copy_from_slice(&out);
                }
            }
            self.state[12] = self.state[12].wrapping_add(4);
            self.offset = 0;
        }
    }

    pub fn apply_keystream(&mut self, buf: &mut [u8]) -> Result<(), ChaCha20Armv8Error> {
        if !Self::is_supported() {
            return Err(ChaCha20Armv8Error::MissingNeonFeature);
        }

        // Stream API stays generic; refill handles vectorization granularity.
        let mut done = 0usize;
        while done < buf.len() {
            if self.offset == 256 {
                self.refill();
            }
            let take = core::cmp::min(256 - self.offset, buf.len() - done);
            for i in 0..take {
                buf[done + i] ^= self.block[self.offset + i];
            }
            self.offset += take;
            done += take;
        }
        Ok(())
    }

    pub fn fill(&mut self, buf: &mut [u8]) -> Result<(), ChaCha20Armv8Error> {
        self.apply_keystream(buf)
    }

    pub fn keystream_block(&mut self) -> Result<[u8; 64], ChaCha20Armv8Error> {
        let mut out = [0u8; 64];
        self.apply_keystream(&mut out)?;
        Ok(out)
    }

    pub fn set_counter(&mut self, counter: u32) -> Result<(), ChaCha20Armv8Error> {
        if !Self::is_supported() {
            return Err(ChaCha20Armv8Error::MissingNeonFeature);
        }
        self.state[12] = counter;
        self.block.fill(0);
        self.offset = 256;
        Ok(())
    }
}

impl Drop for ChaCha20Armv8 {
    fn drop(&mut self) {
        self.state.fill(0);
        self.block.fill(0);
        self.offset = 0;
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn rotl16(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<16>(x), vshrq_n_u32::<16>(x))
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn rotl12(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<12>(x), vshrq_n_u32::<20>(x))
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn rotl8(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<8>(x), vshrq_n_u32::<24>(x))
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn rotl7(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<7>(x), vshrq_n_u32::<25>(x))
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn quarter_round_vec(x: &mut [uint32x4_t; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = vaddq_u32(x[a], x[b]);
    x[d] = rotl16(veorq_u32(x[d], x[a]));

    x[c] = vaddq_u32(x[c], x[d]);
    x[b] = rotl12(veorq_u32(x[b], x[c]));

    x[a] = vaddq_u32(x[a], x[b]);
    x[d] = rotl8(veorq_u32(x[d], x[a]));

    x[c] = vaddq_u32(x[c], x[d]);
    x[b] = rotl7(veorq_u32(x[b], x[c]));
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn chacha20_block4_words(state: [u32; 16]) -> [[u32; 16]; 4] {
    // Layout: each vector lane is one independent ChaCha block.
    let mut x = [vdupq_n_u32(0); 16];
    let mut orig = [vdupq_n_u32(0); 16];

    for i in 0..16 {
        let v = if i == 12 {
            // Counter lane is incremented across lanes: ctr, ctr+1, ctr+2, ctr+3.
            let mut t = vdupq_n_u32(state[12]);
            t = vsetq_lane_u32(state[12].wrapping_add(1), t, 1);
            t = vsetq_lane_u32(state[12].wrapping_add(2), t, 2);
            vsetq_lane_u32(state[12].wrapping_add(3), t, 3)
        } else {
            vdupq_n_u32(state[i])
        };
        x[i] = v;
        orig[i] = v;
    }

    for _ in 0..10 {
        // 20 rounds = 10 column/diagonal double-rounds.
        quarter_round_vec(&mut x, 0, 4, 8, 12);
        quarter_round_vec(&mut x, 1, 5, 9, 13);
        quarter_round_vec(&mut x, 2, 6, 10, 14);
        quarter_round_vec(&mut x, 3, 7, 11, 15);

        quarter_round_vec(&mut x, 0, 5, 10, 15);
        quarter_round_vec(&mut x, 1, 6, 11, 12);
        quarter_round_vec(&mut x, 2, 7, 8, 13);
        quarter_round_vec(&mut x, 3, 4, 9, 14);
    }

    for i in 0..16 {
        x[i] = vaddq_u32(x[i], orig[i]);
    }

    let mut out = [[0u32; 16]; 4];
    // Transpose from lane-major vectors back to block-major scalar words.
    for word_idx in 0..16 {
        let mut lanes = [0u32; 4];
        vst1q_u32(lanes.as_mut_ptr(), x[word_idx]);
        for block_idx in 0..4 {
            out[block_idx][word_idx] = lanes[block_idx];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::ChaCha20;

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

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    #[test]
    fn rfc8439_block1_vector() {
        if !ChaCha20Armv8::is_supported() {
            return;
        }
        let mut key = [0u8; 32];
        for i in 0u8..32 {
            key[usize::from(i)] = i;
        }
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut c = ChaCha20Armv8::with_counter(&key, &nonce, 1).expect("neon");
        let block = c.keystream_block().expect("block");
        assert_eq!(
            hex(&block),
            "10f1e7e4d13b5915500fdd1fa32071c4".to_owned()
                + "c7d1f4c733c068030422aa9ac3d46c4e"
                + "d2826446079faa0914c2d705d98b02a2"
                + "b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn random_parity_with_baseline() {
        if !ChaCha20Armv8::is_supported() {
            return;
        }

        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..1000 {
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 12];
            fill_bytes(&mut seed, &mut key);
            fill_bytes(&mut seed, &mut nonce);
            let counter = xorshift64(&mut seed) as u32;
            let len = (xorshift64(&mut seed) as usize) % 8192;

            let mut data_arm = vec![0u8; len];
            let mut data_base = vec![0u8; len];
            fill_bytes(&mut seed, &mut data_arm);
            data_base.copy_from_slice(&data_arm);

            let mut arm = ChaCha20Armv8::with_counter(&key, &nonce, counter).expect("arm init");
            let mut base = ChaCha20::with_counter(&key, &nonce, counter);
            arm.apply_keystream(&mut data_arm).expect("arm stream");
            base.apply_keystream(&mut data_base);
            assert_eq!(data_arm, data_base);
        }
    }
}
