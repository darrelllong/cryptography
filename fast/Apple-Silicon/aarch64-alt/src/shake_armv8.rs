//! SHAKE alternative path for Apple Silicon.
//!
//! This module keeps the SHAKE API surface intentionally small and one-shot:
//! absorb input bytes, then squeeze caller-requested output bytes.
//! It is designed for high-throughput KEM-style usage patterns.

const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShakeArmv8Error {
    MissingAarch64,
}

pub struct ShakeArmv8;

impl ShakeArmv8 {
    #[must_use]
    pub fn is_supported() -> bool {
        cfg!(target_arch = "aarch64")
    }

    pub fn shake128(data: &[u8], out: &mut [u8]) -> Result<(), ShakeArmv8Error> {
        if !Self::is_supported() {
            return Err(ShakeArmv8Error::MissingAarch64);
        }
        shake::<168>(data, out);
        Ok(())
    }

    pub fn shake256(data: &[u8], out: &mut [u8]) -> Result<(), ShakeArmv8Error> {
        if !Self::is_supported() {
            return Err(ShakeArmv8Error::MissingAarch64);
        }
        shake::<136>(data, out);
        Ok(())
    }
}

#[inline]
fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0u64; 25];
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(RHO[i]);
        }

        for y in 0..5 {
            let row = 5 * y;
            for x in 0..5 {
                state[row + x] = b[row + x] ^ ((!b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)]);
            }
        }

        state[0] ^= rc;
    }
}

#[inline]
fn absorb_rate_bytes<const RATE: usize>(state: &mut [u64; 25], data: &[u8]) {
    let lanes = RATE / 8;
    for i in 0..lanes {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(&data[i * 8..i * 8 + 8]);
        state[i] ^= u64::from_le_bytes(lane);
    }
    keccak_f1600(state);
}

#[inline]
fn squeeze<const RATE: usize>(state: &mut [u64; 25], out: &mut [u8]) {
    let lanes = RATE / 8;
    let mut produced = 0usize;

    while produced + RATE <= out.len() {
        let chunk = &mut out[produced..produced + RATE];
        for i in 0..lanes {
            chunk[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        produced += RATE;
        if produced < out.len() {
            keccak_f1600(state);
        }
    }

    if produced < out.len() {
        let mut lane_idx = 0usize;
        let mut lane = [0u8; 8];
        let mut lane_off = 8usize;

        while produced < out.len() {
            if lane_idx == lanes && lane_off == 8 {
                keccak_f1600(state);
                lane_idx = 0;
            }

            if lane_off == 8 {
                lane = state[lane_idx].to_le_bytes();
                lane_idx += 1;
                lane_off = 0;
            }

            let take = (out.len() - produced).min(8 - lane_off);
            out[produced..produced + take].copy_from_slice(&lane[lane_off..lane_off + take]);
            produced += take;
            lane_off += take;
        }
    }
}

fn shake<const RATE: usize>(data: &[u8], out: &mut [u8]) {
    let mut state = [0u64; 25];

    let mut chunks = data.chunks_exact(RATE);
    for chunk in &mut chunks {
        absorb_rate_bytes::<RATE>(&mut state, chunk);
    }

    let mut block = [0u8; RATE];
    let rem = chunks.remainder();
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= 0x1f;
    block[RATE - 1] ^= 0x80;
    absorb_rate_bytes::<RATE>(&mut state, &block);

    squeeze::<RATE>(&mut state, out);
    state.fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::hash::Xof;
    use cryptography::{Shake128, Shake256};

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
    fn shake128_parity_random_messages() {
        if !ShakeArmv8::is_supported() {
            return;
        }
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..400 {
            let in_len = (xorshift64(&mut seed) as usize) % 8192;
            let out_len = 32 + ((xorshift64(&mut seed) as usize) % 2048);
            let mut msg = vec![0u8; in_len];
            let mut a = vec![0u8; out_len];
            let mut b = vec![0u8; out_len];
            fill_bytes(&mut seed, &mut msg);
            ShakeArmv8::shake128(&msg, &mut a).expect("shake128");

            let mut xof = Shake128::new();
            xof.update(&msg);
            xof.squeeze(&mut b);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn shake256_parity_random_messages() {
        if !ShakeArmv8::is_supported() {
            return;
        }
        let mut seed = 0x0ddc_0ffe_ecad_beefu64;
        for _ in 0..400 {
            let in_len = (xorshift64(&mut seed) as usize) % 8192;
            let out_len = 32 + ((xorshift64(&mut seed) as usize) % 2048);
            let mut msg = vec![0u8; in_len];
            let mut a = vec![0u8; out_len];
            let mut b = vec![0u8; out_len];
            fill_bytes(&mut seed, &mut msg);
            ShakeArmv8::shake256(&msg, &mut a).expect("shake256");

            let mut xof = Shake256::new();
            xof.update(&msg);
            xof.squeeze(&mut b);
            assert_eq!(a, b);
        }
    }
}
