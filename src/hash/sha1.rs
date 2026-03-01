#![allow(
    clippy::inline_always,
    clippy::many_single_char_names,
    clippy::must_use_candidate,
    clippy::new_without_default,
    clippy::needless_range_loop
)]

//! SHA-1 from FIPS 180-4.
//!
//! SHA-1 is retained here for compatibility and HMAC support. It is no longer
//! recommended for collision-sensitive applications.

use super::Digest;

const IV: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

#[inline(always)]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for t in 0..80 {
        let (f, k) = match t {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[t]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    pos: usize,
    bit_len: u64,
}

impl Sha1 {
    pub const BLOCK_LEN: usize = 64;
    pub const OUTPUT_LEN: usize = 20;

    pub fn new() -> Self {
        Self {
            state: IV,
            block: [0u8; 64],
            pos: 0,
            bit_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (64 - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == 64 {
                compress(&mut self.state, &self.block);
                self.block = [0u8; 64];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(512);
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u64) * 8);

        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 56 {
            self.block[self.pos..].fill(0);
            compress(&mut self.state, &self.block);
            self.block = [0u8; 64];
            self.pos = 0;
        }

        self.block[self.pos..56].fill(0);
        self.block[56..].copy_from_slice(&self.bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);

        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    fn finalize_into_reset(&mut self, out: &mut [u8; 20]) {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u64) * 8);

        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 56 {
            self.block[self.pos..].fill(0);
            compress(&mut self.state, &self.block);
            self.block = [0u8; 64];
            self.pos = 0;
        }

        self.block[self.pos..56].fill(0);
        self.block[56..].copy_from_slice(&self.bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);

        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        self.zeroize();
    }
}

impl Digest for Sha1 {
    const BLOCK_LEN: usize = 64;
    const OUTPUT_LEN: usize = 20;

    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        assert_eq!(out.len(), 20, "wrong digest length");
        out.copy_from_slice(&self.finalize());
    }

    fn finalize_reset(&mut self, out: &mut [u8]) {
        let out: &mut [u8; 20] = out.try_into().expect("wrong digest length");
        self.finalize_into_reset(out);
    }

    fn zeroize(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.bit_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    #[test]
    fn sha1_empty() {
        assert_eq!(
            hex(&Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn sha1_abc_streaming() {
        let mut h = Sha1::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            hex(&h.finalize()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }
}
