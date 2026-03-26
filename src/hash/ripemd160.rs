//! RIPEMD-160 from Dobbertin/Bosselaers/Preneel.
//!
//! RIPEMD-160 is retained for interoperability with legacy ecosystems
//! (for example, Bitcoin address derivation). It should not be used as the
//! first choice for new protocol designs.

use super::Digest;

// Initial chaining value from the RIPEMD-160 specification.
const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

// Left-line message word order (r_j) for rounds 0..79.
const RL: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

// Right-line message word order (r'_j) for rounds 0..79.
const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

// Left-line rotation counts (s_j) for rounds 0..79.
const SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

// Right-line rotation counts (s'_j) for rounds 0..79.
const SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

#[inline]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    // Five Boolean functions used over 16-round phases.
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

#[inline]
fn k_left(j: usize) -> u32 {
    // Left-line additive constants K_j (spec Table 2).
    match j {
        0..=15 => 0x0000_0000,
        16..=31 => 0x5a82_7999,
        32..=47 => 0x6ed9_eba1,
        48..=63 => 0x8f1b_bcdc,
        _ => 0xa953_fd4e,
    }
}

#[inline]
fn k_right(j: usize) -> u32 {
    // Right-line additive constants K'_j (spec Table 2).
    match j {
        0..=15 => 0x50a2_8be6,
        16..=31 => 0x5c4d_d124,
        32..=47 => 0x6d70_3ef3,
        48..=63 => 0x7a6d_76e9,
        _ => 0x0000_0000,
    }
}

#[inline]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut words = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
    }

    // RIPEMD-160 runs two parallel 80-round lines (left and right) over the
    // same message block with different schedules/constants, then mixes them.
    let mut al = state[0];
    let mut bl = state[1];
    let mut cl = state[2];
    let mut dl = state[3];
    let mut el = state[4];

    let mut ar = state[0];
    let mut br = state[1];
    let mut cr = state[2];
    let mut dr = state[3];
    let mut er = state[4];

    for j in 0..80 {
        let tl = al
            .wrapping_add(f(j, bl, cl, dl))
            .wrapping_add(words[RL[j]])
            .wrapping_add(k_left(j))
            .rotate_left(SL[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = tl;

        let tr = ar
            .wrapping_add(f(79 - j, br, cr, dr))
            .wrapping_add(words[RR[j]])
            .wrapping_add(k_right(j))
            .rotate_left(SR[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = tr;
    }

    // Feed-forward merge step from the specification: cross-couple both lines
    // back into the 5-word chaining state.
    let t = state[1].wrapping_add(cl).wrapping_add(dr);
    state[1] = state[2].wrapping_add(dl).wrapping_add(er);
    state[2] = state[3].wrapping_add(el).wrapping_add(ar);
    state[3] = state[4].wrapping_add(al).wrapping_add(br);
    state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
    state[0] = t;
}

#[derive(Clone)]
pub struct Ripemd160 {
    state: [u32; 5],
    block: [u8; 64],
    pos: usize,
    bit_len: u64,
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self::new()
    }
}

impl Ripemd160 {
    pub const BLOCK_LEN: usize = 64;
    pub const OUTPUT_LEN: usize = 20;

    #[must_use]
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

    #[must_use]
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
        self.block[56..].copy_from_slice(&self.bit_len.to_le_bytes());
        compress(&mut self.state, &self.block);

        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[must_use]
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
        self.block[56..].copy_from_slice(&self.bit_len.to_le_bytes());
        compress(&mut self.state, &self.block);

        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }

        self.zeroize();
    }
}

impl Digest for Ripemd160 {
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
    fn ripemd160_empty() {
        assert_eq!(
            hex(&Ripemd160::digest(b"")),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn ripemd160_abc() {
        assert_eq!(
            hex(&Ripemd160::digest(b"abc")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn ripemd160_message_digest() {
        assert_eq!(
            hex(&Ripemd160::digest(b"message digest")),
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        );
    }

    #[test]
    fn ripemd160_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::run_openssl(&["dgst", "-ripemd160", "-binary"], msg) else {
            return;
        };
        assert_eq!(Ripemd160::digest(msg).as_slice(), expected.as_slice());
    }
}
