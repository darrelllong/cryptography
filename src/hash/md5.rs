//! MD5 from RFC 1321.
//!
//! MD5 is retained for legacy compatibility. It is broken for collision
//! resistance and should not be used for new integrity designs.

use super::Digest;

const IV: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
    9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
    15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

#[inline]
fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut schedule = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        schedule[i] = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
    }

    let mut a_reg = state[0];
    let mut b_reg = state[1];
    let mut c_reg = state[2];
    let mut d_reg = state[3];

    for round_idx in 0..64 {
        let (mix, word_idx) = match round_idx {
            0..=15 => ((b_reg & c_reg) | ((!b_reg) & d_reg), round_idx),
            16..=31 => ((d_reg & b_reg) | ((!d_reg) & c_reg), (5 * round_idx + 1) % 16),
            32..=47 => (b_reg ^ c_reg ^ d_reg, (3 * round_idx + 5) % 16),
            _ => (c_reg ^ (b_reg | (!d_reg)), (7 * round_idx) % 16),
        };

        let tmp = d_reg;
        d_reg = c_reg;
        c_reg = b_reg;
        b_reg = b_reg.wrapping_add(
            a_reg
                .wrapping_add(mix)
                .wrapping_add(K[round_idx])
                .wrapping_add(schedule[word_idx])
                .rotate_left(S[round_idx]),
        );
        a_reg = tmp;
    }

    state[0] = state[0].wrapping_add(a_reg);
    state[1] = state[1].wrapping_add(b_reg);
    state[2] = state[2].wrapping_add(c_reg);
    state[3] = state[3].wrapping_add(d_reg);
}

#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    pos: usize,
    bit_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub const BLOCK_LEN: usize = 64;
    pub const OUTPUT_LEN: usize = 16;

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
    pub fn finalize(mut self) -> [u8; 16] {
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

        let mut out = [0u8; 16];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    fn finalize_into_reset(&mut self, out: &mut [u8; 16]) {
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

impl Digest for Md5 {
    const BLOCK_LEN: usize = 64;
    const OUTPUT_LEN: usize = 16;

    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        assert_eq!(out.len(), 16, "wrong digest length");
        out.copy_from_slice(&self.finalize());
    }

    fn finalize_reset(&mut self, out: &mut [u8]) {
        let out: &mut [u8; 16] = out.try_into().expect("wrong digest length");
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
    fn md5_empty() {
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_streaming_abc() {
        let mut h = Md5::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(hex(&h.finalize()), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn md5_known_vector() {
        assert_eq!(
            hex(&Md5::digest(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
    }

    #[test]
    fn md5_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::ct::run_openssl(&["dgst", "-md5", "-binary"], msg) else {
            return;
        };
        assert_eq!(Md5::digest(msg).as_slice(), expected.as_slice());
    }
}
