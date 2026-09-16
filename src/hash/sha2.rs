//! SHA-2 family from FIPS 180-4.
//!
//! This module includes both the 32-bit and 64-bit SHA-2 lines:
//!
//! - `Sha224`, `Sha256`
//! - `Sha384`, `Sha512`
//! - `Sha512_224`, `Sha512_256`
//!
//! FIPS 180-4 specifies two hash computations: SHA-256 on 32-bit words (§6.2)
//! and SHA-512 on 64-bit words (§6.4), each with its own functions and
//! constants. The other four algorithms are defined "in the exact same
//! manner" from a different initial hash value, with the final hash value
//! truncated: SHA-224 from SHA-256 (§6.3), and SHA-384, SHA-512/224, and
//! SHA-512/256 from SHA-512 (§6.5 to §6.7). The two computations live in the
//! private `sha256` and `sha512` modules, written in the Standard's notation;
//! the streaming cores after them pad (§5.1) and parse (§5.2) the message.

use super::Digest;

/// The SHA-256 hash computation on 32-bit words, in FIPS 180-4's notation:
/// the functions of §4.1.2, the constants of §4.2.2, and the steps of §6.2.2.
/// `Sigma0` and `Sigma1` are the Standard's Σ₀{256} and Σ₁{256}; `sigma0` and
/// `sigma1` are its σ₀{256} and σ₁{256}.
#[allow(non_snake_case)]
mod sha256 {
    // The Standard writes ∧ for bitwise AND, ⊕ for XOR, ¬ for the complement,
    // ROTR^n(x) for rotation right by n bits (`x.rotate_right(n)`), and
    // SHR^n(x) for the right shift `x >> n` (§2.2.2, §3.2).

    /// Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z), FIPS 180-4 §4.1.2 equation (4.2).
    #[inline]
    const fn Ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    /// Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z), FIPS 180-4 §4.1.2
    /// equation (4.3).
    #[inline]
    const fn Maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    /// Σ₀{256}(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x), FIPS 180-4 §4.1.2
    /// equation (4.4).
    #[inline]
    const fn Sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    /// Σ₁{256}(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x), FIPS 180-4 §4.1.2
    /// equation (4.5).
    #[inline]
    const fn Sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    /// σ₀{256}(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x), FIPS 180-4 §4.1.2
    /// equation (4.6).
    #[inline]
    const fn sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    /// σ₁{256}(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x), FIPS 180-4 §4.1.2
    /// equation (4.7).
    #[inline]
    const fn sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    /// K_0{256}, ..., K_63{256}, FIPS 180-4 §4.2.2: "the first thirty-two
    /// bits of the fractional parts of the cube roots of the first sixty-four
    /// prime numbers", transcribed as the Standard prints them, eight to a
    /// row. A test re-derives every word from that definition.
    #[rustfmt::skip]
    pub(super) const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];

    /// FIPS 180-4 §6.2.2, SHA-256 hash computation: steps 1 to 4 for one
    /// message block M^(i). `H` holds the (i-1)st hash value H_0^(i-1), ...,
    /// H_7^(i-1) on entry and the ith on return. Addition (+) is performed
    /// modulo 2^32.
    #[inline]
    pub(super) fn compress(H: &mut [u32; 8], block: &[u8; 64]) {
        // 1. Prepare the message schedule, {W_t}. The first sixteen words are
        //    the block's M_0^(i), ..., M_15^(i), each big-endian (§3.1,
        //    §5.2.1).
        let mut W = [0u32; 64];
        for (t, M_t) in block.chunks_exact(4).enumerate() {
            W[t] = u32::from_be_bytes([M_t[0], M_t[1], M_t[2], M_t[3]]);
        }
        for t in 16..=63 {
            W[t] = sigma1(W[t - 2])
                .wrapping_add(W[t - 7])
                .wrapping_add(sigma0(W[t - 15]))
                .wrapping_add(W[t - 16]);
        }

        // 2. Initialize the eight working variables, a, b, c, d, e, f, g, and
        //    h, with the (i-1)st hash value.
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *H;

        // 3. For t=0 to 63:
        for t in 0..=63 {
            let T1 = h
                .wrapping_add(Sigma1(e))
                .wrapping_add(Ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(W[t]);
            let T2 = Sigma0(a).wrapping_add(Maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(T1);
            d = c;
            c = b;
            b = a;
            a = T1.wrapping_add(T2);
        }

        // 4. Compute the ith intermediate hash value H^(i).
        H[0] = a.wrapping_add(H[0]);
        H[1] = b.wrapping_add(H[1]);
        H[2] = c.wrapping_add(H[2]);
        H[3] = d.wrapping_add(H[3]);
        H[4] = e.wrapping_add(H[4]);
        H[5] = f.wrapping_add(H[5]);
        H[6] = g.wrapping_add(H[6]);
        H[7] = h.wrapping_add(H[7]);

        // The schedule expands the block's message words; under HMAC the
        // first block is the key xor ipad.
        crate::ct::zeroize_slice(W.as_mut_slice());
    }
}

/// The SHA-512 hash computation on 64-bit words, in FIPS 180-4's notation:
/// the functions of §4.1.3, the constants of §4.2.3, and the steps of §6.4.2.
/// `Sigma0` and `Sigma1` are the Standard's Σ₀{512} and Σ₁{512}; `sigma0` and
/// `sigma1` are its σ₀{512} and σ₁{512}.
#[allow(non_snake_case)]
mod sha512 {
    // The Standard writes ∧ for bitwise AND, ⊕ for XOR, ¬ for the complement,
    // ROTR^n(x) for rotation right by n bits (`x.rotate_right(n)`), and
    // SHR^n(x) for the right shift `x >> n` (§2.2.2, §3.2).

    /// Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z), FIPS 180-4 §4.1.3 equation (4.8).
    #[inline]
    const fn Ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    /// Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z), FIPS 180-4 §4.1.3
    /// equation (4.9).
    #[inline]
    const fn Maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    /// Σ₀{512}(x) = ROTR^28(x) ⊕ ROTR^34(x) ⊕ ROTR^39(x), FIPS 180-4 §4.1.3
    /// equation (4.10).
    #[inline]
    const fn Sigma0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    /// Σ₁{512}(x) = ROTR^14(x) ⊕ ROTR^18(x) ⊕ ROTR^41(x), FIPS 180-4 §4.1.3
    /// equation (4.11).
    #[inline]
    const fn Sigma1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    /// σ₀{512}(x) = ROTR^1(x) ⊕ ROTR^8(x) ⊕ SHR^7(x), FIPS 180-4 §4.1.3
    /// equation (4.12).
    #[inline]
    const fn sigma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    /// σ₁{512}(x) = ROTR^19(x) ⊕ ROTR^61(x) ⊕ SHR^6(x), FIPS 180-4 §4.1.3
    /// equation (4.13).
    #[inline]
    const fn sigma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    /// K_0{512}, ..., K_79{512}, FIPS 180-4 §4.2.3: "the first sixty-four
    /// bits of the fractional parts of the cube roots of the first eighty
    /// prime numbers", transcribed as the Standard prints them, four to a
    /// row. A test re-derives every word from that definition.
    #[rustfmt::skip]
    pub(super) const K: [u64; 80] = [
        0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
    ];

    /// FIPS 180-4 §6.4.2, SHA-512 hash computation: steps 1 to 4 for one
    /// message block M^(i). `H` holds the (i-1)st hash value H_0^(i-1), ...,
    /// H_7^(i-1) on entry and the ith on return. Addition (+) is performed
    /// modulo 2^64.
    #[inline]
    pub(super) fn compress(H: &mut [u64; 8], block: &[u8; 128]) {
        // 1. Prepare the message schedule, {W_t}. The first sixteen words are
        //    the block's M_0^(i), ..., M_15^(i), each big-endian (§3.1,
        //    §5.2.2).
        let mut W = [0u64; 80];
        for (t, M_t) in block.chunks_exact(8).enumerate() {
            W[t] = u64::from_be_bytes([
                M_t[0], M_t[1], M_t[2], M_t[3], M_t[4], M_t[5], M_t[6], M_t[7],
            ]);
        }
        for t in 16..=79 {
            W[t] = sigma1(W[t - 2])
                .wrapping_add(W[t - 7])
                .wrapping_add(sigma0(W[t - 15]))
                .wrapping_add(W[t - 16]);
        }

        // 2. Initialize the eight working variables, a, b, c, d, e, f, g, and
        //    h, with the (i-1)st hash value.
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *H;

        // 3. For t=0 to 79:
        for t in 0..=79 {
            let T1 = h
                .wrapping_add(Sigma1(e))
                .wrapping_add(Ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(W[t]);
            let T2 = Sigma0(a).wrapping_add(Maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(T1);
            d = c;
            c = b;
            b = a;
            a = T1.wrapping_add(T2);
        }

        // 4. Compute the ith intermediate hash value H^(i).
        H[0] = a.wrapping_add(H[0]);
        H[1] = b.wrapping_add(H[1]);
        H[2] = c.wrapping_add(H[2]);
        H[3] = d.wrapping_add(H[3]);
        H[4] = e.wrapping_add(H[4]);
        H[5] = f.wrapping_add(H[5]);
        H[6] = g.wrapping_add(H[6]);
        H[7] = h.wrapping_add(H[7]);

        // The schedule expands the block's message words; under HMAC the
        // first block is the key xor ipad.
        crate::ct::zeroize_slice(W.as_mut_slice());
    }
}

#[derive(Clone)]
struct Sha2_32Core {
    state: [u32; 8],
    block: [u8; 64],
    pos: usize,
    bit_len: u64,
}

impl Sha2_32Core {
    fn new(iv: [u32; 8]) -> Self {
        Self {
            state: iv,
            block: [0u8; 64],
            pos: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (64 - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == 64 {
                sha256::compress(&mut self.state, &self.block);
                self.block = [0u8; 64];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(512);
            }
        }
    }

    fn finalize<const OUT: usize>(mut self) -> [u8; OUT] {
        let mut out = [0u8; OUT];
        self.finalize_in_place(&mut out);
        // `self` drops here, and `Drop` wipes the final chaining state.
        out
    }

    /// FIPS 180-4 §5.1.1 padding and the final §6.2.2 compression(s), then
    /// the leading `OUT` bytes of the big-endian final hash value into
    /// `out`. The state is left holding the final chaining value; the
    /// callers decide whether it is dropped (`finalize`) or replaced
    /// (`finalize_reset`).
    fn finalize_in_place<const OUT: usize>(&mut self, out: &mut [u8; OUT]) {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u64) * 8);
        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 56 {
            self.block[self.pos..].fill(0);
            sha256::compress(&mut self.state, &self.block);
            self.block = [0u8; 64];
            self.pos = 0;
        }

        self.block[self.pos..56].fill(0);
        self.block[56..].copy_from_slice(&self.bit_len.to_be_bytes());
        sha256::compress(&mut self.state, &self.block);

        let mut full = [0u8; 32];
        for (chunk, word) in full.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out.copy_from_slice(&full[..OUT]);
        // SHA-224 truncates: the untransmitted state bytes stay secret.
        crate::ct::zeroize_slice(full.as_mut_slice());
    }

    fn zeroize(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.bit_len = 0;
    }
}

impl Drop for Sha2_32Core {
    fn drop(&mut self) {
        // Under HMAC the chaining state and buffered block are key material.
        self.zeroize();
    }
}

#[derive(Clone)]
struct Sha2_64Core {
    state: [u64; 8],
    block: [u8; 128],
    pos: usize,
    bit_len: u128,
}

impl Sha2_64Core {
    fn new(iv: [u64; 8]) -> Self {
        Self {
            state: iv,
            block: [0u8; 128],
            pos: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (128 - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == 128 {
                sha512::compress(&mut self.state, &self.block);
                self.block = [0u8; 128];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(1024);
            }
        }
    }

    fn finalize<const OUT: usize>(mut self) -> [u8; OUT] {
        let mut out = [0u8; OUT];
        self.finalize_in_place(&mut out);
        // `self` drops here, and `Drop` wipes the final chaining state.
        out
    }

    /// FIPS 180-4 §5.1.2 padding and the final §6.4.2 compression(s), then
    /// the leading `OUT` bytes of the big-endian final hash value into
    /// `out`. The state is left holding the final chaining value; the
    /// callers decide whether it is dropped (`finalize`) or replaced
    /// (`finalize_reset`).
    fn finalize_in_place<const OUT: usize>(&mut self, out: &mut [u8; OUT]) {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u128) * 8);
        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 112 {
            self.block[self.pos..].fill(0);
            sha512::compress(&mut self.state, &self.block);
            self.block = [0u8; 128];
            self.pos = 0;
        }

        self.block[self.pos..112].fill(0);
        self.block[112..].copy_from_slice(&self.bit_len.to_be_bytes());
        sha512::compress(&mut self.state, &self.block);

        let mut full = [0u8; 64];
        for (chunk, word) in full.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out.copy_from_slice(&full[..OUT]);
        // The truncated variants' untransmitted state bytes stay secret.
        crate::ct::zeroize_slice(full.as_mut_slice());
    }

    fn zeroize(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.bit_len = 0;
    }
}

impl Drop for Sha2_64Core {
    fn drop(&mut self) {
        // Under HMAC the chaining state and buffered block are key material.
        self.zeroize();
    }
}

macro_rules! define_sha2_32 {
    ($name:ident, $out_len:expr, $iv:expr) => {
        /// Streaming SHA-2 hasher from FIPS 180-4, built on the 32-bit
        /// (eight-`u32`-word, 64-round) compression function over 64-byte
        /// blocks.
        ///
        #[doc = concat!("`", stringify!($name), "` starts from its own FIPS 180-4")]
        /// §5.3 initial hash value and returns the leading
        #[doc = concat!(stringify!($out_len), " bytes of the big-endian-serialized")]
        /// 256-bit final state.
        #[derive(Clone)]
        pub struct $name {
            inner: Sha2_32Core,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Message block size in bytes: this 32-bit SHA-2 line compresses
            /// 512-bit (64-byte) blocks, and FIPS 180-4 §5.1.1 padding fills
            /// the final block to that boundary.
            pub const BLOCK_LEN: usize = 64;
            /// Digest length in bytes: the digest keeps the leading
            #[doc = concat!(stringify!($out_len), " bytes of the 32-byte final state.")]
            pub const OUTPUT_LEN: usize = $out_len;

            /// Begin hashing from this variant's FIPS 180-4 §5.3 initial hash
            /// value, with an empty block buffer and a zero message length.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    inner: Sha2_32Core::new($iv),
                }
            }

            /// Absorb `data` into the running hash, buffering any partial
            /// 64-byte block; splitting a message across calls produces the
            /// same digest as hashing it in one call.
            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            /// Consume the hasher: apply FIPS 180-4 §5.1.1 padding (a `0x80`
            /// byte, zeros, and the 64-bit big-endian message bit length),
            /// compress the final block, and return the digest.
            #[must_use]
            pub fn finalize(self) -> [u8; $out_len] {
                self.inner.finalize::<$out_len>()
            }

            /// One-shot hash of `data`, equivalent to `new` + `update` +
            /// `finalize`; returns a fixed-size array rather than the `Vec`
            /// of the `Digest::digest` trait helper.
            #[must_use]
            pub fn digest(data: &[u8]) -> [u8; $out_len] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Digest for $name {
            const BLOCK_LEN: usize = 64;
            const OUTPUT_LEN: usize = $out_len;

            fn new() -> Self {
                Self::new()
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(mut self, out: &mut [u8]) {
                let out: &mut [u8; $out_len] = out.try_into().expect("wrong digest length");
                self.inner.finalize_in_place::<$out_len>(out);
            }

            fn finalize_reset(&mut self, out: &mut [u8]) {
                let out: &mut [u8; $out_len] = out.try_into().expect("wrong digest length");
                self.inner.finalize_in_place::<$out_len>(out);
                // Assigning a fresh core drops the consumed one, and `Drop`
                // wipes its chaining state and block buffer.
                self.inner = Sha2_32Core::new($iv);
            }

            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }
    };
}

macro_rules! define_sha2_64 {
    ($name:ident, $out_len:expr, $iv:expr) => {
        /// Streaming SHA-2 hasher from FIPS 180-4, built on the 64-bit
        /// (eight-`u64`-word, 80-round) compression function over 128-byte
        /// blocks.
        ///
        #[doc = concat!("`", stringify!($name), "` starts from its own FIPS 180-4")]
        /// §5.3 initial hash value and returns the leading
        #[doc = concat!(stringify!($out_len), " bytes of the big-endian-serialized")]
        /// 512-bit final state; the distinct initial values keep the
        /// truncated variants domain-separated from SHA-512.
        #[derive(Clone)]
        pub struct $name {
            inner: Sha2_64Core,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Message block size in bytes: this 64-bit SHA-2 line compresses
            /// 1024-bit (128-byte) blocks, and FIPS 180-4 §5.1.2 padding fills
            /// the final block to that boundary.
            pub const BLOCK_LEN: usize = 128;
            /// Digest length in bytes: the digest keeps the leading
            #[doc = concat!(stringify!($out_len), " bytes of the 64-byte final state.")]
            pub const OUTPUT_LEN: usize = $out_len;

            /// Begin hashing from this variant's FIPS 180-4 §5.3 initial hash
            /// value, with an empty block buffer and a zero message length.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    inner: Sha2_64Core::new($iv),
                }
            }

            /// Absorb `data` into the running hash, buffering any partial
            /// 128-byte block; splitting a message across calls produces the
            /// same digest as hashing it in one call.
            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            /// Consume the hasher: apply FIPS 180-4 §5.1.2 padding (a `0x80`
            /// byte, zeros, and the 128-bit big-endian message bit length),
            /// compress the final block, and return the digest.
            #[must_use]
            pub fn finalize(self) -> [u8; $out_len] {
                self.inner.finalize::<$out_len>()
            }

            /// One-shot hash of `data`, equivalent to `new` + `update` +
            /// `finalize`; returns a fixed-size array rather than the `Vec`
            /// of the `Digest::digest` trait helper.
            #[must_use]
            pub fn digest(data: &[u8]) -> [u8; $out_len] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Digest for $name {
            const BLOCK_LEN: usize = 128;
            const OUTPUT_LEN: usize = $out_len;

            fn new() -> Self {
                Self::new()
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(mut self, out: &mut [u8]) {
                let out: &mut [u8; $out_len] = out.try_into().expect("wrong digest length");
                self.inner.finalize_in_place::<$out_len>(out);
            }

            fn finalize_reset(&mut self, out: &mut [u8]) {
                let out: &mut [u8; $out_len] = out.try_into().expect("wrong digest length");
                self.inner.finalize_in_place::<$out_len>(out);
                // Assigning a fresh core drops the consumed one, and `Drop`
                // wipes its chaining state and block buffer.
                self.inner = Sha2_64Core::new($iv);
            }

            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }
    };
}

// FIPS 180-4 §5.3.2 initial hash value H(0) for SHA-224.
define_sha2_32!(
    Sha224,
    28,
    [
        0xc105_9ed8,
        0x367c_d507,
        0x3070_dd17,
        0xf70e_5939,
        0xffc0_0b31,
        0x6858_1511,
        0x64f9_8fa7,
        0xbefa_4fa4,
    ]
);

// FIPS 180-4 §5.3.3 initial hash value H(0) for SHA-256.
define_sha2_32!(
    Sha256,
    32,
    [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
);

// FIPS 180-4 §5.3.4 initial hash value H(0) for SHA-384.
define_sha2_64!(
    Sha384,
    48,
    [
        0xcbbb_9d5d_c105_9ed8,
        0x629a_292a_367c_d507,
        0x9159_015a_3070_dd17,
        0x152f_ecd8_f70e_5939,
        0x6733_2667_ffc0_0b31,
        0x8eb4_4a87_6858_1511,
        0xdb0c_2e0d_64f9_8fa7,
        0x47b5_481d_befa_4fa4,
    ]
);

// FIPS 180-4 §5.3.5 initial hash value H(0) for SHA-512.
define_sha2_64!(
    Sha512,
    64,
    [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ]
);

// FIPS 180-4 §5.3.6.1 initial hash value H(0) for SHA-512/224.
define_sha2_64!(
    Sha512_224,
    28,
    [
        0x8c3d_37c8_1954_4da2,
        0x73e1_9966_89dc_d4d6,
        0x1dfa_b7ae_32ff_9c82,
        0x679d_d514_582f_9fcf,
        0x0f6d_2b69_7bd4_4da8,
        0x77e3_6f73_04c4_8942,
        0x3f9d_85a8_6a1d_36c8,
        0x1112_e6ad_91d6_92a1,
    ]
);

// FIPS 180-4 §5.3.6.2 initial hash value H(0) for SHA-512/256.
define_sha2_64!(
    Sha512_256,
    32,
    [
        0x2231_2194_fc2b_f72c,
        0x9f55_5fa3_c84c_64c2,
        0x2393_b86b_6f53_b151,
        0x9638_7719_5940_eabd,
        0x9628_3ee2_a88e_ffe3,
        0xbe5e_1e25_5386_3992,
        0x2b01_99fc_2c85_b8aa,
        0x0eb7_2ddc_81c5_2ca2,
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::encode_hex;

    /// `finalize_reset` leaves both SHA-2 cores a fresh instance, `zeroize`
    /// scrubs the whole state, and every SHA-2 type wipes itself on drop.
    #[test]
    fn finalize_reset_and_zeroize_scrub_the_state() {
        let msg = b"HMAC feeds key material through this state";

        let mut h = Sha256::new();
        h.update(msg);
        let mut out = [0u8; 32];
        crate::hash::Digest::finalize_reset(&mut h, &mut out);
        assert_eq!(out, Sha256::digest(msg));
        let fresh = Sha256::new();
        assert_eq!(
            (h.inner.state, h.inner.block, h.inner.pos, h.inner.bit_len),
            (fresh.inner.state, [0u8; 64], 0, 0),
            "finalize_reset leaves a fresh SHA-256"
        );

        let mut h = Sha512::new();
        h.update(msg);
        let mut out = [0u8; 64];
        crate::hash::Digest::finalize_reset(&mut h, &mut out);
        assert_eq!(out, Sha512::digest(msg));
        let fresh = Sha512::new();
        assert_eq!(h.inner.state, fresh.inner.state);
        assert!(h.inner.block.iter().all(|&b| b == 0));
        assert_eq!((h.inner.pos, h.inner.bit_len), (0, 0));

        let mut h = Sha224::new();
        h.update(b"a partial block");
        crate::hash::Digest::zeroize(&mut h);
        assert_eq!(
            (h.inner.state, h.inner.pos, h.inner.bit_len),
            ([0u32; 8], 0, 0)
        );

        assert!(core::mem::needs_drop::<Sha224>());
        assert!(core::mem::needs_drop::<Sha256>());
        assert!(core::mem::needs_drop::<Sha384>());
        assert!(core::mem::needs_drop::<Sha512>());
        assert!(core::mem::needs_drop::<Sha512_224>());
        assert!(core::mem::needs_drop::<Sha512_256>());
    }

    #[test]
    fn sha224_empty() {
        assert_eq!(
            encode_hex(&Sha224::digest(b"")),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn sha224_abc_streaming() {
        let mut h = Sha224::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            encode_hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb924".to_owned() + "27ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc_streaming() {
        let mut h = Sha256::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "ba7816bf8f01cfea414140de5dae2223".to_owned() + "b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha384_empty() {
        assert_eq!(
            encode_hex(&Sha384::digest(b"")),
            "38b060a751ac96384cd9327eb1b1e36a".to_owned()
                + "21fdb71114be07434c0cc7bf63f6e1da"
                + "274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn sha384_abc_streaming() {
        let mut h = Sha384::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "cb00753f45a35e8bb5a03d699ac65007".to_owned()
                + "272c32ab0eded1631a8b605a43ff5bed"
                + "8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_empty() {
        assert_eq!(
            encode_hex(&Sha512::digest(b"")),
            "cf83e1357eefb8bdf1542850d66d8007".to_owned()
                + "d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f"
                + "63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_abc_streaming() {
        let mut h = Sha512::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "ddaf35a193617abacc417349ae204131".to_owned()
                + "12e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd"
                + "454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha512_224_empty() {
        assert_eq!(
            encode_hex(&Sha512_224::digest(b"")),
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
        );
    }

    #[test]
    fn sha512_224_abc_streaming() {
        let mut h = Sha512_224::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );
    }

    #[test]
    fn sha512_256_empty() {
        assert_eq!(
            encode_hex(&Sha512_256::digest(b"")),
            "c672b8d1ef56ed28ab87c3622c511406".to_owned() + "9bdd3ad7b8f9737498d0c01ecef0967a"
        );
    }

    #[test]
    fn sha512_256_abc_streaming() {
        let mut h = Sha512_256::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "53048e2681941ef99b2e29b76b4c7dab".to_owned() + "e4c2d0c634fc6d46e0e2f13107e7af23"
        );
    }

    #[test]
    fn sha256_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha256", "-binary"], msg)
            .or_skip("sha256_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha256::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha224_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha224", "-binary"], msg)
            .or_skip("sha224_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha224::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha384_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha384", "-binary"], msg)
            .or_skip("sha384_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha384::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha512_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha512", "-binary"], msg)
            .or_skip("sha512_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha512::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha512_224_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha512-224", "-binary"], msg)
            .or_skip("sha512_224_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha512_224::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha512_256_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha512-256", "-binary"], msg)
            .or_skip("sha512_256_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha512_256::digest(msg).as_slice(), expected.as_slice());
    }

    /// The first `count` primes, by trial division.
    fn first_primes(count: usize) -> Vec<u64> {
        let mut primes = Vec::with_capacity(count);
        let mut n = 2u64;
        while primes.len() < count {
            if primes.iter().all(|&p| !n.is_multiple_of(p)) {
                primes.push(n);
            }
            n += 1;
        }
        primes
    }

    /// The first `w` bits of the fractional part of the `k`th root of `p`, in
    /// exact integer arithmetic: ⌊(p · 2^(k·w))^(1/k)⌋ = ⌊p^(1/k) · 2^w⌋, whose
    /// low `w` bits are those fraction bits.
    fn root_fraction_bits(p: u64, k: u64, w: usize) -> u64 {
        let mut scaled = rump::BigUint::from_u64(p);
        scaled.shl_bits(w * k as usize);
        let fraction = scaled.nth_root_floor(k).low_bits(w);
        fraction.to_u64().expect("w is at most 64")
    }

    /// FIPS 180-4 §4.2.2 and §4.2.3: the words of K{256} and K{512} are the
    /// first 32 and 64 bits of the fractional parts of the cube roots of the
    /// first 64 and 80 prime numbers.
    #[test]
    fn k_words_are_the_cube_root_fractions_of_the_first_primes() {
        for (t, p) in first_primes(80).into_iter().enumerate() {
            if t < 64 {
                assert_eq!(
                    u64::from(sha256::K[t]),
                    root_fraction_bits(p, 3, 32),
                    "K_{t}{{256}}"
                );
            }
            assert_eq!(sha512::K[t], root_fraction_bits(p, 3, 64), "K_{t}{{512}}");
        }
    }

    /// FIPS 180-4 §5.3.2 to §5.3.5: the SHA-256 and SHA-512 initial hash
    /// values are the first 32 and 64 bits of the fractional parts of the
    /// square roots of the first eight primes; SHA-384's are the first 64
    /// bits for the ninth through sixteenth primes, and SHA-224's are the
    /// second 32 bits of those same fractional parts (bits 33 to 64, the low
    /// half of the SHA-384 words).
    #[test]
    fn initial_hash_values_are_the_square_root_fractions_of_primes() {
        let primes = first_primes(16);
        let (first_eight, ninth_to_sixteenth) = primes.split_at(8);
        for (j, &p) in first_eight.iter().enumerate() {
            assert_eq!(
                u64::from(Sha256::new().inner.state[j]),
                root_fraction_bits(p, 2, 32),
                "SHA-256 H_{j}(0)"
            );
            assert_eq!(
                Sha512::new().inner.state[j],
                root_fraction_bits(p, 2, 64),
                "SHA-512 H_{j}(0)"
            );
        }
        for (j, &p) in ninth_to_sixteenth.iter().enumerate() {
            let first_sixty_four = root_fraction_bits(p, 2, 64);
            assert_eq!(
                Sha384::new().inner.state[j],
                first_sixty_four,
                "SHA-384 H_{j}(0)"
            );
            assert_eq!(
                u64::from(Sha224::new().inner.state[j]),
                first_sixty_four & 0xffff_ffff,
                "SHA-224 H_{j}(0)"
            );
        }
    }

    /// FIPS 180-4 §5.3.6, the SHA-512/t IV Generation Function: with H(0)' the
    /// SHA-512 initial hash value and H_i(0)'' = H_i(0)' ⊕ a5a5a5a5a5a5a5a5,
    /// the SHA-512/t initial hash value H(0) is SHA-512("SHA-512/t") using
    /// H(0)'' as the IV. §5.3.6.1 and §5.3.6.2 list the results for t = 224
    /// and t = 256.
    #[test]
    fn sha512_t_initial_values_come_from_the_iv_generation_function() {
        for (name, h0) in [
            ("SHA-512/224", Sha512_224::new().inner.state),
            ("SHA-512/256", Sha512_256::new().inner.state),
        ] {
            let mut h0_double_prime = Sha512::new().inner.state;
            for word in &mut h0_double_prime {
                *word ^= 0xa5a5_a5a5_a5a5_a5a5;
            }
            let mut hasher = Sha2_64Core::new(h0_double_prime);
            hasher.update(name.as_bytes());
            let digest: [u8; 64] = hasher.finalize();
            let mut words = [0u64; 8];
            for (word, bytes) in words.iter_mut().zip(digest.chunks_exact(8)) {
                *word = u64::from_be_bytes(bytes.try_into().expect("an 8-byte chunk"));
            }
            assert_eq!(words, h0, "{name}");
        }
    }
}
