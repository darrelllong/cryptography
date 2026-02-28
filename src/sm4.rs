//! SM4 block cipher (formerly SMS4) — GM/T 0002-2012 / GB/T 32907-2016.
//!
//! 128-bit block, 128-bit key, 32 rounds.
//!
//! The round function is:
//!
//! ```text
//! X_{i+4} = X_i xor T(X_{i+1} xor X_{i+2} xor X_{i+3} xor rk_i)
//! ```
//!
//! where `T = L(tau(.))`, `tau` is the 8-bit S-box applied bytewise, and `L`
//! is the linear diffusion transform used by encryption.  Key expansion uses
//! the related transform `T' = L'(tau(.))`.
//!
//! `Sm4` keeps the direct S-box table lookups. `Sm4Ct` is separate and uses a
//! packed ANF bitset form of the same 8-bit S-box so the round function and
//! key schedule avoid secret-indexed table reads.

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

/// Build the packed ANF coefficients for the SM4 S-box.
///
/// Each output bit becomes two `u128` masks covering the 256 monomials in
/// eight variables. `Sm4Ct` expands the active monomial set for an input byte
/// and then recovers each output bit by parity over the selected terms.
const fn build_sbox_anf() -> [[u128; 2]; 8] {
    let mut out = [[0u128; 2]; 8];
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let mut coeffs = [0u8; 256];
        let mut x = 0usize;
        while x < 256 {
            coeffs[x] = (SBOX[x] >> bit_idx) & 1;
            x += 1;
        }

        let mut var = 0usize;
        while var < 8 {
            let stride = 1usize << var;
            let mut mask = 0usize;
            while mask < 256 {
                if mask & stride != 0 {
                    coeffs[mask] ^= coeffs[mask ^ stride];
                }
                mask += 1;
            }
            var += 1;
        }

        let mut lo = 0u128;
        let mut hi = 0u128;
        let mut monomial = 0usize;
        while monomial < 128 {
            lo |= (coeffs[monomial] as u128) << monomial;
            monomial += 1;
        }
        while monomial < 256 {
            hi |= (coeffs[monomial] as u128) << (monomial - 128);
            monomial += 1;
        }

        out[bit_idx][0] = lo;
        out[bit_idx][1] = hi;
        bit_idx += 1;
    }
    out
}

const SBOX_ANF: [[u128; 2]; 8] = build_sbox_anf();

const FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

const CK: [u32; 32] = [
    0x0007_0e15,
    0x1c23_2a31,
    0x383f_464d,
    0x545b_6269,
    0x7077_7e85,
    0x8c93_9aa1,
    0xa8af_b6bd,
    0xc4cb_d2d9,
    0xe0e7_eef5,
    0xfc03_0a11,
    0x181f_262d,
    0x343b_4249,
    0x5057_5e65,
    0x6c73_7a81,
    0x888f_969d,
    0xa4ab_b2b9,
    0xc0c7_ced5,
    0xdce3_eaf1,
    0xf8ff_060d,
    0x141b_2229,
    0x3037_3e45,
    0x4c53_5a61,
    0x686f_767d,
    0x848b_9299,
    0xa0a7_aeb5,
    0xbcc3_cad1,
    0xd8df_e6ed,
    0xf4fb_0209,
    0x1017_1e25,
    0x2c33_3a41,
    0x484f_565d,
    0x646b_7279,
];

#[inline(always)]
fn tau(x: u32) -> u32 {
    ((SBOX[(x >> 24) as usize] as u32) << 24)
        | ((SBOX[((x >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX[((x >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX[(x & 0xff) as usize] as u32)
}

#[inline(always)]
fn shl_256<const SHIFT: u32>(lo: u128, hi: u128) -> (u128, u128) {
    (lo << SHIFT, (hi << SHIFT) | (lo >> (128 - SHIFT)))
}

#[inline(always)]
fn subset_mask8(x: u8) -> (u128, u128) {
    let mut lo = 1u128;
    let mut hi = 0u128;

    let mask0 = 0u128.wrapping_sub((x & 1) as u128);
    let (add_lo, add_hi) = shl_256::<1>(lo, hi);
    lo |= add_lo & mask0;
    hi |= add_hi & mask0;

    let mask1 = 0u128.wrapping_sub(((x >> 1) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<2>(lo, hi);
    lo |= add_lo & mask1;
    hi |= add_hi & mask1;

    let mask2 = 0u128.wrapping_sub(((x >> 2) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<4>(lo, hi);
    lo |= add_lo & mask2;
    hi |= add_hi & mask2;

    let mask3 = 0u128.wrapping_sub(((x >> 3) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<8>(lo, hi);
    lo |= add_lo & mask3;
    hi |= add_hi & mask3;

    let mask4 = 0u128.wrapping_sub(((x >> 4) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<16>(lo, hi);
    lo |= add_lo & mask4;
    hi |= add_hi & mask4;

    let mask5 = 0u128.wrapping_sub(((x >> 5) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<32>(lo, hi);
    lo |= add_lo & mask5;
    hi |= add_hi & mask5;

    let mask6 = 0u128.wrapping_sub(((x >> 6) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<64>(lo, hi);
    lo |= add_lo & mask6;
    hi |= add_hi & mask6;

    let mask7 = 0u128.wrapping_sub(((x >> 7) & 1) as u128);
    hi |= lo & mask7;

    (lo, hi)
}

#[inline(always)]
fn parity128(mut x: u128) -> u8 {
    x ^= x >> 64;
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    ((0x6996u16 >> (x as u16)) & 1) as u8
}

#[inline(always)]
fn sbox_ct_byte(input: u8) -> u8 {
    let (active_lo, active_hi) = subset_mask8(input);
    let mut out = 0u8;
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let coeff_lo = SBOX_ANF[bit_idx][0];
        let coeff_hi = SBOX_ANF[bit_idx][1];
        let bit = parity128(active_lo & coeff_lo) ^ parity128(active_hi & coeff_hi);
        out |= bit << bit_idx;
        bit_idx += 1;
    }
    out
}

#[inline(always)]
fn tau_ct(x: u32) -> u32 {
    ((sbox_ct_byte((x >> 24) as u8) as u32) << 24)
        | ((sbox_ct_byte(((x >> 16) & 0xff) as u8) as u32) << 16)
        | ((sbox_ct_byte(((x >> 8) & 0xff) as u8) as u32) << 8)
        | (sbox_ct_byte((x & 0xff) as u8) as u32)
}

#[inline(always)]
fn l(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

#[inline(always)]
fn l_prime(x: u32) -> u32 {
    x ^ x.rotate_left(13) ^ x.rotate_left(23)
}

#[inline(always)]
fn t(x: u32) -> u32 {
    l(tau(x))
}

#[inline(always)]
fn t_prime(x: u32) -> u32 {
    l_prime(tau(x))
}

#[inline(always)]
fn t_ct(x: u32) -> u32 {
    l(tau_ct(x))
}

#[inline(always)]
fn t_prime_ct(x: u32) -> u32 {
    l_prime(tau_ct(x))
}

fn expand_round_keys(key: &[u8; 16]) -> ([u32; 32], [u32; 32]) {
    let mut k = [0u32; 36];
    for i in 0..4 {
        let mk = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
        k[i] = mk ^ FK[i];
    }

    let mut enc = [0u32; 32];
    for i in 0..32 {
        k[i + 4] = k[i] ^ t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        enc[i] = k[i + 4];
    }

    let mut dec = enc;
    dec.reverse();
    (enc, dec)
}

fn expand_round_keys_ct(key: &[u8; 16]) -> ([u32; 32], [u32; 32]) {
    let mut k = [0u32; 36];
    for i in 0..4 {
        let mk = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
        k[i] = mk ^ FK[i];
    }

    let mut enc = [0u32; 32];
    for i in 0..32 {
        k[i + 4] = k[i] ^ t_prime_ct(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        enc[i] = k[i + 4];
    }

    let mut dec = enc;
    dec.reverse();
    (enc, dec)
}

#[inline]
fn sm4_core(block: &[u8; 16], rk: &[u32; 32]) -> [u8; 16] {
    let mut x0 = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut x1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let mut x2 = u32::from_be_bytes(block[8..12].try_into().unwrap());
    let mut x3 = u32::from_be_bytes(block[12..16].try_into().unwrap());

    for &rki in rk.iter() {
        let x4 = x0 ^ t(x1 ^ x2 ^ x3 ^ rki);
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&x3.to_be_bytes());
    out[4..8].copy_from_slice(&x2.to_be_bytes());
    out[8..12].copy_from_slice(&x1.to_be_bytes());
    out[12..16].copy_from_slice(&x0.to_be_bytes());
    out
}

#[inline]
fn sm4_core_ct(block: &[u8; 16], rk: &[u32; 32]) -> [u8; 16] {
    let mut x0 = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut x1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let mut x2 = u32::from_be_bytes(block[8..12].try_into().unwrap());
    let mut x3 = u32::from_be_bytes(block[12..16].try_into().unwrap());

    for &rki in rk.iter() {
        let x4 = x0 ^ t_ct(x1 ^ x2 ^ x3 ^ rki);
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&x3.to_be_bytes());
    out[4..8].copy_from_slice(&x2.to_be_bytes());
    out[8..12].copy_from_slice(&x1.to_be_bytes());
    out[12..16].copy_from_slice(&x0.to_be_bytes());
    out
}

/// SM4 block cipher (formerly SMS4).
pub struct Sm4 {
    enc_rk: [u32; 32],
    dec_rk: [u32; 32],
}

/// SM4 constant-time software path using the packed ANF S-box form.
pub struct Sm4Ct {
    enc_rk: [u32; 32],
    dec_rk: [u32; 32],
}

/// Historical SMS4 name retained as an alias.
pub type Sms4 = Sm4;
/// Historical SMS4 name retained for the constant-time path as well.
pub type Sms4Ct = Sm4Ct;

impl Sm4 {
    /// Construct SM4 from a 128-bit key.
    pub fn new(key: &[u8; 16]) -> Self {
        let (enc_rk, dec_rk) = expand_round_keys(key);
        Self { enc_rk, dec_rk }
    }

    /// Construct SM4 and wipe the caller-provided key buffer.
    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt one 128-bit block.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        sm4_core(block, &self.enc_rk)
    }

    /// Decrypt one 128-bit block.
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        sm4_core(block, &self.dec_rk)
    }
}

impl Sm4Ct {
    /// Construct SM4Ct from a 128-bit key.
    pub fn new(key: &[u8; 16]) -> Self {
        let (enc_rk, dec_rk) = expand_round_keys_ct(key);
        Self { enc_rk, dec_rk }
    }

    /// Construct SM4Ct and wipe the caller-provided key buffer.
    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt one 128-bit block.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        sm4_core_ct(block, &self.enc_rk)
    }

    /// Decrypt one 128-bit block.
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        sm4_core_ct(block, &self.dec_rk)
    }
}

impl crate::BlockCipher for Sm4 {
    const BLOCK_LEN: usize = 16;

    fn encrypt(&self, block: &mut [u8]) {
        assert_eq!(block.len(), Self::BLOCK_LEN);
        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(block);
        block.copy_from_slice(&self.encrypt_block(&tmp));
    }

    fn decrypt(&self, block: &mut [u8]) {
        assert_eq!(block.len(), Self::BLOCK_LEN);
        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(block);
        block.copy_from_slice(&self.decrypt_block(&tmp));
    }
}

impl crate::BlockCipher for Sm4Ct {
    const BLOCK_LEN: usize = 16;

    fn encrypt(&self, block: &mut [u8]) {
        assert_eq!(block.len(), Self::BLOCK_LEN);
        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(block);
        block.copy_from_slice(&self.encrypt_block(&tmp));
    }

    fn decrypt(&self, block: &mut [u8]) {
        assert_eq!(block.len(), Self::BLOCK_LEN);
        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(block);
        block.copy_from_slice(&self.decrypt_block(&tmp));
    }
}

impl Drop for Sm4 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.enc_rk.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_rk.as_mut_slice());
    }
}

impl Drop for Sm4Ct {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.enc_rk.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_rk.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    #[test]
    fn example_1_encrypt_decrypt() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let pt: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let ct: [u8; 16] = parse("681edf34d206965e86b3e94f536e4246");

        let sm4 = Sm4::new(&key);
        assert_eq!(sm4.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(sm4.decrypt_block(&ct), pt, "decrypt");
    }

    #[test]
    fn example_1_encrypt_decrypt_ct() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let pt: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let ct: [u8; 16] = parse("681edf34d206965e86b3e94f536e4246");

        let sm4 = Sm4Ct::new(&key);
        assert_eq!(sm4.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(sm4.decrypt_block(&ct), pt, "decrypt");
    }

    #[test]
    fn example_2_million_encryptions() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let mut block: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let expected: [u8; 16] = parse("595298c7c6fd271f0402f804c33d3f66");

        let sm4 = Sm4::new(&key);
        for _ in 0..1_000_000 {
            block = sm4.encrypt_block(&block);
        }

        assert_eq!(block, expected);
    }

    #[test]
    fn example_2_million_encryptions_ct() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let mut block: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let expected: [u8; 16] = parse("595298c7c6fd271f0402f804c33d3f66");

        let sm4 = Sm4Ct::new(&key);
        for _ in 0..1_000_000 {
            block = sm4.encrypt_block(&block);
        }

        assert_eq!(block, expected);
    }

    #[test]
    fn sms4_alias_matches_sm4() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let pt: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let a = Sm4::new(&key);
        let b = Sms4::new(&key);
        assert_eq!(a.encrypt_block(&pt), b.encrypt_block(&pt));
    }

    #[test]
    fn sms4_ct_alias_matches_sm4_ct() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let pt: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let a = Sm4Ct::new(&key);
        let b = Sms4Ct::new(&key);
        assert_eq!(a.encrypt_block(&pt), b.encrypt_block(&pt));
    }

    #[test]
    fn ct_sbox_matches_table() {
        for x in 0u16..=255 {
            let b = x as u8;
            assert_eq!(sbox_ct_byte(b), SBOX[x as usize], "sbox {x:02x}");
        }
    }

    #[test]
    fn sm4_and_sm4ct_match() {
        let key: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let pt: [u8; 16] = parse("0123456789abcdeffedcba9876543210");
        let fast = Sm4::new(&key);
        let slow = Sm4Ct::new(&key);
        assert_eq!(fast.encrypt_block(&pt), slow.encrypt_block(&pt));
    }
}
