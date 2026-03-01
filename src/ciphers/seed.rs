//! SEED block cipher — RFC 4009 / RFC 4196.
//!
//! 128-bit block, 128-bit key, 16-round Feistel network.
//!
//! `Seed` keeps the direct 8-bit S-box lookups from the published Korean
//! standard design. `SeedCt` evaluates the same two 8-bit S-boxes in packed
//! ANF form so the round function and key schedule avoid secret-indexed table
//! reads.

const M0: u8 = 0xfc;
const M1: u8 = 0xf3;
const M2: u8 = 0xcf;
const M3: u8 = 0x3f;

#[rustfmt::skip]
const S0: [u8; 256] = [
    0xA9, 0x85, 0xD6, 0xD3, 0x54, 0x1D, 0xAC, 0x25, 0x5D, 0x43, 0x18, 0x1E, 0x51, 0xFC, 0xCA, 0x63,
    0x28, 0x44, 0x20, 0x9D, 0xE0, 0xE2, 0xC8, 0x17, 0xA5, 0x8F, 0x03, 0x7B, 0xBB, 0x13, 0xD2, 0xEE,
    0x70, 0x8C, 0x3F, 0xA8, 0x32, 0xDD, 0xF6, 0x74, 0xEC, 0x95, 0x0B, 0x57, 0x5C, 0x5B, 0xBD, 0x01,
    0x24, 0x1C, 0x73, 0x98, 0x10, 0xCC, 0xF2, 0xD9, 0x2C, 0xE7, 0x72, 0x83, 0x9B, 0xD1, 0x86, 0xC9,
    0x60, 0x50, 0xA3, 0xEB, 0x0D, 0xB6, 0x9E, 0x4F, 0xB7, 0x5A, 0xC6, 0x78, 0xA6, 0x12, 0xAF, 0xD5,
    0x61, 0xC3, 0xB4, 0x41, 0x52, 0x7D, 0x8D, 0x08, 0x1F, 0x99, 0x00, 0x19, 0x04, 0x53, 0xF7, 0xE1,
    0xFD, 0x76, 0x2F, 0x27, 0xB0, 0x8B, 0x0E, 0xAB, 0xA2, 0x6E, 0x93, 0x4D, 0x69, 0x7C, 0x09, 0x0A,
    0xBF, 0xEF, 0xF3, 0xC5, 0x87, 0x14, 0xFE, 0x64, 0xDE, 0x2E, 0x4B, 0x1A, 0x06, 0x21, 0x6B, 0x66,
    0x02, 0xF5, 0x92, 0x8A, 0x0C, 0xB3, 0x7E, 0xD0, 0x7A, 0x47, 0x96, 0xE5, 0x26, 0x80, 0xAD, 0xDF,
    0xA1, 0x30, 0x37, 0xAE, 0x36, 0x15, 0x22, 0x38, 0xF4, 0xA7, 0x45, 0x4C, 0x81, 0xE9, 0x84, 0x97,
    0x35, 0xCB, 0xCE, 0x3C, 0x71, 0x11, 0xC7, 0x89, 0x75, 0xFB, 0xDA, 0xF8, 0x94, 0x59, 0x82, 0xC4,
    0xFF, 0x49, 0x39, 0x67, 0xC0, 0xCF, 0xD7, 0xB8, 0x0F, 0x8E, 0x42, 0x23, 0x91, 0x6C, 0xDB, 0xA4,
    0x34, 0xF1, 0x48, 0xC2, 0x6F, 0x3D, 0x2D, 0x40, 0xBE, 0x3E, 0xBC, 0xC1, 0xAA, 0xBA, 0x4E, 0x55,
    0x3B, 0xDC, 0x68, 0x7F, 0x9C, 0xD8, 0x4A, 0x56, 0x77, 0xA0, 0xED, 0x46, 0xB5, 0x2B, 0x65, 0xFA,
    0xE3, 0xB9, 0xB1, 0x9F, 0x5E, 0xF9, 0xE6, 0xB2, 0x31, 0xEA, 0x6D, 0x5F, 0xE4, 0xF0, 0xCD, 0x88,
    0x16, 0x3A, 0x58, 0xD4, 0x62, 0x29, 0x07, 0x33, 0xE8, 0x1B, 0x05, 0x79, 0x90, 0x6A, 0x2A, 0x9A,
];

#[rustfmt::skip]
const S1: [u8; 256] = [
    0x38, 0xE8, 0x2D, 0xA6, 0xCF, 0xDE, 0xB3, 0xB8, 0xAF, 0x60, 0x55, 0xC7, 0x44, 0x6F, 0x6B, 0x5B,
    0xC3, 0x62, 0x33, 0xB5, 0x29, 0xA0, 0xE2, 0xA7, 0xD3, 0x91, 0x11, 0x06, 0x1C, 0xBC, 0x36, 0x4B,
    0xEF, 0x88, 0x6C, 0xA8, 0x17, 0xC4, 0x16, 0xF4, 0xC2, 0x45, 0xE1, 0xD6, 0x3F, 0x3D, 0x8E, 0x98,
    0x28, 0x4E, 0xF6, 0x3E, 0xA5, 0xF9, 0x0D, 0xDF, 0xD8, 0x2B, 0x66, 0x7A, 0x27, 0x2F, 0xF1, 0x72,
    0x42, 0xD4, 0x41, 0xC0, 0x73, 0x67, 0xAC, 0x8B, 0xF7, 0xAD, 0x80, 0x1F, 0xCA, 0x2C, 0xAA, 0x34,
    0xD2, 0x0B, 0xEE, 0xE9, 0x5D, 0x94, 0x18, 0xF8, 0x57, 0xAE, 0x08, 0xC5, 0x13, 0xCD, 0x86, 0xB9,
    0xFF, 0x7D, 0xC1, 0x31, 0xF5, 0x8A, 0x6A, 0xB1, 0xD1, 0x20, 0xD7, 0x02, 0x22, 0x04, 0x68, 0x71,
    0x07, 0xDB, 0x9D, 0x99, 0x61, 0xBE, 0xE6, 0x59, 0xDD, 0x51, 0x90, 0xDC, 0x9A, 0xA3, 0xAB, 0xD0,
    0x81, 0x0F, 0x47, 0x1A, 0xE3, 0xEC, 0x8D, 0xBF, 0x96, 0x7B, 0x5C, 0xA2, 0xA1, 0x63, 0x23, 0x4D,
    0xC8, 0x9E, 0x9C, 0x3A, 0x0C, 0x2E, 0xBA, 0x6E, 0x9F, 0x5A, 0xF2, 0x92, 0xF3, 0x49, 0x78, 0xCC,
    0x15, 0xFB, 0x70, 0x75, 0x7F, 0x35, 0x10, 0x03, 0x64, 0x6D, 0xC6, 0x74, 0xD5, 0xB4, 0xEA, 0x09,
    0x76, 0x19, 0xFE, 0x40, 0x12, 0xE0, 0xBD, 0x05, 0xFA, 0x01, 0xF0, 0x2A, 0x5E, 0xA9, 0x56, 0x43,
    0x85, 0x14, 0x89, 0x9B, 0xB0, 0xE5, 0x48, 0x79, 0x97, 0xFC, 0x1E, 0x82, 0x21, 0x8C, 0x1B, 0x5F,
    0x77, 0x54, 0xB2, 0x1D, 0x25, 0x4F, 0x00, 0x46, 0xED, 0x58, 0x52, 0xEB, 0x7E, 0xDA, 0xC9, 0xFD,
    0x30, 0x95, 0x65, 0x3C, 0xB6, 0xE4, 0xBB, 0x7C, 0x0E, 0x50, 0x39, 0x26, 0x32, 0x84, 0x69, 0x93,
    0x37, 0xE7, 0x24, 0xA4, 0xCB, 0x53, 0x0A, 0x87, 0xD9, 0x4C, 0x83, 0x8F, 0xCE, 0x3B, 0x4A, 0xB7,
];

const KC: [u32; 16] = [
    0x9e37_79b9,
    0x3c6e_f373,
    0x78dd_e6e6,
    0xf1bb_cdcc,
    0xe377_9b99,
    0xc6ef_3733,
    0x8dde_6e67,
    0x1bbc_dccf,
    0x3779_b99e,
    0x6ef3_733c,
    0xdde6_e678,
    0xbbcd_ccf1,
    0x779b_99e3,
    0xef37_33c6,
    0xde6e_678d,
    0xbcdc_cf1b,
];

const S0_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&S0);
const S1_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&S1);

#[inline(always)]
fn s0_ct(x: u8) -> u8 {
    crate::ct::eval_byte_sbox(&S0_ANF, x)
}

#[inline(always)]
fn s1_ct(x: u8) -> u8 {
    crate::ct::eval_byte_sbox(&S1_ANF, x)
}

#[inline(always)]
fn g(x: u32) -> u32 {
    let [x0, x1, x2, x3] = x.to_le_bytes();
    let a0 = S0[x0 as usize];
    let a1 = S1[x1 as usize];
    let a2 = S0[x2 as usize];
    let a3 = S1[x3 as usize];
    u32::from_le_bytes([
        (a0 & M0) ^ (a1 & M1) ^ (a2 & M2) ^ (a3 & M3),
        (a0 & M1) ^ (a1 & M2) ^ (a2 & M3) ^ (a3 & M0),
        (a0 & M2) ^ (a1 & M3) ^ (a2 & M0) ^ (a3 & M1),
        (a0 & M3) ^ (a1 & M0) ^ (a2 & M1) ^ (a3 & M2),
    ])
}

#[inline(always)]
fn g_ct(x: u32) -> u32 {
    let [x0, x1, x2, x3] = x.to_le_bytes();
    let a0 = s0_ct(x0);
    let a1 = s1_ct(x1);
    let a2 = s0_ct(x2);
    let a3 = s1_ct(x3);
    u32::from_le_bytes([
        (a0 & M0) ^ (a1 & M1) ^ (a2 & M2) ^ (a3 & M3),
        (a0 & M1) ^ (a1 & M2) ^ (a2 & M3) ^ (a3 & M0),
        (a0 & M2) ^ (a1 & M3) ^ (a2 & M0) ^ (a3 & M1),
        (a0 & M3) ^ (a1 & M0) ^ (a2 & M1) ^ (a3 & M2),
    ])
}

#[inline(always)]
fn round_f(r0: u32, r1: u32, k0: u32, k1: u32, use_ct: bool) -> (u32, u32) {
    let apply_g = if use_ct { g_ct } else { g };

    let mut t0 = r0 ^ k0;
    let mut t1 = r1 ^ k1;
    t1 ^= t0;
    t1 = apply_g(t1);
    t0 = t0.wrapping_add(t1);
    t0 = apply_g(t0);
    t1 = t1.wrapping_add(t0);
    t1 = apply_g(t1);
    t0 = t0.wrapping_add(t1);
    (t0, t1)
}

fn expand_round_keys(key: &[u8; 16], use_ct: bool) -> [u32; 32] {
    let mut k0 = u32::from_be_bytes(key[..4].try_into().unwrap());
    let mut k1 = u32::from_be_bytes(key[4..8].try_into().unwrap());
    let mut k2 = u32::from_be_bytes(key[8..12].try_into().unwrap());
    let mut k3 = u32::from_be_bytes(key[12..].try_into().unwrap());

    let apply_g = if use_ct { g_ct } else { g };
    let mut out = [0u32; 32];

    let mut i = 0usize;
    while i < 16 {
        out[2 * i] = apply_g(k0.wrapping_add(k2).wrapping_sub(KC[i]));
        out[2 * i + 1] = apply_g(k1.wrapping_sub(k3).wrapping_add(KC[i]));

        if i % 2 == 0 {
            let pair = ((k0 as u64) << 32) | (k1 as u64);
            let rot = pair.rotate_right(8);
            k0 = (rot >> 32) as u32;
            k1 = rot as u32;
        } else {
            let pair = ((k2 as u64) << 32) | (k3 as u64);
            let rot = pair.rotate_left(8);
            k2 = (rot >> 32) as u32;
            k3 = rot as u32;
        }

        i += 1;
    }

    out
}

fn seed_encrypt(block: [u8; 16], round_keys: &[u32; 32], use_ct: bool) -> [u8; 16] {
    let mut l0 = u32::from_be_bytes(block[..4].try_into().unwrap());
    let mut l1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let mut r0 = u32::from_be_bytes(block[8..12].try_into().unwrap());
    let mut r1 = u32::from_be_bytes(block[12..].try_into().unwrap());

    let mut i = 0usize;
    while i < 16 {
        let (f0, f1) = round_f(r0, r1, round_keys[2 * i], round_keys[2 * i + 1], use_ct);
        let new_l0 = r0;
        let new_l1 = r1;
        let new_r0 = l0 ^ f0;
        let new_r1 = l1 ^ f1;
        l0 = new_l0;
        l1 = new_l1;
        r0 = new_r0;
        r1 = new_r1;
        i += 1;
    }

    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&r0.to_be_bytes());
    out[4..8].copy_from_slice(&r1.to_be_bytes());
    out[8..12].copy_from_slice(&l0.to_be_bytes());
    out[12..].copy_from_slice(&l1.to_be_bytes());
    out
}

fn seed_decrypt(block: [u8; 16], round_keys: &[u32; 32], use_ct: bool) -> [u8; 16] {
    let mut r0 = u32::from_be_bytes(block[..4].try_into().unwrap());
    let mut r1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let mut l0 = u32::from_be_bytes(block[8..12].try_into().unwrap());
    let mut l1 = u32::from_be_bytes(block[12..].try_into().unwrap());

    let mut i = 16usize;
    while i > 0 {
        i -= 1;
        let (f0, f1) = round_f(l0, l1, round_keys[2 * i], round_keys[2 * i + 1], use_ct);
        let prev_r0 = l0;
        let prev_r1 = l1;
        let prev_l0 = r0 ^ f0;
        let prev_l1 = r1 ^ f1;
        l0 = prev_l0;
        l1 = prev_l1;
        r0 = prev_r0;
        r1 = prev_r1;
    }

    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&l0.to_be_bytes());
    out[4..8].copy_from_slice(&l1.to_be_bytes());
    out[8..12].copy_from_slice(&r0.to_be_bytes());
    out[12..].copy_from_slice(&r1.to_be_bytes());
    out
}

/// SEED fast software path.
pub struct Seed {
    round_keys: [u32; 32],
}

impl Seed {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: expand_round_keys(key, false),
        }
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        seed_encrypt(*block, &self.round_keys, false)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        seed_decrypt(*block, &self.round_keys, false)
    }
}

/// SEED constant-time software path.
pub struct SeedCt {
    round_keys: [u32; 32],
}

impl SeedCt {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: expand_round_keys(key, true),
        }
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        seed_encrypt(*block, &self.round_keys, true)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        seed_decrypt(*block, &self.round_keys, true)
    }
}

impl crate::BlockCipher for Seed {
    const BLOCK_LEN: usize = 16;
    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.encrypt_block(arr));
    }
    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.decrypt_block(arr));
    }
}

impl crate::BlockCipher for SeedCt {
    const BLOCK_LEN: usize = 16;
    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.encrypt_block(arr));
    }
    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.decrypt_block(arr));
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.round_keys.as_mut_slice());
    }
}

impl Drop for SeedCt {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.round_keys.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h16(s: &str) -> [u8; 16] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for x in 0u8..=255 {
            assert_eq!(s0_ct(x), S0[x as usize]);
            assert_eq!(s1_ct(x), S1[x as usize]);
        }
    }

    #[test]
    fn round_keys_zero_key_match_rfc() {
        let rk = expand_round_keys(&[0u8; 16], false);
        assert_eq!(rk[0], 0x7c8f_8c7e);
        assert_eq!(rk[1], 0xc737_a22c);
        assert_eq!(rk[30], 0x7189_1150);
        assert_eq!(rk[31], 0x98b2_55b0);
    }

    #[test]
    fn seed_kats() {
        let cases = [
            (
                h16("00000000000000000000000000000000"),
                h16("000102030405060708090a0b0c0d0e0f"),
                h16("5ebac6e0054e166819aff1cc6d346cdb"),
            ),
            (
                h16("000102030405060708090a0b0c0d0e0f"),
                h16("00000000000000000000000000000000"),
                h16("c11f22f20140505084483597e4370f43"),
            ),
            (
                h16("4706480851e61be85d74bfb3fd956185"),
                h16("83a2f8a288641fb9a4e9a5cc2f131c7d"),
                h16("ee54d13ebcae706d226bc3142cd40d4a"),
            ),
            (
                h16("28dbc3bc49ffd87dcfa509b11d422be7"),
                h16("b41e6be2eba84a148e2eed84593c5ec7"),
                h16("9b9b7bfcd1813cb95d0b3618f40f5122"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Seed::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    #[test]
    fn seed_ct_kats() {
        let cases = [
            (
                h16("00000000000000000000000000000000"),
                h16("000102030405060708090a0b0c0d0e0f"),
                h16("5ebac6e0054e166819aff1cc6d346cdb"),
            ),
            (
                h16("000102030405060708090a0b0c0d0e0f"),
                h16("00000000000000000000000000000000"),
                h16("c11f22f20140505084483597e4370f43"),
            ),
            (
                h16("4706480851e61be85d74bfb3fd956185"),
                h16("83a2f8a288641fb9a4e9a5cc2f131c7d"),
                h16("ee54d13ebcae706d226bc3142cd40d4a"),
            ),
            (
                h16("28dbc3bc49ffd87dcfa509b11d422be7"),
                h16("b41e6be2eba84a148e2eed84593c5ec7"),
                h16("9b9b7bfcd1813cb95d0b3618f40f5122"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = SeedCt::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }
}
