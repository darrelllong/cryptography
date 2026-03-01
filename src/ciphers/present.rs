//! PRESENT lightweight block cipher — CHES 2007 / ISO/IEC 29192-2.
//!
//! 64-bit block cipher with two standard key schedules:
//!
//! - `Present80` / `Present80Ct`: 80-bit key
//! - `Present128` / `Present128Ct`: 128-bit key
//!
//! The round structure is a 31-round SP-network:
//!
//! ```text
//! state <- state xor round_key
//! state <- sbox_layer(state)
//! state <- p_layer(state)
//! ```
//!
//! followed by a final round-key xor. The fast path keeps the direct 4-bit
//! S-box table lookup. The Ct path uses a packed 16-term ANF form of the same
//! 4->4 bijection so substitution avoids secret-indexed table reads while the
//! rest of the permutation network stays unchanged.

const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];
const INV_SBOX: [u8; 16] = [
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA,
];

const SBOX_ANF: [u16; 4] = crate::ct::build_nibble_sbox_anf(&SBOX);
const INV_SBOX_ANF: [u16; 4] = crate::ct::build_nibble_sbox_anf(&INV_SBOX);

#[inline]
fn sbox_ct_nibble(input: u8) -> u8 {
    crate::ct::eval_nibble_sbox(SBOX_ANF, input)
}

#[inline]
fn inv_sbox_ct_nibble(input: u8) -> u8 {
    crate::ct::eval_nibble_sbox(INV_SBOX_ANF, input)
}

#[inline]
fn sbox_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as usize;
        out |= u64::from(SBOX[nibble]) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn inv_sbox_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as usize;
        out |= u64::from(INV_SBOX[nibble]) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn sbox_layer_ct(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as u8;
        out |= u64::from(sbox_ct_nibble(nibble)) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn inv_sbox_layer_ct(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as u8;
        out |= u64::from(inv_sbox_ct_nibble(nibble)) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn p_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut bit = 0usize;
    while bit < 63 {
        let dst = (16 * bit) % 63;
        out |= ((state >> bit) & 1) << dst;
        bit += 1;
    }
    out |= ((state >> 63) & 1) << 63;
    out
}

#[inline]
fn inv_p_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut bit = 0usize;
    while bit < 63 {
        let src = (16 * bit) % 63;
        out |= ((state >> src) & 1) << bit;
        bit += 1;
    }
    out |= ((state >> 63) & 1) << 63;
    out
}

fn present_encrypt(state: u64, round_keys: &[u64; 32]) -> u64 {
    let mut s = state;
    let mut round = 0usize;
    while round < 31 {
        s ^= round_keys[round];
        s = sbox_layer(s);
        s = p_layer(s);
        round += 1;
    }
    s ^ round_keys[31]
}

fn present_encrypt_ct(state: u64, round_keys: &[u64; 32]) -> u64 {
    let mut s = state;
    let mut round = 0usize;
    while round < 31 {
        s ^= round_keys[round];
        s = sbox_layer_ct(s);
        s = p_layer(s);
        round += 1;
    }
    s ^ round_keys[31]
}

fn present_decrypt(state: u64, round_keys: &[u64; 32]) -> u64 {
    let mut s = state ^ round_keys[31];
    let mut round = 31usize;
    while round > 0 {
        round -= 1;
        s = inv_p_layer(s);
        s = inv_sbox_layer(s);
        s ^= round_keys[round];
    }
    s
}

fn present_decrypt_ct(state: u64, round_keys: &[u64; 32]) -> u64 {
    let mut s = state ^ round_keys[31];
    let mut round = 31usize;
    while round > 0 {
        round -= 1;
        s = inv_p_layer(s);
        s = inv_sbox_layer_ct(s);
        s ^= round_keys[round];
    }
    s
}

fn expand_round_keys_80(key: &[u8; 10]) -> [u64; 32] {
    let mut reg = 0u128;
    for &b in key {
        reg = (reg << 8) | u128::from(b);
    }

    let mask80 = (1u128 << 80) - 1;
    let mut out = [0u64; 32];

    for round in 1..=32u8 {
        out[(round - 1) as usize] = ((reg >> 16) & 0xffff_ffff_ffff_ffff) as u64;
        if round == 32 {
            break;
        }

        reg = ((reg << 61) | (reg >> 19)) & mask80;
        let top = ((reg >> 76) & 0x0f) as usize;
        reg &= !(0x0fu128 << 76);
        reg |= u128::from(SBOX[top]) << 76;
        reg ^= u128::from(round) << 15;
    }

    out
}

fn expand_round_keys_128(key: &[u8; 16]) -> [u64; 32] {
    let mut reg = u128::from_be_bytes(*key);
    let mut out = [0u64; 32];

    for round in 1..=32u8 {
        out[(round - 1) as usize] = (reg >> 64) as u64;
        if round == 32 {
            break;
        }

        reg = reg.rotate_left(61);

        let top = ((reg >> 124) & 0x0f) as usize;
        reg &= !(0x0fu128 << 124);
        reg |= u128::from(SBOX[top]) << 124;

        let next = ((reg >> 120) & 0x0f) as usize;
        reg &= !(0x0fu128 << 120);
        reg |= u128::from(SBOX[next]) << 120;

        reg ^= u128::from(round) << 62;
    }

    out
}

/// PRESENT-80 fast software path.
pub struct Present80 {
    round_keys: [u64; 32],
}

impl Present80 {
    #[must_use]
    pub fn new(key: &[u8; 10]) -> Self {
        Self {
            round_keys: expand_round_keys_80(key),
        }
    }

    pub fn new_wiping(key: &mut [u8; 10]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_encrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_decrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// PRESENT-80 constant-time software path.
pub struct Present80Ct {
    round_keys: [u64; 32],
}

impl Present80Ct {
    #[must_use]
    pub fn new(key: &[u8; 10]) -> Self {
        Self {
            round_keys: expand_round_keys_80(key),
        }
    }

    pub fn new_wiping(key: &mut [u8; 10]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_encrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_decrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// PRESENT-128 fast software path.
pub struct Present128 {
    round_keys: [u64; 32],
}

impl Present128 {
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: expand_round_keys_128(key),
        }
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_encrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_decrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// PRESENT-128 constant-time software path.
pub struct Present128Ct {
    round_keys: [u64; 32],
}

impl Present128Ct {
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: expand_round_keys_128(key),
        }
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_encrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        present_decrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// The original PRESENT instantiation from the CHES 2007 paper (80-bit key).
pub type Present = Present80;
/// Constant-time PRESENT-80 alias.
pub type PresentCt = Present80Ct;

macro_rules! impl_block_cipher {
    ($name:ty) => {
        impl crate::BlockCipher for $name {
            const BLOCK_LEN: usize = 8;
            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.encrypt_block(arr));
            }
            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.decrypt_block(arr));
            }
        }
    };
}

impl_block_cipher!(Present80);
impl_block_cipher!(Present80Ct);
impl_block_cipher!(Present128);
impl_block_cipher!(Present128Ct);

macro_rules! impl_drop_zeroize {
    ($name:ty) => {
        impl Drop for $name {
            fn drop(&mut self) {
                crate::ct::zeroize_slice(self.round_keys.as_mut_slice());
            }
        }
    };
}

impl_drop_zeroize!(Present80);
impl_drop_zeroize!(Present80Ct);
impl_drop_zeroize!(Present128);
impl_drop_zeroize!(Present128Ct);

#[cfg(test)]
mod tests {
    use super::*;

    fn h8(s: &str) -> [u8; 8] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    fn h10(s: &str) -> [u8; 10] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    fn h16(s: &str) -> [u8; 16] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    #[test]
    fn ct_sbox_matches_tables() {
        for x in 0u8..16 {
            assert_eq!(sbox_ct_nibble(x), SBOX[x as usize]);
            assert_eq!(inv_sbox_ct_nibble(x), INV_SBOX[x as usize]);
        }
    }

    #[test]
    fn present80_kats() {
        // CHES 2007 Appendix I.
        let cases = [
            (
                h10("00000000000000000000"),
                h8("0000000000000000"),
                h8("5579c1387b228445"),
            ),
            (
                h10("ffffffffffffffffffff"),
                h8("0000000000000000"),
                h8("e72c46c0f5945049"),
            ),
            (
                h10("00000000000000000000"),
                h8("ffffffffffffffff"),
                h8("a112ffc72f68417b"),
            ),
            (
                h10("ffffffffffffffffffff"),
                h8("ffffffffffffffff"),
                h8("3333dcd3213210d2"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Present80::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    #[test]
    fn present80_ct_kats() {
        let cases = [
            (
                h10("00000000000000000000"),
                h8("0000000000000000"),
                h8("5579c1387b228445"),
            ),
            (
                h10("ffffffffffffffffffff"),
                h8("0000000000000000"),
                h8("e72c46c0f5945049"),
            ),
            (
                h10("00000000000000000000"),
                h8("ffffffffffffffff"),
                h8("a112ffc72f68417b"),
            ),
            (
                h10("ffffffffffffffffffff"),
                h8("ffffffffffffffff"),
                h8("3333dcd3213210d2"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Present80Ct::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    #[test]
    fn present128_kats() {
        // Commonly cited four-corner vectors for the 128-bit schedule.
        let cases = [
            (
                h16("00000000000000000000000000000000"),
                h8("0000000000000000"),
                h8("96db702a2e6900af"),
            ),
            (
                h16("ffffffffffffffffffffffffffffffff"),
                h8("0000000000000000"),
                h8("13238c710272a5d8"),
            ),
            (
                h16("00000000000000000000000000000000"),
                h8("ffffffffffffffff"),
                h8("3c6019e5e5edd563"),
            ),
            (
                h16("ffffffffffffffffffffffffffffffff"),
                h8("ffffffffffffffff"),
                h8("628d9fbd4218e5b4"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Present128::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    #[test]
    fn present128_ct_kats() {
        let cases = [
            (
                h16("00000000000000000000000000000000"),
                h8("0000000000000000"),
                h8("96db702a2e6900af"),
            ),
            (
                h16("ffffffffffffffffffffffffffffffff"),
                h8("0000000000000000"),
                h8("13238c710272a5d8"),
            ),
            (
                h16("00000000000000000000000000000000"),
                h8("ffffffffffffffff"),
                h8("3c6019e5e5edd563"),
            ),
            (
                h16("ffffffffffffffffffffffffffffffff"),
                h8("ffffffffffffffff"),
                h8("628d9fbd4218e5b4"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Present128Ct::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }
}
