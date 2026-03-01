//! Twofish block cipher — AES submission (1998).
//!
//! 128-bit block cipher with the three standard key sizes:
//!
//! - `Twofish128` / `Twofish128Ct`
//! - `Twofish192` / `Twofish192Ct`
//! - `Twofish256` / `Twofish256Ct`
//!
//! The fast path keeps direct lookup tables for the 8-bit `q0` / `q1`
//! permutations used inside the keyed `h` function. `Ct` variants evaluate the
//! same permutations from the published 4-bit building blocks with fixed-scan
//! nibble selection so the round function and key schedule avoid
//! secret-indexed table reads.

use crate::ct::zeroize_slice;
use crate::BlockCipher;

const RHO: u32 = 0x0101_0101;
const GF_POLY: u16 = 0x0169;

const Q0_T0: [u8; 16] = [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4];
const Q0_T1: [u8; 16] = [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13];
const Q0_T2: [u8; 16] = [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1];
const Q0_T3: [u8; 16] = [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10];

const Q1_T0: [u8; 16] = [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5];
const Q1_T1: [u8; 16] = [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8];
const Q1_T2: [u8; 16] = [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15];
const Q1_T3: [u8; 16] = [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10];

const RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];

const MDS: [[u8; 4]; 4] = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
];

#[inline]
const fn nibble_lookup(table: &[u8; 16], idx: u8) -> u8 {
    table[idx as usize]
}

#[inline]
const fn ror4(x: u8) -> u8 {
    ((x >> 1) | ((x & 1) << 3)) & 0x0f
}

// Twofish defines q0 / q1 as nibble permutations built from four 4-bit
// lookup stages. We keep that structure visible so the fast and `Ct` paths
// share the same logic and only differ in how each nibble is selected.
const fn q_perm_const(x: u8, which: usize) -> u8 {
    let (t0, t1, t2, t3) = if which == 0 {
        (&Q0_T0, &Q0_T1, &Q0_T2, &Q0_T3)
    } else {
        (&Q1_T0, &Q1_T1, &Q1_T2, &Q1_T3)
    };

    let a0 = x >> 4;
    let b0 = x & 0x0f;
    let a1 = a0 ^ b0;
    let b1 = a0 ^ ror4(b0) ^ ((a0 << 3) & 0x0f);
    let a2 = nibble_lookup(t0, a1);
    let b2 = nibble_lookup(t1, b1);
    let a3 = a2 ^ b2;
    let b3 = a2 ^ ror4(b2) ^ ((a2 << 3) & 0x0f);
    let a4 = nibble_lookup(t2, a3);
    let b4 = nibble_lookup(t3, b3);
    (b4 << 4) | a4
}

const fn build_q(which: usize) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0u8;
    loop {
        out[i as usize] = q_perm_const(i, which);
        if i == u8::MAX {
            break;
        }
        i = i.wrapping_add(1);
    }
    out
}

const Q0: [u8; 256] = build_q(0);
const Q1: [u8; 256] = build_q(1);

#[inline]
fn q_perm_ct(x: u8, which: usize) -> u8 {
    let (t0, t1, t2, t3) = if which == 0 {
        (&Q0_T0, &Q0_T1, &Q0_T2, &Q0_T3)
    } else {
        (&Q1_T0, &Q1_T1, &Q1_T2, &Q1_T3)
    };

    let a0 = x >> 4;
    let b0 = x & 0x0f;
    let a1 = a0 ^ b0;
    let b1 = a0 ^ ror4(b0) ^ ((a0 << 3) & 0x0f);
    let a2 = crate::ct::ct_lookup_u8_16(t0, a1);
    let b2 = crate::ct::ct_lookup_u8_16(t1, b1);
    let a3 = a2 ^ b2;
    let b3 = a2 ^ ror4(b2) ^ ((a2 << 3) & 0x0f);
    let a4 = crate::ct::ct_lookup_u8_16(t2, a3);
    let b4 = crate::ct::ct_lookup_u8_16(t3, b3);
    (b4 << 4) | a4
}

#[inline]
fn q_perm(x: u8, which: usize, use_ct: bool) -> u8 {
    if use_ct {
        q_perm_ct(x, which)
    } else if which == 0 {
        Q0[x as usize]
    } else {
        Q1[x as usize]
    }
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        out ^= a & mask;
        let hi = a & 0x80;
        a <<= 1;
        a ^= ((GF_POLY & 0xff) as u8) & 0u8.wrapping_sub((hi >> 7) & 1);
        b >>= 1;
    }
    out
}

fn rs_mds_encode(bytes: [u8; 8]) -> u32 {
    // The RS matrix compresses each 64-bit key chunk into one S-box key word.
    let mut out = [0u8; 4];
    let mut row = 0usize;
    while row < 4 {
        let mut acc = 0u8;
        let mut col = 0usize;
        while col < 8 {
            acc ^= gf_mul(RS[row][col], bytes[col]);
            col += 1;
        }
        out[row] = acc;
        row += 1;
    }
    u32::from_le_bytes(out)
}

#[inline]
fn b(word: u32, idx: usize) -> u8 {
    ((word >> (idx * 8)) & 0xff) as u8
}

fn mds_multiply(y: [u8; 4]) -> u32 {
    // Twofish's keyed `h()` function always ends with the fixed 4x4 MDS mix.
    let mut out = [0u8; 4];
    let mut row = 0usize;
    while row < 4 {
        let mut acc = 0u8;
        let mut col = 0usize;
        while col < 4 {
            acc ^= gf_mul(MDS[row][col], y[col]);
            col += 1;
        }
        out[row] = acc;
        row += 1;
    }
    u32::from_le_bytes(out)
}

fn h(x: u32, l: &[u32; 4], words: usize, use_ct: bool) -> u32 {
    let mut y = x.to_le_bytes();

    // Extra key words add extra q-permutation layers for 192- and 256-bit
    // keys before the shared 128-bit tail of the construction.
    if words == 4 {
        y[0] = q_perm(y[0], 1, use_ct) ^ b(l[3], 0);
        y[1] = q_perm(y[1], 0, use_ct) ^ b(l[3], 1);
        y[2] = q_perm(y[2], 0, use_ct) ^ b(l[3], 2);
        y[3] = q_perm(y[3], 1, use_ct) ^ b(l[3], 3);
    }
    if words >= 3 {
        y[0] = q_perm(y[0], 1, use_ct) ^ b(l[2], 0);
        y[1] = q_perm(y[1], 1, use_ct) ^ b(l[2], 1);
        y[2] = q_perm(y[2], 0, use_ct) ^ b(l[2], 2);
        y[3] = q_perm(y[3], 0, use_ct) ^ b(l[2], 3);
    }

    // The final three q layers are the common keyed core from the submission
    // paper. This implementation computes them directly instead of building
    // the large keyed MDS tables used by faster Twofish software.
    y[0] = q_perm(
        q_perm(q_perm(y[0], 0, use_ct) ^ b(l[1], 0), 0, use_ct) ^ b(l[0], 0),
        1,
        use_ct,
    );
    y[1] = q_perm(
        q_perm(q_perm(y[1], 1, use_ct) ^ b(l[1], 1), 0, use_ct) ^ b(l[0], 1),
        0,
        use_ct,
    );
    y[2] = q_perm(
        q_perm(q_perm(y[2], 0, use_ct) ^ b(l[1], 2), 1, use_ct) ^ b(l[0], 2),
        1,
        use_ct,
    );
    y[3] = q_perm(
        q_perm(q_perm(y[3], 1, use_ct) ^ b(l[1], 3), 1, use_ct) ^ b(l[0], 3),
        0,
        use_ct,
    );

    mds_multiply(y)
}

fn expand_key<const N: usize>(key: &[u8; N], use_ct: bool) -> ([u32; 40], [u32; 4], usize) {
    let words = N / 8;

    let mut me = [0u32; 4];
    let mut mo = [0u32; 4];
    let mut s_words = [0u32; 4];

    let mut word_idx = 0usize;
    while word_idx < words {
        // Even and odd 32-bit words feed separate `h()` calls in the subkey
        // schedule, while the RS matrix derives the S-box key words in reverse
        // chunk order.
        me[word_idx] = u32::from_le_bytes(key[word_idx * 8..word_idx * 8 + 4].try_into().unwrap());
        mo[word_idx] =
            u32::from_le_bytes(key[word_idx * 8 + 4..word_idx * 8 + 8].try_into().unwrap());
        let chunk: &[u8; 8] = key[word_idx * 8..word_idx * 8 + 8].try_into().unwrap();
        s_words[words - 1 - word_idx] = rs_mds_encode(*chunk);
        word_idx += 1;
    }

    let mut sub = [0u32; 40];
    let mut subkey_idx = 0usize;
    while subkey_idx < 20 {
        // K[0..3] are input whitening, K[4..7] output whitening, and the
        // remaining 32 words supply the 16 rounds.
        let even_input = u32::try_from(2 * subkey_idx).expect("subkey index fits in u32");
        let odd_input = even_input + 1;
        let even_g = h(even_input.wrapping_mul(RHO), &me, words, use_ct);
        let odd_g = h(odd_input.wrapping_mul(RHO), &mo, words, use_ct).rotate_left(8);
        sub[2 * subkey_idx] = even_g.wrapping_add(odd_g);
        sub[2 * subkey_idx + 1] = even_g
            .wrapping_add(odd_g.wrapping_add(odd_g))
            .rotate_left(9);
        subkey_idx += 1;
    }

    (sub, s_words, words)
}

#[inline]
fn round_f(
    x0: u32,
    x1: u32,
    subkeys: &[u32; 40],
    s: &[u32; 4],
    words: usize,
    round: usize,
    use_ct: bool,
) -> (u32, u32) {
    // Twofish's round function is the pair of keyed `g()` calls followed by
    // the pseudo-Hadamard transform and round subkey injection.
    let t0 = h(x0, s, words, use_ct);
    let t1 = h(x1.rotate_left(8), s, words, use_ct);
    let f0 = t0.wrapping_add(t1).wrapping_add(subkeys[8 + 2 * round]);
    let f1 = t0
        .wrapping_add(t1.wrapping_add(t1))
        .wrapping_add(subkeys[8 + 2 * round + 1]);
    (f0, f1)
}

#[derive(Clone, Copy)]
struct TwofishCore {
    subkeys: [u32; 40],
    s: [u32; 4],
    words: usize,
    use_ct: bool,
}

impl TwofishCore {
    fn new<const N: usize>(key: &[u8; N], use_ct: bool) -> Self {
        let (subkeys, s, words) = expand_key(key, use_ct);
        Self {
            subkeys,
            s,
            words,
            use_ct,
        }
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut x0 = u32::from_le_bytes(block[0..4].try_into().unwrap()) ^ self.subkeys[0];
        let mut x1 = u32::from_le_bytes(block[4..8].try_into().unwrap()) ^ self.subkeys[1];
        let mut x2 = u32::from_le_bytes(block[8..12].try_into().unwrap()) ^ self.subkeys[2];
        let mut x3 = u32::from_le_bytes(block[12..16].try_into().unwrap()) ^ self.subkeys[3];

        let mut round = 0usize;
        while round < 8 {
            // Two rounds are grouped per loop so the Feistel word swap stays
            // explicit without introducing a separate temporary block shuffle.
            let (f0, f1) = round_f(
                x0,
                x1,
                &self.subkeys,
                &self.s,
                self.words,
                2 * round,
                self.use_ct,
            );
            x2 = (x2 ^ f0).rotate_right(1);
            x3 = x3.rotate_left(1) ^ f1;

            let (f0, f1) = round_f(
                x2,
                x3,
                &self.subkeys,
                &self.s,
                self.words,
                2 * round + 1,
                self.use_ct,
            );
            x0 = (x0 ^ f0).rotate_right(1);
            x1 = x1.rotate_left(1) ^ f1;

            round += 1;
        }

        let c0 = x2 ^ self.subkeys[4];
        let c1 = x3 ^ self.subkeys[5];
        let c2 = x0 ^ self.subkeys[6];
        let c3 = x1 ^ self.subkeys[7];

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&c0.to_le_bytes());
        out[4..8].copy_from_slice(&c1.to_le_bytes());
        out[8..12].copy_from_slice(&c2.to_le_bytes());
        out[12..16].copy_from_slice(&c3.to_le_bytes());
        out
    }

    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut x2 = u32::from_le_bytes(block[0..4].try_into().unwrap()) ^ self.subkeys[4];
        let mut x3 = u32::from_le_bytes(block[4..8].try_into().unwrap()) ^ self.subkeys[5];
        let mut x0 = u32::from_le_bytes(block[8..12].try_into().unwrap()) ^ self.subkeys[6];
        let mut x1 = u32::from_le_bytes(block[12..16].try_into().unwrap()) ^ self.subkeys[7];

        let mut round = 8usize;
        while round > 0 {
            round -= 1;

            // Decryption walks the same structure backward with the round
            // subkeys consumed in reverse order.
            let (f0, f1) = round_f(
                x2,
                x3,
                &self.subkeys,
                &self.s,
                self.words,
                2 * round + 1,
                self.use_ct,
            );
            x1 = (x1 ^ f1).rotate_right(1);
            x0 = x0.rotate_left(1) ^ f0;

            let (f0, f1) = round_f(
                x0,
                x1,
                &self.subkeys,
                &self.s,
                self.words,
                2 * round,
                self.use_ct,
            );
            x3 = (x3 ^ f1).rotate_right(1);
            x2 = x2.rotate_left(1) ^ f0;
        }

        let p0 = x0 ^ self.subkeys[0];
        let p1 = x1 ^ self.subkeys[1];
        let p2 = x2 ^ self.subkeys[2];
        let p3 = x3 ^ self.subkeys[3];

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&p0.to_le_bytes());
        out[4..8].copy_from_slice(&p1.to_le_bytes());
        out[8..12].copy_from_slice(&p2.to_le_bytes());
        out[12..16].copy_from_slice(&p3.to_le_bytes());
        out
    }
}

macro_rules! define_twofish_type {
    ($name:ident, $name_ct:ident, $key_len:expr) => {
        pub struct $name {
            core: TwofishCore,
        }

        impl $name {
            /// Expand the user key into the whitening and round subkeys.
            pub fn new(key: &[u8; $key_len]) -> Self {
                Self {
                    core: TwofishCore::new(key, false),
                }
            }

            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let out = Self::new(key);
                zeroize_slice(key);
                out
            }

            /// Encrypt one 128-bit block.
            pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                self.core.encrypt_block(block)
            }

            /// Decrypt one 128-bit block.
            pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                self.core.decrypt_block(block)
            }
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = 16;

            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.encrypt_block(arr);
                block.copy_from_slice(&out);
            }

            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.decrypt_block(arr);
                block.copy_from_slice(&out);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                zeroize_slice(&mut self.core.subkeys);
                zeroize_slice(&mut self.core.s);
            }
        }

        pub struct $name_ct {
            core: TwofishCore,
        }

        impl $name_ct {
            /// Expand the user key into the whitening and round subkeys.
            pub fn new(key: &[u8; $key_len]) -> Self {
                Self {
                    core: TwofishCore::new(key, true),
                }
            }

            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let out = Self::new(key);
                zeroize_slice(key);
                out
            }

            /// Encrypt one 128-bit block with the software constant-time path.
            pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                self.core.encrypt_block(block)
            }

            /// Decrypt one 128-bit block with the software constant-time path.
            pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                self.core.decrypt_block(block)
            }
        }

        impl BlockCipher for $name_ct {
            const BLOCK_LEN: usize = 16;

            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.encrypt_block(arr);
                block.copy_from_slice(&out);
            }

            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.decrypt_block(arr);
                block.copy_from_slice(&out);
            }
        }

        impl Drop for $name_ct {
            fn drop(&mut self) {
                zeroize_slice(&mut self.core.subkeys);
                zeroize_slice(&mut self.core.s);
            }
        }
    };
}

define_twofish_type!(Twofish128, Twofish128Ct, 16);
define_twofish_type!(Twofish192, Twofish192Ct, 24);
define_twofish_type!(Twofish256, Twofish256Ct, 32);

pub type Twofish = Twofish128;
pub type TwofishCt = Twofish128Ct;

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i < N {
            let hi = u8::try_from((bytes[2 * i] as char).to_digit(16).unwrap())
                .expect("decoded hex nibble fits in u8");
            let lo = u8::try_from((bytes[2 * i + 1] as char).to_digit(16).unwrap())
                .expect("decoded hex nibble fits in u8");
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    #[test]
    fn twofish128_zero_kat() {
        let key = [0u8; 16];
        let pt = [0u8; 16];
        let ct = decode_hex::<16>("9F589F5CF6122C32B6BFEC2F2AE8C35A");
        let fast = Twofish128::new(&key);
        let slow = Twofish128Ct::new(&key);
        assert_eq!(fast.encrypt_block(&pt), ct);
        assert_eq!(slow.encrypt_block(&pt), ct);
        assert_eq!(fast.decrypt_block(&ct), pt);
        assert_eq!(slow.decrypt_block(&ct), pt);
    }

    #[test]
    fn twofish192_zero_kat() {
        let key = [0u8; 24];
        let pt = [0u8; 16];
        let ct = decode_hex::<16>("EFA71F788965BD4453F860178FC19101");
        let fast = Twofish192::new(&key);
        let slow = Twofish192Ct::new(&key);
        assert_eq!(fast.encrypt_block(&pt), ct);
        assert_eq!(slow.encrypt_block(&pt), ct);
        assert_eq!(fast.decrypt_block(&ct), pt);
        assert_eq!(slow.decrypt_block(&ct), pt);
    }

    #[test]
    fn twofish256_zero_kat() {
        let key = [0u8; 32];
        let pt = [0u8; 16];
        let ct = decode_hex::<16>("57FF739D4DC92C1BD7FC01700CC8216F");
        let fast = Twofish256::new(&key);
        let slow = Twofish256Ct::new(&key);
        assert_eq!(fast.encrypt_block(&pt), ct);
        assert_eq!(slow.encrypt_block(&pt), ct);
        assert_eq!(fast.decrypt_block(&ct), pt);
        assert_eq!(slow.decrypt_block(&ct), pt);
    }

    #[test]
    fn q_tables_match_ct_path() {
        let mut i = 0usize;
        while i < 256 {
            let idx = u8::try_from(i).expect("Q table index fits in u8");
            assert_eq!(Q0[i], q_perm_ct(idx, 0));
            assert_eq!(Q1[i], q_perm_ct(idx, 1));
            i += 1;
        }
    }
}
