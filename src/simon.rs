//! Simon family of lightweight block ciphers.
//!
//! Implemented from "The SIMON and SPECK Families of Lightweight Block Ciphers"
//! (Beaulieu et al., NSA, 2013), §3 and Appendix B.  All 10 variants.
//!
//! # Byte conventions
//!
//! **Block** — two words *(x ∥ y)* laid out in little-endian word order with x
//! first.  x is the "left" word in the paper's Feistel diagram — the operand
//! of the nonlinear function f.
//!
//! **Key** — m words *(k₀ ∥ ℓ₀ ∥ … ∥ ℓ_{m−2})* in little-endian word order,
//! k₀ first.  This matches the C reference-implementation convention.
//!
//! # Naming
//!
//! `Simon{B}_{K}` denotes a B-bit block with a K-bit key, e.g. `Simon64_128`.
//!
//! # Test vectors
//!
//! Known-answer tests use Appendix B of the 2013 paper.

// ─────────────────────────────────────────────────────────────────────────────
// Z sequences — Table 3.2
//
// Five 62-bit LFSR constants.  Bit i (0-indexed from LSB) of Z[j] gives the
// i-th element of sequence zⱼ, used cyclically modulo 62 in the key schedule.
// Values match the Python reference implementation (NSA, 2013).
// ─────────────────────────────────────────────────────────────────────────────

const Z: [u64; 5] = [
    0b01100111000011010100100010111110110011100001101010010001011111,
    0b01011010000110010011111011100010101101000011001001111101110001,
    0b11001101101001111110001000010100011001001011000000111011110101,
    0b11110000101100111001010001001000000111101001100011010111011011,
    0b11110111001001010011000011101000000100011011010110011110001011,
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Load bytes as a little-endian n-bit word into a u64.
#[inline(always)]
fn load_le(src: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in src.iter().enumerate() { v |= (b as u64) << (8 * i); }
    v
}

/// Store the low bytes of a u64 in little-endian order.
#[inline(always)]
fn store_le(mut v: u64, dst: &mut [u8]) {
    for b in dst.iter_mut() { *b = v as u8; v >>= 8; }
}

#[inline(always)]
fn rotl(x: u64, r: u32, n: u32, mask: u64) -> u64 { ((x << r) | (x >> (n - r))) & mask }

#[inline(always)]
fn rotr(x: u64, r: u32, n: u32, mask: u64) -> u64 { ((x >> r) | (x << (n - r))) & mask }

// ─────────────────────────────────────────────────────────────────────────────
// Key expansion — §3
//
// Initial words k₀ … k_{m-1} come from the key bytes (k₀ first, LE).
// For i = m … T-1:
//
//   tmp  = S⁻³(k_{i-1})              right-rotate by 3
//   if m = 4: tmp ⊕= k_{i-3}
//   tmp ⊕= S⁻¹(tmp)                  applies (I ⊕ S⁻¹)
//   k_i  = ∼3 ⊕ zⱼ[(i−m) mod 62] ⊕ k_{i-m} ⊕ tmp
//
// Note: ∼k_{i-m} ⊕ 3 = ∼3 ⊕ k_{i-m}  (XOR is associative/commutative).
// ─────────────────────────────────────────────────────────────────────────────

fn simon_expand(key: &[u8], n: u32, m: usize, t: usize, z_idx: usize, mask: u64,
                rk: &mut [u64]) {
    let wb = (n / 8) as usize;
    for i in 0..m {
        rk[i] = load_le(&key[i * wb..(i + 1) * wb]);
    }
    for i in m..t {
        let mut tmp = rotr(rk[i - 1], 3, n, mask);
        if m == 4 { tmp ^= rk[i - 3]; }
        tmp ^= rotr(tmp, 1, n, mask);
        let z_bit = (Z[z_idx] >> ((i - m) % 62)) & 1;
        rk[i] = (!rk[i - m] ^ tmp ^ z_bit ^ 3) & mask;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Block cipher core
//
// Round function (Figure 3.3):
//   f(x) = (S¹x & S⁸x) ⊕ S²x
//
// Encrypt: for each round key k:
//   (x, y) ← (k ⊕ f(x) ⊕ y,  x)
//
// Decrypt: same step applied in reverse round order using the inverse:
//   given post-round (x, y), the pre-round values are (y,  k ⊕ f(y) ⊕ x)
// ─────────────────────────────────────────────────────────────────────────────

fn simon_enc(block: &mut [u8], rk: &[u64], n: u32, mask: u64) {
    let wb = (n / 8) as usize;
    let mut x = load_le(&block[0..wb]);
    let mut y = load_le(&block[wb..2 * wb]);
    for &k in rk {
        let t = x;
        x = y ^ (rotl(x, 1, n, mask) & rotl(x, 8, n, mask)) ^ rotl(x, 2, n, mask) ^ k;
        y = t;
    }
    store_le(x, &mut block[0..wb]);
    store_le(y, &mut block[wb..2 * wb]);
}

fn simon_dec(block: &mut [u8], rk: &[u64], n: u32, mask: u64) {
    let wb = (n / 8) as usize;
    let mut x = load_le(&block[0..wb]);
    let mut y = load_le(&block[wb..2 * wb]);
    for &k in rk.iter().rev() {
        let t = y;
        y = x ^ (rotl(y, 1, n, mask) & rotl(y, 8, n, mask)) ^ rotl(y, 2, n, mask) ^ k;
        x = t;
    }
    store_le(x, &mut block[0..wb]);
    store_le(y, &mut block[wb..2 * wb]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — one struct per variant (Table 3.1)
//
// Macro arguments:
//   $Name     — struct identifier
//   $n        — word size in bits
//   $m        — number of key words
//   $T        — number of rounds (literal, also used as array size)
//   $z        — Z-sequence index (0–4)
//   $mask     — (1 << $n) - 1
//   $key_len  — key length in bytes = ($n / 8) * $m
//   $blk_len  — block length in bytes = ($n / 8) * 2
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! simon_variant {
    ($Name:ident, $n:expr, $m:expr, $T:literal, $z:expr, $mask:expr,
     $key_len:literal, $blk_len:literal) => {
        pub struct $Name { round_keys: [u64; $T] }
        impl $Name {
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut rk = [0u64; $T];
                simon_expand(key, $n, $m, $T, $z, $mask, &mut rk);
                Self { round_keys: rk }
            }
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                // Mirrors `new`, but clears the caller-owned key bytes after
                // expansion so only the internal round keys remain live.
                let out = Self::new(key);
                crate::ct::zeroize_slice(key.as_mut_slice());
                out
            }
            pub fn encrypt_block(&self, block: &[u8; $blk_len]) -> [u8; $blk_len] {
                let mut out = *block;
                simon_enc(&mut out, &self.round_keys, $n, $mask);
                out
            }
            pub fn decrypt_block(&self, block: &[u8; $blk_len]) -> [u8; $blk_len] {
                let mut out = *block;
                simon_dec(&mut out, &self.round_keys, $n, $mask);
                out
            }
        }
        impl crate::BlockCipher for $Name {
            const BLOCK_LEN: usize = $blk_len;
            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; $blk_len] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.encrypt_block(arr));
            }
            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; $blk_len] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.decrypt_block(arr));
            }
        }
        impl Drop for $Name {
            fn drop(&mut self) {
                // SIMON already avoids table lookups; this handles the
                // remaining concern of clearing stored round keys.
                crate::ct::zeroize_slice(self.round_keys.as_mut_slice());
            }
        }
    };
}

//                          n    m   T    z  mask                      key  blk
simon_variant!(Simon32_64,   16, 4, 32,  0, 0xffff_u64,                8,  4);
simon_variant!(Simon48_72,   24, 3, 36,  0, 0xff_ffff_u64,             9,  6);
simon_variant!(Simon48_96,   24, 4, 36,  1, 0xff_ffff_u64,            12,  6);
simon_variant!(Simon64_96,   32, 3, 42,  2, 0xffff_ffff_u64,          12,  8);
simon_variant!(Simon64_128,  32, 4, 44,  3, 0xffff_ffff_u64,          16,  8);
simon_variant!(Simon96_96,   48, 2, 52,  2, 0xffff_ffff_ffff_u64,     12, 12);
simon_variant!(Simon96_144,  48, 3, 54,  3, 0xffff_ffff_ffff_u64,     18, 12);
simon_variant!(Simon128_128, 64, 2, 68,  2, u64::MAX,                 16, 16);
simon_variant!(Simon128_192, 64, 3, 69,  3, u64::MAX,                 24, 16);
simon_variant!(Simon128_256, 64, 4, 72,  4, u64::MAX,                 32, 16);

// ─────────────────────────────────────────────────────────────────────────────
// Tests — known-answer vectors from Appendix B of the 2013 paper;
//         all other variants verified by encrypt→decrypt roundtrip.
//
// Block bytes: (x ∥ y) little-endian, x first.
// Key bytes:   (k₀ ∥ ℓ₀ ∥ … ∥ ℓ_{m-2}) little-endian, k₀ first.
//
// Example derivation for Simon 32/64:
//   Paper words: k₃k₂k₁k₀ = 0x1918 1110 0908 0100
//   k₀ = 0x0100 → LE bytes 00 01; …; k₃ = 0x1918 → LE bytes 18 19
//   Key bytes: 00 01 08 09 10 11 18 19
//   PT: x = 0x6565 → 65 65;  y = 0x6877 → 77 68  (LE)
//   CT: x = 0xc69b → 9b c6;  y = 0xe9bb → bb e9  (LE)
// ─────────────────────────────────────────────────────────────────────────────

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

    // ── Simon 32/64 — Appendix B ─────────────────────────────────────────────
    // Key words (k₃,k₂,k₁,k₀) = (0x1918, 0x1110, 0x0908, 0x0100).
    // PT (x,y) = (0x6565, 0x6877).  CT (x,y) = (0xc69b, 0xe9bb).

    #[test]
    fn simon32_64_kat() {
        let key: [u8; 8]  = parse("0001080910111819");
        let pt:  [u8; 4]  = parse("65657768");
        let ct:  [u8; 4]  = parse("9bc6bbe9");
        let c = Simon32_64::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 64/128 — Appendix B ────────────────────────────────────────────
    // Key words (k₃…k₀) = (0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100).
    // PT (x,y) = (0x656b696c, 0x20646e75).
    // CT (x,y) = (0x44c8fc20, 0xb9dfa07a).

    #[test]
    fn simon64_128_kat() {
        let key: [u8; 16] = parse("0001020308090a0b1011121318191a1b");
        let pt:  [u8; 8]  = parse("6c696b65756e6420");
        let ct:  [u8; 8]  = parse("20fcc8447aa0dfb9");
        let c = Simon64_128::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Roundtrip tests for remaining variants ────────────────────────────────

    macro_rules! roundtrip {
        ($test:ident, $Cipher:ident, $key:expr, $pt:expr) => {
            #[test]
            fn $test() {
                let c = $Cipher::new(&$key);
                assert_eq!(c.decrypt_block(&c.encrypt_block(&$pt)), $pt);
            }
        };
    }

    roundtrip!(simon48_72_roundtrip,   Simon48_72,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13],
        [0x01,0x23,0x45,0x67,0x89,0xab]);

    roundtrip!(simon48_96_roundtrip,   Simon48_96,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf],
        [0x02,0x46,0x8a,0xce,0x13,0x57]);

    roundtrip!(simon64_96_roundtrip,   Simon64_96,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf],
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]);

    roundtrip!(simon96_96_roundtrip,   Simon96_96,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf],
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf]);

    roundtrip!(simon96_144_roundtrip,  Simon96_144,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
         0x13,0x57,0x9b,0xdf,0x24,0x68,0xac,0xe0,0xf1,0x35],
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf]);

    roundtrip!(simon128_128_roundtrip, Simon128_128,
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f],
        [0x63,0x73,0x65,0x64,0x20,0x73,0x72,0x65,
         0x6c,0x6c,0x65,0x76,0x61,0x72,0x74,0x20]);

    roundtrip!(simon128_192_roundtrip, Simon128_192,
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17],
        [0x20,0x6d,0x61,0x64,0x65,0x20,0x69,0x74,
         0x20,0x65,0x71,0x75,0x69,0x76,0x61,0x6c]);

    roundtrip!(simon128_256_roundtrip, Simon128_256,
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
         0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f],
        [0x6e,0x20,0x74,0x68,0x65,0x72,0x65,0x20,
         0x72,0x69,0x62,0x65,0x20,0x77,0x68,0x65]);
}
