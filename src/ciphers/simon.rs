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

use super::simon_speck_util::{load_le, rotl, rotr, store_le};

// ─────────────────────────────────────────────────────────────────────────────
// Z sequences — Table 3.2
//
// Five 62-bit LFSR constants.  Bit i (0-indexed from LSB) of Z[j] gives the
// i-th element of sequence zⱼ, used cyclically modulo 62 in the key schedule.
// Values match the Python reference implementation (NSA, 2013).
// ─────────────────────────────────────────────────────────────────────────────

const Z: [u64; 5] = [
    0b01_1001_1100_0011_0101_0010_0010_1111_1011_0011_1000_0110_1010_0100_0101_1111,
    0b01_0110_1000_0110_0100_1111_1011_1000_1010_1101_0000_1100_1001_1111_0111_0001,
    0b11_0011_0110_1001_1111_1000_1000_0101_0001_1001_0010_1100_0000_1110_1111_0101,
    0b11_1100_0010_1100_1110_0101_0001_0010_0000_0111_1010_0110_0011_0101_1101_1011,
    0b11_1101_1100_1001_0100_1100_0011_1010_0000_0100_0110_1101_0110_0111_1000_1011,
];

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

fn simon_expand(key: &[u8], n: u32, m: usize, t: usize, z_idx: usize, mask: u64, rk: &mut [u64]) {
    let wb = (n / 8) as usize;
    for i in 0..m {
        rk[i] = load_le(&key[i * wb..(i + 1) * wb]);
    }
    for i in m..t {
        let mut tmp = rotr(rk[i - 1], 3, n, mask);
        if m == 4 {
            tmp ^= rk[i - 3];
        }
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
        pub struct $Name {
            round_keys: [u64; $T],
        }
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
simon_variant!(Simon32_64, 16, 4, 32, 0, 0xffff_u64, 8, 4);
simon_variant!(Simon48_72, 24, 3, 36, 0, 0xff_ffff_u64, 9, 6);
simon_variant!(Simon48_96, 24, 4, 36, 1, 0xff_ffff_u64, 12, 6);
simon_variant!(Simon64_96, 32, 3, 42, 2, 0xffff_ffff_u64, 12, 8);
simon_variant!(Simon64_128, 32, 4, 44, 3, 0xffff_ffff_u64, 16, 8);
simon_variant!(Simon96_96, 48, 2, 52, 2, 0xffff_ffff_ffff_u64, 12, 12);
simon_variant!(Simon96_144, 48, 3, 54, 3, 0xffff_ffff_ffff_u64, 18, 12);
simon_variant!(Simon128_128, 64, 2, 68, 2, u64::MAX, 16, 16);
simon_variant!(Simon128_192, 64, 3, 69, 3, u64::MAX, 24, 16);
simon_variant!(Simon128_256, 64, 4, 72, 4, u64::MAX, 32, 16);

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
        let key: [u8; 8] = parse("0001080910111819");
        let pt: [u8; 4] = parse("65657768");
        let ct: [u8; 4] = parse("9bc6bbe9");
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
        let pt: [u8; 8] = parse("6c696b65756e6420");
        let ct: [u8; 8] = parse("20fcc8447aa0dfb9");
        let c = Simon64_128::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 48/72 — Appendix B ─────────────────────────────────────────────
    // Key (k₂,k₁,k₀) = (0x121110, 0x0a0908, 0x020100).
    // PT (x,y) = (0x612067, 0x6e696c).  CT (x,y) = (0xdae5ac, 0x292cac).

    #[test]
    fn simon48_72_kat() {
        let key: [u8; 9] = parse("00010208090a101112");
        let pt: [u8; 6] = parse("6720616c696e");
        let ct: [u8; 6] = parse("ace5daac2c29");
        let c = Simon48_72::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 48/96 — Appendix B ─────────────────────────────────────────────
    // Key (k₃..k₀) = (0x1a1918, 0x121110, 0x0a0908, 0x020100).
    // PT (x,y) = (0x726963, 0x20646e).  CT (x,y) = (0x6e06a5, 0xacf156).

    #[test]
    fn simon48_96_kat() {
        let key: [u8; 12] = parse("00010208090a10111218191a");
        let pt: [u8; 6] = parse("6369726e6420");
        let ct: [u8; 6] = parse("a5066e56f1ac");
        let c = Simon48_96::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 64/96 — Appendix B ─────────────────────────────────────────────
    // Key (k₂,k₁,k₀) = (0x13121110, 0x0b0a0908, 0x03020100).
    // PT (x,y) = (0x6f722067, 0x6e696c63).  CT (x,y) = (0x5ca2e27f, 0x111a8fc8).

    #[test]
    fn simon64_96_kat() {
        let key: [u8; 12] = parse("0001020308090a0b10111213");
        let pt: [u8; 8] = parse("6720726f636c696e");
        let ct: [u8; 8] = parse("7fe2a25cc88f1a11");
        let c = Simon64_96::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 96/96 — Appendix B ─────────────────────────────────────────────
    // Key (k₁,k₀) = (0x0d0c0b0a0908, 0x050403020100).
    // PT (x,y) = (0x2072616c6c69, 0x702065687420).
    // CT (x,y) = (0x602807a462b4, 0x69063d8ff082).

    #[test]
    fn simon96_96_kat() {
        let key: [u8; 12] = parse("00010203040508090a0b0c0d");
        let pt: [u8; 12] = parse("696c6c617220207468652070");
        let ct: [u8; 12] = parse("b462a407286082f08f3d0669");
        let c = Simon96_96::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 96/144 — Appendix B ────────────────────────────────────────────
    // Key (k₂..k₀) = (0x151413121110, 0x0d0c0b0a0908, 0x050403020100).
    // PT (x,y) = (0x746168742074, 0x73756420666f).
    // CT (x,y) = (0xecad1c6c451e, 0x3f59c5db1ae9).

    #[test]
    fn simon96_144_kat() {
        let key: [u8; 18] = parse("00010203040508090a0b0c0d101112131415");
        let pt: [u8; 12] = parse("7420746861746f6620647573");
        let ct: [u8; 12] = parse("1e456c1cadece91adbc5593f");
        let c = Simon96_144::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 128/128 — Appendix B ───────────────────────────────────────────
    // Key (k₁,k₀) = (0x0f0e0d0c0b0a0908, 0x0706050403020100).
    // PT (x,y) = (0x6373656420737265, 0x6c6c657661727420).
    // CT (x,y) = (0x49681b1e1e54fe3f, 0x65aa832af84e0bbc).

    #[test]
    fn simon128_128_kat() {
        let key: [u8; 16] = parse("000102030405060708090a0b0c0d0e0f");
        let pt: [u8; 16] = parse("65727320646573632074726176656c6c");
        let ct: [u8; 16] = parse("3ffe541e1e1b6849bc0b4ef82a83aa65");
        let c = Simon128_128::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 128/192 — Appendix B ───────────────────────────────────────────
    // Key (k₂..k₀) = (0x1716151413121110, 0x0f0e0d0c0b0a0908, 0x0706050403020100).
    // PT (x,y) = (0x206572656874206e, 0x6568772065626972).
    // CT (x,y) = (0xc4ac61effcdc0d4f, 0x6c9c8d6e2597b85b).

    #[test]
    fn simon128_192_kat() {
        let key: [u8; 24] = parse("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt: [u8; 16] = parse("6e207468657265207269626520776865");
        let ct: [u8; 16] = parse("4f0ddcfcef61acc45bb897256e8d9c6c");
        let c = Simon128_192::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Simon 128/256 — Appendix B ───────────────────────────────────────────
    // Key (k₃..k₀) = (0x1f1e1d1c1b1a1918, 0x1716151413121110,
    //                  0x0f0e0d0c0b0a0908, 0x0706050403020100).
    // PT (x,y) = (0x74206e69206d6f6f, 0x6d69732061207369).
    // CT (x,y) = (0x8d2b5579afc8a3a0, 0x3bf72a87efe7b868).

    #[test]
    fn simon128_256_kat() {
        let key: [u8; 32] =
            parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt: [u8; 16] = parse("6f6f6d20696e2074697320612073696d");
        let ct: [u8; 16] = parse("a0a3c8af79552b8d68b8e7ef872af73b");
        let c = Simon128_256::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }
}
