//! Speck family of lightweight block ciphers.
//!
//! Implemented from "The SIMON and SPECK Families of Lightweight Block Ciphers"
//! (Beaulieu et al., NSA, 2013), §4 and Appendix B.  All 10 variants.
//!
//! # Byte conventions
//!
//! **Block** — two words *(x ∥ y)* laid out in little-endian word order with x
//! first.  x is the word that is right-rotated in each ARX round.
//!
//! **Key** — m words *(k₀ ∥ ℓ₀ ∥ … ∥ ℓ_{m−2})* in little-endian word order,
//! k₀ first.  This matches the C reference-implementation convention.
//!
//! # Naming
//!
//! `Speck{B}_{K}` denotes a B-bit block with a K-bit key, e.g. `Speck64_128`.
//!
//! # Test vectors
//!
//! Known-answer tests use Appendix B of the 2013 paper.

use super::simon_speck_util::{load_le, rotl, rotr, store_le};

// ─────────────────────────────────────────────────────────────────────────────
// Key expansion — §4.2, Figure 4.4
//
// Initial words (from key bytes, k₀ first):
//   rk[0]  = k₀
//   ℓ[j]   = k_{j+1}  for j = 0 … m−2
//
// For i = 0 … T−2:
//   ℓ[i+m−1] = (rk[i] + S^{−α}(ℓ[i])) ⊕ i
//   rk[i+1]  = S^β(rk[i]) ⊕ ℓ[i+m−1]
//
// The ℓ-array is maintained as a plain slice; max index = T−2+m−1 ≤ 35.
// A 40-entry stack buffer covers every variant.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct SpeckParams {
    alpha: u32,
    beta: u32,
    word_bits: u32,
    key_words: usize,
    rounds: usize,
    mask: u64,
}

fn speck_expand(key: &[u8], params: SpeckParams, rk: &mut [u64]) {
    let wb = (params.word_bits / 8) as usize;
    let mut l = [0u64; 40];
    rk[0] = load_le(&key[0..wb]);
    for j in 0..params.key_words - 1 {
        l[j] = load_le(&key[(j + 1) * wb..(j + 2) * wb]);
    }
    for i in 0..params.rounds - 1 {
        l[i + params.key_words - 1] =
            (rk[i].wrapping_add(rotr(l[i], params.alpha, params.word_bits, params.mask))
                ^ u64::try_from(i).expect("round index fits in u64"))
                & params.mask;
        rk[i + 1] = (rotl(rk[i], params.beta, params.word_bits, params.mask)
            ^ l[i + params.key_words - 1])
            & params.mask;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Block cipher core — §4.1, Figure 4.1
//
// Round function (encrypt):
//   x ← (S^{−α}(x) + y) ⊕ k     right-rotate x by α, add y (mod 2ⁿ), XOR k
//   y ← S^β(y) ⊕ x               left-rotate old y by β, XOR new x
//
// Inverse round (decrypt, applied in reverse round order):
//   y ← S^{−β}(y ⊕ x)            right-rotate (y XOR x) by β → recovers old y
//   x ← S^α((x ⊕ k) − y)         left-rotate  (x XOR k − y) by α → recovers old x
//                                 (subtraction is mod 2ⁿ)
// ─────────────────────────────────────────────────────────────────────────────

fn speck_enc(block: &mut [u8], rk: &[u64], alpha: u32, beta: u32, n: u32, mask: u64) {
    let wb = (n / 8) as usize;
    let mut x = load_le(&block[0..wb]);
    let mut y = load_le(&block[wb..2 * wb]);
    for &k in rk {
        x = (rotr(x, alpha, n, mask).wrapping_add(y) ^ k) & mask;
        y = (rotl(y, beta, n, mask) ^ x) & mask;
    }
    store_le(x, &mut block[0..wb]);
    store_le(y, &mut block[wb..2 * wb]);
}

fn speck_dec(block: &mut [u8], rk: &[u64], alpha: u32, beta: u32, n: u32, mask: u64) {
    let wb = (n / 8) as usize;
    let mut x = load_le(&block[0..wb]);
    let mut y = load_le(&block[wb..2 * wb]);
    for &k in rk.iter().rev() {
        y = rotr(y ^ x, beta, n, mask);
        x = rotl((x ^ k).wrapping_sub(y) & mask, alpha, n, mask);
    }
    store_le(x, &mut block[0..wb]);
    store_le(y, &mut block[wb..2 * wb]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — one struct per variant (Table 4.1)
//
// Macro arguments:
//   $Name     — struct identifier
//   $n        — word size in bits
//   $m        — number of key words (so m−1 initial ℓ values)
//   $T        — number of rounds (literal; also used as fixed-array size)
//   $alpha    — rotation constant for x  (right-rotate in encrypt)
//   $beta     — rotation constant for y  (left-rotate  in encrypt)
//   $mask     — (1 << $n) − 1  (u64::MAX when n = 64)
//   $key_len  — key length in bytes  = ($n / 8) × $m
//   $blk_len  — block length in bytes = ($n / 8) × 2
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! speck_variant {
    ($Name:ident, $n:expr, $m:expr, $T:literal, $alpha:expr, $beta:expr, $mask:expr,
     $key_len:literal, $blk_len:literal) => {
        pub struct $Name {
            round_keys: [u64; $T],
        }
        impl $Name {
            /// Expand the paper-defined master key into this variant's round keys.
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut rk = [0u64; $T];
                speck_expand(
                    key,
                    SpeckParams {
                        alpha: $alpha,
                        beta: $beta,
                        word_bits: $n,
                        key_words: $m,
                        rounds: $T,
                        mask: $mask,
                    },
                    &mut rk,
                );
                Self { round_keys: rk }
            }
            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                // Mirrors `new`, but clears the caller-owned key bytes after
                // expansion so only the internal round keys remain live.
                let out = Self::new(key);
                crate::ct::zeroize_slice(key.as_mut_slice());
                out
            }
            /// Encrypt one block using the cached ARX round keys.
            pub fn encrypt_block(&self, block: &[u8; $blk_len]) -> [u8; $blk_len] {
                let mut out = *block;
                speck_enc(&mut out, &self.round_keys, $alpha, $beta, $n, $mask);
                out
            }
            /// Decrypt one block using the cached ARX round keys.
            pub fn decrypt_block(&self, block: &[u8; $blk_len]) -> [u8; $blk_len] {
                let mut out = *block;
                speck_dec(&mut out, &self.round_keys, $alpha, $beta, $n, $mask);
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
                // SPECK's round function is already ARX-only; wipe the cached
                // round keys when the instance is released.
                crate::ct::zeroize_slice(self.round_keys.as_mut_slice());
            }
        }
    };
}

//                            n    m   T    α  β  mask                      key  blk
speck_variant!(Speck32_64, 16, 4, 22, 7, 2, 0xffff_u64, 8, 4);
speck_variant!(Speck48_72, 24, 3, 22, 8, 3, 0xff_ffff_u64, 9, 6);
speck_variant!(Speck48_96, 24, 4, 23, 8, 3, 0xff_ffff_u64, 12, 6);
speck_variant!(Speck64_96, 32, 3, 26, 8, 3, 0xffff_ffff_u64, 12, 8);
speck_variant!(Speck64_128, 32, 4, 27, 8, 3, 0xffff_ffff_u64, 16, 8);
speck_variant!(Speck96_96, 48, 2, 28, 8, 3, 0xffff_ffff_ffff_u64, 12, 12);
speck_variant!(Speck96_144, 48, 3, 29, 8, 3, 0xffff_ffff_ffff_u64, 18, 12);
speck_variant!(Speck128_128, 64, 2, 32, 8, 3, u64::MAX, 16, 16);
speck_variant!(Speck128_192, 64, 3, 33, 8, 3, u64::MAX, 24, 16);
speck_variant!(Speck128_256, 64, 4, 34, 8, 3, u64::MAX, 32, 16);

// ─────────────────────────────────────────────────────────────────────────────
// Tests — known-answer vector from Appendix B of the 2013 paper;
//         all other variants verified by encrypt→decrypt roundtrip.
//
// Block bytes: (x ∥ y) little-endian, x first.
// Key bytes:   (k₀ ∥ ℓ₀ ∥ … ∥ ℓ_{m-2}) little-endian, k₀ first.
//
// Speck 32/64 derivation (Appendix B):
//   Paper words: k₃k₂k₁k₀ = 0x1918 0x1110 0x0908 0x0100
//   k₀ = 0x0100 → LE bytes 00 01; …; k₃ = 0x1918 → LE bytes 18 19
//   Key bytes: 00 01 08 09 10 11 18 19
//   PT: x = 0x6574 → 74 65;  y = 0x694c → 4c 69  (x first, LE)
//   CT: x = 0xa868 → 68 a8;  y = 0x42f2 → f2 42  (x first, LE)
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

    // ── Speck 32/64 — Appendix B ─────────────────────────────────────────────
    // Key words (k₃,k₂,k₁,k₀) = (0x1918, 0x1110, 0x0908, 0x0100).
    // PT (x,y) = (0x6574, 0x694c).  CT (x,y) = (0xa868, 0x42f2).

    #[test]
    fn speck32_64_kat() {
        let key: [u8; 8] = parse("0001080910111819");
        let pt: [u8; 4] = parse("74654c69");
        let ct: [u8; 4] = parse("68a8f242");
        let c = Speck32_64::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 48/72 — Appendix C ─────────────────────────────────────────────
    // Key (k₂,k₁,k₀) = (0x121110, 0x0a0908, 0x020100).
    // PT (x,y) = (0x20796c, 0x6c6172).  CT (x,y) = (0xc049a5, 0x385adc).

    #[test]
    fn speck48_72_kat() {
        let key: [u8; 9] = parse("00010208090a101112");
        let pt: [u8; 6] = parse("6c792072616c");
        let ct: [u8; 6] = parse("a549c0dc5a38");
        let c = Speck48_72::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 48/96 — Appendix C ─────────────────────────────────────────────
    // Key (k₃..k₀) = (0x1a1918, 0x121110, 0x0a0908, 0x020100).
    // PT (x,y) = (0x6d2073, 0x696874).  CT (x,y) = (0x735e10, 0xb6445d).

    #[test]
    fn speck48_96_kat() {
        let key: [u8; 12] = parse("00010208090a10111218191a");
        let pt: [u8; 6] = parse("73206d746869");
        let ct: [u8; 6] = parse("105e735d44b6");
        let c = Speck48_96::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 64/96 — Appendix C ─────────────────────────────────────────────
    // Key (k₂,k₁,k₀) = (0x13121110, 0x0b0a0908, 0x03020100).
    // PT (x,y) = (0x74614620, 0x736e6165).  CT (x,y) = (0x9f7952ec, 0x4175946c).

    #[test]
    fn speck64_96_kat() {
        let key: [u8; 12] = parse("0001020308090a0b10111213");
        let pt: [u8; 8] = parse("2046617465616e73");
        let ct: [u8; 8] = parse("ec52799f6c947541");
        let c = Speck64_96::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 64/128 — Appendix C ────────────────────────────────────────────
    // Key (k₃..k₀) = (0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100).
    // PT (x,y) = (0x3b726574, 0x7475432d).  CT (x,y) = (0x8c6fa548, 0x454e028b).

    #[test]
    fn speck64_128_kat() {
        let key: [u8; 16] = parse("0001020308090a0b1011121318191a1b");
        let pt: [u8; 8] = parse("7465723b2d437574");
        let ct: [u8; 8] = parse("48a56f8c8b024e45");
        let c = Speck64_128::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 96/96 — Appendix C ─────────────────────────────────────────────
    // Key (k₁,k₀) = (0x0d0c0b0a0908, 0x050403020100).
    // PT (x,y) = (0x65776f68202c, 0x656761737520).
    // CT (x,y) = (0x9e4d09ab7178, 0x62bdde8f79aa).

    #[test]
    fn speck96_96_kat() {
        let key: [u8; 12] = parse("00010203040508090a0b0c0d");
        let pt: [u8; 12] = parse("2c20686f7765207573616765");
        let ct: [u8; 12] = parse("7871ab094d9eaa798fdebd62");
        let c = Speck96_96::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 96/144 — Appendix C ────────────────────────────────────────────
    // Key (k₂..k₀) = (0x151413121110, 0x0d0c0b0a0908, 0x050403020100).
    // PT (x,y) = (0x656d6974206e, 0x69202c726576).
    // CT (x,y) = (0x2bf31072228a, 0x7ae440252ee6).

    #[test]
    fn speck96_144_kat() {
        let key: [u8; 18] = parse("00010203040508090a0b0c0d101112131415");
        let pt: [u8; 12] = parse("6e2074696d657665722c2069");
        let ct: [u8; 12] = parse("8a227210f32be62e2540e47a");
        let c = Speck96_144::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 128/128 — Appendix C ───────────────────────────────────────────
    // Key (k₁,k₀) = (0x0f0e0d0c0b0a0908, 0x0706050403020100).
    // PT (x,y) = (0x6c61766975716520, 0x7469206564616d20).
    // CT (x,y) = (0xa65d985179783265, 0x7860fedf5c570d18).

    #[test]
    fn speck128_128_kat() {
        let key: [u8; 16] = parse("000102030405060708090a0b0c0d0e0f");
        let pt: [u8; 16] = parse("206571756976616c206d616465206974");
        let ct: [u8; 16] = parse("6532787951985da6180d575cdffe6078");
        let c = Speck128_128::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 128/192 — Appendix C ───────────────────────────────────────────
    // Key (k₂..k₀) = (0x1716151413121110, 0x0f0e0d0c0b0a0908, 0x0706050403020100).
    // PT (x,y) = (0x7261482066656968, 0x43206f7420746e65).
    // CT (x,y) = (0x1be4cf3a13135566, 0xf9bc185de03c1886).

    #[test]
    fn speck128_192_kat() {
        let key: [u8; 24] = parse("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt: [u8; 16] = parse("6869656620486172656e7420746f2043");
        let ct: [u8; 16] = parse("665513133acfe41b86183ce05d18bcf9");
        let c = Speck128_192::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Speck 128/256 — Appendix C ───────────────────────────────────────────
    // Key (k₃..k₀) = (0x1f1e1d1c1b1a1918, 0x1716151413121110,
    //                  0x0f0e0d0c0b0a0908, 0x0706050403020100).
    // PT (x,y) = (0x65736f6874206e49, 0x202e72656e6f6f70).
    // CT (x,y) = (0x4109010405c0f53e, 0x4eeeb48d9c188f43).

    #[test]
    fn speck128_256_kat() {
        let key: [u8; 32] =
            parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt: [u8; 16] = parse("496e2074686f7365706f6f6e65722e20");
        let ct: [u8; 16] = parse("3ef5c00504010941438f189c8db4ee4e");
        let c = Speck128_256::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }
}
