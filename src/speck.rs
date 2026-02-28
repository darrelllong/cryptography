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

// ─────────────────────────────────────────────────────────────────────────────
// Helpers  (same logic as in simon.rs; each module is self-contained)
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

fn speck_expand(key: &[u8], alpha: u32, beta: u32, n: u32, m: usize, t: usize,
                mask: u64, rk: &mut [u64]) {
    let wb = (n / 8) as usize;
    let mut l = [0u64; 40];
    rk[0] = load_le(&key[0..wb]);
    for j in 0..m - 1 {
        l[j] = load_le(&key[(j + 1) * wb..(j + 2) * wb]);
    }
    for i in 0..t - 1 {
        l[i + m - 1] = (rk[i].wrapping_add(rotr(l[i], alpha, n, mask)) ^ (i as u64)) & mask;
        rk[i + 1] = (rotl(rk[i], beta, n, mask) ^ l[i + m - 1]) & mask;
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
        pub struct $Name { round_keys: [u64; $T] }
        impl $Name {
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut rk = [0u64; $T];
                speck_expand(key, $alpha, $beta, $n, $m, $T, $mask, &mut rk);
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
                speck_enc(&mut out, &self.round_keys, $alpha, $beta, $n, $mask);
                out
            }
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
speck_variant!(Speck32_64,   16, 4, 22,  7, 2, 0xffff_u64,               8,  4);
speck_variant!(Speck48_72,   24, 3, 22,  8, 3, 0xff_ffff_u64,            9,  6);
speck_variant!(Speck48_96,   24, 4, 23,  8, 3, 0xff_ffff_u64,           12,  6);
speck_variant!(Speck64_96,   32, 3, 26,  8, 3, 0xffff_ffff_u64,         12,  8);
speck_variant!(Speck64_128,  32, 4, 27,  8, 3, 0xffff_ffff_u64,         16,  8);
speck_variant!(Speck96_96,   48, 2, 28,  8, 3, 0xffff_ffff_ffff_u64,    12, 12);
speck_variant!(Speck96_144,  48, 3, 29,  8, 3, 0xffff_ffff_ffff_u64,    18, 12);
speck_variant!(Speck128_128, 64, 2, 32,  8, 3, u64::MAX,                16, 16);
speck_variant!(Speck128_192, 64, 3, 33,  8, 3, u64::MAX,                24, 16);
speck_variant!(Speck128_256, 64, 4, 34,  8, 3, u64::MAX,                32, 16);

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
        let pt:  [u8; 4] = parse("74654c69");
        let ct:  [u8; 4] = parse("68a8f242");
        let c = Speck32_64::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Roundtrip tests for all 10 variants ──────────────────────────────────

    macro_rules! roundtrip {
        ($test:ident, $Cipher:ident, $key:expr, $pt:expr) => {
            #[test]
            fn $test() {
                let c = $Cipher::new(&$key);
                assert_eq!(c.decrypt_block(&c.encrypt_block(&$pt)), $pt);
            }
        };
    }

    roundtrip!(speck32_64_roundtrip,   Speck32_64,
        [0x00,0x01,0x08,0x09,0x10,0x11,0x18,0x19],
        [0x74,0x65,0x4c,0x69]);

    roundtrip!(speck48_72_roundtrip,   Speck48_72,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13],
        [0x01,0x23,0x45,0x67,0x89,0xab]);

    roundtrip!(speck48_96_roundtrip,   Speck48_96,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf],
        [0x02,0x46,0x8a,0xce,0x13,0x57]);

    roundtrip!(speck64_96_roundtrip,   Speck64_96,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf],
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]);

    roundtrip!(speck64_128_roundtrip,  Speck64_128,
        [0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,
         0x10,0x11,0x12,0x13,0x18,0x19,0x1a,0x1b],
        [0x2d,0x43,0x75,0x74,0x74,0x65,0x72,0x3b]);

    roundtrip!(speck96_96_roundtrip,   Speck96_96,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf],
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf]);

    roundtrip!(speck96_144_roundtrip,  Speck96_144,
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
         0x13,0x57,0x9b,0xdf,0x24,0x68,0xac,0xe0,0xf1,0x35],
        [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x13,0x57,0x9b,0xdf]);

    roundtrip!(speck128_128_roundtrip, Speck128_128,
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f],
        [0x20,0x65,0x71,0x75,0x69,0x76,0x61,0x6c,
         0x20,0x6d,0x61,0x64,0x65,0x20,0x69,0x74]);

    roundtrip!(speck128_192_roundtrip, Speck128_192,
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17],
        [0x65,0x6e,0x74,0x20,0x61,0x6e,0x64,0x20,
         0x67,0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65]);

    roundtrip!(speck128_256_roundtrip, Speck128_256,
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
         0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f],
        [0x49,0x6e,0x20,0x74,0x68,0x6f,0x73,0x65,
         0x20,0x70,0x6f,0x6f,0x6e,0x65,0x72,0x2e]);
}
