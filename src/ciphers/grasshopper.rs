#![allow(
    clippy::cast_possible_truncation,
    clippy::explicit_iter_loop,
    clippy::inline_always,
    clippy::must_use_candidate
)]

//! Kuznyechik (Grasshopper) block cipher — RFC 7801 / GOST R 34.12-2015.
//!
//! 128-bit block, 256-bit key, 10 rounds.
//! All tables and test vectors from RFC 7801.
//!
//! `Grasshopper` keeps the original fast table-driven software path.
//! `GrasshopperCt` is separate and keeps the same round structure, but removes
//! secret-indexed tables by using a packed ANF bitset form for the S-box and
//! direct arithmetic for the linear transform.

// ── GF(2⁸) with primitive polynomial p(x) = x⁸ + x⁷ + x⁶ + x + 1 ──────────
//
// Reduction: x⁸ ≡ x⁷ + x⁶ + x + 1  ⟹  modulus byte 0xC3.

#[inline(always)]
const fn gf_mul2(a: u8) -> u8 {
    (a << 1) ^ (0xC3 & 0u8.wrapping_sub(a >> 7))
}

const fn gf_mul_const(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = gf_mul2(a);
        b >>= 1;
    }
    r
}

#[inline(always)]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        r ^= a & mask;
        a = gf_mul2(a);
        b >>= 1;
    }
    r
}

// ── S-box and inverse (RFC 7801 §A.1) ────────────────────────────────────────
//
// Pi  : forward substitution (256-entry bijection over GF(2⁸))
// Pi' : inverse substitution

const PI: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219,
    147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129,
    28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212,
    211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112,
    14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154,
    199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
    128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115,
    30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
    165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217,
    231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113,
    103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244,
    180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
];

const PI_INV: [u8; 256] = [
    165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96,
    7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73,
    229, 66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132,
    213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239,
    217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249,
    226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148,
    101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46,
    54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185,
    227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93,
    169, 142, 23, 27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79,
    29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208,
    36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139,
    199, 214, 32, 10, 8, 0, 76, 215, 116,
];

/// Build packed ANF coefficients for the forward or inverse Grasshopper S-box.
///
/// The 8->8 Kuznyechik S-box is dense enough that a hand-written explicit
/// circuit would be unwieldy. `GrasshopperCt` therefore stores each output bit
/// as two packed 128-bit monomial masks and evaluates them with parity at
/// runtime instead of indexing the 256-byte tables.
///
/// As with `DesCt`, this starts from the 256-byte truth table and applies the
/// in-place Moebius transform to recover ANF coefficients. The result is split
/// into two `u128`s because the 8-variable monomial space has 256 entries.
const fn build_pi_anf(table: &[u8; 256]) -> [[u128; 2]; 8] {
    crate::ct::build_byte_sbox_anf(table)
}

const PI_ANF: [[u128; 2]; 8] = build_pi_anf(&PI);
const PI_INV_ANF: [[u128; 2]; 8] = build_pi_anf(&PI_INV);

// ── L-transform (RFC 7801 §2.2) ───────────────────────────────────────────────
//
// l(a₁₅,...,a₀) = 148·a₁₅ ⊕ 32·a₁₄ ⊕ 133·a₁₃ ⊕ 16·a₁₂ ⊕ 194·a₁₁ ⊕ 192·a₁₀
//               ⊕   1·a₉  ⊕ 251·a₈  ⊕   1·a₇  ⊕ 192·a₆  ⊕ 194·a₅  ⊕  16·a₄
//               ⊕ 133·a₃  ⊕  32·a₂  ⊕ 148·a₁  ⊕   1·a₀
//
// In our byte array, block[0] = a₁₅ and block[15] = a₀.
//
// R(block) = [l(block), block[0], …, block[14]]   ← push l to front, drop last
// L = R¹⁶
//
// `Grasshopper` keeps these tables for throughput. `GrasshopperCt` computes the
// products directly instead so the linear layer does not depend on secret-
// indexed byte lookups.

const L_COEFF: [u8; 16] = [
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
];

const fn build_l_tables() -> [[u8; 256]; 16] {
    let mut t = [[0u8; 256]; 16];
    let mut i = 0usize;
    while i < 16 {
        let mut v = 0usize;
        while v < 256 {
            t[i][v] = gf_mul_const(L_COEFF[i], v as u8);
            v += 1;
        }
        i += 1;
    }
    t
}

static L_TABLES: [[u8; 256]; 16] = build_l_tables();

// ── Core transforms ───────────────────────────────────────────────────────────

#[inline]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= y;
    }
}

#[inline]
fn apply_s(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = PI[*b as usize];
    }
}

#[inline]
fn apply_s_inv(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = PI_INV[*b as usize];
    }
}

/// l-function: linear combination of 16 bytes over GF(2⁸).
#[inline]
fn l_func(block: &[u8; 16]) -> u8 {
    let mut r = 0u8;
    for i in 0..16 {
        r ^= L_TABLES[i][block[i] as usize];
    }
    r
}

/// R step: push l(block) to front, shift right, drop last byte.
#[inline]
fn r_step(block: &mut [u8; 16]) {
    let lc = l_func(block);
    block.copy_within(0..15, 1); // block[1..=15] ← old block[0..=14]
    block[0] = lc;
}

/// R⁻¹ step: shift left, recover and append the missing last byte.
///
/// Since l-coefficient for the last input byte (a₀) is 1, the missing byte
/// equals block[0] XOR l(block[1..16] ∥ 0), with no modular inversion needed.
#[inline]
fn r_inv_step(block: &mut [u8; 16]) {
    // sum = L_COEFF[0..15] · block[1..16]
    let sum: u8 = (0..15).fold(0u8, |acc, i| acc ^ L_TABLES[i][block[i + 1] as usize]);
    let new_last = block[0] ^ sum;
    block.copy_within(1..16, 0); // block[0..=14] ← old block[1..=15]
    block[15] = new_last;
}

/// L = R¹⁶.
fn apply_l(block: &mut [u8; 16]) {
    for _ in 0..16 {
        r_step(block);
    }
}

/// L⁻¹ = (R⁻¹)¹⁶.
fn apply_l_inv(block: &mut [u8; 16]) {
    for _ in 0..16 {
        r_inv_step(block);
    }
}

/// Evaluate one Grasshopper S-box byte from the packed ANF representation.
///
/// The active monomials for the byte are expanded once, then each output bit
/// is recovered by intersecting with the precomputed masks and taking parity.
/// That parity step is the GF(2) sum of all ANF terms selected by this input.
#[inline(always)]
fn pi_eval(coeffs: &[[u128; 2]; 8], input: u8) -> u8 {
    crate::ct::eval_byte_sbox(coeffs, input)
}

#[inline]
fn apply_s_ct(block: &mut [u8; 16]) {
    // Same S layer as `apply_s()`, but each byte is evaluated through the
    // packed ANF representation instead of indexing the 256-byte table.
    for b in block.iter_mut() {
        *b = pi_eval(&PI_ANF, *b);
    }
}

#[inline]
fn apply_s_inv_ct(block: &mut [u8; 16]) {
    // Inverse S layer using the packed ANF form of `PI_INV`.
    for b in block.iter_mut() {
        *b = pi_eval(&PI_INV_ANF, *b);
    }
}

#[inline]
fn l_func_ct(block: &[u8; 16]) -> u8 {
    // Same linear map as `l_func()`. The Ct path computes the field products
    // directly instead of indexing `L_TABLES` with secret bytes.
    let mut r = 0u8;
    for i in 0..16 {
        r ^= gf_mul(L_COEFF[i], block[i]);
    }
    r
}

#[inline]
fn r_step_ct(block: &mut [u8; 16]) {
    let lc = l_func_ct(block);
    block.copy_within(0..15, 1);
    block[0] = lc;
}

#[inline]
fn r_inv_step_ct(block: &mut [u8; 16]) {
    let sum: u8 = (0..15).fold(0u8, |acc, i| acc ^ gf_mul(L_COEFF[i], block[i + 1]));
    let new_last = block[0] ^ sum;
    block.copy_within(1..16, 0);
    block[15] = new_last;
}

fn apply_l_ct(block: &mut [u8; 16]) {
    for _ in 0..16 {
        r_step_ct(block);
    }
}

fn apply_l_inv_ct(block: &mut [u8; 16]) {
    for _ in 0..16 {
        r_inv_step_ct(block);
    }
}

// ── Key schedule ──────────────────────────────────────────────────────────────
//
// Round constants C_i = L(Vec₁₂₈(i)), i = 1..32.
// Vec₁₂₈(i): 128-bit big-endian representation of i (stored as [u8; 16]).
// For i ≤ 255 this is [0, …, 0, i] with i in byte[15].
//
// Feistel step F[C](a₁, a₀) = (L(S(a₁ ⊕ C)) ⊕ a₀, a₁).
//
// Key K = k₁ ∥ k₀  (two 128-bit halves).
// K₁ = k₁, K₂ = k₀; round keys K₃–K₁₀ derived by 4 groups of 8 F steps
// using constants C₁–C₃₂.

fn round_const(i: u8) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[15] = i;
    apply_l(&mut v);
    v
}

fn round_const_ct(i: u8) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[15] = i;
    apply_l_ct(&mut v);
    v
}

fn f_step(a1: &mut [u8; 16], a0: &mut [u8; 16], c: &[u8; 16]) {
    let mut tmp = *a1;
    xor_block(&mut tmp, c); // X[C]
    apply_s(&mut tmp); // S
    apply_l(&mut tmp); // L
    xor_block(&mut tmp, a0); // XOR a₀
    *a0 = *a1; // old a₁ becomes new a₀
    *a1 = tmp; // new a₁
}

fn f_step_ct(a1: &mut [u8; 16], a0: &mut [u8; 16], c: &[u8; 16]) {
    let mut tmp = *a1;
    xor_block(&mut tmp, c);
    apply_s_ct(&mut tmp);
    apply_l_ct(&mut tmp);
    xor_block(&mut tmp, a0);
    *a0 = *a1;
    *a1 = tmp;
}

fn key_schedule(key: &[u8; 32]) -> [[u8; 16]; 10] {
    let mut rk = [[0u8; 16]; 10];
    rk[0].copy_from_slice(&key[0..16]); // K₁
    rk[1].copy_from_slice(&key[16..32]); // K₂

    let mut a1 = rk[0];
    let mut a0 = rk[1];

    for group in 0usize..4 {
        for step in 0usize..8 {
            let ci = (group * 8 + step + 1) as u8; // 1..=32
            let c = round_const(ci);
            f_step(&mut a1, &mut a0, &c);
        }
        rk[2 + group * 2] = a1; // K₃, K₅, K₇, K₉
        rk[3 + group * 2] = a0; // K₄, K₆, K₈, K₁₀
    }

    rk
}

fn key_schedule_ct(key: &[u8; 32]) -> [[u8; 16]; 10] {
    let mut rk = [[0u8; 16]; 10];
    rk[0].copy_from_slice(&key[0..16]);
    rk[1].copy_from_slice(&key[16..32]);

    let mut a1 = rk[0];
    let mut a0 = rk[1];

    for group in 0usize..4 {
        for step in 0usize..8 {
            let ci = (group * 8 + step + 1) as u8;
            let c = round_const_ct(ci);
            f_step_ct(&mut a1, &mut a0, &c);
        }
        rk[2 + group * 2] = a1;
        rk[3 + group * 2] = a0;
    }

    rk
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Kuznyechik (Grasshopper) block cipher — RFC 7801 / GOST R 34.12-2015.
///
/// 128-bit block, 256-bit key.  Pure Rust, no unsafe, no heap allocation.
pub struct Grasshopper {
    rk: [[u8; 16]; 10],
}

impl Grasshopper {
    /// Construct from a 32-byte (256-bit) key.
    pub fn new(key: &[u8; 32]) -> Self {
        Grasshopper {
            rk: key_schedule(key),
        }
    }

    /// Construct from a 32-byte key and wipe the provided key buffer.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt a 128-bit block (ECB mode).
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for i in 0..9 {
            xor_block(&mut s, &self.rk[i]);
            apply_s(&mut s);
            apply_l(&mut s);
        }
        xor_block(&mut s, &self.rk[9]);
        s
    }

    /// Decrypt a 128-bit block (ECB mode).
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        xor_block(&mut s, &self.rk[9]);
        for i in (0..9).rev() {
            apply_l_inv(&mut s);
            apply_s_inv(&mut s);
            xor_block(&mut s, &self.rk[i]);
        }
        s
    }
}

/// A software-only constant-time Grasshopper path.
///
/// `GrasshopperCt` keeps the standard round/key schedule structure, but avoids
/// the fast path's table-driven S and L layers: the S-box uses the packed ANF
/// bitset form above and the linear layer uses direct GF(2^8) arithmetic.
pub struct GrasshopperCt {
    rk: [[u8; 16]; 10],
}

impl GrasshopperCt {
    /// Construct from a 32-byte (256-bit) key.
    pub fn new(key: &[u8; 32]) -> Self {
        GrasshopperCt {
            rk: key_schedule_ct(key),
        }
    }

    /// Construct from a 32-byte key and wipe the provided key buffer.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt a 128-bit block (ECB mode).
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for i in 0..9 {
            xor_block(&mut s, &self.rk[i]);
            apply_s_ct(&mut s);
            apply_l_ct(&mut s);
        }
        xor_block(&mut s, &self.rk[9]);
        s
    }

    /// Decrypt a 128-bit block (ECB mode).
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        xor_block(&mut s, &self.rk[9]);
        for i in (0..9).rev() {
            apply_l_inv_ct(&mut s);
            apply_s_inv_ct(&mut s);
            xor_block(&mut s, &self.rk[i]);
        }
        s
    }
}

impl crate::BlockCipher for Grasshopper {
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

impl crate::BlockCipher for GrasshopperCt {
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

impl Drop for Grasshopper {
    fn drop(&mut self) {
        // Grasshopper keeps all 10 round keys in memory for repeated use.
        for rk in self.rk.iter_mut() {
            crate::ct::zeroize_slice(rk.as_mut_slice());
        }
    }
}

impl Drop for GrasshopperCt {
    fn drop(&mut self) {
        for rk in self.rk.iter_mut() {
            crate::ct::zeroize_slice(rk.as_mut_slice());
        }
    }
}

// ── Tests (all vectors from RFC 7801) ────────────────────────────────────────

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

    fn h32(s: &str) -> [u8; 32] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for x in 0u16..=255 {
            let b = x as u8;
            assert_eq!(pi_eval(&PI_ANF, b), PI[x as usize], "pi {x:02x}");
            assert_eq!(
                pi_eval(&PI_INV_ANF, b),
                PI_INV[x as usize],
                "pi_inv {x:02x}"
            );
        }
    }

    // ── S-transform (RFC 7801 §A.3) ───────────────────────────────────────────

    #[test]
    fn s_vectors() {
        let cases = [
            (
                "ffeeddccbbaa99881122334455667700",
                "b66cd8887d38e8d77765aeea0c9a7efc",
            ),
            (
                "b66cd8887d38e8d77765aeea0c9a7efc",
                "559d8dd7bd06cbfe7e7b262523280d39",
            ),
            (
                "559d8dd7bd06cbfe7e7b262523280d39",
                "0c3322fed531e4630d80ef5c5a81c50b",
            ),
            (
                "0c3322fed531e4630d80ef5c5a81c50b",
                "23ae65633f842d29c5df529c13f5acda",
            ),
        ];
        for (inp, exp) in cases {
            let mut b = h16(inp);
            apply_s(&mut b);
            assert_eq!(b, h16(exp), "S({inp})");
        }
    }

    // ── R-transform (RFC 7801 §A.4) ───────────────────────────────────────────

    #[test]
    fn r_vectors() {
        let cases = [
            (
                "00000000000000000000000000000100",
                "94000000000000000000000000000001",
            ),
            (
                "94000000000000000000000000000001",
                "a5940000000000000000000000000000",
            ),
            (
                "a5940000000000000000000000000000",
                "64a59400000000000000000000000000",
            ),
            (
                "64a59400000000000000000000000000",
                "0d64a594000000000000000000000000",
            ),
        ];
        for (inp, exp) in cases {
            let mut b = h16(inp);
            r_step(&mut b);
            assert_eq!(b, h16(exp), "R({inp})");
        }
    }

    // ── L-transform (RFC 7801 §A.5) ───────────────────────────────────────────

    #[test]
    fn l_vectors() {
        let cases = [
            (
                "64a59400000000000000000000000000",
                "d456584dd0e3e84cc3166e4b7fa2890d",
            ),
            (
                "d456584dd0e3e84cc3166e4b7fa2890d",
                "79d26221b87b584cd42fbc4ffea5de9a",
            ),
            (
                "79d26221b87b584cd42fbc4ffea5de9a",
                "0e93691a0cfc60408b7b68f66b513c13",
            ),
            (
                "0e93691a0cfc60408b7b68f66b513c13",
                "e6a8094fee0aa204fd97bcb0b44b8580",
            ),
        ];
        for (inp, exp) in cases {
            let mut b = h16(inp);
            apply_l(&mut b);
            assert_eq!(b, h16(exp), "L({inp})");
        }
    }

    // ── Encrypt / Decrypt (RFC 7801 §5.5) ────────────────────────────────────

    #[test]
    fn encrypt_decrypt_rfc() {
        let key = h32("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        let pt = h16("1122334455667700ffeeddccbbaa9988");
        let ct = h16("7f679d90bebc24305a468d42b9d4edcd");
        let c = Grasshopper::new(&key);
        assert_eq!(c.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(c.decrypt_block(&ct), pt, "decrypt");
    }

    #[test]
    fn encrypt_decrypt_rfc_ct() {
        let key = h32("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        let pt = h16("1122334455667700ffeeddccbbaa9988");
        let ct = h16("7f679d90bebc24305a468d42b9d4edcd");
        let fast = Grasshopper::new(&key);
        let slow = GrasshopperCt::new(&key);
        assert_eq!(slow.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(slow.decrypt_block(&ct), pt, "decrypt");
        assert_eq!(
            slow.encrypt_block(&pt),
            fast.encrypt_block(&pt),
            "match fast"
        );
    }

    // ── Key schedule (RFC 7801 §5.4) ─────────────────────────────────────────

    #[test]
    fn key_schedule_vectors() {
        let key = h32("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        let rk = key_schedule(&key);
        assert_eq!(rk[0], h16("8899aabbccddeeff0011223344556677"), "K_1");
        assert_eq!(rk[1], h16("fedcba98765432100123456789abcdef"), "K_2");
        assert_eq!(rk[2], h16("db31485315694343228d6aef8cc78c44"), "K_3");
        assert_eq!(rk[3], h16("3d4553d8e9cfec6815ebadc40a9ffd04"), "K_4");
        assert_eq!(rk[4], h16("57646468c44a5e28d3e59246f429f1ac"), "K_5");
        assert_eq!(rk[9], h16("72e9dd7416bcf45b755dbaa88e4a4043"), "K_10");
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip() {
        let key = [0xABu8; 32];
        let pt = [0x42u8; 16];
        let c = Grasshopper::new(&key);
        assert_eq!(c.decrypt_block(&c.encrypt_block(&pt)), pt);
    }

    // ── Round constants (RFC 7801 §5.4) ──────────────────────────────────────

    #[test]
    fn round_const_vectors() {
        assert_eq!(
            round_const(1),
            h16("6ea276726c487ab85d27bd10dd849401"),
            "C_1"
        );
        assert_eq!(
            round_const(2),
            h16("dc87ece4d890f4b3ba4eb92079cbeb02"),
            "C_2"
        );
        assert_eq!(
            round_const(3),
            h16("b2259a96b4d88e0be7690430a44f7f03"),
            "C_3"
        );
        assert_eq!(
            round_const(4),
            h16("7bcd1b0b73e32ba5b79cb140f2551504"),
            "C_4"
        );
        assert_eq!(
            round_const(5),
            h16("156f6d791fab511deabb0c502fd18105"),
            "C_5"
        );
        assert_eq!(
            round_const(6),
            h16("a74af7efab73df160dd208608b9efe06"),
            "C_6"
        );
        assert_eq!(
            round_const(7),
            h16("c9e8819dc73ba5ae50f5b570561a6a07"),
            "C_7"
        );
        assert_eq!(
            round_const(8),
            h16("f6593616e6055689adfba18027aa2a08"),
            "C_8"
        );
    }
}
