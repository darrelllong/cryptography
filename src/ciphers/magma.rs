//! Magma (GOST R 34.12-2015) block cipher — RFC 8891.
//!
//! 64-bit block, 256-bit key, 32 Feistel rounds.
//! All tables and test vectors from RFC 8891.
//!
//! `Magma` keeps the original fast table lookups. `MagmaCt` is separate and
//! replaces only the eight 4-bit substitutions with fixed boolean circuits,
//! which is enough to remove secret-indexed lookups from the round function
//! while keeping the implementation compact.

// ── S-boxes (RFC 8891 §4.1) ────────────────────────────────────────────────
//
// Eight 4-bit bijections Pi'_0 .. Pi'_7.
// Pi'_i processes nibble i of the 32-bit word (nibble 0 = bits [3:0]).

const PI: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1], // Pi'_0
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15], // Pi'_1
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0], // Pi'_2
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11], // Pi'_3
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12], // Pi'_4
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0], // Pi'_5
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7], // Pi'_6
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2], // Pi'_7
];

// ── Core transforms ────────────────────────────────────────────────────────

/// t(v): apply 8 independent 4-bit S-boxes to a 32-bit word.
/// Nibble i (bits [4i+3 : 4i]) is passed through Pi'_i.
#[inline]
fn t(v: u32) -> u32 {
    let mut r = 0u32;
    for (i, sbox) in PI.iter().enumerate() {
        let nibble = ((v >> (4 * i)) & 0xf) as usize;
        let sub = sbox[nibble];
        r |= u32::from(sub) << (4 * i);
    }
    r
}

#[inline]
fn nibble_monomials(nibble: u8) -> ([u8; 4], [u8; 6], [u8; 4]) {
    let bits = [
        nibble & 1,
        (nibble >> 1) & 1,
        (nibble >> 2) & 1,
        (nibble >> 3) & 1,
    ];
    let pairs = [
        bits[0] & bits[1],
        bits[0] & bits[2],
        bits[0] & bits[3],
        bits[1] & bits[2],
        bits[1] & bits[3],
        bits[2] & bits[3],
    ];
    let triples = [
        pairs[0] & bits[2],
        pairs[0] & bits[3],
        pairs[1] & bits[3],
        pairs[3] & bits[3],
    ];
    (bits, pairs, triples)
}

// The Ct path uses eight tiny 4->4 circuits. For Magma these are small enough
// to keep in source directly, unlike the larger DES and Grasshopper S-boxes.
//
// Each `pi*_ct` function is the ANF of one RFC S-box, written directly over
// the four input bits. Terms like `x01` or `x123` are monomials, and a literal
// `1` in a `b*` expression is the ANF constant term. The four `b*` wires are
// then packed back into the substituted nibble.
#[inline]
fn pi0_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = pairs[1] ^ pairs[3] ^ triples[0] ^ pairs[4] ^ triples[3];
    let b1 = bits[1] ^ bits[2] ^ pairs[1] ^ pairs[3] ^ bits[3] ^ pairs[2] ^ triples[2] ^ triples[3];
    let b2 = 1 ^ pairs[0] ^ bits[2] ^ pairs[1] ^ pairs[2] ^ triples[3];
    let b3 = 1 ^ bits[0] ^ bits[1] ^ pairs[0] ^ pairs[3] ^ pairs[2] ^ pairs[4] ^ pairs[5];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi1_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = pairs[0]
        ^ bits[2]
        ^ pairs[1]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[1]
        ^ pairs[5];
    let b1 = 1 ^ bits[0] ^ pairs[0] ^ bits[2] ^ bits[3] ^ triples[1] ^ triples[3];
    let b2 = 1
        ^ bits[0]
        ^ bits[1]
        ^ pairs[0]
        ^ bits[2]
        ^ pairs[1]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[5]
        ^ triples[2]
        ^ triples[3];
    let b3 = bits[0] ^ pairs[0] ^ bits[2] ^ pairs[1] ^ pairs[3];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi2_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = 1
        ^ pairs[0]
        ^ bits[2]
        ^ pairs[1]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[1]
        ^ pairs[5]
        ^ triples[2]
        ^ triples[3];
    let b1 = 1 ^ bits[1] ^ pairs[3] ^ triples[0] ^ pairs[2] ^ pairs[4] ^ pairs[5] ^ triples[2];
    let b2 = bits[1]
        ^ pairs[0]
        ^ pairs[1]
        ^ pairs[3]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[2]
        ^ triples[3];
    let b3 = 1 ^ bits[0] ^ bits[1] ^ bits[2] ^ triples[0] ^ triples[1] ^ pairs[5] ^ triples[2];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi3_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = pairs[0]
        ^ bits[2]
        ^ pairs[1]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[1]
        ^ pairs[5]
        ^ triples[2]
        ^ triples[3];
    let b1 = bits[1]
        ^ pairs[0]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[1]
        ^ triples[2]
        ^ triples[3];
    let b2 = 1
        ^ bits[0]
        ^ bits[1]
        ^ pairs[0]
        ^ pairs[1]
        ^ pairs[3]
        ^ triples[0]
        ^ triples[1]
        ^ pairs[5]
        ^ triples[2];
    let b3 = 1 ^ bits[1] ^ pairs[1] ^ pairs[3] ^ bits[3] ^ triples[1] ^ triples[3];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi4_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = 1
        ^ pairs[0]
        ^ bits[2]
        ^ pairs[1]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[1]
        ^ triples[2];
    let b1 = 1 ^ bits[1] ^ pairs[0] ^ bits[2] ^ bits[3] ^ triples[1] ^ triples[2] ^ triples[3];
    let b2 = 1
        ^ pairs[0]
        ^ bits[2]
        ^ pairs[3]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[5]
        ^ triples[2]
        ^ triples[3];
    let b3 = bits[0] ^ bits[2] ^ pairs[3];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi5_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = 1 ^ pairs[0] ^ pairs[1] ^ pairs[3] ^ pairs[4] ^ pairs[5];
    let b1 = bits[1] ^ pairs[1] ^ pairs[3] ^ bits[3] ^ pairs[5] ^ triples[3];
    let b2 = 1 ^ bits[2] ^ pairs[3] ^ triples[0] ^ bits[3] ^ pairs[2] ^ triples[1] ^ triples[3];
    let b3 = bits[0] ^ bits[1] ^ bits[2] ^ pairs[3] ^ triples[0] ^ bits[3] ^ pairs[4] ^ triples[2];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi6_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = pairs[0]
        ^ pairs[1]
        ^ pairs[3]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ triples[1]
        ^ triples[2]
        ^ triples[3];
    let b1 = bits[0] ^ bits[1] ^ bits[2] ^ triples[0] ^ bits[3] ^ pairs[4] ^ triples[3];
    let b2 = bits[0]
        ^ bits[2]
        ^ pairs[3]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ pairs[5]
        ^ triples[2]
        ^ triples[3];
    let b3 = 1 ^ bits[1] ^ bits[2] ^ pairs[1] ^ pairs[3] ^ pairs[2] ^ pairs[4] ^ pairs[5];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[inline]
fn pi7_ct(nibble: u8) -> u8 {
    let (bits, pairs, triples) = nibble_monomials(nibble);

    let b0 = 1
        ^ bits[1]
        ^ pairs[0]
        ^ bits[2]
        ^ pairs[1]
        ^ pairs[3]
        ^ triples[0]
        ^ bits[3]
        ^ pairs[2]
        ^ pairs[4]
        ^ triples[2]
        ^ triples[3];
    let b1 = bits[0] ^ bits[1] ^ pairs[1] ^ pairs[3] ^ triples[0] ^ triples[1] ^ triples[3];
    let b2 = bits[0] ^ bits[1] ^ pairs[0] ^ pairs[3] ^ bits[3] ^ pairs[2] ^ pairs[5] ^ triples[2];
    let b3 = bits[1] ^ triples[0] ^ pairs[2] ^ pairs[5] ^ triples[2] ^ triples[3];

    b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
}

#[cfg(test)]
#[inline]
fn pi_ct(box_idx: usize, nibble: u8) -> u8 {
    match box_idx {
        0 => pi0_ct(nibble),
        1 => pi1_ct(nibble),
        2 => pi2_ct(nibble),
        3 => pi3_ct(nibble),
        4 => pi4_ct(nibble),
        5 => pi5_ct(nibble),
        6 => pi6_ct(nibble),
        7 => pi7_ct(nibble),
        _ => unreachable!(),
    }
}

/// Constant-time variant of `t(v)`.
///
/// This is the same eight-nibble substitution as `t()`, but each nibble is
/// routed through its explicit boolean circuit instead of indexing `PI`.
#[inline]
fn t_ct(v: u32) -> u32 {
    let n0 = (v & 0x0000_000f) as u8;
    let n1 = ((v >> 4) & 0x0000_000f) as u8;
    let n2 = ((v >> 8) & 0x0000_000f) as u8;
    let n3 = ((v >> 12) & 0x0000_000f) as u8;
    let n4 = ((v >> 16) & 0x0000_000f) as u8;
    let n5 = ((v >> 20) & 0x0000_000f) as u8;
    let n6 = ((v >> 24) & 0x0000_000f) as u8;
    let n7 = ((v >> 28) & 0x0000_000f) as u8;

    u32::from(pi0_ct(n0))
        | (u32::from(pi1_ct(n1)) << 4)
        | (u32::from(pi2_ct(n2)) << 8)
        | (u32::from(pi3_ct(n3)) << 12)
        | (u32::from(pi4_ct(n4)) << 16)
        | (u32::from(pi5_ct(n5)) << 20)
        | (u32::from(pi6_ct(n6)) << 24)
        | (u32::from(pi7_ct(n7)) << 28)
}

/// g[k](a): wrapping-add key, substitute, rotate left 11 bits.
#[inline]
fn g(k: u32, a: u32) -> u32 {
    t(a.wrapping_add(k)).rotate_left(11)
}

#[inline]
fn g_ct(k: u32, a: u32) -> u32 {
    // Same Feistel round function as `g()`: the only change is the Ct
    // substitution inside `t_ct`.
    t_ct(a.wrapping_add(k)).rotate_left(11)
}

// ── Key schedule (RFC 8891 §4.3) ───────────────────────────────────────────
//
// 256-bit key K split into 8 × 32-bit subkeys (big-endian bytes):
//   k[i] = K_{i+1} = k_{255-32i} .. k_{224-32i}
//
// Encryption round key sequence (32 keys):
//   k[0..8]  (×3 = rounds 1–24)  then  k[7..0]  (×1 = rounds 25–32)
//
// Decryption round key sequence = encryption sequence reversed:
//   k[0..8]  (×1)  then  k[7..0]  (×3)

fn build_round_keys(key: &[u8; 32]) -> ([u32; 32], [u32; 32]) {
    let mut k = [0u32; 8];
    for i in 0..8 {
        k[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }

    let mut enc = [0u32; 32];
    for i in 0..24 {
        enc[i] = k[i % 8];
    } // rounds 1–24: forward three times
    for i in 0..8 {
        enc[24 + i] = k[7 - i];
    } // rounds 25–32: reversed once

    let mut dec = enc;
    dec.reverse();

    (enc, dec)
}

// ── Feistel core ───────────────────────────────────────────────────────────
//
// Block is split as a₁ || a₀  (a₁ = upper 32 bits, a₀ = lower 32 bits).
//
// Rounds 1–31: G[k](a₁, a₀) = (a₀,  g[k](a₀) ⊕ a₁)  — apply then swap
// Round 32:   G*[k](a₁, a₀) = (g[k](a₀) ⊕ a₁) || a₀  — apply, no swap

fn magma_core(block: [u8; 8], rk: &[u32; 32]) -> [u8; 8] {
    let mut a1 = u32::from_be_bytes(block[0..4].try_into().unwrap()); // upper
    let mut a0 = u32::from_be_bytes(block[4..8].try_into().unwrap()); // lower

    for &round_key in rk.iter().take(31) {
        let tmp = g(round_key, a0) ^ a1;
        a1 = a0;
        a0 = tmp;
    }

    // G* (final round — no swap)
    let c1 = g(rk[31], a0) ^ a1; // upper half of output
    let c0 = a0; // lower half of output

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&c1.to_be_bytes());
    out[4..8].copy_from_slice(&c0.to_be_bytes());
    out
}

fn magma_core_ct(block: [u8; 8], rk: &[u32; 32]) -> [u8; 8] {
    let mut a1 = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut a0 = u32::from_be_bytes(block[4..8].try_into().unwrap());

    for &round_key in rk.iter().take(31) {
        let tmp = g_ct(round_key, a0) ^ a1;
        a1 = a0;
        a0 = tmp;
    }

    let c1 = g_ct(rk[31], a0) ^ a1;
    let c0 = a0;

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&c1.to_be_bytes());
    out[4..8].copy_from_slice(&c0.to_be_bytes());
    out
}

// ── Public interface ───────────────────────────────────────────────────────

/// Magma block cipher — RFC 8891 / GOST R 34.12-2015.
///
/// 64-bit block, 256-bit key.  Pure Rust, no unsafe, no heap allocation.
pub struct Magma {
    enc_rk: [u32; 32],
    dec_rk: [u32; 32],
}

impl Magma {
    /// Construct from a 32-byte (256-bit) key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let (enc_rk, dec_rk) = build_round_keys(key);
        Magma { enc_rk, dec_rk }
    }

    /// Construct from a 32-byte key and wipe the provided key buffer.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt a 64-bit block (ECB mode).
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        magma_core(*block, &self.enc_rk)
    }

    /// Decrypt a 64-bit block (ECB mode).
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        magma_core(*block, &self.dec_rk)
    }
}

/// A software-only constant-time Magma path.
///
/// `MagmaCt` keeps Magma's original structure and key schedule, but replaces
/// the nibble S-box lookups with the fixed boolean circuits above so the round
/// function no longer indexes memory with secret-derived values.
pub struct MagmaCt {
    enc_rk: [u32; 32],
    dec_rk: [u32; 32],
}

impl MagmaCt {
    /// Construct from a 32-byte (256-bit) key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let (enc_rk, dec_rk) = build_round_keys(key);
        MagmaCt { enc_rk, dec_rk }
    }

    /// Construct from a 32-byte key and wipe the provided key buffer.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt a 64-bit block (ECB mode).
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        magma_core_ct(*block, &self.enc_rk)
    }

    /// Decrypt a 64-bit block (ECB mode).
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        magma_core_ct(*block, &self.dec_rk)
    }
}

impl crate::BlockCipher for Magma {
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

impl crate::BlockCipher for MagmaCt {
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

impl Drop for Magma {
    fn drop(&mut self) {
        // Magma caches both round-key orders; wipe them when the instance dies.
        crate::ct::zeroize_slice(self.enc_rk.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_rk.as_mut_slice());
    }
}

impl Drop for MagmaCt {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.enc_rk.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_rk.as_mut_slice());
    }
}

// ── Tests (vectors from RFC 8891) ─────────────────────────────────────────

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

    fn h32(s: &str) -> [u8; 32] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    // ── Encrypt / Decrypt (RFC 8891 §A.3) ────────────────────────────────

    #[test]
    fn encrypt_decrypt_rfc() {
        let key = h32("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = h8("fedcba9876543210");
        let ct = h8("4ee901e5c2d8ca3d");
        let m = Magma::new(&key);
        assert_eq!(m.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(m.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let pt = [0xABu8; 8];
        let m = Magma::new(&key);
        assert_eq!(m.decrypt_block(&m.encrypt_block(&pt)), pt);
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for (box_idx, table) in PI.iter().enumerate() {
            for nibble in 0u8..16 {
                assert_eq!(pi_ct(box_idx, nibble), table[nibble as usize]);
            }
        }
    }

    #[test]
    fn encrypt_decrypt_rfc_ct() {
        let key = h32("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = h8("fedcba9876543210");
        let ct = h8("4ee901e5c2d8ca3d");
        let fast = Magma::new(&key);
        let slow = MagmaCt::new(&key);
        assert_eq!(slow.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(slow.decrypt_block(&ct), pt, "decrypt");
        assert_eq!(
            slow.encrypt_block(&pt),
            fast.encrypt_block(&pt),
            "match fast"
        );
    }
}
