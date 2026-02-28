//! Magma (GOST R 34.12-2015) block cipher — RFC 8891.
//!
//! 64-bit block, 256-bit key, 32 Feistel rounds.
//! All tables and test vectors from RFC 8891.

// ── S-boxes (RFC 8891 §4.1) ────────────────────────────────────────────────
//
// Eight 4-bit bijections Pi'_0 .. Pi'_7.
// Pi'_i processes nibble i of the 32-bit word (nibble 0 = bits [3:0]).

const PI: [[u8; 16]; 8] = [
    [12,  4,  6,  2, 10,  5, 11,  9, 14,  8, 13,  7,  0,  3, 15,  1], // Pi'_0
    [ 6,  8,  2,  3,  9, 10,  5, 12,  1, 14,  4,  7, 11, 13,  0, 15], // Pi'_1
    [11,  3,  5,  8,  2, 15, 10, 13, 14,  1,  7,  4, 12,  9,  6,  0], // Pi'_2
    [12,  8,  2,  1, 13,  4, 15,  6,  7,  0, 10,  5,  3, 14,  9, 11], // Pi'_3
    [ 7, 15,  5, 10,  8,  1,  6, 13,  0,  9,  3, 14, 11,  4,  2, 12], // Pi'_4
    [ 5, 13, 15,  6,  9,  2, 12, 10, 11,  7,  8,  1,  4,  3, 14,  0], // Pi'_5
    [ 8, 14,  2,  5,  6,  9,  1, 12, 15,  4, 11,  0, 13, 10,  3,  7], // Pi'_6
    [ 1,  7, 14, 13,  0,  5,  8,  3,  4, 15, 10,  6,  9, 12, 11,  2], // Pi'_7
];

// ── Core transforms ────────────────────────────────────────────────────────

/// t(v): apply 8 independent 4-bit S-boxes to a 32-bit word.
/// Nibble i (bits [4i+3 : 4i]) is passed through Pi'_i.
#[inline]
fn t(v: u32) -> u32 {
    let mut r = 0u32;
    for i in 0..8usize {
        let nibble = ((v >> (4 * i)) & 0xf) as u8;
        // Scan all 16 entries instead of indexing by a secret nibble.
        let sub = crate::ct::ct_lookup_u8(&PI[i], nibble);
        r |= (sub as u32) << (4 * i);
    }
    r
}

/// g[k](a): wrapping-add key, substitute, rotate left 11 bits.
#[inline]
fn g(k: u32, a: u32) -> u32 {
    t(a.wrapping_add(k)).rotate_left(11)
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
    for i in 0..24 { enc[i]      = k[i % 8]; }   // rounds 1–24: forward three times
    for i in 0..8  { enc[24 + i] = k[7 - i]; }    // rounds 25–32: reversed once

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

fn magma_core(block: &[u8; 8], rk: &[u32; 32]) -> [u8; 8] {
    let mut a1 = u32::from_be_bytes(block[0..4].try_into().unwrap()); // upper
    let mut a0 = u32::from_be_bytes(block[4..8].try_into().unwrap()); // lower

    for r in 0..31 {
        let tmp = g(rk[r], a0) ^ a1;
        a1 = a0;
        a0 = tmp;
    }

    // G* (final round — no swap)
    let c1 = g(rk[31], a0) ^ a1; // upper half of output
    let c0 = a0;                   // lower half of output

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
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        magma_core(block, &self.enc_rk)
    }

    /// Decrypt a 64-bit block (ECB mode).
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        magma_core(block, &self.dec_rk)
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

impl Drop for Magma {
    fn drop(&mut self) {
        // Magma caches both round-key orders; wipe them when the instance dies.
        crate::ct::zeroize_slice(self.enc_rk.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_rk.as_mut_slice());
    }
}

// ── Tests (vectors from RFC 8891) ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn h8(s: &str) -> [u8; 8] {
        let b: Vec<u8> = (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    fn h32(s: &str) -> [u8; 32] {
        let b: Vec<u8> = (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    // ── Encrypt / Decrypt (RFC 8891 §A.3) ────────────────────────────────

    #[test]
    fn encrypt_decrypt_rfc() {
        let key = h32("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt  = h8("fedcba9876543210");
        let ct  = h8("4ee901e5c2d8ca3d");
        let m = Magma::new(&key);
        assert_eq!(m.encrypt_block(&pt), ct, "encrypt");
        assert_eq!(m.decrypt_block(&ct), pt, "decrypt");
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let pt  = [0xABu8; 8];
        let m = Magma::new(&key);
        assert_eq!(m.decrypt_block(&m.encrypt_block(&pt)), pt);
    }
}
