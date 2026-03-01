//! ZUC-128 stream cipher — GM/T 0001.1 / ETSI SAGE ZUC specification v1.6.
//!
//! 128-bit key, 128-bit IV.  Outputs 32-bit keystream words.
//! Used in 3GPP LTE as 128-EEA3 (confidentiality) and 128-EIA3 (integrity).
//!
//! Architecture (spec §2):
//!   - LFSR: 16 cells s[0]..s[15], each a 31-bit integer in GF(2³¹−1).
//!   - Bit reorganization (BR): extracts four 32-bit words X0..X3 from LFSR.
//!   - Nonlinear function F: two 32-bit memory registers R1, R2; takes
//!     X0, X1, X2; produces output W.  Uses composite S-box S=(S0,S1,S0,S1)
//!     and linear transforms L1, L2.
//!   - Keystream word: Z = W ⊕ X3  (working phase only).
//!
//! `Zuc128` keeps the direct S-box table lookups. `Zuc128Ct` is separate and
//! evaluates the same two 8-bit S-boxes through packed ANF bitsets so the
//! nonlinear function avoids secret-indexed table reads.

// ── S-boxes (spec §2.2.4) ─────────────────────────────────────────────────
//
// S is the 32-bit composite S-box S = (S0, S1, S0, S1):
//   byte 3 (MSB) → S0,  byte 2 → S1,  byte 1 → S0,  byte 0 (LSB) → S1.

#[rustfmt::skip]
const S0: [u8; 256] = [
    0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
    0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
    0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
    0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
    0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
    0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
    0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
    0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
    0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
    0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
    0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
    0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
    0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
    0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
    0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
    0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60,
];

#[rustfmt::skip]
const S1: [u8; 256] = [
    0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
    0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
    0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
    0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
    0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
    0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
    0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
    0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
    0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
    0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
    0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
    0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
    0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2,
];

/// Build packed ANF coefficients for a ZUC byte S-box.
const S0_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&S0);
const S1_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&S1);

// ── LFSR initialization constants (spec §2.2.1) ────────────────────────────
//
// d[i] are 15-bit constants packed into the middle of each 31-bit LFSR cell:
//   s[i] = key[i](8b) ‖ d[i](15b) ‖ iv[i](8b)

const D: [u16; 16] = [
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 0x4D78, 0x2F13, 0x6BC4, 0x1AF1,
    0x5E26, 0x3C4D, 0x789A, 0x47AC,
];

// ── GF(2³¹ − 1) arithmetic ────────────────────────────────────────────────
//
// LFSR cells are 31-bit integers in Z/(2³¹−1)Z, stored in bits 30:0 of u32.
// Multiplication by 2ⁿ mod (2³¹−1) is a 31-bit left rotation by n
// (since 2³¹ ≡ 1 mod (2³¹−1)).

/// Addition mod (2³¹ − 1).
#[inline]
fn add31(a: u32, b: u32) -> u32 {
    let c = a.wrapping_add(b);
    (c & 0x7FFF_FFFF).wrapping_add(c >> 31)
}

/// Multiply by 2ⁿ mod (2³¹ − 1) — i.e., 31-bit left rotation by n bits.
#[inline]
fn mul31(a: u32, n: u32) -> u32 {
    ((a << n) | (a >> (31 - n))) & 0x7FFF_FFFF
}

// ── Composite S-box and linear transforms ─────────────────────────────────

/// Composite 32-bit S-box S = (S0, S1, S0, S1), MSB first (spec §2.2.4).
#[inline]
fn sbox(x: u32) -> u32 {
    (S0[(x >> 24) as usize] as u32) << 24
        | (S1[((x >> 16) & 0xFF) as usize] as u32) << 16
        | (S0[((x >> 8) & 0xFF) as usize] as u32) << 8
        | (S1[(x & 0xFF) as usize] as u32)
}

#[inline(always)]
fn sbox_eval(coeffs: &[[u128; 2]; 8], input: u8) -> u8 {
    crate::ct::eval_byte_sbox(coeffs, input)
}

/// Constant-time composite 32-bit S-box using the packed ANF forms of S0/S1.
#[inline]
fn sbox_ct(x: u32) -> u32 {
    (sbox_eval(&S0_ANF, (x >> 24) as u8) as u32) << 24
        | (sbox_eval(&S1_ANF, ((x >> 16) & 0xFF) as u8) as u32) << 16
        | (sbox_eval(&S0_ANF, ((x >> 8) & 0xFF) as u8) as u32) << 8
        | (sbox_eval(&S1_ANF, (x & 0xFF) as u8) as u32)
}

/// Linear transform L1 (spec §2.2.3).
#[inline]
fn l1(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

/// Linear transform L2 (spec §2.2.3).
#[inline]
fn l2(x: u32) -> u32 {
    x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
}

// ── ZUC-128 ───────────────────────────────────────────────────────────────

struct ZucCore {
    s: [u32; 16],
    r1: u32,
    r2: u32,
}

#[inline]
fn bit_reorganization(s: &[u32; 16]) -> (u32, u32, u32, u32) {
    let x0 = ((s[15] << 1) & 0xFFFF_0000) | (s[14] & 0xFFFF);
    let x1 = ((s[11] << 16) & 0xFFFF_0000) | ((s[9] >> 15) & 0xFFFF);
    let x2 = ((s[7] << 16) & 0xFFFF_0000) | ((s[5] >> 15) & 0xFFFF);
    let x3 = ((s[2] << 16) & 0xFFFF_0000) | ((s[0] >> 15) & 0xFFFF);
    (x0, x1, x2, x3)
}

#[inline]
fn nonlinear_f<const CT: bool>(core: &mut ZucCore, x0: u32, x1: u32, x2: u32) -> u32 {
    let w = (x0 ^ core.r1).wrapping_add(core.r2);
    let w1 = core.r1.wrapping_add(x1);
    let w2 = core.r2 ^ x2;
    let sbox_fn = if CT { sbox_ct } else { sbox };
    core.r1 = sbox_fn(l1((w1 << 16) | (w2 >> 16)));
    core.r2 = sbox_fn(l2((w2 << 16) | (w1 >> 16)));
    w
}

#[inline]
fn lfsr_feedback(s: &[u32; 16]) -> u32 {
    let mut v = s[0];
    v = add31(v, mul31(s[0], 8));
    v = add31(v, mul31(s[4], 20));
    v = add31(v, mul31(s[10], 21));
    v = add31(v, mul31(s[13], 17));
    v = add31(v, mul31(s[15], 15));
    v
}

#[inline]
fn lfsr_clock(s: &mut [u32; 16], new_val: u32) {
    s.copy_within(1..16, 0);
    s[15] = if new_val == 0 { 0x7FFF_FFFF } else { new_val };
}

fn init_core<const CT: bool>(key: &[u8; 16], iv: &[u8; 16]) -> ZucCore {
    let mut s = [0u32; 16];
    for i in 0..16 {
        s[i] = ((key[i] as u32) << 23) | ((D[i] as u32) << 8) | (iv[i] as u32);
    }
    let mut core = ZucCore { s, r1: 0, r2: 0 };

    for _ in 0..32 {
        let (x0, x1, x2, _) = bit_reorganization(&core.s);
        let w = nonlinear_f::<CT>(&mut core, x0, x1, x2);
        let s16 = add31(lfsr_feedback(&core.s), w >> 1);
        lfsr_clock(&mut core.s, s16);
    }

    let (x0, x1, x2, _) = bit_reorganization(&core.s);
    nonlinear_f::<CT>(&mut core, x0, x1, x2);
    let fb = lfsr_feedback(&core.s);
    lfsr_clock(&mut core.s, fb);

    core
}

#[inline]
fn next_word_core<const CT: bool>(core: &mut ZucCore) -> u32 {
    let (x0, x1, x2, x3) = bit_reorganization(&core.s);
    let w = nonlinear_f::<CT>(core, x0, x1, x2);
    let fb = lfsr_feedback(&core.s);
    lfsr_clock(&mut core.s, fb);
    w ^ x3
}

fn fill_core<const CT: bool>(core: &mut ZucCore, buf: &mut [u8]) {
    let mut chunks = buf.chunks_exact_mut(4);
    for ch in &mut chunks {
        let ks = next_word_core::<CT>(core).to_be_bytes();
        for (b, k) in ch.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let ks = next_word_core::<CT>(core).to_be_bytes();
        for (b, k) in rem.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
}

/// ZUC-128 stream cipher (GM/T 0001.1 / ETSI SAGE ZUC v1.6).
///
/// Generates 32-bit keystream words via [`next_word`]; byte-oriented output
/// via [`fill`].  Each instance is single-use: reconstruct with a fresh IV
/// to re-key.
///
/// [`next_word`]: Zuc128::next_word
/// [`fill`]: Zuc128::fill
pub struct Zuc128 {
    core: ZucCore,
}

/// ZUC-128 constant-time software path.
///
/// `Zuc128Ct` keeps the same LFSR, bit-reorganization, and linear transforms as
/// `Zuc128`, but replaces the S-box table reads inside the nonlinear function
/// with the packed ANF evaluator above.
pub struct Zuc128Ct {
    core: ZucCore,
}

impl Zuc128 {
    /// Construct and initialize ZUC-128 from a 128-bit key and 128-bit IV.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            core: init_core::<false>(key, iv),
        }
    }

    /// Generate the next 32-bit keystream word.
    pub fn next_word(&mut self) -> u32 {
        next_word_core::<false>(&mut self.core)
    }

    /// XOR `buf` with keystream bytes (32-bit words in big-endian byte order).
    ///
    /// Calling `fill` twice with the same key/IV and an identical buffer
    /// recovers the original contents (stream-cipher encrypt/decrypt).
    pub fn fill(&mut self, buf: &mut [u8]) {
        fill_core::<false>(&mut self.core, buf);
    }
}

impl Zuc128Ct {
    /// Construct and initialize ZUC-128Ct from a 128-bit key and 128-bit IV.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            core: init_core::<true>(key, iv),
        }
    }

    /// Construct and wipe the caller-provided key and IV buffers.
    pub fn new_wiping(key: &mut [u8; 16], iv: &mut [u8; 16]) -> Self {
        let out = Self::new(key, iv);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(iv.as_mut_slice());
        out
    }

    /// Generate the next 32-bit keystream word.
    pub fn next_word(&mut self) -> u32 {
        next_word_core::<true>(&mut self.core)
    }

    /// XOR `buf` with keystream bytes (32-bit words in big-endian byte order).
    pub fn fill(&mut self, buf: &mut [u8]) {
        fill_core::<true>(&mut self.core, buf);
    }
}

impl Drop for Zuc128 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.s.as_mut_slice());
        self.core.r1 = 0;
        self.core.r2 = 0;
    }
}

impl Drop for Zuc128Ct {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.s.as_mut_slice());
        self.core.r1 = 0;
        self.core.r2 = 0;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Official test vectors (ZUC spec §3 / ETSI SAGE ZUC v1.6 Appendix) ─

    // Test Set 1: key = 0x00*16, iv = 0x00*16.
    #[test]
    fn keystream_zeros() {
        let mut z = Zuc128::new(&[0u8; 16], &[0u8; 16]);
        assert_eq!(z.next_word(), 0x27bede74, "Z[0]");
        assert_eq!(z.next_word(), 0x018082da, "Z[1]");
    }

    // Test Set 2: key = 0xFF*16, iv = 0xFF*16.
    #[test]
    fn keystream_ones() {
        let mut z = Zuc128::new(&[0xFFu8; 16], &[0xFFu8; 16]);
        assert_eq!(z.next_word(), 0x0657cfa0, "Z[0]");
        assert_eq!(z.next_word(), 0x7096398b, "Z[1]");
    }

    // Test Set 3: mixed key / IV (ZUC spec §3, test set 3).
    #[test]
    fn keystream_mixed() {
        let key = [
            0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b,
            0x45, 0x5b,
        ];
        let iv = [
            0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8,
            0xc7, 0x66,
        ];
        let mut z = Zuc128::new(&key, &iv);
        assert_eq!(z.next_word(), 0x14f1c272, "Z[0]");
        assert_eq!(z.next_word(), 0x3279c419, "Z[1]");
    }

    #[test]
    fn keystream_zeros_ct() {
        let mut z = Zuc128Ct::new(&[0u8; 16], &[0u8; 16]);
        assert_eq!(z.next_word(), 0x27bede74, "Z[0]");
        assert_eq!(z.next_word(), 0x018082da, "Z[1]");
    }

    #[test]
    fn keystream_ones_ct() {
        let mut z = Zuc128Ct::new(&[0xFFu8; 16], &[0xFFu8; 16]);
        assert_eq!(z.next_word(), 0x0657cfa0, "Z[0]");
        assert_eq!(z.next_word(), 0x7096398b, "Z[1]");
    }

    #[test]
    fn keystream_mixed_ct() {
        let key = [
            0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b,
            0x45, 0x5b,
        ];
        let iv = [
            0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8,
            0xc7, 0x66,
        ];
        let mut z = Zuc128Ct::new(&key, &iv);
        assert_eq!(z.next_word(), 0x14f1c272, "Z[0]");
        assert_eq!(z.next_word(), 0x3279c419, "Z[1]");
    }

    // fill() XOR roundtrip: encrypt then decrypt returns plaintext.
    #[test]
    fn fill_xor_roundtrip() {
        let plaintext = b"Hello, ZUC-128!!";
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let mut buf = *plaintext;
        Zuc128::new(&key, &iv).fill(&mut buf);
        Zuc128::new(&key, &iv).fill(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    #[test]
    fn fill_xor_roundtrip_ct() {
        let plaintext = b"Hello, ZUC-128!!";
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let mut buf = *plaintext;
        Zuc128Ct::new(&key, &iv).fill(&mut buf);
        Zuc128Ct::new(&key, &iv).fill(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    // fill() with non-multiple-of-4 length produces the same bytes as an
    // aligned fill of the next larger multiple of 4, truncated to the
    // requested length.
    #[test]
    fn fill_partial_word() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut buf7 = [0u8; 7];
        let mut buf8 = [0u8; 8];
        Zuc128::new(&key, &iv).fill(&mut buf7);
        Zuc128::new(&key, &iv).fill(&mut buf8);
        // A 7-byte fill must equal the first 7 bytes of an 8-byte fill.
        assert_eq!(buf7[..], buf8[..7]);
    }

    #[test]
    fn fill_partial_word_ct() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut buf7 = [0u8; 7];
        let mut buf8 = [0u8; 8];
        Zuc128Ct::new(&key, &iv).fill(&mut buf7);
        Zuc128Ct::new(&key, &iv).fill(&mut buf8);
        assert_eq!(buf7[..], buf8[..7]);
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for x in 0u16..=255 {
            let b = x as u8;
            assert_eq!(sbox_eval(&S0_ANF, b), S0[x as usize], "S0 {x:02x}");
            assert_eq!(sbox_eval(&S1_ANF, b), S1[x as usize], "S1 {x:02x}");
        }
    }

    #[test]
    fn zuc128_and_ct_match() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let mut fast = Zuc128::new(&key, &iv);
        let mut slow = Zuc128Ct::new(&key, &iv);
        for _ in 0..4 {
            assert_eq!(fast.next_word(), slow.next_word());
        }
    }
}
