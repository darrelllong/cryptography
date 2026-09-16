//! ZUC-128 stream cipher, from ETSI/SAGE "Specification of the 3GPP Confidentiality
//! and Integrity Algorithms 128-EEA3 & 128-EIA3, Document 2: ZUC Specification",
//! version 1.6 (28 June 2011), normative sections 2–3 (the algorithm is also
//! GM/T 0001.1). Test vectors come from Document 3 of the same set,
//! "Implementor's Test Data", version 1.1 (4 January 2011), section 3.
//!
//! 128-bit key, 128-bit IV.  Outputs 32-bit keystream words.
//!
//! This module implements the ZUC keystream generator of Document 2 only. The
//! 3GPP LTE algorithms built on it, 128-EEA3 (confidentiality) and 128-EIA3
//! (integrity) of Document 1 of the same set, with their COUNT/BEARER/DIRECTION
//! IV construction and the EIA3 universal-hash MAC, are not implemented here.
//!
//! Architecture (spec §3):
//!   - LFSR (§3.2): 16 cells `s[0]..s[15]`, each a 31-bit integer in GF(2³¹−1).
//!   - Bit reorganization (BR, §3.3): extracts four 32-bit words X0..X3 from LFSR.
//!   - Nonlinear function F (§3.4): two 32-bit memory registers R1, R2; takes
//!     X0, X1, X2; produces output W.  Uses composite S-box S=(S0,S1,S0,S1)
//!     and linear transforms L1, L2.
//!   - Keystream word: Z = W ⊕ X3  (working phase only).
//!
//! `Zuc128` keeps the direct S-box table lookups. `Zuc128Ct` is separate and
//! evaluates the same two 8-bit S-boxes through packed ANF bitsets so the
//! nonlinear function avoids secret-indexed table reads.

// ── S-boxes (spec §3.4.1) ─────────────────────────────────────────────────
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

// ── LFSR initialization constants (spec §3.5) ──────────────────────────────
//
// d[i] are 15-bit constants packed into the middle of each 31-bit LFSR cell:
//   s[i] = key[i](8b) ‖ d[i](15b) ‖ iv[i](8b)

const D: [u16; 16] = [
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 0x4D78, 0x2F13, 0x6BC4, 0x1AF1,
    0x5E26, 0x3C4D, 0x789A, 0x47AC,
];

// ── LFSR feedback modulo M = 2^31 − 1 (spec §3.2) ──────────────────────────
//
// §3.2 step 1 is v = 2^15·s15 + 2^17·s13 + 2^21·s10 + 2^20·s4 + (1 + 2^8)·s0
// mod M; in initialisation mode step 2 adds u = W >> 1 modulo M as well.
//
// Headroom. Every cell is below 2^31 (§3.2 restricts cells to 1..=M) and so
// is u, so the plain integer sum of all the terms is below
//
//     2^46 + 2^48 + 2^52 + 2^51 + 2^39 + 2^31 + 2^31 < 2^53,
//
// which a u64 holds exactly. Nothing is reduced until the sum is complete.
//
// Reduction. 2^31 = M + 1 ≡ 1 (mod M), so a number with base-2^31 digits
// x = q·2^31 + r is congruent to q + r. For x < 2^53, q < 2^22, so one fold
// leaves y = q + r < 2^31 + 2^22. Folding y again: either y < 2^31 and the
// fold changes nothing, or y ≥ 2^31, its high digit is 1 and its low digit is
// below 2^22, so the result is below 2^22 + 1. Two folds therefore land in
// [0, M], congruent to the sum. 0 and M both stand for the residue 0, which
// §3.2 writes as M ("if s16 = 0, then set s16 = 2^31 − 1"); `lfsr_clock`
// applies that rule without branching.

/// M = 2^31 − 1, the modulus of the LFSR cells (spec §3.2).
const CELL_MODULUS: u64 = (1 << 31) - 1;

/// One base-2^31 digit fold: `q·2^31 + r ≡ q + r (mod M)`.
#[inline]
const fn fold_base_2_31(x: u64) -> u64 {
    let high_digit = x >> 31;
    let low_digit = x & CELL_MODULUS;
    high_digit + low_digit
}

/// The next LFSR cell before the zero rule, as a value in `[0, M]`.
///
/// Spec §3.2 `LFSRWithInitialisationMode(u)` steps 1–2 with `input = u`, or
/// `LFSRWithWorkMode()` step 1 with `input = 0`.
#[inline]
fn lfsr_next(s: &[u32; 16], input: u32) -> u32 {
    let cell = |i: usize| u64::from(s[i]);
    let sum = (cell(15) << 15)
        + (cell(13) << 17)
        + (cell(10) << 21)
        + (cell(4) << 20)
        + (cell(0) << 8)
        + cell(0)
        + u64::from(input);
    // At most M after two folds, so the narrowing keeps every bit.
    fold_base_2_31(fold_base_2_31(sum)) as u32
}

// ── Composite S-box and linear transforms ─────────────────────────────────

/// Composite 32-bit S-box S = (S0, S1, S0, S1), MSB first (spec §2.2.4).
#[inline]
fn sbox(x: u32) -> u32 {
    u32::from(S0[(x >> 24) as usize]) << 24
        | u32::from(S1[((x >> 16) & 0xFF) as usize]) << 16
        | u32::from(S0[((x >> 8) & 0xFF) as usize]) << 8
        | u32::from(S1[(x & 0xFF) as usize])
}

#[inline]
fn sbox_eval(coeffs: &[[u128; 2]; 8], input: u8) -> u8 {
    crate::ct::eval_byte_sbox(coeffs, input)
}

/// Constant-time composite 32-bit S-box using the packed ANF forms of S0/S1.
#[inline]
fn sbox_ct(x: u32) -> u32 {
    u32::from(sbox_eval(&S0_ANF, (x >> 24) as u8)) << 24
        | u32::from(sbox_eval(&S1_ANF, ((x >> 16) & 0xFF) as u8)) << 16
        | u32::from(sbox_eval(&S0_ANF, ((x >> 8) & 0xFF) as u8)) << 8
        | u32::from(sbox_eval(&S1_ANF, (x & 0xFF) as u8))
}

/// Linear transform L1 (spec §3.4.2).
#[inline]
fn l1(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

/// Linear transform L2 (spec §3.4.2).
#[inline]
fn l2(x: u32) -> u32 {
    x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
}

// ── ZUC-128 ───────────────────────────────────────────────────────────────

struct ZucCore {
    /// Keystream bytes of a partially consumed word, right-aligned:
    /// `ks[4 - ks_len..]` are still unused.
    ks: [u8; 4],
    ks_len: u8,
    s: [u32; 16],
    r1: u32,
    r2: u32,
}

impl ZucCore {
    /// Forget the unused bytes of a partially consumed word. Unused keystream
    /// is as secret as the state that made it, so it is wiped, not just
    /// forgotten.
    fn discard_pending(&mut self) {
        crate::ct::zeroize_slice(self.ks.as_mut_slice());
        self.ks_len = 0;
    }
}

/// Extract four 32-bit words X0..X3 from the 31-bit LFSR cells (spec §3.3).
///
/// Each LFSR cell s[i] is a 31-bit value held in bits [30:0] of a u32.
/// The spec defines two 16-bit halves per cell, which overlap in bit 15
/// (§3.3, note: "siH means bits 30...15 and not 31...16 of si"):
///   s[i]^H = bits [30:15]
///   s[i]^L = bits [15:0]
///
/// The four reorganized words are (§3.3 `Bitreorganization()`):
///   X0 = s[15]^H ‖ s[14]^L
///   X1 = s[11]^L ‖ s[ 9]^H
///   X2 = s[ 7]^L ‖ s[ 5]^H
///   X3 = s[ 2]^L ‖ s[ 0]^H   ← feeds the keystream word, not F
///
/// Bit manipulation:
///   s[i]^H as the high half: s[15] << 1 moves bits [30:15] to [31:16];
///     the mask 0xFFFF_0000 drops bits [14:0].
///   s[i]^L as the high half: s[k] << 16 moves bits [15:0] to [31:16].
///   s[i]^L as the low half:  s[14] & 0xFFFF keeps bits [15:0] in place.
///   s[i]^H as the low half:  s[k] >> 15 moves bits [30:15] to [15:0].
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
    // Keep the CT choice as a const-folded branch so monomorphization leaves
    // direct calls in the hot loop instead of an indirect fn-pointer dispatch.
    if CT {
        core.r1 = sbox_ct(l1((w1 << 16) | (w2 >> 16)));
        core.r2 = sbox_ct(l2((w2 << 16) | (w1 >> 16)));
    } else {
        core.r1 = sbox(l1((w1 << 16) | (w2 >> 16)));
        core.r2 = sbox(l2((w2 << 16) | (w1 >> 16)));
    }
    w
}

#[inline]
fn lfsr_clock(s: &mut [u32; 16], new_val: u32) {
    s.copy_within(1..16, 0);
    // 0 and 2^31-1 are congruent mod 2^31-1, so map a zero feedback word to
    // 0x7FFF_FFFF without branching on the secret `new_val`. `is_zero` is
    // all-ones iff `new_val == 0`: for any non-zero u32, `x | -x` has its top
    // bit set, so `>> 31` gives 1 and `- 1` gives 0; for zero it gives all-ones.
    let is_zero = ((new_val | new_val.wrapping_neg()) >> 31).wrapping_sub(1);
    s[15] = new_val | (is_zero & 0x7FFF_FFFF);
}

/// Key loading (spec §3.5): `s[i] = k[i] ‖ d[i] ‖ iv[i]`, with R1 = R2 = 0.
fn load_key_iv(key: &[u8; 16], iv: &[u8; 16]) -> ZucCore {
    let mut s = [0u32; 16];
    for (((cell, &k), &d), &v) in s.iter_mut().zip(key).zip(&D).zip(iv) {
        *cell = (u32::from(k) << 23) | (u32::from(d) << 8) | u32::from(v);
    }
    ZucCore {
        ks: [0; 4],
        ks_len: 0,
        s,
        r1: 0,
        r2: 0,
    }
}

/// Spec §3.6.1 initialisation stage: 32 clocks with `W >> 1` fed back into
/// the LFSR, then the first working-stage clock whose output is discarded
/// (§3.6.2), so that the next `next_word_core` returns `Z[1]`.
fn init_core<const CT: bool>(key: &[u8; 16], iv: &[u8; 16]) -> ZucCore {
    let mut core = load_key_iv(key, iv);

    for _ in 0..32 {
        let (x0, x1, x2, _) = bit_reorganization(&core.s);
        let w = nonlinear_f::<CT>(&mut core, x0, x1, x2);
        let s16 = lfsr_next(&core.s, w >> 1);
        lfsr_clock(&mut core.s, s16);
    }

    let (x0, x1, x2, _) = bit_reorganization(&core.s);
    nonlinear_f::<CT>(&mut core, x0, x1, x2);
    let s16 = lfsr_next(&core.s, 0);
    lfsr_clock(&mut core.s, s16);

    core
}

#[inline]
fn next_word_core<const CT: bool>(core: &mut ZucCore) -> u32 {
    let (x0, x1, x2, x3) = bit_reorganization(&core.s);
    let w = nonlinear_f::<CT>(core, x0, x1, x2);
    let s16 = lfsr_next(&core.s, 0);
    lfsr_clock(&mut core.s, s16);
    w ^ x3
}

fn fill_core<const CT: bool>(core: &mut ZucCore, mut buf: &mut [u8]) {
    // Drain the unused bytes of the last partial word first, so a sequence
    // of `fill` calls sees one continuous keystream regardless of how the
    // caller chunks its buffers.
    let pending = usize::from(core.ks_len);
    if pending > 0 {
        let take = pending.min(buf.len());
        let start = 4 - pending;
        for (b, k) in buf[..take].iter_mut().zip(&core.ks[start..start + take]) {
            *b ^= k;
        }
        core.ks_len = u8::try_from(pending - take).expect("at most 3");
        buf = &mut buf[take..];
    }
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
        core.ks = ks;
        core.ks_len = u8::try_from(4 - rem.len()).expect("at most 3");
    }
}

/// ZUC-128 stream cipher (ETSI/SAGE ZUC Specification v1.6; GM/T 0001.1).
///
/// Generates 32-bit keystream words via [`next_word`]; byte-oriented output
/// via [`fill`].  Each instance is single-use: reconstruct with a fresh IV
/// to re-key.
///
/// **Not constant-time.** The nonlinear function F (§3.4) reads the S0 and S1
/// tables at four indices per clock, and those indices are bytes of the
/// secret registers R1, R2 mixed with LFSR cells; the memory access pattern
/// therefore depends on the key. Where an attacker may observe timing or
/// cache behaviour, use [`Zuc128Ct`], which computes the same keystream
/// without secret-indexed reads.
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
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            core: init_core::<false>(key, iv),
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
    ///
    /// Starts a fresh word: any bytes left over from a partial-word `fill` are
    /// discarded (and wiped).
    pub fn next_word(&mut self) -> u32 {
        self.core.discard_pending();
        next_word_core::<false>(&mut self.core)
    }

    /// XOR `buf` with keystream bytes (32-bit words in big-endian byte order).
    ///
    /// Successive calls continue the same keystream byte for byte: a partially
    /// consumed word is carried over, so chunked and one-shot encryption of the
    /// same data agree.
    ///
    /// Calling `fill` twice with the same key/IV and an identical buffer
    /// recovers the original contents (stream-cipher encrypt/decrypt).
    pub fn fill(&mut self, buf: &mut [u8]) {
        fill_core::<false>(&mut self.core, buf);
    }
}

impl Zuc128Ct {
    /// Construct and initialize ZUC-128Ct from a 128-bit key and 128-bit IV.
    #[must_use]
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
    ///
    /// Starts a fresh word: any bytes left over from a partial-word `fill` are
    /// discarded (and wiped).
    pub fn next_word(&mut self) -> u32 {
        self.core.discard_pending();
        next_word_core::<true>(&mut self.core)
    }

    /// XOR `buf` with keystream bytes (32-bit words in big-endian byte order).
    ///
    /// Successive calls continue the same keystream byte for byte: a partially
    /// consumed word is carried over, so chunked and one-shot encryption of the
    /// same data agree.
    pub fn fill(&mut self, buf: &mut [u8]) {
        fill_core::<true>(&mut self.core, buf);
    }
}

impl Drop for Zuc128 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.s.as_mut_slice());
        crate::ct::zeroize_slice(self.core.ks.as_mut_slice());
        self.core.ks_len = 0;
        self.core.r1 = 0;
        self.core.r2 = 0;
    }
}

impl Drop for Zuc128Ct {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.s.as_mut_slice());
        crate::ct::zeroize_slice(self.core.ks.as_mut_slice());
        self.core.ks_len = 0;
        self.core.r1 = 0;
        self.core.r2 = 0;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn fill_bytes(state: &mut u64, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = xorshift64(state).to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    // ── Test vectors ─────────────────────────────────────────────────────────
    //
    // All from ETSI/SAGE "Specification of the 3GPP Confidentiality and
    // Integrity Algorithms 128-EEA3 & 128-EIA3, Document 3: Implementor's Test
    // Data", version 1.1 (4 January 2011), section 3 "ZUC".

    // Document 3 §3.3, Test Set 1: key = 0x00*16, iv = 0x00*16.
    #[test]
    fn keystream_zeros() {
        let mut z = Zuc128::new(&[0u8; 16], &[0u8; 16]);
        assert_eq!(z.next_word(), 0x27be_de74, "Z[0]");
        assert_eq!(z.next_word(), 0x0180_82da, "Z[1]");
    }

    // Document 3 §3.4, Test Set 2: key = 0xFF*16, iv = 0xFF*16.
    #[test]
    fn keystream_ones() {
        let mut z = Zuc128::new(&[0xFFu8; 16], &[0xFFu8; 16]);
        assert_eq!(z.next_word(), 0x0657_cfa0, "Z[0]");
        assert_eq!(z.next_word(), 0x7096_398b, "Z[1]");
    }

    // Document 3 §3.5, Test Set 3.
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
        assert_eq!(z.next_word(), 0x14f1_c272, "Z[0]");
        assert_eq!(z.next_word(), 0x3279_c419, "Z[1]");
    }

    // Document 3 §3.3, Test Set 1, through the constant-time path.
    #[test]
    fn keystream_zeros_ct() {
        let mut z = Zuc128Ct::new(&[0u8; 16], &[0u8; 16]);
        assert_eq!(z.next_word(), 0x27be_de74, "Z[0]");
        assert_eq!(z.next_word(), 0x0180_82da, "Z[1]");
    }

    // Document 3 §3.4, Test Set 2, through the constant-time path.
    #[test]
    fn keystream_ones_ct() {
        let mut z = Zuc128Ct::new(&[0xFFu8; 16], &[0xFFu8; 16]);
        assert_eq!(z.next_word(), 0x0657_cfa0, "Z[0]");
        assert_eq!(z.next_word(), 0x7096_398b, "Z[1]");
    }

    // Document 3 §3.5, Test Set 3, through the constant-time path.
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
        assert_eq!(z.next_word(), 0x14f1_c272, "Z[0]");
        assert_eq!(z.next_word(), 0x3279_c419, "Z[1]");
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

    /// The keystream is one continuous byte stream: chunked fills must agree
    /// with a single fill regardless of where the chunk boundaries fall
    /// relative to the 32-bit word boundaries.
    #[test]
    fn chunked_fill_matches_one_shot() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut one_shot = [0u8; 29];
        let mut chunked = [0u8; 29];
        Zuc128::new(&key, &iv).fill(&mut one_shot);
        let mut z = Zuc128::new(&key, &iv);
        let mut off = 0;
        for len in [1usize, 3, 7, 4, 9, 5] {
            z.fill(&mut chunked[off..off + len]);
            off += len;
        }
        assert_eq!(chunked, one_shot);

        let mut one_shot_ct = [0u8; 29];
        let mut chunked_ct = [0u8; 29];
        Zuc128Ct::new(&key, &iv).fill(&mut one_shot_ct);
        let mut z = Zuc128Ct::new(&key, &iv);
        let mut off = 0;
        for len in [1usize, 3, 7, 4, 9, 5] {
            z.fill(&mut chunked_ct[off..off + len]);
            off += len;
        }
        assert_eq!(chunked_ct, one_shot_ct);
        assert_eq!(one_shot_ct, one_shot);
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

    /// Fills shorter than the pending remainder of a word: one word is
    /// consumed a byte (or three, then one) at a time, so a partial word is
    /// carried across several calls and drained from successive offsets.
    #[test]
    fn sub_word_fills_drain_one_pending_word_across_calls() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut one_shot = [0u8; 12];
        Zuc128::new(&key, &iv).fill(&mut one_shot);
        let mut one_shot_ct = [0u8; 12];
        Zuc128Ct::new(&key, &iv).fill(&mut one_shot_ct);
        assert_eq!(one_shot_ct, one_shot);

        for lens in [
            [1usize; 12].as_slice(),
            &[3, 1, 1, 1, 2, 1, 1, 2],
            &[2, 1, 1, 3, 3, 2],
        ] {
            let mut chunked = [0u8; 12];
            let mut z = Zuc128::new(&key, &iv);
            let mut off = 0;
            for &len in lens {
                z.fill(&mut chunked[off..off + len]);
                off += len;
            }
            assert_eq!(off, 12);
            assert_eq!(chunked, one_shot, "chunking {lens:?}");

            let mut chunked_ct = [0u8; 12];
            let mut z = Zuc128Ct::new(&key, &iv);
            let mut off = 0;
            for &len in lens {
                z.fill(&mut chunked_ct[off..off + len]);
                off += len;
            }
            assert_eq!(chunked_ct, one_shot, "chunking {lens:?} (ct)");
        }
    }

    /// `next_word` after a partial-word `fill` starts a fresh word and leaves
    /// no pending keystream bytes behind.
    #[test]
    fn next_word_discards_and_wipes_pending_bytes() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut reference = Zuc128::new(&key, &iv);
        let _ = reference.next_word();
        let second = reference.next_word();

        let mut z = Zuc128::new(&key, &iv);
        z.fill(&mut [0u8; 1]);
        assert_eq!(z.core.ks_len, 3);
        assert_eq!(z.next_word(), second);
        assert_eq!(z.core.ks_len, 0);
        assert_eq!(z.core.ks, [0u8; 4]);

        let mut z = Zuc128Ct::new(&key, &iv);
        z.fill(&mut [0u8; 1]);
        assert_eq!(z.next_word(), second);
        assert_eq!(z.core.ks_len, 0);
        assert_eq!(z.core.ks, [0u8; 4]);
    }

    /// `new_wiping` zeroes the caller's key and IV and yields the same stream
    /// as `new`, on both paths.
    #[test]
    fn new_wiping_zeroes_inputs_and_matches_new() {
        let key: [u8; 16] = core::array::from_fn(|i| u8::try_from(i * 9).expect("< 144"));
        let iv: [u8; 16] = core::array::from_fn(|i| u8::try_from(i * 13).expect("< 208"));

        let mut expected = [0u8; 40];
        Zuc128::new(&key, &iv).fill(&mut expected);
        let mut key_buf = key;
        let mut iv_buf = iv;
        let mut z = Zuc128::new_wiping(&mut key_buf, &mut iv_buf);
        assert_eq!(key_buf, [0u8; 16]);
        assert_eq!(iv_buf, [0u8; 16]);
        let mut out = [0u8; 40];
        z.fill(&mut out);
        assert_eq!(out, expected);

        let mut expected_ct = [0u8; 40];
        Zuc128Ct::new(&key, &iv).fill(&mut expected_ct);
        assert_eq!(expected_ct, expected);
        let mut key_buf = key;
        let mut iv_buf = iv;
        let mut z = Zuc128Ct::new_wiping(&mut key_buf, &mut iv_buf);
        assert_eq!(key_buf, [0u8; 16]);
        assert_eq!(iv_buf, [0u8; 16]);
        let mut out = [0u8; 40];
        z.fill(&mut out);
        assert_eq!(out, expected_ct);
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for x in 0u16..=255 {
            let b = u8::try_from(x).expect("table index fits in u8");
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

    #[test]
    fn zuc128_and_ct_match_random_streams() {
        let mut seed = 0x1234_5678_dead_beefu64;
        for _ in 0..128 {
            let mut key = [0u8; 16];
            let mut iv = [0u8; 16];
            fill_bytes(&mut seed, &mut key);
            fill_bytes(&mut seed, &mut iv);
            let len = (xorshift64(&mut seed) as usize % 2048) + 1;

            let mut fast_buf = vec![0u8; len];
            let mut ct_buf = vec![0u8; len];
            fill_bytes(&mut seed, &mut fast_buf);
            ct_buf.copy_from_slice(&fast_buf);

            Zuc128::new(&key, &iv).fill(&mut fast_buf);
            Zuc128Ct::new(&key, &iv).fill(&mut ct_buf);
            assert_eq!(fast_buf, ct_buf);
        }
    }

    /// Document 3 §3.6, Test Set 4: z1, z2, and z2000 (every word in between
    /// is generated), through both paths.
    #[test]
    fn keystream_test_set_4_z2000() {
        let key = [
            0x4d, 0x32, 0x0b, 0xfa, 0xd4, 0xc2, 0x85, 0xbf, 0xd6, 0xb8, 0xbd, 0x00, 0xf3, 0x9d,
            0x8b, 0x41,
        ];
        let iv = [
            0x52, 0x95, 0x9d, 0xab, 0xa0, 0xbf, 0x17, 0x6e, 0xce, 0x2d, 0xc3, 0x15, 0x04, 0x9e,
            0xb5, 0x74,
        ];
        let mut fast = Zuc128::new(&key, &iv);
        let mut ct = Zuc128Ct::new(&key, &iv);
        for (i, expected) in [(1, 0xed44_00e7), (2, 0x0633_e5c5)] {
            assert_eq!(fast.next_word(), expected, "z{i}");
            assert_eq!(ct.next_word(), expected, "z{i} ct");
        }
        for _ in 3..2000 {
            assert_eq!(fast.next_word(), ct.next_word());
        }
        assert_eq!(fast.next_word(), 0x7a57_4cdb, "z2000");
        assert_eq!(ct.next_word(), 0x7a57_4cdb, "z2000 ct");
    }

    struct InitialisedState {
        key: [u8; 16],
        iv: [u8; 16],
        lfsr: [u32; 16],
        r1: u32,
        r2: u32,
    }

    /// Key loading (§3.5) and the 32 initialisation rounds (§3.6.1), stopping
    /// where Document 3 prints "LFSR-state after completion of the
    /// initialisation mode", before the working stage's discarded round.
    fn run_initialisation_rounds<const CT: bool>(key: &[u8; 16], iv: &[u8; 16]) -> ZucCore {
        let mut core = load_key_iv(key, iv);
        for _ in 0..32 {
            let (x0, x1, x2, _) = bit_reorganization(&core.s);
            let w = nonlinear_f::<CT>(&mut core, x0, x1, x2);
            let s16 = lfsr_next(&core.s, w >> 1);
            lfsr_clock(&mut core.s, s16);
        }
        core
    }

    /// Document 3 §3.3–§3.6: the LFSR cells and R1, R2 after initialisation,
    /// for all four test sets, through both paths.
    #[test]
    fn state_after_initialisation_test_sets_1_to_4() {
        let cases = [
            // Document 3 §3.3, Test Set 1.
            InitialisedState {
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                iv: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                lfsr: [
                    0x7ce1_5b8b,
                    0x747c_a0c4,
                    0x6259_dd0b,
                    0x47a9_4c2b,
                    0x3a89_c82e,
                    0x32b4_33fc,
                    0x231e_a13f,
                    0x3171_1e42,
                    0x4ccc_e955,
                    0x3fb6_071e,
                    0x161d_3512,
                    0x7114_b136,
                    0x5154_d452,
                    0x78c6_9a74,
                    0x4f26_ba6b,
                    0x3e1b_8d6a,
                ],
                r1: 0x14cf_d44c,
                r2: 0x8c6d_e800,
            },
            // Document 3 §3.4, Test Set 2.
            InitialisedState {
                key: [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                iv: [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                lfsr: [
                    0x09a3_39ad,
                    0x1291_d190,
                    0x2555_4227,
                    0x36c0_9187,
                    0x0697_773b,
                    0x443c_f9cd,
                    0x6a4c_d899,
                    0x49e3_4bd0,
                    0x5613_0b14,
                    0x20e8_f24c,
                    0x7a5b_1dcc,
                    0x0c3c_c2d1,
                    0x1cc0_82c8,
                    0x7f59_04a2,
                    0x55b6_1ce8,
                    0x1fe4_6106,
                ],
                r1: 0xb801_7bd5,
                r2: 0x9ce2_de5c,
            },
            // Document 3 §3.5, Test Set 3.
            InitialisedState {
                key: [
                    0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1,
                    0x7b, 0x45, 0x5b,
                ],
                iv: [
                    0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb,
                    0xd8, 0xc7, 0x66,
                ],
                lfsr: [
                    0x10da_5941,
                    0x5b6a_cbf6,
                    0x1706_0ce1,
                    0x3536_8174,
                    0x5cf4_385a,
                    0x4799_43df,
                    0x2753_bab2,
                    0x7377_5d6a,
                    0x4393_0a37,
                    0x77b4_af31,
                    0x15b2_e89f,
                    0x24ff_6e20,
                    0x740c_40b9,
                    0x026a_5503,
                    0x194b_2a57,
                    0x7a9a_1cff,
                ],
                r1: 0x860a_7dfa,
                r2: 0xbf0e_0ffc,
            },
            // Document 3 §3.6, Test Set 4.
            InitialisedState {
                key: [
                    0x4d, 0x32, 0x0b, 0xfa, 0xd4, 0xc2, 0x85, 0xbf, 0xd6, 0xb8, 0xbd, 0x00, 0xf3,
                    0x9d, 0x8b, 0x41,
                ],
                iv: [
                    0x52, 0x95, 0x9d, 0xab, 0xa0, 0xbf, 0x17, 0x6e, 0xce, 0x2d, 0xc3, 0x15, 0x04,
                    0x9e, 0xb5, 0x74,
                ],
                lfsr: [
                    0x1f80_8882,
                    0x4fc0_8639,
                    0x246a_9891,
                    0x1f77_c16f,
                    0x50f0_e1c9,
                    0x723e_8fac,
                    0x2433_4616,
                    0x4471_b734,
                    0x7dba_1992,
                    0x2518_0096,
                    0x4637_117c,
                    0x2a92_aac8,
                    0x7da8_d7b5,
                    0x58f4_5afe,
                    0x4281_4800,
                    0x56d7_e7d8,
                ],
                r1: 0x5276_1a25,
                r2: 0x38f7_12e1,
            },
        ];
        for (n, case) in cases.iter().enumerate() {
            for core in [
                run_initialisation_rounds::<false>(&case.key, &case.iv),
                run_initialisation_rounds::<true>(&case.key, &case.iv),
            ] {
                assert_eq!(core.s, case.lfsr, "test set {} LFSR", n + 1);
                assert_eq!(
                    [core.r1, core.r2],
                    [case.r1, case.r2],
                    "test set {} R1, R2",
                    n + 1
                );
            }
        }
    }
}
