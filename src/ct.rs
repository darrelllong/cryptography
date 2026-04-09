//! Constant-time building blocks and secret-handling utilities.
//!
//! Everything in this module is written to avoid secret-dependent branching or
//! memory-access patterns that could leak information through timing or cache
//! side-channels.  The key primitives are:
//!
//! - **Equality masks** (`eq_mask_u8`, `eq_mask_u32`) — branch-free equality
//!   test that returns an all-ones word on match, all-zeros otherwise.
//! - **Full-table scans** (`ct_lookup_u32`, `ct_lookup_u8_16`) — index into a
//!   table by scanning every entry and masking, so the memory-access pattern
//!   never reveals the index.
//! - **Slice comparison** (`constant_time_eq_mask`) — accumulate differences
//!   without short-circuiting, guarded with `black_box` and a compiler fence.
//! - **Zeroization** (`zeroize_slice`) — volatile writes that the compiler
//!   cannot elide, used to wipe key material from memory.
//! - **ANF S-box evaluation** — converts an S-box to Algebraic Normal Form at
//!   compile time, then evaluates it via subset-sum inner products so that every
//!   input produces exactly the same sequence of operations (no branches, no
//!   secret-dependent loads).

use core::hint::black_box;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(feature = "ct_profile")]
use std::time::Instant;

#[cfg(feature = "ct_profile")]
mod profile {
    use core::sync::atomic::{AtomicU64, Ordering};

    static SUBSET_MASK8_CALLS: AtomicU64 = AtomicU64::new(0);
    static PARITY128_CALLS: AtomicU64 = AtomicU64::new(0);
    static EVAL_BYTE_SBOX_CALLS: AtomicU64 = AtomicU64::new(0);

    #[inline(always)]
    pub(super) fn bump_subset_mask8() {
        SUBSET_MASK8_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub(super) fn bump_parity128() {
        PARITY128_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub(super) fn bump_eval_byte_sbox() {
        EVAL_BYTE_SBOX_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn reset() {
        SUBSET_MASK8_CALLS.store(0, Ordering::Relaxed);
        PARITY128_CALLS.store(0, Ordering::Relaxed);
        EVAL_BYTE_SBOX_CALLS.store(0, Ordering::Relaxed);
    }

    pub(super) fn snapshot() -> super::CtAnfProfile {
        super::CtAnfProfile {
            subset_mask8_calls: SUBSET_MASK8_CALLS.load(Ordering::Relaxed),
            parity128_calls: PARITY128_CALLS.load(Ordering::Relaxed),
            eval_byte_sbox_calls: EVAL_BYTE_SBOX_CALLS.load(Ordering::Relaxed),
        }
    }
}

#[cfg(not(feature = "ct_profile"))]
mod profile {
    #[inline(always)]
    pub(super) fn bump_subset_mask8() {}

    #[inline(always)]
    pub(super) fn bump_parity128() {}

    #[inline(always)]
    pub(super) fn bump_eval_byte_sbox() {}
}

#[cfg(feature = "ct_profile")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CtAnfProfile {
    pub subset_mask8_calls: u64,
    pub parity128_calls: u64,
    pub eval_byte_sbox_calls: u64,
}

#[cfg(feature = "ct_profile")]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CtAnfHelperCostsNs {
    pub subset_mask8_ns: f64,
    pub parity128_ns: f64,
    pub eval_byte_sbox_ns: f64,
}

#[cfg(feature = "ct_profile")]
pub fn ct_profile_reset() {
    profile::reset();
}

#[cfg(feature = "ct_profile")]
#[must_use]
pub fn ct_profile_snapshot() -> CtAnfProfile {
    profile::snapshot()
}

#[cfg(feature = "ct_profile")]
#[must_use]
pub fn ct_profile_measure_helper_costs(iterations: u64) -> CtAnfHelperCostsNs {
    let mut input = 0u8;
    let mut acc = 0u64;

    let t_subset = Instant::now();
    for _ in 0..iterations {
        let (lo, hi) = subset_mask8(input);
        acc ^= (lo as u64) ^ ((hi >> 64) as u64);
        input = input.wrapping_add(1);
    }
    let subset_ns = t_subset.elapsed().as_secs_f64() * 1e9 / iterations as f64;

    let t_parity = Instant::now();
    let mut x = 0x0123_4567_89ab_cdef_0011_2233_4455_6677u128;
    for _ in 0..iterations {
        acc ^= u64::from(parity128(x));
        x = x.rotate_left(13) ^ 0x9e37_79b9_7f4a_7c15_6a09_e667_f3bc_c909u128;
    }
    let parity_ns = t_parity.elapsed().as_secs_f64() * 1e9 / iterations as f64;

    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = i as u8;
        i += 1;
    }
    let coeffs = build_byte_sbox_anf(&table);
    let t_eval = Instant::now();
    let mut y = 0u8;
    for _ in 0..iterations {
        y = y.wrapping_add(17);
        acc ^= u64::from(eval_byte_sbox(&coeffs, y));
    }
    let eval_ns = t_eval.elapsed().as_secs_f64() * 1e9 / iterations as f64;

    black_box(acc);
    CtAnfHelperCostsNs {
        subset_mask8_ns: subset_ns,
        parity128_ns: parity_ns,
        eval_byte_sbox_ns: eval_ns,
    }
}

// ---------------------------------------------------------------------------
// Equality masks
// ---------------------------------------------------------------------------

/// Returns `0xFFFF_FFFF` if `a == b`, `0x0000_0000` otherwise — no branches.
///
/// Widening to `u16` before subtracting 1 lets the borrow propagate into
/// bit 8, which would be masked away in an 8-bit subtraction.  Result: bit 8
/// of `(x-1)` is 1 iff `x == 0`.  `wrapping_sub` then splatting that bit
/// to all 32 positions gives the mask.
#[inline]
fn eq_mask_u32(a: u8, b: u8) -> u32 {
    // Branch-free equality mask:
    // - x == 0  => (x - 1) has top byte 0xff, so ((x - 1) >> 8) & 1 == 1
    // - x != 0  => top byte is 0x00, so the bit is 0
    // Then expand 0/1 to 0x0000_0000/0xffff_ffff with two's-complement wrap.
    let x = u16::from(a ^ b);
    let is_zero = u32::from((x.wrapping_sub(1) >> 8) & 1);
    0u32.wrapping_sub(is_zero)
}

/// Returns `0xFF` if `a == b`, `0x00` otherwise — no branches.
///
/// Same trick as [`eq_mask_u32`] but produces an 8-bit mask.
#[inline]
fn eq_mask_u8(a: u8, b: u8) -> u8 {
    // Same arithmetic trick as `eq_mask_u32`, reduced to an 8-bit all-ones/all-zero mask.
    let x = u16::from(a ^ b);
    let is_zero = ((x.wrapping_sub(1) >> 8) & 1) as u8;
    0u8.wrapping_sub(is_zero)
}

// ---------------------------------------------------------------------------
// Zeroization
// ---------------------------------------------------------------------------

/// Overwrites every element of `slice` with its `Default` value.
///
/// Uses `ptr::write_volatile` so the compiler cannot prove the writes are dead
/// and elide them (which it would be allowed to do for ordinary assignments to
/// memory that is about to go out of scope).  The `compiler_fence` prevents
/// reordering the volatile stores with subsequent deallocation or reuse of the
/// backing memory.
///
/// Called by `Drop` implementations and `new_wiping` constructors to ensure
/// expanded round keys do not linger in memory.
pub fn zeroize_slice<T: Copy + Default>(slice: &mut [T]) {
    for item in slice.iter_mut() {
        unsafe { ptr::write_volatile(std::ptr::from_mut::<T>(item), T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Full-table-scan lookups (cache-timing safe)
// ---------------------------------------------------------------------------

/// Reads `table[idx]` by scanning every entry — constant-time for 256-entry tables.
///
/// A direct index leaks `idx` through the data cache: the cache-line touched
/// is determined by `idx`, and timing reveals it.  Scanning all 256 entries
/// unconditionally and masking keeps the access pattern independent of `idx`.
pub(crate) fn ct_lookup_u32(table: &[u32; 256], idx: u8) -> u32 {
    let mut out = 0u32;
    let mut i = 0usize;
    while i < 256 {
        let table_index = i as u8;
        out |= table[i] & eq_mask_u32(table_index, idx);
        i += 1;
    }
    out
}

/// Reads `table[idx]` by scanning all 16 entries — constant-time for nibble tables.
///
/// Same principle as [`ct_lookup_u32`] but for the 16-entry S-boxes used by
/// ciphers such as Magma, Simon, and Speck.  `idx` must be in `0..16`.
pub(crate) fn ct_lookup_u8_16(table: &[u8; 16], idx: u8) -> u8 {
    let mut out = 0u8;
    let mut i = 0usize;
    while i < 16 {
        let table_index = i as u8;
        out |= table[i] & eq_mask_u8(table_index, idx);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Slice equality
// ---------------------------------------------------------------------------

/// Returns `0xFF` if `a == b` (byte-by-byte), `0x00` otherwise.
///
/// Standard `==` can short-circuit on the first differing byte, leaking the
/// mismatch position through timing — critical in MAC verification.
/// `black_box` stops the compiler replacing the XOR-accumulate with an early
/// exit (permitted under as-if); `compiler_fence` prevents reordering the
/// reads past the reduction.
#[inline]
pub(crate) fn constant_time_eq_mask(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= *x ^ *y;
    }
    // Keep `diff` live until the end of the loop body and prevent late-stage
    // cleverness from reintroducing control-flow shortcuts.
    let diff = black_box(diff);
    compiler_fence(Ordering::SeqCst);
    // eq_mask_u8(diff, 0): 0xFF if no byte differed, 0x00 otherwise.
    eq_mask_u8(diff, 0)
}

// ---------------------------------------------------------------------------
// ANF S-box construction (compile-time)
// ---------------------------------------------------------------------------
//
// ANF (Algebraic Normal Form): every Boolean function has a unique
// representation as a multilinear polynomial over GF(2).  Evaluating it
// requires only AND and XOR over fixed coefficients — no table lookup, no
// secret-dependent memory access.  Coefficients are computed from the truth
// table via the Möbius transform.

/// Compute packed ANF coefficients for an 8-bit → 8-bit S-box at compile time.
///
/// Returns `[[u128; 2]; 8]`: one pair of 128-bit words per output bit, with
/// the 256 GF(2) coefficients packed LSB-first into `(lo, hi)`.
/// Applies the Möbius transform in-place: for each variable, XOR entries
/// whose index has that variable's bit set with the entry that has it clear.
pub(crate) const fn build_byte_sbox_anf(table: &[u8; 256]) -> [[u128; 2]; 8] {
    let mut out = [[0u128; 2]; 8];
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let mut coeffs = [0u8; 256];
        let mut x = 0usize;
        while x < 256 {
            coeffs[x] = (table[x] >> bit_idx) & 1;
            x += 1;
        }

        // In-place Möbius transform over F2: convert truth table values into
        // ANF coefficients indexed by monomial bitmasks.
        let mut var = 0usize;
        while var < 8 {
            let stride = 1usize << var;
            let mut mask = 0usize;
            while mask < 256 {
                if mask & stride != 0 {
                    coeffs[mask] ^= coeffs[mask ^ stride];
                }
                mask += 1;
            }
            var += 1;
        }

        // Pack coefficients into (lo, hi): coefficient for monomial i → bit i.
        let mut lo = 0u128;
        let mut hi = 0u128;
        let mut monomial = 0usize;
        while monomial < 128 {
            lo |= (coeffs[monomial] as u128) << monomial;
            monomial += 1;
        }
        while monomial < 256 {
            hi |= (coeffs[monomial] as u128) << (monomial - 128);
            monomial += 1;
        }

        out[bit_idx][0] = lo;
        out[bit_idx][1] = hi;
        bit_idx += 1;
    }
    out
}

/// Compute packed ANF coefficients for a 4-bit → 4-bit S-box at compile time.
///
/// Returns `[u16; 4]`: one 16-bit word per output bit, with coefficient for
/// monomial `i` packed into bit `i`.  Same Möbius transform as
/// [`build_byte_sbox_anf`] but over a 16-entry domain.
pub(crate) const fn build_nibble_sbox_anf(table: &[u8; 16]) -> [u16; 4] {
    let mut out = [0u16; 4];
    let mut bit_idx = 0usize;
    while bit_idx < 4 {
        let mut coeffs = [0u8; 16];
        let mut x = 0usize;
        while x < 16 {
            coeffs[x] = (table[x] >> bit_idx) & 1;
            x += 1;
        }

        // Möbius transform over GF(2)^4.
        let mut var = 0usize;
        while var < 4 {
            let stride = 1usize << var;
            let mut mask = 0usize;
            while mask < 16 {
                if mask & stride != 0 {
                    coeffs[mask] ^= coeffs[mask ^ stride];
                }
                mask += 1;
            }
            var += 1;
        }

        let mut packed = 0u16;
        let mut monomial = 0usize;
        while monomial < 16 {
            packed |= (coeffs[monomial] as u16) << monomial;
            monomial += 1;
        }
        out[bit_idx] = packed;
        bit_idx += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// ANF S-box evaluation (runtime)
// ---------------------------------------------------------------------------

/// Build the 256-bit subset-indicator mask for an 8-bit input `x`.
///
/// Bit `i` of the result is `1` iff `(i & x) == i` — i.e., `i` is a subset
/// of `x`'s bits.  ANF evaluation sums coefficients over exactly those indices,
/// so `parity(mask & coefficients)` gives each output bit.
///
/// Built by iterative doubling without branches: start with bit 0 set (empty
/// subset).  For each bit `k` of `x`, OR the mask with itself shifted by `2^k`,
/// gated by an arithmetic all-ones/all-zeros mask derived from bit `k`.
/// Same sequence of operations for every input — no secret-dependent branches.
#[inline]
pub(crate) fn subset_mask8(x: u8) -> (u128, u128) {
    profile::bump_subset_mask8();
    // Build the "active monomial" mask for ANF evaluation.
    //
    // Index i (0..255) represents monomial `prod_j x_j^{i_j}` where i_j is bit j
    // of i. The monomial is active iff every selected variable bit in i is 1 in
    // the input x, i.e., iff (i & x) == i.
    //
    // We start from monomial 1 (index 0) and conditionally OR shifted copies for
    // each input bit using all-ones/all-zero masks instead of branches.
    let mut lo = 1u128;
    let mut hi = 0u128;

    // Bit 0 of x: subsets gain the {0} element → shift by 2^0 = 1.
    let mask0 = 0u128.wrapping_sub(u128::from(x & 1));
    let add_lo = lo << 1;
    let add_hi = (hi << 1) | (lo >> 127);
    lo |= add_lo & mask0;
    hi |= add_hi & mask0;

    // Bit 1 of x: shift by 2^1 = 2.
    let mask1 = 0u128.wrapping_sub(u128::from((x >> 1) & 1));
    let add_lo = lo << 2;
    let add_hi = (hi << 2) | (lo >> 126);
    lo |= add_lo & mask1;
    hi |= add_hi & mask1;

    // Bit 2 of x: shift by 2^2 = 4.
    let mask2 = 0u128.wrapping_sub(u128::from((x >> 2) & 1));
    let add_lo = lo << 4;
    let add_hi = (hi << 4) | (lo >> 124);
    lo |= add_lo & mask2;
    hi |= add_hi & mask2;

    // Bit 3 of x: shift by 2^3 = 8.
    let mask3 = 0u128.wrapping_sub(u128::from((x >> 3) & 1));
    let add_lo = lo << 8;
    let add_hi = (hi << 8) | (lo >> 120);
    lo |= add_lo & mask3;
    hi |= add_hi & mask3;

    // Bit 4 of x: shift by 2^4 = 16.
    let mask4 = 0u128.wrapping_sub(u128::from((x >> 4) & 1));
    let add_lo = lo << 16;
    let add_hi = (hi << 16) | (lo >> 112);
    lo |= add_lo & mask4;
    hi |= add_hi & mask4;

    // Bit 5 of x: shift by 2^5 = 32.
    let mask5 = 0u128.wrapping_sub(u128::from((x >> 5) & 1));
    let add_lo = lo << 32;
    let add_hi = (hi << 32) | (lo >> 96);
    lo |= add_lo & mask5;
    hi |= add_hi & mask5;

    // Bit 6 of x: shift by 2^6 = 64.
    let mask6 = 0u128.wrapping_sub(u128::from((x >> 6) & 1));
    let add_lo = lo << 64;
    let add_hi = (hi << 64) | (lo >> 64);
    lo |= add_lo & mask6;
    hi |= add_hi & mask6;

    // Bit 7 of x: shift by 2^7 = 128 — crosses the lo/hi boundary.
    // Shifted lo lands entirely in hi (shift == 128, so new_lo = 0, new_hi = lo).
    let mask7 = 0u128.wrapping_sub(u128::from((x >> 7) & 1));
    hi |= lo & mask7;

    (lo, hi)
}

/// XOR-parity of all 128 bits of `x` (i.e., `popcount(x) mod 2`).
///
/// Uses a binary folding: XOR the top 64 bits into the bottom 64, then top 32
/// into bottom 32, etc., until 4 bits remain.  The final nibble is looked up in
/// `0x6996`, a 16-entry packed truth table for 4-bit parity:
///
/// ```text
/// 0x6996 = 0110_1001_1001_0110
/// bit i  =  popcount(i) mod 2  for i in 0..16
/// ```
///
/// Used by [`eval_byte_sbox`] to compute the inner product over GF(2).
#[inline]
pub(crate) fn parity128(x: u128) -> u8 {
    profile::bump_parity128();
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    ((lo.count_ones() ^ hi.count_ones()) & 1) as u8
}

/// Evaluate an 8-bit S-box in ANF representation — constant time.
///
/// Each of the 8 output bits is computed as:
///
/// ```text
/// out_bit = parity( subset_indicator(input) & anf_coefficients[bit] )
/// ```
///
/// which is the inner product of the subset mask with the packed coefficient
/// vector over GF(2).  Every input produces exactly the same sequence of AND
/// and XOR operations; there are no branches and no secret-dependent loads.
#[inline]
pub(crate) fn eval_byte_sbox(coeffs: &[[u128; 2]; 8], input: u8) -> u8 {
    profile::bump_eval_byte_sbox();
    let (active_lo, active_hi) = subset_mask8(input);
    let mut out = 0u8;
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let coeff_lo = coeffs[bit_idx][0];
        let coeff_hi = coeffs[bit_idx][1];
        // Parity is linear: parity(a) ^ parity(b) == parity(a ^ b).
        let bit = parity128((active_lo & coeff_lo) ^ (active_hi & coeff_hi));
        out |= bit << bit_idx;
        bit_idx += 1;
    }
    out
}

/// Build the 16-bit subset-indicator mask for a 4-bit input `x` (low nibble).
///
/// Analogous to [`subset_mask8`] but over 16 monomials: bit `i` of the result
/// is `1` iff `(i & x) == i`.  Used to evaluate 4-bit → 4-bit S-boxes in ANF.
#[inline]
pub(crate) fn subset_mask4(x: u8) -> u16 {
    let mut mask = 1u16;

    // Bit 0: subsets gain {0} → shift by 1.
    let b0 = 0u16.wrapping_sub(u16::from(x & 1));
    mask |= (mask << 1) & b0;

    // Bit 1: shift by 2.
    let b1 = 0u16.wrapping_sub(u16::from((x >> 1) & 1));
    mask |= (mask << 2) & b1;

    // Bit 2: shift by 4.
    let b2 = 0u16.wrapping_sub(u16::from((x >> 2) & 1));
    mask |= (mask << 4) & b2;

    // Bit 3: shift by 8.
    let b3 = 0u16.wrapping_sub(u16::from((x >> 3) & 1));
    mask |= (mask << 8) & b3;

    mask
}

/// XOR-parity of all 16 bits of `x` (`popcount(x) mod 2`).
///
/// Folds down to a nibble then uses the `0x6996` packed truth table, same
/// technique as [`parity128`].
#[inline]
pub(crate) fn parity16(mut x: u16) -> u8 {
    // Fold to one nibble, then use the classic parity lookup constant:
    // 0x6996 = binary 0110_1001_1001_0110 where bit n is parity(n).
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    ((0x6996u16 >> x) & 1) as u8
}

/// Evaluate a 4-bit S-box in ANF representation — constant time.
///
/// Each output bit is `parity(subset_indicator(input) & coeffs[bit])` over
/// GF(2).  Same principle as [`eval_byte_sbox`] but with 16-bit words.
#[inline]
pub(crate) fn eval_nibble_sbox(coeffs: [u16; 4], input: u8) -> u8 {
    let active = subset_mask4(input);
    let mut out = 0u8;
    let mut bit = 0usize;
    while bit < 4 {
        out |= parity16(active & coeffs[bit]) << bit;
        bit += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_mask8_zero_and_all_ones() {
        // x=0: only the empty subset (index 0) is active.
        let (lo0, hi0) = subset_mask8(0);
        assert_eq!(lo0, 1);
        assert_eq!(hi0, 0);

        // x=0xFF: every index i satisfies (i & 0xFF)==i, so all 256 bits are set.
        let (lof, hif) = subset_mask8(0xff);
        assert_eq!(lof, u128::MAX);
        assert_eq!(hif, u128::MAX);
    }

    #[test]
    fn subset_mask8_single_bit() {
        // x=0x01: subsets of {bit0} are {} and {bit0} → indices 0 and 1.
        let (lo, hi) = subset_mask8(0x01);
        assert_eq!(lo, 0b11);
        assert_eq!(hi, 0);

        // x=0x80: subsets of {bit7} are {} and {bit7} → indices 0 and 128.
        let (lo, hi) = subset_mask8(0x80);
        assert_eq!(lo, 1);   // bit 0
        assert_eq!(hi, 1);   // bit 128 (= bit 0 of hi)
    }

    #[test]
    fn parity_helpers_known_values() {
        assert_eq!(parity128(0), 0);
        assert_eq!(parity128(1), 1);
        assert_eq!(parity128(0b1011), 1);
        assert_eq!(parity128(u128::MAX), 0); // 128 ones → even

        assert_eq!(parity16(0), 0);
        assert_eq!(parity16(1), 1);
        assert_eq!(parity16(0b1011), 1);
        assert_eq!(parity16(0xffff), 0); // 16 ones → even
    }

    #[test]
    fn ct_lookup_u8_16_picks_exact_entry() {
        let table = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        for i in 0u8..16 {
            assert_eq!(ct_lookup_u8_16(&table, i), i);
        }
    }

    /// Verify that ANF evaluation is functionally identical to direct table
    /// lookup for every possible input.  Uses a non-trivial S-box (the AES
    /// SubBytes table) so that neither all-zeros nor identity degeneracies
    /// can mask a bug in the Möbius transform or subset-mask logic.
    #[test]
    fn byte_sbox_anf_matches_direct_lookup_all_inputs() {
        // AES SubBytes S-box — a well-known non-linear bijection.
        #[rustfmt::skip]
        const AES_SBOX: [u8; 256] = [
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        ];
        let coeffs = build_byte_sbox_anf(&AES_SBOX);
        for x in 0u8..=255 {
            assert_eq!(
                eval_byte_sbox(&coeffs, x),
                AES_SBOX[x as usize],
                "ANF mismatch at input {x:#04x}"
            );
        }
    }

    /// Same exhaustive check for the 4-bit ANF path using a known non-trivial
    /// nibble S-box (the PRESENT cipher S-box).
    #[test]
    fn nibble_sbox_anf_matches_direct_lookup_all_inputs() {
        const PRESENT_SBOX: [u8; 16] =
            [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2];
        let coeffs = build_nibble_sbox_anf(&PRESENT_SBOX);
        for x in 0u8..16 {
            assert_eq!(
                eval_nibble_sbox(coeffs, x),
                PRESENT_SBOX[x as usize],
                "ANF mismatch at input {x:#03x}"
            );
        }
    }
}
