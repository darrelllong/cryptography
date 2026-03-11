//! Shared helpers for secret handling and software constant-time building
//! blocks.
//!
//! This module keeps the generic pieces that were previously duplicated across
//! several cipher implementations:
//! - explicit zeroization for `Drop` and `new_wiping`
//! - fixed-scan lookup helpers
//! - packed ANF construction for 8-bit and 4-bit S-boxes
//! - runtime packed-ANF evaluators

use core::hint::black_box;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(feature = "ct_profile")]
use std::time::Instant;

#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::process::{Command, Stdio};

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

#[inline]
fn eq_mask_u8(a: u8, b: u8) -> u8 {
    // Same arithmetic trick as `eq_mask_u32`, reduced to an 8-bit all-ones/all-zero mask.
    let x = u16::from(a ^ b);
    let is_zero = ((x.wrapping_sub(1) >> 8) & 1) as u8;
    0u8.wrapping_sub(is_zero)
}

pub(crate) fn zeroize_slice<T: Copy + Default>(slice: &mut [T]) {
    // Shared by `Drop` impls and `new_wiping` constructors so expanded round
    // keys do not remain in memory longer than necessary.
    for item in slice.iter_mut() {
        // Use volatile writes so the compiler does not elide the wipe.
        unsafe { ptr::write_volatile(std::ptr::from_mut::<T>(item), T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

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
    eq_mask_u8(diff, 0)
}

#[cfg(test)]
pub(crate) fn run_openssl(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(stdin).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

#[cfg(test)]
pub(crate) fn run_openssl_enc(
    cipher_name: &str,
    key_hex: &str,
    iv_hex: Option<&str>,
    input: &[u8],
) -> Option<Vec<u8>> {
    let mut args = vec!["enc", cipher_name, "-nopad", "-nosalt", "-K", key_hex];
    if let Some(iv) = iv_hex {
        args.extend(["-iv", iv]);
    }
    args.push("-e");
    run_openssl(&args, input)
}

/// Build packed ANF coefficients for an 8-bit S-box.
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

/// Build packed ANF coefficients for a 4-bit S-box.
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

    let mask0 = 0u128.wrapping_sub(u128::from(x & 1));
    let add_lo = lo << 1;
    let add_hi = (hi << 1) | (lo >> 127);
    lo |= add_lo & mask0;
    hi |= add_hi & mask0;

    let mask1 = 0u128.wrapping_sub(u128::from((x >> 1) & 1));
    let add_lo = lo << 2;
    let add_hi = (hi << 2) | (lo >> 126);
    lo |= add_lo & mask1;
    hi |= add_hi & mask1;

    let mask2 = 0u128.wrapping_sub(u128::from((x >> 2) & 1));
    let add_lo = lo << 4;
    let add_hi = (hi << 4) | (lo >> 124);
    lo |= add_lo & mask2;
    hi |= add_hi & mask2;

    let mask3 = 0u128.wrapping_sub(u128::from((x >> 3) & 1));
    let add_lo = lo << 8;
    let add_hi = (hi << 8) | (lo >> 120);
    lo |= add_lo & mask3;
    hi |= add_hi & mask3;

    let mask4 = 0u128.wrapping_sub(u128::from((x >> 4) & 1));
    let add_lo = lo << 16;
    let add_hi = (hi << 16) | (lo >> 112);
    lo |= add_lo & mask4;
    hi |= add_hi & mask4;

    let mask5 = 0u128.wrapping_sub(u128::from((x >> 5) & 1));
    let add_lo = lo << 32;
    let add_hi = (hi << 32) | (lo >> 96);
    lo |= add_lo & mask5;
    hi |= add_hi & mask5;

    let mask6 = 0u128.wrapping_sub(u128::from((x >> 6) & 1));
    let add_lo = lo << 64;
    let add_hi = (hi << 64) | (lo >> 64);
    lo |= add_lo & mask6;
    hi |= add_hi & mask6;

    let mask7 = 0u128.wrapping_sub(u128::from((x >> 7) & 1));
    hi |= lo & mask7;

    (lo, hi)
}

#[inline]
pub(crate) fn parity128(x: u128) -> u8 {
    profile::bump_parity128();
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    ((lo.count_ones() ^ hi.count_ones()) & 1) as u8
}

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

#[inline]
pub(crate) fn subset_mask4(x: u8) -> u16 {
    let mut mask = 1u16;

    let b0 = 0u16.wrapping_sub(u16::from(x & 1));
    mask |= (mask << 1) & b0;

    let b1 = 0u16.wrapping_sub(u16::from((x >> 1) & 1));
    mask |= (mask << 2) & b1;

    let b2 = 0u16.wrapping_sub(u16::from((x >> 2) & 1));
    mask |= (mask << 4) & b2;

    let b3 = 0u16.wrapping_sub(u16::from((x >> 3) & 1));
    mask |= (mask << 8) & b3;

    mask
}

#[inline]
pub(crate) fn parity16(mut x: u16) -> u8 {
    // Fold to one nibble, then use the classic parity lookup constant:
    // 0x6996 = binary 0110_1001_1001_0110 where bit n is parity(n).
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    ((0x6996u16 >> x) & 1) as u8
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_mask8_zero_and_all_ones() {
        let (lo0, hi0) = subset_mask8(0);
        assert_eq!(lo0, 1);
        assert_eq!(hi0, 0);

        let (lof, hif) = subset_mask8(0xff);
        assert_eq!(lof, u128::MAX);
        assert_eq!(hif, u128::MAX);
    }

    #[test]
    fn subset_mask8_single_bit() {
        let (lo, hi) = subset_mask8(0x01);
        assert_eq!(lo, 0b11);
        assert_eq!(hi, 0);

        let (lo, hi) = subset_mask8(0x80);
        assert_eq!(lo, 1);
        assert_eq!(hi, 1);
    }

    #[test]
    fn parity_helpers_known_values() {
        assert_eq!(parity128(0), 0);
        assert_eq!(parity128(1), 1);
        assert_eq!(parity128(0b1011), 1);
        assert_eq!(parity128(u128::MAX), 0);

        assert_eq!(parity16(0), 0);
        assert_eq!(parity16(1), 1);
        assert_eq!(parity16(0b1011), 1);
        assert_eq!(parity16(0xffff), 0);
    }

    #[test]
    fn ct_lookup_u8_16_picks_exact_entry() {
        let table = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        for i in 0u8..16 {
            assert_eq!(ct_lookup_u8_16(&table, i), i);
        }
    }
}
