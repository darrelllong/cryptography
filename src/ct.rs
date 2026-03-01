//! Shared helpers for secret handling and software constant-time building
//! blocks.
//!
//! This module keeps the generic pieces that were previously duplicated across
//! several cipher implementations:
//! - explicit zeroization for `Drop` and `new_wiping`
//! - fixed-scan lookup helpers
//! - packed ANF construction for 8-bit and 4-bit S-boxes
//! - runtime packed-ANF evaluators

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[inline(always)]
fn eq_mask_u32(a: u8, b: u8) -> u32 {
    let x = (a ^ b) as u16;
    let is_zero = ((x.wrapping_sub(1) >> 8) & 1) as u32;
    0u32.wrapping_sub(is_zero)
}

pub(crate) fn zeroize_slice<T: Copy + Default>(slice: &mut [T]) {
    // Shared by `Drop` impls and `new_wiping` constructors so expanded round
    // keys do not remain in memory longer than necessary.
    for item in slice.iter_mut() {
        // Use volatile writes so the compiler does not elide the wipe.
        unsafe { ptr::write_volatile(item as *mut T, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn ct_lookup_u32(table: &[u32; 256], idx: u8) -> u32 {
    let mut out = 0u32;
    let mut i = 0usize;
    while i < 256 {
        out |= table[i] & eq_mask_u32(i as u8, idx);
        i += 1;
    }
    out
}

pub(crate) fn ct_lookup_u8_16(table: &[u8; 16], idx: u8) -> u8 {
    let mut out = 0u8;
    let mut i = 0usize;
    while i < 16 {
        out |= table[i] & (eq_mask_u32(i as u8, idx) as u8);
        i += 1;
    }
    out
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

#[inline(always)]
pub(crate) const fn shl_256<const SHIFT: u32>(lo: u128, hi: u128) -> (u128, u128) {
    debug_assert!(SHIFT >= 1 && SHIFT <= 127);
    (lo << SHIFT, (hi << SHIFT) | (lo >> (128 - SHIFT)))
}

#[inline(always)]
pub(crate) fn subset_mask8(x: u8) -> (u128, u128) {
    let mut lo = 1u128;
    let mut hi = 0u128;

    let mask0 = 0u128.wrapping_sub((x & 1) as u128);
    let (add_lo, add_hi) = shl_256::<1>(lo, hi);
    lo |= add_lo & mask0;
    hi |= add_hi & mask0;

    let mask1 = 0u128.wrapping_sub(((x >> 1) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<2>(lo, hi);
    lo |= add_lo & mask1;
    hi |= add_hi & mask1;

    let mask2 = 0u128.wrapping_sub(((x >> 2) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<4>(lo, hi);
    lo |= add_lo & mask2;
    hi |= add_hi & mask2;

    let mask3 = 0u128.wrapping_sub(((x >> 3) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<8>(lo, hi);
    lo |= add_lo & mask3;
    hi |= add_hi & mask3;

    let mask4 = 0u128.wrapping_sub(((x >> 4) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<16>(lo, hi);
    lo |= add_lo & mask4;
    hi |= add_hi & mask4;

    let mask5 = 0u128.wrapping_sub(((x >> 5) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<32>(lo, hi);
    lo |= add_lo & mask5;
    hi |= add_hi & mask5;

    let mask6 = 0u128.wrapping_sub(((x >> 6) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<64>(lo, hi);
    lo |= add_lo & mask6;
    hi |= add_hi & mask6;

    let mask7 = 0u128.wrapping_sub(((x >> 7) & 1) as u128);
    hi |= lo & mask7;

    (lo, hi)
}

#[inline(always)]
pub(crate) fn parity128(mut x: u128) -> u8 {
    x ^= x >> 64;
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    ((0x6996u16 >> (x as u16)) & 1) as u8
}

#[inline(always)]
pub(crate) fn eval_byte_sbox(coeffs: &[[u128; 2]; 8], input: u8) -> u8 {
    let (active_lo, active_hi) = subset_mask8(input);
    let mut out = 0u8;
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let coeff_lo = coeffs[bit_idx][0];
        let coeff_hi = coeffs[bit_idx][1];
        let bit = parity128(active_lo & coeff_lo) ^ parity128(active_hi & coeff_hi);
        out |= bit << bit_idx;
        bit_idx += 1;
    }
    out
}

#[inline(always)]
pub(crate) fn subset_mask4(x: u8) -> u16 {
    let mut mask = 1u16;

    let b0 = 0u16.wrapping_sub((x & 1) as u16);
    mask |= (mask << 1) & b0;

    let b1 = 0u16.wrapping_sub(((x >> 1) & 1) as u16);
    mask |= (mask << 2) & b1;

    let b2 = 0u16.wrapping_sub(((x >> 2) & 1) as u16);
    mask |= (mask << 4) & b2;

    let b3 = 0u16.wrapping_sub(((x >> 3) & 1) as u16);
    mask |= (mask << 8) & b3;

    mask
}

#[inline(always)]
pub(crate) fn parity16(mut x: u16) -> u8 {
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    ((0x6996u16 >> x) & 1) as u8
}

#[inline(always)]
pub(crate) fn eval_nibble_sbox(coeffs: &[u16; 4], input: u8) -> u8 {
    let active = subset_mask4(input);
    let mut out = 0u8;
    let mut bit = 0usize;
    while bit < 4 {
        out |= parity16(active & coeffs[bit]) << bit;
        bit += 1;
    }
    out
}
