//! Small shared helpers for the software-hardening pass.
//!
//! At the moment this module is only about secret lifetime management:
//! explicit wiping for caller-provided keys and stored round keys. Timing
//! behavior lives with each cipher so the implementation choice stays close to
//! the hot path it affects.

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
