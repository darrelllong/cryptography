//! Small shared helpers for the software-hardening pass:
//! fixed-scan table selection and explicit key-buffer wiping.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let mut x = !(a ^ b);
    x &= x >> 4;
    x &= x >> 2;
    x &= x >> 1;
    x & 1
}

#[inline(always)]
pub(crate) fn ct_lookup_u8(table: &[u8], idx: u8) -> u8 {
    // Scan the whole table so the memory access pattern does not depend on `idx`.
    let mut out = 0u8;
    let mut i = 0usize;
    while i < table.len() {
        let mask = 0u8.wrapping_sub(ct_eq_u8(i as u8, idx));
        out |= table[i] & mask;
        i += 1;
    }
    out
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
