//! Small shared helpers for the software-hardening pass.
//!
//! At the moment this module is only about secret lifetime management:
//! explicit wiping for caller-provided keys and stored round keys. Timing
//! behavior lives with each cipher so the implementation choice stays close to
//! the hot path it affects.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

pub(crate) fn zeroize_slice<T: Copy + Default>(slice: &mut [T]) {
    // Shared by `Drop` impls and `new_wiping` constructors so expanded round
    // keys do not remain in memory longer than necessary.
    for item in slice.iter_mut() {
        // Use volatile writes so the compiler does not elide the wipe.
        unsafe { ptr::write_volatile(item as *mut T, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}
