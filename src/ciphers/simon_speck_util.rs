//! Shared word helpers for the SIMON / SPECK families.

/// Load bytes as a little-endian n-bit word into a u64.
#[inline]
pub(super) fn load_le(src: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in src.iter().enumerate() {
        v |= u64::from(b) << (8 * i);
    }
    v
}

/// Store the low bytes of a u64 in little-endian order.
#[inline]
pub(super) fn store_le(mut v: u64, dst: &mut [u8]) {
    for b in dst.iter_mut() {
        *b = u8::try_from(v & 0xff).expect("masked byte fits in u8");
        v >>= 8;
    }
}

#[inline]
pub(super) fn rotl(x: u64, r: u32, n: u32, mask: u64) -> u64 {
    debug_assert!(r > 0 && r < n);
    ((x << r) | (x >> (n - r))) & mask
}

#[inline]
pub(super) fn rotr(x: u64, r: u32, n: u32, mask: u64) -> u64 {
    debug_assert!(r > 0 && r < n);
    ((x >> r) | (x << (n - r))) & mask
}
