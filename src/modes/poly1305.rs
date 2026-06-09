//! Poly1305 one-time authenticator (RFC 8439 / RFC 7539 profile).
//!
//! This implementation uses the standard 32-byte one-time key split into
//! `r || s`, applies RFC clamping to `r`, and computes tags modulo 2^130-5.
//!
//! The accumulator is held in five radix-2^26 limbs with 64-bit intermediate
//! products (the classic "poly1305-donna" schoolbook form): branch-free,
//! allocation-free, and constant-time with respect to both key and message
//! contents (only the message *length* affects the schedule).

#[inline]
fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Compute a Poly1305 tag over `msg` with the given one-time `key`.
///
/// The key must be unique per message under a fixed long-term secret.
#[must_use]
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    // r in five 26-bit limbs, with the RFC 8439 §2.5.1 clamp folded into the
    // masks (top nibble of bytes 3/7/11/15 and low two bits of 4/8/12 clear).
    let r0 = le32(key, 0) & 0x03ff_ffff;
    let r1 = (le32(key, 3) >> 2) & 0x03ff_ff03;
    let r2 = (le32(key, 6) >> 4) & 0x03ff_c0ff;
    let r3 = (le32(key, 9) >> 6) & 0x03f0_3fff;
    let r4 = (le32(key, 12) >> 8) & 0x000f_ffff;

    // Precomputed 5·r limbs for the reduction folding of high partial products.
    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    for chunk in msg.chunks(16) {
        // Block value: little-endian chunk with the 0x01 domain byte appended
        // (RFC 8439 §2.5.1). The fixed 17-byte buffer makes full and partial
        // blocks share one code path.
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;

        h0 = h0.wrapping_add(le32(&block, 0) & 0x03ff_ffff);
        h1 = h1.wrapping_add((le32(&block, 3) >> 2) & 0x03ff_ffff);
        h2 = h2.wrapping_add((le32(&block, 6) >> 4) & 0x03ff_ffff);
        h3 = h3.wrapping_add((le32(&block, 9) >> 6) & 0x03ff_ffff);
        h4 = h4.wrapping_add(le32(&block, 13));

        // h *= r (mod 2^130 - 5): schoolbook product with the x^k terms for
        // k >= 5 folded back via 2^130 = 5 (the s* limbs).
        let d0 = u64::from(h0) * u64::from(r0)
            + u64::from(h1) * u64::from(s4)
            + u64::from(h2) * u64::from(s3)
            + u64::from(h3) * u64::from(s2)
            + u64::from(h4) * u64::from(s1);
        let d1 = u64::from(h0) * u64::from(r1)
            + u64::from(h1) * u64::from(r0)
            + u64::from(h2) * u64::from(s4)
            + u64::from(h3) * u64::from(s3)
            + u64::from(h4) * u64::from(s2);
        let d2 = u64::from(h0) * u64::from(r2)
            + u64::from(h1) * u64::from(r1)
            + u64::from(h2) * u64::from(r0)
            + u64::from(h3) * u64::from(s4)
            + u64::from(h4) * u64::from(s3);
        let d3 = u64::from(h0) * u64::from(r3)
            + u64::from(h1) * u64::from(r2)
            + u64::from(h2) * u64::from(r1)
            + u64::from(h3) * u64::from(r0)
            + u64::from(h4) * u64::from(s4);
        let d4 = u64::from(h0) * u64::from(r4)
            + u64::from(h1) * u64::from(r3)
            + u64::from(h2) * u64::from(r2)
            + u64::from(h3) * u64::from(r1)
            + u64::from(h4) * u64::from(r0);

        // Single carry chain brings every limb back below 2^26 (plus a small
        // residue in h1 that the next round absorbs).
        let mut c;
        c = d0 >> 26;
        h0 = (d0 as u32) & 0x03ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        h1 = (d1 as u32) & 0x03ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        h2 = (d2 as u32) & 0x03ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        h3 = (d3 as u32) & 0x03ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        h4 = (d4 as u32) & 0x03ff_ffff;
        h0 = h0.wrapping_add((c as u32) * 5);
        let c32 = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c32);
    }

    // Full carry propagation, then conditionally subtract p = 2^130 - 5
    // (branch-free select on the borrow of h + 5 - 2^130).
    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 = h0.wrapping_add(c * 5);
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 = h1.wrapping_add(c);

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    // mask = all-ones when h >= p (no borrow out of g4), else zero.
    let mask = (g4 >> 31).wrapping_sub(1);
    h0 = (h0 & !mask) | (g0 & mask);
    h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask);
    h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);

    // Repack 5x26-bit limbs into 4x32-bit words (h mod 2^128).
    let t0 = h0 | (h1 << 26);
    let t1 = (h1 >> 6) | (h2 << 20);
    let t2 = (h2 >> 12) | (h3 << 14);
    let t3 = (h3 >> 18) | (h4 << 8);

    // tag = (h + s) mod 2^128 with a 64-bit carry chain.
    let mut f = u64::from(t0) + u64::from(le32(key, 16));
    let o0 = f as u32;
    f = u64::from(t1) + u64::from(le32(key, 20)) + (f >> 32);
    let o1 = f as u32;
    f = u64::from(t2) + u64::from(le32(key, 24)) + (f >> 32);
    let o2 = f as u32;
    f = u64::from(t3) + u64::from(le32(key, 28)) + (f >> 32);
    let o3 = f as u32;

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&o0.to_le_bytes());
    out[4..8].copy_from_slice(&o1.to_le_bytes());
    out[8..12].copy_from_slice(&o2.to_le_bytes());
    out[12..16].copy_from_slice(&o3.to_le_bytes());
    out
}

/// Poly1305 state wrapper for repeated message authentication with a fixed
/// one-time key.
pub struct Poly1305 {
    key: [u8; 32],
}

impl Poly1305 {
    /// Construct a Poly1305 context from a one-time key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Construct a Poly1305 context and wipe the caller-provided key bytes.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Compute a Poly1305 tag over `msg`.
    #[must_use]
    pub fn compute(&self, msg: &[u8]) -> [u8; 16] {
        poly1305_mac(msg, &self.key)
    }

    /// Verify a Poly1305 tag in constant time.
    #[must_use]
    pub fn verify(&self, msg: &[u8], tag: &[u8; 16]) -> bool {
        crate::ct::constant_time_eq_mask(&self.compute(msg), tag) == u8::MAX
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.key.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::{poly1305_mac, Poly1305};

    fn unhex(input: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        let key = <[u8; 32]>::try_from(unhex(
            "85d6be7857556d337f4452fe42d506a8\
             0103808afb0db2fd4abff6af4149f51b",
        ))
        .expect("key");
        let msg = b"Cryptographic Forum Research Group";
        let expected =
            <[u8; 16]>::try_from(unhex("a8061dc1305136c6c22b8baf0c0127a9")).expect("tag");
        assert_eq!(poly1305_mac(msg, &key), expected);
    }

    #[test]
    fn wrapper_verify_roundtrip() {
        let key = [0x11u8; 32];
        let mac = Poly1305::new(&key);
        let msg = b"poly1305 message";
        let tag = mac.compute(msg);
        assert!(mac.verify(msg, &tag));

        let mut tampered = tag;
        tampered[0] ^= 0x80;
        assert!(!mac.verify(msg, &tampered));
    }
}
