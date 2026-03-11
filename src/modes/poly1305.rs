//! Poly1305 one-time authenticator (RFC 8439 / RFC 7539 profile).
//!
//! This implementation uses the standard 32-byte one-time key split into
//! `r || s`, applies RFC clamping to `r`, and computes tags modulo 2^130-5.

use crate::public_key::bigint::BigUint;

#[inline]
fn le_bytes_to_biguint(bytes: &[u8]) -> BigUint {
    let mut be = bytes.to_vec();
    be.reverse();
    BigUint::from_be_bytes(&be)
}

#[inline]
fn biguint_to_16_le(value: &BigUint) -> [u8; 16] {
    let be = value.to_be_bytes();
    let mut out = [0u8; 16];
    if be.len() >= 16 {
        out.copy_from_slice(&be[be.len() - 16..]);
    } else {
        out[16 - be.len()..].copy_from_slice(&be);
    }
    out.reverse();
    out
}

/// Compute a Poly1305 tag over `msg` with the given one-time `key`.
///
/// The key must be unique per message under a fixed long-term secret.
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[..16]);

    // RFC 8439 §2.5.1 clamp for r: clear the high nibble of bytes
    // 3/7/11/15 and the low two bits of bytes 4/8/12.
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;

    let r_big = le_bytes_to_biguint(&r);
    let s_big = le_bytes_to_biguint(&key[16..32]);

    let mut p = BigUint::one();
    p.shl_bits(130);
    p = p.sub_ref(&BigUint::from_u64(5));

    let mut acc = BigUint::zero();
    for chunk in msg.chunks(16) {
        let mut block = Vec::with_capacity(chunk.len() + 1);
        block.extend_from_slice(chunk);
        block.push(1);
        let n = le_bytes_to_biguint(&block);
        acc = acc.add_ref(&n).modulo(&p);
        acc = BigUint::mod_mul(&acc, &r_big, &p);
    }

    let mut mod_2_128 = BigUint::one();
    mod_2_128.shl_bits(128);
    let tag = acc.add_ref(&s_big).modulo(&mod_2_128);
    biguint_to_16_le(&tag)
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
