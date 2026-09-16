//! RFC 6979 deterministic nonce derivation, shared by DSA and ECDSA.
//!
//! Both signature schemes derive their per-message nonce `k ∈ [1, q)` from
//! the private key and the message digest with the HMAC-DRBG-style
//! construction of RFC 6979 §3.2, and both truncate hash outputs to the
//! subgroup order's width with the same `bits2int` rule (§2.3.2, which is
//! also the FIPS 186-4 §4.6 / FIPS 186-5 §6.4.1 digest truncation). The
//! conversion helpers and the derivation loop live here once.
//!
//! The owned private-key octets, the K/V state and every candidate's octets
//! are wiped on drop, including early returns and unwinding; the wiping is
//! unconditional. The HMAC state remains live across range and
//! signature-level rejections, as the §3.2 chain requires.

use core::marker::PhantomData;

use crate::hash::Digest;
use crate::zeroize_slice;
use crate::Hmac;
use rump::BigUint;

/// RFC 6979 §2.3.2 `bits2int`: keep the leftmost `target_bits` bits of the
/// input, interpreting the octets as a big-endian integer.
///
/// The shift amount is derived from `input.len() * 8`, not from the trimmed
/// width of the integer, so it does not depend on leading zero bits.
pub(crate) fn bits_to_int(input: &[u8], target_bits: usize) -> BigUint {
    let mut value = BigUint::from_be_bytes(input);
    let input_bits = input.len() * 8;
    if input_bits > target_bits {
        value.shr_bits(input_bits - target_bits);
    }
    value
}

/// RFC 6979 §2.3.3 `int2octets`: fixed-width big-endian encoding of a value
/// already reduced below the group order, so it always fits.
pub(crate) fn int_to_octets(value: &BigUint, len: usize) -> Vec<u8> {
    value.to_be_bytes_padded(len)
}

/// RFC 6979 §2.3.4 `bits2octets`: `bits2int`, reduce modulo `q`, then
/// `int2octets`.
pub(crate) fn bits_to_octets(input: &[u8], q: &BigUint, q_bits: usize, ro_len: usize) -> Vec<u8> {
    let z1 = bits_to_int(input, q_bits);
    let z2 = z1.rem(q);
    int_to_octets(&z2, ro_len)
}

/// Own nonce bytes so they are wiped on replacement and on every exit.
struct NonceBytes(Vec<u8>);

impl Drop for NonceBytes {
    fn drop(&mut self) {
        zeroize_slice(self.0.as_mut_slice());
    }
}

/// RFC 6979 section 3.2 nonce stream for one signature.
///
/// Asking for another candidate rejects the previous one and advances K/V
/// through step h.3. Thus both out-of-range and zero-r/zero-s rejections use
/// the same transition, without restarting from the private key and digest.
pub(crate) struct NonceGenerator<'a, H: Digest> {
    q: &'a BigUint,
    q_bits: usize,
    ro_len: usize,
    k: NonceBytes,
    v: NonceBytes,
    retry: bool,
    hash: PhantomData<H>,
}

impl<'a, H: Digest> NonceGenerator<'a, H> {
    /// Initialize one stream. Reject a degenerate order or empty-output hash.
    pub(crate) fn new(q: &'a BigUint, x: &BigUint, digest: &[u8]) -> Option<Self> {
        if q <= &BigUint::one() || H::OUTPUT_LEN == 0 {
            return None;
        }
        let q_bits = q.bits();
        let ro_len = q_bits.div_ceil(8);
        let bx = NonceBytes(int_to_octets(x, ro_len));
        let bh = bits_to_octets(digest, q, q_bits, ro_len);
        let mut state = Self {
            q,
            q_bits,
            ro_len,
            k: NonceBytes(vec![0; H::OUTPUT_LEN]),
            v: NonceBytes(vec![1; H::OUTPUT_LEN]),
            retry: false,
            hash: PhantomData,
        };
        state.update(0x00, &[&bx.0, &bh]);
        state.update(0x01, &[&bx.0, &bh]);
        Some(state)
    }

    /// Update K before V, absorbing the separator and optional seed pieces.
    fn update(&mut self, separator: u8, seed: &[&[u8]]) {
        let mut mac = Hmac::<H>::new(&self.k.0);
        mac.update(&self.v.0);
        mac.update(&[separator]);
        for piece in seed {
            mac.update(piece);
        }
        self.k = NonceBytes(mac.finalize());
        self.advance_v();
    }

    fn advance_v(&mut self) {
        let next = Hmac::<H>::compute(&self.k.0, &self.v.0);
        self.v = NonceBytes(next);
    }

    /// Return the next in-range candidate, rejecting any previously returned one.
    pub(crate) fn next(&mut self) -> BigUint {
        loop {
            if self.retry {
                self.update(0x00, &[]);
            }
            self.retry = true;
            let mut t = NonceBytes(Vec::with_capacity(self.ro_len));
            while t.0.len() < self.ro_len {
                self.advance_v();
                let take = (self.ro_len - t.0.len()).min(self.v.0.len());
                t.0.extend_from_slice(&self.v.0[..take]);
            }
            let candidate = bits_to_int(&t.0, self.q_bits);
            if !candidate.is_zero() && &candidate < self.q {
                return candidate;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{bits_to_int, bits_to_octets, int_to_octets};
    use rump::BigUint;

    #[test]
    fn bits_to_int_keeps_leftmost_bits_by_octet_width() {
        // A 16-bit input truncated to 9 bits keeps the top 9: 0x00ff >> 7 = 1.
        assert_eq!(bits_to_int(&[0x00, 0xff], 9), BigUint::one());
        // Inputs no wider than the target are taken whole.
        assert_eq!(bits_to_int(&[0x01, 0x02], 16), BigUint::from_u64(0x0102));
        assert_eq!(bits_to_int(&[0x01, 0x02], 24), BigUint::from_u64(0x0102));
    }

    #[test]
    fn octet_conversions_are_fixed_width() {
        assert_eq!(int_to_octets(&BigUint::from_u64(5), 3), [0, 0, 5]);
        // bits2octets reduces modulo q before padding: 0xff >> 4 = 15 ≡ 4 (mod 11).
        let q = BigUint::from_u64(11);
        assert_eq!(bits_to_octets(&[0xff], &q, 4, 1), [4]);
    }
}
