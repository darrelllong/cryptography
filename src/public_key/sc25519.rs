//! Arithmetic modulo `L`, the order of edwards25519's prime-order subgroup,
//! constant time in its operands.
//!
//! RFC 8032 §5.1.6 reduces a SHA-512 digest modulo `L` to get the nonce `r`
//! and the challenge `k`, and computes `S = (r + k·a) mod L`. Every one of
//! those values is secret, so this module is fixed-width and branch-free:
//! four 64-bit limbs, Montgomery multiplication with `R = 2^256`, and a final
//! subtraction that is always performed and then selected under a mask.
//!
//! Montgomery form never escapes this module. The callers hand over ordinary
//! little-endian scalars and get them back.

use crate::ct::{select_u64, zeroize_slice};

/// Limbs in a scalar, and the encoded width RFC 8032 §5.1.6 uses.
const LIMBS: usize = 4;
pub(crate) const SC_BYTES: usize = 32;
/// The digest width the reduction takes, which is SHA-512's.
pub(crate) const WIDE_BYTES: usize = 64;

/// `L = 2^252 + 27742317777372353535851937790883648493` (RFC 8032 §5.1), in
/// four 64-bit limbs, least significant first. The tests recompute these from
/// that expression.
const L: [u64; LIMBS] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// `R^2 mod L` for `R = 2^256`, which converts into Montgomery form, and
/// `-L^-1 mod 2^64`, which is the per-limb multiplier the reduction needs.
/// Both follow from `L` alone, and the tests recompute them.
const R2: [u64; LIMBS] = [
    0xa406_11e3_449c_0f01,
    0xd00e_1ba7_6885_9347,
    0xceec_73d2_17f5_be65,
    0x0399_411b_7c30_9a3d,
];
const L_INVERSE_NEGATED: u64 = 0xd2b5_1da3_1254_7e1b;

/// A scalar modulo `L`, as four limbs.
#[derive(Clone, Copy)]
pub(crate) struct Scalar([u64; LIMBS]);

impl Scalar {
    const ONE: Scalar = Scalar([1, 0, 0, 0]);

    /// Wipe a scalar that held a secret.
    pub(crate) fn zeroize(&mut self) {
        zeroize_slice(&mut self.0);
    }

    fn from_le_bytes(bytes: &[u8; SC_BYTES]) -> Scalar {
        let mut limbs = [0u64; LIMBS];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().expect("eight bytes"));
        }
        Scalar(limbs)
    }

    pub(crate) fn to_le_bytes(self) -> [u8; SC_BYTES] {
        let mut out = [0u8; SC_BYTES];
        for (limb, chunk) in self.0.iter().zip(out.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }
}

/// `a - L` when that does not borrow, `a` when it does: the one conditional
/// subtraction a sum or a Montgomery product can need. Both branches are
/// computed and the answer is selected under a mask.
fn subtract_l_if_possible(a: [u64; LIMBS], carry: u64) -> [u64; LIMBS] {
    let mut reduced = [0u64; LIMBS];
    let mut borrow = 0u64;
    for (index, slot) in reduced.iter_mut().enumerate() {
        let (difference, borrowed) = a[index].overflowing_sub(L[index] + borrow);
        *slot = difference;
        borrow = u64::from(borrowed);
    }
    // A borrow out of the top limb means a < L, unless the value carried a bit
    // above the four limbs, in which case the subtraction was needed.
    let keep = 0u64.wrapping_sub(borrow & (carry ^ 1));
    let mut out = [0u64; LIMBS];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = select_u64(keep, a[index], reduced[index]);
    }
    out
}

/// `(a + b) mod L`, for `a` and `b` already below `L`.
fn add(a: &Scalar, b: &Scalar) -> Scalar {
    let mut sum = [0u64; LIMBS];
    let mut carry = 0u64;
    for (index, slot) in sum.iter_mut().enumerate() {
        let wide = u128::from(a.0[index]) + u128::from(b.0[index]) + u128::from(carry);
        *slot = wide as u64;
        carry = (wide >> 64) as u64;
    }
    Scalar(subtract_l_if_possible(sum, carry))
}

/// `a · b · R^-1 mod L`, by the coarsely integrated operand scanning form of
/// Montgomery multiplication: one pass per limb of `b`, each accumulating a
/// product and then clearing the low limb.
fn montgomery_mul(a: &Scalar, b: &Scalar) -> Scalar {
    // One limb wider than the operands, for the accumulator's top carry.
    let mut acc = [0u64; LIMBS + 1];
    for i in 0..LIMBS {
        // acc += a * b[i]
        let mut carry = 0u128;
        for (slot, limb) in acc[..LIMBS].iter_mut().zip(a.0.iter()) {
            let wide = u128::from(*slot) + u128::from(*limb) * u128::from(b.0[i]) + carry;
            *slot = wide as u64;
            carry = wide >> 64;
        }
        let wide = u128::from(acc[LIMBS]) + carry;
        acc[LIMBS] = wide as u64;
        let mut overflow = (wide >> 64) as u64;

        // acc += L * m, chosen so the low limb becomes zero, then shift down.
        let m = acc[0].wrapping_mul(L_INVERSE_NEGATED);
        let mut carry = 0u128;
        for (slot, modulus_limb) in acc[..LIMBS].iter_mut().zip(L.iter()) {
            let wide = u128::from(*slot) + u128::from(*modulus_limb) * u128::from(m) + carry;
            *slot = wide as u64;
            carry = wide >> 64;
        }
        let wide = u128::from(acc[LIMBS]) + carry;
        acc[LIMBS] = wide as u64;
        overflow += (wide >> 64) as u64;

        acc.copy_within(1.., 0);
        acc[LIMBS] = overflow;
    }

    let mut limbs = [0u64; LIMBS];
    limbs.copy_from_slice(&acc[..LIMBS]);
    let out = Scalar(subtract_l_if_possible(limbs, acc[LIMBS]));
    zeroize_slice(acc.as_mut_slice());
    out
}

/// Into Montgomery form: `a · R mod L`.
fn to_montgomery(a: &Scalar) -> Scalar {
    montgomery_mul(a, &Scalar(R2))
}

/// Out of Montgomery form: `a · R^-1 mod L`.
fn from_montgomery(a: &Scalar) -> Scalar {
    montgomery_mul(a, &Scalar::ONE)
}

/// A 256-bit little-endian value modulo `L`.
pub(crate) fn reduce(bytes: &[u8; SC_BYTES]) -> Scalar {
    let raw = Scalar::from_le_bytes(bytes);
    let mut lifted = to_montgomery(&raw);
    let out = from_montgomery(&lifted);
    lifted.zeroize();
    out
}

/// A 512-bit little-endian value modulo `L`, which is what RFC 8032 §5.1.6
/// does to a SHA-512 digest.
///
/// The value is `low + high · 2^256`, and `2^256` is `R`, so the high half's
/// contribution is exactly its conversion into Montgomery form.
pub(crate) fn reduce_wide(bytes: &[u8; WIDE_BYTES]) -> Scalar {
    let mut low = [0u8; SC_BYTES];
    let mut high = [0u8; SC_BYTES];
    low.copy_from_slice(&bytes[..SC_BYTES]);
    high.copy_from_slice(&bytes[SC_BYTES..]);

    let mut low_reduced = reduce(&low);
    let mut high_lifted = to_montgomery(&Scalar::from_le_bytes(&high));
    let out = add(&low_reduced, &high_lifted);

    zeroize_slice(low.as_mut_slice());
    zeroize_slice(high.as_mut_slice());
    low_reduced.zeroize();
    high_lifted.zeroize();
    out
}

/// `(a · b + c) mod L`, the response `S` of RFC 8032 §5.1.6.
pub(crate) fn mul_add(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    // The Montgomery product is `a·b·R^-1`, so lifting it once gives `a·b`.
    let mut product = montgomery_mul(a, b);
    let mut plain = to_montgomery(&product);
    let out = add(&plain, c);
    product.zeroize();
    plain.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vt::BigUint;

    fn order() -> BigUint {
        let mut be = L;
        be.reverse();
        let mut bytes = Vec::new();
        for limb in be {
            bytes.extend_from_slice(&limb.to_be_bytes());
        }
        BigUint::from_be_bytes(&bytes)
    }

    fn as_biguint(scalar: &Scalar) -> BigUint {
        let mut be = scalar.to_le_bytes();
        be.reverse();
        BigUint::from_be_bytes(&be)
    }

    fn from_le(bytes: &[u8]) -> BigUint {
        let mut be = bytes.to_vec();
        be.reverse();
        BigUint::from_be_bytes(&be)
    }

    /// The constants are what their definitions say.
    #[test]
    fn the_constants_come_from_their_definitions() {
        let two = BigUint::from_u64(2);
        let expected = two.pow_u64(252).add(
            &BigUint::from_str_radix("27742317777372353535851937790883648493", 10)
                .expect("the RFC's constant"),
        );
        assert_eq!(order(), expected, "L");

        // R^2 mod L, with R = 2^256.
        let r2 = two.pow_u64(512).rem(&order());
        let mut bytes = Vec::new();
        for limb in R2 {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        assert_eq!(from_le(&bytes), r2, "R^2 mod L");

        // L * (-L^-1 mod 2^64) ≡ -1 (mod 2^64).
        let low = L[0].wrapping_mul(L_INVERSE_NEGATED);
        assert_eq!(low, u64::MAX, "-L^-1 mod 2^64");
    }

    /// Reduction and multiply-add agree with the same arithmetic in the
    /// crate's big integers, on the boundaries and on pseudorandom inputs.
    #[test]
    fn the_arithmetic_agrees_with_big_integers() {
        let modulus = order();
        let mut wide = [0u8; WIDE_BYTES];

        // Zero, one, L itself, L - 1, and 2^512 - 1.
        let cases: [[u8; WIDE_BYTES]; 5] = [
            [0u8; WIDE_BYTES],
            {
                let mut w = [0u8; WIDE_BYTES];
                w[0] = 1;
                w
            },
            {
                let mut w = [0u8; WIDE_BYTES];
                for (i, limb) in L.iter().enumerate() {
                    w[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
                }
                w
            },
            {
                let mut w = [0u8; WIDE_BYTES];
                for (i, limb) in L.iter().enumerate() {
                    w[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
                }
                w[0] -= 1;
                w
            },
            [0xff; WIDE_BYTES],
        ];
        for case in cases {
            let mine = as_biguint(&reduce_wide(&case));
            assert_eq!(mine, from_le(&case).rem(&modulus), "reduce_wide");
        }

        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..64 {
            for chunk in wide.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let reduced = reduce_wide(&wide);
            assert_eq!(
                as_biguint(&reduced),
                from_le(&wide).rem(&modulus),
                "reduce_wide on a pseudorandom digest"
            );

            let mut a_bytes = [0u8; WIDE_BYTES];
            let mut b_bytes = [0u8; WIDE_BYTES];
            let mut c_bytes = [0u8; WIDE_BYTES];
            for buffer in [&mut a_bytes, &mut b_bytes, &mut c_bytes] {
                for chunk in buffer.chunks_exact_mut(8) {
                    chunk.copy_from_slice(&next().to_le_bytes());
                }
            }
            let a = reduce_wide(&a_bytes);
            let b = reduce_wide(&b_bytes);
            let c = reduce_wide(&c_bytes);
            let expected = as_biguint(&a)
                .mul(&as_biguint(&b))
                .add(&as_biguint(&c))
                .rem(&modulus);
            assert_eq!(as_biguint(&mul_add(&a, &b, &c)), expected, "mul_add");
        }
    }

    /// A reduced scalar round-trips through its encoding.
    #[test]
    fn encoding_round_trips() {
        let mut bytes = [0u8; SC_BYTES];
        bytes[0] = 7;
        bytes[31] = 0x0f;
        let scalar = reduce(&bytes);
        assert_eq!(scalar.to_le_bytes(), bytes, "a value already below L");
    }
}
