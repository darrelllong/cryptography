//! The field of `p = 2^255 - 19`, in five limbs of 51 bits.
//!
//! Curve25519 and edwards25519 are the same field, so the ladder of
//! [`super::x25519`] and the Edwards arithmetic of [`super::ed25519_group`]
//! share this one implementation. Every operation here is constant time in
//! its inputs: no branch and no memory index depends on a field element, and
//! the conditional forms — [`fe_cswap`], [`fe_cmov`] — touch every limb
//! whatever their flag says.
//!
//! Representation is "relaxed": limbs may exceed `2^51` between operations,
//! within the bound the next operation states. [`fe_to_bytes`] canonicalises.

use crate::ct::zeroize_slice;

/// Five limbs of 51 bits, which is `5 × 51 = 255`, the width of the field.
pub(crate) const LIMBS: usize = 5;
const LIMB_BITS: u32 = 51;

/// A field element's encoded width, which is also a scalar's (RFC 7748 §5,
/// RFC 8032 §5.1).
pub(crate) const FE_BYTES: usize = 32;

const MASK51: u64 = (1u64 << LIMB_BITS) - 1;

// Field modulus p = 2^255 - 19 in 5x51 limbs.
//   limb 0 = 2^51 - 19 = 0x7_ffff_ffff_ffed
//   limbs 1..4 = 2^51 - 1 = 0x7_ffff_ffff_ffff
const P_LIMBS: [u64; LIMBS] = [
    0x7_ffff_ffff_ffed,
    0x7_ffff_ffff_ffff,
    0x7_ffff_ffff_ffff,
    0x7_ffff_ffff_ffff,
    0x7_ffff_ffff_ffff,
];

/// Field element modulo `p = 2^255 - 19`, stored in five limbs of radix 2^51.
///
/// Representation is "relaxed" — limbs may exceed 2^51 between operations as
/// long as the bound is respected by the next operation. `to_bytes`
/// canonicalises before serialising.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe([u64; LIMBS]);

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; LIMBS]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// A field element from limbs already in the radix-2^51 form, for the
    /// curve constants a caller states as limbs and checks against their
    /// definitions.
    pub(crate) const fn from_limbs(limbs: [u64; LIMBS]) -> Fe {
        Fe(limbs)
    }
}

#[inline(always)]
pub(crate) fn fe_add(a: &Fe, b: &Fe) -> Fe {
    Fe([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
    ])
}

#[inline(always)]
pub(crate) fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // Add 4*p to keep every limb non-negative without changing the residue.
    // 4*p = 2^257 - 76; per-limb: limb0 = 2^53 - 76, limbs 1..4 = 2^53 - 4.
    Fe([
        a.0[0] + 0x1f_ffff_ffff_ffb4 - b.0[0],
        a.0[1] + 0x1f_ffff_ffff_fffc - b.0[1],
        a.0[2] + 0x1f_ffff_ffff_fffc - b.0[2],
        a.0[3] + 0x1f_ffff_ffff_fffc - b.0[3],
        a.0[4] + 0x1f_ffff_ffff_fffc - b.0[4],
    ])
}

/// Schoolbook 5×5 limb multiply mod `p`, with two-pass carry reduction.
pub(crate) fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a.0[0] as u128;
    let a1 = a.0[1] as u128;
    let a2 = a.0[2] as u128;
    let a3 = a.0[3] as u128;
    let a4 = a.0[4] as u128;

    let b0 = b.0[0] as u128;
    let b1 = b.0[1] as u128;
    let b2 = b.0[2] as u128;
    let b3 = b.0[3] as u128;
    let b4 = b.0[4] as u128;

    // Pre-multiply the cross terms by 19 (= 2^255 wrap-around factor).
    let b1_19 = 19 * b1;
    let b2_19 = 19 * b2;
    let b3_19 = 19 * b3;
    let b4_19 = 19 * b4;

    let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    fe_carry_u128(r0, r1, r2, r3, r4)
}

#[inline(always)]
fn fe_carry_u128(mut r0: u128, mut r1: u128, mut r2: u128, mut r3: u128, mut r4: u128) -> Fe {
    let mask = (1u128 << 51) - 1;
    r1 += r0 >> 51;
    r0 &= mask;
    r2 += r1 >> 51;
    r1 &= mask;
    r3 += r2 >> 51;
    r2 &= mask;
    r4 += r3 >> 51;
    r3 &= mask;
    let carry = r4 >> 51;
    r4 &= mask;
    r0 += 19 * carry;
    r1 += r0 >> 51;
    r0 &= mask;
    Fe([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
}

#[inline(always)]
pub(crate) fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

pub(crate) fn fe_pow2k(a: &Fe, k: u32) -> Fe {
    let mut t = *a;
    for _ in 0..k {
        t = fe_sq(&t);
    }
    t
}

/// Little-endian bytes of the public exponent `p - 2 = 2^255 - 21`.
///
/// `2^255 - 21 = (2^255 - 1) - 20`. `2^255 - 1` is 255 one bits, and
/// `20 = 0b1_0100` only clears bits 2 and 4 of its all-ones low byte, with no
/// borrow: `0xff - 0x14 = 0xeb`. Bytes 1..=30 stay `0xff`; bit 255 is clear, so
/// the top byte is `0x7f`.
const P_MINUS_2_LE: [u8; FE_BYTES] = {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xeb;
    bytes[31] = 0x7f;
    bytes
};

/// `base^exponent` for a public little-endian `exponent`, in constant time
/// with respect to `base`.
///
/// Fixed 4-bit windows, most significant first. Every window costs exactly
/// four squarings and one multiplication by `base^digit` from a table, and the
/// table index is a digit of the public exponent, so neither the operation
/// sequence nor the memory access pattern depends on `base`. A zero digit
/// still multiplies (by `base^0 = 1`), which keeps the sequence uniform.
fn fe_pow_public(base: &Fe, exponent: &[u8; FE_BYTES]) -> Fe {
    // powers[d] = base^d for each 4-bit digit d.
    let mut powers = [Fe::ONE; 16];
    for d in 1..powers.len() {
        powers[d] = fe_mul(&powers[d - 1], base);
    }

    let mut acc = Fe::ONE;
    for byte in exponent.iter().rev() {
        for digit in [byte >> 4, byte & 0x0f] {
            acc = fe_pow2k(&acc, 4);
            acc = fe_mul(&acc, &powers[usize::from(digit)]);
        }
    }

    for power in &mut powers {
        zeroize_slice(&mut power.0);
    }
    acc
}

/// Compute `z^(p-2) = z^(2^255 - 21)` (modular inverse for nonzero z).
///
/// RFC 7748 §5 ends the ladder with `x_2 * (z_2^(p - 2))`. By Fermat's little
/// theorem `z^(p-2) = z^-1` for nonzero `z`; zero maps to zero.
pub(crate) fn fe_invert(z: &Fe) -> Fe {
    fe_pow_public(z, &P_MINUS_2_LE)
}

/// Constant-time conditional swap: if `swap == 1`, swap `a` and `b`; if `0`,
/// no change. Touches every limb regardless of `swap`.
#[inline(always)]
pub(crate) fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..LIMBS {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Decode 32 LE bytes into a field element. Per RFC 7748 §5, the high bit of
/// the most-significant byte is masked off first.
pub(crate) fn fe_from_bytes(bytes: &[u8; FE_BYTES]) -> Fe {
    let mut buf = *bytes;
    buf[31] &= 0x7f;
    let load = |off: usize| -> u64 {
        let mut x = [0u8; 8];
        x.copy_from_slice(&buf[off..off + 8]);
        u64::from_le_bytes(x)
    };
    Fe([
        load(0) & MASK51,
        (load(6) >> 3) & MASK51,
        (load(12) >> 6) & MASK51,
        (load(19) >> 1) & MASK51,
        (load(24) >> 12) & MASK51,
    ])
}

/// Encode a field element into 32 LE bytes, fully canonicalised mod `p`.
///
/// The conditional subtraction of `p` is mask-driven, and the mask goes
/// through [`crate::ct::select_u64`]: written as a plain select, the compiler
/// emitted a conditional branch on the borrow, which is a branch on the value
/// being encoded.
pub(crate) fn fe_to_bytes(a: &Fe) -> [u8; FE_BYTES] {
    let mut t = a.0;
    // Two carry passes bring t into [0, 2*p).
    for _ in 0..2 {
        let c = t[0] >> 51;
        t[0] &= MASK51;
        t[1] += c;
        let c = t[1] >> 51;
        t[1] &= MASK51;
        t[2] += c;
        let c = t[2] >> 51;
        t[2] &= MASK51;
        t[3] += c;
        let c = t[3] >> 51;
        t[3] &= MASK51;
        t[4] += c;
        let c = t[4] >> 51;
        t[4] &= MASK51;
        t[0] += 19 * c;
    }
    // After two passes each limb is < 2^52 and t < 2*p.
    // Conditionally subtract p: compute t - p using wrapping arithmetic and
    // borrow propagation. If t < p (borrow=1), keep t; else use t - p.
    let mut s = [0u64; 5];
    let mut borrow: u64 = 0;
    for i in 0..LIMBS {
        let diff = t[i].wrapping_sub(P_LIMBS[i]).wrapping_sub(borrow);
        s[i] = diff & MASK51;
        // Bit 63 of `diff` is set iff t[i] < P_LIMBS[i] + borrow (wraparound).
        // Inputs are < 2^52, P_LIMBS[i] < 2^51, borrow ∈ {0,1}, so the only
        // way bit 63 ends up set is via underflow.
        borrow = (diff >> 63) & 1;
    }
    let select_t = 0u64.wrapping_sub(borrow);
    let mut out = [0u64; LIMBS];
    for i in 0..LIMBS {
        out[i] = crate::ct::select_u64(select_t, t[i], s[i]);
    }

    // Pack five 51-bit limbs into 32 LE bytes.
    let mut bytes = [0u8; FE_BYTES];
    bytes[0] = out[0] as u8;
    bytes[1] = (out[0] >> 8) as u8;
    bytes[2] = (out[0] >> 16) as u8;
    bytes[3] = (out[0] >> 24) as u8;
    bytes[4] = (out[0] >> 32) as u8;
    bytes[5] = (out[0] >> 40) as u8;
    bytes[6] = ((out[0] >> 48) | (out[1] << 3)) as u8;
    bytes[7] = (out[1] >> 5) as u8;
    bytes[8] = (out[1] >> 13) as u8;
    bytes[9] = (out[1] >> 21) as u8;
    bytes[10] = (out[1] >> 29) as u8;
    bytes[11] = (out[1] >> 37) as u8;
    bytes[12] = ((out[1] >> 45) | (out[2] << 6)) as u8;
    bytes[13] = (out[2] >> 2) as u8;
    bytes[14] = (out[2] >> 10) as u8;
    bytes[15] = (out[2] >> 18) as u8;
    bytes[16] = (out[2] >> 26) as u8;
    bytes[17] = (out[2] >> 34) as u8;
    bytes[18] = (out[2] >> 42) as u8;
    bytes[19] = ((out[2] >> 50) | (out[3] << 1)) as u8;
    bytes[20] = (out[3] >> 7) as u8;
    bytes[21] = (out[3] >> 15) as u8;
    bytes[22] = (out[3] >> 23) as u8;
    bytes[23] = (out[3] >> 31) as u8;
    bytes[24] = (out[3] >> 39) as u8;
    bytes[25] = ((out[3] >> 47) | (out[4] << 4)) as u8;
    bytes[26] = (out[4] >> 4) as u8;
    bytes[27] = (out[4] >> 12) as u8;
    bytes[28] = (out[4] >> 20) as u8;
    bytes[29] = (out[4] >> 28) as u8;
    bytes[30] = (out[4] >> 36) as u8;
    bytes[31] = (out[4] >> 44) as u8;
    // `t`, `s`, and `out` hold the encoded value in limb form; called from
    // the ladder, that value is the shared secret.
    zeroize_slice(&mut t[..]);
    zeroize_slice(&mut s[..]);
    zeroize_slice(&mut out[..]);
    bytes
}

/// Multiply by a small constant that fits in a limb, such as the ladder's
/// `(A + 2)/4` or a curve coefficient.
#[inline]
pub(crate) fn fe_mul_small(a: &Fe, k: u64) -> Fe {
    let k = u128::from(k);
    fe_carry_u128(
        u128::from(a.0[0]) * k,
        u128::from(a.0[1]) * k,
        u128::from(a.0[2]) * k,
        u128::from(a.0[3]) * k,
        u128::from(a.0[4]) * k,
    )
}

/// Wipe a field element that held a secret.
#[inline]
pub(crate) fn fe_zeroize(a: &mut Fe) {
    zeroize_slice(&mut a.0);
}

/// `-a`, as `0 - a`. Only the tests need it: the Edwards arithmetic reaches
/// negation through subtraction from zero directly.
#[cfg(test)]
#[inline(always)]
pub(crate) fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&Fe::ZERO, a)
}

/// Constant-time conditional move: `a` becomes `b` when `flag` is 1 and is
/// unchanged when it is 0. Every limb is written either way.
#[inline(always)]
pub(crate) fn fe_cmov(a: &mut Fe, b: &Fe, flag: u64) {
    let mask = 0u64.wrapping_sub(flag);
    for i in 0..LIMBS {
        a.0[i] = crate::ct::select_u64(mask, b.0[i], a.0[i]);
    }
}

/// The sign bit RFC 8032 §5.1.2 encodes: the least significant bit of the
/// canonical encoding.
#[inline]
pub(crate) fn fe_is_negative(a: &Fe) -> u64 {
    let mut bytes = fe_to_bytes(a);
    let bit = u64::from(bytes[0] & 1);
    zeroize_slice(bytes.as_mut_slice());
    bit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decode_hex_array;

    /// Sanity: bytes -> Fe -> bytes round-trips for canonical inputs.
    #[test]
    fn fe_bytes_roundtrip() {
        let bytes = decode_hex_array::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        );
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe.0, [1, 0, 0, 0, 0]);
        assert_eq!(fe_to_bytes(&fe), bytes);

        let bytes = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe.0, [9, 0, 0, 0, 0]);
        assert_eq!(fe_to_bytes(&fe), bytes);
    }

    /// Sanity: fe_mul(1, x) == x (canonical).
    #[test]
    fn fe_mul_by_one_is_identity() {
        let x = fe_from_bytes(&decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        ));
        let out = fe_mul(&Fe::ONE, &x);
        assert_eq!(fe_to_bytes(&out), fe_to_bytes(&x));
    }

    /// Sanity: fe_mul(2, fe_invert(2)) == 1.
    #[test]
    fn fe_invert_simple() {
        let two = Fe([2, 0, 0, 0, 0]);
        let inv = fe_invert(&two);
        let prod = fe_mul(&two, &inv);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(fe_to_bytes(&prod), one);
    }

    /// The four conditional and predicate forms, on values that exercise both
    /// answers: a move that does and does not happen, the sign bit of an odd
    /// and an even element, and zero against non-zero.
    #[test]
    fn conditional_and_predicate_forms_answer_both_ways() {
        let one = Fe::ONE;
        let two = fe_add(&Fe::ONE, &Fe::ONE);

        let mut a = one;
        fe_cmov(&mut a, &two, 0);
        assert_eq!(fe_to_bytes(&a), fe_to_bytes(&one), "a move with flag 0");
        fe_cmov(&mut a, &two, 1);
        assert_eq!(fe_to_bytes(&a), fe_to_bytes(&two), "a move with flag 1");

        assert_eq!(fe_is_negative(&one), 1, "1 is odd");
        assert_eq!(fe_is_negative(&two), 0, "2 is even");

        // Negation is the additive inverse, and zero encodes as zero.
        let zero = fe_to_bytes(&Fe::ZERO);
        assert_eq!(fe_to_bytes(&fe_add(&two, &fe_neg(&two))), zero);
        assert_eq!(fe_to_bytes(&fe_sub(&Fe::ZERO, &Fe::ZERO)), zero);
    }

    /// Multiplying by a small constant agrees with multiplying by the field
    /// element that constant encodes.
    #[test]
    fn small_multiply_agrees_with_the_general_one() {
        let x = fe_from_bytes(&decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        ));
        for k in [1u64, 2, 121_665, 0xffff_ffff] {
            let mut limbs = [0u64; LIMBS];
            limbs[0] = k & ((1 << 51) - 1);
            limbs[1] = k >> 51;
            let general = fe_mul(&x, &Fe(limbs));
            assert_eq!(
                fe_to_bytes(&fe_mul_small(&x, k)),
                fe_to_bytes(&general),
                "k = {k}"
            );
        }
    }
}
