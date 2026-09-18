//! edwards25519 in extended coordinates, constant time in the scalar.
//!
//! RFC 8032 §5.1 signs with two multiplications of the base point: the public
//! key `A = a·B` and the commitment `R = r·B`. Both scalars are secret, and
//! `r` is the one a signature can least afford to leak, since partial
//! knowledge of many nonces recovers the private key by lattice reduction. So
//! this module does what [`super::x25519`] does for the ladder: a fixed
//! number of operations, no branch on the scalar, and no memory index derived
//! from it.
//!
//! The multiplication is a fixed-base comb. The scalar's 64 nibbles each
//! select one entry from that position's table of sixteen precomputed
//! multiples, and the selection reads every entry under a mask. A point is
//! carried as `(X : Y : Z : T)` with `x = X/Z`, `y = Y/Z` and `xy = T/Z`,
//! where the addition and doubling of Hisil, Wong, Carter and Dawson are
//! complete for this curve: `a = -1` and `d` is not a square, so no input
//! reaches a special case that would need a branch.
//!
//! Verification is not here. It works on public data, where the generic
//! variable-time arithmetic of [`super::ec_edwards`] is the right tool.

use super::fe25519::{
    fe_add, fe_cmov, fe_invert, fe_is_negative, fe_mul, fe_sq, fe_sub, fe_to_bytes, fe_zeroize, Fe,
    FE_BYTES,
};
use std::sync::OnceLock;

/// `2d`, where `d = -121665/121666 mod p` is the curve constant of RFC 8032
/// §5.1, in the field's five 51-bit limbs. The addition below needs only this
/// multiple; the tests recompute it from that definition.
const D2: Fe = Fe::from_limbs([
    0x0006_9b94_26b2_f159,
    0x0003_5050_762a_dd7a,
    0x0003_cf44_c003_8052,
    0x0006_738c_c740_7977,
    0x0002_406d_9dc5_6dff,
]);

/// The base point `B` of RFC 8032 §5.1: the point with `y = 4/5` whose `x` is
/// even. The tests recompute it from that definition.
const BASE_X: Fe = Fe::from_limbs([
    0x0006_2d60_8f25_d51a,
    0x0004_12a4_b4f6_592a,
    0x0007_5b71_71a4_b31d,
    0x0001_ff60_5271_18fe,
    0x0002_1693_6d3c_d6e5,
]);
const BASE_Y: Fe = Fe::from_limbs([
    0x0006_6666_6666_6658,
    0x0004_cccc_cccc_cccc,
    0x0001_9999_9999_9999,
    0x0003_3333_3333_3333,
    0x0006_6666_6666_6666,
]);

/// The comb's shape: a scalar is 256 bits, read four bits at a time, so there
/// are 64 positions and each holds the sixteen multiples a nibble can select.
const COMB_BITS: usize = 4;
const COMB_POSITIONS: usize = FE_BYTES * 8 / COMB_BITS;
const COMB_ENTRIES: usize = 1 << COMB_BITS;

/// A point as `(X : Y : Z : T)`, with `x = X/Z`, `y = Y/Z` and `xy = T/Z`.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    /// The neutral element `(0 : 1 : 1 : 0)`.
    const NEUTRAL: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    const BASE: Point = Point {
        x: BASE_X,
        y: BASE_Y,
        z: Fe::ONE,
        // T = XY/Z, which is XY here since Z = 1. Computed in `base_point`
        // rather than written out, so the limbs above are the only curve
        // constants this module carries.
        t: Fe::ZERO,
    };

    /// Wipe a point that held a secret multiple.
    fn zeroize(&mut self) {
        fe_zeroize(&mut self.x);
        fe_zeroize(&mut self.y);
        fe_zeroize(&mut self.z);
        fe_zeroize(&mut self.t);
    }
}

/// `B` with its `T` coordinate filled in.
fn base_point() -> Point {
    Point {
        t: fe_mul(&BASE_X, &BASE_Y),
        ..Point::BASE
    }
}

/// The addition of Hisil, Wong, Carter and Dawson for `a = -1`, which is
/// complete on this curve: every pair of points, equal or not, neutral or not,
/// takes this one sequence.
fn add(p: &Point, q: &Point) -> Point {
    let a = fe_mul(&fe_sub(&p.y, &p.x), &fe_sub(&q.y, &q.x));
    let b = fe_mul(&fe_add(&p.y, &p.x), &fe_add(&q.y, &q.x));
    let c = fe_mul(&fe_mul(&p.t, &D2), &q.t);
    let d = fe_add(&fe_mul(&p.z, &q.z), &fe_mul(&p.z, &q.z));
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    Point {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// Doubling, the same authors' formula for `a = -1`.
fn double(p: &Point) -> Point {
    let a = fe_sq(&p.x);
    let b = fe_sq(&p.y);
    let z2 = fe_sq(&p.z);
    let c = fe_add(&z2, &z2);
    let h = fe_add(&a, &b);
    let e = fe_sub(&h, &fe_sq(&fe_add(&p.x, &p.y)));
    let g = fe_sub(&a, &b);
    let f = fe_add(&c, &g);
    Point {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// Constant-time conditional move between two points.
fn cmov(p: &mut Point, q: &Point, flag: u64) {
    fe_cmov(&mut p.x, &q.x, flag);
    fe_cmov(&mut p.y, &q.y, flag);
    fe_cmov(&mut p.z, &q.z, flag);
    fe_cmov(&mut p.t, &q.t, flag);
}

/// The comb table: for each of the 64 nibble positions, the sixteen multiples
/// `j · 2^(4·position) · B` that a nibble can select.
///
/// It is built once, from public data, so the building may take whatever time
/// it takes. Only the reading of it has to be constant time.
type Comb = Vec<[Point; COMB_ENTRIES]>;

fn comb() -> &'static Comb {
    static TABLE: OnceLock<Comb> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: Comb = Vec::with_capacity(COMB_POSITIONS);
        let mut position_base = base_point();
        for _ in 0..COMB_POSITIONS {
            let mut entries = [Point::NEUTRAL; COMB_ENTRIES];
            for entry in 1..COMB_ENTRIES {
                entries[entry] = add(&entries[entry - 1], &position_base);
            }
            table.push(entries);
            // The next position's base is this one's shifted by four bits.
            for _ in 0..COMB_BITS {
                position_base = double(&position_base);
            }
        }
        table
    })
}

/// `scalar · B`, in a fixed number of operations, reading every table entry of
/// every position under a mask.
///
/// The scalar is taken little-endian, as RFC 8032 takes it, and is not
/// reduced here: the callers pass `a` after clamping and `r` after reduction
/// modulo `L`.
pub(crate) fn scalar_mul_base(scalar: &[u8; FE_BYTES]) -> Point {
    let table = comb();
    let mut acc = Point::NEUTRAL;
    for position in 0..COMB_POSITIONS {
        let byte = scalar[position / 2];
        // The nibble this position consumes: low then high within each byte,
        // which matches the little-endian scalar.
        let shift = 4 * (position % 2) as u32;
        let digit = u64::from((byte >> shift) & 0x0f);

        let mut chosen = Point::NEUTRAL;
        for (entry, point) in table[position].iter().enumerate() {
            // 1 exactly when this entry is the one the digit names, without a
            // branch and without an index derived from the digit.
            let matches = ((entry as u64 ^ digit).wrapping_sub(1)) >> 63;
            cmov(&mut chosen, point, matches);
        }
        acc = add(&acc, &chosen);
        chosen.zeroize();
    }
    acc
}

/// The affine coordinates `(x, y) = (X/Z, Y/Z)`, each canonically encoded
/// little-endian.
///
/// A caller that needs both the encoding and the coordinates takes them from
/// here, rather than encoding and decoding again: decoding recovers `x` with a
/// square root, and the time that takes depends on the point, which for `R` is
/// a function of the nonce.
pub(crate) fn affine(p: &Point) -> ([u8; FE_BYTES], [u8; FE_BYTES]) {
    let z_inverse = fe_invert(&p.z);
    let mut x = fe_mul(&p.x, &z_inverse);
    let mut y = fe_mul(&p.y, &z_inverse);
    let out = (fe_to_bytes(&x), fe_to_bytes(&y));
    fe_zeroize(&mut x);
    fe_zeroize(&mut y);
    out
}

/// The encoding of RFC 8032 §5.1.2: the 255-bit `y`, with the low bit of `x`
/// in the top bit.
pub(crate) fn compress(p: &Point) -> [u8; FE_BYTES] {
    let z_inverse = fe_invert(&p.z);
    let mut x = fe_mul(&p.x, &z_inverse);
    let mut y = fe_mul(&p.y, &z_inverse);
    let mut out = fe_to_bytes(&y);
    out[FE_BYTES - 1] |= (fe_is_negative(&x) as u8) << 7;
    fe_zeroize(&mut x);
    fe_zeroize(&mut y);
    out
}

/// `-p`, which negating `x` and `t` gives.
#[cfg(test)]
fn negate(p: &Point) -> Point {
    use super::fe25519::fe_neg;
    Point {
        x: fe_neg(&p.x),
        y: p.y,
        z: p.z,
        t: fe_neg(&p.t),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fe25519::fe_neg;
    use super::*;
    use crate::public_key::ec_edwards::ed25519;
    use crate::test_utils::decode_hex_array;
    use crate::vt::BigUint;

    /// The curve constants are what their definitions say: `d` is
    /// `-121665/121666`, `2d` is twice it, and the base point is the `y = 4/5`
    /// point of even `x`, on the curve.
    #[test]
    fn the_curve_constants_come_from_their_definitions() {
        let small = |v: u64| {
            let mut bytes = [0u8; FE_BYTES];
            bytes[..8].copy_from_slice(&v.to_le_bytes());
            super::super::fe25519::fe_from_bytes(&bytes)
        };
        let derived_d = fe_mul(&fe_neg(&small(121_665)), &fe_invert(&small(121_666)));
        assert_eq!(
            fe_to_bytes(&fe_add(&derived_d, &derived_d)),
            fe_to_bytes(&D2),
            "2d"
        );

        let derived_y = fe_mul(&small(4), &fe_invert(&small(5)));
        assert_eq!(fe_to_bytes(&derived_y), fe_to_bytes(&BASE_Y), "By");
        assert_eq!(fe_is_negative(&BASE_X), 0, "Bx is the even root");

        // -x² + y² = 1 + d·x²·y² on the curve.
        let x2 = fe_sq(&BASE_X);
        let y2 = fe_sq(&BASE_Y);
        let left = fe_sub(&y2, &x2);
        let right = fe_add(&Fe::ONE, &fe_mul(&derived_d, &fe_mul(&x2, &y2)));
        assert_eq!(fe_to_bytes(&left), fe_to_bytes(&right), "B is on the curve");
    }

    /// The group laws hold: the neutral element is neutral, addition is
    /// commutative, doubling agrees with adding a point to itself, and a point
    /// plus its negation is the neutral element.
    #[test]
    fn the_group_laws_hold() {
        let b = base_point();
        let b2 = double(&b);
        let b3 = add(&b2, &b);

        assert_eq!(compress(&add(&b, &Point::NEUTRAL)), compress(&b));
        assert_eq!(compress(&add(&b, &b)), compress(&b2), "2B two ways");
        assert_eq!(compress(&add(&b, &b2)), compress(&b3), "commutes");
        assert_eq!(compress(&add(&b2, &b)), compress(&b3), "commutes");
        assert_eq!(
            compress(&add(&b, &negate(&b))),
            compress(&Point::NEUTRAL),
            "B - B"
        );
        assert_eq!(
            compress(&double(&Point::NEUTRAL)),
            compress(&Point::NEUTRAL)
        );
    }

    /// The comb agrees with the crate's generic Edwards arithmetic, which is
    /// independently written and checked against RFC 8032's vectors, on the
    /// small scalars and on scalars with structure the comb might mishandle:
    /// zero, one, a single set bit in every nibble position, and all ones.
    #[test]
    fn the_comb_agrees_with_the_generic_arithmetic() {
        let curve = ed25519();
        let check = |scalar: [u8; FE_BYTES], what: &str| {
            let mine = compress(&scalar_mul_base(&scalar));
            let mut be = scalar;
            be.reverse();
            let theirs = curve.encode_point(&curve.scalar_mul_base(&BigUint::from_be_bytes(&be)));
            assert_eq!(mine.to_vec(), theirs, "{what}");
        };

        check([0u8; FE_BYTES], "zero");
        let mut one = [0u8; FE_BYTES];
        one[0] = 1;
        check(one, "one");
        check([0xff; FE_BYTES], "every bit set");

        for position in 0..COMB_POSITIONS {
            let mut scalar = [0u8; FE_BYTES];
            scalar[position / 2] = 1 << (4 * (position % 2));
            check(scalar, &format!("the low bit of nibble {position}"));
        }

        for seed in [1u8, 7, 0x5a, 0xa5, 0xfe] {
            let mut scalar = [0u8; FE_BYTES];
            for (index, byte) in scalar.iter_mut().enumerate() {
                *byte = seed.wrapping_mul(index as u8).wrapping_add(seed);
            }
            check(scalar, "a pseudorandom scalar");
        }
    }

    /// RFC 8032 §7.1's first public key, straight from its secret scalar: the
    /// seed's SHA-512 digest, clamped, times the base point.
    #[test]
    fn rfc8032_first_public_key() {
        let seed: [u8; 32] =
            decode_hex_array("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let mut digest = crate::Sha512::digest(&seed);
        digest[0] &= 248;
        digest[31] &= 127;
        digest[31] |= 64;
        let mut scalar = [0u8; FE_BYTES];
        scalar.copy_from_slice(&digest[..32]);
        assert_eq!(
            compress(&scalar_mul_base(&scalar)).to_vec(),
            decode_hex_array::<32>(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            )
            .to_vec()
        );
    }
}
