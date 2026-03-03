//! Arithmetic in binary extension fields GF(2^m).
//!
//! Elements of GF(2^m) are represented as [`BigUint`] values whose bit
//! pattern encodes a polynomial over GF(2): bit `i` set means the coefficient
//! of `x^i` is 1.  The field modulus is an irreducible polynomial of degree
//! `m` over GF(2), also stored as a `BigUint` with the same bit-pattern
//! convention.
//!
//! All arithmetic here is used exclusively by the binary-curve point
//! arithmetic in [`ec`](crate::public_key::ec); it is not part of the public
//! API of the crate.
//!
//! ## Algorithm notes
//!
//! - **Addition** is XOR (no modular reduction needed: XOR of two polynomials
//!   of degree < m has degree < m).
//! - **Multiplication** uses a schoolbook shift-and-XOR loop followed by
//!   polynomial reduction modulo the irreducible polynomial.
//! - **Inversion** uses the binary extended GCD for polynomials over GF(2)
//!   (Algorithm 2.22 of Hankerson, Menezes, Vanstone — *Guide to ECC*).
//! - **Half-trace** computes HT(c) = Σ c^{2^{2i}} (i = 0...(m−1)/2), which
//!   is a root of z² + z = c for any c in GF(2^m) with Tr(c) = 0.  This
//!   solves the quadratic needed for compressed-point decompression on curves
//!   with odd m.

use crate::public_key::bigint::BigUint;

// ─── Public(crate) interface ─────────────────────────────────────────────────

/// Add two GF(2^m) elements: XOR with no reduction needed.
#[inline]
pub(crate) fn gf2m_add(a: &BigUint, b: &BigUint) -> BigUint {
    let mut out = a.clone();
    out.bitxor_assign(b);
    out
}

/// Multiply two GF(2^m) elements modulo the irreducible polynomial `poly`.
///
/// Uses a shift-and-XOR loop: for each set bit `i` of `b`, XOR `a << i` into
/// an accumulator, then reduce the accumulator modulo `poly`.
pub(crate) fn gf2m_mul(a: &BigUint, b: &BigUint, poly: &BigUint, degree: usize) -> BigUint {
    if a.is_zero() || b.is_zero() {
        return BigUint::zero();
    }

    let mut acc = BigUint::zero();
    let mut temp = a.clone();
    let b_bits = b.bits();

    for i in 0..b_bits {
        if b.bit(i) {
            acc.bitxor_assign(&temp);
        }
        temp.shl1();
    }

    gf2m_reduce(acc, poly, degree)
}

/// Square an element in GF(2^m).
#[inline]
pub(crate) fn gf2m_sq(a: &BigUint, poly: &BigUint, degree: usize) -> BigUint {
    gf2m_mul(a, a, poly, degree)
}

/// Invert an element in GF(2^m) via the binary extended GCD algorithm.
///
/// Returns `None` only if `a` is zero (not invertible).
///
/// Algorithm 2.22 from Hankerson, Menezes, Vanstone — *Guide to ECC*.
/// Invariant during the loop: `b ≡ u · a (mod poly)` in the sense that
/// `b` and `u` are updated in lockstep so that `b = u · a XOR s · poly`
/// for some polynomial `s` we do not track.
pub(crate) fn gf2m_inv(a: &BigUint, poly: &BigUint, degree: usize) -> Option<BigUint> {
    if a.is_zero() {
        return None;
    }

    let mut u = a.clone();
    let mut v = poly.clone();
    let mut b = BigUint::one();
    let mut c = BigUint::zero();

    // Loop until u = 1 (degree 0 polynomial over GF(2)).
    while !u.is_one() {
        // How many bits separate the leading terms of u and v?
        let deg_u = u.bits(); // deg(u) + 1
        let deg_v = v.bits(); // deg(v) + 1

        // Ensure deg(u) >= deg(v) by swapping if necessary.
        if deg_u < deg_v {
            core::mem::swap(&mut u, &mut v);
            core::mem::swap(&mut b, &mut c);
        }

        // j = deg(u) - deg(v), guaranteed >= 0 after the potential swap.
        // Use saturating_sub defensively (logically it's always exact here).
        let j = u.bits().saturating_sub(v.bits());

        // u = u XOR (v * x^j);  b = b XOR (c * x^j).
        let mut sv = v.clone();
        sv.shl_bits(j);
        u.bitxor_assign(&sv);

        let mut sc = c.clone();
        sc.shl_bits(j);
        b.bitxor_assign(&sc);
    }

    // u is now 1; b satisfies b · a ≡ 1 (mod poly), possibly with degree ≥ m.
    Some(gf2m_reduce(b, poly, degree))
}

/// Compute the half-trace HT(c) = Σ_{i=0}^{(m−1)/2} c^{2^{2i}} in GF(2^m).
///
/// For any `c` with absolute trace Tr(c) = 0 (which holds for all valid
/// x-coordinates on FIPS binary curves), `z = HT(c)` solves `z² + z = c`.
/// Used for compressed-point decompression.
///
/// `degree` must be odd (all FIPS 186-4 binary curve degrees are odd).
pub(crate) fn gf2m_half_trace(c: &BigUint, poly: &BigUint, degree: usize) -> BigUint {
    // HT(c) = c^{2^0} + c^{2^2} + c^{2^4} + ... + c^{2^{degree-1}}
    // Starting from power = c, square twice per iteration to advance by 2
    // exponent steps: c → c^4 → c^{16} → ...
    let mut t = c.clone(); // accumulator starts at c^{2^0}
    let mut power = c.clone(); // current term

    for _ in 0..(degree - 1) / 2 {
        // Advance power from c^{2^{2i}} to c^{2^{2(i+1)}} = c^{2^{2i+2}}.
        power = gf2m_sq(&gf2m_sq(&power, poly, degree), poly, degree);
        t.bitxor_assign(&power);
    }

    t
}

// ─── Private helper ──────────────────────────────────────────────────────────

/// Reduce `a` modulo `poly` (an irreducible polynomial of degree `degree`).
///
/// Scans from the highest set bit of `a` down to `degree`, and for each set
/// bit at position `i ≥ degree`, XORs in `poly << (i − degree)`.  The leading
/// bit of `poly << (i − degree)` is `i`, which clears bit `i`; the remaining
/// bits of the shifted polynomial are all at positions `< i`, so the scan
/// remains valid as it continues downward.
fn gf2m_reduce(mut a: BigUint, poly: &BigUint, degree: usize) -> BigUint {
    let mut current_bits = a.bits();
    while current_bits > degree {
        let i = current_bits - 1; // position of the highest set bit
        let shift = i - degree;
        let mut shifted = poly.clone();
        shifted.shl_bits(shift);
        a.bitxor_assign(&shifted);
        current_bits = a.bits();
    }
    a
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // GF(2^163) irreducible polynomial: x^163 + x^7 + x^6 + x^3 + 1
    fn poly163() -> BigUint {
        let mut p = BigUint::zero();
        p.set_bit(163);
        p.set_bit(7);
        p.set_bit(6);
        p.set_bit(3);
        p.set_bit(0);
        p
    }

    #[test]
    fn gf2m_add_xor() {
        let a = BigUint::from_u64(0b1010);
        let b = BigUint::from_u64(0b1100);
        let c = gf2m_add(&a, &b);
        assert_eq!(c, BigUint::from_u64(0b0110));
    }

    #[test]
    fn gf2m_add_self_is_zero() {
        let a = BigUint::from_u64(0xDEAD_BEEF);
        let c = gf2m_add(&a, &a);
        assert!(c.is_zero(), "a XOR a must be zero");
    }

    #[test]
    fn gf2m_mul_small() {
        // GF(2^4) with poly = x^4 + x + 1 = 0b10011
        let poly = BigUint::from_u64(0b10011);
        // (x^2 + 1) * (x + 1) = x^3 + x^2 + x + 1 = 0b1111
        let a = BigUint::from_u64(0b0101);
        let b = BigUint::from_u64(0b0011);
        let c = gf2m_mul(&a, &b, &poly, 4);
        assert_eq!(c, BigUint::from_u64(0b1111));
    }

    #[test]
    fn gf2m_mul_reduce() {
        // GF(2^4) with poly = x^4 + x + 1.
        // x^3 * x = x^4 = x + 1 = 0b0011 (since x^4 ≡ x + 1 mod poly).
        let poly = BigUint::from_u64(0b10011);
        let a = BigUint::from_u64(0b1000); // x^3
        let b = BigUint::from_u64(0b0010); // x
        let c = gf2m_mul(&a, &b, &poly, 4);
        assert_eq!(c, BigUint::from_u64(0b0011), "x^3 * x = x + 1 in GF(2^4)");
    }

    #[test]
    fn gf2m_sq_equals_mul_self() {
        let poly = poly163();
        let a = BigUint::from_u64(0xABCD_1234);
        let sq = gf2m_sq(&a, &poly, 163);
        let mul = gf2m_mul(&a, &a, &poly, 163);
        assert_eq!(sq, mul, "sq must equal mul(a, a)");
    }

    #[test]
    fn gf2m_inv_roundtrip_gf163() {
        let poly = poly163();
        let a = BigUint::from_u64(0x1234_5678_9ABC_DEF0);
        let a_inv = gf2m_inv(&a, &poly, 163).expect("a is non-zero, must be invertible");
        let product = gf2m_mul(&a, &a_inv, &poly, 163);
        assert_eq!(product, BigUint::one(), "a * a^{{-1}} must be 1 in GF(2^163)");
    }

    #[test]
    fn gf2m_inv_of_one_is_one() {
        let poly = poly163();
        let one_inv = gf2m_inv(&BigUint::one(), &poly, 163).expect("1 is invertible");
        assert_eq!(one_inv, BigUint::one());
    }

    #[test]
    fn gf2m_inv_zero_returns_none() {
        let poly = poly163();
        assert!(gf2m_inv(&BigUint::zero(), &poly, 163).is_none());
    }

    #[test]
    fn gf2m_half_trace_solves_quadratic() {
        // For GF(2^163), verify HT(c)^2 + HT(c) = c for a fixed c with Tr(c) = 0.
        // We use a known element: c = generator element 2 (x polynomial element).
        // Note: Tr(x) in GF(2^163) is 0 (this is a fact about GF(2^163)).
        let poly = poly163();
        let c = BigUint::from_u64(2); // polynomial x
        let z = gf2m_half_trace(&c, &poly, 163);
        // Verify z^2 + z = c
        let z_sq = gf2m_sq(&z, &poly, 163);
        let check = gf2m_add(&z_sq, &z);
        assert_eq!(check, c, "HT(c)^2 + HT(c) must equal c");
    }

    #[test]
    fn gf2m_mul_associative() {
        let poly = poly163();
        let a = BigUint::from_u64(0x1111_2222);
        let b = BigUint::from_u64(0x3333_4444);
        let c = BigUint::from_u64(0x5555_6666);
        let ab_c = gf2m_mul(&gf2m_mul(&a, &b, &poly, 163), &c, &poly, 163);
        let a_bc = gf2m_mul(&a, &gf2m_mul(&b, &c, &poly, 163), &poly, 163);
        assert_eq!(ab_c, a_bc, "multiplication must be associative");
    }

    #[test]
    fn gf2m_mul_distributive() {
        let poly = poly163();
        let a = BigUint::from_u64(0xABCD);
        let b = BigUint::from_u64(0x1234);
        let c = BigUint::from_u64(0x5678);
        let a_bc = gf2m_mul(&a, &gf2m_add(&b, &c), &poly, 163);
        let ab_ac = gf2m_add(&gf2m_mul(&a, &b, &poly, 163), &gf2m_mul(&a, &c, &poly, 163));
        assert_eq!(a_bc, ab_ac, "multiplication must distribute over addition");
    }
}
