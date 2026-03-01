//! Primality and modular-arithmetic helpers for the public-key layer.
//!
//! These routines mirror the structure of the teaching-oriented Python code:
//! repeated-squaring modular exponentiation plus Miller-Rabin with a fixed
//! witness set. The fixed bases keep the implementation deterministic and easy
//! to test while we are still in the pure-Rust, dependency-free foundation.

use super::bigint::{BigInt, BigUint};

const SMALL_PRIMES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

/// Greatest common divisor by Euclid's algorithm.
#[must_use]
pub fn gcd(lhs: &BigUint, rhs: &BigUint) -> BigUint {
    let mut current = lhs.clone();
    let mut next = rhs.clone();
    while !next.is_zero() {
        let remainder = current.modulo(&next);
        current = next;
        next = remainder;
    }
    current
}

/// Least common multiple.
///
/// This is the Carmichael-function building block used by the RSA code: the
/// Python reference chooses `lambda = lcm(p - 1, q - 1)` rather than Euler's
/// totient because the private exponent only needs to invert modulo the
/// exponent cycle length.
#[must_use]
pub fn lcm(lhs: &BigUint, rhs: &BigUint) -> BigUint {
    if lhs.is_zero() || rhs.is_zero() {
        return BigUint::zero();
    }

    let divisor = gcd(lhs, rhs);
    let (quotient, remainder) = lhs.div_rem(&divisor);
    debug_assert!(remainder.is_zero(), "gcd divides the left operand exactly");
    quotient.mul_ref(rhs)
}

/// `base^exponent mod modulus` by repeated squaring.
///
/// # Panics
///
/// Panics if `modulus == 0`.
#[must_use]
pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    assert!(!modulus.is_zero(), "modulus must be non-zero");
    if modulus == &BigUint::one() {
        return BigUint::zero();
    }

    let mut result = BigUint::one();
    let mut power = base.modulo(modulus);
    for bit in 0..exponent.bits() {
        if exponent.bit(bit) {
            result = BigUint::mod_mul(&result, &power, modulus);
        }
        power = BigUint::mod_mul(&power, &power, modulus);
    }
    result
}

fn decompose_n_minus_one(n: &BigUint) -> (BigUint, usize) {
    let mut odd_factor = n.sub_ref(&BigUint::one());
    let mut two_adic_exponent = 0usize;
    while !odd_factor.is_odd() {
        odd_factor.shr1();
        two_adic_exponent += 1;
    }
    (odd_factor, two_adic_exponent)
}

fn is_witness(base: &BigUint, candidate: &BigUint) -> bool {
    let one = BigUint::one();
    let n_minus_one = candidate.sub_ref(&one);
    let (odd_factor, two_adic_exponent) = decompose_n_minus_one(candidate);
    let mut value = mod_pow(base, &odd_factor, candidate);

    for _ in 0..two_adic_exponent {
        let next = BigUint::mod_mul(&value, &value, candidate);
        if next == one && value != one && value != n_minus_one {
            return true;
        }
        value = next;
    }

    value != one
}

/// Miller-Rabin probable-prime test with a fixed witness set.
#[must_use]
pub fn is_probable_prime(n: &BigUint) -> bool {
    is_probable_prime_with_bases(n, &SMALL_PRIMES)
}

/// Miller-Rabin using explicit witness bases.
#[must_use]
pub fn is_probable_prime_with_bases(candidate: &BigUint, bases: &[u64]) -> bool {
    if candidate.is_zero() {
        return false;
    }
    if candidate == &BigUint::one() {
        return false;
    }

    for &prime in &SMALL_PRIMES {
        let small_prime = BigUint::from_u64(prime);
        if candidate == &small_prime {
            return true;
        }
        if candidate.rem_u64(prime) == 0 {
            return false;
        }
    }

    if !candidate.is_odd() {
        return false;
    }

    let n_minus_one = candidate.sub_ref(&BigUint::one());

    for &base in bases {
        let witness = BigUint::from_u64(base);
        if witness >= n_minus_one {
            continue;
        }
        if is_witness(&witness, candidate) {
            return false;
        }
    }

    true
}

/// Multiplicative inverse `a^{-1} mod n`, if it exists.
#[must_use]
pub fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    if n.is_zero() {
        return None;
    }

    let mut t = BigInt::zero();
    let mut new_t = BigInt::from_biguint(BigUint::one());
    let mut r = n.clone();
    let mut new_r = a.modulo(n);

    while !new_r.is_zero() {
        let (quotient, remainder) = r.div_rem(&new_r);
        let next_t = t.sub_ref(&new_t.mul_biguint_ref(&quotient));
        t = new_t;
        new_t = next_t;
        r = new_r;
        new_r = remainder;
    }

    if !r.is_one() {
        return None;
    }

    Some(t.modulo_positive(n))
}

#[cfg(test)]
mod tests {
    use super::{gcd, is_probable_prime, lcm, mod_inverse, mod_pow};
    use crate::public_key::bigint::BigUint;

    #[test]
    fn gcd_small_values() {
        let lhs = BigUint::from_u64(48);
        let rhs = BigUint::from_u64(18);
        assert_eq!(gcd(&lhs, &rhs), BigUint::from_u64(6));
    }

    #[test]
    fn lcm_small_values() {
        let lhs = BigUint::from_u64(60);
        let rhs = BigUint::from_u64(52);
        assert_eq!(lcm(&lhs, &rhs), BigUint::from_u64(780));
    }

    #[test]
    fn modular_exponentiation_small_values() {
        let base = BigUint::from_u64(7);
        let exponent = BigUint::from_u64(560);
        let modulus = BigUint::from_u64(561);
        assert_eq!(mod_pow(&base, &exponent, &modulus), BigUint::from_u64(1));
    }

    #[test]
    fn miller_rabin_rejects_composites() {
        assert!(!is_probable_prime(&BigUint::from_u64(561)));
        assert!(!is_probable_prime(&BigUint::from_u64(341)));
        assert!(!is_probable_prime(&BigUint::from_u64(221)));
    }

    #[test]
    fn miller_rabin_accepts_primes() {
        assert!(is_probable_prime(&BigUint::from_u64(65_537)));
        assert!(is_probable_prime(&BigUint::from_be_bytes(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc5
        ])));
    }

    #[test]
    fn modular_inverse_small_values() {
        assert_eq!(
            mod_inverse(&BigUint::from_u64(11), &BigUint::from_u64(16)),
            Some(BigUint::from_u64(3))
        );
        assert_eq!(
            mod_inverse(&BigUint::from_u64(23), &BigUint::from_u64(46)),
            None
        );
    }
}
