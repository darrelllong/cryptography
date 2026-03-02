//! Primality and modular-arithmetic helpers for the public-key layer.
//!
//! These routines mirror the structure of the teaching-oriented Python code:
//! repeated-squaring modular exponentiation plus Miller-Rabin with a fixed
//! witness set. The fixed bases keep the implementation deterministic and easy
//! to test while we are still in the pure-Rust, dependency-free foundation.
//!
//! A smaller `u128`-bounded Miller-Rabin helper also exists in
//! `crate::cprng::primes`; the duplication is intentional because the
//! arithmetic types and intended use-cases differ.

use super::bigint::{BigInt, BigUint, MontgomeryCtx};
use crate::Csprng;

const MR_BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

const SMALL_TRIAL_PRIMES: [u16; 168] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
    503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
    701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
    911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
];

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
    if let Some(ctx) = MontgomeryCtx::new(modulus) {
        return ctx.pow(base, exponent);
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

fn is_witness(
    base: &BigUint,
    ctx: &MontgomeryCtx,
    odd_factor: &BigUint,
    two_adic_exponent: usize,
) -> bool {
    let one = BigUint::one();
    let n_minus_one = ctx.modulus().sub_ref(&one);
    let mut value = ctx.pow(base, odd_factor);

    for _ in 0..two_adic_exponent {
        let next = ctx.square(&value);
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
    is_probable_prime_with_bases(n, &MR_BASES)
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

    for &prime in &SMALL_TRIAL_PRIMES {
        let prime = u64::from(prime);
        let remainder = candidate.rem_u64(prime);
        if remainder == 0 {
            if candidate.bits() <= 10 && candidate.rem_u64(1u64 << 10) == prime {
                return true;
            }
            return false;
        }
    }

    if bases.is_empty() {
        return false;
    }

    let Some(ctx) = MontgomeryCtx::new(candidate) else {
        return false;
    };
    let n_minus_one = candidate.sub_ref(&BigUint::one());
    let (odd_factor, two_adic_exponent) = decompose_n_minus_one(candidate);

    for &base in bases {
        let witness = BigUint::from_u64(base);
        if witness >= n_minus_one {
            continue;
        }
        if is_witness(&witness, &ctx, &odd_factor, two_adic_exponent) {
            return false;
        }
    }

    true
}

/// Draw a random integer in `[0, upper_exclusive)`.
#[must_use]
pub fn random_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    if upper_exclusive.is_zero() {
        return None;
    }

    let bits = upper_exclusive.bits();
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    let excess_bits = bytes.len() * 8 - bits;
    let top_mask = 0xff_u8 >> excess_bits;

    loop {
        rng.fill_bytes(&mut bytes);
        bytes[0] &= top_mask;
        let candidate = BigUint::from_be_bytes(&bytes);
        crate::ct::zeroize_slice(bytes.as_mut_slice());
        if candidate < *upper_exclusive {
            return Some(candidate);
        }
    }
}

/// Draw a random integer in `[1, upper_exclusive)`.
#[must_use]
pub fn random_nonzero_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    if upper_exclusive <= &BigUint::one() {
        return None;
    }

    loop {
        let candidate = random_below(rng, upper_exclusive)?;
        if !candidate.is_zero() {
            return Some(candidate);
        }
    }
}

/// Draw a random integer in `[1, upper_exclusive)` that is coprime to `coprime_to`.
#[must_use]
pub fn random_coprime_below<R: Csprng>(
    rng: &mut R,
    upper_exclusive: &BigUint,
    coprime_to: &BigUint,
) -> Option<BigUint> {
    loop {
        let candidate = random_nonzero_below(rng, upper_exclusive)?;
        if gcd(&candidate, coprime_to) == BigUint::one() {
            return Some(candidate);
        }
    }
}

/// Draw a teaching-sized probable prime with the requested bit length.
#[must_use]
pub fn random_probable_prime<R: Csprng>(rng: &mut R, bits: usize) -> Option<BigUint> {
    if bits < 2 {
        return None;
    }

    let mut bytes = vec![0u8; bits.div_ceil(8)];
    let top_bit = (bits - 1) % 8;
    let excess_bits = bytes.len() * 8 - bits;
    let top_mask = 0xff_u8 >> excess_bits;
    loop {
        rng.fill_bytes(&mut bytes);
        bytes[0] &= top_mask;
        bytes[0] |= 1u8 << top_bit;
        let last = bytes.len() - 1;
        bytes[last] |= 1;

        let candidate = BigUint::from_be_bytes(&bytes);
        crate::ct::zeroize_slice(bytes.as_mut_slice());
        if is_probable_prime(&candidate) {
            return Some(candidate);
        }
    }
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
    use super::{
        gcd, is_probable_prime, is_probable_prime_with_bases, lcm, mod_inverse, mod_pow,
        random_nonzero_below,
    };
    use crate::public_key::bigint::BigUint;
    use crate::Csprng;

    struct ZeroRng;

    impl Csprng for ZeroRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.fill(0);
        }
    }

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
    fn miller_rabin_rejects_empty_witness_sets() {
        assert!(!is_probable_prime_with_bases(
            &BigUint::from_u64(65_537),
            &[]
        ));
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

    #[test]
    fn random_nonzero_below_rejects_unit_bound() {
        let mut rng = ZeroRng;
        assert_eq!(random_nonzero_below(&mut rng, &BigUint::one()), None);
    }
}
