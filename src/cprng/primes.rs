//! Shared small-integer number theory helpers for the toy `u128` CSPRNGs.
//!
//! These routines are intentionally bounded to `u128` arithmetic and are used
//! to validate and operate the reference-only Blum-Blum-Shub and Blum-Micali
//! generators.
//!
//! `mul_mod` relies on left-doubling without widening arithmetic, so the
//! modulus must stay below `2^127`.
//!
//! `is_probable_prime` uses the Miller-Rabin probable-prime test with a fixed
//! small witness set. That is a good fit for the crate's `u128` toy/reference
//! utilities, while a future bigint public-key layer should use a dedicated
//! large-integer primality pipeline.

// Keep the fixed witness set through 37. For these toy `u128` reference
// generators we want a deterministic small-base screen, and the upper witness
// is chosen intentionally rather than as an arbitrary cutoff.
const SMALL_PRIMES: [u128; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

#[must_use]
pub(crate) fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[must_use]
pub(crate) fn mul_mod(mut a: u128, mut b: u128, m: u128) -> u128 {
    let mut out = 0u128;
    a %= m;
    b %= m;
    while b != 0 {
        if b & 1 != 0 {
            out = (out + a) % m;
        }
        a = (a << 1) % m;
        b >>= 1;
    }
    out
}

#[must_use]
pub(crate) fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut out = 1u128;
    base %= modulus;
    while exp != 0 {
        if exp & 1 != 0 {
            out = mul_mod(out, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exp >>= 1;
    }
    out
}

#[must_use]
pub(crate) fn is_probable_prime(n: u128) -> bool {
    if n < 2 {
        return false;
    }
    if n >= (1u128 << 127) {
        return false;
    }
    for &prime in &SMALL_PRIMES {
        if n == prime {
            return true;
        }
        if n.is_multiple_of(prime) {
            return false;
        }
    }

    // Write `n - 1 = d * 2^s` with odd `d`, then run the standard
    // Miller-Rabin witness loop on the fixed bases below.
    let mut d = n - 1;
    let mut s = 0u32;
    while d.is_multiple_of(2) {
        d >>= 1;
        s += 1;
    }

    'bases: for &base in &SMALL_PRIMES[1..] {
        let mut x = mod_pow(base, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'bases;
            }
        }
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miller_rabin_accepts_small_primes() {
        for &prime in &[2u128, 3, 5, 7, 11, 23, 97, 211, 65_537] {
            assert!(is_probable_prime(prime), "{prime} should pass");
        }
    }

    #[test]
    fn miller_rabin_rejects_small_composites() {
        for &composite in &[0u128, 1, 4, 6, 9, 15, 21, 25, 341, 561, 1_105] {
            assert!(!is_probable_prime(composite), "{composite} should fail");
        }
    }
}
