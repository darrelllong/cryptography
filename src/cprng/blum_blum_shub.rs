//! Blum Blum Shub (BBS) pseudorandom bit generator.
//!
//! This is the classic quadratic-residue generator:
//!
//! ```text
//! x0   = seed^2 mod n
//! x{i+1} = x{i}^2 mod n
//! bit_i  = lsb(x{i})
//! ```
//!
//! where `n = p*q` for distinct primes `p ≡ q ≡ 3 (mod 4)`.
//!
//! This implementation is intentionally small and uses `u128`, which keeps it
//! practical as a reference tool but not as a serious large-parameter BBS.
//! The construction is the Blum-Blum-Shub generator from Blum, Blum, and Shub
//! (1986), translated here into a tiny fixed-width reference form.

use super::primes::{gcd, is_probable_prime, mul_mod};

/// Blum Blum Shub over a `u128` modulus.
pub struct BlumBlumShub {
    n: u128,
    state: u128,
}

impl BlumBlumShub {
    /// Construct from the prime factors and a seed.
    ///
    /// Preconditions:
    /// - `p != q`
    /// - `p` and `q` are probable primes
    /// - `p % 4 == 3`
    /// - `q % 4 == 3`
    /// - `gcd(seed, p*q) == 1`
    ///
    /// # Panics
    ///
    /// Panics if the modulus overflows `u128`, if the modulus is too large for
    /// this reference implementation's `mul_mod` helper, or if the parameters
    /// violate the stated Blum Blum Shub preconditions.
    #[must_use]
    pub fn new(p: u128, q: u128, seed: u128) -> Self {
        assert!(p > 3 && q > 3, "p and q must be > 3");
        assert!(p != q, "p and q must be distinct");
        assert!(
            p < (1u128 << 127) && q < (1u128 << 127),
            "p and q must be < 2^127 for the u128 mul_mod helper"
        );
        assert!(is_probable_prime(p), "p must be a probable prime");
        assert!(is_probable_prime(q), "q must be a probable prime");
        assert_eq!(p % 4, 3, "p must be congruent to 3 mod 4");
        assert_eq!(q % 4, 3, "q must be congruent to 3 mod 4");
        let n = p.checked_mul(q).expect("modulus overflow");
        assert!(
            n < (1u128 << 127),
            "modulus must be < 2^127 for the u128 mul_mod helper"
        );
        assert!(seed > 0 && seed < n, "seed must be in 1..n");
        assert_eq!(gcd(seed, n), 1, "seed must be coprime to n");

        Self {
            n,
            state: mul_mod(seed, seed, n),
        }
    }

    /// Current internal state `x_i`.
    #[must_use]
    pub fn state(&self) -> u128 {
        self.state
    }

    /// Return the current output bit and advance to the next state.
    pub fn next_bit(&mut self) -> u8 {
        let bit = (self.state & 1) as u8;
        self.state = mul_mod(self.state, self.state, self.n);
        bit
    }

    /// Fill `out` with generator output bytes, most-significant-bit first per byte.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            let mut v = 0u8;
            for _ in 0..8 {
                v = (v << 1) | self.next_bit();
            }
            *byte = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiki_small_example_bits() {
        let mut bbs = BlumBlumShub::new(11, 23, 3);
        assert_eq!(bbs.state(), 9);

        let mut bits = [0u8; 8];
        for bit in &mut bits {
            *bit = bbs.next_bit();
        }
        assert_eq!(bits, [1, 1, 0, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn fill_bytes_matches_reference_packing() {
        let mut bbs = BlumBlumShub::new(11, 23, 3);
        let mut out = [0u8; 2];
        bbs.fill_bytes(&mut out);
        assert_eq!(out, [0xca, 0x0d]);
    }

    #[test]
    fn large_modulus_above_u64_still_advances() {
        let p = (1u128 << 32) + 15;
        let q = (1u128 << 32) + 75;
        let mut bbs = BlumBlumShub::new(p, q, 3);
        let n = p * q;

        for _ in 0..16 {
            let _ = bbs.next_bit();
            assert!(bbs.state() < n);
        }
    }

    #[test]
    #[should_panic(expected = "p must be a probable prime")]
    fn rejects_composite_factor() {
        let _ = BlumBlumShub::new(15, 23, 2);
    }
}
