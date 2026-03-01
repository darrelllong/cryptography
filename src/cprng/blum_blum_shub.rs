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

use crate::Csprng;

#[inline]
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[inline]
fn mul_mod(mut a: u128, mut b: u128, m: u128) -> u128 {
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
    /// - `p % 4 == 3`
    /// - `q % 4 == 3`
    /// - `gcd(seed, p*q) == 1`
    pub fn new(p: u128, q: u128, seed: u128) -> Self {
        assert!(p > 3 && q > 3, "p and q must be > 3");
        assert!(p != q, "p and q must be distinct");
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
    pub fn state(&self) -> u128 {
        self.state
    }

    /// Return the current output bit and advance to the next state.
    pub fn next_bit(&mut self) -> u8 {
        let bit = (self.state & 1) as u8;
        self.state = mul_mod(self.state, self.state, self.n);
        bit
    }
}

impl Csprng for BlumBlumShub {
    fn fill_bytes(&mut self, out: &mut [u8]) {
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
        let q = (1u128 << 32) + 63;
        let mut bbs = BlumBlumShub::new(p, q, 3);
        let n = p * q;

        for _ in 0..16 {
            let _ = bbs.next_bit();
            assert!(bbs.state() < n);
        }
    }
}
