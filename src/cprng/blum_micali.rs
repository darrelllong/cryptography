//! Blum-Micali pseudorandom bit generator.
//!
//! This is the original discrete-log based one-bit generator:
//!
//! ```text
//! x{i+1} = g^x{i} mod p
//! bit_i  = 1 if x{i+1} <= (p-1)/2 else 0
//! ```
//!
//! For a secure instantiation, `p` should be a large prime and `g` should be a
//! generator of a large subgroup. This reference implementation uses `u128`
//! arithmetic, so it is intended for experimentation and testing, not for
//! modern deployment.

use super::primes::{is_probable_prime, mod_pow};
use crate::Csprng;

/// Blum-Micali over a `u128` prime field.
pub struct BlumMicali {
    p: u128,
    g: u128,
    state: u128,
}

impl BlumMicali {
    /// Construct a generator with probable-prime modulus `p`, base `g`, and seed `x0`.
    ///
    /// # Panics
    ///
    /// Panics if the parameters violate the documented Blum-Micali
    /// preconditions or if `p` is too large for this reference
    /// implementation's `mul_mod` helper.
    #[must_use]
    pub fn new(p: u128, g: u128, seed: u128) -> Self {
        assert!(p > 2, "p must be > 2");
        assert!(
            p < (1u128 << 127),
            "modulus must be < 2^127 for the u128 mul_mod helper"
        );
        assert!(is_probable_prime(p), "p must be a probable prime");
        assert!(g > 1 && g < p, "g must be in 2..p");
        assert!(seed > 0 && seed < p, "seed must be in 1..p");
        Self { p, g, state: seed }
    }

    /// Current internal exponent state `x_i`.
    #[must_use]
    pub fn state(&self) -> u128 {
        self.state
    }

    /// Advance once and return the next output bit.
    pub fn next_bit(&mut self) -> u8 {
        self.state = mod_pow(self.g, self.state, self.p);
        u8::from(self.state <= (self.p - 1) / 2)
    }
}

impl Csprng for BlumMicali {
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
    fn small_reference_sequence() {
        let mut bm = BlumMicali::new(23, 5, 3);

        let mut bits = [0u8; 10];
        for bit in &mut bits {
            *bit = bm.next_bit();
        }
        assert_eq!(bits, [1, 1, 1, 0, 1, 1, 0, 0, 0, 1]);
    }

    #[test]
    fn fill_bytes_matches_reference_packing() {
        let mut bm = BlumMicali::new(23, 5, 3);
        let mut out = [0u8; 2];
        bm.fill_bytes(&mut out);
        assert_eq!(out, [0xec, 0x6f]);
    }

    #[test]
    #[should_panic(expected = "p must be a probable prime")]
    fn rejects_composite_modulus() {
        let _ = BlumMicali::new(21, 2, 3);
    }
}
