//! Cocks's early public-key scheme (CESG memo, 1973).
//!
//! This is the raw arithmetic primitive from the companion Python code: no
//! padding, no encoding, and no higher-level message framing. Callers are
//! responsible for mapping messages into the integer domain expected by the
//! scheme.

use crate::public_key::bigint::BigUint;
use crate::public_key::primes::{is_probable_prime, mod_inverse, mod_pow};

/// Public key for the raw Cocks primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CocksPublicKey {
    n: BigUint,
}

/// Private key for the raw Cocks primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CocksPrivateKey {
    pi: BigUint,
    q: BigUint,
}

/// Namespace wrapper for the raw Cocks construction.
pub struct Cocks;

impl CocksPublicKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Encrypt the raw integer message.
    ///
    /// This follows the teaching implementation directly: `c = m^n mod n`.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> BigUint {
        mod_pow(message, &self.n, &self.n)
    }
}

impl CocksPrivateKey {
    /// Return the stored exponent `pi = p^{-1} mod (q - 1)`.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.pi
    }

    /// Return the private prime `q`.
    #[must_use]
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    /// Decrypt the raw integer ciphertext.
    ///
    /// The Python source recovers the message as `c^pi mod q`, so the original
    /// message must be interpreted in the range `[0, q)`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        mod_pow(ciphertext, &self.pi, &self.q)
    }
}

impl Cocks {
    /// Derive a raw key pair from explicit primes `p` and `q`.
    ///
    /// Returns `None` if the inputs are equal, composite, or if `p` is not
    /// invertible modulo `q - 1`.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(CocksPublicKey, CocksPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }

        let q_minus_one = q.sub_ref(&BigUint::one());
        let pi = mod_inverse(p, &q_minus_one)?;
        let n = p.mul_ref(q);

        Some((
            CocksPublicKey { n },
            CocksPrivateKey {
                pi,
                q: q.clone(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Cocks;
    use crate::public_key::bigint::BigUint;

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(17);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid small primes");
        assert_eq!(public.modulus(), &BigUint::from_u64(187));
        assert_eq!(private.exponent(), &BigUint::from_u64(3));
        assert_eq!(private.q(), &BigUint::from_u64(17));
    }

    #[test]
    fn roundtrip_small_messages() {
        let prime_p = BigUint::from_u64(19);
        let prime_q = BigUint::from_u64(23);
        let (public, private) =
            Cocks::from_primes(&prime_p, &prime_q).expect("valid Cocks key");

        for msg in [0u64, 1, 2, 7, 11, 22] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message);
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_python() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(17);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid small primes");
        let message = BigUint::from_u64(5);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(ciphertext, BigUint::from_u64(113));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn rejects_non_invertible_choice() {
        let p = BigUint::from_u64(23);
        let q = BigUint::from_u64(47);
        assert!(Cocks::from_primes(&p, &q).is_none());
    }
}
