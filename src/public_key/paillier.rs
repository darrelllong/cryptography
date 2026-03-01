//! Paillier public-key primitive (Pascal Paillier, 1999).
//!
//! This keeps the raw arithmetic core from the companion Python code: the
//! `L(x) = (x - 1) / n` map, the Carmichael-function private exponent, and the
//! multiplicative encryption formula over `n^2`. Random key generation and
//! message encoding stay in later layers.

use crate::public_key::bigint::BigUint;
use crate::public_key::primes::{gcd, is_probable_prime, lcm, mod_inverse, mod_pow};

/// Public key for the raw Paillier primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaillierPublicKey {
    n: BigUint,
    zeta: BigUint,
}

/// Private key for the raw Paillier primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaillierPrivateKey {
    n: BigUint,
    lambda: BigUint,
    u: BigUint,
}

/// Namespace wrapper for the raw Paillier construction.
pub struct Paillier;

impl PaillierPublicKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return the public base `zeta`.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.zeta
    }

    /// Encrypt with an explicit nonce `r`.
    ///
    /// The Python reference chooses `r` randomly from `Z_n^*`; this raw layer
    /// takes it explicitly until a higher-level RNG/keygen API is added.
    #[must_use]
    pub fn encrypt_with_nonce(&self, message: &BigUint, nonce: &BigUint) -> Option<BigUint> {
        if nonce.is_zero() || nonce >= &self.n || gcd(nonce, &self.n) != BigUint::one() {
            return None;
        }

        let n_squared = self.n.mul_ref(&self.n);
        let left = mod_pow(&self.zeta, message, &n_squared);
        let right = mod_pow(nonce, &self.n, &n_squared);
        Some(BigUint::mod_mul(&left, &right, &n_squared))
    }
}

impl PaillierPrivateKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return the Carmichael exponent `lambda = lcm(p - 1, q - 1)`.
    #[must_use]
    pub fn lambda(&self) -> &BigUint {
        &self.lambda
    }

    /// Return the precomputed decryption factor `u`.
    #[must_use]
    pub fn decryption_factor(&self) -> &BigUint {
        &self.u
    }

    /// Decrypt the raw ciphertext.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        let n_squared = self.n.mul_ref(&self.n);
        let value = mod_pow(ciphertext, &self.lambda, &n_squared);
        let lifted = paillier_l(&value, &self.n);
        BigUint::mod_mul(&lifted, &self.u, &self.n)
    }
}

impl Paillier {
    /// Derive a raw Paillier key pair from explicit primes and an explicit
    /// public base.
    ///
    /// Returns `None` if the primes are invalid, `gcd(n, (p - 1)(q - 1)) != 1`,
    /// or if the supplied base does not make the `L(zeta^lambda mod n^2)`
    /// factor invertible modulo `n`.
    #[must_use]
    pub fn from_primes_with_base(
        p: &BigUint,
        q: &BigUint,
        base: &BigUint,
    ) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }

        let n = p.mul_ref(q);
        let p_minus_one = p.sub_ref(&BigUint::one());
        let q_minus_one = q.sub_ref(&BigUint::one());
        let totient = p_minus_one.mul_ref(&q_minus_one);
        if gcd(&n, &totient) != BigUint::one() {
            return None;
        }

        let lambda = lcm(&p_minus_one, &q_minus_one);
        let n_squared = n.mul_ref(&n);
        let zeta = base.modulo(&n_squared);
        if zeta <= BigUint::one() {
            return None;
        }

        let lifted = paillier_l(&mod_pow(&zeta, &lambda, &n_squared), &n);
        let u = mod_inverse(&lifted, &n)?;

        Some((
            PaillierPublicKey {
                n: n.clone(),
                zeta,
            },
            PaillierPrivateKey { n, lambda, u },
        ))
    }

    /// Derive a raw Paillier key pair using the deterministic base `n + 1`.
    ///
    /// The Python reference samples `zeta` randomly, but `n + 1` is the usual
    /// simple choice and lets the raw primitive be constructed without adding a
    /// separate randomness layer yet.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        let n = p.mul_ref(q);
        let base = n.add_ref(&BigUint::one());
        Self::from_primes_with_base(p, q, &base)
    }
}

fn paillier_l(value: &BigUint, modulus: &BigUint) -> BigUint {
    let shifted = value.sub_ref(&BigUint::one());
    let (quotient, remainder) = shifted.div_rem(modulus);
    debug_assert!(remainder.is_zero(), "Paillier L input is congruent to 1 mod n");
    quotient
}

#[cfg(test)]
mod tests {
    use super::Paillier;
    use crate::public_key::bigint::BigUint;

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        assert_eq!(public.modulus(), &BigUint::from_u64(15));
        assert_eq!(public.generator(), &BigUint::from_u64(16));
        assert_eq!(private.modulus(), &BigUint::from_u64(15));
        assert_eq!(private.lambda(), &BigUint::from_u64(4));
        assert_eq!(private.decryption_factor(), &BigUint::from_u64(4));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let nonce = BigUint::from_u64(2);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");

        for msg in [0u64, 1, 7, 14] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public
                .encrypt_with_nonce(&message, &nonce)
                .expect("valid Paillier nonce");
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let nonce = BigUint::from_u64(2);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let message = BigUint::from_u64(7);
        let ciphertext = public
            .encrypt_with_nonce(&message, &nonce)
            .expect("valid Paillier nonce");
        assert_eq!(ciphertext, BigUint::from_u64(83));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn raw_paillier_is_additively_homomorphic() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let left_nonce = BigUint::from_u64(2);
        let right_nonce = BigUint::from_u64(4);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let left = BigUint::from_u64(7);
        let right = BigUint::from_u64(6);

        let left_cipher = public
            .encrypt_with_nonce(&left, &left_nonce)
            .expect("valid Paillier nonce");
        let right_cipher = public
            .encrypt_with_nonce(&right, &right_nonce)
            .expect("valid Paillier nonce");
        let modulus_squared = public.modulus().mul_ref(public.modulus());
        let combined_cipher = BigUint::mod_mul(&left_cipher, &right_cipher, &modulus_squared);
        let decrypted = private.decrypt_raw(&combined_cipher);
        let expected = left.add_ref(&right).modulo(public.modulus());

        assert_eq!(decrypted, expected);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(7);
        assert!(Paillier::from_primes(&p, &q).is_none());

        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        assert!(Paillier::from_primes_with_base(&p, &q, &BigUint::one()).is_none());
    }

    #[test]
    fn rejects_invalid_nonce() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, _) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let message = BigUint::from_u64(7);
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::zero())
            .is_none());
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::from_u64(3))
            .is_none());
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::from_u64(15))
            .is_none());
    }
}
