//! Schmidt-Samoa public-key primitive (Schmidt-Samoa, 2005).
//!
//! This is the raw arithmetic map from the companion Python code: explicit
//! prime inputs, public modulus `n = p^2 q`, and private decryption exponent
//! modulo `gamma = p q`. Padding and randomized wrappers come later.

use crate::public_key::bigint::BigUint;
use crate::public_key::primes::{is_probable_prime, lcm, mod_inverse, mod_pow};

/// Public key for the raw Schmidt-Samoa primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchmidtSamoaPublicKey {
    n: BigUint,
}

/// Private key for the raw Schmidt-Samoa primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchmidtSamoaPrivateKey {
    d: BigUint,
    gamma: BigUint,
}

/// Namespace wrapper for the raw Schmidt-Samoa construction.
pub struct SchmidtSamoa;

impl SchmidtSamoaPublicKey {
    /// Return the public modulus `n = p^2 q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Apply the raw public map `m^n mod n`.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> BigUint {
        mod_pow(message, &self.n, &self.n)
    }
}

impl SchmidtSamoaPrivateKey {
    /// Return the private exponent.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.d
    }

    /// Return `gamma = p q`.
    #[must_use]
    pub fn gamma(&self) -> &BigUint {
        &self.gamma
    }

    /// Apply the raw private map `c^d mod gamma`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        mod_pow(ciphertext, &self.d, &self.gamma)
    }
}

impl SchmidtSamoa {
    /// Derive a raw Schmidt-Samoa key pair from explicit primes.
    ///
    /// Returns `None` if the primes are equal, composite, or violate the
    /// divisibility checks from the Python reference.
    #[must_use]
    pub fn from_primes(
        p: &BigUint,
        q: &BigUint,
    ) -> Option<(SchmidtSamoaPublicKey, SchmidtSamoaPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }

        let p_minus_one = p.sub_ref(&BigUint::one());
        let q_minus_one = q.sub_ref(&BigUint::one());
        if q_minus_one.modulo(p).is_zero() || p_minus_one.modulo(q).is_zero() {
            return None;
        }

        let gamma = p.mul_ref(q);
        let lambda = lcm(&p_minus_one, &q_minus_one);
        let p_squared = p.mul_ref(p);
        let n = p_squared.mul_ref(q);
        let d = mod_inverse(&n, &lambda)?;

        Some((
            SchmidtSamoaPublicKey { n },
            SchmidtSamoaPrivateKey { d, gamma },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::SchmidtSamoa;
    use crate::public_key::bigint::BigUint;

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) =
            SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");
        assert_eq!(public.modulus(), &BigUint::from_u64(45));
        assert_eq!(private.exponent(), &BigUint::from_u64(1));
        assert_eq!(private.gamma(), &BigUint::from_u64(15));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) =
            SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");

        for msg in [0u64, 1, 2, 7, 14] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message);
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) =
            SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");
        let message = BigUint::from_u64(7);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(ciphertext, BigUint::from_u64(37));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(7);
        assert!(SchmidtSamoa::from_primes(&p, &q).is_none());

        let p = BigUint::from_u64(3);
        let composite = BigUint::from_u64(21);
        assert!(SchmidtSamoa::from_primes(&p, &composite).is_none());
    }
}
