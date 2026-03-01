//! RSA public-key primitive (Rivest, Shamir, Adleman, 1978).
//!
//! This module intentionally implements only the raw trapdoor permutation from
//! the companion Python code: key derivation from explicit primes plus raw
//! modular exponentiation for encrypt/decrypt. Padding, encoding, and hybrid
//! KEM/PKE framing are separate layers.

use core::fmt;

use crate::public_key::bigint::BigUint;
use crate::public_key::primes::{gcd, is_probable_prime, lcm, mod_inverse, mod_pow};
use crate::Csprng;

/// Public key for the raw RSA primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKey {
    e: BigUint,
    n: BigUint,
}

/// Private key for the raw RSA primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct RsaPrivateKey {
    d: BigUint,
    n: BigUint,
}

/// Namespace wrapper for the raw RSA construction.
pub struct Rsa;

impl RsaPublicKey {
    /// Return the public exponent.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.e
    }

    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Apply the raw public operation `m^e mod n`.
    ///
    /// Like the Python reference, this is the naked permutation. Callers are
    /// responsible for mapping structured messages into the integer domain.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> BigUint {
        mod_pow(message, &self.e, &self.n)
    }
}

impl RsaPrivateKey {
    /// Return the private exponent.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.d
    }

    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Apply the raw private operation `c^d mod n`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        mod_pow(ciphertext, &self.d, &self.n)
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaPrivateKey(<redacted>)")
    }
}

impl Rsa {
    /// Derive a raw RSA key pair from explicit primes and an explicit exponent.
    ///
    /// Returns `None` if the inputs are equal, composite, the exponent is not
    /// greater than one, or the exponent is not invertible modulo
    /// `lambda = lcm(p - 1, q - 1)`.
    #[must_use]
    pub fn from_primes_with_exponent(
        p: &BigUint,
        q: &BigUint,
        exponent: &BigUint,
    ) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }
        if exponent <= &BigUint::one() {
            return None;
        }

        let p_minus_one = p.sub_ref(&BigUint::one());
        let q_minus_one = q.sub_ref(&BigUint::one());
        let lambda = lcm(&p_minus_one, &q_minus_one);
        if gcd(exponent, &lambda) != BigUint::one() {
            return None;
        }

        let d = mod_inverse(exponent, &lambda)?;
        let n = p.mul_ref(q);

        Some((
            RsaPublicKey {
                e: exponent.clone(),
                n: n.clone(),
            },
            RsaPrivateKey { d, n },
        ))
    }

    /// Derive a raw RSA key pair from explicit primes using the Python
    /// reference's default exponent search.
    ///
    /// The reference starts at `2^16 + 1` and increments the power until it
    /// finds a value coprime to `lambda = lcm(p - 1, q - 1)`.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }

        let p_minus_one = p.sub_ref(&BigUint::one());
        let q_minus_one = q.sub_ref(&BigUint::one());
        let lambda = lcm(&p_minus_one, &q_minus_one);

        let mut exponent_bit = 16usize;
        loop {
            let mut exponent = BigUint::zero();
            exponent.set_bit(exponent_bit);
            exponent = exponent.add_ref(&BigUint::one());
            if gcd(&exponent, &lambda) == BigUint::one() {
                return Self::from_primes_with_exponent(p, q, &exponent);
            }
            exponent_bit += 1;
        }
    }

    /// Generate a teaching-sized RSA key pair from a CSPRNG and explicit
    /// public exponent.
    ///
    /// This keeps the raw primitive usable without forcing callers to provide
    /// their own prime search. The generated primes are only screened with the
    /// in-tree Miller-Rabin helper, so this is appropriate for demonstration
    /// and testing rather than high-assurance production key generation.
    #[must_use]
    pub fn generate_with_exponent<R: Csprng>(
        rng: &mut R,
        bits: usize,
        exponent: &BigUint,
    ) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        if bits < 32 {
            return None;
        }

        let p_bits = bits / 2;
        let q_bits = bits - p_bits;
        loop {
            let p = random_probable_prime(rng, p_bits);
            let q = random_probable_prime(rng, q_bits);
            if let Some(keypair) = Self::from_primes_with_exponent(&p, &q, exponent) {
                return Some(keypair);
            }
        }
    }

    /// Generate a teaching-sized RSA key pair using the Python reference's
    /// default exponent search.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R, bits: usize) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        if bits < 32 {
            return None;
        }

        let p_bits = bits / 2;
        let q_bits = bits - p_bits;
        loop {
            let p = random_probable_prime(rng, p_bits);
            let q = random_probable_prime(rng, q_bits);
            if let Some(keypair) = Self::from_primes(&p, &q) {
                return Some(keypair);
            }
        }
    }
}

fn random_probable_prime<R: Csprng>(rng: &mut R, bits: usize) -> BigUint {
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
        if is_probable_prime(&candidate) {
            crate::ct::zeroize_slice(bytes.as_mut_slice());
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rsa;
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

    #[test]
    fn derive_reference_key_with_default_exponent() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");
        assert_eq!(public.modulus(), &BigUint::from_u64(3_233));
        assert_eq!(public.exponent(), &BigUint::from_u64(65_537));
        assert_eq!(private.exponent(), &BigUint::from_u64(413));
        assert_eq!(private.modulus(), &BigUint::from_u64(3_233));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");

        for msg in [0u64, 1, 2, 65, 123, 3_232] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message);
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");
        let message = BigUint::from_u64(65);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(ciphertext, BigUint::from_u64(2_790));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn raw_rsa_is_multiplicatively_homomorphic() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");
        let left = BigUint::from_u64(12);
        let right = BigUint::from_u64(17);

        let left_cipher = public.encrypt_raw(&left);
        let right_cipher = public.encrypt_raw(&right);
        let combined_cipher = BigUint::mod_mul(&left_cipher, &right_cipher, public.modulus());
        let decrypted = private.decrypt_raw(&combined_cipher);
        let expected = BigUint::mod_mul(&left, &right, public.modulus());

        assert_eq!(decrypted, expected);
    }

    #[test]
    fn explicit_exponent_matches_classic_example() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let exponent = BigUint::from_u64(17);
        let (public, private) =
            Rsa::from_primes_with_exponent(&p, &q, &exponent).expect("valid RSA key");
        assert_eq!(public.exponent(), &BigUint::from_u64(17));
        assert_eq!(private.exponent(), &BigUint::from_u64(413));
    }

    #[test]
    fn rejects_non_invertible_exponent() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(13);
        let exponent = BigUint::from_u64(3);
        assert!(Rsa::from_primes_with_exponent(&p, &q, &exponent).is_none());
    }

    #[test]
    fn generate_teaching_keypair() {
        let seed = [0x55u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Rsa::generate(&mut drbg, 64).expect("generated RSA key");
        assert!(public.modulus().bits() >= 63);
        let message = BigUint::from_u64(42);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }
}
