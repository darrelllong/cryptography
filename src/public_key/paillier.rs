//! Paillier public-key primitive (Pascal Paillier, 1999).
//!
//! This keeps the raw arithmetic core from the companion Python code: the
//! `L(x) = (x - 1) / n` map, the Carmichael-function private exponent, and the
//! multiplicative encryption formula over `n^2`. Random key generation and
//! message encoding stay in later layers.

use core::fmt;

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::io::{decode_biguints, encode_biguints, pem_unwrap, pem_wrap};
use crate::public_key::primes::{
    gcd, is_probable_prime, lcm, mod_inverse, mod_pow, random_coprime_below, random_probable_prime,
};
use crate::Csprng;

const PAILLIER_PUBLIC_LABEL: &str = "CRYPTOGRAPHY PAILLIER PUBLIC KEY";
const PAILLIER_PRIVATE_LABEL: &str = "CRYPTOGRAPHY PAILLIER PRIVATE KEY";

/// Public key for the raw Paillier primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaillierPublicKey {
    n: BigUint,
    zeta: BigUint,
}

/// Private key for the raw Paillier primitive.
#[derive(Clone, Eq, PartialEq)]
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

    /// Return the largest plaintext integer accepted by the raw scheme.
    #[must_use]
    pub fn max_plaintext_exclusive(&self) -> &BigUint {
        &self.n
    }

    /// Encrypt with an explicit nonce `r`.
    ///
    /// The Python reference chooses `r` randomly from `Z_n^*`; this raw layer
    /// takes it explicitly until a higher-level RNG/keygen API is added.
    #[must_use]
    pub fn encrypt_with_nonce(&self, message: &BigUint, nonce: &BigUint) -> Option<BigUint> {
        if message >= &self.n {
            return None;
        }
        if nonce.is_zero() || nonce >= &self.n || gcd(nonce, &self.n) != BigUint::one() {
            return None;
        }

        let n_squared = self.n.mul_ref(&self.n);
        let left = mod_pow(&self.zeta, message, &n_squared);
        let right = mod_pow(nonce, &self.n, &n_squared);
        let product = if let Some(ctx) = MontgomeryCtx::new(&n_squared) {
            ctx.mul(&left, &right)
        } else {
            BigUint::mod_mul(&left, &right, &n_squared)
        };
        Some(product)
    }

    /// Encrypt a byte string with a fresh random nonce from `Z_n^*`.
    #[must_use]
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<BigUint> {
        let message_int = BigUint::from_be_bytes(message);
        let nonce = random_coprime_below(rng, &self.n, &self.n)?;
        self.encrypt_with_nonce(&message_int, &nonce)
    }

    /// Re-randomize an existing ciphertext without changing the plaintext.
    ///
    /// Returns `None` if the input is not in the ciphertext range `[0, n^2)`.
    #[must_use]
    pub fn rerandomize<R: Csprng>(&self, ciphertext: &BigUint, rng: &mut R) -> Option<BigUint> {
        let nonce = random_coprime_below(rng, &self.n, &self.n)?;
        let n_squared = self.n.mul_ref(&self.n);
        if ciphertext >= &n_squared {
            return None;
        }
        let factor = mod_pow(&nonce, &self.n, &n_squared);
        let product = if let Some(ctx) = MontgomeryCtx::new(&n_squared) {
            ctx.mul(ciphertext, &factor)
        } else {
            BigUint::mod_mul(ciphertext, &factor, &n_squared)
        };
        Some(product)
    }

    /// Combine two ciphertexts so that decryption adds the plaintexts modulo `n`.
    ///
    /// Returns `None` if either input is not in the ciphertext range `[0, n^2)`.
    #[must_use]
    pub fn add_ciphertexts(&self, lhs: &BigUint, rhs: &BigUint) -> Option<BigUint> {
        let n_squared = self.n.mul_ref(&self.n);
        if lhs >= &n_squared || rhs >= &n_squared {
            return None;
        }
        if let Some(ctx) = MontgomeryCtx::new(&n_squared) {
            Some(ctx.mul(lhs, rhs))
        } else {
            Some(BigUint::mod_mul(lhs, rhs, &n_squared))
        }
    }

    /// Encode the public key in the crate-defined binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.n, &self.zeta])
    }

    /// Decode the public key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let n = fields.next()?;
        let zeta = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() || zeta <= BigUint::one() {
            return None;
        }
        Some(Self { n, zeta })
    }

    /// Encode the public key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(PAILLIER_PUBLIC_LABEL, &self.to_binary())
    }

    /// Decode the public key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(PAILLIER_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
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
        if let Some(ctx) = MontgomeryCtx::new(&self.n) {
            ctx.mul(&lifted, &self.u)
        } else {
            BigUint::mod_mul(&lifted, &self.u, &self.n)
        }
    }

    /// Decrypt a ciphertext back into the big-endian byte string interpreted
    /// as the plaintext integer.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Vec<u8> {
        self.decrypt_raw(ciphertext).to_be_bytes()
    }

    /// Encode the private key in the crate-defined binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.n, &self.lambda, &self.u])
    }

    /// Decode the private key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let n = fields.next()?;
        let lambda = fields.next()?;
        let u = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() || lambda.is_zero() || u.is_zero() {
            return None;
        }
        Some(Self { n, lambda, u })
    }

    /// Encode the private key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(PAILLIER_PRIVATE_LABEL, &self.to_binary())
    }

    /// Decode the private key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(PAILLIER_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
    }
}

impl fmt::Debug for PaillierPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaillierPrivateKey(<redacted>)")
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
            PaillierPublicKey { n: n.clone(), zeta },
            PaillierPrivateKey { n, lambda, u },
        ))
    }

    /// Derive a raw Paillier key pair using the deterministic base `n + 1`.
    ///
    /// The Python reference samples `zeta` randomly, but `n + 1` is the usual
    /// simple choice and lets the raw primitive be constructed without adding a
    /// separate randomness layer yet.
    #[must_use]
    pub fn from_primes(
        p: &BigUint,
        q: &BigUint,
    ) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        let n = p.mul_ref(q);
        let base = n.add_ref(&BigUint::one());
        Self::from_primes_with_base(p, q, &base)
    }

    /// Generate a teaching-sized Paillier key pair using the standard `n + 1`
    /// base.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        // With fewer than 8 total bits the split can collapse to the same tiny
        // prime on both sides, so a distinct-prime key may never be found.
        if bits < 8 {
            return None;
        }

        let p_bits = bits / 2;
        let q_bits = bits - p_bits;
        loop {
            let p = random_probable_prime(rng, p_bits)?;
            let q = random_probable_prime(rng, q_bits)?;
            if let Some(keypair) = Self::from_primes(&p, &q) {
                return Some(keypair);
            }
        }
    }
}

fn paillier_l(value: &BigUint, modulus: &BigUint) -> BigUint {
    let shifted = value.sub_ref(&BigUint::one());
    let (quotient, remainder) = shifted.div_rem(modulus);
    debug_assert!(
        remainder.is_zero(),
        "Paillier L input is congruent to 1 mod n"
    );
    quotient
}

#[cfg(test)]
mod tests {
    use super::{Paillier, PaillierPrivateKey, PaillierPublicKey};
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

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

    #[test]
    fn byte_wrapper_roundtrip_and_rerandomize() {
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let mut drbg = CtrDrbgAes256::new(&[0x52; 48]);
        let ciphertext = public.encrypt(&[0x12, 0x34], &mut drbg).expect("message fits");
        let rerandomized = public
            .rerandomize(&ciphertext, &mut drbg)
            .expect("rerandomization");
        assert_eq!(private.decrypt(&ciphertext), vec![0x12, 0x34]);
        assert_eq!(private.decrypt(&rerandomized), vec![0x12, 0x34]);
        assert_ne!(ciphertext, rerandomized);
    }

    #[test]
    fn add_ciphertexts_wrapper_matches_plaintext_addition() {
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let left = public
            .encrypt_with_nonce(&BigUint::from_u64(0x12), &BigUint::from_u64(2))
            .expect("valid nonce");
        let right = public
            .encrypt_with_nonce(&BigUint::from_u64(0x34), &BigUint::from_u64(3))
            .expect("valid nonce");
        let combined = public
            .add_ciphertexts(&left, &right)
            .expect("ciphertexts are in range");
        assert_eq!(private.decrypt(&combined), vec![0x46]);
    }

    #[test]
    fn generate_teaching_keypair() {
        let mut drbg = CtrDrbgAes256::new(&[0x53; 48]);
        let (public, private) = Paillier::generate(&mut drbg, 32).expect("Paillier key generation");
        let ciphertext = public.encrypt(&[0x2a], &mut drbg).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), vec![0x2a]);
    }

    #[test]
    fn wrappers_reject_out_of_range_ciphertexts() {
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, _) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let invalid = public.modulus().mul_ref(public.modulus());
        let mut drbg = CtrDrbgAes256::new(&[0x95; 48]);
        assert!(public.rerandomize(&invalid, &mut drbg).is_none());
        let valid = public
            .encrypt_with_nonce(&BigUint::from_u64(7), &BigUint::from_u64(2))
            .expect("valid nonce");
        assert!(public.add_ciphertexts(&valid, &invalid).is_none());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid key");

        let public_blob = public.to_binary();
        let private_blob = private.to_binary();
        assert_eq!(PaillierPublicKey::from_binary(&public_blob), Some(public.clone()));
        assert_eq!(PaillierPrivateKey::from_binary(&private_blob), Some(private.clone()));

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        assert_eq!(PaillierPublicKey::from_pem(&public_pem), Some(public));
        assert_eq!(PaillierPrivateKey::from_pem(&private_pem), Some(private));
    }
}
