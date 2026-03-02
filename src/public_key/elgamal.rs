//! `ElGamal` public-key primitive (Taher `ElGamal`, 1985).
//!
//! This is the raw textbook construction from the companion Python code:
//! explicit group parameters plus the bare multiplicative encrypt/decrypt
//! transform. Random key generation and message encoding stay in later layers.

use core::fmt;

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::primes::{
    is_probable_prime, mod_pow, random_nonzero_below, random_probable_prime,
};
use crate::Csprng;

/// Public key for the raw `ElGamal` primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalPublicKey {
    p: BigUint,
    r: BigUint,
    b: BigUint,
}

/// Private key for the raw `ElGamal` primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct ElGamalPrivateKey {
    p: BigUint,
    a: BigUint,
}

/// Raw `ElGamal` ciphertext pair `(gamma, delta)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalCiphertext {
    gamma: BigUint,
    delta: BigUint,
}

/// Namespace wrapper for the raw `ElGamal` construction.
pub struct ElGamal;

impl ElGamalPublicKey {
    /// Return the prime modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Return the caller-supplied generator/base.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.r
    }

    /// Return `b = r^a mod p`.
    #[must_use]
    pub fn public_component(&self) -> &BigUint {
        &self.b
    }

    /// Encrypt with an explicit ephemeral exponent `k`.
    ///
    /// The Python reference chooses `k` randomly; the raw primitive takes it
    /// explicitly so key generation and randomness stay separate.
    #[must_use]
    pub fn encrypt_with_ephemeral(
        &self,
        message: &BigUint,
        ephemeral: &BigUint,
    ) -> Option<ElGamalCiphertext> {
        if message >= &self.p {
            return None;
        }
        if ephemeral.is_zero() {
            return None;
        }

        let p_minus_one = self.p.sub_ref(&BigUint::one());
        if ephemeral >= &p_minus_one {
            return None;
        }

        let gamma = mod_pow(&self.r, ephemeral, &self.p);
        let shared = mod_pow(&self.b, ephemeral, &self.p);
        let delta = if let Some(ctx) = MontgomeryCtx::new(&self.p) {
            ctx.mul(message, &shared)
        } else {
            BigUint::mod_mul(message, &shared, &self.p)
        };
        Some(ElGamalCiphertext { gamma, delta })
    }

    /// Encrypt a byte string with a fresh random ephemeral exponent.
    ///
    /// This is the minimal "usable" layer for textbook `ElGamal`: it samples
    /// the ephemeral exponent from `[1, p - 2]`, interprets the message as one
    /// big-endian integer, and applies the raw group operation. The encoded
    /// integer must be strictly smaller than `p`, so the practical message
    /// capacity is at most `floor((bits(p) - 1) / 8)` bytes. Callers that need
    /// hybrid encryption or padding should build that on top.
    #[must_use]
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<ElGamalCiphertext> {
        let message_int = BigUint::from_be_bytes(message);
        let upper = self.p.sub_ref(&BigUint::one());
        let ephemeral = random_nonzero_below(rng, &upper)?;
        self.encrypt_with_ephemeral(&message_int, &ephemeral)
    }
}

impl ElGamalPrivateKey {
    /// Return the prime modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Return the secret exponent `a`.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.a
    }

    /// Decrypt the raw ciphertext.
    ///
    /// This matches the Python source exactly: instead of an explicit modular
    /// inverse, it uses Fermat's little theorem and multiplies by
    /// `gamma^(p - 1 - a) mod p`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &ElGamalCiphertext) -> BigUint {
        let exponent = self.p.sub_ref(&BigUint::one()).sub_ref(&self.a);
        let factor = mod_pow(&ciphertext.gamma, &exponent, &self.p);
        if let Some(ctx) = MontgomeryCtx::new(&self.p) {
            ctx.mul(&factor, &ciphertext.delta)
        } else {
            BigUint::mod_mul(&factor, &ciphertext.delta, &self.p)
        }
    }

    /// Decrypt a ciphertext back into the big-endian byte string that was
    /// interpreted as the plaintext integer.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> Vec<u8> {
        self.decrypt_raw(ciphertext).to_be_bytes()
    }
}

impl fmt::Debug for ElGamalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElGamalPrivateKey(<redacted>)")
    }
}

impl ElGamalCiphertext {
    /// Return the first ciphertext component.
    #[must_use]
    pub fn gamma(&self) -> &BigUint {
        &self.gamma
    }

    /// Return the second ciphertext component.
    #[must_use]
    pub fn delta(&self) -> &BigUint {
        &self.delta
    }
}

impl ElGamal {
    /// Derive a raw `ElGamal` key pair from explicit parameters.
    ///
    /// Returns `None` if `p` is composite, `r` is not in `[2, p)`, or the
    /// secret exponent is not in `[1, p - 2]`.
    #[must_use]
    pub fn from_secret_exponent(
        prime: &BigUint,
        generator: &BigUint,
        secret: &BigUint,
    ) -> Option<(ElGamalPublicKey, ElGamalPrivateKey)> {
        if !is_probable_prime(prime) {
            return None;
        }
        if generator <= &BigUint::one() || generator >= prime {
            return None;
        }

        let p_minus_one = prime.sub_ref(&BigUint::one());
        if secret.is_zero() || secret >= &p_minus_one {
            return None;
        }

        let public_component = mod_pow(generator, secret, prime);
        Some((
            ElGamalPublicKey {
                p: prime.clone(),
                r: generator.clone(),
                b: public_component,
            },
            ElGamalPrivateKey {
                p: prime.clone(),
                a: secret.clone(),
            },
        ))
    }

    /// Generate a teaching-sized `ElGamal` key pair over a safe-prime field.
    ///
    /// This chooses a probable prime `q`, sets `p = 2q + 1`, accepts only
    /// safe-prime candidates where `p` is also probably prime, then chooses a
    /// generator of the full multiplicative group modulo `p`. The resulting
    /// parameters are suitable for the raw textbook primitive and the minimal
    /// byte-oriented wrapper above.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(ElGamalPublicKey, ElGamalPrivateKey)> {
        if bits < 4 {
            return None;
        }

        loop {
            let q = random_probable_prime(rng, bits - 1)?;
            let prime = q.add_ref(&q).add_ref(&BigUint::one());
            if !is_probable_prime(&prime) {
                continue;
            }

            let generator = find_safe_prime_generator(&prime, &q)?;
            let upper = prime.sub_ref(&BigUint::one());
            let secret = random_nonzero_below(rng, &upper)?;
            if let Some(keypair) = Self::from_secret_exponent(&prime, &generator, &secret) {
                return Some(keypair);
            }
        }
    }
}

fn find_safe_prime_generator(prime: &BigUint, q: &BigUint) -> Option<BigUint> {
    let one = BigUint::one();
    let two = BigUint::from_u64(2);
    let ctx = MontgomeryCtx::new(prime)?;
    let upper = prime.sub_ref(&one);
    let mut candidate = BigUint::from_u64(2);

    while candidate < upper {
        if ctx.pow(&candidate, &two) != one && ctx.pow(&candidate, q) != one {
            return Some(candidate);
        }
        candidate = candidate.add_ref(&one);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::ElGamal;
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(23);
        let r = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &r, &a).expect("valid ElGamal key");
        assert_eq!(public.modulus(), &BigUint::from_u64(23));
        assert_eq!(public.generator(), &BigUint::from_u64(5));
        assert_eq!(public.public_component(), &BigUint::from_u64(17));
        assert_eq!(private.modulus(), &BigUint::from_u64(23));
        assert_eq!(private.exponent(), &BigUint::from_u64(7));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(23);
        let r = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let k = BigUint::from_u64(3);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &r, &a).expect("valid ElGamal key");

        for msg in [0u64, 1, 2, 11, 22] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public
                .encrypt_with_ephemeral(&message, &k)
                .expect("valid ephemeral exponent");
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(23);
        let r = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let k = BigUint::from_u64(3);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &r, &a).expect("valid ElGamal key");
        let message = BigUint::from_u64(11);
        let ciphertext = public
            .encrypt_with_ephemeral(&message, &k)
            .expect("valid ephemeral exponent");
        assert_eq!(ciphertext.gamma(), &BigUint::from_u64(10));
        assert_eq!(ciphertext.delta(), &BigUint::from_u64(16));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let composite = BigUint::from_u64(21);
        let generator = BigUint::from_u64(5);
        let secret = BigUint::from_u64(7);
        assert!(ElGamal::from_secret_exponent(&composite, &generator, &secret).is_none());

        let p = BigUint::from_u64(23);
        assert!(ElGamal::from_secret_exponent(&p, &BigUint::one(), &secret).is_none());
        assert!(ElGamal::from_secret_exponent(&p, &generator, &BigUint::zero()).is_none());
    }

    #[test]
    fn rejects_invalid_ephemeral_exponent() {
        let p = BigUint::from_u64(23);
        let r = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, _) = ElGamal::from_secret_exponent(&p, &r, &a).expect("valid ElGamal key");
        let message = BigUint::from_u64(11);
        assert!(public
            .encrypt_with_ephemeral(&message, &BigUint::zero())
            .is_none());
        assert!(public
            .encrypt_with_ephemeral(&message, &BigUint::from_u64(22))
            .is_none());
    }

    #[test]
    fn generate_teaching_keypair() {
        let mut drbg = CtrDrbgAes256::new(&[0x33; 48]);
        let (public, private) = ElGamal::generate(&mut drbg, 32).expect("ElGamal key generation");
        let message = BigUint::from_u64(42);
        let ciphertext = public
            .encrypt_with_ephemeral(&message, &BigUint::from_u64(3))
            .expect("valid ephemeral exponent");
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn byte_wrapper_roundtrip() {
        let p = BigUint::from_u64(65_537);
        let r = BigUint::from_u64(3);
        let a = BigUint::from_u64(7);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &r, &a).expect("valid ElGamal key");
        let mut drbg = CtrDrbgAes256::new(&[0x44; 48]);
        let message = [0x12, 0x34];
        let ciphertext = public.encrypt(&message, &mut drbg).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), message.to_vec());
    }
}
