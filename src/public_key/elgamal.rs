//! `ElGamal` public-key primitive (Taher `ElGamal`, 1985).
//!
//! This keeps the published `ElGamal` arithmetic map explicit: group
//! parameters plus the multiplicative encrypt/decrypt transform. The wrapper
//! layer adds subgroup-aware key generation and byte-oriented ciphertext
//! serialization while keeping the group arithmetic itself visible and
//! auditable.

use core::fmt;

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{
    generate_prime_order_group, is_probable_prime, mod_pow, random_nonzero_below,
};
use crate::Csprng;

const ELGAMAL_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ELGAMAL PUBLIC KEY";
const ELGAMAL_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ELGAMAL PRIVATE KEY";

/// Public key for the `ElGamal` primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalPublicKey {
    /// Prime modulus `p`.
    p: BigUint,
    /// Exclusive upper bound for the ephemeral exponent.
    ///
    /// Generated keys store the subgroup order `q`. Explicit caller-built
    /// keys fall back to `p - 1`, which is always safe when the subgroup
    /// order is unknown.
    exponent_bound: BigUint,
    /// Generator of the active multiplicative group or subgroup.
    r: BigUint,
    /// Public component `b = r^a mod p`.
    b: BigUint,
}

/// Private key for the `ElGamal` primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct ElGamalPrivateKey {
    /// Prime modulus `p`.
    p: BigUint,
    /// Exponent cycle used during decryption.
    ///
    /// Generated keys store the subgroup order `q`; explicit caller-built
    /// keys conservatively use `p - 1`.
    exponent_modulus: BigUint,
    /// Secret exponent `a`.
    a: BigUint,
}

/// Raw `ElGamal` ciphertext pair `(gamma, delta)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalCiphertext {
    gamma: BigUint,
    delta: BigUint,
}

/// Namespace wrapper for the `ElGamal` construction.
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

    /// Return the exclusive upper bound for the ephemeral exponent.
    ///
    /// For generated keys this is the subgroup order `q`. For keys built from
    /// explicit caller-supplied parameters, the code falls back to `p - 1`
    /// because the subgroup order is not derivable from the inputs alone.
    #[must_use]
    pub fn ephemeral_exclusive_bound(&self) -> &BigUint {
        &self.exponent_bound
    }

    /// Return `b = r^a mod p`.
    #[must_use]
    pub fn public_component(&self) -> &BigUint {
        &self.b
    }

    /// Encrypt with an explicit ephemeral exponent `k`.
    ///
    /// Textbook `ElGamal` uses `k` as the per-message randomizer. This
    /// lower-level entry point keeps it explicit so callers can separate the
    /// arithmetic from the randomness when they need deterministic control.
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

        if ephemeral >= &self.exponent_bound {
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
    /// the ephemeral exponent from `[1, q)` when the public key carries an
    /// explicit subgroup order, and from `[1, p - 1)` otherwise. The encoded
    /// integer must be strictly smaller than `p`, so the practical message
    /// capacity is at most `floor((bits(p) - 1) / 8)` bytes. Callers that need
    /// hybrid encryption or padding should build that on top.
    #[must_use]
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<ElGamalCiphertext> {
        let message_int = BigUint::from_be_bytes(message);
        let ephemeral = random_nonzero_below(rng, &self.exponent_bound)?;
        self.encrypt_with_ephemeral(&message_int, &ephemeral)
    }

    /// Encrypt a byte string and return a serialized ciphertext blob.
    ///
    /// The serialized form is a DER `SEQUENCE` containing the `(gamma, delta)`
    /// pair in order, so the byte-level API stays self-contained without
    /// hiding the two-component `ElGamal` structure.
    #[must_use]
    pub fn encrypt_bytes<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<Vec<u8>> {
        let ciphertext = self.encrypt(message, rng)?;
        Some(ciphertext.to_binary())
    }

    /// Encode the public key in the crate-defined binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.exponent_bound, &self.r, &self.b])
    }

    /// Decode the public key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let exponent_bound = fields.next()?;
        let r = fields.next()?;
        let b = fields.next()?;
        if fields.next().is_some()
            || p <= BigUint::one()
            || exponent_bound <= BigUint::one()
            || r <= BigUint::one()
            || b.is_zero()
        {
            return None;
        }
        Some(Self {
            p,
            exponent_bound,
            r,
            b,
        })
    }

    /// Encode the public key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ELGAMAL_PUBLIC_LABEL, &self.to_binary())
    }

    /// Encode the public key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "ElGamalPublicKey",
            &[
                ("p", &self.p),
                ("exponent-bound", &self.exponent_bound),
                ("generator", &self.r),
                ("public-component", &self.b),
            ],
        )
    }

    /// Decode the public key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(ELGAMAL_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    /// Decode the public key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "ElGamalPublicKey",
            &["p", "exponent-bound", "generator", "public-component"],
            xml,
        )?
        .into_iter();
        let p = fields.next()?;
        let exponent_bound = fields.next()?;
        let r = fields.next()?;
        let b = fields.next()?;
        if fields.next().is_some()
            || p <= BigUint::one()
            || exponent_bound <= BigUint::one()
            || r <= BigUint::one()
            || b.is_zero()
        {
            return None;
        }
        Some(Self {
            p,
            exponent_bound,
            r,
            b,
        })
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

    /// Return the exponent-cycle modulus used during decryption.
    ///
    /// Generated keys store the subgroup order here, so decryption can reduce
    /// the exponent to `q - a`. Caller-supplied keys fall back to `p - 1`,
    /// which is always valid by Fermat's little theorem even when the subgroup
    /// order is unknown.
    #[must_use]
    pub fn exponent_modulus(&self) -> &BigUint {
        &self.exponent_modulus
    }

    /// Decrypt the raw ciphertext.
    ///
    /// This avoids an explicit modular inverse by multiplying `delta` by
    /// `gamma^(q-a)` (or conservatively `gamma^(p-1-a)` when the subgroup
    /// order is unknown). In the generated-key case, `gamma` lives in the
    /// order-`q` subgroup, so `g^q = 1` and
    /// `gamma^(q-a) * delta = g^(k(q-a)) * m * g^(ak) = g^(kq) * m = m`.
    /// In the fallback case, the exponent cycle is `p - 1`, so Fermat's
    /// little theorem gives the same cancellation.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &ElGamalCiphertext) -> BigUint {
        let exponent = self.exponent_modulus.sub_ref(&self.a);
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

    /// Decrypt a byte-encoded ciphertext produced by [`ElGamalPublicKey::encrypt_bytes`].
    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = ElGamalCiphertext::from_binary(ciphertext)?;
        Some(self.decrypt(&ciphertext))
    }

    /// Encode the private key in the crate-defined binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.exponent_modulus, &self.a])
    }

    /// Decode the private key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let exponent_modulus = fields.next()?;
        let a = fields.next()?;
        if fields.next().is_some()
            || p <= BigUint::one()
            || exponent_modulus <= BigUint::one()
            || a.is_zero()
            || a >= exponent_modulus
        {
            return None;
        }
        Some(Self {
            p,
            exponent_modulus,
            a,
        })
    }

    /// Encode the private key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ELGAMAL_PRIVATE_LABEL, &self.to_binary())
    }

    /// Encode the private key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "ElGamalPrivateKey",
            &[
                ("p", &self.p),
                ("exponent-modulus", &self.exponent_modulus),
                ("a", &self.a),
            ],
        )
    }

    /// Decode the private key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(ELGAMAL_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    /// Decode the private key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields =
            xml_unwrap("ElGamalPrivateKey", &["p", "exponent-modulus", "a"], xml)?.into_iter();
        let p = fields.next()?;
        let exponent_modulus = fields.next()?;
        let a = fields.next()?;
        if fields.next().is_some()
            || p <= BigUint::one()
            || exponent_modulus <= BigUint::one()
            || a.is_zero()
            || a >= exponent_modulus
        {
            return None;
        }
        Some(Self {
            p,
            exponent_modulus,
            a,
        })
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

    /// Encode the ciphertext as a DER `SEQUENCE` of `(gamma, delta)`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.gamma, &self.delta])
    }

    /// Decode the ciphertext from the crate's binary `ElGamal` ciphertext form.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let gamma = fields.next()?;
        let delta = fields.next()?;
        if fields.next().is_some() || gamma.is_zero() || delta.is_zero() {
            return None;
        }
        Some(Self { gamma, delta })
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
        // `a = 0` makes `b = r^a = 1`, and `a = p - 1` does the same by
        // Fermat. Both give a trivially useless public key, so the secret must
        // live strictly inside the non-zero exponent range.
        if secret.is_zero() || secret >= &p_minus_one {
            return None;
        }

        let public_component = mod_pow(generator, secret, prime);
        Some((
            ElGamalPublicKey {
                p: prime.clone(),
                exponent_bound: p_minus_one.clone(),
                r: generator.clone(),
                b: public_component,
            },
            ElGamalPrivateKey {
                p: prime.clone(),
                exponent_modulus: p_minus_one,
                a: secret.clone(),
            },
        ))
    }

    /// Generate an `ElGamal` key pair over a prime-order subgroup.
    ///
    /// This chooses a probable-prime subgroup order `q`, searches for a prime
    /// modulus `p = kq + 1`, then derives a generator of the order-`q`
    /// subgroup by raising a random base to the cofactor `k`. That mirrors the
    /// usual DSA/DH parameter-generation shape and avoids the extremely slow
    /// safe-prime search that would insist on `k = 2`.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(ElGamalPublicKey, ElGamalPrivateKey)> {
        let (prime, q, _cofactor, generator) = generate_prime_order_group(rng, bits)?;
        let secret = random_nonzero_below(rng, &q)?;
        let public_component = mod_pow(&generator, &secret, &prime);
        Some((
            ElGamalPublicKey {
                p: prime.clone(),
                exponent_bound: q.clone(),
                r: generator,
                b: public_component,
            },
            ElGamalPrivateKey {
                p: prime,
                exponent_modulus: q,
                a: secret,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{ElGamal, ElGamalPrivateKey, ElGamalPublicKey};
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

    #[test]
    fn generate_rejects_too_few_bits() {
        let mut drbg = CtrDrbgAes256::new(&[0x94; 48]);
        assert!(ElGamal::generate(&mut drbg, 15).is_none());
        assert!(ElGamal::generate(&mut drbg, 16).is_none());
        assert!(ElGamal::generate(&mut drbg, 17).is_none());
        assert!(ElGamal::generate(&mut drbg, 18).is_none());
    }

    #[test]
    fn generate_then_random_encrypt_roundtrip() {
        let mut key_rng = CtrDrbgAes256::new(&[0x53; 48]);
        let mut enc_rng = CtrDrbgAes256::new(&[0x54; 48]);
        let (public, private) =
            ElGamal::generate(&mut key_rng, 32).expect("ElGamal key generation");
        let message = [0x2a];
        let ciphertext = public
            .encrypt(&message, &mut enc_rng)
            .expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), message.to_vec());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let p = BigUint::from_u64(23);
        let r = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, private) = ElGamal::from_secret_exponent(&p, &r, &a).expect("valid key");

        let public_blob = public.to_binary();
        let private_blob = private.to_binary();
        assert_eq!(
            ElGamalPublicKey::from_binary(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            ElGamalPrivateKey::from_binary(&private_blob),
            Some(private.clone())
        );

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(
            ElGamalPublicKey::from_pem(&public_pem),
            Some(public.clone())
        );
        assert_eq!(
            ElGamalPrivateKey::from_pem(&private_pem),
            Some(private.clone())
        );
        assert_eq!(ElGamalPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(ElGamalPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn generated_key_serialization_roundtrip() {
        let mut key_rng = CtrDrbgAes256::new(&[0x63; 48]);
        let mut enc_rng = CtrDrbgAes256::new(&[0x64; 48]);
        let (public, private) =
            ElGamal::generate(&mut key_rng, 32).expect("ElGamal key generation");
        let message = [0x11];

        let public = ElGamalPublicKey::from_binary(&public.to_binary()).expect("public binary");
        let private = ElGamalPrivateKey::from_xml(&private.to_xml()).expect("private XML");
        let ciphertext = public
            .encrypt(&message, &mut enc_rng)
            .expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), message.to_vec());
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let p = BigUint::from_u64(65_537);
        let r = BigUint::from_u64(3);
        let a = BigUint::from_u64(7);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &r, &a).expect("valid ElGamal key");
        let mut drbg = CtrDrbgAes256::new(&[0x45; 48]);
        let message = [0x12, 0x34];
        let ciphertext = public
            .encrypt_bytes(&message, &mut drbg)
            .expect("message fits");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(message.to_vec()));
    }
}
