//! Rabin public-key primitive (Michael O. Rabin, 1979).
//!
//! This mirrors the companion Python code rather than the pure square map:
//! encryption prepends a fixed CRC tag and adds `n / 2` before squaring so the
//! decryptor can distinguish the intended square root among the four CRT roots.

use core::fmt;

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{is_probable_prime, mod_inverse, mod_pow, random_probable_prime};
use crate::Csprng;

const TAG: u32 = 0x7c6d_6a7f;
const RABIN_PUBLIC_LABEL: &str = "CRYPTOGRAPHY RABIN PUBLIC KEY";
const RABIN_PRIVATE_LABEL: &str = "CRYPTOGRAPHY RABIN PRIVATE KEY";

/// Public key for the Rabin primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RabinPublicKey {
    n: BigUint,
}

/// Private key for the Rabin primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct RabinPrivateKey {
    n: BigUint,
    p: BigUint,
    q: BigUint,
}

/// Namespace wrapper for the Rabin construction.
pub struct Rabin;

impl RabinPublicKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Encrypt the raw integer message using the tagged Python variant.
    ///
    /// Returns `None` if the tagged payload would not fit below `n`, since the
    /// matching decryption logic only recovers payloads in that range.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> Option<BigUint> {
        let payload = tagged_payload(message, &self.n)?;
        Some(mod_pow(&payload, &BigUint::from_u64(2), &self.n))
    }

    /// Encrypt a byte string using the tagged Rabin variant.
    #[must_use]
    pub fn encrypt(&self, message: &[u8]) -> Option<BigUint> {
        let message_int = BigUint::from_be_bytes(message);
        self.encrypt_raw(&message_int)
    }

    /// Encrypt a byte string and serialize the ciphertext as bytes.
    ///
    /// The serialized form is the crate's single-`INTEGER` DER payload for
    /// non-RSA public-key ciphertexts.
    #[must_use]
    pub fn encrypt_bytes(&self, message: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = self.encrypt(message)?;
        Some(encode_biguints(&[&ciphertext]))
    }

    /// Encode the public key in the crate-defined binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.n])
    }

    /// Decode the public key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let n = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() {
            return None;
        }
        Some(Self { n })
    }

    /// Encode the public key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(RABIN_PUBLIC_LABEL, &self.to_binary())
    }

    /// Encode the public key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap("RabinPublicKey", &[("n", &self.n)])
    }

    /// Decode the public key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(RABIN_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    /// Decode the public key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("RabinPublicKey", &["n"], xml)?.into_iter();
        let n = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() {
            return None;
        }
        Some(Self { n })
    }
}

impl RabinPrivateKey {
    /// Return the first Rabin prime.
    #[must_use]
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    /// Return the second Rabin prime.
    #[must_use]
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    /// Decrypt the raw Rabin ciphertext and recover the tagged message, if any
    /// of the four square roots carries the embedded CRC tag.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> Option<BigUint> {
        let half = half_modulus(&self.n);
        let tag_modulus = BigUint::from_u64(1u64 << 32);

        let p_exponent = self
            .p
            .add_ref(&BigUint::one())
            .div_rem(&BigUint::from_u64(4))
            .0;
        let q_exponent = self
            .q
            .add_ref(&BigUint::one())
            .div_rem(&BigUint::from_u64(4))
            .0;
        let m_p = mod_pow(ciphertext, &p_exponent, &self.p);
        let m_q = mod_pow(ciphertext, &q_exponent, &self.q);

        let p_coeff = mod_inverse(&self.p, &self.q)?;
        let q_coeff = mod_inverse(&self.q, &self.p)?;
        let (term_from_q, term_from_p) = if let Some(ctx) = MontgomeryCtx::new(&self.n) {
            (
                ctx.mul(&ctx.mul(&p_coeff, &self.p), &m_q),
                ctx.mul(&ctx.mul(&q_coeff, &self.q), &m_p),
            )
        } else {
            (
                BigUint::mod_mul(&BigUint::mod_mul(&p_coeff, &self.p, &self.n), &m_q, &self.n),
                BigUint::mod_mul(&BigUint::mod_mul(&q_coeff, &self.q, &self.n), &m_p, &self.n),
            )
        };

        let x = term_from_q.add_ref(&term_from_p).modulo(&self.n);
        let y = sub_mod(&term_from_q, &term_from_p, &self.n);

        for root in [
            x.clone(),
            neg_mod(&x, &self.n),
            y.clone(),
            neg_mod(&y, &self.n),
        ] {
            if root < half {
                continue;
            }

            let candidate = root.sub_ref(&half);
            if candidate.rem_u64(1u64 << 32) != u64::from(TAG) {
                continue;
            }

            let (message, remainder) = candidate.div_rem(&tag_modulus);
            debug_assert_eq!(remainder, BigUint::from_u64(u64::from(TAG)));
            return Some(message);
        }

        None
    }

    /// Decrypt a ciphertext and recover the original big-endian byte string
    /// if one of the four roots carries the embedded tag.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Option<Vec<u8>> {
        Some(self.decrypt_raw(ciphertext)?.to_be_bytes())
    }

    /// Decrypt a byte-encoded ciphertext produced by [`RabinPublicKey::encrypt_bytes`].
    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut fields = decode_biguints(ciphertext)?.into_iter();
        let value = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        self.decrypt(&value)
    }

    /// Encode the private key in the crate-defined binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.n, &self.p, &self.q])
    }

    /// Decode the private key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let n = fields.next()?;
        let p = fields.next()?;
        let q = fields.next()?;
        if fields.next().is_some()
            || n <= BigUint::one()
            || p <= BigUint::one()
            || q <= BigUint::one()
        {
            return None;
        }
        Some(Self { n, p, q })
    }

    /// Encode the private key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(RABIN_PRIVATE_LABEL, &self.to_binary())
    }

    /// Encode the private key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "RabinPrivateKey",
            &[("n", &self.n), ("p", &self.p), ("q", &self.q)],
        )
    }

    /// Decode the private key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(RABIN_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    /// Decode the private key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("RabinPrivateKey", &["n", "p", "q"], xml)?.into_iter();
        let n = fields.next()?;
        let p = fields.next()?;
        let q = fields.next()?;
        if fields.next().is_some()
            || n <= BigUint::one()
            || p <= BigUint::one()
            || q <= BigUint::one()
        {
            return None;
        }
        Some(Self { n, p, q })
    }
}

impl fmt::Debug for RabinPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RabinPrivateKey(<redacted>)")
    }
}

impl Rabin {
    /// Derive a raw Rabin key pair from explicit Rabin primes.
    ///
    /// Returns `None` unless `p` and `q` are distinct primes congruent to `3`
    /// modulo `4`, which is the condition that makes the square-root shortcut
    /// `(c^((p + 1) / 4) mod p)` valid during decryption.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(RabinPublicKey, RabinPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }
        if p.rem_u64(4) != 3 || q.rem_u64(4) != 3 {
            return None;
        }

        let n = p.mul_ref(q);

        Some((
            RabinPublicKey { n: n.clone() },
            RabinPrivateKey {
                n,
                p: p.clone(),
                q: q.clone(),
            },
        ))
    }

    /// Generate a Rabin key pair with primes congruent to `3` modulo `4`.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(RabinPublicKey, RabinPrivateKey)> {
        // With fewer than 8 total bits the split can collapse to the same tiny
        // Blum prime on both sides, so a distinct-prime key may never be
        // found.
        if bits < 8 {
            return None;
        }

        let p_bits = bits / 2;
        let q_bits = bits - p_bits;
        loop {
            let p = random_rabin_prime(rng, p_bits)?;
            let q = random_rabin_prime(rng, q_bits)?;
            if let Some(keypair) = Self::from_primes(&p, &q) {
                return Some(keypair);
            }
        }
    }
}

fn random_rabin_prime<R: Csprng>(rng: &mut R, bits: usize) -> Option<BigUint> {
    loop {
        let candidate = random_probable_prime(rng, bits)?;
        if candidate.rem_u64(4) == 3 {
            return Some(candidate);
        }
    }
}

fn tagged_payload(message: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let half = half_modulus(modulus);
    let tag_modulus = BigUint::from_u64(1u64 << 32);
    let tag = BigUint::from_u64(u64::from(TAG));
    let payload = message.mul_ref(&tag_modulus).add_ref(&tag).add_ref(&half);
    if &payload >= modulus {
        None
    } else {
        Some(payload)
    }
}

fn half_modulus(modulus: &BigUint) -> BigUint {
    modulus.div_rem(&BigUint::from_u64(2)).0
}

fn neg_mod(value: &BigUint, modulus: &BigUint) -> BigUint {
    if value.is_zero() {
        BigUint::zero()
    } else {
        modulus.sub_ref(value)
    }
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs.sub_ref(rhs)
    } else {
        modulus.sub_ref(&rhs.sub_ref(lhs))
    }
}

#[cfg(test)]
mod tests {
    use super::{Rabin, RabinPrivateKey, RabinPublicKey};
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

    fn reference_primes() -> (BigUint, BigUint) {
        (BigUint::from_u64(131_071), BigUint::from_u64(131_111))
    }

    #[test]
    fn derive_reference_key() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        assert_eq!(public.modulus(), &BigUint::from_u128(17_184_849_881));
        assert_eq!(private.p(), &BigUint::from_u64(131_071));
        assert_eq!(private.q(), &BigUint::from_u64(131_111));
    }

    #[test]
    fn roundtrip_small_messages() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");

        for msg in [0u64, 1] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message).expect("message fits");
            let plaintext = private
                .decrypt_raw(&ciphertext)
                .expect("tagged root exists");
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let message = BigUint::from_u64(1);
        let ciphertext = public.encrypt_raw(&message).expect("message fits");
        assert_eq!(ciphertext, BigUint::from_u64(7_234_315_345));
        assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
    }

    #[test]
    fn rejects_message_that_does_not_fit_tagged_payload() {
        let (p, q) = reference_primes();
        let (public, _) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        assert!(public.encrypt_raw(&BigUint::from_u64(2)).is_none());
    }

    #[test]
    fn rejects_invalid_primes() {
        let p = BigUint::from_u64(13);
        let q = BigUint::from_u64(19);
        assert!(Rabin::from_primes(&p, &q).is_none());

        let p = BigUint::from_u64(131_071);
        let composite = BigUint::from_u64(21);
        assert!(Rabin::from_primes(&p, &composite).is_none());
    }

    #[test]
    fn byte_wrapper_roundtrip() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let ciphertext = public.encrypt(&[0x01]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x01]));
    }

    #[test]
    fn generate_teaching_keypair() {
        let mut drbg = CtrDrbgAes256::new(&[0x61; 48]);
        let (public, private) = Rabin::generate(&mut drbg, 48).expect("Rabin key generation");
        let ciphertext = public.encrypt(&[0x00]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x00]));
    }

    #[test]
    fn generate_rejects_too_few_bits() {
        let mut drbg = CtrDrbgAes256::new(&[0x92; 48]);
        assert!(Rabin::generate(&mut drbg, 7).is_none());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0xa2; 48]);
        let (public, private) = Rabin::generate(&mut drbg, 48).expect("Rabin key generation");

        let public_blob = public.to_binary();
        let private_blob = private.to_binary();
        assert_eq!(
            RabinPublicKey::from_binary(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            RabinPrivateKey::from_binary(&private_blob),
            Some(private.clone())
        );

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(RabinPublicKey::from_pem(&public_pem), Some(public.clone()));
        assert_eq!(
            RabinPrivateKey::from_pem(&private_pem),
            Some(private.clone())
        );
        assert_eq!(RabinPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(RabinPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let ciphertext = public.encrypt_bytes(&[0x01]).expect("message fits");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(vec![0x01]));
    }
}
