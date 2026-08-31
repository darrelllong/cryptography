//! Rabin public-key primitive (Michael O. Rabin, 1979).
//!
//! This uses the tagged/disambiguated variant rather than the pure square map:
//! encryption prepends a fixed disambiguation tag and adds `n / 2` before
//! squaring so the decryptor can distinguish the intended square root among
//! the four CRT roots.

use core::fmt;

use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::public_key::primes::{is_probable_prime_untrusted, random_probable_prime};
use crate::Csprng;
use rump::modular::{mod_inverse, mod_pow, MontgomeryContext};
use rump::BigUint;

// Arbitrary 32-bit disambiguation tag. It is not a checksum; it is just a
// recognizable marker carried inside the encoded plaintext so decryption can
// identify the intended root.
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
    p_exponent: BigUint,
    q_exponent: BigUint,
    p_coeff: Option<BigUint>,
    q_coeff: Option<BigUint>,
    p_ctx: Option<MontgomeryContext>,
    q_ctx: Option<MontgomeryContext>,
    n_ctx: Option<MontgomeryContext>,
    half_n: BigUint,
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

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.n.clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        if n <= BigUint::one() {
            return None;
        }
        Some(Self { n })
    }
}

crate::public_key::io::impl_xml_serialization!(RabinPublicKey, "RabinPublicKey", ["n"]);
crate::public_key::io::impl_blob_pem_serialization!(RabinPublicKey, RABIN_PUBLIC_LABEL, ["n"]);

impl RabinPrivateKey {
    fn from_components(n: BigUint, p: BigUint, q: BigUint) -> Self {
        let p_exponent = p.add(&BigUint::one()).div_rem(&BigUint::from_u64(4)).0;
        let q_exponent = q.add(&BigUint::one()).div_rem(&BigUint::from_u64(4)).0;
        let p_coeff = mod_inverse(&p, &q);
        let q_coeff = mod_inverse(&q, &p);
        let p_ctx = MontgomeryContext::new(&p).ok();
        let q_ctx = MontgomeryContext::new(&q).ok();
        let n_ctx = MontgomeryContext::new(&n).ok();
        let half_n = half_modulus(&n);
        Self {
            n,
            p,
            q,
            p_exponent,
            q_exponent,
            p_coeff,
            q_coeff,
            p_ctx,
            q_ctx,
            n_ctx,
            half_n,
        }
    }

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
    /// of the four square roots carries the embedded disambiguation tag.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> Option<BigUint> {
        let tag_modulus = BigUint::from_u64(1u64 << 32);
        let m_p = if let Some(ctx) = &self.p_ctx {
            ctx.pow(ciphertext, &self.p_exponent)
        } else {
            mod_pow(ciphertext, &self.p_exponent, &self.p)
        };
        let m_q = if let Some(ctx) = &self.q_ctx {
            ctx.pow(ciphertext, &self.q_exponent)
        } else {
            mod_pow(ciphertext, &self.q_exponent, &self.q)
        };

        let p_coeff = self.p_coeff.as_ref()?;
        let q_coeff = self.q_coeff.as_ref()?;
        // Standard CRT lifting: rebuild the root that is congruent to `m_p`
        // modulo `p` and to `m_q` modulo `q`.
        // Valid Rabin keys always have an odd modulus, so the Montgomery path
        // is the normal case here.
        let ctx = self.n_ctx.as_ref()?;
        let term_from_q = ctx.mul(&ctx.mul(p_coeff, &self.p), &m_q);
        let term_from_p = ctx.mul(&ctx.mul(q_coeff, &self.q), &m_p);

        let x = term_from_q.add(&term_from_p).rem(&self.n);
        let y = sub_mod(&term_from_q, &term_from_p, &self.n);

        for root in [
            x.clone(),
            neg_mod(&x, &self.n),
            y.clone(),
            neg_mod(&y, &self.n),
        ] {
            // The encoder added `n / 2`, so the intended root is the one that
            // lands in the upper half of the residue range.
            if root < self.half_n {
                continue;
            }

            let candidate = root.sub(&self.half_n);
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

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.n.clone(), self.p.clone(), self.q.clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        let p = fields.next()?;
        let q = fields.next()?;
        if n <= BigUint::one() || p <= BigUint::one() || q <= BigUint::one() {
            return None;
        }
        if p.mul(&q) != n {
            return None;
        }
        Some(Self::from_components(n, p, q))
    }
}

crate::public_key::io::impl_xml_serialization!(RabinPrivateKey, "RabinPrivateKey", ["n", "p", "q"]);
crate::public_key::io::impl_blob_pem_serialization!(
    RabinPrivateKey,
    RABIN_PRIVATE_LABEL,
    ["n", "p", "q"]
);

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
        if p == q || !is_probable_prime_untrusted(p) || !is_probable_prime_untrusted(q) {
            return None;
        }
        if p.rem_u64(4) != 3 || q.rem_u64(4) != 3 {
            return None;
        }

        let n = p.mul(q);

        Some((
            RabinPublicKey { n: n.clone() },
            RabinPrivateKey::from_components(n, p.clone(), q.clone()),
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
    // Encode `message || tag` and then shift by `n / 2` so the intended root
    // always lands in the upper half of the residue space.
    let payload = message.mul(&tag_modulus).add(&tag).add(&half);
    if &payload >= modulus {
        None
    } else {
        Some(payload)
    }
}

fn half_modulus(modulus: &BigUint) -> BigUint {
    // The encoder shifts by `n / 2`, and decryption keeps only roots in the
    // upper half `[n/2, n)`, so `n / 2` is the threshold that makes the
    // disambiguation work.
    modulus.div_rem(&BigUint::from_u64(2)).0
}

fn neg_mod(value: &BigUint, modulus: &BigUint) -> BigUint {
    if value.is_zero() {
        BigUint::zero()
    } else {
        modulus.sub(value)
    }
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs.sub(rhs)
    } else {
        modulus.sub(&rhs.sub(lhs))
    }
}

#[cfg(test)]
mod tests {
    use super::{Rabin, RabinPrivateKey, RabinPublicKey};
    use crate::public_key::io::encode_biguints;
    use crate::CtrDrbgAes256;
    use rump::BigUint;

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
    fn generate_keypair_roundtrip() {
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

        let public_blob = public.to_key_blob();
        let private_blob = private.to_key_blob();
        assert_eq!(
            RabinPublicKey::from_key_blob(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            RabinPrivateKey::from_key_blob(&private_blob),
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

    #[test]
    fn rejects_malformed_serialized_private_key() {
        let bogus_n = BigUint::from_u64(95);
        let p = BigUint::from_u64(7);
        let q = BigUint::from_u64(13);
        let blob = encode_biguints(&[&bogus_n, &p, &q]);
        assert!(RabinPrivateKey::from_key_blob(&blob).is_none());
    }
}
