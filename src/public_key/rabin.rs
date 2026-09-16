//! Rabin public-key primitive (Michael O. Rabin, 1979).
//!
//! The square map `c = m² mod n` has four preimages, so the encoder makes
//! the intended one recognizable: the plaintext integer is shifted up by
//! 128 bits and a fixed 128-bit tag is placed in the freed low bits (the
//! tag is appended, not prepended), and `⌊n/2⌋` is added so that the
//! intended root lies in the upper half of `[0, n)`. The decryptor computes
//! the four CRT roots and returns the message from the first one that lies
//! in the upper half and carries the tag.
//!
//! Security notes, the same ones that apply to textbook RSA:
//!
//! - **Deterministic.** Equal messages give equal ciphertexts, so the scheme
//!   is not IND-CPA; a ciphertext can be tested against a guessed message
//!   with one public operation. Nothing here plays the role OAEP plays for
//!   RSA.
//! - **No chosen-ciphertext protection.** Rabin's trapdoor is equivalent to
//!   factoring, and that cuts both ways: a decryptor that returns a square
//!   root of an attacker-chosen square other than the one the attacker
//!   started from reveals a factor of `n` through a gcd. The tag is what
//!   keeps the decryptor from doing so, and only probabilistically: a
//!   wrong root carries the tag with probability about `2^-128` per root,
//!   so an adversary with a decryption oracle expects on the order of
//!   `2^126` queries before one leaks a factor. Do not expose decryption
//!   of arbitrary ciphertexts.
//!
//! The private square-root exponents `(p + 1)/4` and `(q + 1)/4` drive
//! rump's variable-time exponentiation, whose sequence of squarings and
//! multiplications is the exponent's window pattern; an adversary who
//! observes it (a co-resident process reading the cache or branch
//! predictor, a probe on the power rail) learns `p` and `q`.

use core::fmt;

use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::public_key::primes::{is_probable_prime_untrusted, random_probable_prime};
use crate::Csprng;
use rump::modular::{mod_inverse, mod_pow, MontgomeryContext};
use rump::BigUint;

/// Width in bits of the disambiguation tag: the low `TAG_BITS` bits of the
/// encoded plaintext. 128 bits put the chance that a wrong square root also
/// carries the tag at about `2^-128`, the level the module documentation
/// relies on.
const TAG_BITS: usize = 128;

/// The 128-bit disambiguation tag: the first 128 bits of
/// `SHA-256("cryptography-rs Rabin redundancy tag")`. It is not a checksum;
/// it is a fixed marker in the low bits of the encoded plaintext that lets
/// decryption pick out the intended root. Any fixed value serves, and a
/// hash of a public sentence is one nobody chose for a hidden property.
const TAG: u128 = 0xc95f_fbc2_7cf3_7650_8327_a231_ece9_352a;
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

    /// Encrypt the raw integer message: `c = (m · 2^128 + TAG + ⌊n/2⌋)² mod n`.
    ///
    /// Deterministic — equal messages give equal ciphertexts (see the module
    /// documentation). Returns `None` if the tagged payload would not fit
    /// below `n`, since the matching decryption logic only recovers payloads
    /// in that range: `m` must be below roughly `n / 2^129`.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> Option<BigUint> {
        let payload = tagged_payload(message, &self.n)?;
        Some(mod_pow(&payload, &BigUint::from_u64(2), &self.n))
    }

    /// Encrypt a byte string, read as a big-endian integer, with
    /// [`Self::encrypt_raw`]. Leading zero octets do not survive the trip
    /// through the integer; see [`RabinPrivateKey::decrypt`].
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
    ///
    /// Structural validation (public material): `n` is the product of two
    /// Blum primes (`p ≡ q ≡ 3 (mod 4)`), so `n ≡ 1 (mod 4)` and `n ≥ 21`.
    /// Compositeness is not tested; a prime `n` breaks only its owner's key.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        if n < BigUint::from_u64(21) || n.rem_u64(4) != 1 {
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

    /// Decrypt the raw Rabin ciphertext: compute the four square roots of
    /// `c` modulo `n` and return the message carried by the first root, in
    /// the fixed order `x, −x, y, −y`, that lies in `[⌊n/2⌋, n)` and has the
    /// tag in its low 128 bits after `⌊n/2⌋` is removed. For a ciphertext
    /// made by [`RabinPublicKey::encrypt_raw`] the intended root is the only
    /// one that qualifies except with probability about `2^-126`; if a
    /// second root also qualified, whichever comes first in that order
    /// would be returned. `None` when no root qualifies.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> Option<BigUint> {
        let tag = BigUint::from_u128(TAG);
        let mut tag_modulus = BigUint::one();
        tag_modulus.shl_bits(TAG_BITS);
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
        let y = BigUint::mod_sub(&term_from_q, &term_from_p, &self.n);

        for root in [
            x.clone(),
            BigUint::mod_neg(&x, &self.n),
            y.clone(),
            BigUint::mod_neg(&y, &self.n),
        ] {
            // The encoder added `n / 2`, so the intended root is the one that
            // lands in the upper half of the residue range.
            if root < self.half_n {
                continue;
            }

            let candidate = root.sub(&self.half_n);
            let (message, low_bits) = candidate.div_rem(&tag_modulus);
            if low_bits == tag {
                return Some(message);
            }
        }

        None
    }

    /// Decrypt a ciphertext with [`Self::decrypt_raw`] and return the
    /// recovered integer's minimal big-endian encoding: no leading zero
    /// octets, and `0x00` alone for the integer zero. A message that began
    /// with zero octets, or was empty, therefore comes back without them.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Option<Vec<u8>> {
        Some(self.decrypt_raw(ciphertext)?.to_be_bytes())
    }

    /// Decrypt a byte-encoded ciphertext produced by
    /// [`RabinPublicKey::encrypt_bytes`]; the plaintext bytes are those of
    /// [`Self::decrypt`].
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
    ///
    /// Full validation (private material): exactly what
    /// [`Rabin::from_primes`] requires — distinct hardened probable primes
    /// congruent to `3 (mod 4)` — plus `n = p·q`; every derived value
    /// (square-root exponents, CRT coefficients, `n/2`) is recomputed.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        let p = fields.next()?;
        let q = fields.next()?;
        let (_, private) = Rabin::from_primes(&p, &q)?;
        if private.n != n {
            return None;
        }
        Some(private)
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
    /// Smallest modulus width [`Self::generate`] accepts. Two `bits/2`-bit
    /// primes give `n ≥ 2^(bits − 2)`, so the payload room `n − ⌊n/2⌋` is at
    /// least `2^(bits − 3)`; a one-octet message needs `2^136` of it, hence
    /// 140.
    pub const MIN_GENERATED_BITS: usize = 140;

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
    ///
    /// `bits` must be at least [`Self::MIN_GENERATED_BITS`]: below that the
    /// 128-bit tag plus `⌊n/2⌋` can leave no room under `n` for even a
    /// one-octet message.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(RabinPublicKey, RabinPrivateKey)> {
        if bits < Self::MIN_GENERATED_BITS {
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

/// `m · 2^128 + TAG + ⌊n/2⌋`: the message with the tag appended in its low
/// 128 bits, shifted into the upper half of `[0, n)`. `None` if that is not
/// below `n`.
fn tagged_payload(message: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let half = half_modulus(modulus);
    let mut tag_modulus = BigUint::one();
    tag_modulus.shl_bits(TAG_BITS);
    let tag = BigUint::from_u128(TAG);
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

#[cfg(test)]
mod tests {
    use super::{Rabin, RabinPrivateKey, RabinPublicKey};
    use crate::public_key::io::encode_biguints;
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    /// The Mersenne primes `2^89 − 1` and `2^107 − 1`, both `≡ 3 (mod 4)`
    /// as every Mersenne prime above 3 is; `n` is 196 bits, which leaves
    /// room under `n` for messages below `2^67` beside the 128-bit tag.
    fn reference_primes() -> (BigUint, BigUint) {
        let mersenne = |e: usize| {
            let mut m = BigUint::one();
            m.shl_bits(e);
            m.sub(&BigUint::one())
        };
        (mersenne(89), mersenne(107))
    }

    #[test]
    fn derive_reference_key() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        assert_eq!(public.modulus(), &p.mul(&q));
        assert_eq!(public.modulus().bits(), 196);
        assert_eq!(private.p(), &p);
        assert_eq!(private.q(), &q);
    }

    #[test]
    fn roundtrip_small_messages() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");

        for msg in [0u64, 1, 2, 255, u64::MAX] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message).expect("message fits");
            let plaintext = private
                .decrypt_raw(&ciphertext)
                .expect("tagged root exists");
            assert_eq!(plaintext, message);
        }
    }

    /// `((1 · 2^128 + TAG + ⌊n/2⌋)² mod n` for the reference key, computed
    /// with integer arithmetic outside this crate.
    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let message = BigUint::from_u64(1);
        let ciphertext = public.encrypt_raw(&message).expect("message fits");
        assert_eq!(
            ciphertext,
            BigUint::from_be_bytes(&crate::test_utils::decode_hex(
                "4c02cf7787ec754daee5117bd67c90fa2c60310bc15466dc"
            ))
        );
        assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
        let zero = public.encrypt_raw(&BigUint::zero()).expect("message fits");
        assert_eq!(
            zero,
            BigUint::from_be_bytes(&crate::test_utils::decode_hex(
                "0f45b389ca4dcbf07ecacf7c9e407c90fa558c308410f2d5a7"
            ))
        );
    }

    /// The payload `m · 2^128 + TAG + ⌊n/2⌋` must stay below `n`: for the
    /// 196-bit reference key that admits `m < 2^67` and no more.
    #[test]
    fn rejects_message_that_does_not_fit_tagged_payload() {
        let (p, q) = reference_primes();
        let (public, _) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let mut too_large = BigUint::one();
        too_large.shl_bits(67);
        assert!(public.encrypt_raw(&too_large).is_none());
        let mut fits = BigUint::one();
        fits.shl_bits(66);
        assert!(public.encrypt_raw(&fits).is_some());
    }

    /// The tag is appended: the low 128 bits of the shifted payload. A root
    /// whose low bits differ from the tag by one bit is not accepted, which
    /// is what a ciphertext of the wrong tag exercises.
    #[test]
    fn decrypt_rejects_a_payload_with_the_wrong_tag() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let n = public.modulus();
        let half = n.div_rem(&BigUint::from_u64(2)).0;
        let mut shifted = BigUint::from_u64(5);
        shifted.shl_bits(128);
        let good = shifted.add(&BigUint::from_u128(super::TAG)).add(&half);
        let bad = shifted.add(&BigUint::from_u128(super::TAG ^ 1)).add(&half);
        let square = |x: &BigUint| rump::modular::mod_pow(x, &BigUint::from_u64(2), n);
        assert_eq!(
            private.decrypt_raw(&square(&good)),
            Some(BigUint::from_u64(5))
        );
        assert_eq!(private.decrypt_raw(&square(&bad)), None);
        // Textbook Rabin without the shift: a root in the lower half is
        // never taken even when it carries the tag.
        let unshifted = shifted.add(&BigUint::from_u128(super::TAG));
        assert_eq!(private.decrypt_raw(&square(&unshifted)), None);
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

    /// Bytes go through the integer: leading zero octets are dropped and the
    /// zero message comes back as one `0x00` octet.
    #[test]
    fn byte_wrapper_roundtrip() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let ciphertext = public.encrypt(&[0x01]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x01]));
        let ciphertext = public.encrypt(&[0x00, 0x00, 0x2a]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x2a]));
        let ciphertext = public.encrypt(&[]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x00]));
    }

    /// At the minimum generated size a one-octet message always fits.
    #[test]
    fn generate_keypair_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0x61; 48]);
        let (public, private) =
            Rabin::generate(&mut drbg, Rabin::MIN_GENERATED_BITS).expect("Rabin key generation");
        let ciphertext = public.encrypt(&[0xff]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0xff]));
        let ciphertext = public.encrypt(&[0x00]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x00]));
    }

    #[test]
    fn generate_rejects_too_few_bits() {
        let mut drbg = CtrDrbgAes256::new(&[0x92; 48]);
        assert!(Rabin::generate(&mut drbg, Rabin::MIN_GENERATED_BITS - 1).is_none());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0xa2; 48]);
        let (public, private) = Rabin::generate(&mut drbg, 160).expect("Rabin key generation");

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
        let u = BigUint::from_u64;
        // p = 7, q = 11 are Blum primes: n = 77.
        assert!(
            RabinPrivateKey::from_key_blob(&encode_biguints(&[&u(77), &u(7), &u(11)])).is_some()
        );
        for (n, p, q) in [
            (95, 7, 13),  // n != p * q
            (91, 7, 13),  // q ≡ 1 (mod 4)
            (49, 7, 7),   // p == q
            (105, 15, 7), // composite "prime" 15 ≡ 3 (mod 4)
            (77, 77, 1),  // q = 1
        ] {
            let blob = encode_biguints(&[&u(n), &u(p), &u(q)]);
            assert!(
                RabinPrivateKey::from_key_blob(&blob).is_none(),
                "{n} {p} {q}"
            );
        }
    }

    #[test]
    fn public_key_parse_rejects_non_blum_modulus() {
        let u = BigUint::from_u64;
        assert!(RabinPublicKey::from_key_blob(&encode_biguints(&[&u(77)])).is_some());
        // Even, ≡ 3 (mod 4), and below the smallest product of two Blum primes.
        for n in [78u64, 79, 15, 1, 0] {
            assert!(
                RabinPublicKey::from_key_blob(&encode_biguints(&[&u(n)])).is_none(),
                "{n}"
            );
        }
    }
}
