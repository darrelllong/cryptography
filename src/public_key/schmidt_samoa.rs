//! Schmidt-Samoa public-key primitive (Katja Schmidt-Samoa, 2005).
//!
//! This keeps the Schmidt-Samoa arithmetic map explicit: prime inputs, public
//! modulus `n = p^2 q`, and private decryption exponent modulo `gamma = p q`.
//! On top of that arithmetic core, the byte helpers serialize ciphertexts as
//! single-field DER `INTEGER` payloads so the scheme can be used directly on
//! byte strings.

use core::fmt;

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{
    is_probable_prime, lcm, mod_inverse, mod_pow, random_probable_prime,
};
use crate::Csprng;

const SCHMIDT_SAMOA_PUBLIC_LABEL: &str = "CRYPTOGRAPHY SCHMIDT-SAMOA PUBLIC KEY";
const SCHMIDT_SAMOA_PRIVATE_LABEL: &str = "CRYPTOGRAPHY SCHMIDT-SAMOA PRIVATE KEY";

/// Public key for the Schmidt-Samoa primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchmidtSamoaPublicKey {
    n: BigUint,
    n_ctx: Option<MontgomeryCtx>,
}

/// Private key for the Schmidt-Samoa primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct SchmidtSamoaPrivateKey {
    d: BigUint,
    gamma: BigUint,
    gamma_ctx: Option<MontgomeryCtx>,
}

/// Namespace wrapper for the Schmidt-Samoa construction.
pub struct SchmidtSamoa;

impl SchmidtSamoaPublicKey {
    /// Return the public modulus `n = p^2 q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return a conservative public upper bound for byte-oriented plaintexts.
    ///
    /// For `n = p^2 q`, the private reduction modulus `gamma = p q` always
    /// satisfies `gamma > floor(sqrt(n))`, so any message below this bound is
    /// guaranteed to round-trip through the private map.
    #[must_use]
    pub fn max_plaintext_exclusive(&self) -> BigUint {
        self.n.sqrt_floor()
    }

    /// Apply the raw public map `m^n mod n`.
    ///
    /// Unlike textbook RSA, the public exponent is the modulus `n` itself.
    /// The inverse map recovers the original message only for values
    /// interpreted in the range `[0, gamma)`, where `gamma = p q`.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> BigUint {
        if let Some(ctx) = &self.n_ctx {
            ctx.pow(message, &self.n)
        } else {
            mod_pow(message, &self.n, &self.n)
        }
    }

    /// Encrypt a byte string using the conservative public plaintext bound.
    #[must_use]
    pub fn encrypt(&self, message: &[u8]) -> Option<BigUint> {
        let message_int = BigUint::from_be_bytes(message);
        if message_int >= self.max_plaintext_exclusive() {
            return None;
        }
        Some(self.encrypt_raw(&message_int))
    }

    /// Encrypt a byte string and return the serialized ciphertext bytes.
    #[must_use]
    pub fn encrypt_bytes(&self, message: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = self.encrypt(message)?;
        Some(encode_biguints(&[&ciphertext]))
    }

    /// Encode the public key in the crate-defined binary format.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.n])
    }

    /// Decode the public key from the crate-defined binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let n = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() {
            return None;
        }
        let n_ctx = MontgomeryCtx::new(&n);
        Some(Self { n, n_ctx })
    }

    /// Encode the public key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(SCHMIDT_SAMOA_PUBLIC_LABEL, &self.to_key_blob())
    }

    /// Encode the public key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap("SchmidtSamoaPublicKey", &[("n", &self.n)])
    }

    /// Decode the public key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(SCHMIDT_SAMOA_PUBLIC_LABEL, pem)?;
        Self::from_key_blob(&blob)
    }

    /// Decode the public key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("SchmidtSamoaPublicKey", &["n"], xml)?.into_iter();
        let n = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() {
            return None;
        }
        let n_ctx = MontgomeryCtx::new(&n);
        Some(Self { n, n_ctx })
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
    ///
    /// This recovers the original message only for plaintexts represented in
    /// the range `[0, gamma)`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        if let Some(ctx) = &self.gamma_ctx {
            ctx.pow(ciphertext, &self.d)
        } else {
            mod_pow(ciphertext, &self.d, &self.gamma)
        }
    }

    /// Decrypt a ciphertext back into the big-endian byte string that was
    /// interpreted as the plaintext integer.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Vec<u8> {
        self.decrypt_raw(ciphertext).to_be_bytes()
    }

    /// Decrypt a byte-encoded ciphertext produced by [`SchmidtSamoaPublicKey::encrypt_bytes`].
    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut fields = decode_biguints(ciphertext)?.into_iter();
        let value = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        Some(self.decrypt(&value))
    }

    /// Encode the private key in the crate-defined binary format.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.d, &self.gamma])
    }

    /// Decode the private key from the crate-defined binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let d = fields.next()?;
        let gamma = fields.next()?;
        if fields.next().is_some() || d.is_zero() || gamma <= BigUint::one() {
            return None;
        }
        let gamma_ctx = MontgomeryCtx::new(&gamma);
        Some(Self {
            d,
            gamma,
            gamma_ctx,
        })
    }

    /// Encode the private key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(SCHMIDT_SAMOA_PRIVATE_LABEL, &self.to_key_blob())
    }

    /// Encode the private key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "SchmidtSamoaPrivateKey",
            &[("d", &self.d), ("gamma", &self.gamma)],
        )
    }

    /// Decode the private key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(SCHMIDT_SAMOA_PRIVATE_LABEL, pem)?;
        Self::from_key_blob(&blob)
    }

    /// Decode the private key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("SchmidtSamoaPrivateKey", &["d", "gamma"], xml)?.into_iter();
        let d = fields.next()?;
        let gamma = fields.next()?;
        if fields.next().is_some() || d.is_zero() || gamma <= BigUint::one() {
            return None;
        }
        let gamma_ctx = MontgomeryCtx::new(&gamma);
        Some(Self {
            d,
            gamma,
            gamma_ctx,
        })
    }
}

impl fmt::Debug for SchmidtSamoaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SchmidtSamoaPrivateKey(<redacted>)")
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
        // This explicit divisibility check is equivalent to the later
        // `mod_inverse(...)?` failure, but keeping it here makes the Python
        // parameter restriction visible at the key-derivation boundary.
        if q_minus_one.modulo(p).is_zero() || p_minus_one.modulo(q).is_zero() {
            return None;
        }

        let gamma = p.mul_ref(q);
        let lambda = lcm(&p_minus_one, &q_minus_one);
        let p_squared = p.mul_ref(p);
        let n = p_squared.mul_ref(q);
        let d = mod_inverse(&n, &lambda)?;

        let n_ctx = MontgomeryCtx::new(&n);
        let gamma_ctx = MontgomeryCtx::new(&gamma);
        Some((
            SchmidtSamoaPublicKey { n, n_ctx },
            SchmidtSamoaPrivateKey {
                d,
                gamma,
                gamma_ctx,
            },
        ))
    }

    /// Generate a Schmidt-Samoa key pair.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(SchmidtSamoaPublicKey, SchmidtSamoaPrivateKey)> {
        // The split is roughly `bits / 3` for `p`, so tiny bit sizes can
        // collapse to the same minimal prime and never yield a valid pair.
        if bits < 8 {
            return None;
        }

        let p_bits = bits / 3;
        let q_bits = bits.saturating_sub(2 * p_bits);
        let p_bits = p_bits.max(2);
        let q_bits = q_bits.max(2);
        loop {
            let p = random_probable_prime(rng, p_bits)?;
            let q = random_probable_prime(rng, q_bits)?;
            if let Some(keypair) = Self::from_primes(&p, &q) {
                return Some(keypair);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SchmidtSamoa, SchmidtSamoaPrivateKey, SchmidtSamoaPublicKey};
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");
        assert_eq!(public.modulus(), &BigUint::from_u64(45));
        // With p = 3 and q = 5, n = 45 ≡ 1 (mod lcm(2, 4)), so the modular
        // inverse used for the private exponent collapses to d = 1.
        assert_eq!(private.exponent(), &BigUint::from_u64(1));
        assert_eq!(private.gamma(), &BigUint::from_u64(15));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");

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
        let (public, private) = SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");
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

        let p = BigUint::from_u64(5);
        assert!(SchmidtSamoa::from_primes(&p, &p).is_none());
    }

    #[test]
    fn byte_wrapper_roundtrip() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");
        let ciphertext = public.encrypt(&[0x05]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), vec![0x05]);
    }

    #[test]
    fn generate_keypair_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0x71; 48]);
        let (public, private) =
            SchmidtSamoa::generate(&mut drbg, 48).expect("Schmidt-Samoa key generation");
        let ciphertext = public.encrypt(&[0x2a]).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), vec![0x2a]);
    }

    #[test]
    fn generate_rejects_too_few_bits() {
        let mut drbg = CtrDrbgAes256::new(&[0x93; 48]);
        assert!(SchmidtSamoa::generate(&mut drbg, 7).is_none());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0xb3; 48]);
        let (public, private) =
            SchmidtSamoa::generate(&mut drbg, 48).expect("Schmidt-Samoa key generation");

        let public_blob = public.to_key_blob();
        let private_blob = private.to_key_blob();
        assert_eq!(
            SchmidtSamoaPublicKey::from_key_blob(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            SchmidtSamoaPrivateKey::from_key_blob(&private_blob),
            Some(private.clone())
        );

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(
            SchmidtSamoaPublicKey::from_pem(&public_pem),
            Some(public.clone())
        );
        assert_eq!(
            SchmidtSamoaPrivateKey::from_pem(&private_pem),
            Some(private.clone())
        );
        assert_eq!(SchmidtSamoaPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(
            SchmidtSamoaPrivateKey::from_xml(&private_xml),
            Some(private)
        );
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = SchmidtSamoa::from_primes(&p, &q).expect("valid Schmidt-Samoa key");
        let ciphertext = public.encrypt_bytes(&[0x05]).expect("message fits");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(vec![0x05]));
    }
}
