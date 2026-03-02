//! Clifford Cocks's original public-key scheme (CESG memo, 1973).
//!
//! This predates RSA by five years and is historically important as the first
//! public-key encryption construction described in the open literature later on.
//! The module keeps the published Cocks arithmetic map exactly as written in
//! the companion Python code and layers a minimal byte-oriented interface on
//! top of it. The arithmetic primitive remains available directly, while the
//! byte helpers serialize ciphertext integers as single-field DER `INTEGER`
//! sequences so callers can move ciphertexts around as bytes.

use core::fmt;

use crate::public_key::bigint::BigUint;
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{is_probable_prime, mod_inverse, mod_pow, random_probable_prime};
use crate::Csprng;

const COCKS_PUBLIC_LABEL: &str = "CRYPTOGRAPHY COCKS PUBLIC KEY";
const COCKS_PRIVATE_LABEL: &str = "CRYPTOGRAPHY COCKS PRIVATE KEY";

/// Public key for the Cocks primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CocksPublicKey {
    n: BigUint,
}

/// Private key for the Cocks primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct CocksPrivateKey {
    pi: BigUint,
    q: BigUint,
}

/// Namespace wrapper for the Cocks construction.
pub struct Cocks;

impl CocksPublicKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return a conservative public upper bound for byte-oriented plaintexts.
    ///
    /// When `p < q`, the private prime `q` is strictly larger than
    /// `floor(sqrt(n))`, so any message in `[0, floor(sqrt(n)))` will also be
    /// in the range recovered by the private map `c^pi mod q`.
    #[must_use]
    pub fn max_plaintext_exclusive(&self) -> BigUint {
        self.n.sqrt_floor()
    }

    /// Encrypt the raw integer message.
    ///
    /// This follows the reference implementation directly: `c = m^n mod n`,
    /// where the public exponent is the modulus `n` itself.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> BigUint {
        mod_pow(message, &self.n, &self.n)
    }

    /// Encrypt a byte string using the conservative public plaintext bound.
    ///
    /// The Cocks private map only recovers integers modulo the private prime
    /// `q`. This wrapper therefore accepts only messages strictly below
    /// `floor(sqrt(n))`, which is a public bound guaranteed to stay below `q`
    /// because the key generator enforces `p < q`.
    #[must_use]
    pub fn encrypt(&self, message: &[u8]) -> Option<BigUint> {
        let message_int = BigUint::from_be_bytes(message);
        if message_int >= self.max_plaintext_exclusive() {
            return None;
        }
        Some(self.encrypt_raw(&message_int))
    }

    /// Encrypt a byte string and return the ciphertext as a byte string.
    ///
    /// The encoded ciphertext is the crate's standard one-`INTEGER` DER
    /// payload for non-RSA public-key values. That keeps the byte-oriented
    /// helper unambiguous for this specific scheme without changing the
    /// underlying arithmetic map.
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
        pem_wrap(COCKS_PUBLIC_LABEL, &self.to_binary())
    }

    /// Encode the public key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap("CocksPublicKey", &[("n", &self.n)])
    }

    /// Decode the public key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(COCKS_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    /// Decode the public key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("CocksPublicKey", &["n"], xml)?.into_iter();
        let n = fields.next()?;
        if fields.next().is_some() || n <= BigUint::one() {
            return None;
        }
        Some(Self { n })
    }
}

impl fmt::Debug for CocksPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CocksPrivateKey(<redacted>)")
    }
}

impl CocksPrivateKey {
    /// Return the stored exponent `pi = p^{-1} mod (q - 1)`.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.pi
    }

    /// Return the private prime `q`.
    #[must_use]
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    /// Decrypt the raw integer ciphertext.
    ///
    /// The Python source recovers the message as `c^pi mod q`, so the original
    /// message must be interpreted in the range `[0, q)`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        mod_pow(ciphertext, &self.pi, &self.q)
    }

    /// Decrypt a ciphertext back into the big-endian byte string that was
    /// interpreted as the plaintext integer.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Vec<u8> {
        self.decrypt_raw(ciphertext).to_be_bytes()
    }

    /// Decrypt a byte-encoded ciphertext produced by [`CocksPublicKey::encrypt_bytes`].
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
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.pi, &self.q])
    }

    /// Decode the private key from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let pi = fields.next()?;
        let q = fields.next()?;
        if fields.next().is_some() || pi.is_zero() || q <= BigUint::one() {
            return None;
        }
        Some(Self { pi, q })
    }

    /// Encode the private key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(COCKS_PRIVATE_LABEL, &self.to_binary())
    }

    /// Encode the private key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap("CocksPrivateKey", &[("pi", &self.pi), ("q", &self.q)])
    }

    /// Decode the private key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(COCKS_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    /// Decode the private key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("CocksPrivateKey", &["pi", "q"], xml)?.into_iter();
        let pi = fields.next()?;
        let q = fields.next()?;
        if fields.next().is_some() || pi.is_zero() || q <= BigUint::one() {
            return None;
        }
        Some(Self { pi, q })
    }
}

impl Cocks {
    /// Derive a raw key pair from explicit primes `p` and `q`.
    ///
    /// Returns `None` if `p >= q`, the inputs are equal, either prime is
    /// composite, or if
    /// `p` is not invertible modulo `q - 1`.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(CocksPublicKey, CocksPrivateKey)> {
        if p >= q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }

        let q_minus_one = q.sub_ref(&BigUint::one());
        let pi = mod_inverse(p, &q_minus_one)?;
        let n = p.mul_ref(q);

        Some((CocksPublicKey { n }, CocksPrivateKey { pi, q: q.clone() }))
    }

    /// Generate a Cocks key pair with `p < q`.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(CocksPublicKey, CocksPrivateKey)> {
        // With fewer than 8 total bits the split can collapse to the same tiny
        // prime on both sides, so a distinct-prime key may never be found.
        if bits < 8 {
            return None;
        }

        let p_bits = bits / 2;
        let q_bits = bits - p_bits;
        loop {
            let mut p = random_probable_prime(rng, p_bits)?;
            let mut q = random_probable_prime(rng, q_bits)?;
            if q < p {
                core::mem::swap(&mut p, &mut q);
            }
            if let Some(keypair) = Self::from_primes(&p, &q) {
                return Some(keypair);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cocks, CocksPrivateKey, CocksPublicKey};
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(17);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid small primes");
        assert_eq!(public.modulus(), &BigUint::from_u64(187));
        assert_eq!(private.exponent(), &BigUint::from_u64(3));
        assert_eq!(private.q(), &BigUint::from_u64(17));
    }

    #[test]
    fn roundtrip_small_messages() {
        let prime_p = BigUint::from_u64(19);
        let prime_q = BigUint::from_u64(23);
        let (public, private) = Cocks::from_primes(&prime_p, &prime_q).expect("valid Cocks key");

        for msg in [0u64, 1, 2, 7, 11, 22] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message);
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_python() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(17);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid small primes");
        let message = BigUint::from_u64(5);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(ciphertext, BigUint::from_u64(113));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn rejects_non_invertible_choice() {
        let p = BigUint::from_u64(23);
        let q = BigUint::from_u64(47);
        // Here q - 1 = 46 is divisible by p = 23, so p has no inverse modulo
        // q - 1 and the Cocks private exponent cannot be formed.
        assert!(Cocks::from_primes(&p, &q).is_none());
    }

    #[test]
    fn byte_wrapper_roundtrip() {
        let prime_p = BigUint::from_u64(19);
        let prime_q = BigUint::from_u64(23);
        let (public, private) = Cocks::from_primes(&prime_p, &prime_q).expect("valid Cocks key");
        let ciphertext = public.encrypt(&[0x0b]).expect("message fits public bound");
        assert_eq!(private.decrypt(&ciphertext), vec![0x0b]);
    }

    #[test]
    fn generate_teaching_keypair() {
        let mut drbg = CtrDrbgAes256::new(&[0x21; 48]);
        let (public, private) = Cocks::generate(&mut drbg, 32).expect("Cocks key generation");
        let ciphertext = public.encrypt(&[0x2a]).expect("message fits public bound");
        assert_eq!(private.decrypt(&ciphertext), vec![0x2a]);
    }

    #[test]
    fn generate_rejects_too_few_bits() {
        let mut drbg = CtrDrbgAes256::new(&[0x91; 48]);
        assert!(Cocks::generate(&mut drbg, 7).is_none());
    }

    #[test]
    fn rejects_unordered_primes() {
        let p = BigUint::from_u64(17);
        let q = BigUint::from_u64(11);
        assert!(Cocks::from_primes(&p, &q).is_none());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(17);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid key");

        let public_blob = public.to_binary();
        let private_blob = private.to_binary();
        assert_eq!(
            CocksPublicKey::from_binary(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            CocksPrivateKey::from_binary(&private_blob),
            Some(private.clone())
        );

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(CocksPublicKey::from_pem(&public_pem), Some(public.clone()));
        assert_eq!(
            CocksPrivateKey::from_pem(&private_pem),
            Some(private.clone())
        );
        assert_eq!(CocksPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(CocksPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn generated_key_serialization_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0xa1; 48]);
        let (public, private) = Cocks::generate(&mut drbg, 32).expect("Cocks key generation");
        let message = [0x07];

        let public = CocksPublicKey::from_xml(&public.to_xml()).expect("public XML");
        let private = CocksPrivateKey::from_binary(&private.to_binary()).expect("private binary");
        let ciphertext = public.encrypt(&message).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), message.to_vec());
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let p = BigUint::from_u64(13);
        let q = BigUint::from_u64(23);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid Cocks key");
        let ciphertext = public.encrypt_bytes(&[0x0b]).expect("message fits public bound");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(vec![0x0b]));
    }
}
