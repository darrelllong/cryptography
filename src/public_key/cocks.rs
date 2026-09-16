//! Clifford Cocks's public-key scheme (CESG, 1973).
//!
//! Cocks described the construction in an internal CESG memorandum of
//! November 1973, "A Note on Non-Secret Encryption" (`pubs/`); GCHQ
//! declassified it in December 1997. Rivest, Shamir and Adleman published
//! RSA independently in 1977. The module keeps the arithmetic map of the
//! memorandum and layers a byte-oriented interface on top of it. The
//! arithmetic primitive remains available directly, while the byte helpers
//! serialize ciphertext integers as single-field DER `INTEGER` sequences so
//! callers can move ciphertexts around as bytes.
//!
//! Security notes, the same ones that apply to textbook RSA:
//!
//! - **Deterministic.** `c = m^n mod n` involves no randomness, so equal
//!   messages give equal ciphertexts and the scheme is not IND-CPA; a
//!   ciphertext can be tested against a guessed message with one public
//!   operation. Nothing here plays the role OAEP plays for RSA.
//! - **No chosen-ciphertext protection.** The map is multiplicative, so a
//!   decryptor exposed to arbitrary ciphertexts is a plaintext oracle for
//!   any ciphertext an adversary can derive from another.
//!
//! The private exponent `π = p⁻¹ mod (q − 1)` drives rump's variable-time
//! exponentiation modulo `q`, whose sequence of squarings and
//! multiplications is the exponent's window pattern; an adversary who
//! observes it (a co-resident process reading the cache or branch
//! predictor, a probe on the power rail) learns `π`, and with `n`, the
//! prime `q` is then a gcd away.

use core::fmt;

use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::public_key::primes::{is_probable_prime_untrusted, random_probable_prime};
use crate::Csprng;
use rump::modular::{mod_inverse, mod_pow};
use rump::number_theory::gcd;
use rump::BigUint;

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
    /// Cocks uses the unusual public map `c = m^n mod n`, where the public
    /// exponent is the modulus `n` itself. Deterministic — equal messages
    /// give equal ciphertexts (see the module documentation).
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

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.n.clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// Structural validation (public material): `n = p·q` with `p < q` and
    /// `p` invertible modulo the even `q − 1`, so both primes are odd and
    /// `n` is odd and at least `3 · 5`. Compositeness is not tested.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        if !n.is_odd() || n < BigUint::from_u64(15) {
            return None;
        }
        Some(Self { n })
    }
}

crate::public_key::io::impl_xml_serialization!(CocksPublicKey, "CocksPublicKey", ["n"]);
crate::public_key::io::impl_blob_pem_serialization!(CocksPublicKey, COCKS_PUBLIC_LABEL, ["n"]);

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
    /// The message is recovered as `c^pi mod q`, so the original message
    /// must be interpreted in the range `[0, q)`. Why it works: modulo `q`,
    /// `c^π ≡ m^{pqπ}` and `pπ ≡ 1 (mod q − 1)`, so `pqπ ≡ q ≡ 1 (mod q − 1)`
    /// and Fermat gives `m^{pqπ} ≡ m (mod q)`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        mod_pow(ciphertext, &self.pi, &self.q)
    }

    /// Decrypt a ciphertext with [`Self::decrypt_raw`] and return the
    /// recovered integer's minimal big-endian encoding: no leading zero
    /// octets, and `0x00` alone for the integer zero. A message that began
    /// with zero octets, or was empty, therefore comes back without them.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Vec<u8> {
        self.decrypt_raw(ciphertext).to_be_bytes()
    }

    /// Decrypt a byte-encoded ciphertext produced by
    /// [`CocksPublicKey::encrypt_bytes`]; the plaintext bytes are those of
    /// [`Self::decrypt`].
    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut fields = decode_biguints(ciphertext)?.into_iter();
        let value = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        Some(self.decrypt(&value))
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.pi.clone(), self.q.clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// The blob carries `pi = p⁻¹ mod (q − 1)` and `q`, not `p`, so this is
    /// the consistency those fields allow: `q` is an odd hardened probable
    /// prime, and `pi` is a unit modulo `q − 1` in `[1, q − 1)` — which
    /// every inverse is, and which makes it odd.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let pi = fields.next()?;
        let q = fields.next()?;
        if !q.is_odd() || !is_probable_prime_untrusted(&q) {
            return None;
        }
        let q_minus_one = q.sub(&BigUint::one());
        if pi.is_zero() || pi >= q_minus_one || gcd(&pi, &q_minus_one) != BigUint::one() {
            return None;
        }
        Some(Self { pi, q })
    }
}

crate::public_key::io::impl_xml_serialization!(CocksPrivateKey, "CocksPrivateKey", ["pi", "q"]);
crate::public_key::io::impl_blob_pem_serialization!(
    CocksPrivateKey,
    COCKS_PRIVATE_LABEL,
    ["pi", "q"]
);

impl Cocks {
    /// Derive a raw key pair from explicit primes `p` and `q`.
    ///
    /// Returns `None` if `p >= q`, the inputs are equal, either prime is
    /// composite, or if
    /// `p` is not invertible modulo `q - 1`.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(CocksPublicKey, CocksPrivateKey)> {
        if p >= q || !is_probable_prime_untrusted(p) || !is_probable_prime_untrusted(q) {
            return None;
        }

        let q_minus_one = q.sub(&BigUint::one());
        let pi = mod_inverse(p, &q_minus_one)?;
        let n = p.mul(q);

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
    use crate::CtrDrbgAes256;
    use rump::BigUint;

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
    fn exact_small_ciphertext_known_answer() {
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
        // Bytes go through the integer: leading zero octets are dropped and
        // the zero message comes back as one `0x00` octet.
        let ciphertext = public
            .encrypt(&[0x00, 0x0b])
            .expect("message fits public bound");
        assert_eq!(private.decrypt(&ciphertext), vec![0x0b]);
        let ciphertext = public.encrypt(&[]).expect("message fits public bound");
        assert_eq!(private.decrypt(&ciphertext), vec![0x00]);
    }

    #[test]
    fn generate_keypair_roundtrip() {
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

        let public_blob = public.to_key_blob();
        let private_blob = private.to_key_blob();
        assert_eq!(
            CocksPublicKey::from_key_blob(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            CocksPrivateKey::from_key_blob(&private_blob),
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
        let private =
            CocksPrivateKey::from_key_blob(&private.to_key_blob()).expect("private binary");
        let ciphertext = public.encrypt(&message).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), message.to_vec());
    }

    #[test]
    fn key_parse_rejects_tampered_fields() {
        use crate::public_key::io::encode_biguints;
        let u = BigUint::from_u64;
        // p = 11, q = 17: n = 187, pi = 3.
        assert!(CocksPublicKey::from_key_blob(&encode_biguints(&[&u(187)])).is_some());
        for n in [186u64, 1, 9, 0] {
            assert!(
                CocksPublicKey::from_key_blob(&encode_biguints(&[&u(n)])).is_none(),
                "{n}"
            );
        }
        assert!(CocksPrivateKey::from_key_blob(&encode_biguints(&[&u(3), &u(17)])).is_some());
        for (pi, q) in [
            (3u64, 15u64), // composite q
            (3, 2),        // even q
            (0, 17),       // pi = 0
            (16, 17),      // pi = q - 1
            (17, 17),      // pi >= q - 1
            (4, 17),       // gcd(pi, q - 1) = 4
        ] {
            let blob = encode_biguints(&[&u(pi), &u(q)]);
            assert!(
                CocksPrivateKey::from_key_blob(&blob).is_none(),
                "pi={pi} q={q}"
            );
        }
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let p = BigUint::from_u64(13);
        let q = BigUint::from_u64(23);
        let (public, private) = Cocks::from_primes(&p, &q).expect("valid Cocks key");
        let ciphertext = public
            .encrypt_bytes(&[0x0b])
            .expect("message fits public bound");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(vec![0x0b]));
    }
}
