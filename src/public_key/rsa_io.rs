//! Modern RSA key externalization helpers.
//!
//! The raw `Rsa` primitive stores just enough information to derive standards
//! formats on demand:
//! - `SubjectPublicKeyInfo` (SPKI) for public keys
//! - `PKCS #8` (`PrivateKeyInfo`) for private keys
//!
//! Lower-level PKCS #1 RSA key structures are also exposed because they are the
//! inner payloads of those modern containers and remain useful for debugging or
//! interop with older tooling.
//!
//! The containers and the textual encoding are the shared `pkix` layer; this
//! module supplies the `rsaEncryption` identifier, whose parameters RFC 3279
//! §2.3.1 requires to be `NULL`, and the PKCS #1 structures inside.

use crate::public_key::io::{der_integer_biguint, der_integer_u8, der_sequence_of, DerReader};
use crate::public_key::pkix::{
    pem_decode, pem_encode, pkcs8_ber, AlgorithmIdentifier, OneAsymmetricKey, SubjectPublicKeyInfo,
    NULL_PARAMETERS, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL, RSA_ENCRYPTION,
};
use crate::public_key::rsa::{Rsa, RsaPrivateKey, RsaPublicKey};
use crate::zeroize_slice;
use rump::number_theory::lcm;
use rump::BigUint;

/// Textual label of a bare PKCS #1 `RSAPublicKey`. RFC 7468 does not list the
/// PKCS #1 labels; these are the conventional ones.
const RSA_PUBLIC_KEY_LABEL: &str = "RSA PUBLIC KEY";

/// Textual label of a bare PKCS #1 `RSAPrivateKey`.
const RSA_PRIVATE_KEY_LABEL: &str = "RSA PRIVATE KEY";

/// Largest modulus, and largest prime, a private-key parser accepts:
/// 16 384 bits, the top of the sizes in common use (SP 800-57 Part 1 stops
/// at 15 360). The parsers prove a private key by rebuilding it from its
/// primes, which runs the hash-hardened primality test on attacker-chosen
/// integers; the bound is applied before that test, so a hostile key file
/// cannot make the parser exponentiate an arbitrarily wide number.
const MAX_MODULUS_BITS: usize = 16_384;

/// `rsaEncryption` with the `NULL` parameters RFC 3279 §2.3.1 requires.
fn rsa_encryption() -> AlgorithmIdentifier<'static> {
    AlgorithmIdentifier::new(&RSA_ENCRYPTION, Some(NULL_PARAMETERS))
}

impl RsaPublicKey {
    /// Encode the public key as the PKCS #1 `RSAPublicKey` structure in DER.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        der_sequence_of(vec![
            der_integer_biguint(self.modulus()),
            der_integer_biguint(self.exponent()),
        ])
    }

    /// Encode the public key as `SubjectPublicKeyInfo` in DER.
    #[must_use]
    pub fn to_spki_der(&self) -> Vec<u8> {
        SubjectPublicKeyInfo::new(rsa_encryption(), &self.to_pkcs1_der()).to_der()
    }

    /// Encode the public key as the PKCS #1 `RSA PUBLIC KEY` PEM label.
    #[must_use]
    pub fn to_pkcs1_pem(&self) -> String {
        pem_encode(RSA_PUBLIC_KEY_LABEL, self.to_pkcs1_der())
    }

    /// Encode the public key as `PUBLIC KEY` PEM (`SubjectPublicKeyInfo`).
    #[must_use]
    pub fn to_spki_pem(&self) -> String {
        pem_encode(PUBLIC_KEY_LABEL, self.to_spki_der())
    }

    /// Decode a PKCS #1 `RSAPublicKey` structure (RFC 8017 Appendix A.1.1) in
    /// strict DER. No specification asks a receiver of a bare `RSAPublicKey`
    /// to accept BER, and RFC 3279 §2.3.1 carries it in a
    /// `SubjectPublicKeyInfo` as "The DER encoded RSAPublicKey".
    #[must_use]
    pub fn from_pkcs1_der(der: &[u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let seq = outer.read_sequence()?;
        if !outer.is_finished() {
            return None;
        }

        let mut reader = DerReader::new(seq);
        let modulus = reader.read_integer_biguint()?;
        let public_exponent = reader.read_integer_biguint()?;
        if !reader.is_finished() {
            return None;
        }

        public_key_from_fields(public_exponent, modulus)
    }

    /// Decode `SubjectPublicKeyInfo` in strict DER: `rsaEncryption` with the
    /// `NULL` parameters RFC 3279 §2.3.1 requires, around a DER
    /// `RSAPublicKey`.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let spki = SubjectPublicKeyInfo::from_der(der)?;
        if !spki
            .algorithm()
            .matches(&RSA_ENCRYPTION, Some(NULL_PARAMETERS))
        {
            return None;
        }
        Self::from_pkcs1_der(spki.subject_public_key())
    }

    /// Decode a PKCS #1 `RSA PUBLIC KEY` PEM document, the text read by RFC
    /// 7468 §2's parser rules and its contents as [`Self::from_pkcs1_der`]
    /// reads them: RFC 7468 defines no such label, and nothing asks for BER
    /// there.
    #[must_use]
    pub fn from_pkcs1_pem(pem: &str) -> Option<Self> {
        pem_decode(RSA_PUBLIC_KEY_LABEL, pem, Self::from_pkcs1_der)
    }

    /// Decode a `PUBLIC KEY` PEM document (`SubjectPublicKeyInfo`), the text
    /// read by RFC 7468 §2's parser rules. RFC 7468 §13 requires the contents
    /// to be BER ("DER preferred"), so any BER encoding of the container is
    /// accepted; the `RSAPublicKey` inside must still be DER (RFC 3279
    /// §2.3.1), and the key is checked as [`Self::from_spki_der`] checks it.
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        pem_decode(PUBLIC_KEY_LABEL, pem, Self::from_spki_der)
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.exponent().clone(), self.modulus().clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let public_exponent = fields.next()?;
        let modulus = fields.next()?;
        public_key_from_fields(public_exponent, modulus)
    }
}

/// RFC 8017 §3.1: an RSA public key `(n, e)` has `n` the product of two odd
/// primes (so `n` is odd) and a public exponent with `3 ≤ e ≤ n − 1` and
/// `gcd(e, λ(n)) = 1`, which makes `e` odd because `λ(n)` is even. This is
/// the shape every parser enforces, for private keys too (§3.2 embeds the
/// public key). Compositeness of `n` is not tested on the public path — a
/// prime `n` breaks only the key of whoever published it — and the private
/// path proves it by rebuilding the key from its primes.
fn rfc8017_public_key_shape(e: &BigUint, n: &BigUint) -> bool {
    n.is_odd() && e.is_odd() && *e >= BigUint::from_u64(3) && e < n
}

/// Structural validation of a parsed RSA public key.
fn public_key_from_fields(e: BigUint, n: BigUint) -> Option<RsaPublicKey> {
    if !rfc8017_public_key_shape(&e, &n) {
        return None;
    }
    Some(RsaPublicKey::from_components(e, n))
}

crate::public_key::io::impl_xml_serialization!(RsaPublicKey, "RsaPublicKey", ["e", "n"]);

impl RsaPrivateKey {
    /// Encode the private key as the PKCS #1 `RSAPrivateKey` structure in DER.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        // Every component's encoding holds private material; each is wiped
        // once copied into the one encoding, which is allocated at its exact
        // size, so only the returned encoding survives.
        der_sequence_of(vec![
            der_integer_u8(0),
            der_integer_biguint(self.modulus()),
            der_integer_biguint(self.public_exponent()),
            der_integer_biguint(self.exponent()),
            der_integer_biguint(self.prime1()),
            der_integer_biguint(self.prime2()),
            der_integer_biguint(self.crt_exponent1()),
            der_integer_biguint(self.crt_exponent2()),
            der_integer_biguint(self.crt_coefficient()),
        ])
    }

    /// Encode the private key as `PrivateKeyInfo` (`PKCS #8`) in DER.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        let mut pkcs1 = self.to_pkcs1_der();
        let out = OneAsymmetricKey::new(rsa_encryption(), &pkcs1, None).to_der();
        zeroize_slice(pkcs1.as_mut_slice());
        out
    }

    /// Encode the private key as PKCS #1 `RSA PRIVATE KEY` PEM.
    #[must_use]
    pub fn to_pkcs1_pem(&self) -> String {
        pem_encode(RSA_PRIVATE_KEY_LABEL, self.to_pkcs1_der())
    }

    /// Encode the private key as `PRIVATE KEY` PEM (`PKCS #8`).
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode(PRIVATE_KEY_LABEL, self.to_pkcs8_der())
    }

    /// Decode a PKCS #1 `RSAPrivateKey` structure (RFC 8017 Appendix A.1.2) in
    /// strict DER. No specification asks a receiver of a bare `RSAPrivateKey`
    /// to accept BER; inside PKCS #8, where RFC 5208 §5 makes it "a BER
    /// encoding", [`Self::from_pkcs8_ber`] accepts BER.
    ///
    /// Only two-prime keys are read: A.1.2 makes `version` 0 for them and 1
    /// for multi-prime keys carrying `otherPrimeInfos`, and this crate's key
    /// type holds exactly two primes, so `version` 1 is refused. The
    /// modulus and both primes must be at most `MAX_MODULUS_BITS` (16 384) wide.
    #[must_use]
    pub fn from_pkcs1_der(der: &[u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let seq = outer.read_sequence()?;
        if !outer.is_finished() {
            return None;
        }

        let mut reader = DerReader::new(seq);
        // Version ::= INTEGER { two-prime(0), multi(1) }.
        let version = reader.read_integer_small()?;
        if version != 0 {
            return None;
        }

        let modulus = reader.read_integer_biguint()?;
        let public_exponent = reader.read_integer_biguint()?;
        let private_exponent = reader.read_integer_biguint()?;
        let prime1 = reader.read_integer_biguint()?;
        let prime2 = reader.read_integer_biguint()?;
        let exponent1 = reader.read_integer_biguint()?;
        let exponent2 = reader.read_integer_biguint()?;
        let coefficient = reader.read_integer_biguint()?;
        if !reader.is_finished() {
            return None;
        }

        let private = private_key_from_primes(&modulus, &public_exponent, &prime1, &prime2)?;
        if !private_exponent_matches(&public_exponent, &private_exponent, &prime1, &prime2) {
            return None;
        }

        if exponent1 != *private.crt_exponent1() || exponent2 != *private.crt_exponent2() {
            return None;
        }
        if coefficient != *private.crt_coefficient() {
            return None;
        }

        Some(private.with_exponent(private_exponent))
    }

    /// Decode `PrivateKeyInfo` (`PKCS #8`), that is RFC 5958
    /// `OneAsymmetricKey`, in strict DER; [`Self::from_pkcs8_ber`] is the BER
    /// receiver RFC 5958 §2 requires.
    ///
    /// Attributes are accepted and ignored. RFC 5958 §2 leaves the structure
    /// inside a version 2 `publicKey` to the algorithm; for `rsaEncryption`
    /// that is the `RSAPublicKey` of RFC 3279 §2.3.1, and since
    /// `RSAPrivateKey` already carries `n` and `e`, a present copy must match
    /// them.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let key = OneAsymmetricKey::from_der(der)?;
        if !key
            .algorithm()
            .matches(&RSA_ENCRYPTION, Some(NULL_PARAMETERS))
        {
            return None;
        }
        let private = Self::from_pkcs1_der(key.private_key())?;
        if let Some(public_key) = key.public_key() {
            let own = RsaPublicKey::from_components(
                private.public_exponent().clone(),
                private.modulus().clone(),
            );
            if RsaPublicKey::from_pkcs1_der(public_key)? != own {
                return None;
            }
        }
        Some(private)
    }

    /// Decode `PrivateKeyInfo` (`PKCS #8`), RFC 5958 `OneAsymmetricKey`, in
    /// any X.690 BER encoding, DER included: RFC 5958 §2 says "receivers MUST
    /// support BER". The `RSAPrivateKey` inside may be BER as well, being "a
    /// BER encoding of a value of type RSAPrivateKey" (RFC 5208 §5); a version
    /// 2 `publicKey` must be a DER `RSAPublicKey` (RFC 3279 §2.3.1). The key
    /// is then checked as [`Self::from_pkcs8_der`] checks it.
    #[must_use]
    pub fn from_pkcs8_ber(ber: &[u8]) -> Option<Self> {
        pkcs8_ber(ber, Self::from_pkcs8_der)
    }

    /// Decode a PKCS #1 `RSA PRIVATE KEY` PEM document, the text read by RFC
    /// 7468 §2's parser rules and its contents as [`Self::from_pkcs1_der`]
    /// reads them: RFC 7468 defines no such label, and nothing asks for BER
    /// there.
    #[must_use]
    pub fn from_pkcs1_pem(pem: &str) -> Option<Self> {
        pem_decode(RSA_PRIVATE_KEY_LABEL, pem, Self::from_pkcs1_der)
    }

    /// Decode a `PRIVATE KEY` PEM document (`PKCS #8`), the text read by RFC
    /// 7468 §2's parser rules and its contents as [`Self::from_pkcs8_ber`]
    /// reads them: RFC 7468 §10 requires them to be BER ("DER preferred").
    #[must_use]
    pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        pem_decode(PRIVATE_KEY_LABEL, pem, Self::from_pkcs8_der)
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.public_exponent().clone(),
            self.exponent().clone(),
            self.modulus().clone(),
            self.prime1().clone(),
            self.prime2().clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let public_exponent = fields.next()?;
        let private_exponent = fields.next()?;
        let modulus = fields.next()?;
        let prime1 = fields.next()?;
        let prime2 = fields.next()?;

        let private = private_key_from_primes(&modulus, &public_exponent, &prime1, &prime2)?;
        if !private_exponent_matches(&public_exponent, &private_exponent, &prime1, &prime2) {
            return None;
        }
        Some(private.with_exponent(private_exponent))
    }
}

/// Rebuild a parsed private key from its primes and check it against the
/// parsed modulus. The size bound comes first, before the hardened primality
/// test inside [`Rsa::from_primes_with_exponent`] sees the primes, and the
/// public-key shape of RFC 8017 §3.1 is checked on the parsed `(n, e)`.
fn private_key_from_primes(
    modulus: &BigUint,
    public_exponent: &BigUint,
    prime1: &BigUint,
    prime2: &BigUint,
) -> Option<RsaPrivateKey> {
    if modulus.bits() > MAX_MODULUS_BITS
        || prime1.bits() > MAX_MODULUS_BITS
        || prime2.bits() > MAX_MODULUS_BITS
        || !rfc8017_public_key_shape(public_exponent, modulus)
    {
        return None;
    }
    let (public, private) = Rsa::from_primes_with_exponent(prime1, prime2, public_exponent)?;
    if public.modulus() != modulus {
        return None;
    }
    Some(private)
}

/// RFC 8017 §3.2: the private exponent is "a positive integer less than n
/// satisfying e · d ≡ 1 (mod λ(n))", `λ = lcm(p − 1, q − 1)`. Keys in the wild
/// carry either `d = e⁻¹ mod λ(n)` (what this crate generates) or the larger
/// `d = e⁻¹ mod φ(n)`; both are valid, so a parser checks the range and the
/// congruence rather than comparing against one canonical representative.
fn private_exponent_matches(e: &BigUint, d: &BigUint, p: &BigUint, q: &BigUint) -> bool {
    let one = BigUint::one();
    if d.is_zero() || d >= &p.mul(q) {
        return false;
    }
    let lambda = lcm(&p.sub(&one), &q.sub(&one));
    BigUint::mod_mul(e, d, &lambda) == one
}

crate::public_key::io::impl_xml_serialization!(
    RsaPrivateKey,
    "RsaPrivateKey",
    ["e", "d", "n", "p", "q"]
);

#[cfg(test)]
mod tests {
    use super::{RsaPrivateKey, RsaPublicKey};
    use crate::public_key::rsa::Rsa;
    use rump::BigUint;

    #[test]
    fn rsa_rejects_nonminimal_der_lengths_and_integers() {
        let (public, _) = Rsa::from_primes_with_exponent(
            &BigUint::from_u64(61),
            &BigUint::from_u64(53),
            &BigUint::from_u64(17),
        )
        .expect("valid RSA key");
        let der = public.to_pkcs1_der();
        assert!(der[1] < 128);
        let mut long_length = vec![0x30, 0x81, der[1]];
        long_length.extend_from_slice(&der[2..]);
        assert!(RsaPublicKey::from_pkcs1_der(&long_length).is_none());

        // n=3233 starts with 0x0c; an extra INTEGER sign octet is redundant.
        let mut padded_integer = der;
        padded_integer[1] += 1;
        padded_integer[3] += 1;
        padded_integer.insert(4, 0);
        assert!(RsaPublicKey::from_pkcs1_der(&padded_integer).is_none());
    }

    #[test]
    fn rsa_containers_reject_nonempty_algorithm_null() {
        let (public, private) = Rsa::from_primes_with_exponent(
            &BigUint::from_u64(61),
            &BigUint::from_u64(53),
            &BigUint::from_u64(17),
        )
        .expect("valid RSA key");
        use crate::public_key::io::{der_bit_string, der_octet_string, der_oid, der_sequence};
        let mut algorithm = der_oid(super::RSA_ENCRYPTION.content());
        algorithm.extend_from_slice(&[0x05, 0x01, 0x00]);
        let algorithm = der_sequence(&algorithm);
        let mut public_body = algorithm.clone();
        public_body.extend(der_bit_string(&public.to_pkcs1_der()));
        assert!(RsaPublicKey::from_spki_der(&der_sequence(&public_body)).is_none());

        let mut private_body = super::der_integer_u8(0);
        private_body.extend(algorithm);
        private_body.extend(der_octet_string(&private.to_pkcs1_der()));
        assert!(RsaPrivateKey::from_pkcs8_der(&der_sequence(&private_body)).is_none());
    }

    /// RFC 3279 §2.3.1: `rsaEncryption` parameters MUST be `NULL`, so absent
    /// parameters fail both containers.
    #[test]
    fn rsa_containers_reject_absent_algorithm_parameters() {
        use crate::public_key::pkix::{
            AlgorithmIdentifier, OneAsymmetricKey, SubjectPublicKeyInfo,
        };
        let (public, private) = Rsa::from_primes_with_exponent(
            &BigUint::from_u64(61),
            &BigUint::from_u64(53),
            &BigUint::from_u64(17),
        )
        .expect("valid RSA key");
        let absent = AlgorithmIdentifier::new(&super::RSA_ENCRYPTION, None);
        let pkcs1 = public.to_pkcs1_der();
        let spki = SubjectPublicKeyInfo::new(absent, &pkcs1).to_der();
        assert!(RsaPublicKey::from_spki_der(&spki).is_none());
        let pkcs1 = private.to_pkcs1_der();
        let pkcs8 = OneAsymmetricKey::new(absent, &pkcs1, None).to_der();
        assert!(RsaPrivateKey::from_pkcs8_der(&pkcs8).is_none());
    }

    /// RFC 5958 version 2 carries `[1] publicKey`; for RSA it must be the
    /// key's own `RSAPublicKey`.
    #[test]
    fn pkcs8_version_2_public_key_must_match_the_private_key() {
        use crate::public_key::pkix::OneAsymmetricKey;
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).expect("valid RSA key");
        let (other, _) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(7)).expect("valid RSA key");
        let pkcs1 = private.to_pkcs1_der();
        let with_public = |public_key: &[u8]| {
            OneAsymmetricKey::new(super::rsa_encryption(), &pkcs1, Some(public_key)).to_der()
        };
        assert_eq!(
            RsaPrivateKey::from_pkcs8_der(&with_public(&public.to_pkcs1_der())),
            Some(private.clone())
        );
        assert!(RsaPrivateKey::from_pkcs8_der(&with_public(&other.to_pkcs1_der())).is_none());
        assert!(RsaPrivateKey::from_pkcs8_der(&with_public(&[0x05, 0x00])).is_none());
    }

    // The p = 61, q = 53 fixtures use e = 17: the default search would pick
    // 65537 > n = 3233, which RFC 8017 §3.1 does not allow in a public key,
    // and the parsers enforce that shape.

    #[test]
    fn spki_roundtrip() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, _) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).expect("valid RSA key");

        let der = public.to_spki_der();
        let parsed = RsaPublicKey::from_spki_der(&der).expect("parse SPKI");
        assert_eq!(parsed, public);

        let pem = public.to_spki_pem();
        let parsed = RsaPublicKey::from_spki_pem(&pem).expect("parse SPKI PEM");
        assert_eq!(parsed, public);
    }

    #[test]
    fn pkcs8_roundtrip() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (_, private) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).expect("valid RSA key");

        let der = private.to_pkcs8_der();
        let parsed = RsaPrivateKey::from_pkcs8_der(&der).expect("parse PKCS#8");
        assert_eq!(parsed, private);

        let pem = private.to_pkcs8_pem();
        let parsed = RsaPrivateKey::from_pkcs8_pem(&pem).expect("parse PKCS#8 PEM");
        assert_eq!(parsed, private);
    }

    #[test]
    fn xml_roundtrip() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).expect("valid RSA key");

        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(RsaPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(RsaPrivateKey::from_xml(&private_xml), Some(private));
    }

    /// PKCS #1 §3.2 requires only `e·d ≡ 1 (mod λ(n))`. This crate generates
    /// `d = e⁻¹ mod λ(n)`, but keys produced with `d = e⁻¹ mod φ(n)` are
    /// common (OpenSSL 1.x, and any implementation following the original
    /// RSA paper). Hand-built RSAPrivateKey with p = 61, q = 53, e = 17:
    /// φ = 3120 gives d = 2753 (λ = 780 would give 413). dP = 53, dQ = 49,
    /// qInv = 38 are the same for either `d`.
    const PHI_REDUCED_PKCS1: [u8; 31] = [
        0x30, 0x1D, // SEQUENCE
        0x02, 0x01, 0x00, // version 0
        0x02, 0x02, 0x0C, 0xA1, // n = 3233
        0x02, 0x01, 0x11, // e = 17
        0x02, 0x02, 0x0A, 0xC1, // d = 2753 = 17⁻¹ mod φ(n)
        0x02, 0x01, 0x3D, // p = 61
        0x02, 0x01, 0x35, // q = 53
        0x02, 0x01, 0x35, // dP = d mod 60
        0x02, 0x01, 0x31, // dQ = d mod 52
        0x02, 0x01, 0x26, // qInv = 53⁻¹ mod 61
    ];

    #[test]
    fn pkcs1_accepts_phi_reduced_private_exponent() {
        let private = RsaPrivateKey::from_pkcs1_der(&PHI_REDUCED_PKCS1)
            .expect("d = e^-1 mod phi(n) is a valid PKCS #1 private exponent");
        assert_eq!(private.exponent(), &BigUint::from_u64(2753));
        // The key keeps its serialized `d`, so re-encoding is byte-exact.
        assert_eq!(private.to_pkcs1_der(), PHI_REDUCED_PKCS1);

        let (public, _) = Rsa::from_primes_with_exponent(
            &BigUint::from_u64(61),
            &BigUint::from_u64(53),
            &BigUint::from_u64(17),
        )
        .expect("valid RSA key");
        let message = BigUint::from_u64(65);
        assert_eq!(private.decrypt_raw(&public.encrypt_raw(&message)), message);
    }

    #[test]
    fn public_key_parse_enforces_rfc8017_ranges() {
        use crate::public_key::io::encode_biguints;
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        // has exactly the crate's integer-sequence framing.
        let n = BigUint::from_u64(3233);
        let e = BigUint::from_u64(17);
        assert!(RsaPublicKey::from_pkcs1_der(&encode_biguints(&[&n, &e])).is_some());
        // Even e, e = 1, e = n, e > n, even n, and a swapped (e, n) order
        // where the "exponent" 3233 exceeds the "modulus" 17.
        for (n, e) in [
            (3233u64, 16u64),
            (3233, 1),
            (3233, 3233),
            (3233, 3235),
            (3234, 17),
            (17, 3233),
        ] {
            let blob = encode_biguints(&[&BigUint::from_u64(n), &BigUint::from_u64(e)]);
            assert!(RsaPublicKey::from_pkcs1_der(&blob).is_none(), "n={n} e={e}");
        }
        assert!(
            RsaPublicKey::from_xml("<RsaPublicKey><e>10</e><n>0CA1</n></RsaPublicKey>").is_none()
        );
    }

    /// RFC 8017 A.1.2: `version` 1 means multi-prime with `otherPrimeInfos`;
    /// the two-prime reader refuses it even when the eight integers that
    /// follow are a valid two-prime key.
    #[test]
    fn pkcs1_rejects_multi_prime_version() {
        let mut der = PHI_REDUCED_PKCS1;
        der[4] = 0x01;
        assert!(RsaPrivateKey::from_pkcs1_der(&der).is_none());
    }

    /// A private key wider than `MAX_MODULUS_BITS` is refused before its
    /// "primes" reach the hardened primality test: `p = q = 2^16384 + 1` (a
    /// 16 385-bit composite) with `n = p·q` would otherwise cost a
    /// 32 769-bit exponentiation per Miller–Rabin round.
    #[test]
    fn private_key_parsers_cap_the_modulus_width_before_primality_testing() {
        use crate::public_key::io::{der_integer_biguint, der_integer_u8, der_sequence_of};
        let mut prime = BigUint::one();
        prime.shl_bits(super::MAX_MODULUS_BITS);
        prime = prime.add(&BigUint::one());
        let modulus = prime.mul(&prime);
        let e = BigUint::from_u64(65_537);
        let started = std::time::Instant::now();
        let der = der_sequence_of(vec![
            der_integer_u8(0),
            der_integer_biguint(&modulus),
            der_integer_biguint(&e),
            der_integer_biguint(&e),
            der_integer_biguint(&prime),
            der_integer_biguint(&prime),
            der_integer_biguint(&e),
            der_integer_biguint(&e),
            der_integer_biguint(&e),
        ]);
        assert!(RsaPrivateKey::from_pkcs1_der(&der).is_none());
        let hex =
            |value: &BigUint| crate::test_utils::encode_hex(&value.to_be_bytes()).to_uppercase();
        let xml = format!(
            "<RsaPrivateKey><e>{e}</e><d>{e}</d><n>{n}</n><p>{p}</p><q>{p}</q></RsaPrivateKey>",
            e = "010001",
            n = hex(&modulus),
            p = hex(&prime),
        );
        assert!(RsaPrivateKey::from_xml(&xml).is_none());
        // One hardened primality round on a 16 385-bit number takes seconds
        // in a debug build; the refusal takes far less than one.
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn pkcs1_rejects_private_exponent_not_congruent_to_inverse() {
        let mut der = PHI_REDUCED_PKCS1;
        der[15] = 0xC2; // d = 2754: 17 * 2754 ≡ 18 (mod 780)
        assert!(RsaPrivateKey::from_pkcs1_der(&der).is_none());
    }

    /// RFC 8017 §3.2 requires `d < n`. d = 2753 + 780 = 3533 is still
    /// `≡ 17⁻¹ (mod λ(n))` and leaves dP and dQ unchanged, so only the range
    /// check can reject it.
    #[test]
    fn pkcs1_rejects_private_exponent_at_or_above_modulus() {
        let mut der = PHI_REDUCED_PKCS1;
        der[14] = 0x0D;
        der[15] = 0xCD; // d = 3533 ≥ n = 3233
        assert!(RsaPrivateKey::from_pkcs1_der(&der).is_none());
    }

    /// Whatever the installed OpenSSL/LibreSSL emits (PKCS #1 or PKCS #8
    /// armor, φ- or λ-reduced `d`) must parse and re-encode byte-exactly.
    #[test]
    fn openssl_generated_private_key_parses() {
        let Some(pem) = crate::test_utils::openssl(&["genrsa", "512"], b"")
            .or_skip("openssl_generated_private_key_parses")
        else {
            return;
        };
        let pem = String::from_utf8(pem).expect("PEM is ASCII");
        let private = RsaPrivateKey::from_pkcs8_pem(&pem)
            .or_else(|| RsaPrivateKey::from_pkcs1_pem(&pem))
            .expect("OpenSSL-generated RSA key must parse");
        let reencoded = if pem.contains("BEGIN RSA PRIVATE KEY") {
            private.to_pkcs1_pem()
        } else {
            private.to_pkcs8_pem()
        };
        assert_eq!(reencoded.trim_end(), pem.trim_end());
    }

    #[test]
    fn generated_key_xml_roundtrip() {
        let mut drbg = crate::CtrDrbgAes256::new(&[0xc1; 48]);
        let (public, private) = Rsa::generate(&mut drbg, 64).expect("generated RSA key");

        let public_der = public.to_spki_der();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();

        assert_eq!(
            RsaPublicKey::from_spki_der(&public_der),
            Some(public.clone())
        );
        assert_eq!(RsaPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(RsaPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn openssl_accepts_spki_pem() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, _) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).expect("valid RSA key");

        let Some(expected) = crate::test_utils::openssl(
            &[
                "pkey", "-pubin", "-inform", "PEM", "-pubout", "-outform", "DER",
            ],
            public.to_spki_pem().as_bytes(),
        )
        .or_skip("openssl_accepts_spki_pem") else {
            return;
        };

        assert_eq!(expected, public.to_spki_der());
    }

    #[test]
    fn openssl_accepts_pkcs8_pem() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (_, private) =
            Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).expect("valid RSA key");

        let Some(round_tripped) = crate::test_utils::openssl(
            &["pkey", "-inform", "PEM", "-outform", "DER"],
            private.to_pkcs8_pem().as_bytes(),
        )
        .or_skip("openssl_accepts_pkcs8_pem") else {
            return;
        };

        // Acceptance is the property under test, and OpenSSL's DER output
        // form for a private key is version-dependent: 3.6 re-emits the
        // PKCS #8 PrivateKeyInfo, while 3.5 (Ubuntu 26.04) unwraps to the
        // traditional PKCS #1 RSAPrivateKey. Either way, what comes back
        // must decode to the same key.
        let decoded = RsaPrivateKey::from_pkcs8_der(&round_tripped)
            .or_else(|| RsaPrivateKey::from_pkcs1_der(&round_tripped))
            .expect("openssl output is PKCS #8 or PKCS #1 DER");
        assert_eq!(decoded, private);
    }

    fn toy_key() -> (RsaPublicKey, RsaPrivateKey) {
        Rsa::from_primes_with_exponent(
            &BigUint::from_u64(61),
            &BigUint::from_u64(53),
            &BigUint::from_u64(17),
        )
        .expect("valid RSA key")
    }

    /// RFC 5958 §2 ("receivers MUST support BER") and RFC 5208 §5 (the
    /// contents "are a BER encoding of a value of type RSAPrivateKey"):
    /// `from_pkcs8_ber` and `PRIVATE KEY` text (RFC 7468 §10) read the key in
    /// every BER form, inside and out, where `from_pkcs8_der` does not. A bare
    /// `RSAPrivateKey` has no BER receiver, since nothing asks for one.
    #[test]
    fn pkcs8_ber_receiver_follows_rfc5958_and_rfc5208() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        use crate::public_key::pkix::{pem_encode, OneAsymmetricKey, PRIVATE_KEY_LABEL};
        let (_, private) = toy_key();
        let pkcs1 = private.to_pkcs1_der();
        assert_eq!(
            RsaPrivateKey::from_pkcs8_ber(&private.to_pkcs8_der()),
            Some(private.clone())
        );
        for style in STYLES {
            let pkcs1_ber = reencode(&pkcs1, style);
            // A segmenting style leaves PKCS #1, which holds no strings, as DER.
            if pkcs1_ber != pkcs1 {
                assert!(
                    RsaPrivateKey::from_pkcs1_der(&pkcs1_ber).is_none(),
                    "{style:?}"
                );
                let text = pem_encode("RSA PRIVATE KEY", pkcs1_ber.clone());
                assert!(RsaPrivateKey::from_pkcs1_pem(&text).is_none(), "{style:?}");
            }

            let ber = reencode(
                &OneAsymmetricKey::new(super::rsa_encryption(), &pkcs1_ber, None).to_der(),
                style,
            );
            assert!(RsaPrivateKey::from_pkcs8_der(&ber).is_none(), "{style:?}");
            assert_eq!(
                RsaPrivateKey::from_pkcs8_ber(&ber),
                Some(private.clone()),
                "{style:?}"
            );
            assert_eq!(
                RsaPrivateKey::from_pkcs8_pem(&pem_encode(PRIVATE_KEY_LABEL, ber)),
                Some(private.clone()),
                "{style:?}"
            );
        }
    }

    /// RFC 7468 §13 lets `PUBLIC KEY` text hold a BER `SubjectPublicKeyInfo`,
    /// but RFC 3279 §2.3.1 makes the `RSAPublicKey` inside "The DER encoded
    /// RSAPublicKey", so only the container may be BER.
    #[test]
    fn spki_pem_takes_a_ber_container_around_a_der_rsa_public_key_only() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        use crate::public_key::pkix::{pem_encode, SubjectPublicKeyInfo, PUBLIC_KEY_LABEL};
        let (public, _) = toy_key();
        let spki = public.to_spki_der();
        for style in STYLES {
            let ber = reencode(&spki, style);
            assert!(RsaPublicKey::from_spki_der(&ber).is_none(), "{style:?}");
            assert_eq!(
                RsaPublicKey::from_spki_pem(&pem_encode(PUBLIC_KEY_LABEL, ber)),
                Some(public.clone()),
                "{style:?}"
            );
        }
        let pkcs1_ber = reencode(&public.to_pkcs1_der(), STYLES[1]);
        assert!(RsaPublicKey::from_pkcs1_der(&pkcs1_ber).is_none());
        let inner_ber = SubjectPublicKeyInfo::new(super::rsa_encryption(), &pkcs1_ber).to_der();
        assert!(RsaPublicKey::from_spki_pem(&pem_encode(PUBLIC_KEY_LABEL, inner_ber)).is_none());
    }

    /// Every encoding that holds a private component is allocated at its
    /// exact length, so no reallocation leaves a copy of it in freed memory.
    #[test]
    fn private_key_encodings_allocate_exactly_their_length() {
        let (_, private) = toy_key();
        for der in [private.to_pkcs1_der(), private.to_pkcs8_der()] {
            assert_eq!(der.capacity(), der.len());
        }
        for text in [
            private.to_pkcs1_pem(),
            private.to_pkcs8_pem(),
            private.to_xml(),
        ] {
            assert_eq!(text.capacity(), text.len());
        }
    }

    /// OpenSSL reads the BER forms of the PKCS #8 key, the `RSAPrivateKey`
    /// inside in BER too, as the key the DER form encodes.
    ///
    /// OpenSSL 3.0 refuses one of them with `ASN1_get_object: header too
    /// long`: the `rsaEncryption` NULL written with three length octets,
    /// `05 83 00 00 00`, which X.690 §8.1.3.5 permits. It reads the NULL with
    /// one length octet, and OpenSSL 3.6 reads both. On OpenSSL 3.0 that
    /// refusal is reported and the other forms are checked.
    #[test]
    fn openssl_reads_the_ber_forms_as_the_same_key() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        use crate::public_key::pkix::OneAsymmetricKey;
        use crate::test_utils::{openssl3, openssl3_pkcs8_der, OpenSslOutcome};
        const TEST: &str = "rsa_io::openssl_reads_the_ber_forms_as_the_same_key";
        let (_, private) = toy_key();
        let Some(expected) = openssl3_pkcs8_der("DER", &private.to_pkcs8_der()).or_skip(TEST)
        else {
            return;
        };
        let Some(version) = openssl3(&["version"], b"").or_skip(TEST) else {
            return;
        };
        let openssl_3_0 = version.starts_with(b"OpenSSL 3.0.");
        for style in STYLES {
            let inner = reencode(&private.to_pkcs1_der(), style);
            let ber = reencode(
                &OneAsymmetricKey::new(super::rsa_encryption(), &inner, None).to_der(),
                style,
            );
            let outcome = openssl3_pkcs8_der("DER", &ber);
            if let (true, OpenSslOutcome::Unsupported(reason)) = (openssl_3_0, &outcome) {
                if style.length_octets > 1 {
                    eprintln!("{TEST}: OpenSSL 3.0 refuses {style:?}: {reason}");
                    continue;
                }
            }
            let Some(read) = outcome.or_skip(TEST) else {
                return;
            };
            assert_eq!(read, expected, "{style:?}");
        }
    }
}
