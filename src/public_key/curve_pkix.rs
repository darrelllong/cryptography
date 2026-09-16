//! RFC 8410 key encodings for the algorithms over curve25519 and curve448:
//! X25519 and X448 (RFC 7748) and Ed25519 (RFC 8032).
//!
//! - §3 names each algorithm by one object identifier, whose parameters MUST
//!   be absent wherever it appears.
//! - §4 carries a public key in a `SubjectPublicKeyInfo` whose
//!   `subjectPublicKey` BIT STRING is the key's byte string itself, with no
//!   ASN.1 wrapping.
//! - §7 carries a private key in a `OneAsymmetricKey` (RFC 5958) whose
//!   `privateKey` OCTET STRING holds `CurvePrivateKey ::= OCTET STRING`, the
//!   private key's byte string. The optional version 2 `publicKey` holds the
//!   public key's byte string.
//!
//! RFC 9295 replaces §5, the certificate key-usage rules, which do not touch
//! these encodings. RFC 8410 also assigns `id-Ed448` (1.3.101.113); the crate
//! implements no Ed448 signature, so no identifier for it is defined here.
//!
//! These helpers frame and check the containers. The key modules check the
//! key bytes, including that a version 2 public key is the one the private key
//! derives.
//!
//! The helpers read strict DER. A `OneAsymmetricKey` in BER, which RFC 5958 §2
//! requires receivers to support, reaches them through `pkix::pkcs8_ber` or
//! `PRIVATE KEY` text (RFC 7468 §10), both of which bring it to DER first.
//! That includes `CurvePrivateKey`: RFC 8410 §7 asks only that it be an OCTET
//! STRING, so it may arrive in BER as well.

use crate::public_key::io::{der_octet_string, DerReader};
use crate::public_key::pkix::{
    AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey, SubjectPublicKeyInfo,
};
use crate::zeroize_slice;

/// `id-X25519`, 1.3.101.110 (RFC 8410 §3).
pub(crate) const ID_X25519: ObjectIdentifier = ObjectIdentifier::from_arcs(&[1, 3, 101, 110]);

/// `id-X448`, 1.3.101.111 (RFC 8410 §3).
pub(crate) const ID_X448: ObjectIdentifier = ObjectIdentifier::from_arcs(&[1, 3, 101, 111]);

/// `id-Ed25519`, 1.3.101.112 (RFC 8410 §3).
pub(crate) const ID_ED25519: ObjectIdentifier = ObjectIdentifier::from_arcs(&[1, 3, 101, 112]);

/// The DER `SubjectPublicKeyInfo` of `public_key` under `algorithm`, with the
/// parameters absent (§3) and the key's bytes as the `subjectPublicKey` (§4).
pub(crate) fn public_key_to_spki(algorithm: &ObjectIdentifier, public_key: &[u8]) -> Vec<u8> {
    SubjectPublicKeyInfo::new(AlgorithmIdentifier::new(algorithm, None), public_key).to_der()
}

/// The public key's bytes from the DER `SubjectPublicKeyInfo` in `der`, when
/// its algorithm is `algorithm` with the parameters absent (§3) and the key is
/// `len` bytes long (§4).
pub(crate) fn public_key_from_spki<'a>(
    der: &'a [u8],
    algorithm: &ObjectIdentifier,
    len: usize,
) -> Option<&'a [u8]> {
    let spki = SubjectPublicKeyInfo::from_der(der)?;
    let public_key = spki.subject_public_key();
    (spki.algorithm().matches(algorithm, None) && public_key.len() == len).then_some(public_key)
}

/// The DER `OneAsymmetricKey` of `private_key` under `algorithm` (§7):
/// version 1, the parameters absent, the key's bytes wrapped as
/// `CurvePrivateKey`, and no public key. The intermediate buffer is wiped;
/// only the returned encoding holds the key.
pub(crate) fn private_key_to_pkcs8(algorithm: &ObjectIdentifier, private_key: &[u8]) -> Vec<u8> {
    let mut curve_private_key = der_octet_string(private_key);
    let der = OneAsymmetricKey::new(
        AlgorithmIdentifier::new(algorithm, None),
        &curve_private_key,
        None,
    )
    .to_der();
    zeroize_slice(curve_private_key.as_mut_slice());
    der
}

/// The private key's bytes and the octets of the optional version 2
/// `publicKey` from the DER `OneAsymmetricKey` in `der` (§7), when its
/// algorithm is `algorithm` with the parameters absent (§3) and its
/// `privateKey` holds exactly one `CurvePrivateKey` of `len` bytes. Both are
/// views into `der`; the caller checks the public key against the private one.
pub(crate) fn private_key_from_pkcs8<'a>(
    der: &'a [u8],
    algorithm: &ObjectIdentifier,
    len: usize,
) -> Option<(&'a [u8], Option<&'a [u8]>)> {
    let package = OneAsymmetricKey::from_der(der)?;
    if !package.algorithm().matches(algorithm, None) {
        return None;
    }
    let mut contents = DerReader::new(package.private_key());
    let private_key = contents.read_octet_string()?;
    (contents.is_finished() && private_key.len() == len)
        .then_some((private_key, package.public_key()))
}

#[cfg(test)]
mod tests {
    use super::{
        private_key_from_pkcs8, private_key_to_pkcs8, public_key_from_spki, public_key_to_spki,
        ID_ED25519, ID_X25519, ID_X448,
    };
    use crate::public_key::io::{der_bit_string, der_octet_string, der_oid, der_sequence};
    use crate::public_key::pkix::{AlgorithmIdentifier, OneAsymmetricKey, NULL_PARAMETERS};

    #[test]
    fn identifiers_match_rfc8410_section_3() {
        // 1.3 packs to 2B (X.690 §8.19.4); §10.2 and §10.3 dump 2B 65 6E and
        // 2B 65 70.
        assert_eq!(ID_X25519.content(), [0x2b, 0x65, 0x6e]);
        assert_eq!(ID_X448.content(), [0x2b, 0x65, 0x6f]);
        assert_eq!(ID_ED25519.content(), [0x2b, 0x65, 0x70]);
    }

    #[test]
    fn spki_framing_follows_section_4_and_refuses_the_rest() {
        let key: Vec<u8> = (0x40..0x60).collect();
        let der = public_key_to_spki(&ID_X25519, &key);
        // The 42-byte shape of the §10.2 certificate's key: SEQUENCE {
        // SEQUENCE { OID }, BIT STRING { 00, key } }.
        let expected = [
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
            ][..],
            &key,
        ]
        .concat();
        assert_eq!(der, expected);
        assert_eq!(public_key_from_spki(&der, &ID_X25519, 32), Some(&key[..]));

        let spki = |parameters: &[u8], key: &[u8]| {
            let algorithm =
                der_sequence(&[der_oid(ID_X25519.content()), parameters.to_vec()].concat());
            der_sequence(&[algorithm, der_bit_string(key)].concat())
        };
        assert_eq!(spki(&[], &key), der);
        // Another algorithm, another length, and §3's absent parameters: even
        // NULL is refused.
        assert!(public_key_from_spki(&der, &ID_ED25519, 32).is_none());
        assert!(public_key_from_spki(&der, &ID_X25519, 31).is_none());
        assert!(public_key_from_spki(&spki(&[], &key[..31]), &ID_X25519, 32).is_none());
        assert!(public_key_from_spki(&spki(NULL_PARAMETERS, &key), &ID_X25519, 32).is_none());
        // Bytes after the SEQUENCE.
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(public_key_from_spki(&trailing, &ID_X25519, 32).is_none());
    }

    #[test]
    fn pkcs8_framing_follows_section_7_and_refuses_the_rest() {
        let key: Vec<u8> = (0x60..0x80).collect();
        let der = private_key_to_pkcs8(&ID_X25519, &key);
        // The shape of the §10.3 examples: SEQUENCE { INTEGER 0, SEQUENCE {
        // OID }, OCTET STRING { OCTET STRING { key } } }.
        let expected = [
            &[
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
                0x04, 0x20,
            ][..],
            &key,
        ]
        .concat();
        assert_eq!(der, expected);
        assert_eq!(
            private_key_from_pkcs8(&der, &ID_X25519, 32),
            Some((&key[..], None))
        );

        // A version 2 public key is handed to the caller to check.
        let absent = AlgorithmIdentifier::new(&ID_X25519, None);
        let curve_private_key = der_octet_string(&key);
        let public: Vec<u8> = (0xa0..0xc0).collect();
        let v2 = OneAsymmetricKey::new(absent, &curve_private_key, Some(&public)).to_der();
        assert_eq!(
            private_key_from_pkcs8(&v2, &ID_X25519, 32),
            Some((&key[..], Some(&public[..])))
        );

        let package = |algorithm, private_key: &[u8]| {
            OneAsymmetricKey::new(algorithm, private_key, None).to_der()
        };
        let null = AlgorithmIdentifier::new(&ID_X25519, Some(NULL_PARAMETERS));
        let mut tagged = curve_private_key.clone();
        tagged[0] = 0x80;
        let mut trailing = der.clone();
        trailing.push(0);
        for (rejected, algorithm, why) in [
            (der.clone(), &ID_X448, "another algorithm"),
            (
                package(null, &curve_private_key),
                &ID_X25519,
                "NULL parameters",
            ),
            (package(absent, &key), &ID_X25519, "a bare key"),
            (
                package(absent, &der_octet_string(&key[..31])),
                &ID_X25519,
                "a short key",
            ),
            (
                package(
                    absent,
                    &[curve_private_key.clone(), vec![0x05, 0x00]].concat(),
                ),
                &ID_X25519,
                "data after CurvePrivateKey",
            ),
            (package(absent, &tagged), &ID_X25519, "a [0]-tagged key"),
            (trailing, &ID_X25519, "bytes after the SEQUENCE"),
        ] {
            assert!(
                private_key_from_pkcs8(&rejected, algorithm, 32).is_none(),
                "{why}"
            );
        }
    }

    /// RFC 5958 §2 ("receivers MUST support BER"): a `OneAsymmetricKey` in
    /// any BER form, and a `CurvePrivateKey` in BER inside a DER one (RFC 8410
    /// §7 asks only for an OCTET STRING), reach these DER helpers through the
    /// BER receiver as the key they encode.
    #[test]
    fn ber_keys_reach_the_helpers_through_the_ber_receiver() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        use crate::public_key::pkix::pkcs8_ber;
        let key: Vec<u8> = (0x60..0x80).collect();
        let der = private_key_to_pkcs8(&ID_X25519, &key);
        let read = |ber: &[u8]| {
            pkcs8_ber(ber, |der| {
                private_key_from_pkcs8(der, &ID_X25519, 32)
                    .map(|(scalar, public)| (scalar.to_vec(), public.map(<[u8]>::to_vec)))
            })
        };
        let curve_private_key = reencode(&der_octet_string(&key), STYLES[3]);
        let inner_ber = OneAsymmetricKey::new(
            AlgorithmIdentifier::new(&ID_X25519, None),
            &curve_private_key,
            None,
        )
        .to_der();
        for ber in STYLES
            .iter()
            .map(|&style| reencode(&der, style))
            .chain([inner_ber])
        {
            assert!(private_key_from_pkcs8(&ber, &ID_X25519, 32).is_none());
            assert_eq!(read(&ber), Some((key.clone(), None)), "{ber:02x?}");
        }
    }
}
