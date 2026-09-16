//! Standard key containers: the PKIX structures that carry a public or a
//! private key together with the identifier of its algorithm.
//!
//! - [`AlgorithmIdentifier`], RFC 5280 §4.1.1.2.
//! - [`SubjectPublicKeyInfo`], RFC 5280 §4.1 and §4.1.2.7, for public keys.
//!   Its RFC 7468 §13 textual label is [`PUBLIC_KEY_LABEL`].
//! - [`OneAsymmetricKey`], RFC 5958 §2, for private keys. Version 1 is the
//!   PKCS #8 `PrivateKeyInfo` of RFC 5208 §5; version 2 adds `[1] publicKey`.
//!   Its RFC 7468 §10 textual label is [`PRIVATE_KEY_LABEL`].
//! - [`ObjectIdentifier`], an identifier's X.690 §8.19 contents octets built
//!   at compile time from the components the specifications print, so each
//!   constant can be checked against its RFC by eye.
//! - [`pem_encode`] and [`pem_decode`], the RFC 7468 textual encoding.
//!
//! The algorithm-specific contents — the parameters, the `subjectPublicKey`
//! bits, the `privateKey` octets — are the family modules' to build and to
//! check; this layer frames them in strict DER and nothing more. Decoders are
//! borrowed views that copy no key material, so whoever owns a secret-bearing
//! buffer wipes it. Encoders that handle a private key wipe their intermediate
//! buffers, as `io` does.
//!
//! ## BER receivers
//!
//! RFC 5958 §2 says of `OneAsymmetricKey` that "receivers MUST support BER",
//! and RFC 7468 §10 and §13 say the data under the `PRIVATE KEY` and `PUBLIC
//! KEY` labels "MUST be a BER (DER preferred ...) encoded" `PrivateKeyInfo` or
//! `OneAsymmetricKey`, and `SubjectPublicKeyInfo`. The DER views stay strict;
//! [`one_asymmetric_key_to_der`] and [`subject_public_key_info_to_der`] read
//! any BER encoding of either container and write its DER encoding for them.
//! What a key's octet or bit string holds is its algorithm's to define, and
//! some algorithms require DER there, so those contents are converted only
//! where the algorithm's specification allows BER ([`key_contents`]).
//! [`pem_decode`] applies the conversion under the two labels, and
//! [`pkcs8_ber`] to a binary `OneAsymmetricKey`.

use crate::public_key::curve_pkix::{ID_ED25519, ID_X25519, ID_X448};
use crate::public_key::io::{
    ber_to_der, class, context_tag, der_bit_string, der_implicit_bit_string, der_integer_u8,
    der_octet_string, der_oid, der_sequence, der_sequence_of, pem_contents, pem_wrap, set_of_order,
    tag, wiped_tlv, BerReader, BitString, DerReader, WipedBytes,
};
use crate::zeroize_slice;

// ─── Object identifiers ──────────────────────────────────────────────────────

/// An `OBJECT IDENTIFIER` value, held as the contents octets of its DER
/// encoding (X.690 §8.19).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectIdentifier {
    octets: [u8; ObjectIdentifier::CAPACITY],
    len: usize,
}

impl ObjectIdentifier {
    /// Contents octets an identifier may take. The longest this crate names,
    /// under NIST's 2.16.840.1.101.3.4 arc, needs nine.
    const CAPACITY: usize = 16;

    /// Encode the identifier whose components are `arcs` (X.690 §8.19.2 to
    /// §8.19.5). In constant context a malformed identifier fails the build.
    ///
    /// # Panics
    ///
    /// Panics if there are fewer than two components, if the first two lie
    /// outside what §8.19.4's packing allows (a first component above 2, or a
    /// second above 39 under the roots 0 and 1), or if the encoding would
    /// exceed the capacity.
    pub(crate) const fn from_arcs(arcs: &[u64]) -> Self {
        assert!(
            arcs.len() >= 2,
            "an object identifier has at least two components"
        );
        assert!(
            arcs[0] == 2 || (arcs[0] < 2 && arcs[1] < 40),
            "the first two components are out of range"
        );
        let mut oid = Self {
            octets: [0; Self::CAPACITY],
            len: 0,
        };
        // §8.19.4: the first subidentifier is (X*40) + Y.
        oid.push_subidentifier(arcs[0] * 40 + arcs[1]);
        let mut index = 2;
        while index < arcs.len() {
            // §8.19.5: each later subidentifier is the next component.
            oid.push_subidentifier(arcs[index]);
            index += 1;
        }
        oid
    }

    /// Append one subidentifier (§8.19.2): base 128, most significant group
    /// first, bit 8 set on every octet but the last, in the fewest octets.
    const fn push_subidentifier(&mut self, value: u64) {
        let mut groups = 1;
        while groups < 10 && value >> (7 * groups) != 0 {
            groups += 1;
        }
        assert!(
            self.len + groups <= Self::CAPACITY,
            "object identifier too long"
        );
        while groups > 0 {
            groups -= 1;
            let group = ((value >> (7 * groups)) & 0x7f).to_be_bytes()[7];
            self.octets[self.len] = if groups == 0 { group } else { 0x80 | group };
            self.len += 1;
        }
    }

    /// The contents octets.
    pub(crate) fn content(&self) -> &[u8] {
        &self.octets[..self.len]
    }
}

/// `rsaEncryption`, 1.2.840.113549.1.1.1 (RFC 3279 §2.3.1).
pub(crate) const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[1, 2, 840, 113_549, 1, 1, 1]);

/// The DER encoding of `NULL`: the parameters RFC 3279 §2.3.1 requires with
/// `rsaEncryption`.
pub(crate) const NULL_PARAMETERS: &[u8] = &[0x05, 0x00];

/// `id-ecPublicKey`, 1.2.840.10045.2.1 (RFC 5480 §2.1.1): an elliptic-curve
/// public key usable with any algorithm.
pub(crate) const ID_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[1, 2, 840, 10045, 2, 1]);

/// `id-ecDH`, 1.3.132.1.12 (RFC 5480 §2.1.2): an elliptic-curve public key
/// restricted to Diffie-Hellman key agreement.
pub(crate) const ID_EC_DH: ObjectIdentifier = ObjectIdentifier::from_arcs(&[1, 3, 132, 1, 12]);

/// `id-dsa`, 1.2.840.10040.4.1 (RFC 3279 §2.3.2).
pub(crate) const ID_DSA: ObjectIdentifier = ObjectIdentifier::from_arcs(&[1, 2, 840, 10040, 4, 1]);

/// `dhpublicnumber`, 1.2.840.10046.2.1 (RFC 3279 §2.3.3).
pub(crate) const DH_PUBLIC_NUMBER: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[1, 2, 840, 10046, 2, 1]);

// ─── Textual labels ──────────────────────────────────────────────────────────

/// RFC 7468 §13: the label of a `SubjectPublicKeyInfo`.
pub(crate) const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";

/// RFC 7468 §10: the label of a `OneAsymmetricKey` (`PrivateKeyInfo`).
pub(crate) const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";

/// RFC 5915 §4: the label of a bare `ECPrivateKey` (SEC 1 C.4). RFC 7468 does
/// not list it; RFC 5915 names it for local storage.
pub(crate) const EC_PRIVATE_KEY_LABEL: &str = "EC PRIVATE KEY";

// ─── AlgorithmIdentifier ─────────────────────────────────────────────────────

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
/// parameters ANY DEFINED BY algorithm OPTIONAL }` (RFC 5280 §4.1.1.2).
///
/// The parameters are held as the complete DER encoding of their one value,
/// or absent. DER is canonical, so comparing encodings compares values.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AlgorithmIdentifier<'a> {
    algorithm: &'a [u8],
    parameters: Option<&'a [u8]>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// `algorithm` with `parameters`, the complete DER encoding of one value,
    /// or `None` for absent parameters.
    pub(crate) fn new(algorithm: &'a ObjectIdentifier, parameters: Option<&'a [u8]>) -> Self {
        Self {
            algorithm: algorithm.content(),
            parameters,
        }
    }

    /// The DER encoding.
    pub(crate) fn to_der(self) -> Vec<u8> {
        let mut body = der_oid(self.algorithm);
        if let Some(parameters) = self.parameters {
            body.extend_from_slice(parameters);
        }
        der_sequence(&body)
    }

    /// Read one `AlgorithmIdentifier` from `reader`. Parameters, when present,
    /// must be exactly one value in strict DER
    /// ([`DerReader::read_element`]); what they mean is the caller's to check.
    pub(crate) fn read(reader: &mut DerReader<'a>) -> Option<Self> {
        let body = reader.read_sequence()?;
        let mut fields = DerReader::new(body);
        let algorithm = fields.read_oid()?;
        let parameters = if fields.is_finished() {
            None
        } else {
            Some(fields.read_element()?)
        };
        if !fields.is_finished() {
            return None;
        }
        Some(Self {
            algorithm,
            parameters,
        })
    }

    /// Whether the algorithm is `oid`.
    pub(crate) fn is(&self, oid: &ObjectIdentifier) -> bool {
        self.algorithm == oid.content()
    }

    /// The complete DER encoding of the parameters, or `None` when absent.
    pub(crate) fn parameters(&self) -> Option<&'a [u8]> {
        self.parameters
    }

    /// Whether the algorithm is `oid` and the parameters are exactly
    /// `parameters` (`None` for absent).
    pub(crate) fn matches(&self, oid: &ObjectIdentifier, parameters: Option<&[u8]>) -> bool {
        self.is(oid) && self.parameters() == parameters
    }
}

// ─── SubjectPublicKeyInfo ────────────────────────────────────────────────────

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }` (RFC 5280 §4.1, §4.1.2.7).
///
/// Every public key this crate encodes is a whole number of octets, so the
/// `subjectPublicKey` is held as those octets and a bit string with unused
/// bits does not decode.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    subject_public_key: &'a [u8],
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// A public key under `algorithm`.
    pub(crate) fn new(algorithm: AlgorithmIdentifier<'a>, subject_public_key: &'a [u8]) -> Self {
        Self {
            algorithm,
            subject_public_key,
        }
    }

    /// The DER encoding.
    pub(crate) fn to_der(self) -> Vec<u8> {
        let mut body = self.algorithm.to_der();
        body.extend(der_bit_string(self.subject_public_key));
        der_sequence(&body)
    }

    /// Decode all of `der` as one `SubjectPublicKeyInfo`; trailing bytes fail.
    pub(crate) fn from_der(der: &'a [u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let body = outer.read_sequence()?;
        if !outer.is_finished() {
            return None;
        }
        let mut fields = DerReader::new(body);
        let algorithm = AlgorithmIdentifier::read(&mut fields)?;
        let subject_public_key = fields.read_bit_string()?;
        if !fields.is_finished() {
            return None;
        }
        Some(Self {
            algorithm,
            subject_public_key,
        })
    }

    /// The algorithm identifier.
    pub(crate) fn algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.algorithm
    }

    /// The octets of `subjectPublicKey`.
    pub(crate) fn subject_public_key(&self) -> &'a [u8] {
        self.subject_public_key
    }
}

// ─── OneAsymmetricKey ────────────────────────────────────────────────────────

/// `OneAsymmetricKey` (RFC 5958 §2 and Appendix A, whose module uses implicit
/// tags):
///
/// ```text
/// OneAsymmetricKey ::= SEQUENCE {
///   version                   Version,               -- v1(0), v2(1)
///   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///   privateKey                PrivateKey,            -- OCTET STRING
///   attributes            [0] Attributes OPTIONAL,   -- SET OF Attribute
///   ...,
///   [[2: publicKey        [1] PublicKey OPTIONAL ]], -- BIT STRING
///   ... }
/// ```
///
/// Version 1 is PKCS #8's `PrivateKeyInfo` (RFC 5208 §5). Attributes are
/// checked as strict DER and not kept: no key type in this crate has a use for
/// them, and the encoder never writes any.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OneAsymmetricKey<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    private_key: &'a [u8],
    public_key: Option<&'a [u8]>,
}

impl<'a> OneAsymmetricKey<'a> {
    /// A private key under `algorithm`, with `private_key` the contents of the
    /// `privateKey` OCTET STRING and `public_key` the octets of the optional
    /// `publicKey`. The encoder follows RFC 5958 §2: version 2 exactly when
    /// the public key is present, version 1 otherwise.
    pub(crate) fn new(
        algorithm: AlgorithmIdentifier<'a>,
        private_key: &'a [u8],
        public_key: Option<&'a [u8]>,
    ) -> Self {
        Self {
            algorithm,
            private_key,
            public_key,
        }
    }

    /// The DER encoding, with no attributes. It is allocated at its exact
    /// size and every intermediate buffer that holds the private key is
    /// wiped; only the returned encoding keeps it.
    pub(crate) fn to_der(self) -> Vec<u8> {
        let mut parts = vec![
            der_integer_u8(u8::from(self.public_key.is_some())),
            self.algorithm.to_der(),
            der_octet_string(self.private_key),
        ];
        if let Some(octets) = self.public_key {
            parts.push(der_implicit_bit_string(1, octets));
        }
        der_sequence_of(parts)
    }

    /// Decode all of `der` as one `OneAsymmetricKey`; trailing bytes fail.
    ///
    /// The version is what RFC 5958 §2 ties to the public key: "version
    /// identifies the version of OneAsymmetricKey.  If publicKey is present,
    /// then version is set to v2 else version is set to v1." So v2 is
    /// accepted with `publicKey` and v1 without, and nothing else: `Version
    /// ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)` names no other value. The
    /// attributes must be a DER `SET OF` RFC 5911 `Attribute`s.
    pub(crate) fn from_der(der: &'a [u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let body = outer.read_sequence()?;
        if !outer.is_finished() {
            return None;
        }
        let mut fields = DerReader::new(body);
        let version = fields.read_integer_small()?;
        let algorithm = AlgorithmIdentifier::read(&mut fields)?;
        let private_key = fields.read_octet_string()?;
        if fields.peek_tag() == Some(context_tag(0, true))
            && !attributes_are_der(fields.read_implicit_constructed(0)?)
        {
            return None;
        }
        let public_key = if fields.peek_tag() == Some(context_tag(1, false)) {
            Some(fields.read_implicit_bit_string(1)?)
        } else {
            None
        };
        if !fields.is_finished() || version != u8::from(public_key.is_some()) {
            return None;
        }
        Some(Self {
            algorithm,
            private_key,
            public_key,
        })
    }

    /// The private-key algorithm identifier.
    pub(crate) fn algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.algorithm
    }

    /// The contents of the `privateKey` OCTET STRING.
    pub(crate) fn private_key(&self) -> &'a [u8] {
        self.private_key
    }

    /// The octets of `publicKey`, when present.
    pub(crate) fn public_key(&self) -> Option<&'a [u8]> {
        self.public_key
    }
}

/// The contents of `[0] Attributes` (RFC 5958 §2: `SET OF Attribute`): each
/// element an RFC 5911 `Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER,
/// attrValues SET OF ... }` in strict DER, the elements in X.690 §11.6 order.
fn attributes_are_der(contents: &[u8]) -> bool {
    let mut reader = DerReader::new(contents);
    let mut previous: Option<&[u8]> = None;
    while !reader.is_finished() {
        let Some(attribute) = reader.read_element() else {
            return false;
        };
        if previous.is_some_and(|prior| set_of_order(prior, attribute).is_gt())
            || !is_attribute(attribute)
        {
            return false;
        }
        previous = Some(attribute);
    }
    true
}

/// Whether `encoding`, already checked as DER, has the shape of an RFC 5911
/// `Attribute`.
fn is_attribute(encoding: &[u8]) -> bool {
    let mut outer = DerReader::new(encoding);
    let Some(body) = outer.read_sequence() else {
        return false;
    };
    let mut fields = DerReader::new(body);
    fields.read_oid().is_some()
        && fields.read_set().is_some()
        && fields.is_finished()
        && outer.is_finished()
}

// ─── RFC 7468 textual encoding ───────────────────────────────────────────────

/// Armor `der` under `label` in RFC 7468's strict textual encoding (Figure 3:
/// base64 in lines of exactly 64 characters but the last, LF line ends), then
/// wipe `der`, which may hold a private key.
pub(crate) fn pem_encode(label: &str, mut der: Vec<u8>) -> String {
    let pem = pem_wrap(label, &der);
    zeroize_slice(der.as_mut_slice());
    pem
}

/// Decode the RFC 7468 textual encoding labelled `label` in `text` and hand
/// its contents to `parse`, the text read by RFC 7468 §2's parser rules
/// ([`pem_contents`]).
///
/// RFC 7468 gives each standard label a type and requires its data to be BER:
/// under `PRIVATE KEY`, "The encoded data MUST be a BER (DER preferred ...)
/// encoded ASN.1 PrivateKeyInfo structure ... or a OneAsymmetricKey
/// structure" (§10), and under `PUBLIC KEY` the same of a
/// `SubjectPublicKeyInfo` (§13). Under those two labels the contents are
/// brought to DER first ([`one_asymmetric_key_to_der`],
/// [`subject_public_key_info_to_der`]), so a strict DER `parse` reads every BER
/// form while an algorithm's DER-only contents stay DER-only; DER passes
/// through unchanged. Under any other label the decoded octets go to `parse`
/// as they are: RFC 7468 names no other label this crate uses, and the
/// specifications that name the rest describe DER contents. For `EC PRIVATE
/// KEY`, RFC 5915 §4 asks receivers of a transfer encoding to "be prepared to
/// handle Basic Encoding Rules (BER)", which `from_sec1_ber` and
/// `from_pkcs8_ber` do for the binary object, but defines the text form as
/// "the PEM encoding, which is the Base64 encoding (see Section 4 of
/// [RFC4648]), of the DER-encoded ECPrivateKey object", so `from_sec1_pem`
/// reads strict DER. PKCS #1's `RSA PRIVATE KEY` and `RSA PUBLIC KEY` and the
/// crate's own labels carry DER likewise. Every buffer is wiped before this
/// returns, since it may hold a private key.
pub(crate) fn pem_decode<T>(
    label: &str,
    text: &str,
    parse: impl FnOnce(&[u8]) -> Option<T>,
) -> Option<T> {
    let contents = pem_contents(label, text)?;
    match label {
        PRIVATE_KEY_LABEL => parse(&one_asymmetric_key_to_der(&contents)?),
        PUBLIC_KEY_LABEL => parse(&subject_public_key_info_to_der(&contents)?),
        _ => parse(&contents),
    }
}

/// Decode the binary `OneAsymmetricKey` `ber` in any X.690 BER encoding (RFC
/// 5958 §2: "receivers MUST support BER") and hand its DER encoding to
/// `parse`: the receiver each private-key type's `from_pkcs8_ber` puts in
/// front of its strict `from_pkcs8_der`. The DER encoding is wiped once
/// `parse` returns.
pub(crate) fn pkcs8_ber<T>(ber: &[u8], parse: impl FnOnce(&[u8]) -> Option<T>) -> Option<T> {
    parse(&one_asymmetric_key_to_der(ber)?)
}

// ─── BER receivers ───────────────────────────────────────────────────────────

/// How an algorithm's specification encodes what a key's `privateKey` OCTET
/// STRING or its public key's BIT STRING holds, which decides whether a BER
/// receiver converts those contents along with the container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyContents {
    /// A BER encoding of one ASN.1 value, converted to DER with the container.
    Ber,
    /// Octets taken exactly as they are: a key's own byte string, or an
    /// encoding the specification requires in DER, which a BER container
    /// does not relax.
    Exact,
}

/// The contents rules of the algorithm whose identifier has contents octets
/// `algorithm`: for its private key, then for its public key.
///
/// | Algorithm | `privateKey` | Public key |
/// |---|---|---|
/// | `rsaEncryption` | BER: "the contents are a BER encoding of a value of type RSAPrivateKey" (RFC 5208 §5) | exact: "The DER encoded RSAPublicKey is the value of the BIT STRING" (RFC 3279 §2.3.1) |
/// | `id-dsa` | BER: an `INTEGER` (RFC 5958 §2), under RFC 5208 §5 | exact: "MUST be ASN.1 DER encoded as an INTEGER" (RFC 3279 §2.3.2) |
/// | `id-ecPublicKey`, `id-ecDH` | BER: receivers "SHOULD be prepared to handle Basic Encoding Rules (BER)" for `ECPrivateKey` (RFC 5915 §4) | exact: the `ECPoint` octets (RFC 5480 §2.2) |
/// | `id-X25519`, `id-X448`, `id-Ed25519` | BER: `CurvePrivateKey ::= OCTET STRING` (RFC 8410 §7), under RFC 5208 §5 | exact: the key's own bytes (RFC 8410 §4) |
/// | `dhpublicnumber` | BER: an `INTEGER`, the convention `ffc_pkix` documents, under RFC 5208 §5 | BER: "MUST be ASN.1 encoded as an INTEGER" (RFC 3279 §2.3.3) |
/// | any other, ML-KEM and ML-DSA among them | exact: RFC 9935 §6 and RFC 9881 §6 hold "DER-encoded CHOICE structures" | exact |
fn key_contents(algorithm: &[u8]) -> (KeyContents, KeyContents) {
    use KeyContents::{Ber, Exact};
    let is = |oid: &ObjectIdentifier| algorithm == oid.content();
    if [
        &RSA_ENCRYPTION,
        &ID_DSA,
        &ID_EC_PUBLIC_KEY,
        &ID_EC_DH,
        &ID_X25519,
        &ID_X448,
        &ID_ED25519,
    ]
    .into_iter()
    .any(is)
    {
        (Ber, Exact)
    } else if is(&DH_PUBLIC_NUMBER) {
        (Ber, Ber)
    } else {
        (Exact, Exact)
    }
}

/// `octets`, what a key's octet string holds, in the form `rule` gives it in
/// DER: converted when it is a BER encoding, as it is otherwise.
fn contents_to_der(rule: KeyContents, octets: WipedBytes) -> Option<WipedBytes> {
    match rule {
        KeyContents::Ber => ber_to_der(&octets),
        KeyContents::Exact => Some(octets),
    }
}

/// `bits`, a public key's bit string, in the form `rule` gives it in DER. An
/// encoding is a whole number of octets, so BER contents with unused bits
/// fail.
fn bits_to_der(rule: KeyContents, bits: BitString) -> Option<BitString> {
    match rule {
        KeyContents::Ber if bits.unused() == 0 => {
            Some(BitString::whole_octets(ber_to_der(bits.octets())?))
        }
        KeyContents::Ber => None,
        KeyContents::Exact => Some(bits),
    }
}

/// Read an `AlgorithmIdentifier` (RFC 5280 §4.1.1.2) in BER: the contents
/// octets of the algorithm's identifier, and the DER encoding of the whole,
/// the parameters converted as `ANY` ([`BerReader::read_any`]).
fn algorithm_identifier_to_der<'a>(reader: &mut BerReader<'a>) -> Option<(&'a [u8], WipedBytes)> {
    reader.read_sequence(|fields| {
        let algorithm = fields.read_oid()?;
        let parameters = if fields.is_finished() {
            None
        } else {
            Some(fields.read_any()?)
        };
        let identifier = der_oid(algorithm);
        let der = wiped_tlv(
            tag::SEQUENCE,
            &[&identifier, parameters.as_deref().unwrap_or(&[])],
        );
        Some((algorithm, der))
    })
}

/// The DER encoding of the `OneAsymmetricKey` that `ber` holds in BER (RFC
/// 5958 §2 and Appendix A, whose module tags implicitly), all of `ber`.
///
/// Every component may take any form X.690 clause 8 allows ([`BerReader`]):
/// definite lengths in any number of octets or indefinite ones, the
/// `privateKey` OCTET STRING and the `[1]` public key constructed from
/// segments, the attributes in any order. The version's value and each
/// attribute's shape are left for [`OneAsymmetricKey::from_der`] to check. The
/// key's contents are converted as [`key_contents`] allows. The result is
/// allocated at its exact size and wiped when dropped.
pub(crate) fn one_asymmetric_key_to_der(ber: &[u8]) -> Option<WipedBytes> {
    let mut reader = BerReader::new(ber);
    let der = reader.read_sequence(|fields| {
        let version = fields.read_integer()?;
        let (algorithm, algorithm_der) = algorithm_identifier_to_der(fields)?;
        let (private_rule, public_rule) = key_contents(algorithm);
        let private_key = contents_to_der(private_rule, fields.read_octet_string()?)?;
        let attributes = if fields.next_is(class::CONTEXT_SPECIFIC, 0) {
            Some(fields.read_set_of(class::CONTEXT_SPECIFIC, 0)?)
        } else {
            None
        };
        let public_key = if fields.next_is(class::CONTEXT_SPECIFIC, 1) {
            let bits = fields.read_bit_string(class::CONTEXT_SPECIFIC, 1)?;
            Some(bits_to_der(public_rule, bits)?.to_der(context_tag(1, false)))
        } else {
            None
        };
        let private_key = wiped_tlv(tag::OCTET_STRING, &[&private_key[..]]);
        Some(wiped_tlv(
            tag::SEQUENCE,
            &[
                &version[..],
                &algorithm_der[..],
                &private_key[..],
                attributes.as_deref().unwrap_or(&[]),
                public_key.as_deref().unwrap_or(&[]),
            ],
        ))
    })?;
    reader.is_finished().then_some(der)
}

/// The DER encoding of the `SubjectPublicKeyInfo` that `ber` holds in BER (RFC
/// 5280 §4.1: `SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT
/// STRING }`), all of `ber`, the key's bit string converted as
/// [`key_contents`] allows.
pub(crate) fn subject_public_key_info_to_der(ber: &[u8]) -> Option<WipedBytes> {
    let mut reader = BerReader::new(ber);
    let der = reader.read_sequence(|fields| {
        let (algorithm, algorithm_der) = algorithm_identifier_to_der(fields)?;
        let (_, public_rule) = key_contents(algorithm);
        let bits = fields.read_bit_string(class::UNIVERSAL, 3)?;
        let subject_public_key = bits_to_der(public_rule, bits)?.to_der(tag::BIT_STRING);
        Some(wiped_tlv(
            tag::SEQUENCE,
            &[&algorithm_der[..], &subject_public_key[..]],
        ))
    })?;
    reader.is_finished().then_some(der)
}

#[cfg(test)]
mod tests {
    use super::{
        one_asymmetric_key_to_der, pem_decode, pem_encode, pkcs8_ber,
        subject_public_key_info_to_der, AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey,
        SubjectPublicKeyInfo, DH_PUBLIC_NUMBER, NULL_PARAMETERS, PRIVATE_KEY_LABEL,
        PUBLIC_KEY_LABEL, RSA_ENCRYPTION,
    };
    use crate::public_key::io::ber_forms::{reencode, STYLES};
    use crate::public_key::io::{
        der_integer_u8, der_octet_string, der_sequence, pem_contents, DerReader,
    };
    use crate::test_utils::openssl3;

    /// RFC 8410 §9: `id-Ed25519 OBJECT IDENTIFIER ::= { 1 3 101 112 }`, used
    /// here only as the algorithm of the RFC's container examples.
    const ID_ED25519: ObjectIdentifier = ObjectIdentifier::from_arcs(&[1, 3, 101, 112]);

    /// RFC 8410 §10.3, first example: a version 1 key.
    const RFC8410_V1_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
        -----END PRIVATE KEY-----\n";

    /// RFC 8410 §10.3, second example: version 2 with an attribute and the
    /// public key.
    const RFC8410_V2_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
        oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n\
        Z9w7lshQhqowtrbLDFw4rXAxZuE=\n\
        -----END PRIVATE KEY-----\n";

    /// The `privateKey` contents of both examples: `CurvePrivateKey`, itself
    /// an OCTET STRING.
    const RFC8410_PRIVATE_KEY: [u8; 34] = [
        0x04, 0x20, 0xD4, 0xEE, 0x72, 0xDB, 0xF9, 0x13, 0x58, 0x4A, 0xD5, 0xB6, 0xD8, 0xF1, 0xF7,
        0x69, 0xF8, 0xAD, 0x3A, 0xFE, 0x7C, 0x28, 0xCB, 0xF1, 0xD4, 0xFB, 0xE0, 0x97, 0xA8, 0x8F,
        0x44, 0x75, 0x58, 0x42,
    ];

    /// The `publicKey` of the second example.
    const RFC8410_PUBLIC_KEY: [u8; 32] = [
        0x19, 0xBF, 0x44, 0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1, 0x67, 0xDC, 0x3B,
        0x96, 0xC8, 0x50, 0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD, 0x70, 0x31,
        0x66, 0xE1,
    ];

    fn der_of(pem: &str) -> Vec<u8> {
        pem_decode(PRIVATE_KEY_LABEL, pem, |der| Some(der.to_vec())).expect("RFC 7468 text")
    }

    #[test]
    fn object_identifiers_match_x690_and_the_rfcs() {
        // X.690 §8.19.5 EXAMPLE: {2 999 3} has contents 88 37 03.
        assert_eq!(
            ObjectIdentifier::from_arcs(&[2, 999, 3]).content(),
            [0x88, 0x37, 0x03]
        );
        // The rsaEncryption octets the RSA containers carried before this
        // layer existed, cross-checked there against OpenSSL.
        assert_eq!(
            RSA_ENCRYPTION.content(),
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        );
        // RFC 8410 §10.3's dump: 06 03 2B 65 70.
        assert_eq!(ID_ED25519.content(), [0x2b, 0x65, 0x70]);
    }

    #[test]
    fn rfc8410_version_1_example_decodes_and_reencodes_exactly() {
        let der = der_of(RFC8410_V1_PEM);
        let key = OneAsymmetricKey::from_der(&der).expect("RFC 8410 §10.3 example");
        assert!(key.algorithm().matches(&ID_ED25519, None));
        assert_eq!(key.private_key(), RFC8410_PRIVATE_KEY);
        assert!(key.public_key().is_none());

        let rebuilt = OneAsymmetricKey::new(
            AlgorithmIdentifier::new(&ID_ED25519, None),
            &RFC8410_PRIVATE_KEY,
            None,
        )
        .to_der();
        assert_eq!(rebuilt, der);
        // The RFC prints the strict textual form, which the encoder emits.
        assert_eq!(pem_encode(PRIVATE_KEY_LABEL, rebuilt), RFC8410_V1_PEM);
    }

    #[test]
    fn rfc8410_version_2_example_with_attribute_and_public_key_decodes() {
        let der = der_of(RFC8410_V2_PEM);
        let key = OneAsymmetricKey::from_der(&der).expect("RFC 8410 §10.3 example");
        assert!(key.algorithm().matches(&ID_ED25519, None));
        assert_eq!(key.private_key(), RFC8410_PRIVATE_KEY);
        assert_eq!(key.public_key(), Some(&RFC8410_PUBLIC_KEY[..]));

        // Without the attribute, the encoder's version 2 form is the example
        // with its [0] element removed: offsets 48..81 in the RFC's dump.
        let rebuilt = OneAsymmetricKey::new(
            AlgorithmIdentifier::new(&ID_ED25519, None),
            &RFC8410_PRIVATE_KEY,
            Some(&RFC8410_PUBLIC_KEY),
        )
        .to_der();
        let mut expected = der[2..48].to_vec();
        expected.extend_from_slice(&der[81..]);
        assert_eq!(rebuilt, der_sequence(&expected));
        let reparsed = OneAsymmetricKey::from_der(&rebuilt).expect("version 2 round trip");
        assert_eq!(reparsed.public_key(), Some(&RFC8410_PUBLIC_KEY[..]));
    }

    /// The RFC 8410 version 2 example with its body rebuilt from `parts`.
    fn one_asymmetric_key(parts: &[&[u8]]) -> Vec<u8> {
        der_sequence(&parts.concat())
    }

    #[test]
    fn one_asymmetric_key_enforces_rfc5958_structure() {
        let algorithm = AlgorithmIdentifier::new(&ID_ED25519, None).to_der();
        let private = der_octet_string(&RFC8410_PRIVATE_KEY);
        let attribute = der_of(RFC8410_V2_PEM)[48..81].to_vec();
        let mut public = vec![0x81, 0x21, 0x00];
        public.extend_from_slice(&RFC8410_PUBLIC_KEY);
        let v1 = der_integer_u8(0);
        let v2 = der_integer_u8(1);

        // Accepted: v1, v1 with attributes, v2 with the public key, v2 with
        // both.
        for parts in [
            vec![&v1[..], &algorithm, &private],
            vec![&v1[..], &algorithm, &private, &attribute],
            vec![&v2[..], &algorithm, &private, &public],
            vec![&v2[..], &algorithm, &private, &attribute, &public],
        ] {
            assert!(OneAsymmetricKey::from_der(&one_asymmetric_key(&parts)).is_some());
        }

        // RFC 5958 §2: "If publicKey is present, then version is set to v2
        // else version is set to v1", so v1 with a public key and v2 without
        // one fail; there is no version 3.
        let v3 = der_integer_u8(2);
        for parts in [
            vec![&v1[..], &algorithm, &private, &public],
            vec![&v2[..], &algorithm, &private],
            vec![&v2[..], &algorithm, &private, &attribute],
            vec![&v3[..], &algorithm, &private],
            vec![&v3[..], &algorithm, &private, &public],
        ] {
            assert!(
                OneAsymmetricKey::from_der(&one_asymmetric_key(&parts)).is_none(),
                "{parts:02x?}"
            );
        }
        // Components out of order, repeated, or unknown.
        assert!(OneAsymmetricKey::from_der(&one_asymmetric_key(&[
            &v2, &algorithm, &private, &public, &attribute
        ]))
        .is_none());
        assert!(OneAsymmetricKey::from_der(&one_asymmetric_key(&[
            &v2, &algorithm, &private, &public, &public
        ]))
        .is_none());
        assert!(OneAsymmetricKey::from_der(&one_asymmetric_key(&[
            &v1,
            &algorithm,
            &private,
            &[0x82, 0x00]
        ]))
        .is_none());
        // A public key with unused bits, or constructed.
        let mut unused_bits = public.clone();
        unused_bits[2] = 0x01;
        assert!(OneAsymmetricKey::from_der(&one_asymmetric_key(&[
            &v2,
            &algorithm,
            &private,
            &unused_bits
        ]))
        .is_none());
        let mut constructed = public.clone();
        constructed[0] = 0xA1;
        assert!(OneAsymmetricKey::from_der(&one_asymmetric_key(&[
            &v2,
            &algorithm,
            &private,
            &constructed
        ]))
        .is_none());
        // Trailing bytes after the SEQUENCE.
        let mut trailing = one_asymmetric_key(&[&v1, &algorithm, &private]);
        trailing.push(0);
        assert!(OneAsymmetricKey::from_der(&trailing).is_none());
    }

    #[test]
    fn attributes_must_be_a_der_set_of_attribute() {
        let algorithm = AlgorithmIdentifier::new(&ID_ED25519, None).to_der();
        let private = der_octet_string(&RFC8410_PRIVATE_KEY);
        let v1 = der_integer_u8(0);
        let parse = |attributes: &[u8]| {
            OneAsymmetricKey::from_der(&one_asymmetric_key(&[
                &v1, &algorithm, &private, attributes,
            ]))
            .is_some()
        };
        // Attribute { 1.2.3, SET { INTEGER 1 } } and { 1.2.4, SET { INTEGER 1 } }.
        let first: &[u8] = &[
            0x30, 0x09, 0x06, 0x02, 0x2a, 0x03, 0x31, 0x03, 0x02, 0x01, 0x01,
        ];
        let second: &[u8] = &[
            0x30, 0x09, 0x06, 0x02, 0x2a, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01,
        ];
        let wrap = |body: &[u8]| {
            let mut out = vec![0xA0, u8::try_from(body.len()).expect("short")];
            out.extend_from_slice(body);
            out
        };
        assert!(parse(&wrap(&[])));
        assert!(parse(&wrap(&[first, second].concat())));
        // §11.6 order.
        assert!(!parse(&wrap(&[second, first].concat())));
        // Not an Attribute: a bare OID, or a SEQUENCE without the SET.
        assert!(!parse(&wrap(&[0x06, 0x02, 0x2a, 0x03])));
        assert!(!parse(&wrap(&[0x30, 0x04, 0x06, 0x02, 0x2a, 0x03])));
        // A value that is BER but not DER: INTEGER 1 with a redundant octet.
        let non_minimal: &[u8] = &[
            0x30, 0x0a, 0x06, 0x02, 0x2a, 0x03, 0x31, 0x04, 0x02, 0x02, 0x00, 0x01,
        ];
        assert!(!parse(&wrap(non_minimal)));

        // An attribute value under a universal tag number X.680 leaves
        // unassigned (15, and 37 in the high-tag-number form) is DER when
        // primitive: it carries no rule to check, and the BER receiver copies
        // it as it is, so the DER view and the receiver agree on the key.
        // Constructed, its DER form would need the type, and both refuse it.
        for (values, accepted) in [
            (&[0x0f, 0x00][..], true),
            (&[0x1f, 0x25, 0x00], true),
            (&[0x0f, 0x00, 0x1f, 0x25, 0x00], true),
            (&[0x2f, 0x00], false),
            (&[0x3f, 0x25, 0x00], false),
        ] {
            let set = [
                &[0x31, u8::try_from(values.len()).expect("short")][..],
                values,
            ]
            .concat();
            let attribute = der_sequence(&[&[0x06, 0x02, 0x2a, 0x03][..], &set].concat());
            let key = one_asymmetric_key(&[&v1, &algorithm, &private, &wrap(&attribute)]);
            assert_eq!(
                OneAsymmetricKey::from_der(&key).is_some(),
                accepted,
                "{values:02x?}"
            );
            assert_eq!(
                one_asymmetric_key_to_der(&key).as_deref(),
                accepted.then_some(&key[..]),
                "{values:02x?}"
            );
        }
    }

    #[test]
    fn subject_public_key_info_round_trips_and_rejects_non_der() {
        let parameters: &[u8] = NULL_PARAMETERS;
        let key: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let der = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(&RSA_ENCRYPTION, Some(parameters)),
            key,
        )
        .to_der();
        let spki = SubjectPublicKeyInfo::from_der(&der).expect("round trip");
        assert!(spki
            .algorithm()
            .matches(&RSA_ENCRYPTION, Some(NULL_PARAMETERS)));
        assert!(!spki.algorithm().matches(&RSA_ENCRYPTION, None));
        assert_eq!(spki.subject_public_key(), key);

        let mut trailing = der.clone();
        trailing.push(0);
        assert!(SubjectPublicKeyInfo::from_der(&trailing).is_none());

        let spki_with = |algorithm_body: &[u8], bit_string: &[u8]| {
            let mut body = der_sequence(algorithm_body);
            body.extend_from_slice(bit_string);
            SubjectPublicKeyInfo::from_der(&der_sequence(&body)).is_none()
        };
        let oid = [&[0x06u8, 0x09][..], RSA_ENCRYPTION.content()].concat();
        let bits = [&[0x03u8, 0x06, 0x00][..], key].concat();
        // Non-DER NULL, two parameter values, a parameter that is not DER, and
        // a bit string with unused bits.
        assert!(spki_with(&[&oid[..], &[0x05, 0x01, 0x00]].concat(), &bits));
        assert!(spki_with(
            &[&oid[..], NULL_PARAMETERS, NULL_PARAMETERS].concat(),
            &bits
        ));
        assert!(spki_with(&[&oid[..], &[0x01, 0x01, 0x01]].concat(), &bits));
        let mut unused = bits.clone();
        unused[2] = 0x01;
        assert!(spki_with(&[&oid[..], NULL_PARAMETERS].concat(), &unused));
        assert!(!spki_with(&[&oid[..], NULL_PARAMETERS].concat(), &bits));
    }

    #[test]
    fn read_element_applies_the_schema_free_der_rules() {
        let element = |bytes: &[u8]| {
            let mut reader = DerReader::new(bytes);
            reader.read_element().is_some() && reader.is_finished()
        };
        // Accepted: BOOLEAN TRUE, a negative INTEGER, a BIT STRING with its
        // unused bits zero, an ordered SET, a high tag number, opaque [0].
        for good in [
            &[0x01, 0x01, 0xff][..],
            &[0x02, 0x01, 0x80],
            &[0x03, 0x02, 0x04, 0xf0],
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            &[0x9f, 0x1f, 0x00],
            &[0x80, 0x02, 0x00, 0x00],
        ] {
            assert!(element(good), "{good:02x?}");
        }
        // Rejected: BOOLEAN 01, INTEGER FF 80, a set unused bit, a constructed
        // OCTET STRING, a primitive SEQUENCE, an unordered SET, tag 5 in the
        // high-number form, an OID subidentifier led by 80, a NULL with
        // contents, end-of-contents, and nesting past the depth bound.
        let mut deep = vec![0x04, 0x00];
        for _ in 0..40 {
            let mut outer = vec![0x30, u8::try_from(deep.len()).expect("short")];
            outer.extend_from_slice(&deep);
            deep = outer;
        }
        for bad in [
            &[0x01, 0x01, 0x01][..],
            &[0x02, 0x02, 0xff, 0x80],
            &[0x03, 0x02, 0x04, 0xf8],
            &[0x24, 0x03, 0x04, 0x01, 0x00],
            &[0x10, 0x00],
            &[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01],
            &[0x1f, 0x05, 0x00],
            &[0x06, 0x02, 0x80, 0x01],
            &[0x05, 0x01, 0x00],
            &[0x00, 0x00],
            &deep[..],
        ] {
            assert!(!element(bad), "{bad:02x?}");
        }
    }

    /// The base64 of the RFC 8410 version 1 example, on one line.
    const RFC8410_V1_BASE64: &str =
        "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";

    /// RFC 8410 Appendix A: "The following is a BER encoding of a private key;
    /// it is valid, but it may not be accepted by many systems."
    const RFC8410_BER_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIACAQAwgAYDK2VwAAAEIgQg1O5y2/kTWErVttjx92n4rTr+fCjL8dT74Jeoj0R1W\n\
        EIAAA==\n\
        -----END PRIVATE KEY-----\n";

    fn decoded(label: &str, text: &str) -> Option<Vec<u8>> {
        pem_decode(label, text, |der| Some(der.to_vec()))
    }

    #[test]
    fn pem_decode_follows_the_rfc7468_parser_rules() {
        let expected = der_of(RFC8410_V1_PEM);
        let body = RFC8410_V1_BASE64;
        let (head, tail) = body.split_at(10);
        let accepted = [
            // §2: "Data before the encapsulation boundaries are permitted, and
            // parsers MUST NOT malfunction when processing such data": text,
            // another label's instance, and text sharing a line with a
            // boundary look-alike.
            format!("A key follows.\n-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            format!(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n\
                 -----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
            ),
            format!(
                "x -----BEGIN PRIVATE KEY-----\n\
                 -----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
            ),
            // §2: parsers "MUST handle different newline conventions": CRLF,
            // CR, a mixture, and no line end after the end boundary (§3
            // Figure 1: `posteb *WSP [eol]`).
            format!("-----BEGIN PRIVATE KEY-----\r\n{body}\r\n-----END PRIVATE KEY-----\r\n"),
            format!("-----BEGIN PRIVATE KEY-----\r{body}\r-----END PRIVATE KEY-----"),
            format!("-----BEGIN PRIVATE KEY-----\n{head}\r\n{tail}\r-----END PRIVATE KEY-----\n"),
            // §2: "Empty space can appear between the pre-encapsulation
            // boundary and the base64".
            format!("-----BEGIN PRIVATE KEY-----\n\n \t\n{body}\n-----END PRIVATE KEY-----\n"),
            // §2: "Parsers MAY handle other line sizes".
            format!("-----BEGIN PRIVATE KEY-----\n{head}\n{tail}\n-----END PRIVATE KEY-----\n"),
            // §2: "parsers SHOULD ignore whitespace and other non-base64
            // characters": blanks at either end of a base64 line, a blank line
            // inside the base64, VT and FF, whitespace around the boundaries on
            // their lines, and characters outside the base64 alphabet.
            format!(
                "-----BEGIN PRIVATE KEY----- \n  {head} \t\n\n{tail}  \n-----END PRIVATE KEY-----\t\n"
            ),
            format!("-----BEGIN PRIVATE KEY-----\n{head}\u{0b}{tail}\u{0c}\n-----END PRIVATE KEY-----\n"),
            format!("  -----BEGIN PRIVATE KEY-----\n{body}\n   -----END PRIVATE KEY-----   \n"),
            format!("-----BEGIN PRIVATE KEY-----\n{head}*.{tail}\u{e9}\n-----END PRIVATE KEY-----\n"),
            // §2: "Files MAY contain multiple textual encoding instances"; what
            // follows the end boundary's line is not this message.
            format!(
                "-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n\
                 more text\n-----BEGIN X-----\n"
            ),
        ];
        for text in &accepted {
            assert_eq!(
                decoded(PRIVATE_KEY_LABEL, text).as_deref(),
                Some(&expected[..]),
                "{text:?}"
            );
        }
        // §3 Figure 1's `base64finl` puts padding on two lines (`base64pad
        // *WSP eol base64pad`); RFC 4648 §10: "f" is "Zg==".
        assert_eq!(
            decoded("X", "-----BEGIN X-----\nZg=\n=\n-----END X-----\n"),
            Some(b"f".to_vec())
        );
        // §3: `label = [ labelchar *( ["-" / SP] labelchar ) ]  ; empty ok`.
        assert_eq!(
            decoded("", "-----BEGIN -----\nZg==\n-----END -----\n"),
            Some(b"f".to_vec())
        );
    }

    #[test]
    fn pem_decode_rejects_what_rfc7468_does_not_allow() {
        let body = RFC8410_V1_BASE64;
        let rejected = [
            // §2: the label names the type, and labels are "formally
            // case-sensitive".
            format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN private key-----\n{body}\n-----END private key-----\n"),
            // §2: "There is exactly one space character (SP) separating the
            // "BEGIN" or "END" from the label. There are exactly five
            // hyphen-minus ... no more, no less."
            format!("-----BEGIN  PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            format!("----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY------\n{body}\n-----END PRIVATE KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY----\n"),
            // §2: the encoding "begins with a line comprising" its boundary and
            // "ends with a line comprising" the other, so a boundary shares its
            // line with nothing but whitespace: text before it, base64 after
            // the first, base64 before the second, text after the second.
            format!("x -----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY-----{body}\n-----END PRIVATE KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----x\n"),
            // §2: "Generators MUST put the same label on the "-----END " line";
            // a parser "MAY disregard the label ... instead of signaling an
            // error", and this one signals it. No end boundary at all, and a
            // second pre-encapsulation boundary inside the message.
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n"),
            format!(
                "-----BEGIN PRIVATE KEY-----\n{body}\n\
                 -----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
            ),
            String::new(),
        ];
        for text in &rejected {
            assert!(decoded(PRIVATE_KEY_LABEL, text).is_none(), "{text:?}");
        }
        // §2 makes the data "base64-encoded data according to Section 4 of
        // [RFC4648]": padding missing or inside the data, too much padding,
        // and non-zero pad bits, which RFC 4648 §3.5 lets a decoder refuse.
        for base64 in ["Zg", "Zg==Zg==", "Z===", "Zh=="] {
            let text = format!("-----BEGIN X-----\n{base64}\n-----END X-----\n");
            assert!(decoded("X", &text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn rfc8410_ber_example_is_the_der_example_in_ber() {
        const TEST: &str = "rfc8410_ber_example_is_the_der_example_in_ber";
        let expected = der_of(RFC8410_V1_PEM);
        // RFC 7468 §10: the data "MUST be a BER (DER preferred ...)" encoding.
        assert_eq!(
            decoded(PRIVATE_KEY_LABEL, RFC8410_BER_PEM).as_deref(),
            Some(&expected[..])
        );
        // RFC 5958 §2: "receivers MUST support BER". The DER view does not.
        let ber = pem_contents(PRIVATE_KEY_LABEL, RFC8410_BER_PEM).expect("base64");
        assert_eq!(ber[..2], [0x30, 0x80]);
        assert!(OneAsymmetricKey::from_der(&ber).is_none());
        assert_eq!(
            pkcs8_ber(&ber, |der| Some(der.to_vec())).as_deref(),
            Some(&expected[..])
        );
        // OpenSSL, run as a black box, reads the BER example as the same key.
        let Some(openssl) = openssl3(
            &["pkey", "-inform", "PEM", "-outform", "DER"],
            RFC8410_BER_PEM.as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(openssl, expected);
    }

    #[test]
    fn one_asymmetric_key_in_every_ber_form_converts_to_its_der() {
        let v1 = der_of(RFC8410_V1_PEM);
        let v2 = der_of(RFC8410_V2_PEM);
        for der in [&v1, &v2] {
            assert_eq!(one_asymmetric_key_to_der(der).as_deref(), Some(&der[..]));
            for style in STYLES {
                let ber = reencode(der, style);
                assert!(OneAsymmetricKey::from_der(&ber).is_none(), "{style:?}");
                assert_eq!(
                    one_asymmetric_key_to_der(&ber).as_deref(),
                    Some(&der[..]),
                    "{style:?}"
                );
            }
        }

        // X.690 §8.12.3: a SET OF need not keep its order, so the attributes
        // may arrive in any order; DER takes §11.6's.
        let curdle = &v2[50..81];
        let small: &[u8] = &[
            0x30, 0x09, 0x06, 0x02, 0x2a, 0x03, 0x31, 0x03, 0x02, 0x01, 0x01,
        ];
        let algorithm = AlgorithmIdentifier::new(&ID_ED25519, None).to_der();
        let private = der_octet_string(&RFC8410_PRIVATE_KEY);
        let with_attributes = |attributes: &[&[u8]]| {
            let set = attributes.concat();
            let tagged = [&[0xa0, u8::try_from(set.len()).expect("short")][..], &set].concat();
            one_asymmetric_key(&[&der_integer_u8(0), &algorithm, &private, &tagged])
        };
        let sorted = with_attributes(&[small, curdle]);
        let unsorted = with_attributes(&[curdle, small]);
        assert!(OneAsymmetricKey::from_der(&sorted).is_some());
        assert!(OneAsymmetricKey::from_der(&unsorted).is_none());
        assert_eq!(
            one_asymmetric_key_to_der(&unsorted).as_deref(),
            Some(&sorted[..])
        );

        // RFC 8410 §7's CurvePrivateKey inside the privateKey may be BER too:
        // here constructed from two segments.
        let key = &RFC8410_PRIVATE_KEY[2..];
        let curve_private_key = [
            &[0x24, 0x80, 0x04, 0x10][..],
            &key[..16],
            &[0x04, 0x10],
            &key[16..],
            &[0x00, 0x00],
        ]
        .concat();
        let inner_ber = one_asymmetric_key(&[
            &der_integer_u8(0),
            &algorithm,
            &der_octet_string(&curve_private_key),
        ]);
        assert!(OneAsymmetricKey::from_der(&inner_ber).is_some());
        assert_eq!(
            one_asymmetric_key_to_der(&inner_ber).as_deref(),
            Some(&v1[..])
        );
    }

    #[test]
    fn subject_public_key_info_in_every_ber_form_converts_to_its_der() {
        let key: Vec<u8> = (0x40..0x60).collect();
        let der =
            SubjectPublicKeyInfo::new(AlgorithmIdentifier::new(&ID_ED25519, None), &key).to_der();
        assert_eq!(
            subject_public_key_info_to_der(&der).as_deref(),
            Some(&der[..])
        );
        for style in STYLES {
            let ber = reencode(&der, style);
            assert!(SubjectPublicKeyInfo::from_der(&ber).is_none(), "{style:?}");
            assert_eq!(
                subject_public_key_info_to_der(&ber).as_deref(),
                Some(&der[..]),
                "{style:?}"
            );
            // RFC 7468 §13: `PUBLIC KEY` data "MUST be a BER (DER preferred
            // ...)" encoding.
            let text = pem_encode(PUBLIC_KEY_LABEL, ber);
            assert_eq!(decoded(PUBLIC_KEY_LABEL, &text).as_deref(), Some(&der[..]));
        }
    }

    #[test]
    fn a_ber_container_does_not_relax_contents_an_algorithm_requires_in_der() {
        // RFC 9935 §6 and RFC 9881 §6 put "DER-encoded CHOICE structures" in
        // the privateKey. An algorithm not listed as BER keeps its contents
        // exactly, so the CHOICE decoder still sees this seed's long-form
        // length and refuses it.
        let ml_kem_768 = ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 2]);
        let algorithm = AlgorithmIdentifier::new(&ml_kem_768, None).to_der();
        let seed_in_long_form = [&[0x80, 0x81, 0x40][..], &[0x5a; 64]].concat();
        let der = one_asymmetric_key(&[
            &der_integer_u8(0),
            &algorithm,
            &der_octet_string(&seed_in_long_form),
        ]);
        for style in STYLES {
            assert_eq!(
                one_asymmetric_key_to_der(&reencode(&der, style)).as_deref(),
                Some(&der[..]),
                "{style:?}"
            );
        }

        // RFC 3279 §2.3.1: "The DER encoded RSAPublicKey is the value of the
        // BIT STRING", so its long-form length is kept for the RSA decoder to
        // refuse; a Diffie-Hellman key is only "ASN.1 encoded" (§2.3.3), so
        // its INTEGER is converted.
        let rsa_key = [0x30, 0x81, 0x06, 0x02, 0x01, 0x0b, 0x02, 0x01, 0x03];
        let rsa = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(&RSA_ENCRYPTION, Some(NULL_PARAMETERS)),
            &rsa_key,
        )
        .to_der();
        assert_eq!(
            subject_public_key_info_to_der(&reencode(&rsa, STYLES[0])).as_deref(),
            Some(&rsa[..])
        );
        let dh = |key: &[u8]| {
            SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(NULL_PARAMETERS)),
                key,
            )
            .to_der()
        };
        assert_eq!(
            subject_public_key_info_to_der(&dh(&[0x02, 0x81, 0x01, 0x12])).as_deref(),
            Some(&dh(&[0x02, 0x01, 0x12])[..])
        );
        // BER contents must be a whole number of octets.
        let mut unused_bits = dh(&[0x02, 0x01, 0x12]);
        let at = unused_bits.len() - 4;
        assert_eq!(unused_bits[at], 0x00);
        unused_bits[at] = 0x01;
        assert!(subject_public_key_info_to_der(&unused_bits).is_none());
    }

    #[test]
    fn ber_containers_fail_where_ber_or_the_structure_does() {
        let v1 = der_of(RFC8410_V1_PEM);
        let ber = reencode(&v1, STYLES[3]);
        for end in 0..ber.len() {
            assert!(one_asymmetric_key_to_der(&ber[..end]).is_none(), "{end}");
        }
        let mut trailing = ber.clone();
        trailing.push(0x00);
        assert!(one_asymmetric_key_to_der(&trailing).is_none());

        let algorithm = AlgorithmIdentifier::new(&ID_ED25519, None).to_der();
        let private = der_octet_string(&RFC8410_PRIVATE_KEY);
        let v1_integer = der_integer_u8(0);
        for parts in [
            // X.690 §8.3.2: a version not in the fewest octets.
            vec![&[0x02, 0x02, 0x00, 0x00][..], &algorithm, &private],
            // A version that is not an INTEGER, and a missing privateKey.
            vec![&[0x04, 0x01, 0x00][..], &algorithm, &private],
            vec![&v1_integer[..], &algorithm],
            // A primitive [0] (a SET OF is constructed), a component RFC 5958
            // does not define, and two parameters.
            vec![&v1_integer[..], &algorithm, &private, &[0x80, 0x00]],
            vec![&v1_integer[..], &algorithm, &private, &[0x82, 0x00]],
            vec![
                &v1_integer[..],
                &der_sequence(
                    &[
                        &[0x06, 0x03, 0x2b, 0x65, 0x70][..],
                        &[0x05, 0x00, 0x05, 0x00],
                    ]
                    .concat(),
                ),
                &private,
            ],
        ] {
            assert!(
                one_asymmetric_key_to_der(&one_asymmetric_key(&parts)).is_none(),
                "{parts:02x?}"
            );
        }
        // A SubjectPublicKeyInfo with no key, or an OCTET STRING for one.
        assert!(subject_public_key_info_to_der(&der_sequence(&algorithm)).is_none());
        assert!(subject_public_key_info_to_der(&der_sequence(
            &[&algorithm[..], &der_octet_string(&[0x01])].concat()
        ))
        .is_none());
    }
}
