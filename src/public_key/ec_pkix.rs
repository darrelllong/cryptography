//! Standard encodings of elliptic-curve keys, shared by ECDSA, ECDH and
//! ECIES.
//!
//! - Public keys are RFC 5480 `SubjectPublicKeyInfo`s: the `id-ecPublicKey`
//!   algorithm of §2.1.1, whose `ECParameters` must be a `namedCurve` (RFC
//!   5480 forbids `implicitCurve` and `specifiedCurve` in PKIX), and the
//!   public point as §2.2's `ECPoint`, the SEC 1 §2.3.3 octet string. RFC
//!   8813 changes only which key-usage bits a certificate may assert for these
//!   keys, not the encodings.
//! - Private keys are RFC 5915 `ECPrivateKey`s, alone under §4's
//!   `EC PRIVATE KEY` label (the SEC 1 C.4 form) or as the `privateKey` of an
//!   RFC 5958 `OneAsymmetricKey` whose algorithm is `id-ecPublicKey` with the
//!   `namedCurve` (RFC 5915 §1).
//!
//! ## Named curves
//!
//! Only a curve with an object identifier has a standard encoding, so the
//! encoders return `None` for any other curve and the decoders reject an
//! identifier this table lacks. The identifiers are RFC 5480 §2.1.1.1's for
//! the fifteen NIST curves and SEC 2 v2.0 §A.2.1's for secp256k1, and each
//! constructor's parameters were checked against the section of SEC 2 v2.0
//! that defines the curve of that name:
//!
//! | Constructor | Name | Object identifier |
//! |---|---|---|
//! | [`p192`] | secp192r1 (P-192) | 1.2.840.10045.3.1.1 |
//! | [`p224`] | secp224r1 (P-224) | 1.3.132.0.33 |
//! | [`p256`] | secp256r1 (P-256) | 1.2.840.10045.3.1.7 |
//! | [`p384`] | secp384r1 (P-384) | 1.3.132.0.34 |
//! | [`p521`] | secp521r1 (P-521) | 1.3.132.0.35 |
//! | [`secp256k1`] | secp256k1 | 1.3.132.0.10 |
//! | [`k163`] | sect163k1 (K-163) | 1.3.132.0.1 |
//! | [`b163`] | sect163r2 (B-163) | 1.3.132.0.15 |
//! | [`k233`] | sect233k1 (K-233) | 1.3.132.0.26 |
//! | [`b233`] | sect233r1 (B-233) | 1.3.132.0.27 |
//! | [`k283`] | sect283k1 (K-283) | 1.3.132.0.16 |
//! | [`b283`] | sect283r1 (B-283) | 1.3.132.0.17 |
//! | [`k409`] | sect409k1 (K-409) | 1.3.132.0.36 |
//! | [`b409`] | sect409r1 (B-409) | 1.3.132.0.37 |
//! | [`k571`] | sect571k1 (K-571) | 1.3.132.0.38 |
//! | [`b571`] | sect571r1 (B-571) | 1.3.132.0.39 |
//!
//! A curve matches an entry when [`CurveParams::same_curve`] says so, so a key
//! built on the same parameters under another base point has no identifier.
//!
//! ## What the encoders write
//!
//! The point is uncompressed, the form RFC 5480 §2.2 requires every
//! implementation to support. An `ECPrivateKey` is version 1 with `privateKey`
//! the I2OSP of `d` in ⌈log2(n)/8⌉ octets, the `parameters` RFC 5915 §3 says
//! MUST be present, and the `publicKey` it says SHOULD be; that holds inside
//! PKCS #8 too. The PKCS #8 container is version 1.
//!
//! ## What the decoders accept
//!
//! - A point compressed or uncompressed, which RFC 5480 §2.2 allows; any other
//!   first octet is rejected as it requires, including the hybrid form it
//!   forbids. The point must then be a valid public key (SEC 1 §3.2.2.1): not
//!   the identity, coordinates in the field, on the curve, in the subgroup of
//!   order `n`.
//! - An `ECPrivateKey` of version 1 whose `privateKey` has exactly
//!   ⌈log2(n)/8⌉ octets and `1 ≤ d < n`, whose `publicKey`, if present, is
//!   `d·G`, and whose `parameters` name the curve. Inside PKCS #8 they may be
//!   absent, since the algorithm identifier names the curve and SEC 1 C.4 lets
//!   parameters "known by other means" be omitted (OpenSSL writes that form);
//!   if present they must name the same curve. Alone, the key needs them.
//! - For ECDH keys only, the key-agreement-only `id-ecDH` of RFC 5480 §2.1.2
//!   as well as `id-ecPublicKey`.
//! - A version 2 `OneAsymmetricKey` whose `publicKey`, if present, is `d·G`.
//!
//! ## Encoding rules
//!
//! `from_spki_der`, `from_sec1_der` and `from_pkcs8_der` accept strict DER.
//! `from_pkcs8_ber` accepts any X.690 BER encoding, as RFC 5958 §2 requires of
//! a `OneAsymmetricKey` receiver, with the `ECPrivateKey` inside in BER too:
//! RFC 5915 §4 says receivers "SHOULD be prepared to handle Basic Encoding
//! Rules (BER)", and `from_sec1_ber` applies that to a bare `ECPrivateKey`.
//! The `PRIVATE KEY` and `PUBLIC KEY` text decoders accept BER contents, which
//! RFC 7468 §10 and §13 require. `EC PRIVATE KEY` text is "the PEM encoding
//! ... of the DER-encoded ECPrivateKey object" (RFC 5915 §4), so its contents
//! are strict DER.

use std::sync::OnceLock;

use crate::public_key::ec::{
    b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384, p521,
    secp256k1, AffinePoint, CurveParams,
};
use crate::public_key::io::{
    context_tag, der_bit_string, der_explicit, der_integer_u8, der_octet_string, der_oid,
    der_sequence_of, DerReader,
};
use crate::public_key::pkix::{
    AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey, SubjectPublicKeyInfo, ID_EC_DH,
    ID_EC_PUBLIC_KEY,
};
use crate::zeroize_slice;
use rump::BigUint;

// ─── Named curves ────────────────────────────────────────────────────────────

/// A curve with an object identifier.
struct NamedCurve {
    oid: ObjectIdentifier,
    build: fn() -> CurveParams,
}

/// The named curves (see the module docs for the sources).
static NAMED_CURVES: [NamedCurve; 16] = [
    // RFC 5480 §2.1.1.1 and SEC 2 §A.2.1, under ansi-X9-62 curves(3) prime(1).
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 2, 840, 10045, 3, 1, 1]),
        build: p192,
    },
    // RFC 5480 §2.1.1.1 and SEC 2 §A.2.1, under certicom-arc curve(0).
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 33]),
        build: p224,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 2, 840, 10045, 3, 1, 7]),
        build: p256,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 34]),
        build: p384,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 35]),
        build: p521,
    },
    // SEC 2 §A.2.1 only: RFC 5480 lists the NIST curves.
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 10]),
        build: secp256k1,
    },
    // RFC 5480 §2.1.1.1 and SEC 2 §A.2.2, under certicom-arc curve(0).
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 1]),
        build: k163,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 15]),
        build: b163,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 26]),
        build: k233,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 27]),
        build: b233,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 16]),
        build: k283,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 17]),
        build: b283,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 36]),
        build: k409,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 37]),
        build: b409,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 38]),
        build: k571,
    },
    NamedCurve {
        oid: ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 39]),
        build: b571,
    },
];

/// The named curves' parameters, in table order, built once.
fn named_curve_parameters() -> &'static [CurveParams] {
    static CURVES: OnceLock<Vec<CurveParams>> = OnceLock::new();
    CURVES.get_or_init(|| NAMED_CURVES.iter().map(|named| (named.build)()).collect())
}

/// The object identifier of `curve`, when it is a named curve.
fn curve_identifier(curve: &CurveParams) -> Option<&'static ObjectIdentifier> {
    NAMED_CURVES
        .iter()
        .zip(named_curve_parameters())
        .find(|(_, parameters)| parameters.same_curve(curve))
        .map(|(named, _)| &named.oid)
}

/// The curve whose identifier has contents octets `oid`.
fn curve_named(oid: &[u8]) -> Option<CurveParams> {
    let index = NAMED_CURVES
        .iter()
        .position(|named| named.oid.content() == oid)?;
    Some(named_curve_parameters()[index].clone())
}

/// RFC 5480 §2.1.1 `ECParameters` in its `namedCurve` choice, as a complete
/// DER value, when `curve` is named.
fn ec_parameters(curve: &CurveParams) -> Option<Vec<u8>> {
    Some(der_oid(curve_identifier(curve)?.content()))
}

/// The identifier and curve an `ECParameters` encoding names. Only
/// `namedCurve` is accepted (RFC 5480 §2.1.1: `implicitCurve` and
/// `specifiedCurve` MUST NOT be used), and only for a named curve.
fn curve_from_ec_parameters(encoding: &[u8]) -> Option<(&[u8], CurveParams)> {
    let mut reader = DerReader::new(encoding);
    let oid = reader.read_oid()?;
    if !reader.is_finished() {
        return None;
    }
    Some((oid, curve_named(oid)?))
}

/// The `ECPoint` of a public key (RFC 5480 §2.2): its first octet is 04
/// (uncompressed) or 02 or 03 (compressed), and "the public key MUST be
/// rejected if any other value is included in the first octet". The point
/// must then be a valid public key (SEC 1 §3.2.2.1).
fn public_point(curve: &CurveParams, octets: &[u8]) -> Option<AffinePoint> {
    if !matches!(octets.first(), Some(0x02..=0x04)) {
        return None;
    }
    let point = curve.decode_point(octets)?;
    curve.is_valid_public_point(&point).then_some(point)
}

/// RFC 5915 §3: `privateKey` has ⌈log2(n)/8⌉ octets, which is ⌈bits(n)/8⌉
/// since the prime `n` is not a power of two.
fn private_key_len(curve: &CurveParams) -> usize {
    curve.n.bits().div_ceil(8)
}

// ─── Algorithm identifiers ───────────────────────────────────────────────────

/// The algorithm identifiers a key type's decoders accept. Every encoder
/// writes `id-ecPublicKey`.
#[derive(Clone, Copy)]
pub(crate) enum EcAlgorithms {
    /// `id-ecPublicKey` (RFC 5480 §2.1.1), usable with any algorithm.
    Unrestricted,
    /// `id-ecPublicKey`, or `id-ecDH`, restricted to key agreement (RFC 5480
    /// §2.1.2).
    EcdhAllowed,
}

/// The identifier and curve of an elliptic-curve algorithm identifier whose
/// algorithm `accepted` allows. RFC 5480 §2.1.1 and §2.1.2: the parameters
/// "MUST always be present".
fn ec_algorithm<'a>(
    algorithm: &AlgorithmIdentifier<'a>,
    accepted: EcAlgorithms,
) -> Option<(&'a [u8], CurveParams)> {
    let allowed = algorithm.is(&ID_EC_PUBLIC_KEY)
        || (matches!(accepted, EcAlgorithms::EcdhAllowed) && algorithm.is(&ID_EC_DH));
    if !allowed {
        return None;
    }
    curve_from_ec_parameters(algorithm.parameters()?)
}

// ─── SubjectPublicKeyInfo ────────────────────────────────────────────────────

/// RFC 5480 `SubjectPublicKeyInfo` of the point `q` on `curve`, when `curve`
/// is named and `q` is not the identity.
pub(crate) fn spki_der(curve: &CurveParams, q: &AffinePoint) -> Option<Vec<u8>> {
    // RFC 5480 §2.2 lets an `ECPoint` begin only with 02, 03 or 04, so the
    // identity, whose SEC 1 encoding is the single octet 00, has no
    // `subjectPublicKey`.
    if q.is_infinity() {
        return None;
    }
    let parameters = ec_parameters(curve)?;
    let point = curve.encode_point(q);
    Some(
        SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&parameters)),
            &point,
        )
        .to_der(),
    )
}

/// Decode an RFC 5480 `SubjectPublicKeyInfo` into its curve and validated
/// point.
pub(crate) fn decode_spki(
    der: &[u8],
    accepted: EcAlgorithms,
) -> Option<(CurveParams, AffinePoint)> {
    let spki = SubjectPublicKeyInfo::from_der(der)?;
    let (_, curve) = ec_algorithm(spki.algorithm(), accepted)?;
    let q = public_point(&curve, spki.subject_public_key())?;
    Some((curve, q))
}

// ─── ECPrivateKey ────────────────────────────────────────────────────────────

/// RFC 5915 §3 `ECPrivateKey`, with every field, when `curve` is named:
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL }
/// ```
///
/// The module's `DEFINITIONS EXPLICIT TAGS` make both tags explicit. Every
/// buffer holding `d` is wiped; only the returned encoding keeps it.
pub(crate) fn sec1_der(curve: &CurveParams, d: &BigUint, q: &AffinePoint) -> Option<Vec<u8>> {
    let parameters = der_explicit(0, &ec_parameters(curve)?);
    let public_key = der_explicit(1, &der_bit_string(&curve.encode_point(q)));
    let mut scalar = d.to_be_bytes_padded(private_key_len(curve));
    let private_key = der_octet_string(&scalar);
    zeroize_slice(scalar.as_mut_slice());
    // Sized exactly, each part wiped once copied, so no copy of `d` survives.
    Some(der_sequence_of(vec![
        der_integer_u8(1),
        private_key,
        parameters,
        public_key,
    ]))
}

/// Decode an `ECPrivateKey` as the module docs describe. `named` is the
/// identifier and curve of the enclosing PKCS #8 algorithm, if any.
fn decode_ec_private_key(
    der: &[u8],
    named: Option<(&[u8], CurveParams)>,
) -> Option<(CurveParams, BigUint, AffinePoint)> {
    let mut outer = DerReader::new(der);
    let body = outer.read_sequence()?;
    if !outer.is_finished() {
        return None;
    }
    let mut fields = DerReader::new(body);
    if fields.read_integer_small()? != 1 {
        return None;
    }
    let private_key = fields.read_octet_string()?;
    let parameters = if fields.peek_tag() == Some(context_tag(0, true)) {
        Some(curve_from_ec_parameters(fields.read_explicit(0)?)?)
    } else {
        None
    };
    let public_key = if fields.peek_tag() == Some(context_tag(1, true)) {
        let mut inner = DerReader::new(fields.read_explicit(1)?);
        let bits = inner.read_bit_string()?;
        if !inner.is_finished() {
            return None;
        }
        Some(bits)
    } else {
        None
    };
    if !fields.is_finished() {
        return None;
    }
    let curve = match (parameters, named) {
        (Some((inner_oid, curve)), Some((outer_oid, _))) => {
            if inner_oid != outer_oid {
                return None;
            }
            curve
        }
        (Some((_, curve)), None) | (None, Some((_, curve))) => curve,
        (None, None) => return None,
    };
    if private_key.len() != private_key_len(&curve) {
        return None;
    }
    let d = BigUint::from_be_bytes(private_key);
    if d.is_zero() || d >= curve.n {
        return None;
    }
    let q = curve.scalar_mul(&curve.base_point(), &d);
    // `q` is a valid public key by construction, so a present `publicKey`
    // needs only to decode to it; the identity and every other first octet
    // decode to something else.
    if let Some(bits) = public_key {
        if curve.decode_point(bits)? != q {
            return None;
        }
    }
    Some((curve, d, q))
}

/// Decode a bare `ECPrivateKey`, which must name its curve.
pub(crate) fn decode_sec1(der: &[u8]) -> Option<(CurveParams, BigUint, AffinePoint)> {
    decode_ec_private_key(der, None)
}

// ─── OneAsymmetricKey ────────────────────────────────────────────────────────

/// RFC 5958 `OneAsymmetricKey` (version 1) holding the `ECPrivateKey` of
/// [`sec1_der`], under `id-ecPublicKey` with the `namedCurve` (RFC 5915 §1).
pub(crate) fn pkcs8_der(curve: &CurveParams, d: &BigUint, q: &AffinePoint) -> Option<Vec<u8>> {
    let parameters = ec_parameters(curve)?;
    let mut ec_private_key = sec1_der(curve, d, q)?;
    let out = OneAsymmetricKey::new(
        AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&parameters)),
        &ec_private_key,
        None,
    )
    .to_der();
    zeroize_slice(ec_private_key.as_mut_slice());
    Some(out)
}

/// Decode an RFC 5958 `OneAsymmetricKey` holding an `ECPrivateKey`.
pub(crate) fn decode_pkcs8(
    der: &[u8],
    accepted: EcAlgorithms,
) -> Option<(CurveParams, BigUint, AffinePoint)> {
    let key = OneAsymmetricKey::from_der(der)?;
    let named = ec_algorithm(key.algorithm(), accepted)?;
    let (curve, d, q) = decode_ec_private_key(key.private_key(), Some(named))?;
    // RFC 5958 §2 says an EC public key travels inside `ECPrivateKey`; a
    // version 2 `publicKey` is the same `ECPoint` and must agree.
    if let Some(bits) = key.public_key() {
        if curve.decode_point(bits)? != q {
            return None;
        }
    }
    Some((curve, d, q))
}

/// Emit the standard encodings for one elliptic-curve key pair type.
///
/// Both types must keep their curve in a field `curve` and their point in a
/// field `q`; the private type keeps its scalar in `d`. `$accepted` names the
/// [`EcAlgorithms`] variant the decoders accept.
macro_rules! impl_ec_key_encodings {
    ($public:ident, $private:ident, $accepted:ident) => {
        impl $public {
            /// Encode as an RFC 5480 `SubjectPublicKeyInfo` in DER: the
            /// `id-ecPublicKey` algorithm with the curve's `namedCurve`, and
            /// the point uncompressed (SEC 1 §2.3.3).
            ///
            /// Returns `None` unless the curve is a named curve — P-192,
            /// P-224, P-256, P-384, P-521, secp256k1, or a NIST B- or K-
            /// binary curve — since a key on any other curve has no standard
            /// encoding. The crate-defined formats still carry it. It is also
            /// `None` for the identity point, which RFC 5480 §2.2 cannot
            /// encode.
            #[must_use]
            pub fn to_spki_der(&self) -> Option<Vec<u8>> {
                crate::public_key::ec_pkix::spki_der(&self.curve, &self.q)
            }

            /// [`Self::to_spki_der`] under the RFC 7468 `PUBLIC KEY` label.
            #[must_use]
            pub fn to_spki_pem(&self) -> Option<String> {
                let der = self.to_spki_der()?;
                Some(crate::public_key::pkix::pem_encode(
                    crate::public_key::pkix::PUBLIC_KEY_LABEL,
                    der,
                ))
            }

            /// Decode an RFC 5480 `SubjectPublicKeyInfo` in strict DER.
            ///
            /// The curve must be named; the point may be compressed or
            /// uncompressed and must be a valid public key (SEC 1 §3.2.2.1).
            /// ECDH keys also accept the `id-ecDH` algorithm (RFC 5480
            /// §2.1.2).
            #[must_use]
            pub fn from_spki_der(der: &[u8]) -> Option<Self> {
                let (curve, q) = crate::public_key::ec_pkix::decode_spki(
                    der,
                    crate::public_key::ec_pkix::EcAlgorithms::$accepted,
                )?;
                Some(Self { curve, q })
            }

            /// Decode a `PUBLIC KEY` textual encoding, read by RFC 7468 §2's
            /// parser rules. RFC 7468 §13 requires the contents to be BER
            /// ("DER preferred"), so any BER encoding of the container is
            /// accepted, and the key is then checked as
            /// [`Self::from_spki_der`] checks it.
            #[must_use]
            pub fn from_spki_pem(pem: &str) -> Option<Self> {
                crate::public_key::pkix::pem_decode(
                    crate::public_key::pkix::PUBLIC_KEY_LABEL,
                    pem,
                    Self::from_spki_der,
                )
            }
        }

        impl $private {
            /// Encode as an RFC 5915 `ECPrivateKey` in DER (the SEC 1 C.4
            /// form): version 1, the scalar in ⌈log2(n)/8⌉ octets, the
            /// `namedCurve`, and the uncompressed public point.
            ///
            /// Returns `None` unless the curve is a named curve (see
            /// `to_spki_der` on the public key).
            #[must_use]
            pub fn to_sec1_der(&self) -> Option<Vec<u8>> {
                crate::public_key::ec_pkix::sec1_der(&self.curve, &self.d, &self.q)
            }

            /// [`Self::to_sec1_der`] under the `EC PRIVATE KEY` label of RFC
            /// 5915 §4.
            #[must_use]
            pub fn to_sec1_pem(&self) -> Option<String> {
                let der = self.to_sec1_der()?;
                Some(crate::public_key::pkix::pem_encode(
                    crate::public_key::pkix::EC_PRIVATE_KEY_LABEL,
                    der,
                ))
            }

            /// Decode an RFC 5915 `ECPrivateKey` in strict DER.
            ///
            /// The key must name its curve, a named curve; `privateKey` must
            /// have exactly ⌈log2(n)/8⌉ octets holding `1 ≤ d < n`; a present
            /// `publicKey` must be `d·G`.
            #[must_use]
            pub fn from_sec1_der(der: &[u8]) -> Option<Self> {
                let (curve, d, q) = crate::public_key::ec_pkix::decode_sec1(der)?;
                Some(Self { curve, d, q })
            }

            /// Decode an RFC 5915 `ECPrivateKey` in any X.690 BER encoding, DER
            /// included: RFC 5915 §4 says receivers "SHOULD be prepared to
            /// handle Basic Encoding Rules (BER)". The key is then checked as
            /// [`Self::from_sec1_der`] checks it.
            #[must_use]
            pub fn from_sec1_ber(ber: &[u8]) -> Option<Self> {
                Self::from_sec1_der(&crate::public_key::io::ber_to_der(ber)?)
            }

            /// Decode an `EC PRIVATE KEY` textual encoding, read by RFC 7468
            /// §2's parser rules, its contents as [`Self::from_sec1_der`] reads
            /// them: RFC 5915 §4 describes this form as the PEM encoding "of
            /// the DER-encoded ECPrivateKey object".
            #[must_use]
            pub fn from_sec1_pem(pem: &str) -> Option<Self> {
                crate::public_key::pkix::pem_decode(
                    crate::public_key::pkix::EC_PRIVATE_KEY_LABEL,
                    pem,
                    Self::from_sec1_der,
                )
            }

            /// Encode as an RFC 5958 `OneAsymmetricKey` (PKCS #8
            /// `PrivateKeyInfo`, version 1) in DER: `id-ecPublicKey` with the
            /// `namedCurve`, holding the `ECPrivateKey` of
            /// [`Self::to_sec1_der`] (RFC 5915 §1).
            ///
            /// Returns `None` unless the curve is a named curve.
            #[must_use]
            pub fn to_pkcs8_der(&self) -> Option<Vec<u8>> {
                crate::public_key::ec_pkix::pkcs8_der(&self.curve, &self.d, &self.q)
            }

            /// [`Self::to_pkcs8_der`] under the RFC 7468 `PRIVATE KEY` label.
            #[must_use]
            pub fn to_pkcs8_pem(&self) -> Option<String> {
                let der = self.to_pkcs8_der()?;
                Some(crate::public_key::pkix::pem_encode(
                    crate::public_key::pkix::PRIVATE_KEY_LABEL,
                    der,
                ))
            }

            /// Decode an RFC 5958 `OneAsymmetricKey` holding an RFC 5915
            /// `ECPrivateKey`, in strict DER.
            ///
            /// The algorithm's `namedCurve` names the curve; the inner
            /// `parameters` may be absent or must name the same curve. ECDH
            /// keys also accept the `id-ecDH` algorithm. A version 2
            /// `publicKey` must be `d·G`.
            #[must_use]
            pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
                let (curve, d, q) = crate::public_key::ec_pkix::decode_pkcs8(
                    der,
                    crate::public_key::ec_pkix::EcAlgorithms::$accepted,
                )?;
                Some(Self { curve, d, q })
            }

            /// Decode an RFC 5958 `OneAsymmetricKey` holding an RFC 5915
            /// `ECPrivateKey`, in any X.690 BER encoding, DER included: RFC
            /// 5958 §2 says "receivers MUST support BER", and RFC 5915 §4 asks
            /// receivers to handle BER in the `ECPrivateKey` inside. The key is
            /// then checked as [`Self::from_pkcs8_der`] checks it.
            #[must_use]
            pub fn from_pkcs8_ber(ber: &[u8]) -> Option<Self> {
                crate::public_key::pkix::pkcs8_ber(ber, Self::from_pkcs8_der)
            }

            /// Decode a `PRIVATE KEY` textual encoding, read by RFC 7468 §2's
            /// parser rules, its contents as [`Self::from_pkcs8_ber`] reads
            /// them: RFC 7468 §10 requires them to be BER ("DER preferred").
            #[must_use]
            pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
                crate::public_key::pkix::pem_decode(
                    crate::public_key::pkix::PRIVATE_KEY_LABEL,
                    pem,
                    Self::from_pkcs8_der,
                )
            }
        }
    };
}
pub(crate) use impl_ec_key_encodings;

#[cfg(test)]
mod tests {
    use super::NAMED_CURVES;
    use crate::public_key::ec::{p256, AffinePoint, CurveParams};
    use crate::public_key::ec::{p384, p521};
    use crate::public_key::ecdh::{Ecdh, EcdhPrivateKey, EcdhPublicKey};
    use crate::public_key::ecdsa::{Ecdsa, EcdsaPrivateKey, EcdsaPublicKey};
    use crate::public_key::ecies::{EciesPrivateKey, EciesPublicKey};
    use crate::public_key::io::ber_forms::{reencode, STYLES};
    use crate::public_key::io::{
        der_bit_string, der_explicit, der_integer_u8, der_octet_string, der_oid, der_sequence,
    };
    use crate::public_key::pkix::{
        pem_decode, pem_encode, AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey,
        SubjectPublicKeyInfo, EC_PRIVATE_KEY_LABEL, ID_EC_DH, ID_EC_PUBLIC_KEY, PRIVATE_KEY_LABEL,
        PUBLIC_KEY_LABEL, RSA_ENCRYPTION,
    };
    use crate::test_utils::openssl3;
    use rump::BigUint;

    /// One of RFC 9500 §2.3's publicly known ECDLP test keys: its encoded
    /// form and the values the RFC lists beside it.
    struct Rfc9500Key {
        curve: fn() -> CurveParams,
        pem: &'static str,
        d: &'static str,
        qx: &'static str,
        qy: &'static str,
    }

    /// RFC 9500 §2.3: "testECCP256", "testECCP384" and "testECCP521".
    const RFC9500_KEYS: [Rfc9500Key; 3] = [
        Rfc9500Key {
            curve: p256,
            pem: "-----BEGIN EC PRIVATE KEY-----\n\
        MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49\n\
        AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV\n\
        uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==\n\
        -----END EC PRIVATE KEY-----\n",
            d: "E6CB5BDD80AA45AE9C95E8C15476679FFEC953C16851E711E743939589C64FC1",
            qx: "422548F88FB782FFB5ECA3744452C72A1E558FBD6F73BE5E48E93232CC45C5B1",
            qy: "6C4CD10C4CB8D5B8A17139E94882C8992572993425F41419AB7E90A42A494272",
        },
        Rfc9500Key {
            curve: p384,
            pem: "-----BEGIN EC PRIVATE KEY-----\n\
        MIGkAgEBBDDiVjMo36v2gYhga5EyQoHB1YpEVkMbCdUQs1/syfMHyhgihG+iZxNx\n\
        qagbrA41dJ2gBwYFK4EEACKhZANiAARbCQG4hSMpbrkZ1Q/6GpyzdLxNQJWGKCv+\n\
        yhGx2VrbtUc0r1cL+CtyKM8ia89MJd28/jsaOtOUMO/3Y+HWjS4VHZFyC3eVtY2m\n\
        s0Y5YTqPubWo2kjGdHEX+ZGehCTzfsg=\n\
        -----END EC PRIVATE KEY-----\n",
            d: "E2563328DFABF68188606B91324281C1D58A4456431B09D510B35FECC9F307CA1822846FA2671371A9A81BAC0E35749D",
            qx: "5B0901B88523296EB919D50FFA1A9CB374BC4D409586282BFECA11B1D95ADBB54734AF570BF82B7228CF226BCF4C25DD",
            qy: "BCFE3B1A3AD39430EFF763E1D68D2E151D91720B7795B58DA6B34639613A8FB9B5A8DA48C6747117F9919E8424F37EC8",
        },
        Rfc9500Key {
            curve: p521,
            pem: "-----BEGIN EC PRIVATE KEY-----\n\
        MIHcAgEBBEIB2STcygqIf42Zdno32HTmN6Esy0d9bghmU1ZpTWi3ZV5QaWOP3ntF\n\
        yFQBPcd6NbGGVbhMlmpgIg1A+R7Z9RRYAuqgBwYFK4EEACOhgYkDgYYABAHQ/XJX\n\
        qEx0f1YldcBzhdvr8vUr6lgIPbgv3RUx2KrjzIdf8C/3+i2iYNjrYtbS9dZJJ44y\n\
        FzagYoy7swMItuYY2wD2KtIExkYDWbyBiriWG/Dw/A7FquikKBc85W8A3psVfB5c\n\
        gsZPVi/K3vxKTCj200LPPvYW/ILTO3KFySHyvzb92A==\n\
        -----END EC PRIVATE KEY-----\n",
            d: "01D924DCCA0A887F8D99767A37D874E637A12CCB477D6E08665356694D68B7655E5069638FDE7B45C854013DC77A35B18655B84C966A60220D40F91ED9F5145802EA",
            qx: "01D0FD7257A84C747F562575C07385DBEBF2F52BEA58083DB82FDD1531D8AAE3CC875FF02FF7FA2DA260D8EB62D6D2F5D649278E321736A0628CBBB30308B6E618DB",
            qy: "F62AD204C6460359BC818AB8961BF0F0FC0EC5AAE8A428173CE56F00DE9B157C1E5C82C64F562FCADEFC4A4C28F6D342CF3EF616FC82D33B7285C921F2BF36FDD8",
        },
    ];

    /// Index of P-256 in [`NAMED_CURVES`].
    const P256: usize = 2;

    fn hex(value: &str) -> BigUint {
        BigUint::from_str_radix(value, 16).expect("hexadecimal")
    }

    fn spki_with(algorithm: AlgorithmIdentifier<'_>, point: &[u8]) -> Vec<u8> {
        SubjectPublicKeyInfo::new(algorithm, point).to_der()
    }

    /// The RFC 9500 P-256 key's `ECPrivateKey` split into its four
    /// components: `30 77 | 02 01 01 | 04 20 d | A0 0A oid | A1 44 point`.
    fn p256_components() -> [Vec<u8>; 4] {
        let der = pem_decode(EC_PRIVATE_KEY_LABEL, RFC9500_KEYS[0].pem, |der| {
            Some(der.to_vec())
        })
        .expect("RFC 9500 PEM");
        assert_eq!(der.len(), 121);
        [
            der[2..5].to_vec(),
            der[5..39].to_vec(),
            der[39..51].to_vec(),
            der[51..].to_vec(),
        ]
    }

    fn sec1(components: &[&[u8]]) -> Vec<u8> {
        der_sequence(&components.concat())
    }

    #[test]
    fn rfc9500_ec_private_keys_decode_and_reencode_exactly() {
        for key in &RFC9500_KEYS {
            let private = EcdsaPrivateKey::from_sec1_pem(key.pem).expect("RFC 9500 §2.3 key");
            assert!(private.curve().same_curve(&(key.curve)()));
            assert_eq!(private.private_scalar(), &hex(key.d));
            let public = private.to_public_key();
            assert_eq!(
                public.public_point(),
                &AffinePoint::new(hex(key.qx), hex(key.qy))
            );
            assert_eq!(private.to_sec1_pem().as_deref(), Some(key.pem));

            // The same key is an ECDH and an ECIES key.
            let ecdh = EcdhPrivateKey::from_sec1_pem(key.pem).expect("ECDH");
            assert_eq!(ecdh.private_scalar(), &hex(key.d));
            let ecies = EciesPrivateKey::from_sec1_pem(key.pem).expect("ECIES");
            assert_eq!(ecies.to_sec1_pem().as_deref(), Some(key.pem));

            let pkcs8 = private.to_pkcs8_pem().expect("named curve");
            let again = EcdsaPrivateKey::from_pkcs8_pem(&pkcs8).expect("PKCS #8");
            assert_eq!(again.private_scalar(), private.private_scalar());
            let spki = public.to_spki_pem().expect("named curve");
            let parsed = EcdsaPublicKey::from_spki_pem(&spki).expect("SPKI");
            assert_eq!(parsed.public_point(), public.public_point());
            assert!(EciesPublicKey::from_spki_pem(&spki).is_some());
            assert!(EcdhPublicKey::from_spki_pem(&spki).is_some());
        }
    }

    #[test]
    fn every_named_curve_round_trips_under_its_identifier() {
        for named in &NAMED_CURVES {
            let curve = (named.build)();
            let (public, private) =
                Ecdsa::from_secret_scalar(curve.clone(), &BigUint::from_u64(7)).expect("7 < n");
            let parameters = der_oid(named.oid.content());
            let expected = spki_with(
                AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&parameters)),
                &curve.encode_point(public.public_point()),
            );
            let spki = public.to_spki_der().expect("named curve");
            assert_eq!(spki, expected);
            let decoded = EcdsaPublicKey::from_spki_der(&spki).expect("SPKI");
            assert!(decoded.curve().same_curve(&curve));
            assert_eq!(decoded.public_point(), public.public_point());

            let sec1 = private.to_sec1_der().expect("named curve");
            let decoded = EcdsaPrivateKey::from_sec1_der(&sec1).expect("SEC 1");
            assert!(decoded.curve().same_curve(&curve));
            assert_eq!(decoded.private_scalar(), &BigUint::from_u64(7));
            let pkcs8 = private.to_pkcs8_der().expect("named curve");
            let decoded = EcdsaPrivateKey::from_pkcs8_der(&pkcs8).expect("PKCS #8");
            assert!(decoded.curve().same_curve(&curve));
        }
    }

    #[test]
    fn keys_on_curves_without_an_identifier_have_no_standard_encoding() {
        // P-256 with −G as its base point: a sound curve no identifier names.
        let named = p256();
        let curve = CurveParams::new(
            named.p.clone(),
            named.a.clone(),
            named.b.clone(),
            named.n.clone(),
            named.h,
            named.gx.clone(),
            named.p.sub(&named.gy),
        )
        .expect("valid parameters");
        let (public, private) =
            Ecdsa::from_secret_scalar(curve, &BigUint::from_u64(7)).expect("7 < n");
        assert!(public.to_spki_der().is_none() && public.to_spki_pem().is_none());
        assert!(private.to_sec1_der().is_none() && private.to_sec1_pem().is_none());
        assert!(private.to_pkcs8_der().is_none() && private.to_pkcs8_pem().is_none());
    }

    #[test]
    fn the_identity_has_no_subject_public_key() {
        // RFC 5480 §2.2 lets an `ECPoint` begin only with 02, 03 or 04, so the
        // identity, whose SEC 1 encoding is the octet `00`, has no
        // `subjectPublicKey`: the encoder refuses it, and no public-key import
        // yields a key that holds it.
        assert!(super::spki_der(&p256(), &AffinePoint::infinity()).is_none());
        assert!(EcdsaPublicKey::from_wire_bytes(p256(), &[0x00]).is_none());
        assert!(EcdhPublicKey::from_wire_bytes(p256(), &[0x00]).is_none());
        assert!(EciesPublicKey::from_wire_bytes(p256(), &[0x00]).is_none());
    }

    /// RFC 5958 §2 ("receivers MUST support BER") and RFC 5915 §4 (receivers
    /// "SHOULD be prepared to handle" BER): the BER receivers read the RFC 9500
    /// P-256 key in every BER form, the `ECPrivateKey` inside included, where
    /// the DER decoders refuse it. RFC 7468 §10 and §13 let `PRIVATE KEY` and
    /// `PUBLIC KEY` text hold BER; `EC PRIVATE KEY` text holds "the DER-encoded
    /// ECPrivateKey" (RFC 5915 §4).
    #[test]
    fn ber_receivers_follow_rfc5958_and_rfc5915() {
        let private = EcdsaPrivateKey::from_sec1_pem(RFC9500_KEYS[0].pem).expect("RFC 9500 key");
        let public = private.to_public_key();
        let scalar = Some(private.private_scalar().clone());
        let sec1 = private.to_sec1_der().expect("named curve");
        let spki = public.to_spki_der().expect("named curve");
        let parameters = der_oid(NAMED_CURVES[P256].oid.content());
        let algorithm = AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&parameters));
        assert!(EcdsaPrivateKey::from_sec1_ber(&sec1).is_some());
        assert!(
            EcdsaPrivateKey::from_pkcs8_ber(&private.to_pkcs8_der().expect("named curve"))
                .is_some()
        );
        for style in STYLES {
            let sec1_ber = reencode(&sec1, style);
            assert!(
                EcdsaPrivateKey::from_sec1_der(&sec1_ber).is_none(),
                "{style:?}"
            );
            assert_eq!(
                EcdsaPrivateKey::from_sec1_ber(&sec1_ber).map(|key| key.private_scalar().clone()),
                scalar,
                "{style:?}"
            );
            assert!(EciesPrivateKey::from_sec1_ber(&sec1_ber).is_some());
            let text = pem_encode(EC_PRIVATE_KEY_LABEL, sec1_ber.clone());
            assert!(EcdsaPrivateKey::from_sec1_pem(&text).is_none(), "{style:?}");

            let ber = reencode(
                &OneAsymmetricKey::new(algorithm, &sec1_ber, None).to_der(),
                style,
            );
            assert!(EcdsaPrivateKey::from_pkcs8_der(&ber).is_none(), "{style:?}");
            for decoded in [
                EcdsaPrivateKey::from_pkcs8_ber(&ber),
                EcdsaPrivateKey::from_pkcs8_pem(&pem_encode(PRIVATE_KEY_LABEL, ber.clone())),
            ] {
                assert_eq!(
                    decoded.map(|key| key.private_scalar().clone()),
                    scalar,
                    "{style:?}"
                );
            }
            assert!(EcdhPrivateKey::from_pkcs8_ber(&ber).is_some());

            let spki_ber = reencode(&spki, style);
            assert!(
                EcdsaPublicKey::from_spki_der(&spki_ber).is_none(),
                "{style:?}"
            );
            let decoded = EcdsaPublicKey::from_spki_pem(&pem_encode(PUBLIC_KEY_LABEL, spki_ber));
            assert_eq!(
                decoded.map(|key| key.public_point() == public.public_point()),
                Some(true),
                "{style:?}"
            );
        }
    }

    /// OpenSSL reads the BER forms of the RFC 9500 P-256 key's PKCS #8 and
    /// SPKI encodings as that key. OpenSSL 3.6 refuses constructed strings in
    /// these containers, which X.690 §8.6.1 and §8.7.1 allow, so only the
    /// length forms are put to it.
    #[test]
    fn openssl_reads_the_ber_forms_as_the_same_key() {
        const TEST: &str = "ec_pkix::openssl_reads_the_ber_forms_as_the_same_key";
        let private = EcdsaPrivateKey::from_sec1_pem(RFC9500_KEYS[0].pem).expect("RFC 9500 key");
        let spki = private.to_public_key().to_spki_der().expect("named curve");
        let pkcs8 = private.to_pkcs8_der().expect("named curve");
        for style in [STYLES[0], STYLES[1]] {
            let Some(from_private) = openssl3(
                &["pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                &reencode(&pkcs8, style),
            )
            .or_skip(TEST) else {
                return;
            };
            assert_eq!(from_private, spki, "{style:?}");
            let Some(from_public) = openssl3(
                &[
                    "pkey", "-pubin", "-inform", "DER", "-pubout", "-outform", "DER",
                ],
                &reencode(&spki, style),
            )
            .or_skip(TEST) else {
                return;
            };
            assert_eq!(from_public, spki, "{style:?}");
        }
    }

    #[test]
    fn subject_public_key_follows_rfc5480() {
        let curve = p256();
        let (public, _) =
            Ecdsa::from_secret_scalar(curve.clone(), &BigUint::from_u64(7)).expect("7 < n");
        let q = public.public_point();
        let parameters = der_oid(NAMED_CURVES[P256].oid.content());
        let algorithm = AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&parameters));

        // §2.2: the compressed form decodes to the same key, which re-encodes
        // uncompressed.
        let compressed = curve.encode_point_compressed(q);
        let decoded = EcdsaPublicKey::from_spki_der(&spki_with(algorithm, &compressed))
            .expect("compressed ECPoint");
        assert_eq!(decoded.public_point(), q);
        assert_eq!(decoded.to_spki_der(), public.to_spki_der());

        // The hybrid form, the identity, a point off the curve, and an
        // x-coordinate equal to p.
        let uncompressed = curve.encode_point(q);
        let mut hybrid = uncompressed.clone();
        hybrid[0] = if q.y.is_odd() { 0x07 } else { 0x06 };
        let mut off_curve = uncompressed.clone();
        off_curve[64] ^= 1;
        let mut out_of_field = uncompressed.clone();
        out_of_field[1..33].copy_from_slice(&curve.p.to_be_bytes_padded(32));
        for point in [hybrid, vec![0x00], off_curve, out_of_field] {
            assert!(EcdsaPublicKey::from_spki_der(&spki_with(algorithm, &point)).is_none());
        }

        // §2.1.1: parameters absent, implicitCurve (NULL), specifiedCurve (a
        // SEQUENCE), a curve with no entry (secp192k1), and another algorithm.
        let secp192k1 = der_oid(ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 31]).content());
        for algorithm in [
            AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, None),
            AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&[0x05, 0x00])),
            AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&[0x30, 0x03, 0x02, 0x01, 0x01])),
            AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&secp192k1)),
            AlgorithmIdentifier::new(&RSA_ENCRYPTION, Some(&parameters)),
        ] {
            assert!(EcdsaPublicKey::from_spki_der(&spki_with(algorithm, &uncompressed)).is_none());
        }
    }

    #[test]
    fn ec_private_key_follows_rfc5915() {
        let [version, private, parameters, public] = p256_components();
        let accepts = |components: &[&[u8]]| EcdsaPrivateKey::from_sec1_der(&sec1(components));
        assert!(accepts(&[&version, &private, &parameters, &public]).is_some());
        // publicKey is optional; alone, the key needs parameters.
        assert!(accepts(&[&version, &private, &parameters]).is_some());
        assert!(accepts(&[&version, &private, &public]).is_none());
        // Only ecPrivkeyVer1.
        for other in [0, 2] {
            assert!(accepts(&[&der_integer_u8(other), &private, &parameters, &public]).is_none());
        }
        // privateKey of 31 or 33 octets, d = 0, and d = n.
        let short = der_octet_string(&private[3..]);
        let long = der_octet_string(&[&[0u8][..], &private[2..]].concat());
        let zero = der_octet_string(&[0u8; 32]);
        let order = der_octet_string(&p256().n.to_be_bytes_padded(32));
        for scalar in [short, long, zero, order] {
            assert!(accepts(&[&version, &scalar, &parameters, &public]).is_none());
        }
        // Parameters naming P-384, or implicitCurve; a valid point that is not
        // d·G; components out of order; trailing bytes.
        let p384_parameters = der_explicit(
            0,
            &der_oid(ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 34]).content()),
        );
        let implicit = der_explicit(0, &[0x05, 0x00]);
        let key = EcdsaPrivateKey::from_sec1_der(&sec1(&[&version, &private, &parameters]))
            .expect("RFC 9500 key");
        let negated = key.curve().negate(key.to_public_key().public_point());
        let wrong_public = der_explicit(1, &der_bit_string(&key.curve().encode_point(&negated)));
        assert!(accepts(&[&version, &private, &p384_parameters, &public]).is_none());
        assert!(accepts(&[&version, &private, &implicit, &public]).is_none());
        assert!(accepts(&[&version, &private, &parameters, &wrong_public]).is_none());
        assert!(accepts(&[&version, &private, &public, &parameters]).is_none());
        assert!(accepts(&[&private, &version, &parameters, &public]).is_none());
        let mut trailing = sec1(&[&version, &private, &parameters, &public]);
        trailing.push(0);
        assert!(EcdsaPrivateKey::from_sec1_der(&trailing).is_none());
    }

    #[test]
    fn pkcs8_names_the_curve_once_or_consistently() {
        let [version, private, parameters, public] = p256_components();
        let named = der_oid(NAMED_CURVES[P256].oid.content());
        let pkcs8 = |algorithm: AlgorithmIdentifier<'_>, inner: &[u8], point: Option<&[u8]>| {
            OneAsymmetricKey::new(algorithm, inner, point).to_der()
        };
        let algorithm = AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, Some(&named));
        let with_parameters = sec1(&[&version, &private, &parameters, &public]);
        let without_parameters = sec1(&[&version, &private, &public]);
        let p384_parameters = der_explicit(
            0,
            &der_oid(ObjectIdentifier::from_arcs(&[1, 3, 132, 0, 34]).content()),
        );
        let p384_inside = sec1(&[&version, &private, &p384_parameters, &public]);

        assert!(
            EcdsaPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &with_parameters, None)).is_some()
        );
        // OpenSSL's form, without the inner parameters.
        assert!(
            EcdsaPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &without_parameters, None)).is_some()
        );
        assert!(EcdsaPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &p384_inside, None)).is_none());
        let absent = AlgorithmIdentifier::new(&ID_EC_PUBLIC_KEY, None);
        assert!(EcdsaPrivateKey::from_pkcs8_der(&pkcs8(absent, &with_parameters, None)).is_none());

        // A version 2 publicKey must be d·G: the RFC 9500 point, not its
        // negation.
        let point = &public[5..];
        assert!(
            EcdsaPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &with_parameters, Some(point)))
                .is_some()
        );
        let key = EcdsaPrivateKey::from_sec1_der(&with_parameters).expect("RFC 9500 key");
        let negated = key
            .curve()
            .encode_point(&key.curve().negate(key.to_public_key().public_point()));
        assert!(EcdsaPrivateKey::from_pkcs8_der(&pkcs8(
            algorithm,
            &with_parameters,
            Some(&negated)
        ))
        .is_none());
    }

    #[test]
    fn id_ec_dh_names_ecdh_keys_only() {
        let (public, private) =
            Ecdh::from_secret_scalar(p256(), &BigUint::from_u64(7)).expect("7 < n");
        let named = der_oid(NAMED_CURVES[P256].oid.content());
        let ecdh_only = AlgorithmIdentifier::new(&ID_EC_DH, Some(&named));
        let spki = spki_with(ecdh_only, &public.to_wire_bytes());
        let decoded = EcdhPublicKey::from_spki_der(&spki).expect("id-ecDH for ECDH");
        assert!(EcdsaPublicKey::from_spki_der(&spki).is_none());
        assert!(EciesPublicKey::from_spki_der(&spki).is_none());
        // The encoder always writes id-ecPublicKey.
        assert_eq!(decoded.to_spki_der(), public.to_spki_der());

        let inner = private.to_sec1_der().expect("named curve");
        let pkcs8 = OneAsymmetricKey::new(ecdh_only, &inner, None).to_der();
        assert!(EcdhPrivateKey::from_pkcs8_der(&pkcs8).is_some());
        assert!(EcdsaPrivateKey::from_pkcs8_der(&pkcs8).is_none());
        assert!(EciesPrivateKey::from_pkcs8_der(&pkcs8).is_none());
    }

    #[test]
    fn named_curve_identifiers_match_rfc9500_encodings() {
        // The RFC 9500 keys carry `06 08 2A 86 48 CE 3D 03 01 07` (P-256),
        // `06 05 2B 81 04 00 22` (P-384) and `06 05 2B 81 04 00 23` (P-521).
        for (key, expected) in RFC9500_KEYS.iter().zip([
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..],
            &[0x2b, 0x81, 0x04, 0x00, 0x22],
            &[0x2b, 0x81, 0x04, 0x00, 0x23],
        ]) {
            let der = pem_decode(EC_PRIVATE_KEY_LABEL, key.pem, |der| Some(der.to_vec()))
                .expect("RFC 9500 PEM");
            let mut encoded = vec![0x06, u8::try_from(expected.len()).expect("short")];
            encoded.extend_from_slice(expected);
            assert!(der.windows(encoded.len()).any(|window| window == encoded));
            let entry = NAMED_CURVES
                .iter()
                .find(|named| named.oid.content() == expected)
                .expect("table entry");
            assert!((entry.build)().same_curve(&(key.curve)()));
        }
        assert!(p384().same_curve(&(RFC9500_KEYS[1].curve)()));
        assert!(p521().same_curve(&(RFC9500_KEYS[2].curve)()));
    }

    /// OpenSSL's names for the table's curves, in table order.
    const OPENSSL_CURVE_NAMES: [&str; 16] = [
        "prime192v1",
        "secp224r1",
        "prime256v1",
        "secp384r1",
        "secp521r1",
        "secp256k1",
        "sect163k1",
        "sect163r2",
        "sect233k1",
        "sect233r1",
        "sect283k1",
        "sect283r1",
        "sect409k1",
        "sect409r1",
        "sect571k1",
        "sect571r1",
    ];

    /// For every named curve, a key OpenSSL generates parses here, and each
    /// standard form this crate writes for it is byte for byte what OpenSSL
    /// writes or reads back.
    #[test]
    fn openssl_keys_agree_on_every_named_curve() {
        const TEST: &str = "openssl_keys_agree_on_every_named_curve";
        let Some(listing) = openssl3(&["ecparam", "-list_curves"], b"").or_skip(TEST) else {
            return;
        };
        let listing = String::from_utf8_lossy(&listing).into_owned();
        for (named, name) in NAMED_CURVES.iter().zip(OPENSSL_CURVE_NAMES) {
            if !listing
                .lines()
                .any(|line| line.split(':').next().map(str::trim) == Some(name))
            {
                eprintln!("skipping {TEST} for {name}: the installed openssl lacks the curve");
                continue;
            }
            let curve_option = format!("ec_paramgen_curve:{name}");
            // `genpkey -outform DER` writes an EC key as a bare SEC 1
            // `ECPrivateKey`; its PEM output is the PKCS #8 `PRIVATE KEY`.
            let Some(pem) = openssl3(
                &[
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    &curve_option,
                    "-pkeyopt",
                    "ec_param_enc:named_curve",
                ],
                b"",
            )
            .or_skip(TEST) else {
                return;
            };
            let pem = String::from_utf8(pem).expect("PEM is ASCII");
            let pkcs8 = pem_decode(PRIVATE_KEY_LABEL, &pem, |der| Some(der.to_vec()))
                .unwrap_or_else(|| panic!("OpenSSL's {name} key must be PKCS #8 PEM"));
            let private = EcdsaPrivateKey::from_pkcs8_pem(&pem)
                .unwrap_or_else(|| panic!("OpenSSL's {name} PKCS #8 key must parse"));
            assert!(private.curve().same_curve(&(named.build)()), "{name}");

            // Ours names the curve inside ECPrivateKey too (RFC 5915 §3);
            // OpenSSL reads it and writes back exactly its own form.
            let ours = private.to_pkcs8_der().expect("named curve");
            let Some(reread) =
                openssl3(&["pkey", "-inform", "DER", "-outform", "DER"], &ours).or_skip(TEST)
            else {
                return;
            };
            assert_eq!(reread, pkcs8, "{name}: PKCS #8");

            let Some(sec1) =
                openssl3(&["ec", "-inform", "DER", "-outform", "DER"], &pkcs8).or_skip(TEST)
            else {
                return;
            };
            assert_eq!(
                private.to_sec1_der().as_deref(),
                Some(&sec1[..]),
                "{name}: SEC 1"
            );
            assert!(EcdsaPrivateKey::from_sec1_der(&sec1)
                .is_some_and(|key| key.private_scalar() == private.private_scalar()));

            let public = private.to_public_key();
            let Some(spki) = openssl3(
                &["pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                &pkcs8,
            )
            .or_skip(TEST) else {
                return;
            };
            assert_eq!(
                public.to_spki_der().as_deref(),
                Some(&spki[..]),
                "{name}: SPKI"
            );

            let Some(compressed) = openssl3(
                &[
                    "ec",
                    "-inform",
                    "DER",
                    "-pubout",
                    "-conv_form",
                    "compressed",
                    "-outform",
                    "DER",
                ],
                &pkcs8,
            )
            .or_skip(TEST) else {
                return;
            };
            let decoded = EcdsaPublicKey::from_spki_der(&compressed)
                .unwrap_or_else(|| panic!("OpenSSL's compressed {name} SPKI must parse"));
            assert_eq!(decoded.public_point(), public.public_point(), "{name}");
        }
    }

    /// OpenSSL reads the PEM forms of the RFC 9500 P-256 key as written here.
    #[test]
    fn openssl_reads_our_pem_encodings() {
        const TEST: &str = "openssl_reads_our_pem_encodings";
        let private = EcdhPrivateKey::from_sec1_pem(RFC9500_KEYS[0].pem).expect("RFC 9500 key");
        let Some(sec1) = openssl3(
            &["ec", "-inform", "PEM", "-outform", "PEM"],
            private.to_sec1_pem().expect("named curve").as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(String::from_utf8_lossy(&sec1), RFC9500_KEYS[0].pem);

        let Some(pkcs8) = openssl3(
            &["pkey", "-inform", "PEM", "-outform", "DER"],
            private.to_pkcs8_pem().expect("named curve").as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        let reread = EcdhPrivateKey::from_pkcs8_der(&pkcs8).expect("OpenSSL's PKCS #8");
        assert_eq!(reread.private_scalar(), private.private_scalar());

        let public = private.to_public_key();
        let Some(spki) = openssl3(
            &["pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
            public.to_spki_pem().expect("named curve").as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(public.to_spki_der().as_deref(), Some(&spki[..]));
    }
}
