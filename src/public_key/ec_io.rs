//! The crate-defined encodings of short-Weierstrass elliptic-curve keys,
//! shared by ECDSA, ECDH, EC-ElGamal and ECIES.
//!
//! All four schemes hold the same key material: a public key is the domain
//! parameters and the point `Q = d·G`; a private key is the domain parameters
//! and the scalar `d`, with `Q` derived. One encoder and one decoder per
//! format live here, and each scheme's key types take them through
//! [`impl_ec_public_key_io!`] and [`impl_ec_private_key_io!`], supplying only
//! the PEM label and the XML root name that identify the scheme.
//!
//! # Formats
//!
//! **Key blob.** One field-type octet, `00` for a prime field and `01` for a
//! binary field, followed by the crate's DER `SEQUENCE` of positive
//! `INTEGER`s: `[p, a, b, n, h, Gx, Gy, Qx, Qy]` for a public key and
//! `[p, a, b, n, h, Gx, Gy, d]` for a private key. On a binary field `p` is
//! the reduction polynomial `f(x)` as a bit pattern, so the field degree is
//! `deg f = bits(p) − 1`. Any other field-type octet is refused.
//!
//! **PEM.** RFC 7468 armor over the key blob, under a label of the form
//! `CRYPTOGRAPHY <SCHEME> <ROLE> KEY`.
//!
//! **XML.** The crate's flat form with the elements `p, a, b, n, h, degree,
//! gx, gy` followed by `qx, qy` or `d`; `degree` is `0` for a prime field and
//! `m` for `F_2^m`.
//!
//! # Decoding
//!
//! Every decoder validates what it reads before it hands a key back:
//!
//! - the domain parameters go through [`CurveParams::from_explicit`], which
//!   admits them only as a named curve of SEC 2 / FIPS 186-4 or by the SEC 1
//!   v2.0 §3.1.1.2.1 / §3.1.2.2.1 validation primitive;
//! - a public point must be a valid public key
//!   ([`CurveParams::is_valid_public_point`], SEC 1 §3.2.2.1): not `∞`,
//!   coordinates in the field, on the curve, in the subgroup of order `n`;
//! - a private scalar must lie in `[1, n − 1]` (SEC 1 §3.2.1) and its `d·G`
//!   must be a valid public key ([`CurveParams::public_point_for_scalar`]).
//!
//! The XML field count is fixed by the element list; the blob decoders
//! refuse a `SEQUENCE` with too few or too many `INTEGER`s.
//!
//! # Scrubbing
//!
//! A private scalar's DER image is wiped once it has been copied into the
//! blob being returned; the blob is wiped after it has been armored into PEM;
//! a PEM body is held in a buffer that wipes itself when dropped, on every
//! path out of the decoder; and every decoded `BigUint` wipes its limbs when
//! dropped. What the encoders return is the caller's to protect.

use crate::public_key::ec::{AffinePoint, CurveParams, ExplicitField};
use crate::public_key::io::{
    decode_biguints, encode_biguints, extend_wiped, pem_contents, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::zeroize_slice;
use rump::BigUint;

/// The field-type octet of a prime-field key blob.
const FIELD_PRIME: u8 = 0x00;

/// The field-type octet of a binary-field key blob.
const FIELD_BINARY: u8 = 0x01;

/// The XML elements of a public key, in order.
const PUBLIC_XML_FIELDS: [&str; 10] = ["p", "a", "b", "n", "h", "degree", "gx", "gy", "qx", "qy"];

/// The XML elements of a private key, in order.
const PRIVATE_XML_FIELDS: [&str; 9] = ["p", "a", "b", "n", "h", "degree", "gx", "gy", "d"];

/// Where a serialized key says which field it is over: the blob's field-type
/// octet, or the XML `degree` element.
#[derive(Clone, Copy)]
enum Layout {
    Blob { field_type: u8 },
    Xml,
}

/// The field-type octet of `curve`'s key blob.
fn field_type_octet(curve: &CurveParams) -> u8 {
    if curve.gf2m_degree().is_some() {
        FIELD_BINARY
    } else {
        FIELD_PRIME
    }
}

/// The XML `degree` element: `m` for `F_2^m`, `0` for a prime field.
///
/// # Panics
///
/// Panics if a binary-field degree does not fit in `u64`, which no
/// [`CurveParams`] can have: its reduction polynomial is a `BigUint` whose
/// bit length is a `usize`.
fn degree_element(curve: &CurveParams) -> BigUint {
    BigUint::from_u64(u64::try_from(curve.gf2m_degree().unwrap_or(0)).expect("degree fits in u64"))
}

// ─── Encoders ────────────────────────────────────────────────────────────────

/// The key blob of the public key `(curve, q)`.
pub(crate) fn public_key_blob(curve: &CurveParams, q: &AffinePoint) -> Vec<u8> {
    let h = BigUint::from_u64(curve.h);
    let mut out = vec![field_type_octet(curve)];
    out.extend_from_slice(&encode_biguints(&[
        &curve.p, &curve.a, &curve.b, &curve.n, &h, &curve.gx, &curve.gy, &q.x, &q.y,
    ]));
    out
}

/// The key blob of the private key `(curve, d)`. The DER image of `d` is
/// wiped once copied; only the returned blob carries the scalar.
pub(crate) fn private_key_blob(curve: &CurveParams, d: &BigUint) -> Vec<u8> {
    let h = BigUint::from_u64(curve.h);
    let body = encode_biguints(&[
        &curve.p, &curve.a, &curve.b, &curve.n, &h, &curve.gx, &curve.gy, d,
    ]);
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(field_type_octet(curve));
    extend_wiped(&mut out, body);
    out
}

/// PEM armor under `label` over the public key blob.
pub(crate) fn public_key_pem(label: &str, curve: &CurveParams, q: &AffinePoint) -> String {
    pem_wrap(label, &public_key_blob(curve, q))
}

/// PEM armor under `label` over the private key blob, which is wiped once
/// armored.
pub(crate) fn private_key_pem(label: &str, curve: &CurveParams, d: &BigUint) -> String {
    let mut blob = private_key_blob(curve, d);
    let pem = pem_wrap(label, &blob);
    zeroize_slice(blob.as_mut_slice());
    pem
}

/// The flat XML document `<root>` of the public key `(curve, q)`.
pub(crate) fn public_key_xml(root: &str, curve: &CurveParams, q: &AffinePoint) -> String {
    let h = BigUint::from_u64(curve.h);
    let degree = degree_element(curve);
    xml_wrap(
        root,
        &[
            ("p", &curve.p),
            ("a", &curve.a),
            ("b", &curve.b),
            ("n", &curve.n),
            ("h", &h),
            ("degree", &degree),
            ("gx", &curve.gx),
            ("gy", &curve.gy),
            ("qx", &q.x),
            ("qy", &q.y),
        ],
    )
}

/// The flat XML document `<root>` of the private key `(curve, d)`.
/// `xml_wrap` wipes the byte image of every value it formats.
pub(crate) fn private_key_xml(root: &str, curve: &CurveParams, d: &BigUint) -> String {
    let h = BigUint::from_u64(curve.h);
    let degree = degree_element(curve);
    xml_wrap(
        root,
        &[
            ("p", &curve.p),
            ("a", &curve.a),
            ("b", &curve.b),
            ("n", &curve.n),
            ("h", &h),
            ("degree", &degree),
            ("gx", &curve.gx),
            ("gy", &curve.gy),
            ("d", d),
        ],
    )
}

// ─── Decoders ────────────────────────────────────────────────────────────────

/// The domain parameters at the front of a serialized key: `p, a, b, n, h`,
/// the XML `degree` where the layout has one, then `Gx, Gy`. Accepted on the
/// grounds of [`CurveParams::from_explicit`] only.
fn decode_curve(layout: Layout, fields: &mut impl Iterator<Item = BigUint>) -> Option<CurveParams> {
    let p = fields.next()?;
    let a = fields.next()?;
    let b = fields.next()?;
    let n = fields.next()?;
    let h = fields.next()?.to_u64()?;
    let field = match layout {
        Layout::Blob { field_type } => match field_type {
            FIELD_PRIME => ExplicitField::Prime(p),
            FIELD_BINARY => ExplicitField::Binary {
                degree: p.bits().checked_sub(1)?,
                modulus: p,
            },
            _ => return None,
        },
        Layout::Xml => {
            let degree = usize::try_from(fields.next()?.to_u64()?).ok()?;
            if degree == 0 {
                ExplicitField::Prime(p)
            } else {
                ExplicitField::Binary { modulus: p, degree }
            }
        }
    };
    let gx = fields.next()?;
    let gy = fields.next()?;
    CurveParams::from_explicit(field, a, b, n, h, gx, gy)
}

/// A public key from its schema fields: the curve, then `Qx, Qy` and nothing
/// more, with `Q` a valid public key (SEC 1 §3.2.2.1).
fn decode_public(layout: Layout, fields: Vec<BigUint>) -> Option<(CurveParams, AffinePoint)> {
    let mut fields = fields.into_iter();
    let curve = decode_curve(layout, &mut fields)?;
    let x = fields.next()?;
    let y = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let q = AffinePoint::new(x, y);
    curve.is_valid_public_point(&q).then_some((curve, q))
}

/// A private key from its schema fields: the curve, then `d` and nothing
/// more, with `1 ≤ d < n` and `d·G` a valid public key.
fn decode_private(
    layout: Layout,
    fields: Vec<BigUint>,
) -> Option<(CurveParams, BigUint, AffinePoint)> {
    let mut fields = fields.into_iter();
    let curve = decode_curve(layout, &mut fields)?;
    let d = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let q = curve.public_point_for_scalar(&d)?;
    Some((curve, d, q))
}

/// The field-type octet and the DER body of a key blob.
fn split_blob(blob: &[u8]) -> Option<(Layout, Vec<BigUint>)> {
    let (&field_type, body) = blob.split_first()?;
    Some((Layout::Blob { field_type }, decode_biguints(body)?))
}

/// The public key a key blob encodes.
pub(crate) fn public_key_from_blob(blob: &[u8]) -> Option<(CurveParams, AffinePoint)> {
    let (layout, fields) = split_blob(blob)?;
    decode_public(layout, fields)
}

/// The private key a key blob encodes.
pub(crate) fn private_key_from_blob(blob: &[u8]) -> Option<(CurveParams, BigUint, AffinePoint)> {
    let (layout, fields) = split_blob(blob)?;
    decode_private(layout, fields)
}

/// The public key a PEM document under `label` encodes.
pub(crate) fn public_key_from_pem(label: &str, pem: &str) -> Option<(CurveParams, AffinePoint)> {
    let blob = pem_contents(label, pem)?;
    public_key_from_blob(&blob)
}

/// The private key a PEM document under `label` encodes. The decoded body is
/// held in a buffer that wipes itself when dropped, whichever way this
/// returns.
pub(crate) fn private_key_from_pem(
    label: &str,
    pem: &str,
) -> Option<(CurveParams, BigUint, AffinePoint)> {
    let blob = pem_contents(label, pem)?;
    private_key_from_blob(&blob)
}

/// The public key an XML document `<root>` encodes.
pub(crate) fn public_key_from_xml(root: &str, xml: &str) -> Option<(CurveParams, AffinePoint)> {
    decode_public(Layout::Xml, xml_unwrap(root, &PUBLIC_XML_FIELDS, xml)?)
}

/// The private key an XML document `<root>` encodes.
pub(crate) fn private_key_from_xml(
    root: &str,
    xml: &str,
) -> Option<(CurveParams, BigUint, AffinePoint)> {
    decode_private(Layout::Xml, xml_unwrap(root, &PRIVATE_XML_FIELDS, xml)?)
}

// ─── Per-scheme methods ──────────────────────────────────────────────────────

/// Emit `to_key_blob` / `from_key_blob`, `to_pem` / `from_pem` and `to_xml` /
/// `from_xml` for an EC public key type with fields `curve: CurveParams` and
/// `q: AffinePoint`, under the given PEM label and XML root name.
macro_rules! impl_ec_public_key_io {
    ($ty:ident, $label:literal, $root:literal) => {
        impl $ty {
            /// Encode in the crate-defined binary format: one field-type
            /// octet (`00` prime field, `01` binary field), then
            /// `[p, a, b, n, h, Gx, Gy, Qx, Qy]` as a DER `SEQUENCE` of
            /// positive `INTEGER`s.
            #[must_use]
            pub fn to_key_blob(&self) -> ::std::vec::Vec<u8> {
                crate::public_key::ec_io::public_key_blob(&self.curve, &self.q)
            }

            /// Decode from the crate-defined binary format.
            ///
            /// Returns `None` unless the field-type octet is `00` or `01`,
            /// the domain parameters are a named curve or pass the SEC 1
            /// v2.0 §3.1.1.2.1 / §3.1.2.2.1 validation primitive
            /// ([`CurveParams::from_explicit`]), and `Q` is a valid public
            /// key (§3.2.2.1, [`CurveParams::is_valid_public_point`]).
            ///
            /// [`CurveParams::from_explicit`]: crate::public_key::ec::CurveParams::from_explicit
            /// [`CurveParams::is_valid_public_point`]: crate::public_key::ec::CurveParams::is_valid_public_point
            #[must_use]
            pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
                let (curve, q) = crate::public_key::ec_io::public_key_from_blob(blob)?;
                Some(Self { curve, q })
            }

            /// Encode as RFC 7468 PEM armor over the key blob, under the
            #[doc = concat!("`", $label, "` label.")]
            #[must_use]
            pub fn to_pem(&self) -> String {
                crate::public_key::ec_io::public_key_pem($label, &self.curve, &self.q)
            }

            /// Decode from PEM armor; the label must match and the body
            /// must decode as [`Self::from_key_blob`] requires.
            #[must_use]
            pub fn from_pem(pem: &str) -> Option<Self> {
                let (curve, q) = crate::public_key::ec_io::public_key_from_pem($label, pem)?;
                Some(Self { curve, q })
            }

            /// Encode as the crate's flat XML form: the root element
            #[doc = concat!("`<", $root, ">` holding `p, a, b, n, h, degree, gx, gy, qx, qy`,")]
            /// with `degree` `0` on a prime field and `m` on `F_2^m`.
            #[must_use]
            pub fn to_xml(&self) -> String {
                crate::public_key::ec_io::public_key_xml($root, &self.curve, &self.q)
            }

            /// Decode from the crate's flat XML form, validating the domain
            /// parameters and the point as [`Self::from_key_blob`] does.
            #[must_use]
            pub fn from_xml(xml: &str) -> Option<Self> {
                let (curve, q) = crate::public_key::ec_io::public_key_from_xml($root, xml)?;
                Some(Self { curve, q })
            }
        }
    };
}
pub(crate) use impl_ec_public_key_io;

/// Emit `to_key_blob` / `from_key_blob`, `to_pem` / `from_pem` and `to_xml` /
/// `from_xml` for an EC private key type with fields `curve: CurveParams`,
/// `d: BigUint` and `q: AffinePoint`, under the given PEM label and XML root
/// name. Every temporary holding `d` or its encoding is wiped.
macro_rules! impl_ec_private_key_io {
    ($ty:ident, $label:literal, $root:literal) => {
        impl $ty {
            /// Encode in the crate-defined binary format: one field-type
            /// octet (`00` prime field, `01` binary field), then
            /// `[p, a, b, n, h, Gx, Gy, d]` as a DER `SEQUENCE` of positive
            /// `INTEGER`s. The DER image of `d` is wiped once copied into the
            /// returned blob.
            #[must_use]
            pub fn to_key_blob(&self) -> ::std::vec::Vec<u8> {
                crate::public_key::ec_io::private_key_blob(&self.curve, &self.d)
            }

            /// Decode from the crate-defined binary format.
            ///
            /// Returns `None` unless the field-type octet is `00` or `01`,
            /// the domain parameters are a named curve or pass the SEC 1
            /// v2.0 §3.1.1.2.1 / §3.1.2.2.1 validation primitive
            /// ([`CurveParams::from_explicit`]), `1 ≤ d < n` (§3.2.1), and
            /// `d·G` is a valid public key (§3.2.2.1). The public point is
            /// derived, never read.
            ///
            /// [`CurveParams::from_explicit`]: crate::public_key::ec::CurveParams::from_explicit
            #[must_use]
            pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
                let (curve, d, q) = crate::public_key::ec_io::private_key_from_blob(blob)?;
                Some(Self { curve, d, q })
            }

            /// Encode as RFC 7468 PEM armor over the key blob, under the
            #[doc = concat!("`", $label, "` label. The blob is wiped once armored.")]
            #[must_use]
            pub fn to_pem(&self) -> String {
                crate::public_key::ec_io::private_key_pem($label, &self.curve, &self.d)
            }

            /// Decode from PEM armor; the label must match and the body
            /// must decode as [`Self::from_key_blob`] requires. The decoded
            /// body is wiped on every path out.
            #[must_use]
            pub fn from_pem(pem: &str) -> Option<Self> {
                let (curve, d, q) = crate::public_key::ec_io::private_key_from_pem($label, pem)?;
                Some(Self { curve, d, q })
            }

            /// Encode as the crate's flat XML form: the root element
            #[doc = concat!("`<", $root, ">` holding `p, a, b, n, h, degree, gx, gy, d`,")]
            /// with `degree` `0` on a prime field and `m` on `F_2^m`. The
            /// byte image of `d` formatted into the document is wiped.
            #[must_use]
            pub fn to_xml(&self) -> String {
                crate::public_key::ec_io::private_key_xml($root, &self.curve, &self.d)
            }

            /// Decode from the crate's flat XML form, validating the domain
            /// parameters and the scalar as [`Self::from_key_blob`] does.
            #[must_use]
            pub fn from_xml(xml: &str) -> Option<Self> {
                let (curve, d, q) = crate::public_key::ec_io::private_key_from_xml($root, xml)?;
                Some(Self { curve, d, q })
            }
        }
    };
}
pub(crate) use impl_ec_private_key_io;

// ─── Shared tests ────────────────────────────────────────────────────────────

/// The crate-encoding tests every EC scheme runs, given its namespace type
/// (with `generate(curve, rng)`), its key types, and the PEM labels and XML
/// root names its encodings carry. The tests use only the public API of the
/// key types: `curve()`, `public_point()`, `private_scalar()` and the six
/// encoders and decoders.
#[cfg(test)]
macro_rules! ec_key_io_tests {
    ($namespace:ident, $public:ident, $private:ident, $public_label:expr, $private_label:expr, $public_root:literal, $private_root:literal) => {
        mod ec_key_io {
            use super::{$namespace, $private, $public};
            use crate::public_key::ec::{b163, p256, secp256k1, CurveParams};
            use rump::BigUint;

            fn rng() -> crate::CtrDrbgAes256 {
                crate::CtrDrbgAes256::new(&[0xe1; 48])
            }

            /// P-256 under `−G`: sound parameters that no name covers, so
            /// the decoders accept them by the SEC 1 validation primitive.
            fn p256_under_negated_g() -> CurveParams {
                let named = p256();
                CurveParams::new(
                    named.p.clone(),
                    named.a.clone(),
                    named.b.clone(),
                    named.n.clone(),
                    named.h,
                    named.gx.clone(),
                    named.p.sub(&named.gy),
                )
                .expect("valid parameters")
            }

            /// `y² = x³ + 2x + 2` over `F_17` with `G = (5, 1)` of order 19:
            /// the textbook curve of Paar and Pelzl, *Understanding
            /// Cryptography* (Springer, 2010), Example 9.5. Its 5-bit field
            /// is outside what the SEC 1 primitive admits.
            fn toy_curve() -> CurveParams {
                CurveParams::new(
                    BigUint::from_u64(17),
                    BigUint::from_u64(2),
                    BigUint::from_u64(2),
                    BigUint::from_u64(19),
                    1,
                    BigUint::from_u64(5),
                    BigUint::one(),
                )
                .expect("valid toy curve")
            }

            fn decoders_agree(public: &$public, private: &$private, curve: &CurveParams) {
                let blob = public.to_key_blob();
                assert_eq!(
                    blob[0],
                    u8::from(curve.gf2m_degree().is_some()),
                    "field-type octet"
                );
                let pem = public.to_pem();
                assert!(pem.contains($public_label));
                let xml = public.to_xml();
                assert!(xml.starts_with(concat!("<", $public_root, ">")));
                for decoded in [
                    $public::from_key_blob(&blob).expect("public blob"),
                    $public::from_pem(&pem).expect("public PEM"),
                    $public::from_xml(&xml).expect("public XML"),
                ] {
                    assert!(decoded.curve().same_curve(curve));
                    assert_eq!(decoded.public_point(), public.public_point());
                }

                let blob = private.to_key_blob();
                assert_eq!(blob[0], u8::from(curve.gf2m_degree().is_some()));
                let pem = private.to_pem();
                assert!(pem.contains($private_label));
                let xml = private.to_xml();
                assert!(xml.starts_with(concat!("<", $private_root, ">")));
                for decoded in [
                    $private::from_key_blob(&blob).expect("private blob"),
                    $private::from_pem(&pem).expect("private PEM"),
                    $private::from_xml(&xml).expect("private XML"),
                ] {
                    assert!(decoded.curve().same_curve(curve));
                    assert_eq!(decoded.private_scalar(), private.private_scalar());
                    assert_eq!(
                        decoded.to_public_key().public_point(),
                        public.public_point()
                    );
                }
            }

            /// Blob, PEM and XML round-trip on a NIST prime curve, on
            /// secp256k1, on the binary curve B-163 (through the binary
            /// branch of every decoder) and on P-256 under `−G`.
            #[test]
            fn every_encoding_round_trips_on_prime_binary_and_unnamed_curves() {
                let mut rng = rng();
                for curve in [p256(), secp256k1(), b163(), p256_under_negated_g()] {
                    let (public, private) = $namespace::generate(curve.clone(), &mut rng);
                    decoders_agree(&public, &private, &curve);
                }
            }

            /// The field-type octet is `00` or `01` and nothing else: `02`
            /// and `ff` are refused, and so is `01` on a prime-field blob,
            /// whose `p` is no reduction polynomial SEC 1 admits.
            #[test]
            fn key_blob_refuses_every_other_field_type_octet() {
                let mut rng = rng();
                let (public, private) = $namespace::generate(p256(), &mut rng);
                for (blob, is_public) in
                    [(public.to_key_blob(), true), (private.to_key_blob(), false)]
                {
                    assert_eq!(blob[0], 0x00);
                    for octet in [0x01u8, 0x02, 0x03, 0xff] {
                        let mut altered = blob.clone();
                        altered[0] = octet;
                        if is_public {
                            assert!($public::from_key_blob(&altered).is_none(), "{octet:#04x}");
                        } else {
                            assert!($private::from_key_blob(&altered).is_none(), "{octet:#04x}");
                        }
                    }
                }
                let (public, _) = $namespace::generate(b163(), &mut rng);
                let mut blob = public.to_key_blob();
                assert_eq!(blob[0], 0x01);
                blob[0] = 0x02;
                assert!($public::from_key_blob(&blob).is_none());
            }

            /// The Paar–Pelzl toy curve is refused on every decoder, public
            /// and private, blob, PEM and XML.
            #[test]
            fn toy_curve_is_refused_on_every_path() {
                let mut rng = rng();
                let (public, private) = $namespace::generate(toy_curve(), &mut rng);
                assert!($public::from_key_blob(&public.to_key_blob()).is_none());
                assert!($public::from_pem(&public.to_pem()).is_none());
                assert!($public::from_xml(&public.to_xml()).is_none());
                assert!($private::from_key_blob(&private.to_key_blob()).is_none());
                assert!($private::from_pem(&private.to_pem()).is_none());
                assert!($private::from_xml(&private.to_xml()).is_none());
            }

            /// A blob with a field missing or one too many is refused.
            #[test]
            fn key_blob_field_count_is_exact() {
                use crate::public_key::io::{decode_biguints, encode_biguints};
                let mut rng = rng();
                let (public, private) = $namespace::generate(p256(), &mut rng);
                for (blob, expected, is_public) in [
                    (public.to_key_blob(), 9, true),
                    (private.to_key_blob(), 8, false),
                ] {
                    let fields = decode_biguints(&blob[1..]).expect("DER body");
                    assert_eq!(fields.len(), expected);
                    let short: Vec<&BigUint> = fields[..expected - 1].iter().collect();
                    let mut long: Vec<&BigUint> = fields.iter().collect();
                    long.push(&fields[0]);
                    for body in [encode_biguints(&short), encode_biguints(&long)] {
                        let altered = [&blob[..1], &body].concat();
                        if is_public {
                            assert!($public::from_key_blob(&altered).is_none());
                        } else {
                            assert!($private::from_key_blob(&altered).is_none());
                        }
                    }
                }
            }
        }
    };
}
#[cfg(test)]
pub(crate) use ec_key_io_tests;
