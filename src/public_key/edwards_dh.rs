//! Diffie-Hellman key agreement over twisted Edwards curves.
//!
//! This is the Edwards analogue of the short-Weierstrass [`crate::public_key::ecdh`]
//! wrapper: two parties each hold a scalar `d` and public point `Q = d·G`, then
//! compute the same shared point
//!
//! ```text
//! S = d_A · Q_B = d_B · Q_A = d_A · d_B · G
//! ```
//!
//! The shared secret returned here is the RFC 8032-style compressed point
//! encoding of `S`. Callers should pass that byte string through a KDF before
//! using it as a symmetric key.

use core::fmt;

use crate::public_key::ec_edwards::{EdwardsMulTable, EdwardsPoint, TwistedEdwardsCurve};
use crate::Csprng;
use rump::BigUint;

const EDWARDS_DH_PUBLIC_LABEL: &str = "CRYPTOGRAPHY EDWARDS-DH PUBLIC KEY";
const EDWARDS_DH_PRIVATE_LABEL: &str = "CRYPTOGRAPHY EDWARDS-DH PRIVATE KEY";

/// Public key for Edwards-curve Diffie-Hellman.
#[derive(Clone, Debug)]
pub struct EdwardsDhPublicKey {
    curve: TwistedEdwardsCurve,
    q: EdwardsPoint,
    q_table: EdwardsMulTable,
}

/// Private key for Edwards-curve Diffie-Hellman.
#[derive(Clone)]
pub struct EdwardsDhPrivateKey {
    curve: TwistedEdwardsCurve,
    d: BigUint,
    q: EdwardsPoint,
}

/// Namespace wrapper for Edwards-curve Diffie-Hellman.
pub struct EdwardsDh;

impl EdwardsDhPublicKey {
    /// Return the curve parameters.
    #[must_use]
    pub fn curve(&self) -> &TwistedEdwardsCurve {
        &self.curve
    }

    /// Return the public point `Q = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &EdwardsPoint {
        &self.q
    }

    /// Encode the public point using the curve's RFC 8032-style compressed form.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Decode a public key from the compressed Edwards point form.
    #[must_use]
    pub fn from_wire_bytes(curve: TwistedEdwardsCurve, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.curve.p.clone(),
            self.curve.a.clone(),
            self.curve.d.clone(),
            self.curve.n.clone(),
            self.curve.gx.clone(),
            self.curve.gy.clone(),
            self.q.x.clone(),
            self.q.y.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let qx = fields.next()?;
        let qy = fields.next()?;
        let curve = TwistedEdwardsCurve::from_explicit(p, a, d_curve, n, gx, gy)?;
        let q = EdwardsPoint::new(qx, qy);
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EdwardsDhPublicKey,
    "EdwardsDhPublicKey",
    ["p", "a", "d", "n", "gx", "gy", "qx", "qy"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EdwardsDhPublicKey,
    EDWARDS_DH_PUBLIC_LABEL,
    ["p", "a", "d", "n", "gx", "gy", "qx", "qy"]
);

impl EdwardsDhPrivateKey {
    /// Return the curve parameters.
    #[must_use]
    pub fn curve(&self) -> &TwistedEdwardsCurve {
        &self.curve
    }

    /// Return the private scalar `d ∈ [1, n)`.
    #[must_use]
    pub fn private_scalar(&self) -> &BigUint {
        &self.d
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> EdwardsDhPublicKey {
        EdwardsDhPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
            q_table: self.curve.precompute_mul_table(&self.q),
        }
    }

    /// Compute the shared point and return its compressed Edwards encoding,
    /// or `None` when `peer` is on another curve.
    ///
    /// The shared point is never the neutral element: every public-key
    /// import path checks `Q` into the prime-order subgroup and away from
    /// the neutral element ([`TwistedEdwardsCurve::is_valid_public_point`]),
    /// so `Q` has order exactly `n`, and `d ∈ [1, n)` is no multiple of `n`.
    /// That validation on import is the defence against small-subgroup
    /// inputs; nothing is re-checked here.
    ///
    /// Returning the encoded point keeps the wrapper purely in Edwards form;
    /// callers should pass the bytes through a KDF before using them as key
    /// material.
    #[must_use]
    pub fn agree_compressed_point(&self, peer: &EdwardsDhPublicKey) -> Option<Vec<u8>> {
        if !self.curve.same_curve(&peer.curve) {
            return None;
        }
        let shared = self.curve.scalar_mul_cached(&peer.q_table, &self.d);
        Some(self.curve.encode_point(&shared))
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.curve.p.clone(),
            self.curve.a.clone(),
            self.curve.d.clone(),
            self.curve.n.clone(),
            self.curve.gx.clone(),
            self.curve.gy.clone(),
            self.d.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let d = fields.next()?;
        let curve = TwistedEdwardsCurve::from_explicit(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        let q = curve.scalar_mul_base(&d);
        Some(Self { curve, d, q })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EdwardsDhPrivateKey,
    "EdwardsDhPrivateKey",
    ["p", "a", "d", "n", "gx", "gy", "scalar"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EdwardsDhPrivateKey,
    EDWARDS_DH_PRIVATE_LABEL,
    ["p", "a", "d", "n", "gx", "gy", "scalar"]
);

impl fmt::Debug for EdwardsDhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EdwardsDhPrivateKey(<redacted>)")
    }
}

impl EdwardsDh {
    /// Generate a fresh Edwards-DH key pair on `curve`.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: TwistedEdwardsCurve,
        rng: &mut R,
    ) -> (EdwardsDhPublicKey, EdwardsDhPrivateKey) {
        let d = curve.random_scalar(rng);
        let q = curve.scalar_mul_base(&d);
        (
            EdwardsDhPublicKey {
                curve: curve.clone(),
                q: q.clone(),
                q_table: curve.precompute_mul_table(&q),
            },
            EdwardsDhPrivateKey { curve, d, q },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{EdwardsDh, EdwardsDhPrivateKey, EdwardsDhPublicKey};
    use crate::public_key::ec_edwards::ed25519;
    use crate::public_key::io::{encode_biguints, xml_wrap};
    use crate::test_utils::decode_hex;
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    fn rng(seed: u8) -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[seed; 48])
    }

    #[test]
    fn agreement_roundtrip_ed25519() {
        let (pub_a, priv_a) = EdwardsDh::generate(ed25519(), &mut rng(0x11));
        let (pub_b, priv_b) = EdwardsDh::generate(ed25519(), &mut rng(0x22));
        let shared_a = priv_a.agree_compressed_point(&pub_b).expect("shared a");
        let shared_b = priv_b.agree_compressed_point(&pub_a).expect("shared b");
        assert_eq!(shared_a, shared_b);
    }

    /// Regression fixture: the private scalar 7 agreed with the peer point
    /// `11·G` gives `77·G`. The two encodings are this implementation's RFC
    /// 8032 §5.1.2 encodings of `11·G` and `77·G`, the same values
    /// `ec_edwards` pins for those base-point multiples; they have no external
    /// source and guard against unintended change, not as independent known
    /// answers.
    #[test]
    fn agreement_of_7_with_11g_is_the_regression_encoding_of_77g() {
        let curve = ed25519();
        let private = EdwardsDhPrivateKey {
            curve: curve.clone(),
            d: BigUint::from_u64(7),
            q: curve.scalar_mul_base(&BigUint::from_u64(7)),
        };
        let peer_bytes =
            decode_hex("1337036ac32d8f30d4589c3c1c595812ce0fff40e37c6f5a97ab213f318290ad");
        let peer = EdwardsDhPublicKey::from_wire_bytes(curve, &peer_bytes).expect("peer");
        let shared = private.agree_compressed_point(&peer).expect("shared");
        assert_eq!(
            shared,
            decode_hex("aa6df914f7a0f04e7f852adf459873f17dba5b1671ea62e82cc10ed6aecc489c")
        );
    }

    #[test]
    fn public_serialization_roundtrip() {
        let (public, _) = EdwardsDh::generate(ed25519(), &mut rng(0x33));
        let bin = public.to_key_blob();
        let pem = public.to_pem();
        let xml = public.to_xml();
        let round_bin = EdwardsDhPublicKey::from_key_blob(&bin).expect("bin");
        let round_pem = EdwardsDhPublicKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsDhPublicKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_key_blob(), public.to_key_blob());
        assert_eq!(round_pem.to_key_blob(), public.to_key_blob());
        assert_eq!(round_xml.to_key_blob(), public.to_key_blob());
    }

    #[test]
    fn private_serialization_roundtrip() {
        let (_, private) = EdwardsDh::generate(ed25519(), &mut rng(0x44));
        let bin = private.to_key_blob();
        let pem = private.to_pem();
        let xml = private.to_xml();
        let round_bin = EdwardsDhPrivateKey::from_key_blob(&bin).expect("bin");
        let round_pem = EdwardsDhPrivateKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsDhPrivateKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_key_blob(), private.to_key_blob());
        assert_eq!(round_pem.to_key_blob(), private.to_key_blob());
        assert_eq!(round_xml.to_key_blob(), private.to_key_blob());
    }

    #[test]
    fn debug_redacts_private_key() {
        let (_, private) = EdwardsDh::generate(ed25519(), &mut rng(0x55));
        assert_eq!(format!("{private:?}"), "EdwardsDhPrivateKey(<redacted>)");
    }

    /// The public-key schema fields with `p` added to field `index` (6 = `qx`,
    /// 7 = `qy`): the same point modulo `p`, encoded non-canonically.
    fn public_fields_offset_by_p(public: &EdwardsDhPublicKey, index: usize) -> Vec<BigUint> {
        let mut fields = public.serial_fields();
        fields[index] = fields[index].add(&public.curve.p);
        fields
    }

    fn public_blob(fields: &[BigUint]) -> Vec<u8> {
        let refs: Vec<&BigUint> = fields.iter().collect();
        encode_biguints(&refs)
    }

    fn public_xml(fields: &[BigUint]) -> String {
        let names = ["p", "a", "d", "n", "gx", "gy", "qx", "qy"];
        let pairs: Vec<(&str, &BigUint)> = names.iter().copied().zip(fields.iter()).collect();
        xml_wrap("EdwardsDhPublicKey", &pairs)
    }

    #[test]
    fn public_blob_rejects_non_canonical_coordinates() {
        let (public, _) = EdwardsDh::generate(ed25519(), &mut rng(0x55));
        assert!(EdwardsDhPublicKey::from_key_blob(&public_blob(&public.serial_fields())).is_some());
        for index in [6, 7] {
            let blob = public_blob(&public_fields_offset_by_p(&public, index));
            assert!(
                EdwardsDhPublicKey::from_key_blob(&blob).is_none(),
                "blob decode accepted field {index} + p"
            );
        }
    }

    #[test]
    fn public_xml_rejects_non_canonical_coordinates() {
        let (public, _) = EdwardsDh::generate(ed25519(), &mut rng(0x66));
        assert!(EdwardsDhPublicKey::from_xml(&public_xml(&public.serial_fields())).is_some());
        for index in [6, 7] {
            let xml = public_xml(&public_fields_offset_by_p(&public, index));
            assert!(
                EdwardsDhPublicKey::from_xml(&xml).is_none(),
                "XML decode accepted field {index} + p"
            );
        }
    }
}
