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

use crate::public_key::bigint::BigUint;
use crate::public_key::ec_edwards::{EdwardsMulTable, EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::Csprng;

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
        if !validate_public_point(&curve, &q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
    }

    /// Encode in the crate-defined binary format: `[p, a, d, n, Gx, Gy, Qx, Qy]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[
            &self.curve.p,
            &self.curve.a,
            &self.curve.d,
            &self.curve.n,
            &self.curve.gx,
            &self.curve.gy,
            &self.q.x,
            &self.q.y,
        ])
    }

    /// Decode from the crate-defined binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let qx = fields.next()?;
        let qy = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        let q = EdwardsPoint::new(qx, qy);
        if !validate_public_point(&curve, &q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_DH_PUBLIC_LABEL, &self.to_key_blob())
    }

    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_DH_PUBLIC_LABEL, pem)?;
        Self::from_key_blob(&blob)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "EdwardsDhPublicKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("d", &self.curve.d),
                ("n", &self.curve.n),
                ("gx", &self.curve.gx),
                ("gy", &self.curve.gy),
                ("qx", &self.q.x),
                ("qy", &self.q.y),
            ],
        )
    }

    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EdwardsDhPublicKey",
            &["p", "a", "d", "n", "gx", "gy", "qx", "qy"],
            xml,
        )?
        .into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let qx = fields.next()?;
        let qy = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        let q = EdwardsPoint::new(qx, qy);
        if !validate_public_point(&curve, &q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
    }
}

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

    /// Compute the shared point and return its compressed Edwards encoding.
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
        if shared.is_neutral() {
            return None;
        }
        Some(self.curve.encode_point(&shared))
    }

    /// Encode in the crate-defined binary format: `[p, a, d, n, Gx, Gy, d_scalar]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[
            &self.curve.p,
            &self.curve.a,
            &self.curve.d,
            &self.curve.n,
            &self.curve.gx,
            &self.curve.gy,
            &self.d,
        ])
    }

    /// Decode from the crate-defined binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let d = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        let q = curve.scalar_mul_base(&d);
        Some(Self { curve, d, q })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_DH_PRIVATE_LABEL, &self.to_key_blob())
    }

    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_DH_PRIVATE_LABEL, pem)?;
        Self::from_key_blob(&blob)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "EdwardsDhPrivateKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("d", &self.curve.d),
                ("n", &self.curve.n),
                ("gx", &self.curve.gx),
                ("gy", &self.curve.gy),
                ("scalar", &self.d),
            ],
        )
    }

    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EdwardsDhPrivateKey",
            &["p", "a", "d", "n", "gx", "gy", "scalar"],
            xml,
        )?
        .into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let d = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        let q = curve.scalar_mul_base(&d);
        Some(Self { curve, d, q })
    }
}

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

fn validate_public_point(curve: &TwistedEdwardsCurve, point: &EdwardsPoint) -> bool {
    !point.is_neutral()
        && curve.is_on_curve(point)
        && curve.scalar_mul(point, &curve.n).is_neutral()
}

#[cfg(test)]
mod tests {
    use super::{EdwardsDh, EdwardsDhPrivateKey, EdwardsDhPublicKey};
    use crate::public_key::ec_edwards::ed25519;
    use crate::vt::BigUint;
    use crate::CtrDrbgAes256;

    fn decode_hex(hex: &str) -> Vec<u8> {
        let bytes = hex.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            let hi = (chunk[0] as char).to_digit(16).expect("hex") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

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

    #[test]
    fn agreement_fixture_matches_known_ed25519_encoding() {
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
}
