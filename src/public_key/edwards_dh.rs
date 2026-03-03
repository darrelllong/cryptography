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
use crate::public_key::ec_edwards::{EdwardsPoint, TwistedEdwardsCurve};
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
}

/// Private key for Edwards-curve Diffie-Hellman.
#[derive(Clone)]
pub struct EdwardsDhPrivateKey {
    curve: TwistedEdwardsCurve,
    d: BigUint,
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
    pub fn to_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Decode a public key from the compressed Edwards point form.
    #[must_use]
    pub fn from_bytes(curve: TwistedEdwardsCurve, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !validate_public_point(&curve, &q) {
            return None;
        }
        Some(Self { curve, q })
    }

    /// Encode in the crate-defined binary format: `[p, a, d, n, Gx, Gy, Qx, Qy]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
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
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
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
        Some(Self { curve, q })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_DH_PUBLIC_LABEL, &self.to_binary())
    }

    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_DH_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
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
        Some(Self { curve, q })
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
        let q = self.curve.scalar_mul(&self.curve.base_point(), &self.d);
        EdwardsDhPublicKey {
            curve: self.curve.clone(),
            q,
        }
    }

    /// Compute the shared point and return its compressed Edwards encoding.
    ///
    /// Returning the encoded point keeps the wrapper purely in Edwards form;
    /// callers should pass the bytes through a KDF before using them as key
    /// material.
    #[must_use]
    pub fn agree(&self, peer: &EdwardsDhPublicKey) -> Option<Vec<u8>> {
        if !same_curve(&self.curve, &peer.curve) {
            return None;
        }
        let shared = self.curve.diffie_hellman(&self.d, &peer.q);
        if shared.is_neutral() {
            return None;
        }
        Some(self.curve.encode_point(&shared))
    }

    /// Encode in the crate-defined binary format: `[p, a, d, n, Gx, Gy, d_scalar]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
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
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
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
        Some(Self { curve, d })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_DH_PRIVATE_LABEL, &self.to_binary())
    }

    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_DH_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
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
        Some(Self { curve, d })
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
        let q = curve.scalar_mul(&curve.base_point(), &d);
        (
            EdwardsDhPublicKey {
                curve: curve.clone(),
                q,
            },
            EdwardsDhPrivateKey { curve, d },
        )
    }
}

fn validate_public_point(curve: &TwistedEdwardsCurve, point: &EdwardsPoint) -> bool {
    !point.is_neutral() && curve.is_on_curve(point) && curve.scalar_mul(point, &curve.n).is_neutral()
}

fn same_curve(lhs: &TwistedEdwardsCurve, rhs: &TwistedEdwardsCurve) -> bool {
    lhs.p == rhs.p
        && lhs.a == rhs.a
        && lhs.d == rhs.d
        && lhs.n == rhs.n
        && lhs.gx == rhs.gx
        && lhs.gy == rhs.gy
}

#[cfg(test)]
mod tests {
    use super::{EdwardsDh, EdwardsDhPrivateKey, EdwardsDhPublicKey};
    use crate::public_key::ec_edwards::ed25519;
    use crate::CtrDrbgAes256;

    fn rng(seed: u8) -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[seed; 48])
    }

    #[test]
    fn agreement_roundtrip_ed25519() {
        let (pub_a, priv_a) = EdwardsDh::generate(ed25519(), &mut rng(0x11));
        let (pub_b, priv_b) = EdwardsDh::generate(ed25519(), &mut rng(0x22));
        let shared_a = priv_a.agree(&pub_b).expect("shared a");
        let shared_b = priv_b.agree(&pub_a).expect("shared b");
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn public_serialization_roundtrip() {
        let (public, _) = EdwardsDh::generate(ed25519(), &mut rng(0x33));
        let bin = public.to_binary();
        let pem = public.to_pem();
        let xml = public.to_xml();
        let round_bin = EdwardsDhPublicKey::from_binary(&bin).expect("bin");
        let round_pem = EdwardsDhPublicKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsDhPublicKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_binary(), public.to_binary());
        assert_eq!(round_pem.to_binary(), public.to_binary());
        assert_eq!(round_xml.to_binary(), public.to_binary());
    }

    #[test]
    fn private_serialization_roundtrip() {
        let (_, private) = EdwardsDh::generate(ed25519(), &mut rng(0x44));
        let bin = private.to_binary();
        let pem = private.to_pem();
        let xml = private.to_xml();
        let round_bin = EdwardsDhPrivateKey::from_binary(&bin).expect("bin");
        let round_pem = EdwardsDhPrivateKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsDhPrivateKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_binary(), private.to_binary());
        assert_eq!(round_pem.to_binary(), private.to_binary());
        assert_eq!(round_xml.to_binary(), private.to_binary());
    }

    #[test]
    fn debug_redacts_private_key() {
        let (_, private) = EdwardsDh::generate(ed25519(), &mut rng(0x55));
        assert_eq!(format!("{private:?}"), "EdwardsDhPrivateKey(<redacted>)");
    }
}
