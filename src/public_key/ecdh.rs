//! Elliptic-Curve Diffie-Hellman (ECDH) key exchange.
//!
//! ECDH is the standard EC key agreement protocol.  Two parties each hold a
//! static key pair `(d, Q)` with `Q = d·G` on a shared curve.  After
//! exchanging public points, both compute the same shared secret from their
//! own private scalar and the peer's public point:
//!
//! ```text
//! Alice: S = d_A · Q_B = d_A · d_B · G
//! Bob:   S = d_B · Q_A = d_A · d_B · G
//! ```
//!
//! The shared secret returned by [`EcdhPrivateKey::agree`] is the **x-coordinate**
//! of the shared point `S`, zero-padded to `coord_len` bytes (per ANSI X9.63 /
//! SEC 1 v2.0).  Both parties must apply the same KDF to this raw value before
//! using it as a symmetric key.
//!
//! ## Ephemeral vs. static use
//!
//! This module exposes static key pairs for simplicity.  For ephemeral ECDH
//! (where a fresh key pair is generated per session), call
//! [`Ecdh::generate`] per handshake, use [`EcdhPrivateKey::agree`], then
//! discard the ephemeral private key.  ECIES in [`ecies`] combines ephemeral
//! ECDH with symmetric encryption into a self-contained encryption scheme.
//!
//! ## Side-channel note
//!
//! The scalar multiplication is not constant-time; see [`ec`].
//!
//! [`ec`]: crate::public_key::ec
//! [`ecies`]: crate::public_key::ecies

use core::fmt;

use crate::public_key::bigint::BigUint;
use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::Csprng;

const ECDH_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ECDH PUBLIC KEY";
const ECDH_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ECDH PRIVATE KEY";

// ─── Types ───────────────────────────────────────────────────────────────────

/// Public key for ECDH.
///
/// The public key is the curve point `Q = d·G`.  It is exchanged openly with
/// the peer.
#[derive(Clone, Debug)]
pub struct EcdhPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for ECDH.
///
/// The private key is the scalar `d ∈ [1, n)`.  It must remain secret.
#[derive(Clone)]
pub struct EcdhPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

pub struct Ecdh;

// ─── EcdhPublicKey ────────────────────────────────────────────────────────────

impl EcdhPublicKey {
    /// The curve parameters for this key.
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The public point `Q = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &AffinePoint {
        &self.q
    }

    /// Encode the public point as an uncompressed SEC 1 byte string.
    ///
    /// This is the standard wire format for exchanging ECDH public keys.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Decode a public key from an uncompressed or compressed SEC 1 byte string.
    ///
    /// Returns `None` if the encoding is malformed or the point is not on the
    /// curve.
    #[must_use]
    pub fn from_wire_bytes(curve: CurveParams, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        Some(Self { curve, q })
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode in binary format: field-type byte then `[p, a, b, n, h, Gx, Gy, Qx, Qy]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let h = BigUint::from_u64(self.curve.h);
        let field_byte = u8::from(self.curve.gf2m_degree().is_some());
        let mut out = vec![field_byte];
        out.extend_from_slice(&encode_biguints(&[
            &self.curve.p,
            &self.curve.a,
            &self.curve.b,
            &self.curve.n,
            &h,
            &self.curve.gx,
            &self.curve.gy,
            &self.q.x,
            &self.q.y,
        ]));
        out
    }

    /// Decode from binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&field_type, rest) = blob.split_first()?;
        let mut fields = decode_biguints(rest)?.into_iter();
        let field_prime = fields.next()?;
        let curve_a = fields.next()?;
        let curve_b = fields.next()?;
        let subgroup_order = fields.next()?;
        let cofactor_big = fields.next()?;
        let base_x = fields.next()?;
        let base_y = fields.next()?;
        let public_x = fields.next()?;
        let public_y = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let cofactor = biguint_to_u64(&cofactor_big)?;
        let curve = if field_type == 0x01 {
            let field_degree = field_prime.bits().checked_sub(1)?;
            CurveParams::new_binary(
                field_prime,
                field_degree,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                (base_x, base_y),
            )?
        } else {
            CurveParams::new(
                field_prime,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                base_x,
                base_y,
            )?
        };
        let public_point = AffinePoint::new(public_x, public_y);
        if !curve.is_on_curve(&public_point) {
            return None;
        }
        Some(Self {
            curve,
            q: public_point,
        })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ECDH_PUBLIC_LABEL, &self.to_key_blob())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_key_blob(&pem_unwrap(ECDH_PUBLIC_LABEL, pem)?)
    }

    /// # Panics
    ///
    /// Panics only if a binary-field curve reports a degree that does not fit
    /// in `u64`, which would indicate malformed curve parameters.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let h = BigUint::from_u64(self.curve.h);
        let degree = BigUint::from_u64(
            u64::try_from(self.curve.gf2m_degree().unwrap_or(0)).expect("degree fits in u64"),
        );
        xml_wrap(
            "EcdhPublicKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("b", &self.curve.b),
                ("n", &self.curve.n),
                ("h", &h),
                ("degree", &degree),
                ("gx", &self.curve.gx),
                ("gy", &self.curve.gy),
                ("qx", &self.q.x),
                ("qy", &self.q.y),
            ],
        )
    }

    /// Returns `None` if the XML root element, tag names, or integer encoding is invalid.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EcdhPublicKey",
            &["p", "a", "b", "n", "h", "degree", "gx", "gy", "qx", "qy"],
            xml,
        )?
        .into_iter();
        let field_prime = fields.next()?;
        let curve_a = fields.next()?;
        let curve_b = fields.next()?;
        let subgroup_order = fields.next()?;
        let cofactor_big = fields.next()?;
        let degree_big = fields.next()?;
        let base_x = fields.next()?;
        let base_y = fields.next()?;
        let public_x = fields.next()?;
        let public_y = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let cofactor = biguint_to_u64(&cofactor_big)?;
        let field_degree = usize::try_from(biguint_to_u64(&degree_big)?).ok()?;
        let curve = if field_degree > 0 {
            CurveParams::new_binary(
                field_prime,
                field_degree,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                (base_x, base_y),
            )?
        } else {
            CurveParams::new(
                field_prime,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                base_x,
                base_y,
            )?
        };
        let public_point = AffinePoint::new(public_x, public_y);
        if !curve.is_on_curve(&public_point) {
            return None;
        }
        Some(Self {
            curve,
            q: public_point,
        })
    }
}

// ─── EcdhPrivateKey ───────────────────────────────────────────────────────────

impl EcdhPrivateKey {
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The private scalar `d ∈ [1, n)`.
    #[must_use]
    pub fn private_scalar(&self) -> &BigUint {
        &self.d
    }

    /// Derive the matching public key `Q = d·G`.
    #[must_use]
    pub fn to_public_key(&self) -> EcdhPublicKey {
        EcdhPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Perform ECDH key agreement with `peer`.
    ///
    /// Computes `S = d · Q_peer` and returns the x-coordinate of `S`,
    /// zero-padded to `coord_len` bytes (the standard raw shared-secret
    /// representation).
    ///
    /// Returns `None` if the shared point is the point at infinity, which
    /// indicates that `peer.q` is a low-order point — an invalid key or a
    /// small-subgroup attack.
    #[must_use]
    pub fn agree_x_coordinate(&self, peer: &EcdhPublicKey) -> Option<Vec<u8>> {
        let s = self.curve.diffie_hellman(&self.d, &peer.q);
        if s.is_infinity() {
            return None;
        }
        let x_bytes = s.x.to_be_bytes();
        let coord_len = self.curve.coord_len;
        let mut out = vec![0u8; coord_len];
        if x_bytes.len() <= coord_len {
            out[coord_len - x_bytes.len()..].copy_from_slice(&x_bytes);
        } else {
            // x_bytes longer than coord_len can't happen for a valid in-field point,
            // but handle it gracefully by taking the least-significant bytes.
            out.copy_from_slice(&x_bytes[x_bytes.len() - coord_len..]);
        }
        Some(out)
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode in binary format: field-type byte then `[p, a, b, n, h, Gx, Gy, d]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let h = BigUint::from_u64(self.curve.h);
        let field_byte = u8::from(self.curve.gf2m_degree().is_some());
        let mut out = vec![field_byte];
        out.extend_from_slice(&encode_biguints(&[
            &self.curve.p,
            &self.curve.a,
            &self.curve.b,
            &self.curve.n,
            &h,
            &self.curve.gx,
            &self.curve.gy,
            &self.d,
        ]));
        out
    }

    /// Decode from binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&field_type, rest) = blob.split_first()?;
        let mut fields = decode_biguints(rest)?.into_iter();
        let field_prime = fields.next()?;
        let curve_a = fields.next()?;
        let curve_b = fields.next()?;
        let subgroup_order = fields.next()?;
        let cofactor_big = fields.next()?;
        let base_x = fields.next()?;
        let base_y = fields.next()?;
        let private_scalar = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let cofactor = biguint_to_u64(&cofactor_big)?;
        let curve = if field_type == 0x01 {
            let field_degree = field_prime.bits().checked_sub(1)?;
            CurveParams::new_binary(
                field_prime,
                field_degree,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                (base_x, base_y),
            )?
        } else {
            CurveParams::new(
                field_prime,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                base_x,
                base_y,
            )?
        };
        if private_scalar.is_zero() || private_scalar.cmp(&curve.n).is_ge() {
            return None;
        }
        let q = curve.scalar_mul(&curve.base_point(), &private_scalar);
        Some(Self {
            curve,
            d: private_scalar,
            q,
        })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ECDH_PRIVATE_LABEL, &self.to_key_blob())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_key_blob(&pem_unwrap(ECDH_PRIVATE_LABEL, pem)?)
    }

    /// # Panics
    ///
    /// Panics only if a binary-field curve reports a degree that does not fit
    /// in `u64`, which would indicate malformed curve parameters.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let h = BigUint::from_u64(self.curve.h);
        let degree = BigUint::from_u64(
            u64::try_from(self.curve.gf2m_degree().unwrap_or(0)).expect("degree fits in u64"),
        );
        xml_wrap(
            "EcdhPrivateKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("b", &self.curve.b),
                ("n", &self.curve.n),
                ("h", &h),
                ("degree", &degree),
                ("gx", &self.curve.gx),
                ("gy", &self.curve.gy),
                ("d", &self.d),
            ],
        )
    }

    /// Returns `None` if the XML root element, tag names, or integer encoding is invalid.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EcdhPrivateKey",
            &["p", "a", "b", "n", "h", "degree", "gx", "gy", "d"],
            xml,
        )?
        .into_iter();
        let field_prime = fields.next()?;
        let curve_a = fields.next()?;
        let curve_b = fields.next()?;
        let subgroup_order = fields.next()?;
        let cofactor_big = fields.next()?;
        let degree_big = fields.next()?;
        let base_x = fields.next()?;
        let base_y = fields.next()?;
        let private_scalar = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let cofactor = biguint_to_u64(&cofactor_big)?;
        let field_degree = usize::try_from(biguint_to_u64(&degree_big)?).ok()?;
        let curve = if field_degree > 0 {
            CurveParams::new_binary(
                field_prime,
                field_degree,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                (base_x, base_y),
            )?
        } else {
            CurveParams::new(
                field_prime,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                base_x,
                base_y,
            )?
        };
        if private_scalar.is_zero() || private_scalar.cmp(&curve.n).is_ge() {
            return None;
        }
        let q = curve.scalar_mul(&curve.base_point(), &private_scalar);
        Some(Self {
            curve,
            d: private_scalar,
            q,
        })
    }
}

impl fmt::Debug for EcdhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdhPrivateKey(<redacted>)")
    }
}

// ─── Ecdh namespace ───────────────────────────────────────────────────────────

impl Ecdh {
    /// Generate a random ECDH key pair on `curve`.
    #[must_use]
    pub fn generate<R: Csprng>(curve: CurveParams, rng: &mut R) -> (EcdhPublicKey, EcdhPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        (
            EcdhPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EcdhPrivateKey { curve, d, q },
        )
    }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Convert a small `BigUint` (≤ 8 bytes) to `u64`.
///
/// Used to decode the cofactor `h` from serialized key material; returns `None`
/// if the value is too large, indicating a malformed key.
fn biguint_to_u64(value: &BigUint) -> Option<u64> {
    let bytes = value.to_be_bytes();
    if bytes.len() > 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr[8 - bytes.len()..].copy_from_slice(&bytes);
    Some(u64::from_be_bytes(arr))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{Ecdh, EcdhPrivateKey, EcdhPublicKey};
    use crate::public_key::ec::{p256, p384, p521, secp256k1};
    use crate::CtrDrbgAes256;

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0x77; 48])
    }

    // ── Agreement ─────────────────────────────────────────────────────────────

    #[test]
    fn agreement_p256() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(p256(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(p256(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32); // P-256 coord_len
    }

    #[test]
    fn agreement_p384() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(p384(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(p384(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 48); // P-384 coord_len
    }

    #[test]
    fn agreement_secp256k1() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(secp256k1(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(secp256k1(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn agreement_p521() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(p521(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(p521(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 66); // P-521 coord_len
    }

    #[test]
    fn different_keys_give_different_secrets() {
        let mut rng = rng();
        let (_pub_a, priv_a) = Ecdh::generate(p256(), &mut rng);
        let (pub_b, _) = Ecdh::generate(p256(), &mut rng);
        let (pub_c, _) = Ecdh::generate(p256(), &mut rng);
        let s1 = priv_a.agree_x_coordinate(&pub_b).expect("agree with B");
        let s2 = priv_a.agree_x_coordinate(&pub_c).expect("agree with C");
        assert_ne!(s1, s2);
    }

    // ── to_bytes / from_bytes ────────────────────────────────────────────────

    #[test]
    fn to_bytes_from_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(p256(), &mut rng);
        let bytes = public.to_wire_bytes();
        assert_eq!(bytes[0], 0x04); // uncompressed prefix
        let recovered = EcdhPublicKey::from_wire_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_consistent() {
        let mut rng = rng();
        let (public, private) = Ecdh::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.q, public.q);
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(p256(), &mut rng);
        let blob = public.to_key_blob();
        let recovered = EcdhPublicKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(p256(), &mut rng);
        let blob = private.to_key_blob();
        let recovered = EcdhPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDH PUBLIC KEY"));
        let recovered = EcdhPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDH PRIVATE KEY"));
        let recovered = EcdhPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EcdhPublicKey"));
        let recovered = EcdhPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        let recovered = EcdhPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn debug_private_key_redacted() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(p256(), &mut rng);
        assert_eq!(format!("{private:?}"), "EcdhPrivateKey(<redacted>)");
    }
}
