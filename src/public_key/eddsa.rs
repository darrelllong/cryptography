//! Edwards-curve Digital Signature Algorithm style signatures.
//!
//! This module builds a Schnorr/EdDSA-style signature layer on top of the
//! existing twisted Edwards arithmetic in [`ec_edwards`].  The signing
//! equation follows the standard Edwards pattern:
//!
//! - choose a nonce scalar `k`
//! - compute `R = k·G`
//! - hash `R || A || M` to a scalar challenge `e`
//! - return `S = k + e·d mod n`
//!
//! Verification checks `S·G = R + e·A`.
//!
//! This is intentionally *not* a byte-for-byte RFC 8032 Ed25519 clone: the
//! key type stores the scalar directly instead of the RFC's hashed/clamped
//! secret-key seed format.  The point arithmetic and point encoding still use
//! the Edwards machinery in [`ec_edwards`], so the module is suitable for the
//! crate's "pure Rust, explicit arithmetic" design.
//!
//! [`ec_edwards`]: crate::public_key::ec_edwards

use core::fmt;

use crate::hash::Digest;
use crate::public_key::bigint::BigUint;
use crate::public_key::ec_edwards::{EdwardsMulTable, EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::Csprng;

const EDDSA_PUBLIC_LABEL: &str = "CRYPTOGRAPHY EDDSA PUBLIC KEY";
const EDDSA_PRIVATE_LABEL: &str = "CRYPTOGRAPHY EDDSA PRIVATE KEY";

/// Public key for the Edwards-curve signature layer.
#[derive(Clone, Debug)]
pub struct EdDsaPublicKey {
    /// Edwards curve parameters.
    curve: TwistedEdwardsCurve,
    /// Public point `A = d·G`.
    a_point: EdwardsPoint,
    /// Cached precompute table for repeated `k·A` verification work.
    a_table: EdwardsMulTable,
}

/// Private key for the Edwards-curve signature layer.
#[derive(Clone)]
pub struct EdDsaPrivateKey {
    /// Edwards curve parameters.
    curve: TwistedEdwardsCurve,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `A = d·G`.
    ///
    /// Signing hashes `R || A || M`, so caching `A` avoids a full scalar
    /// multiplication on every signature.
    a_point: EdwardsPoint,
}

/// Signature pair `(R, S)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdDsaSignature {
    /// Nonce point `R = k·G`.
    r_point: EdwardsPoint,
    /// Response scalar `S = k + e·d mod n`.
    s: BigUint,
}

/// Namespace wrapper for the Edwards-curve signature construction.
pub struct EdDsa;

impl PartialEq for EdDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.curve.same_curve(&other.curve) && self.a_point == other.a_point
    }
}

impl Eq for EdDsaPublicKey {}

impl PartialEq for EdDsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.curve.same_curve(&other.curve) && self.d == other.d
    }
}

impl Eq for EdDsaPrivateKey {}

impl EdDsaPublicKey {
    /// Return the curve parameters.
    #[must_use]
    pub fn curve(&self) -> &TwistedEdwardsCurve {
        &self.curve
    }

    /// Return the public point `A = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &EdwardsPoint {
        &self.a_point
    }

    /// Encode just the public point using the curve's compressed Edwards form.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.a_point)
    }

    /// Rebuild a public key from a compressed Edwards point plus explicit curve parameters.
    #[must_use]
    pub fn from_wire_bytes(curve: TwistedEdwardsCurve, bytes: &[u8]) -> Option<Self> {
        let a_point = curve.decode_point(bytes)?;
        if !validate_public_point(&curve, &a_point) {
            return None;
        }
        let a_table = curve.precompute_mul_table(&a_point);
        Some(Self {
            curve,
            a_point,
            a_table,
        })
    }

    /// Verify a signature over a raw message byte string.
    #[must_use]
    pub fn verify_message<H: Digest>(&self, message: &[u8], signature: &EdDsaSignature) -> bool {
        if signature.s.is_zero() || signature.s >= self.curve.n {
            return false;
        }
        if signature.r_point.is_neutral()
            || !self.curve.is_on_curve(&signature.r_point)
            || !point_in_prime_subgroup(&self.curve, &signature.r_point)
        {
            return false;
        }

        let challenge =
            challenge_scalar::<H>(&self.curve, &signature.r_point, &self.a_point, message);

        let lhs = self.curve.scalar_mul_base(&signature.s);
        let rhs = self.curve.add(
            &signature.r_point,
            &self.curve.scalar_mul_cached(&self.a_table, &challenge),
        );
        lhs == rhs
    }

    /// Verify a byte-encoded signature produced by [`EdDsaPrivateKey::sign_message_bytes`].
    #[must_use]
    pub fn verify_message_bytes<H: Digest>(&self, message: &[u8], signature: &[u8]) -> bool {
        let Some(signature) = EdDsaSignature::from_key_blob(signature, &self.curve) else {
            return false;
        };
        self.verify_message::<H>(message, &signature)
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
            self.a_point.x.clone(),
            self.a_point.y.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let ax = fields.next()?;
        let ay = fields.next()?;
        let curve = TwistedEdwardsCurve::new(p, a, d, n, gx, gy)?;
        // Reject non-canonical coordinates: is_on_curve reduces mod p, so a
        // coordinate of p+k passes the curve equation.  Enforce ax, ay < p.
        if ax >= curve.p || ay >= curve.p {
            return None;
        }
        let a_point = EdwardsPoint::new(ax, ay);
        if !validate_public_point(&curve, &a_point) {
            return None;
        }
        let a_table = curve.precompute_mul_table(&a_point);
        Some(Self {
            curve,
            a_point,
            a_table,
        })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EdDsaPublicKey,
    "EdDsaPublicKey",
    ["p", "a", "d", "n", "gx", "gy", "ax", "ay"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EdDsaPublicKey,
    EDDSA_PUBLIC_LABEL,
    ["p", "a", "d", "n", "gx", "gy", "ax", "ay"]
);

impl EdDsaPrivateKey {
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

    /// Return the cached public point `A = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &EdwardsPoint {
        &self.a_point
    }

    /// Derive the matching public key `A = d·G`.
    #[must_use]
    pub fn to_public_key(&self) -> EdDsaPublicKey {
        EdDsaPublicKey {
            curve: self.curve.clone(),
            a_point: self.a_point.clone(),
            a_table: self.curve.precompute_mul_table(&self.a_point),
        }
    }

    /// Sign with an explicit nonce scalar `k`.
    ///
    /// Reusing the same nonce with the same private key leaks the secret
    /// scalar from two signatures, so this entry point is for deterministic
    /// tests and fixed vectors only.
    #[must_use]
    pub fn sign_message_with_nonce<H: Digest>(
        &self,
        message: &[u8],
        nonce: &BigUint,
    ) -> Option<EdDsaSignature> {
        if nonce.is_zero() || nonce >= &self.curve.n {
            return None;
        }

        let r_point = self.curve.scalar_mul_base(nonce);
        if r_point.is_neutral() {
            return None;
        }
        let challenge = challenge_scalar::<H>(&self.curve, &r_point, &self.a_point, message);
        let ed = BigUint::mod_mul(&challenge, &self.d, &self.curve.n);
        let s = nonce.add_ref(&ed).modulo(&self.curve.n);
        Some(EdDsaSignature { r_point, s })
    }

    /// Sign using a fresh random nonce.
    #[must_use]
    pub fn sign_message<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<EdDsaSignature> {
        loop {
            let nonce = self.curve.random_scalar(rng);
            if let Some(signature) = self.sign_message_with_nonce::<H>(message, &nonce) {
                return Some(signature);
            }
        }
    }

    /// Sign and serialize in one step.
    #[must_use]
    pub fn sign_message_bytes<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let signature = self.sign_message::<H, R>(message, rng)?;
        Some(signature.to_key_blob())
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
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        let a_point = curve.scalar_mul_base(&d);
        Some(Self { curve, d, a_point })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EdDsaPrivateKey,
    "EdDsaPrivateKey",
    ["p", "a", "d", "n", "gx", "gy", "private"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EdDsaPrivateKey,
    EDDSA_PRIVATE_LABEL,
    ["p", "a", "d", "n", "gx", "gy", "private"]
);

impl fmt::Debug for EdDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EdDsaPrivateKey(<redacted>)")
    }
}

impl EdDsaSignature {
    /// Return the nonce point `R`.
    #[must_use]
    pub fn nonce_point(&self) -> &EdwardsPoint {
        &self.r_point
    }

    /// Return the response scalar `S`.
    #[must_use]
    pub fn response(&self) -> &BigUint {
        &self.s
    }

    /// Encode the signature in the crate-defined binary format.
    ///
    /// Field layout: `[Rx, Ry, S]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.r_point.x, &self.r_point.y, &self.s])
    }

    /// Decode a signature from the crate-defined binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8], curve: &TwistedEdwardsCurve) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let rx = fields.next()?;
        let ry = fields.next()?;
        let s = fields.next()?;
        if fields.next().is_some() || s.is_zero() || s >= curve.n {
            return None;
        }
        // Reject non-canonical coordinates: is_on_curve reduces mod p internally
        // so a coordinate of p+k passes the curve equation, but the stored
        // point would have non-canonical field representatives.  The wire-bytes
        // path already enforces y < p; enforce the same here.
        if rx >= curve.p || ry >= curve.p {
            return None;
        }
        let r_point = EdwardsPoint::new(rx, ry);
        if !curve.is_on_curve(&r_point) {
            return None;
        }
        Some(Self { r_point, s })
    }
}

impl EdDsa {
    /// Generate a random key pair `(public, private)` for the chosen curve.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: TwistedEdwardsCurve,
        rng: &mut R,
    ) -> (EdDsaPublicKey, EdDsaPrivateKey) {
        let (d, a_point) = curve.generate_keypair(rng);
        let public = EdDsaPublicKey {
            curve: curve.clone(),
            a_point: a_point.clone(),
            a_table: curve.precompute_mul_table(&a_point),
        };
        let private = EdDsaPrivateKey { curve, d, a_point };
        (public, private)
    }

    /// Derive a key pair from an explicit secret scalar.
    #[must_use]
    pub fn from_secret_scalar(
        curve: TwistedEdwardsCurve,
        secret: &BigUint,
    ) -> Option<(EdDsaPublicKey, EdDsaPrivateKey)> {
        if secret.is_zero() || secret >= &curve.n {
            return None;
        }
        let a_point = curve.scalar_mul_base(secret);
        if !validate_public_point(&curve, &a_point) {
            return None;
        }
        Some((
            EdDsaPublicKey {
                curve: curve.clone(),
                a_point: a_point.clone(),
                a_table: curve.precompute_mul_table(&a_point),
            },
            EdDsaPrivateKey {
                curve,
                d: secret.clone(),
                a_point,
            },
        ))
    }
}

/// Verify that a public point is on-curve, in the prime-order subgroup, and non-neutral.
fn validate_public_point(curve: &TwistedEdwardsCurve, point: &EdwardsPoint) -> bool {
    !point.is_neutral() && curve.is_on_curve(point) && point_in_prime_subgroup(curve, point)
}

/// Check subgroup membership by verifying `n·P = 0`.
fn point_in_prime_subgroup(curve: &TwistedEdwardsCurve, point: &EdwardsPoint) -> bool {
    curve.scalar_mul(point, &curve.n).is_neutral()
}

/// Compute the EdDSA-style challenge scalar `e = H(encode(R) || encode(A) || M) mod n`.
fn challenge_scalar<H: Digest>(
    curve: &TwistedEdwardsCurve,
    r_point: &EdwardsPoint,
    a_point: &EdwardsPoint,
    message: &[u8],
) -> BigUint {
    let mut transcript = curve.encode_point(r_point);
    transcript.extend_from_slice(&curve.encode_point(a_point));
    transcript.extend_from_slice(message);
    BigUint::from_be_bytes(&H::digest(&transcript)).modulo(&curve.n)
}

#[cfg(test)]
mod tests {
    use super::{EdDsa, EdDsaPrivateKey, EdDsaPublicKey, EdDsaSignature};
    use crate::public_key::bigint::BigUint;
    use crate::public_key::ec_edwards::ed25519;
    use crate::public_key::io::encode_biguints;
    use crate::{CtrDrbgAes256, Sha512};

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0x5a; 48])
    }

    #[test]
    fn roundtrip_sign_verify_ed25519() {
        let curve = ed25519();
        let (public, private) = EdDsa::generate(curve, &mut rng());
        let sig = private
            .sign_message::<Sha512, _>(b"edwards signature", &mut rng())
            .expect("sign");
        assert!(public.verify_message::<Sha512>(b"edwards signature", &sig));
        assert!(!public.verify_message::<Sha512>(b"wrong", &sig));
    }

    #[test]
    fn sign_with_explicit_nonce_roundtrip() {
        let curve = ed25519();
        let secret = BigUint::from_u64(7);
        let nonce = BigUint::from_u64(11);
        let (public, private) = EdDsa::from_secret_scalar(curve, &secret).expect("explicit secret");
        let sig = private
            .sign_message_with_nonce::<Sha512>(b"abc", &nonce)
            .expect("explicit nonce");
        assert!(public.verify_message::<Sha512>(b"abc", &sig));
    }

    #[test]
    fn sign_message_with_nonce_is_repeatable() {
        let curve = ed25519();
        let secret = BigUint::from_u64(7);
        let nonce = BigUint::from_u64(11);
        let (_public, private) =
            EdDsa::from_secret_scalar(curve, &secret).expect("explicit secret");
        let lhs = private
            .sign_message_with_nonce::<Sha512>(b"abc", &nonce)
            .expect("first signature");
        let rhs = private
            .sign_message_with_nonce::<Sha512>(b"abc", &nonce)
            .expect("second signature");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let curve = ed25519();
        let (public, private) = EdDsa::generate(curve, &mut rng());
        let mut sig = private
            .sign_message::<Sha512, _>(b"tamper", &mut rng())
            .expect("sign");
        sig.s = sig.s.add_ref(&BigUint::one()).modulo(&public.curve().n);
        if sig.s.is_zero() {
            sig.s = BigUint::one();
        }
        assert!(!public.verify_message::<Sha512>(b"tamper", &sig));
    }

    #[test]
    fn key_serialization_roundtrip() {
        let curve = ed25519();
        let (public, private) = EdDsa::generate(curve, &mut rng());

        let public_bin = public.to_key_blob();
        let public_pem = public.to_pem();
        let public_xml = public.to_xml();
        assert_eq!(
            EdDsaPublicKey::from_key_blob(&public_bin).expect("public binary"),
            public
        );
        assert_eq!(
            EdDsaPublicKey::from_pem(&public_pem).expect("public pem"),
            public
        );
        assert_eq!(
            EdDsaPublicKey::from_xml(&public_xml).expect("public xml"),
            public
        );

        let private_bin = private.to_key_blob();
        let private_pem = private.to_pem();
        let private_xml = private.to_xml();
        let private_round = EdDsaPrivateKey::from_key_blob(&private_bin).expect("private binary");
        assert_eq!(private_round, private);
        assert_eq!(private_round.to_public_key(), public);
        assert_eq!(
            EdDsaPrivateKey::from_pem(&private_pem).expect("private pem"),
            private
        );
        assert_eq!(
            EdDsaPrivateKey::from_xml(&private_xml).expect("private xml"),
            private
        );
    }

    #[test]
    fn public_bytes_roundtrip() {
        let curve = ed25519();
        let (public, _) = EdDsa::generate(curve.clone(), &mut rng());
        let bytes = public.to_wire_bytes();
        let round = EdDsaPublicKey::from_wire_bytes(curve, &bytes).expect("public bytes");
        assert_eq!(round, public);
    }

    #[test]
    fn signature_binary_roundtrip() {
        let curve = ed25519();
        let (public, private) = EdDsa::generate(curve, &mut rng());
        let sig = private
            .sign_message::<Sha512, _>(b"serialize", &mut rng())
            .expect("sign");
        let blob = sig.to_key_blob();
        let decoded = EdDsaSignature::from_key_blob(&blob, public.curve()).expect("decode sig");
        assert_eq!(decoded, sig);
        assert!(public.verify_message::<Sha512>(b"serialize", &decoded));
    }

    #[test]
    fn signature_binary_rejects_out_of_range_s() {
        let curve = ed25519();
        let base = curve.base_point();
        let blob = encode_biguints(&[&base.x, &base.y, &curve.n]);
        assert!(EdDsaSignature::from_key_blob(&blob, &curve).is_none());
    }
}
