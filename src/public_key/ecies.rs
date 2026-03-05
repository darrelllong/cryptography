//! Elliptic Curve Integrated Encryption Scheme (ECIES).
//!
//! ECIES is the standard EC public-key encryption scheme for arbitrary-length
//! byte messages.  It uses ephemeral ECDH for key agreement and AES-256-GCM
//! for authenticated symmetric encryption, giving confidentiality, integrity,
//! and authenticity in a single pass.
//!
//! ## Algorithm
//!
//! **Encryption** (sender has recipient's public key `Q`):
//! 1. Sample ephemeral scalar `k ∈ [1, n)` and compute `R = k·G`.
//! 2. Compute shared point `S = k·Q`.
//! 3. Derive AES-256 key:   `key   = SHA-256([0x01] ‖ S.x)` (32 bytes).
//! 4. Derive GCM nonce:     `nonce = SHA-256([0x02] ‖ S.x)[0..12]`.
//! 5. Encrypt message with AES-256-GCM; use `R_bytes` as AAD.
//! 6. Output: `R_bytes ‖ ciphertext ‖ tag`.
//!
//! **Decryption** (recipient has private scalar `d`):
//! 1. Parse `R_bytes` from ciphertext, decode into point `R`.
//! 2. Compute shared point `S = d·R`.
//! 3. Re-derive `key` and `nonce` from `S.x`.
//! 4. Verify GCM tag and decrypt.
//!
//! The KDF output is unique for each encryption because `k` is sampled
//! freshly every time; the derived key never repeats.
//!
//! ## Wire format
//!
//! ```text
//! | R (uncompressed, 1 + 2·coord_len bytes) | ciphertext (len(plaintext)) | tag (16 bytes) |
//! ```
//!
//! The minimum ciphertext length is `1 + 2·coord_len + 16` bytes (for an
//! empty plaintext); P-256 gives a minimum of 81 bytes.
//!
//! ## Side-channel note
//!
//! The ECDH scalar multiplication is not constant-time; see [`ec`].
//!
//! [`ec`]: crate::public_key::ec

use core::fmt;

use crate::ciphers::aes::Aes256;
use crate::hash::sha2::Sha256;
use crate::modes::Gcm;
use crate::public_key::bigint::BigUint;
use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::Csprng;

const ECIES_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ECIES PUBLIC KEY";
const ECIES_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ECIES PRIVATE KEY";

// ─── Types ───────────────────────────────────────────────────────────────────

/// Public key for ECIES.
#[derive(Clone, Debug)]
pub struct EciesPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for ECIES.
#[derive(Clone)]
pub struct EciesPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

pub struct Ecies;

// ─── EciesPublicKey ───────────────────────────────────────────────────────────

impl EciesPublicKey {
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

    /// Encode the public point as a compact SEC 1 point string.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Rebuild a public key from a compact SEC 1 point string plus explicit curve parameters.
    #[must_use]
    pub fn from_bytes(curve: CurveParams, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        Some(Self { curve, q })
    }

    /// Encrypt `message` for the holder of the matching private key.
    ///
    /// Generates a fresh ephemeral key pair on each call.  The returned bytes
    /// follow the wire format described in the module documentation.
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Vec<u8> {
        loop {
            // Fresh ephemeral keypair.
            let (k, r) = self.curve.generate_keypair(rng);
            let r_bytes = self.curve.encode_point(&r); // 1 + 2·coord_len bytes

            // Shared point S = k·Q.
            let s = self.curve.diffie_hellman(&k, &self.q);
            if s.is_infinity() {
                // Negligible: retry with a different k.
                continue;
            }
            let sx = pad_coord(&s.x.to_be_bytes(), self.curve.coord_len);

            // KDF: key = SHA-256(0x01 || S.x), nonce = SHA-256(0x02 || S.x)[0..12].
            let key = kdf_key(&sx);
            let nonce = kdf_nonce(&sx);

            // AES-256-GCM: encrypt in-place, AAD = R_bytes.
            let gcm = Gcm::new(Aes256::new(&key));
            let mut ciphertext = message.to_vec();
            let tag = gcm.encrypt(&nonce, &r_bytes, &mut ciphertext);

            // Wire: R_bytes || ciphertext || tag.
            let mut out = r_bytes;
            out.extend_from_slice(&ciphertext);
            out.extend_from_slice(&tag);
            return out;
        }
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode in binary format: field-type byte then `[p, a, b, n, h, Gx, Gy, Qx, Qy]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
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
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
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
        pem_wrap(ECIES_PUBLIC_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_binary(&pem_unwrap(ECIES_PUBLIC_LABEL, pem)?)
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
            "EciesPublicKey",
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
            "EciesPublicKey",
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

// ─── EciesPrivateKey ──────────────────────────────────────────────────────────

impl EciesPrivateKey {
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
    pub fn to_public_key(&self) -> EciesPublicKey {
        EciesPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Decrypt a ciphertext produced by [`EciesPublicKey::encrypt`].
    ///
    /// Returns `None` if the ciphertext is malformed or the authentication
    /// tag does not verify.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Minimum length: 1 (tag byte) + 2·coord_len (x, y) + 16 (GCM tag).
        let r_len = 1 + 2 * self.curve.coord_len;
        let min_len = r_len + 16;
        if ciphertext.len() < min_len {
            return None;
        }

        let r_bytes = &ciphertext[..r_len];
        let body = &ciphertext[r_len..];
        let (ct, tag) = body.split_at(body.len() - 16);

        // Parse R and validate it's on the curve.
        let r = self.curve.decode_point(r_bytes)?;

        // Shared point S = d·R.
        let s = self.curve.diffie_hellman(&self.d, &r);
        if s.is_infinity() {
            return None;
        }
        let sx = pad_coord(&s.x.to_be_bytes(), self.curve.coord_len);

        // Re-derive key and nonce.
        let key = kdf_key(&sx);
        let nonce = kdf_nonce(&sx);

        // AES-256-GCM decrypt; AAD = r_bytes.
        let gcm = Gcm::new(Aes256::new(&key));
        let mut plaintext = ct.to_vec();
        if gcm.decrypt(&nonce, r_bytes, &mut plaintext, tag) {
            Some(plaintext)
        } else {
            None
        }
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode in binary format: field-type byte then `[p, a, b, n, h, Gx, Gy, d]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
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
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
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
        pem_wrap(ECIES_PRIVATE_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_binary(&pem_unwrap(ECIES_PRIVATE_LABEL, pem)?)
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
            "EciesPrivateKey",
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
            "EciesPrivateKey",
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

impl fmt::Debug for EciesPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EciesPrivateKey(<redacted>)")
    }
}

// ─── Ecies namespace ──────────────────────────────────────────────────────────

impl Ecies {
    /// Generate a random ECIES key pair on `curve`.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: CurveParams,
        rng: &mut R,
    ) -> (EciesPublicKey, EciesPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        (
            EciesPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EciesPrivateKey { curve, d, q },
        )
    }
}

// ─── KDF helpers ─────────────────────────────────────────────────────────────

/// Derive the AES-256 key from the shared-point x-coordinate.
///
/// The leading `0x01` byte is a domain-separation constant.  It ensures the
/// key bytes are independent of the nonce bytes even though both are SHA-256
/// outputs over the same shared secret: `kdf_key(s) ≠ kdf_nonce(s)` always.
fn kdf_key(sx: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + sx.len());
    input.push(0x01u8);
    input.extend_from_slice(sx);
    Sha256::digest(&input)
}

/// Derive the 12-byte GCM nonce from the shared-point x-coordinate.
///
/// The leading `0x02` byte distinguishes this from [`kdf_key`] (which uses
/// `0x01`), preventing the first 12 bytes of the key from coinciding with the
/// nonce when the shared secret happens to repeat across sessions.
fn kdf_nonce(sx: &[u8]) -> [u8; 12] {
    let mut input = Vec::with_capacity(1 + sx.len());
    input.push(0x02u8);
    input.extend_from_slice(sx);
    let digest = Sha256::digest(&input);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

/// Zero-pad a field-element byte slice to exactly `coord_len` bytes.
///
/// `BigUint::to_be_bytes` strips leading zeros, so the x-coordinate of a point
/// whose high bytes are zero can be shorter than `coord_len`.  The KDF must
/// receive a fixed-length input: without padding, two different ephemeral keys
/// that share the same non-zero suffix would produce the same KDF input.
fn pad_coord(bytes: &[u8], coord_len: usize) -> Vec<u8> {
    if bytes.len() >= coord_len {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; coord_len - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

/// Convert a small `BigUint` (≤ 8 bytes) to a `u64`.
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
    use super::{Ecies, EciesPrivateKey, EciesPublicKey};
    use crate::public_key::ec::{p256, p384, p521, secp256k1};
    use crate::CtrDrbgAes256;

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0xef; 48])
    }

    // ── Basic encrypt / decrypt round trips ───────────────────────────────────

    #[test]
    fn roundtrip_empty_message_p256() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let ct = public.encrypt(&[], &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, b"");
    }

    #[test]
    fn roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let msg = b"hello ECIES world";
        let ct = public.encrypt(msg, &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn roundtrip_p384() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p384(), &mut rng);
        let msg = b"p384 ecies test message with more bytes";
        let ct = public.encrypt(msg, &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn roundtrip_secp256k1() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(secp256k1(), &mut rng);
        let msg = b"secp256k1 ecies test";
        let ct = public.encrypt(msg, &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn roundtrip_p521() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p521(), &mut rng);
        let msg = b"p521 ecies with a longer message to check padding";
        let ct = public.encrypt(msg, &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn roundtrip_large_message() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let msg = vec![0x42u8; 1024];
        let ct = public.encrypt(&msg, &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    // ── Freshness: same message gives different ciphertext ────────────────────

    #[test]
    fn encrypt_is_randomized() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let msg = b"same message";
        let ct1 = public.encrypt(msg, &mut rng);
        let ct2 = public.encrypt(msg, &mut rng);
        assert_ne!(ct1, ct2);
    }

    // ── Rejection tests ───────────────────────────────────────────────────────

    #[test]
    fn wrong_key_rejected() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let (_, private2) = Ecies::generate(p256(), &mut rng);
        let ct = public.encrypt(b"secret", &mut rng);
        assert!(private2.decrypt(&ct).is_none());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let mut ct = public.encrypt(b"tamper me", &mut rng);
        // Flip a bit in the ciphertext body (not the R prefix).
        let flip_pos = ct.len() / 2;
        ct[flip_pos] ^= 0x01;
        assert!(private.decrypt(&ct).is_none());
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let ct = public.encrypt(b"truncate", &mut rng);
        assert!(private.decrypt(&ct[..ct.len() - 1]).is_none());
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_matches() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.q, public.q);
        // Encrypt with derived public key, decrypt with original private key.
        let ct = derived.encrypt(b"derived key test", &mut rng);
        let pt = private.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, b"derived key test");
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let blob = public.to_binary();
        let recovered = EciesPublicKey::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let bytes = public.to_bytes();
        let recovered = EciesPublicKey::from_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(p256(), &mut rng);
        let blob = private.to_binary();
        let recovered = EciesPrivateKey::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECIES PUBLIC KEY"));
        let recovered = EciesPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECIES PRIVATE KEY"));
        let recovered = EciesPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EciesPublicKey"));
        let recovered = EciesPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        let recovered = EciesPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn debug_private_key_redacted() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(p256(), &mut rng);
        assert_eq!(format!("{private:?}"), "EciesPrivateKey(<redacted>)");
    }
}
