//! Elliptic-Curve Digital Signature Algorithm (ECDSA, FIPS 186-5).
//!
//! ECDSA is the elliptic-curve analogue of DSA: rather than computing scalar
//! multiplications in a prime subgroup of `Z_p^*`, it uses the group of points
//! on a short-Weierstrass elliptic curve and produces the same `(r, s)`
//! signature shape.
//!
//! ## Algorithm summary
//!
//! **Key generation**: Choose a named curve with generator `G` and prime order
//! `n`.  Sample a uniform random scalar `d ∈ [1, n)` and set `Q = d·G`.
//! The public key is `(curve, Q)`; the private key is `(curve, d)`.
//!
//! **Signing** (given message digest representative `z` and nonce `k ∈ [1, n)`):
//! 1. Compute `(x₁, y₁) = k·G`.
//! 2. Set `r = x₁ mod n`.  If `r = 0`, retry with a new `k`.
//! 3. Set `s = k⁻¹ · (z + r·d) mod n`.  If `s = 0`, retry.
//!
//! **Verification** (given public key `Q`, representative `z`, signature `(r, s)`):
//! 1. Check `r, s ∈ [1, n)`.
//! 2. Compute `w = s⁻¹ mod n`, `u₁ = z·w mod n`, `u₂ = r·w mod n`.
//! 3. Compute `(x₁, y₁) = u₁·G + u₂·Q`.
//! 4. Accept if and only if `r ≡ x₁ (mod n)`.
//!
//! ## Side-channel note
//!
//! The scalar multiplication in [`ec`] is not constant-time (left-to-right
//! double-and-add, branching on secret bits).  This implementation is
//! suitable for educational and experimental use.  Replace the scalar-mul
//! loop with a Montgomery ladder before deploying in an environment with
//! side-channel adversaries.
//!
//! [`ec`]: crate::public_key::ec

use core::fmt;

use crate::hash::Digest;
use crate::public_key::bigint::BigUint;
use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{mod_inverse, random_nonzero_below};
use crate::Csprng;

const ECDSA_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ECDSA PUBLIC KEY";
const ECDSA_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ECDSA PRIVATE KEY";

// ─── Key and signature types ─────────────────────────────────────────────────

/// Public key for ECDSA.
///
/// Stores the curve parameters and the public point `Q = d·G`.
#[derive(Clone, Debug)]
pub struct EcdsaPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for ECDSA.
///
/// Stores the curve parameters and the secret scalar `d ∈ [1, n)`.
/// The matching public key is derived on demand via [`to_public_key`].
///
/// [`to_public_key`]: EcdsaPrivateKey::to_public_key
#[derive(Clone)]
pub struct EcdsaPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

/// Raw ECDSA signature pair `(r, s)`.
///
/// Both components are positive integers in `[1, n)` relative to the subgroup
/// order of the signing curve.  The serialized form is a DER `SEQUENCE` of
/// two `INTEGER` values, matching the shape used by [`DsaSignature`].
///
/// [`DsaSignature`]: crate::public_key::dsa::DsaSignature
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcdsaSignature {
    r: BigUint,
    s: BigUint,
}

pub struct Ecdsa;

// ─── EcdsaPublicKey ───────────────────────────────────────────────────────────

impl EcdsaPublicKey {
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

    /// Convenience: hashes `message` with `H` then calls [`verify`][Self::verify].
    #[must_use]
    pub fn verify_message<H: Digest>(&self, message: &[u8], signature: &EcdsaSignature) -> bool {
        let digest = H::digest(message);
        self.verify(&digest, signature)
    }

    /// Convenience: hashes `message` with `H` then calls [`verify_bytes`][Self::verify_bytes].
    #[must_use]
    pub fn verify_message_bytes<H: Digest>(&self, message: &[u8], signature: &[u8]) -> bool {
        let digest = H::digest(message);
        self.verify_bytes(&digest, signature)
    }

    /// Verify `signature` over a raw digest byte string.
    ///
    /// The digest is reduced to a scalar representative matching FIPS 186-5
    /// (leftmost `bits(n)` bits of the hash output).
    #[must_use]
    pub fn verify(&self, digest: &[u8], signature: &EcdsaSignature) -> bool {
        let z = digest_to_scalar(digest, &self.curve.n);
        self.verify_raw(&z, signature)
    }

    /// Core ECDSA verification over a pre-reduced scalar `z`.
    #[must_use]
    pub fn verify_raw(&self, hash: &BigUint, signature: &EcdsaSignature) -> bool {
        let n = &self.curve.n;

        // Both components must lie in [1, n).
        if signature.r.is_zero() || signature.s.is_zero() || &signature.r >= n || &signature.s >= n
        {
            return false;
        }

        let Some(w) = mod_inverse(&signature.s, n) else {
            return false;
        };

        // u₁ = z·w mod n,  u₂ = r·w mod n
        let u1 = BigUint::mod_mul(hash, &w, n);
        let u2 = BigUint::mod_mul(&signature.r, &w, n);

        // (x₁, y₁) = u₁·G + u₂·Q
        let g = self.curve.base_point();
        let term1 = self.curve.scalar_mul(&g, &u1);
        let term2 = self.curve.scalar_mul(&self.q, &u2);
        let sum = self.curve.add(&term1, &term2);

        if sum.is_infinity() {
            return false;
        }

        // Accept iff r ≡ x₁ (mod n).
        sum.x.modulo(n) == signature.r
    }

    /// Verify a byte-encoded signature produced by [`EcdsaPrivateKey::sign_bytes`].
    #[must_use]
    pub fn verify_bytes(&self, digest: &[u8], signature: &[u8]) -> bool {
        let Some(sig) = EcdsaSignature::from_binary(signature) else {
            return false;
        };
        self.verify(digest, &sig)
    }

    /// Encode the public key in the crate-defined binary format.
    ///
    /// Layout: one field-type byte (`0x00` = prime, `0x01` = binary) followed
    /// by `[p, a, b, n, h, Gx, Gy, Qx, Qy]` as a DER `SEQUENCE` of positive
    /// `INTEGER`s.
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

    /// Decode a public key from the crate-defined binary format.
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
        pem_wrap(ECDSA_PUBLIC_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(ECDSA_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
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
            "EcdsaPublicKey",
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
            "EcdsaPublicKey",
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

// ─── EcdsaPrivateKey ──────────────────────────────────────────────────────────

impl EcdsaPrivateKey {
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
    pub fn to_public_key(&self) -> EcdsaPublicKey {
        EcdsaPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Sign with an explicit nonce `k`.
    ///
    /// ECDSA requires a fresh `k ∈ [1, n)` for every signature.  This
    /// lower-level entry point keeps the arithmetic explicit for deterministic
    /// tests.
    ///
    /// Reusing the same `k` for two different messages with the same key
    /// immediately reveals the private scalar.  Outside of fixed vectors,
    /// prefer [`Self::sign`] or [`Self::sign_message`], which sample a fresh
    /// nonce internally.
    #[must_use]
    pub fn sign_with_k(&self, digest: &[u8], nonce: &BigUint) -> Option<EcdsaSignature> {
        let n = &self.curve.n;
        if nonce.is_zero() || nonce >= n {
            return None;
        }

        let z = digest_to_scalar(digest, n);

        // (x₁, y₁) = k·G
        let r_point = self.curve.scalar_mul(&self.curve.base_point(), nonce);
        if r_point.is_infinity() {
            return None;
        }
        let r = r_point.x.modulo(n);
        if r.is_zero() {
            return None;
        }

        // s = k⁻¹ · (z + r·d) mod n
        let k_inv = mod_inverse(nonce, n)?;
        let rd = BigUint::mod_mul(&r, &self.d, n);
        let z_plus_rd = z.add_ref(&rd).modulo(n);
        let s = BigUint::mod_mul(&k_inv, &z_plus_rd, n);
        if s.is_zero() {
            return None;
        }

        Some(EcdsaSignature { r, s })
    }

    /// Preferred explicit name for signing a pre-hashed digest with a caller-supplied nonce.
    #[must_use]
    pub fn sign_digest_with_nonce(&self, digest: &[u8], nonce: &BigUint) -> Option<EcdsaSignature> {
        self.sign_with_k(digest, nonce)
    }

    /// Sign a digest using a fresh random nonce.
    ///
    /// Retries only in the negligible edge cases where `r = 0` or `s = 0`.
    #[must_use]
    pub fn sign<R: Csprng>(&self, digest: &[u8], rng: &mut R) -> Option<EcdsaSignature> {
        loop {
            let nonce = random_nonzero_below(rng, &self.curve.n)?;
            if let Some(sig) = self.sign_with_k(digest, &nonce) {
                return Some(sig);
            }
        }
    }

    /// Convenience: hashes `message` with `H` then calls [`sign`][Self::sign].
    #[must_use]
    pub fn sign_message<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<EcdsaSignature> {
        let digest = H::digest(message);
        self.sign(&digest, rng)
    }

    /// Signs and serializes in one step; output is accepted by [`EcdsaPublicKey::verify_bytes`].
    #[must_use]
    pub fn sign_bytes<R: Csprng>(&self, digest: &[u8], rng: &mut R) -> Option<Vec<u8>> {
        let sig = self.sign(digest, rng)?;
        Some(sig.to_binary())
    }

    /// Convenience: signs and serializes; output accepted by [`EcdsaPublicKey::verify_message_bytes`].
    #[must_use]
    pub fn sign_message_bytes<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let sig = self.sign_message::<H, R>(message, rng)?;
        Some(sig.to_binary())
    }

    /// Encode the private key in the crate-defined binary format.
    ///
    /// Layout: one field-type byte (`0x00` = prime, `0x01` = binary) followed
    /// by `[p, a, b, n, h, Gx, Gy, d]`.
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

    /// Decode a private key from the crate-defined binary format.
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
        pem_wrap(ECDSA_PRIVATE_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(ECDSA_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
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
            "EcdsaPrivateKey",
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
            "EcdsaPrivateKey",
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

impl fmt::Debug for EcdsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaPrivateKey(<redacted>)")
    }
}

// ─── EcdsaSignature ───────────────────────────────────────────────────────────

impl EcdsaSignature {
    #[must_use]
    pub fn r(&self) -> &BigUint {
        &self.r
    }

    #[must_use]
    pub fn s(&self) -> &BigUint {
        &self.s
    }

    /// Encode the signature as a DER `SEQUENCE` of `(r, s)`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.r, &self.s])
    }

    /// Decode a crate-defined binary ECDSA signature.
    ///
    /// Zero values are rejected immediately.  Range checks against the curve
    /// order happen during verification because the signature encoding does
    /// not carry the curve parameters.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let r = fields.next()?;
        let s = fields.next()?;
        if fields.next().is_some() || r.is_zero() || s.is_zero() {
            return None;
        }
        Some(Self { r, s })
    }
}

// ─── Ecdsa namespace ──────────────────────────────────────────────────────────

impl Ecdsa {
    /// Returns `(public_key, private_key)`.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: CurveParams,
        rng: &mut R,
    ) -> (EcdsaPublicKey, EcdsaPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        let public = EcdsaPublicKey {
            curve: curve.clone(),
            q: q.clone(),
        };
        let private = EcdsaPrivateKey { curve, d, q };
        (public, private)
    }

    /// Derive a key pair from an explicit curve and secret scalar.
    ///
    /// Returns `None` if `secret` is zero or ≥ `n`.
    #[must_use]
    pub fn from_secret_scalar(
        curve: CurveParams,
        secret: &BigUint,
    ) -> Option<(EcdsaPublicKey, EcdsaPrivateKey)> {
        if secret.is_zero() || secret >= &curve.n {
            return None;
        }
        let q = curve.scalar_mul(&curve.base_point(), secret);
        Some((
            EcdsaPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EcdsaPrivateKey {
                curve,
                d: secret.clone(),
                q,
            },
        ))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a small `BigUint` (≤ 8 bytes) to a `u64`.
///
/// Returns `None` if the value has more than 8 bytes, which would indicate
/// a corrupt or unusually large cofactor in a serialized key.
fn biguint_to_u64(value: &BigUint) -> Option<u64> {
    let bytes = value.to_be_bytes();
    if bytes.len() > 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr[8 - bytes.len()..].copy_from_slice(&bytes);
    Some(u64::from_be_bytes(arr))
}

/// FIPS 186-5 digest representative reduction.
///
/// Keeps the leftmost `N = bits(n)` bits of the hash.  The shift amount is
/// derived from `digest.len() * 8`, not from the trimmed width of the integer,
/// to avoid a length-dependent branch on the hash output.
fn digest_to_scalar(digest: &[u8], modulus: &BigUint) -> BigUint {
    let mut value = BigUint::from_be_bytes(digest);
    let hash_bits = digest.len() * 8;
    let target_bits = modulus.bits();
    if hash_bits > target_bits {
        for _ in 0..(hash_bits - target_bits) {
            value.shr1();
        }
    }
    value
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{Ecdsa, EcdsaPrivateKey, EcdsaPublicKey, EcdsaSignature};
    use crate::public_key::bigint::BigUint;
    use crate::public_key::ec::{p256, p384, p521, secp256k1};
    use crate::{CtrDrbgAes256, Sha256, Sha384, Sha512};

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0xab; 48])
    }

    // ── Sign-and-verify round trips ──────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"hello world";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        assert!(public.verify_message::<Sha256>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_p384() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p384(), &mut rng);
        let msg = b"p384 test message";
        let sig = private
            .sign_message::<Sha384, _>(msg, &mut rng)
            .expect("sign");
        assert!(public.verify_message::<Sha384>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_secp256k1() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(secp256k1(), &mut rng);
        let msg = b"secp256k1 test";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        assert!(public.verify_message::<Sha256>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_p521() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p521(), &mut rng);
        let msg = b"p521 test message";
        let sig = private
            .sign_message::<Sha512, _>(msg, &mut rng)
            .expect("sign");
        assert!(public.verify_message::<Sha512>(msg, &sig));
    }

    // ── Deterministic signing via explicit nonce ──────────────────────────────

    #[test]
    fn sign_with_k_is_deterministic() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = [0x42u8; 32];
        let k = BigUint::from_u64(12_345_678_901_234_567_u64);
        let sig1 = private.sign_with_k(&digest, &k).expect("first sign");
        let sig2 = private.sign_with_k(&digest, &k).expect("second sign");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_digest_with_nonce_matches_sign_with_k() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = [0x42u8; 32];
        let nonce = BigUint::from_u64(12_345_678_901_234_567_u64);
        let lhs = private.sign_with_k(&digest, &nonce).expect("legacy");
        let rhs = private
            .sign_digest_with_nonce(&digest, &nonce)
            .expect("canonical");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn sign_with_k_zero_rejected() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = [0x00u8; 32];
        assert!(private.sign_with_k(&digest, &BigUint::zero()).is_none());
    }

    #[test]
    fn sign_with_k_equal_to_n_rejected() {
        let curve = p256();
        let n = curve.n.clone();
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(curve, &mut rng);
        let digest = [0x01u8; 32];
        assert!(private.sign_with_k(&digest, &n).is_none());
    }

    // ── Rejection tests ───────────────────────────────────────────────────────

    #[test]
    fn wrong_message_rejected() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"correct message";
        let wrong = b"wrong message";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        assert!(!public.verify_message::<Sha256>(wrong, &sig));
    }

    #[test]
    fn tampered_r_rejected() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"message";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        let bad = EcdsaSignature {
            r: sig.r.add_ref(&BigUint::one()),
            s: sig.s.clone(),
        };
        assert!(!public.verify_message::<Sha256>(msg, &bad));
    }

    #[test]
    fn tampered_s_rejected() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"message";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        let bad = EcdsaSignature {
            r: sig.r.clone(),
            s: sig.s.add_ref(&BigUint::one()),
        };
        assert!(!public.verify_message::<Sha256>(msg, &bad));
    }

    #[test]
    fn wrong_key_rejected() {
        let mut rng = rng();
        let (_, private1) = Ecdsa::generate(p256(), &mut rng);
        let (public2, _) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"message";
        let sig = private1
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        assert!(!public2.verify_message::<Sha256>(msg, &sig));
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_matches_generated() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        // Signing with private and verifying with the derived public key must work.
        let msg = b"derived key test";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        assert!(derived.verify_message::<Sha256>(msg, &sig));
        // The derived public point must match the original.
        assert_eq!(derived.q, public.q);
    }

    // ── from_secret_scalar ────────────────────────────────────────────────────

    #[test]
    fn from_secret_scalar_rejects_zero() {
        assert!(Ecdsa::from_secret_scalar(p256(), &BigUint::zero()).is_none());
    }

    #[test]
    fn from_secret_scalar_rejects_out_of_range() {
        let curve = p256();
        let too_large = curve.n.clone();
        assert!(Ecdsa::from_secret_scalar(curve, &too_large).is_none());
    }

    // ── Serialization: binary ─────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(p256(), &mut rng);
        let blob = public.to_binary();
        let recovered = EcdsaPublicKey::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
        assert_eq!(recovered.curve.n, public.curve.n);
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(p256(), &mut rng);
        let bytes = public.to_bytes();
        let recovered = EcdsaPublicKey::from_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
        assert_eq!(recovered.curve.n, public.curve.n);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let blob = private.to_binary();
        let recovered = EcdsaPrivateKey::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
        assert_eq!(recovered.curve.n, private.curve.n);
    }

    #[test]
    fn signature_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"roundtrip test";
        let sig = private
            .sign_message::<Sha256, _>(msg, &mut rng)
            .expect("sign");
        let blob = sig.to_binary();
        let recovered = EcdsaSignature::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered, sig);
    }

    // ── Serialization: PEM ────────────────────────────────────────────────────

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDSA PUBLIC KEY"));
        let recovered = EcdsaPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDSA PRIVATE KEY"));
        let recovered = EcdsaPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    // ── Serialization: XML ────────────────────────────────────────────────────

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EcdsaPublicKey"));
        let recovered = EcdsaPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        assert!(xml.contains("EcdsaPrivateKey"));
        let recovered = EcdsaPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    // ── Byte-level sign_bytes / verify_bytes ──────────────────────────────────

    #[test]
    fn sign_bytes_verify_bytes_roundtrip() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = Sha256::digest(b"test message bytes");
        let sig_bytes = private.sign_bytes(&digest, &mut rng).expect("sign_bytes");
        assert!(public.verify_bytes(&digest, &sig_bytes));
    }

    #[test]
    fn sign_message_bytes_verify_message_bytes_roundtrip() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"end-to-end bytes test";
        let sig_bytes = private
            .sign_message_bytes::<Sha256, _>(msg, &mut rng)
            .expect("sign_message_bytes");
        assert!(public.verify_message_bytes::<Sha256>(msg, &sig_bytes));
    }

    // ── Debug impl ────────────────────────────────────────────────────────────

    #[test]
    fn private_key_debug_redacted() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let s = format!("{private:?}");
        assert_eq!(s, "EcdsaPrivateKey(<redacted>)");
        // The scalar itself must not appear.
        assert!(!s.contains(&format!("{:?}", private.d)));
    }
}
