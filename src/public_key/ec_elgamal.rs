//! Elliptic-curve `ElGamal` encryption.
//!
//! `EC-ElGamal` is the elliptic-curve analogue of textbook `ElGamal`: rather than
//! computing exponentiations in a prime subgroup of `Z_p^*`, it uses the group
//! of points on a short-Weierstrass elliptic curve.
//!
//! ## Plaintext spaces
//!
//! Three plaintext representations are supported, each with its own
//! encrypt/decrypt pair:
//!
//! | API | Plaintext | Notes |
//! |-----|-----------|-------|
//! | `encrypt_point` / `decrypt_point` | [`AffinePoint`] | Pure group operation |
//! | `encrypt` / `decrypt` | `&[u8]` | Koblitz embedding; ≤ `coord_len − 1` bytes |
//! | `encrypt_int` / `decrypt_int` | `u64` | Homomorphic; DL recovery limits range |
//!
//! ## Encryption
//!
//! Given a public key `(curve, Q)`, encrypting point `M` with nonce `k`:
//! ```text
//! C₁ = k·G,   C₂ = M + k·Q
//! ```
//!
//! Decryption with private scalar `d`:
//! ```text
//! M = C₂ − d·C₁   (since d·C₁ = d·k·G = k·Q)
//! ```
//!
//! ## Additive homomorphism
//!
//! EC-ElGamal is additively homomorphic over the integer-encoding (`encrypt_int`)
//! layer: if `Enc(m₁) = (C₁, C₂)` and `Enc(m₂) = (C₁', C₂')` then
//! `(C₁+C₁', C₂+C₂')` decrypts to `(m₁+m₂)·G`.  The [`add_ciphertexts`]
//! method performs this operation.
//!
//! ## Side-channel note
//!
//! The underlying scalar multiplication is not constant-time; see the note in
//! [`ec`](crate::public_key::ec).
//!
//! [`add_ciphertexts`]: EcElGamalPublicKey::add_ciphertexts

use core::fmt;

use crate::public_key::bigint::BigUint;
use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::random_nonzero_below;
use crate::Csprng;

const EC_ELGAMAL_PUBLIC_LABEL: &str = "CRYPTOGRAPHY EC-ELGAMAL PUBLIC KEY";
const EC_ELGAMAL_PRIVATE_LABEL: &str = "CRYPTOGRAPHY EC-ELGAMAL PRIVATE KEY";
const EC_ELGAMAL_CT_LABEL: &str = "CRYPTOGRAPHY EC-ELGAMAL CIPHERTEXT";

// ─── Types ───────────────────────────────────────────────────────────────────

/// Public key for EC-ElGamal.
#[derive(Clone, Debug)]
pub struct EcElGamalPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for EC-ElGamal.
#[derive(Clone)]
pub struct EcElGamalPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
}

/// A pair of curve points `(C₁, C₂)` encoding one encrypted message.
///
/// The point-level ciphertext `(C₁, C₂)` satisfies:
/// - `C₁ = k·G`
/// - `C₂ = M + k·Q` (for a plaintext point `M`)
///
/// Two ciphertexts may be added with [`EcElGamalPublicKey::add_ciphertexts`],
/// producing a ciphertext whose decryption is the point-sum of the originals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcElGamalCiphertext {
    c1: AffinePoint,
    c2: AffinePoint,
}

pub struct EcElGamal;

// ─── EcElGamalPublicKey ───────────────────────────────────────────────────────

impl EcElGamalPublicKey {
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The public point `Q = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &AffinePoint {
        &self.q
    }

    /// Encrypt a curve point `m` directly.
    ///
    /// Returns `(k·G, M + k·Q)` for a freshly sampled nonce `k`.
    pub fn encrypt_point<R: Csprng>(&self, m: &AffinePoint, rng: &mut R) -> EcElGamalCiphertext {
        loop {
            let Some(k) = random_nonzero_below(rng, &self.curve.n) else {
                continue;
            };
            let ct = self.encrypt_point_with_k(m, &k);
            // Retry in the negligible case where k·G = ∞ (k = 0 mod n, impossible
            // for n prime and k drawn from [1, n)).
            if !ct.c1.is_infinity() {
                return ct;
            }
        }
    }

    /// Encrypt a curve point with an explicit nonce `k`.
    ///
    /// The caller is responsible for choosing `k` uniformly in `[1, n)`.
    /// Reusing `k` for two plaintexts reveals the discrete logarithm of the
    /// difference of the plaintexts.
    #[must_use]
    pub fn encrypt_point_with_k(&self, m: &AffinePoint, k: &BigUint) -> EcElGamalCiphertext {
        let g = self.curve.base_point();
        let c1 = self.curve.scalar_mul(&g, k);
        let kq = self.curve.scalar_mul(&self.q, k);
        let c2 = self.curve.add(m, &kq);
        EcElGamalCiphertext { c1, c2 }
    }

    /// Encrypt a byte message using Koblitz point embedding.
    ///
    /// The message is embedded into a curve point by appending a one-byte
    /// Koblitz index to the message and trying successive x-coordinates
    /// until a valid curve point is found.  The message length is limited
    /// to `curve.coord_len − 1` bytes.
    ///
    /// Returns `None` if the message is too long or if the curve does not
    /// support compressed-point decoding (i.e. `p ≢ 3 mod 4`, which applies
    /// to P-224).  Failure after 256 index attempts is extremely unlikely
    /// (`< 2^{-256}` probability) for any real curve.
    #[must_use]
    pub fn encrypt<R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<EcElGamalCiphertext> {
        let m_point = koblitz_encode(&self.curve, message)?;
        Some(self.encrypt_point(&m_point, rng))
    }

    /// Encrypt a small non-negative integer for additive-homomorphic use.
    ///
    /// The plaintext integer `m` is embedded as the point `m·G`.  Decryption
    /// recovers `m` by solving the discrete logarithm of the decrypted point
    /// up to a caller-supplied maximum value; see [`EcElGamalPrivateKey::decrypt_int`].
    ///
    /// The homomorphic property: for ciphertexts encrypting `m₁` and `m₂`
    /// respectively, [`add_ciphertexts`] produces a ciphertext for `m₁ + m₂`
    /// (as a point `(m₁ + m₂)·G`).
    ///
    /// [`add_ciphertexts`]: Self::add_ciphertexts
    pub fn encrypt_int<R: Csprng>(&self, m: u64, rng: &mut R) -> EcElGamalCiphertext {
        let g = self.curve.base_point();
        let m_point = if m == 0 {
            AffinePoint::infinity()
        } else {
            self.curve.scalar_mul(&g, &BigUint::from_u64(m))
        };
        self.encrypt_point(&m_point, rng)
    }

    /// Homomorphic addition: combine two ciphertexts into one whose decryption
    /// is the sum of the individual decrypted messages.
    ///
    /// For two ciphertexts `(C₁, C₂)` and `(C₁', C₂')`:
    /// ```text
    /// add_ciphertexts → (C₁ + C₁', C₂ + C₂')
    /// ```
    /// Decryption gives `(m₁ + m₂)·G` (point addition) or `M₁ + M₂` (for the
    /// point-encryption layer).
    #[must_use]
    pub fn add_ciphertexts(
        &self,
        ct1: &EcElGamalCiphertext,
        ct2: &EcElGamalCiphertext,
    ) -> EcElGamalCiphertext {
        EcElGamalCiphertext {
            c1: self.curve.add(&ct1.c1, &ct2.c1),
            c2: self.curve.add(&ct1.c2, &ct2.c2),
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
        pem_wrap(EC_ELGAMAL_PUBLIC_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_binary(&pem_unwrap(EC_ELGAMAL_PUBLIC_LABEL, pem)?)
    }

    /// # Panics
    ///
    /// Panics only if a malformed binary-field degree exceeds `u64`. That
    /// cannot happen for valid curve parameters in this crate.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let cofactor = BigUint::from_u64(self.curve.h);
        let degree = BigUint::from_u64(
            u64::try_from(self.curve.gf2m_degree().unwrap_or(0)).expect("degree fits in u64"),
        );
        xml_wrap(
            "EcElGamalPublicKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("b", &self.curve.b),
                ("n", &self.curve.n),
                ("h", &cofactor),
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
            "EcElGamalPublicKey",
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

// ─── EcElGamalPrivateKey ──────────────────────────────────────────────────────

impl EcElGamalPrivateKey {
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
    pub fn to_public_key(&self) -> EcElGamalPublicKey {
        let q = self.curve.scalar_mul(&self.curve.base_point(), &self.d);
        EcElGamalPublicKey {
            curve: self.curve.clone(),
            q,
        }
    }

    /// Decrypt a point-level ciphertext.
    ///
    /// Computes `C₂ − d·C₁`.  Returns the point at infinity if both `C₁` and
    /// `C₂` are the point at infinity (the trivially encrypted identity).
    #[must_use]
    pub fn decrypt_point(&self, ct: &EcElGamalCiphertext) -> AffinePoint {
        let dc1 = self.curve.scalar_mul(&ct.c1, &self.d);
        let neg_dc1 = self.curve.negate(&dc1);
        self.curve.add(&ct.c2, &neg_dc1)
    }

    /// Decrypt a byte-level ciphertext (Koblitz embedding).
    ///
    /// Returns the bytes originally passed to [`EcElGamalPublicKey::encrypt`].
    /// Note that leading zero bytes are not preserved: if you encrypted `b"\x00hello"`,
    /// you get back `b"hello"`.  This matches the behavior of `BigUint::to_be_bytes`.
    #[must_use]
    pub fn decrypt(&self, ct: &EcElGamalCiphertext) -> Vec<u8> {
        let m_point = self.decrypt_point(ct);
        koblitz_decode(&self.curve, &m_point)
    }

    /// Decrypt a homomorphically encrypted integer.
    ///
    /// Recovers `m` by solving the discrete logarithm of the decrypted point
    /// `m·G` using Baby-step Giant-step, up to `max_m` (exclusive).  Returns
    /// `None` if no solution is found in `[0, max_m)`.
    ///
    /// For practical performance, `max_m` should be at most `2²⁴` (~16 million).
    /// Larger values require proportionally more time and memory.
    #[must_use]
    pub fn decrypt_int(&self, ct: &EcElGamalCiphertext, max_m: u64) -> Option<u64> {
        let m_point = self.decrypt_point(ct);
        bsgs_dlog(&self.curve, &m_point, max_m)
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
        Some(Self {
            curve,
            d: private_scalar,
        })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EC_ELGAMAL_PRIVATE_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_binary(&pem_unwrap(EC_ELGAMAL_PRIVATE_LABEL, pem)?)
    }

    /// # Panics
    ///
    /// Panics only if a malformed binary-field degree exceeds `u64`. That
    /// cannot happen for valid curve parameters in this crate.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let cofactor = BigUint::from_u64(self.curve.h);
        let degree = BigUint::from_u64(
            u64::try_from(self.curve.gf2m_degree().unwrap_or(0)).expect("degree fits in u64"),
        );
        xml_wrap(
            "EcElGamalPrivateKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("b", &self.curve.b),
                ("n", &self.curve.n),
                ("h", &cofactor),
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
            "EcElGamalPrivateKey",
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
        Some(Self {
            curve,
            d: private_scalar,
        })
    }
}

impl fmt::Debug for EcElGamalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcElGamalPrivateKey(<redacted>)")
    }
}

// ─── EcElGamalCiphertext ─────────────────────────────────────────────────────

impl EcElGamalCiphertext {
    /// Return `C₁ = k·G`.
    #[must_use]
    pub fn c1(&self) -> &AffinePoint {
        &self.c1
    }

    /// Return `C₂ = M + k·Q`.
    #[must_use]
    pub fn c2(&self) -> &AffinePoint {
        &self.c2
    }

    /// Encode as `[C1x, C1y, C2x, C2y]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.c1.x, &self.c1.y, &self.c2.x, &self.c2.y])
    }

    /// Decode from binary format.  Does not check that points are on any
    /// particular curve (that would require curve parameters).
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let c1x = fields.next()?;
        let c1y = fields.next()?;
        let c2x = fields.next()?;
        let c2y = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            c1: AffinePoint::new(c1x, c1y),
            c2: AffinePoint::new(c2x, c2y),
        })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EC_ELGAMAL_CT_LABEL, &self.to_binary())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_binary(&pem_unwrap(EC_ELGAMAL_CT_LABEL, pem)?)
    }

    /// # Panics
    ///
    /// Panics only if an internal XML field name is malformed, which cannot
    /// happen for the fixed schema used by this type.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "EcElGamalCiphertext",
            &[
                ("c1x", &self.c1.x),
                ("c1y", &self.c1.y),
                ("c2x", &self.c2.x),
                ("c2y", &self.c2.y),
            ],
        )
    }

    /// Returns `None` if the XML root element, tag names, or integer encoding is invalid.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields =
            xml_unwrap("EcElGamalCiphertext", &["c1x", "c1y", "c2x", "c2y"], xml)?.into_iter();
        let c1x = fields.next()?;
        let c1y = fields.next()?;
        let c2x = fields.next()?;
        let c2y = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            c1: AffinePoint::new(c1x, c1y),
            c2: AffinePoint::new(c2x, c2y),
        })
    }
}

// ─── EcElGamal namespace ─────────────────────────────────────────────────────

impl EcElGamal {
    /// Generate a random key pair on `curve`.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: CurveParams,
        rng: &mut R,
    ) -> (EcElGamalPublicKey, EcElGamalPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        (
            EcElGamalPublicKey {
                curve: curve.clone(),
                q,
            },
            EcElGamalPrivateKey { curve, d },
        )
    }
}

// ─── Koblitz byte embedding ───────────────────────────────────────────────────

/// Encode `message` as a curve point using the Koblitz index trick.
///
/// Builds x-candidate = `message_padded || j` for j in `0..=255` and tries
/// `decode_point` with a compressed prefix until a point is found.  Works on
/// any curve where the compressed-point decoding is implemented (p ≡ 3 mod 4).
///
/// Message capacity: `coord_len − 1` bytes.
fn koblitz_encode(curve: &CurveParams, message: &[u8]) -> Option<AffinePoint> {
    let capacity = curve.coord_len.checked_sub(1)?;
    if message.len() > capacity {
        return None;
    }

    // Zero-pad to exactly `capacity` bytes, then try each Koblitz index.
    let mut x_buf = Vec::with_capacity(1 + curve.coord_len);
    x_buf.push(0x02); // compressed-point prefix (parity will be whatever decode gives)
    x_buf.resize(1 + capacity - message.len(), 0u8);
    x_buf.extend_from_slice(message);
    x_buf.push(0u8); // placeholder for index byte

    for j in 0u8..=255 {
        *x_buf.last_mut().expect("x_buf has coord_len + 1 bytes") = j;
        if let Some(point) = curve.decode_point(&x_buf) {
            return Some(point);
        }
    }
    None
}

/// Recover a byte message from the x-coordinate of a Koblitz-encoded point.
///
/// Strips the last byte (the Koblitz index `j`) and leading zero bytes,
/// matching the behavior of `BigUint::to_be_bytes`.
fn koblitz_decode(curve: &CurveParams, point: &AffinePoint) -> Vec<u8> {
    if point.is_infinity() {
        return Vec::new();
    }
    // Pad x to exactly coord_len bytes.
    let x_bytes = point.x.to_be_bytes();
    let padded_len = curve.coord_len;
    let pad = if x_bytes.len() < padded_len {
        padded_len - x_bytes.len()
    } else {
        0
    };

    // Build: [0 * pad] ++ x_bytes, then strip last byte (j index).
    let full_len = pad + x_bytes.len(); // = coord_len if no overflow
    let message_end = full_len.saturating_sub(1); // drop last byte

    let mut out = Vec::with_capacity(padded_len);
    out.resize(pad, 0u8);
    out.extend_from_slice(&x_bytes);
    out.truncate(message_end);

    // Strip leading zeros (matching BigUint::to_be_bytes behavior).
    let first_nonzero = out.iter().position(|&b| b != 0).unwrap_or(out.len());
    out[first_nonzero..].to_vec()
}

// ─── Baby-step Giant-step DL recovery ────────────────────────────────────────

/// Solve `m·G = target` for `m ∈ [0, max_m)` using Baby-step Giant-step.
///
/// Builds a hash table of `ceil(sqrt(max_m))` baby steps, then walks giant
/// steps until a match is found. Time and space complexity: `O(sqrt(max_m))`.
///
/// Returns `None` if no solution is found.
fn bsgs_dlog(curve: &CurveParams, target: &AffinePoint, max_m: u64) -> Option<u64> {
    if max_m == 0 {
        return None;
    }
    if target.is_infinity() {
        return Some(0);
    }

    let step = max_m.isqrt().saturating_add(1);
    let g = curve.base_point();

    // Baby steps: table maps compressed-point bytes → baby-step index j.
    // Entry j corresponds to the point j·G.
    let mut table = std::collections::HashMap::with_capacity(
        usize::try_from(step).expect("step fits in usize"),
    );
    let mut baby = AffinePoint::infinity();
    for j in 0u64..step {
        let key = curve.encode_point(&baby);
        table.entry(key).or_insert(j);
        baby = curve.add(&baby, &g);
    }

    // Giant step: the stride point is `step·G`.
    let stride_point = curve.scalar_mul(&g, &BigUint::from_u64(step));
    let neg_stride = curve.negate(&stride_point);

    // Walk: current = target - i·step·G = target + i·(−step·G).
    let mut current = target.clone();
    for i in 0u64..step {
        let key = curve.encode_point(&current);
        if let Some(&j) = table.get(&key) {
            let m = i * step + j;
            if m < max_m {
                return Some(m);
            }
        }
        current = curve.add(&current, &neg_stride);
    }
    None
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
    use super::{EcElGamal, EcElGamalCiphertext, EcElGamalPrivateKey, EcElGamalPublicKey};
    use crate::public_key::bigint::BigUint;
    use crate::public_key::ec::{p256, p384, secp256k1};
    use crate::CtrDrbgAes256;

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0xcd; 48])
    }

    // ── Point-level encrypt / decrypt ─────────────────────────────────────────

    #[test]
    fn point_roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let g = public.curve().base_point();
        let m = public.curve().scalar_mul(&g, &BigUint::from_u64(42));
        let ct = public.encrypt_point(&m, &mut rng);
        let recovered = private.decrypt_point(&ct);
        assert_eq!(recovered, m);
    }

    #[test]
    fn point_roundtrip_infinity() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let m = crate::public_key::ec::AffinePoint::infinity();
        let ct = public.encrypt_point(&m, &mut rng);
        let recovered = private.decrypt_point(&ct);
        assert!(recovered.is_infinity());
    }

    // ── Byte-level encrypt / decrypt ──────────────────────────────────────────

    #[test]
    fn bytes_roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let msg = b"hello EC-ElGamal";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        let recovered = private.decrypt(&ct);
        assert_eq!(recovered, msg);
    }

    #[test]
    fn bytes_roundtrip_p384() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p384(), &mut rng);
        let msg = b"p384 message bytes";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        let recovered = private.decrypt(&ct);
        assert_eq!(recovered, msg);
    }

    #[test]
    fn bytes_roundtrip_secp256k1() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(secp256k1(), &mut rng);
        let msg = b"secp256k1 test";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        let recovered = private.decrypt(&ct);
        assert_eq!(recovered, msg);
    }

    #[test]
    fn bytes_too_long_rejected() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        // P-256 coord_len = 32, capacity = 31 bytes.
        let long_msg = [0x42u8; 32];
        assert!(public.encrypt(&long_msg, &mut rng).is_none());
    }

    // ── Integer / homomorphic ─────────────────────────────────────────────────

    #[test]
    fn int_roundtrip_zero() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt_int(0, &mut rng);
        let m = private.decrypt_int(&ct, 100).expect("decrypt");
        assert_eq!(m, 0);
    }

    #[test]
    fn int_roundtrip_small() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        for &val in &[1u64, 7, 42, 999, 65535] {
            let ct = public.encrypt_int(val, &mut rng);
            let m = private.decrypt_int(&ct, 100_000).expect("decrypt");
            assert_eq!(m, val, "failed for value {val}");
        }
    }

    #[test]
    fn int_out_of_range_returns_none() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        // Encrypt 1000, then try to decrypt with max_m = 100.
        let ct = public.encrypt_int(1000, &mut rng);
        assert!(private.decrypt_int(&ct, 100).is_none());
    }

    // ── Additive homomorphism ─────────────────────────────────────────────────

    #[test]
    fn add_ciphertexts_homomorphic() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let ct1 = public.encrypt_int(7, &mut rng);
        let ct2 = public.encrypt_int(11, &mut rng);
        let combined = public.add_ciphertexts(&ct1, &ct2);
        let sum = private.decrypt_int(&combined, 100).expect("decrypt");
        assert_eq!(sum, 18);
    }

    #[test]
    fn add_ciphertexts_three_terms() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let ct1 = public.encrypt_int(100, &mut rng);
        let ct2 = public.encrypt_int(200, &mut rng);
        let ct3 = public.encrypt_int(300, &mut rng);
        let combined = public.add_ciphertexts(&public.add_ciphertexts(&ct1, &ct2), &ct3);
        let sum = private.decrypt_int(&combined, 700).expect("decrypt");
        assert_eq!(sum, 600);
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_matches() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.q, public.q);
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let blob = public.to_binary();
        let recovered = EcElGamalPublicKey::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(p256(), &mut rng);
        let blob = private.to_binary();
        let recovered = EcElGamalPrivateKey::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn ciphertext_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt(b"test", &mut rng).expect("encrypt");
        let blob = ct.to_binary();
        let recovered = EcElGamalCiphertext::from_binary(&blob).expect("from_binary");
        assert_eq!(recovered, ct);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("EC-ELGAMAL PUBLIC KEY"));
        let recovered = EcElGamalPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("EC-ELGAMAL PRIVATE KEY"));
        let recovered = EcElGamalPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn ciphertext_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt(b"pem test", &mut rng).expect("encrypt");
        let pem = ct.to_pem();
        let recovered = EcElGamalCiphertext::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered, ct);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EcElGamalPublicKey"));
        let recovered = EcElGamalPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        let recovered = EcElGamalPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn ciphertext_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt(b"xml test", &mut rng).expect("encrypt");
        let xml = ct.to_xml();
        let recovered = EcElGamalCiphertext::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered, ct);
    }

    // ── Debug redaction ───────────────────────────────────────────────────────

    #[test]
    fn private_key_debug_redacted() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(p256(), &mut rng);
        let s = format!("{private:?}");
        assert_eq!(s, "EcElGamalPrivateKey(<redacted>)");
    }
}
