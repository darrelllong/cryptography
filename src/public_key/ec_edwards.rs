//! Twisted Edwards curve arithmetic over prime fields.
//!
//! Curve form: `a·x² + y² = 1 + d·x²·y² (mod p)`, where `p` is prime.
//!
//! This module provides the arithmetic substrate for signature schemes such as
//! EdDSA (Ed25519) and key-agreement schemes that use Edwards-form curves.
//!
//! ## Named curves
//!
//! - [`ed25519`]: the Edwards curve underlying the Ed25519 signature scheme
//!   (RFC 8032).  Field prime `p = 2^255 − 19`; `a = −1`; 128-bit classical
//!   security.
//!
//! ## Coordinates
//!
//! Point arithmetic uses extended twisted Edwards coordinates `(X : Y : Z : T)`
//! where `x = X/Z`, `y = Y/Z`, and `T = X·Y/Z` (so `x·y = T/Z`).  The
//! extended form enables a unified addition formula that handles both
//! `P + Q` and `2P` identically, with no special-case branches for the neutral
//! element, and is also complete (valid for all inputs including `P = −Q`).
//!
//! A single `Z`-inversion converts the final result back to affine.
//!
//! ## Neutral element
//!
//! The neutral element (group identity) is the affine point `(0, 1)`, which
//! satisfies `a·0 + 1 = 1 + d·0 = 1`.  In extended coordinates it is
//! `(0, Z, Z, 0)` for any non-zero `Z`.
//!
//! ## Point encoding
//!
//! Ed25519 uses the RFC 8032 §5.1.2 encoding:
//!
//! - 32 bytes: the little-endian encoding of `y`.
//! - The most-significant bit of the last byte carries the low bit (sign) of `x`.
//!
//! This is a 255-bit `y` value plus one parity bit, packed into 32 bytes.
//!
//! ## Side-channel note
//!
//! The scalar multiplication loop branches on individual bits of the scalar
//! and is **not constant-time**.  It is unsuitable for environments where
//! timing or power measurements of the scalar are possible.
//!
//! ## Field square root
//!
//! For `p = 2^255 − 19`, which satisfies `p ≡ 5 (mod 8)`, point decompression
//! uses the RFC 8032 §5.1.3 square-root algorithm:
//!
//! 1. Compute the candidate `β = u^{(p+3)/8}`.
//! 2. If `β² = u`, return `β`.
//! 3. If `β² = −u`, return `β · √(−1)` where `√(−1) = 2^{(p−1)/4} mod p`.
//! 4. Otherwise `u` has no square root.
//!
//! This uses two modular exponentiations plus a comparison.

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::primes::{mod_inverse, random_nonzero_below};
use crate::Csprng;

// ─── Core types ─────────────────────────────────────────────────────────────

/// Parameters for a twisted Edwards curve `a·x² + y² = 1 + d·x²·y² (mod p)`.
///
/// All constants are ordinary residues in `[0, p)`.  Two [`MontgomeryCtx`]
/// values are pre-built at construction: one for field arithmetic mod `p` and
/// one for scalar arithmetic mod `n`.  An additional `d2 = 2·d mod p` is
/// cached because the unified addition formula multiplies by `2·d` in the hot
/// path.
#[derive(Clone, Debug)]
pub struct TwistedEdwardsCurve {
    /// Field prime `p`.
    pub p: BigUint,
    /// Curve coefficient `a`.  For Ed25519 this is `p − 1` (i.e. `−1 mod p`).
    pub a: BigUint,
    /// Curve coefficient `d`.
    pub d: BigUint,
    /// `2·d mod p`, cached for the unified addition formula.
    pub(crate) d2: BigUint,
    /// Prime order of the base-point subgroup.
    pub n: BigUint,
    /// x-coordinate of the standard base point `G`.
    pub gx: BigUint,
    /// y-coordinate of the standard base point `G`.
    pub gy: BigUint,
    /// Precomputed Montgomery context for field arithmetic mod `p`.
    pub(crate) field: MontgomeryCtx,
    /// Precomputed Montgomery context for scalar arithmetic mod `n`.
    ///
    /// This is cached next to the field context so Edwards-based scalar
    /// protocols can reuse the subgroup modulus without redoing the Newton
    /// setup, even when a given code path only touches the field arithmetic.
    pub(crate) _scalar: MontgomeryCtx,
    /// Byte length of a field element: `⌈p.bits() / 8⌉`.
    pub coord_len: usize,
}

/// An affine Edwards curve point, or the neutral element `(0, 1)`.
///
/// The coordinates are ordinary residues in `[0, p)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdwardsPoint {
    /// x-coordinate.  Meaningful only when `!neutral`.
    pub x: BigUint,
    /// y-coordinate.  Meaningful only when `!neutral`.
    pub y: BigUint,
    /// `true` when this is the neutral element (group identity `(0, 1)`).
    pub neutral: bool,
}

/// Extended twisted Edwards coordinates `(X : Y : Z : T)`.
///
/// Represents the affine point `(x, y)` as `(x·Z, y·Z, Z, x·y·Z)` for any
/// non-zero `Z`.  The neutral element `(0, 1)` is `(0, Z, Z, 0)`.
struct ExtendedPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

// ─── EdwardsPoint ───────────────────────────────────────────────────────────

impl EdwardsPoint {
    /// The neutral element (group identity, the affine point `(0, 1)`).
    #[must_use]
    pub fn neutral() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::one(),
            neutral: true,
        }
    }

    /// A finite affine point `(x, y)`.
    ///
    /// The caller is responsible for ensuring that `(x, y)` actually lies on
    /// the curve; use [`TwistedEdwardsCurve::is_on_curve`] to verify.
    #[must_use]
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            neutral: false,
        }
    }

    /// Return `true` if this is the neutral element.
    #[must_use]
    pub fn is_neutral(&self) -> bool {
        self.neutral
    }
}

// ─── ExtendedPoint ──────────────────────────────────────────────────────────

impl ExtendedPoint {
    /// The neutral element `(0, 1, 1, 0)` in extended coordinates.
    fn neutral() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::one(),
            z: BigUint::one(),
            t: BigUint::zero(),
        }
    }

    fn is_neutral(&self) -> bool {
        self.x.is_zero() && self.y == self.z
    }

    /// Lift an affine point to extended coordinates with `Z = 1`.
    ///
    /// For affine `(x, y)`: extended `(x, y, 1, x·y)`.
    /// For the neutral element `(0, 1)`: extended `(0, 1, 1, 0)`.
    fn from_affine(p: &EdwardsPoint, ctx: &MontgomeryCtx) -> Self {
        if p.neutral {
            return Self::neutral();
        }
        let t = ctx.mul(&p.x, &p.y);
        Self {
            x: p.x.clone(),
            y: p.y.clone(),
            z: BigUint::one(),
            t,
        }
    }

    /// Convert back to affine coordinates.
    ///
    /// Recovers `x = X/Z` and `y = Y/Z` via Fermat inversion
    /// `Z⁻¹ = Z^{p−2} mod p`.  The projective neutral `(0 : Z : Z : 0)` is
    /// canonicalized back to the affine identity `(0, 1)` so the explicit
    /// `neutral` flag always stays in sync with the coordinates.
    fn to_affine(&self, curve: &TwistedEdwardsCurve) -> EdwardsPoint {
        if self.is_neutral() {
            return EdwardsPoint::neutral();
        }

        // Fast path: a freshly lifted affine point keeps `Z = 1` until it
        // actually goes through a non-trivial addition or doubling.  In that
        // case there is no need to pay for a Fermat inversion.
        if self.z == BigUint::one() {
            return EdwardsPoint::new(self.x.clone(), self.y.clone());
        }

        let ctx = &curve.field;
        let p_minus_2 = curve.p.sub_ref(&BigUint::from_u64(2));
        let z_inv = ctx.pow(&self.z, &p_minus_2);

        let x = ctx.mul(&self.x, &z_inv);
        let y = ctx.mul(&self.y, &z_inv);

        EdwardsPoint::new(x, y)
    }
}

// ─── Field helpers ──────────────────────────────────────────────────────────

/// `(a + b) mod p`  (both inputs in `[0, p)`)
#[inline]
fn fadd(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let s = a.add_ref(b);
    if &s >= p {
        s.sub_ref(p)
    } else {
        s
    }
}

/// `(a − b) mod p`  (both inputs in `[0, p)`)
#[inline]
fn fsub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        a.sub_ref(b)
    } else {
        p.sub_ref(&b.sub_ref(a))
    }
}

/// `(−a) mod p`
#[inline]
fn fneg(a: &BigUint, p: &BigUint) -> BigUint {
    if a.is_zero() {
        BigUint::zero()
    } else {
        p.sub_ref(a)
    }
}

// ─── Point arithmetic ───────────────────────────────────────────────────────

/// Unified addition `P₁ + P₂` in extended twisted Edwards coordinates.
///
/// Uses the RFC 8032 §5.1.4 / "add-2008-hwcd" formula for `a = −1`:
///
/// ```text
/// A = (Y₁−X₁)·(Y₂−X₂)
/// B = (Y₁+X₁)·(Y₂+X₂)
/// C = T₁·2d·T₂
/// D = Z₁·2·Z₂
/// E = B−A,  F = D−C,  G = D+C,  H = B+A
/// (X₃, Y₃, T₃, Z₃) = (E·F, G·H, E·H, F·G)
/// ```
///
/// The formula is *unified*: it works when `P₁ = P₂` (doubling) or
/// `P₁ = −P₂` (result is the neutral), and it is *complete* over any prime
/// field with `−d` a non-square, which holds for Ed25519.
fn point_add_extended(
    curve: &TwistedEdwardsCurve,
    p1: &ExtendedPoint,
    p2: &ExtendedPoint,
) -> ExtendedPoint {
    let ctx = &curve.field;
    let m = &curve.p;

    // A = (Y₁ − X₁)·(Y₂ − X₂)
    let y1_m_x1 = fsub(&p1.y, &p1.x, m);
    let y2_m_x2 = fsub(&p2.y, &p2.x, m);
    let a = ctx.mul(&y1_m_x1, &y2_m_x2);

    // B = (Y₁ + X₁)·(Y₂ + X₂)
    let y1_p_x1 = fadd(&p1.y, &p1.x, m);
    let y2_p_x2 = fadd(&p2.y, &p2.x, m);
    let b = ctx.mul(&y1_p_x1, &y2_p_x2);

    // C = T₁·2d·T₂  (using the precomputed d2 = 2d mod p)
    let t2_scaled = ctx.mul(&p2.t, &curve.d2);
    let c = ctx.mul(&p1.t, &t2_scaled);

    // D = Z₁·2·Z₂  =  2·(Z₁·Z₂)
    let z1z2 = ctx.mul(&p1.z, &p2.z);
    let d = fadd(&z1z2, &z1z2, m);

    // E = B−A,  F = D−C,  G = D+C,  H = B+A
    let e = fsub(&b, &a, m);
    let f = fsub(&d, &c, m);
    let g = fadd(&d, &c, m);
    let h = fadd(&b, &a, m); // correct for a = −1: H = B − a·A = B + A

    ExtendedPoint {
        x: ctx.mul(&e, &f),
        y: ctx.mul(&g, &h),
        z: ctx.mul(&f, &g),
        t: ctx.mul(&e, &h),
    }
}

/// Point doubling via the unified addition formula with `P₁ = P₂`.
///
/// The unified Edwards addition formula is *complete* and handles `P + P`
/// without any special-case branching.  A dedicated "dbl-2008-hwcd" formula
/// would save a few multiplications, but the unified formula is simpler to
/// audit and correct for a toolkit.  This wrapper exists so callers can
/// express intent (`double` vs `add`) without committing to a specific
/// internal formula.
fn point_double_extended(curve: &TwistedEdwardsCurve, p1: &ExtendedPoint) -> ExtendedPoint {
    point_add_extended(curve, p1, p1)
}

/// Scalar multiplication `k·P` via left-to-right binary double-and-add.
///
/// The loop stays in extended coordinates throughout; a single conversion
/// to affine is paid at the end.
///
/// **Side-channel note**: the inner loop branches on individual bits of `k`.
/// This is not constant-time.
fn scalar_mul_extended(
    curve: &TwistedEdwardsCurve,
    point: &EdwardsPoint,
    k: &BigUint,
) -> EdwardsPoint {
    if k.is_zero() || point.is_neutral() {
        return EdwardsPoint::neutral();
    }

    let mut result = ExtendedPoint::neutral();
    let p_ext = ExtendedPoint::from_affine(point, &curve.field);

    for i in (0..k.bits()).rev() {
        result = point_add_extended(curve, &result, &result);
        if k.bit(i) {
            result = point_add_extended(curve, &result, &p_ext);
        }
    }

    result.to_affine(curve)
}

// ─── TwistedEdwardsCurve ────────────────────────────────────────────────────

impl TwistedEdwardsCurve {
    /// Construct curve parameters from raw field values.
    ///
    /// Returns `None` if the field prime `p` or subgroup order `n` is even,
    /// which prevents building a `MontgomeryCtx`.
    #[must_use]
    pub fn new(
        p: BigUint,
        a: BigUint,
        d: BigUint,
        n: BigUint,
        gx: BigUint,
        gy: BigUint,
    ) -> Option<Self> {
        let field = MontgomeryCtx::new(&p)?;
        let scalar = MontgomeryCtx::new(&n)?;
        let coord_len = (p.bits() + 7) / 8;
        let d2 = {
            let v = d.add_ref(&d);
            if &v >= &p { v.sub_ref(&p) } else { v }
        };
        Some(Self {
            p,
            a,
            d,
            d2,
            n,
            gx,
            gy,
            field,
            _scalar: scalar,
            coord_len,
        })
    }

    /// The base point `G`.
    #[must_use]
    pub fn base_point(&self) -> EdwardsPoint {
        EdwardsPoint::new(self.gx.clone(), self.gy.clone())
    }

    /// Return `true` if `point` lies on this curve.
    ///
    /// Checks `a·x² + y² ≡ 1 + d·x²·y² (mod p)`.  The neutral element
    /// trivially passes.
    #[must_use]
    pub fn is_on_curve(&self, point: &EdwardsPoint) -> bool {
        if point.neutral {
            return true;
        }
        let ctx = &self.field;
        let x2 = ctx.square(&point.x);
        let y2 = ctx.square(&point.y);
        // lhs = a·x² + y²
        let ax2 = ctx.mul(&self.a, &x2);
        let lhs = fadd(&ax2, &y2, &self.p);
        // rhs = 1 + d·x²·y²
        let x2y2 = ctx.mul(&x2, &y2);
        let dx2y2 = ctx.mul(&self.d, &x2y2);
        let rhs = fadd(&BigUint::one(), &dx2y2, &self.p);
        lhs == rhs
    }

    /// Negate a point: `(x, y)` → `(−x mod p, y)`.
    ///
    /// On a twisted Edwards curve the negation of `(x, y)` is `(−x, y)`
    /// (compare with Weierstrass where negation flips the `y` coordinate).
    #[must_use]
    pub fn negate(&self, point: &EdwardsPoint) -> EdwardsPoint {
        if point.neutral {
            return point.clone();
        }
        EdwardsPoint::new(fneg(&point.x, &self.p), point.y.clone())
    }

    /// Add two affine curve points.
    #[must_use]
    pub fn add(&self, p: &EdwardsPoint, q: &EdwardsPoint) -> EdwardsPoint {
        let pe = ExtendedPoint::from_affine(p, &self.field);
        let qe = ExtendedPoint::from_affine(q, &self.field);
        point_add_extended(self, &pe, &qe).to_affine(self)
    }

    /// Double an affine curve point (`2P`).
    #[must_use]
    pub fn double(&self, p: &EdwardsPoint) -> EdwardsPoint {
        let pe = ExtendedPoint::from_affine(p, &self.field);
        point_double_extended(self, &pe).to_affine(self)
    }

    /// Scalar multiplication `k·P`.
    ///
    /// Returns the neutral element when `k = 0` or `P` is neutral.
    #[must_use]
    pub fn scalar_mul(&self, point: &EdwardsPoint, k: &BigUint) -> EdwardsPoint {
        scalar_mul_extended(self, point, k)
    }

    /// Compute the ECDH shared point `d·Q`.
    #[must_use]
    pub fn diffie_hellman(
        &self,
        private_scalar: &BigUint,
        public_point: &EdwardsPoint,
    ) -> EdwardsPoint {
        self.scalar_mul(public_point, private_scalar)
    }

    /// Sample a uniform random scalar in `[1, n)`.
    pub fn random_scalar<R: Csprng>(&self, rng: &mut R) -> BigUint {
        random_nonzero_below(rng, &self.n)
            .expect("curve order n is always > 1 for any valid cryptographic curve")
    }

    /// Generate a random key pair `(d, Q)` where `Q = d·G`.
    pub fn generate_keypair<R: Csprng>(&self, rng: &mut R) -> (BigUint, EdwardsPoint) {
        let d = self.random_scalar(rng);
        let q = self.scalar_mul(&self.base_point(), &d);
        (d, q)
    }

    /// Compute `k⁻¹ mod n`.  Returns `None` if `k = 0`.
    #[must_use]
    pub fn scalar_invert(&self, k: &BigUint) -> Option<BigUint> {
        mod_inverse(k, &self.n)
    }

    /// Encode a point using the RFC 8032 §5.1.2 encoding.
    ///
    /// Output: `coord_len` bytes, little-endian `y`, with the LSB of `x`
    /// stored in the most-significant bit of the last byte.
    ///
    /// The neutral element `(0, 1)` encodes as all-zero bytes except the
    /// last byte which is `0x01` (i.e. the encoding of `y = 1` with sign 0).
    #[must_use]
    pub fn encode_point(&self, point: &EdwardsPoint) -> Vec<u8> {
        // For the neutral element (0, 1): y = 1, x = 0 (even); encoding is
        // 01 00 00 ... 00 in little-endian.
        let (x_ref, y_ref) = if point.neutral {
            (&BigUint::zero(), &BigUint::one())
        } else {
            (&point.x, &point.y)
        };

        // y in big-endian, then reverse to get little-endian.
        let y_be = pad_to(y_ref.to_be_bytes(), self.coord_len);
        let mut out: Vec<u8> = y_be.into_iter().rev().collect();

        // Set MSB of last byte to the LSB (sign) of x.
        if x_ref.is_odd() {
            *out.last_mut().expect("coord_len > 0") |= 0x80;
        }
        out
    }

    /// Decode a point from its RFC 8032 §5.1.2 encoding.
    ///
    /// Returns `None` for wrong-length input, for an `x`-coordinate with no
    /// square root on this curve (the `y` value is not on the curve), or if
    /// the field prime does not satisfy `p ≡ 3 (mod 4)` or `p ≡ 5 (mod 8)`.
    #[must_use]
    pub fn decode_point(&self, bytes: &[u8]) -> Option<EdwardsPoint> {
        if bytes.len() != self.coord_len {
            return None;
        }
        let x_odd = (bytes[self.coord_len - 1] & 0x80) != 0;
        let mut y_le = bytes.to_vec();
        *y_le.last_mut().expect("length > 0") &= 0x7f;
        // Convert little-endian y to BigUint (big-endian internally).
        let y_be: Vec<u8> = y_le.into_iter().rev().collect();
        let y = BigUint::from_be_bytes(&y_be);
        let x = self.field_recover_x(&y, x_odd)?;
        let pt = if x.is_zero() && y == BigUint::one() {
            EdwardsPoint::neutral()
        } else {
            EdwardsPoint::new(x, y)
        };
        if self.is_on_curve(&pt) {
            Some(pt)
        } else {
            None
        }
    }

    /// Recover `x` from `y` using the curve equation and the requested sign.
    ///
    /// From `a·x² + y² = 1 + d·x²·y²`:
    ///
    /// ```text
    /// x² = (y² − 1) / (d·y² − a)
    /// ```
    ///
    /// For `a = −1` this simplifies to `x² = (y² − 1) / (d·y² + 1)`.
    ///
    /// The square root is computed using the algorithm appropriate for `p mod 8`:
    ///
    /// - `p ≡ 3 (mod 4)`: `x = (x²)^{(p+1)/4}`
    /// - `p ≡ 5 (mod 8)`: RFC 8032 two-step method (covers Ed25519's prime)
    ///
    /// Returns `None` if `x²` has no square root in `F_p`.
    fn field_recover_x(&self, y: &BigUint, x_odd: bool) -> Option<BigUint> {
        let ctx = &self.field;

        // x² = (y² − 1) / (d·y² − a)
        // For a = p − 1 (i.e. a = −1): d·y² − a = d·y² + 1.
        let y2 = ctx.square(y);
        let numerator = fsub(&y2, &BigUint::one(), &self.p);
        let dy2 = ctx.mul(&self.d, &y2);
        let denominator = fsub(&dy2, &self.a, &self.p); // d·y² − a

        // Compute x² = numerator / denominator via Fermat inversion.
        let p_minus_2 = self.p.sub_ref(&BigUint::from_u64(2));
        let denom_inv = ctx.pow(&denominator, &p_minus_2);
        let x_squared = ctx.mul(&numerator, &denom_inv);

        // Compute the square root of x_squared mod p.
        let x_candidate = self.field_sqrt(&x_squared)?;

        // Select the root with the requested sign.
        let x = if x_candidate.is_odd() == x_odd {
            x_candidate
        } else {
            fneg(&x_candidate, &self.p)
        };
        Some(x)
    }

    /// Compute `√u mod p`.
    ///
    /// Dispatches on `p mod 8`:
    /// - `p ≡ 3 (mod 4)`: uses `u^{(p+1)/4}`.
    /// - `p ≡ 5 (mod 8)`: uses the RFC 8032 two-step method.
    ///
    /// Returns `None` if `u` has no square root in `F_p`.
    fn field_sqrt(&self, u: &BigUint) -> Option<BigUint> {
        let ctx = &self.field;
        let p_mod8 = self.p.rem_u64(8);

        if p_mod8 == 3 || p_mod8 == 7 {
            // p ≡ 3 (mod 4): candidate = u^{(p+1)/4}.
            let (exp, _) = self.p.add_ref(&BigUint::one()).div_rem(&BigUint::from_u64(4));
            let candidate = ctx.pow(u, &exp);
            if ctx.square(&candidate) == *u {
                Some(candidate)
            } else {
                None
            }
        } else if p_mod8 == 5 {
            // p ≡ 5 (mod 8): RFC 8032 §5.1.3 algorithm.
            //
            // Step 1: candidate β = u^{(p+3)/8}
            let (exp, _) = self.p.add_ref(&BigUint::from_u64(3)).div_rem(&BigUint::from_u64(8));
            let beta = ctx.pow(u, &exp);
            let beta2 = ctx.square(&beta);

            if beta2 == *u {
                return Some(beta);
            }

            // Step 2: check if β² = −u  (i.e. β² + u = 0 mod p)
            let neg_u = fneg(u, &self.p);
            if beta2 == neg_u {
                // Multiply by √(−1) = 2^{(p−1)/4} mod p.
                let (sqrt_m1_exp, _) =
                    self.p.sub_ref(&BigUint::one()).div_rem(&BigUint::from_u64(4));
                let sqrt_m1 = ctx.pow(&BigUint::from_u64(2), &sqrt_m1_exp);
                return Some(ctx.mul(&beta, &sqrt_m1));
            }

            None // no square root
        } else {
            // General case (p ≡ 1 mod 8) is not implemented; return None.
            // A Tonelli-Shanks implementation would handle this.
            None
        }
    }
}

/// Pad `bytes` to `len` bytes by prepending zeros (big-endian padding).
fn pad_to(bytes: Vec<u8>, len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes;
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

// ─── Named curves ────────────────────────────────────────────────────────────

/// Parse a compact hexadecimal string (spaces ignored) into a `BigUint`.
fn from_hex(hex: &str) -> BigUint {
    let cleaned: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0, "hex string must have even length");
    let bytes: Vec<u8> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex digit"))
        .collect();
    BigUint::from_be_bytes(&bytes)
}

/// Ed25519 twisted Edwards curve.
///
/// Reference: RFC 8032.  This is the curve underlying the Ed25519 signature
/// scheme; the same group is used as the basis for X25519 ECDH (though X25519
/// uses the birationally equivalent Montgomery form Curve25519).
///
/// Field prime: `p = 2^255 − 19`.
/// Curve equation: `−x² + y² = 1 + d·x²·y² (mod p)`, i.e. `a = −1`.
/// Subgroup order: `n = 2^252 + 27742317777372353535851937790883648493`.
///
/// Security level: ~128-bit classical, ~64-bit quantum (Grover).
///
/// Encoding: RFC 8032 §5.1.2 little-endian 32-byte format.
#[must_use]
pub fn ed25519() -> TwistedEdwardsCurve {
    // p = 2^255 − 19
    let p = from_hex("7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFED");
    // a = −1 mod p = p − 1
    let a = p.sub_ref(&BigUint::one());
    // d = −121665/121666 mod p  (the specific constant from RFC 8032)
    let d = from_hex("52036CEE 2B6FFE73 8CC74079 7779E898 00700A4D 4141D8AB 75EB4DCA 135978A3");
    // n = 2^252 + 27742317777372353535851937790883648493
    //   (the prime order of the Ed25519 base-point subgroup, called ℓ in RFC 8032)
    let n = from_hex("10000000 00000000 00000000 00000000 14DEF9DE A2F79CD6 5812631A 5CF5D3ED");
    // Base point G = (Gx, Gy)
    // Gy = 4/5 mod p; Gx is the positive (even) square root derived from Gy.
    let gx = from_hex("216936D3 CD6E53FE C0A4E231 FDD6DC5C 692CC760 9525A7B2 C9562D60 8F25D51A");
    let gy = from_hex("6666666666666666 66666666666666666666666666666666 6666666666666658");
    TwistedEdwardsCurve::new(p, a, d, n, gx, gy)
        .expect("Ed25519 parameters are well-formed")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_base_point_on_curve() {
        let curve = ed25519();
        let g = curve.base_point();
        assert!(
            curve.is_on_curve(&g),
            "Ed25519 base point G must satisfy −x² + y² = 1 + d·x²·y²"
        );
    }

    #[test]
    fn ed25519_double_equals_add_self() {
        let curve = ed25519();
        let g = curve.base_point();
        let via_double = curve.double(&g);
        let via_add = curve.add(&g, &g);
        assert_eq!(via_double, via_add, "2G via double must equal G+G via add");
        assert!(curve.is_on_curve(&via_double), "2G must lie on Ed25519");
    }

    #[test]
    fn ed25519_scalar_mul_matches_repeated_add() {
        // 4G via scalar_mul must equal 2G + 2G.
        let curve = ed25519();
        let g = curve.base_point();
        let four_g_scalar = curve.scalar_mul(&g, &BigUint::from_u64(4));
        let two_g = curve.double(&g);
        let four_g_add = curve.add(&two_g, &two_g);
        assert_eq!(four_g_scalar, four_g_add, "4G via scalar_mul must equal 2G+2G");
    }

    #[test]
    fn ed25519_order_times_base_point_is_neutral() {
        // n·G = neutral element by definition of the subgroup order.
        let curve = ed25519();
        let g = curve.base_point();
        let n = curve.n.clone();
        let result = curve.scalar_mul(&g, &n);
        assert!(result.is_neutral(), "n·G must be the neutral element for Ed25519");
    }

    #[test]
    fn ed25519_negation_sums_to_neutral() {
        // P + (−P) = neutral.
        let curve = ed25519();
        let g = curve.base_point();
        let neg_g = curve.negate(&g);
        let sum = curve.add(&g, &neg_g);
        assert!(sum.is_neutral(), "G + (−G) must be the neutral element");
    }

    #[test]
    fn ed25519_encode_decode_roundtrip() {
        let curve = ed25519();
        let g = curve.base_point();
        let encoded = curve.encode_point(&g);
        assert_eq!(encoded.len(), 32, "Ed25519 encoding must be 32 bytes");
        let decoded = curve
            .decode_point(&encoded)
            .expect("decode must succeed for the standard base point");
        assert_eq!(decoded, g, "encode/decode must be the identity");
    }

    #[test]
    fn ed25519_encode_decode_2g_roundtrip() {
        let curve = ed25519();
        let two_g = curve.double(&curve.base_point());
        let encoded = curve.encode_point(&two_g);
        let decoded = curve.decode_point(&encoded).expect("decode 2G");
        assert_eq!(decoded, two_g);
    }

    #[test]
    fn ed25519_neutral_encodes_correctly() {
        let curve = ed25519();
        let neutral = EdwardsPoint::neutral();
        let enc = curve.encode_point(&neutral);
        // Neutral is (0, 1); encoding is LE(1) = 01 00 00 ... 00 (32 bytes).
        assert_eq!(enc[0], 0x01, "first byte of neutral encoding must be 1 (LE)");
        assert!(enc[1..].iter().all(|&b| b == 0), "remaining bytes of neutral must be 0");
    }

    #[test]
    fn ed25519_neutral_roundtrip_preserves_identity() {
        let curve = ed25519();
        let neutral = EdwardsPoint::neutral();
        let enc = curve.encode_point(&neutral);
        let dec = curve.decode_point(&enc).expect("decode neutral");
        assert!(dec.is_neutral(), "decode_point must preserve the neutral element");
    }

    #[test]
    fn ed25519_decode_rejects_bad_length() {
        let curve = ed25519();
        let g = curve.base_point();
        let mut enc = curve.encode_point(&g);
        enc.pop();
        assert!(curve.decode_point(&enc).is_none(), "truncated encoding must be rejected");
    }

    #[test]
    fn ed25519_ecdh_shared_secret_agrees() {
        use crate::CtrDrbgAes256;

        let curve = ed25519();
        let mut rng = CtrDrbgAes256::new(&[0xcd; 48]);

        let (d_a, q_a) = curve.generate_keypair(&mut rng);
        let (d_b, q_b) = curve.generate_keypair(&mut rng);

        let shared_a = curve.diffie_hellman(&d_a, &q_b);
        let shared_b = curve.diffie_hellman(&d_b, &q_a);
        assert_eq!(shared_a, shared_b, "ECDH shared points must agree");
        assert!(!shared_a.is_neutral(), "ECDH shared point must not be neutral");
        assert!(curve.is_on_curve(&shared_a), "ECDH shared point must lie on Ed25519");
    }

    #[test]
    fn ed25519_scalar_invert_roundtrip() {
        let curve = ed25519();
        let k = BigUint::from_u64(0x1234_5678_abcd_ef01);
        let k_inv = curve.scalar_invert(&k).expect("k is non-zero");
        let product = BigUint::mod_mul(&k, &k_inv, &curve.n);
        assert_eq!(product, BigUint::one(), "k * k⁻¹ must equal 1 mod n");
    }
}
