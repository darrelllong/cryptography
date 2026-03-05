//! Elliptic-curve arithmetic over short-Weierstrass prime-field curves.
//!
//! Supported curve form:
//!
//! ```math
//! y^2 = x^3 + ax + b  \pmod{p}
//! ```
//!
//! where `p` is prime and the curve parameters `(a, b, n, h, G)` define a
//! subgroup of prime order `n` with cofactor `h`.
//!
//! This module is the arithmetic substrate for elliptic-curve public-key
//! schemes such as `ECDH`, `ECDSA`, and `EC-ElGamal`. It provides:
//!
//! - [`CurveParams`] — curve parameters with precomputed field and scalar
//!   Montgomery contexts.
//! - [`AffinePoint`] — a curve point in affine `(x, y)` coordinates, or `∞`.
//! - Named-curve constructors: [`p256`], [`p384`], [`secp256k1`].
//! - SEC 1 byte encoding and decoding for uncompressed and compressed points.
//! - Random scalar sampling and ECDH shared-point computation.
//!
//! ## Coordinate system
//!
//! All scalar multiplications use Jacobian projective coordinates `(X : Y : Z)`
//! internally to avoid a costly field inversion on every intermediate step.
//! The affine point `(x, y)` maps to `(x·Z², y·Z³, Z)` for any `Z ≠ 0`.  A
//! single inversion converts the final result back to affine.
//!
//! ## Field arithmetic
//!
//! Field operations delegate to the same [`MontgomeryCtx`] that backs RSA,
//! `ElGamal`, and `DSA` elsewhere in the crate.  [`CurveParams`] stores one
//! `MontgomeryCtx` for the field prime `p` (used in point arithmetic) and one
//! for the subgroup order `n` (used in scalar arithmetic), both pre-built at
//! construction time.
//!
//! ## Side-channel note
//!
//! The scalar multiplication in this module uses a left-to-right double-and-add
//! loop and is **not constant-time**.  Branches and memory accesses depend on
//! the secret scalar, so the current implementation is unsuitable in an
//! adversarial environment where a side-channel attacker can observe timing or
//! power consumption.  A constant-time Montgomery ladder should replace the
//! loop before exposing scalar multiplication to such an environment.

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::gf2m::{gf2m_add, gf2m_half_trace, gf2m_inv, gf2m_mul, gf2m_sq};
use crate::public_key::primes::{mod_inverse, random_nonzero_below};
use crate::Csprng;

// ─── Core types ─────────────────────────────────────────────────────────────

/// Discriminates between prime-field and binary-extension-field arithmetic.
///
/// Prime-field curves use Montgomery arithmetic via [`MontgomeryCtx`].
/// Binary-field curves use polynomial arithmetic over `GF(2^m)`; `poly` is the
/// irreducible polynomial encoded as a `BigUint` bit-pattern and `degree` is
/// its degree `m`.
#[derive(Clone, Debug)]
pub(crate) enum FieldCtx {
    /// Short-Weierstrass curve over a prime field `F_p`.
    Prime(MontgomeryCtx),
    /// Short-Weierstrass curve over a binary extension field GF(2^m).
    Binary {
        /// Irreducible polynomial of degree `degree`, encoded as a `BigUint`.
        poly: BigUint,
        /// Degree of the extension, i.e. m in GF(2^m).
        degree: usize,
    },
}

/// Parameters for a short-Weierstrass elliptic curve y² = x³ + ax + b (mod p).
///
/// All coordinates and coefficients are ordinary residues in `[0, p)`.  The
/// two `MontgomeryCtx` fields are pre-built at construction and shared by
/// every arithmetic operation on the curve.
///
/// A `CurveParams` value is relatively large (two Montgomery contexts plus six
/// `BigUint`s) but heap-allocated and cheap to clone once built.
#[derive(Clone, Debug)]
pub struct CurveParams {
    /// Field prime — all point coordinates are reduced modulo `p`.
    pub p: BigUint,
    /// Curve coefficient `a` in `F_p`.
    pub a: BigUint,
    /// Curve coefficient `b` in `F_p`.
    pub b: BigUint,
    /// Prime order of the base-point subgroup.
    pub n: BigUint,
    /// Cofactor `h`.  For all named curves here `h = 1`.
    pub h: u64,
    /// x-coordinate of the standard base point `G`.
    pub gx: BigUint,
    /// y-coordinate of the standard base point `G`.
    pub gy: BigUint,
    /// Field context: Montgomery arithmetic for prime fields, polynomial
    /// arithmetic for binary extension fields.
    ///
    /// For prime curves, this holds a precomputed [`MontgomeryCtx`] for
    /// arithmetic mod `p`.  For binary curves, this holds the irreducible
    /// polynomial and degree; `p` stores the polynomial as a bit-pattern.
    pub(crate) field: FieldCtx,
    /// Precomputed Montgomery context for scalar arithmetic mod `n`.
    ///
    /// This is kept alongside the field context because scalar-field helpers
    /// (signatures, Diffie-Hellman, and related protocols) need the same
    /// modulus repeatedly even when a particular module is not using it yet.
    pub(crate) _scalar: MontgomeryCtx,
    /// Byte length of a field element: `⌈p.bits() / 8⌉`.
    ///
    /// Used for fixed-length point encoding; coordinates are zero-padded to
    /// this length so that every encoded coordinate has the same width.
    pub coord_len: usize,
}

/// An affine curve point, or the point at infinity.
///
/// The coordinates are ordinary residues in `[0, p)`.  The point at infinity
/// is the group identity: `P + ∞ = P` and `n·G = ∞`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinePoint {
    /// x-coordinate.  Meaningful only when `!infinity`.
    pub x: BigUint,
    /// y-coordinate.  Meaningful only when `!infinity`.
    pub y: BigUint,
    /// `true` when this represents the point at infinity (the group identity).
    pub infinity: bool,
}

/// Jacobian projective coordinates `(X : Y : Z)`.
///
/// The affine point `(x, y)` corresponds to `(X, Y, Z)` with `x = X/Z²` and
/// `y = Y/Z³`, for any non-zero `Z`.  This representation eliminates field
/// inversions in every intermediate addition and doubling step; a single
/// inversion recovers affine coordinates at the end.  The point at infinity
/// is represented with `Z = 0`.
struct JacobianPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

// ─── AffinePoint ────────────────────────────────────────────────────────────

impl AffinePoint {
    /// The group identity (point at infinity).
    #[must_use]
    pub fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            infinity: true,
        }
    }

    /// A finite affine point `(x, y)`.
    ///
    /// The caller is responsible for ensuring that `(x, y)` lies on the
    /// intended curve; use [`CurveParams::is_on_curve`] to validate.
    #[must_use]
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    /// Return `true` if this is the point at infinity.
    #[must_use]
    pub fn is_infinity(&self) -> bool {
        self.infinity
    }
}

// ─── JacobianPoint ──────────────────────────────────────────────────────────

impl JacobianPoint {
    /// The point at infinity in Jacobian form (`Z = 0`).
    fn infinity() -> Self {
        // X and Y are irrelevant when Z = 0; set them to 1 to avoid allocating
        // limb vectors unnecessarily.
        Self {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Lift an affine point to Jacobian coordinates with `Z = 1`.
    ///
    /// Setting `Z = 1` means `X = x·1² = x` and `Y = y·1³ = y`, so the
    /// Jacobian coordinates are just the affine coordinates unchanged.
    fn from_affine(p: &AffinePoint) -> Self {
        if p.infinity {
            return Self::infinity();
        }
        Self {
            x: p.x.clone(),
            y: p.y.clone(),
            z: BigUint::one(),
        }
    }

    /// Project back to affine coordinates.
    ///
    /// Recovers `x = X/Z²` and `y = Y/Z³` by computing the field inverse of
    /// `Z` via Fermat's little theorem: `Z⁻¹ = Z^{p−2} mod p` (valid because
    /// `p` is prime).  This is the only modular exponentiation (and therefore
    /// the only costly operation) that the scalar-multiplication loop pays per
    /// call; every intermediate step uses inversion-free Jacobian arithmetic.
    fn to_affine(&self, curve: &CurveParams) -> AffinePoint {
        if self.is_infinity() {
            return AffinePoint::infinity();
        }
        // Fast path: if Z = 1 (as set by from_affine) no inversion is needed.
        if self.z == BigUint::one() {
            return AffinePoint::new(self.x.clone(), self.y.clone());
        }

        let ctx = curve.prime_ctx();
        let p = &curve.p;

        // z_inv = Z^{p-2} mod p  (Fermat inversion over a prime field)
        let p_minus_2 = p.sub_ref(&BigUint::from_u64(2));
        let z_inv = ctx.pow(&self.z, &p_minus_2);

        // z_inv2 = Z^{-2}  and  z_inv3 = Z^{-3}
        let z_inv2 = ctx.square(&z_inv);
        let z_inv3 = ctx.mul(&z_inv2, &z_inv);

        let x = ctx.mul(&self.x, &z_inv2);
        let y = ctx.mul(&self.y, &z_inv3);

        AffinePoint::new(x, y)
    }
}

// ─── Field helpers ──────────────────────────────────────────────────────────

/// `(a + b) mod p`.
///
/// Both inputs must be in `[0, p)`.  The sum is at most `2p − 2`, so at most
/// one subtraction is needed to reduce back into `[0, p)`.
#[inline]
fn field_add(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let sum = a.add_ref(b);
    if &sum >= p {
        sum.sub_ref(p)
    } else {
        sum
    }
}

/// `(a − b) mod p`.
///
/// Both inputs must be in `[0, p)`.
#[inline]
fn field_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        a.sub_ref(b)
    } else {
        // a < b: result = p − (b − a).  Since both are in [0, p), the
        // difference b − a is in (0, p), and p − (b − a) is in (0, p).
        p.sub_ref(&b.sub_ref(a))
    }
}

/// `(−a) mod p`.
#[inline]
fn field_neg(a: &BigUint, p: &BigUint) -> BigUint {
    if a.is_zero() {
        BigUint::zero()
    } else {
        p.sub_ref(a)
    }
}

/// Pad `bytes` to `len` bytes by prepending zero bytes.
///
/// `BigUint::to_be_bytes` strips leading zero bytes; point encoding needs
/// fixed-width coordinates so that every field element occupies the same
/// number of bytes regardless of its value.
fn pad_to(bytes: Vec<u8>, len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes;
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

// ─── Point arithmetic ───────────────────────────────────────────────────────

/// Point doubling in Jacobian coordinates.
///
/// Uses the general short-Weierstrass doubling formulas from the Explicit
/// Formulas Database (Hankerson–Menezes–Vanstone, Guide to ECC, §3.2.2):
///
/// ```text
/// A  = 4·X·Y²
/// B  = 3·X² + a·Z⁴
/// X' = B² − 2·A
/// Y' = B·(A − X') − 8·Y⁴
/// Z' = 2·Y·Z
/// ```
///
/// This handles any curve coefficient `a`, including the common `a = −3` of
/// the NIST curves (no special case is needed for `a = −3` for correctness,
/// though a specialised formula would be marginally faster).
fn point_double_jacobian(curve: &CurveParams, p: &JacobianPoint) -> JacobianPoint {
    if p.is_infinity() {
        return JacobianPoint::infinity();
    }

    let ctx = curve.prime_ctx();
    let m = &curve.p;

    // Y² and Y⁴
    let y2 = ctx.square(&p.y);
    let y4 = ctx.square(&y2);

    // A = 4·X·Y²
    let xy2 = ctx.mul(&p.x, &y2);
    let two_xy2 = field_add(&xy2, &xy2, m);
    let a = field_add(&two_xy2, &two_xy2, m);

    // X²; Z² and Z⁴
    let x2 = ctx.square(&p.x);
    let z2 = ctx.square(&p.z);
    let z4 = ctx.square(&z2);

    // B = 3·X² + a·Z⁴
    let three_x2 = field_add(&field_add(&x2, &x2, m), &x2, m);
    let a_coeff_z4 = ctx.mul(&curve.a, &z4);
    let b = field_add(&three_x2, &a_coeff_z4, m);

    // X' = B² − 2·A
    let b2 = ctx.square(&b);
    let two_a = field_add(&a, &a, m);
    let x_new = field_sub(&b2, &two_a, m);

    // Y' = B·(A − X') − 8·Y⁴
    let a_minus_x = field_sub(&a, &x_new, m);
    let b_times = ctx.mul(&b, &a_minus_x);
    let two_y4 = field_add(&y4, &y4, m);
    let four_y4 = field_add(&two_y4, &two_y4, m);
    let eight_y4 = field_add(&four_y4, &four_y4, m);
    let y_new = field_sub(&b_times, &eight_y4, m);

    // Z' = 2·Y·Z
    let yz = ctx.mul(&p.y, &p.z);
    let z_new = field_add(&yz, &yz, m);

    JacobianPoint {
        x: x_new,
        y: y_new,
        z: z_new,
    }
}

/// Point addition in Jacobian coordinates.
///
/// Uses the standard complete-Jacobian formulas (EFD `add-2007-bl`):
///
/// ```text
/// U₁ = X₁·Z₂²,   U₂ = X₂·Z₁²
/// S₁ = Y₁·Z₂³,   S₂ = Y₂·Z₁³
/// H  = U₂ − U₁,  R  = S₂ − S₁
/// X₃ = R² − H³ − 2·U₁·H²
/// Y₃ = R·(U₁·H² − X₃) − S₁·H³
/// Z₃ = H·Z₁·Z₂
/// ```
///
/// The `H = 0` branch handles both the doubling case (`R = 0` too, meaning
/// `P₁ = P₂`) and the point-at-infinity case (`R ≠ 0`, meaning `P₁ = −P₂`).
fn point_add_jacobian(
    curve: &CurveParams,
    p1: &JacobianPoint,
    p2: &JacobianPoint,
) -> JacobianPoint {
    if p1.is_infinity() {
        return JacobianPoint {
            x: p2.x.clone(),
            y: p2.y.clone(),
            z: p2.z.clone(),
        };
    }
    if p2.is_infinity() {
        return JacobianPoint {
            x: p1.x.clone(),
            y: p1.y.clone(),
            z: p1.z.clone(),
        };
    }

    let ctx = curve.prime_ctx();
    let m = &curve.p;

    let z1_2 = ctx.square(&p1.z);
    let z2_2 = ctx.square(&p2.z);
    let z1_3 = ctx.mul(&z1_2, &p1.z);
    let z2_3 = ctx.mul(&z2_2, &p2.z);

    let u1 = ctx.mul(&p1.x, &z2_2);
    let u2 = ctx.mul(&p2.x, &z1_2);
    let s1 = ctx.mul(&p1.y, &z2_3);
    let s2 = ctx.mul(&p2.y, &z1_3);

    let h = field_sub(&u2, &u1, m);
    let r = field_sub(&s2, &s1, m);

    if h.is_zero() {
        return if r.is_zero() {
            // P₁ = P₂: use the doubling formula instead of the addition
            // formula (which has a division by H = 0 and would give garbage).
            point_double_jacobian(curve, p1)
        } else {
            // P₁ = −P₂: the sum is the point at infinity.
            JacobianPoint::infinity()
        };
    }

    let h2 = ctx.square(&h);
    let h3 = ctx.mul(&h2, &h);
    let u1h2 = ctx.mul(&u1, &h2);

    // X₃ = R² − H³ − 2·U₁·H²
    let r2 = ctx.square(&r);
    let two_u1h2 = field_add(&u1h2, &u1h2, m);
    let x3 = field_sub(&field_sub(&r2, &h3, m), &two_u1h2, m);

    // Y₃ = R·(U₁·H² − X₃) − S₁·H³
    let u1h2_minus_x3 = field_sub(&u1h2, &x3, m);
    let r_term = ctx.mul(&r, &u1h2_minus_x3);
    let s1h3 = ctx.mul(&s1, &h3);
    let y3 = field_sub(&r_term, &s1h3, m);

    // Z₃ = H·Z₁·Z₂
    let hz1 = ctx.mul(&h, &p1.z);
    let z3 = ctx.mul(&hz1, &p2.z);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Scalar multiplication `k·P` via left-to-right binary double-and-add.
///
/// The loop stays in Jacobian coordinates from start to finish and converts
/// back to affine exactly once at the end, paying one field inversion instead
/// of one per bit.
///
/// **Side-channel note**: branching in the inner loop depends on the bit value
/// of `k`.  This is not constant-time; see the module-level note.
fn scalar_mul_jacobian(curve: &CurveParams, point: &AffinePoint, k: &BigUint) -> AffinePoint {
    if k.is_zero() || point.is_infinity() {
        return AffinePoint::infinity();
    }

    let mut result = JacobianPoint::infinity();
    let p_jac = JacobianPoint::from_affine(point);

    // Scan from the most-significant bit down to bit 0.
    for i in (0..k.bits()).rev() {
        result = point_double_jacobian(curve, &result);
        if k.bit(i) {
            result = point_add_jacobian(curve, &result, &p_jac);
        }
    }

    result.to_affine(curve)
}

// ─── Binary-curve affine arithmetic ─────────────────────────────────────────

/// On-curve check for binary Weierstrass curves: `y² + xy = x³ + ax² + b`.
fn is_on_curve_binary(
    x: &BigUint,
    y: &BigUint,
    a: &BigUint,
    b: &BigUint,
    poly: &BigUint,
    degree: usize,
) -> bool {
    // lhs = y² + x·y
    let y2 = gf2m_sq(y, poly, degree);
    let xy = gf2m_mul(x, y, poly, degree);
    let lhs = gf2m_add(&y2, &xy);
    // rhs = x³ + a·x² + b
    let x2 = gf2m_sq(x, poly, degree);
    let x3 = gf2m_mul(x, &x2, poly, degree);
    let ax2 = gf2m_mul(a, &x2, poly, degree);
    let rhs = gf2m_add(&gf2m_add(&x3, &ax2), b);
    lhs == rhs
}

/// Point addition for binary Weierstrass curves in affine coordinates.
///
/// Uses the standard formula for P ≠ Q, neither at infinity (Hankerson et al.,
/// §3.1):
/// ```text
/// λ = (yP + yQ) / (xP + xQ)
/// xR = λ² + λ + xP + xQ + a
/// yR = λ(xP + xR) + xR + yP
/// ```
fn add_binary(
    p: &AffinePoint,
    q: &AffinePoint,
    a: &BigUint,
    poly: &BigUint,
    degree: usize,
) -> AffinePoint {
    if p.is_infinity() {
        return q.clone();
    }
    if q.is_infinity() {
        return p.clone();
    }

    let x1 = &p.x;
    let y1 = &p.y;
    let x2 = &q.x;
    let y2 = &q.y;

    let dx = gf2m_add(x1, x2);
    if dx.is_zero() {
        // x1 = x2: either P = Q (double) or Q = −P (sum = ∞).
        let dy = gf2m_add(y1, y2);
        return if dy.is_zero() {
            // y1 = y2 and x1 = x2 → P = Q.
            double_binary(p, a, poly, degree)
        } else {
            // Q = −P (since −P = (xP, xP ⊕ yP), so xP ⊕ yP = yQ when xP = xQ
            // and the sum is the identity).
            AffinePoint::infinity()
        };
    }

    // λ = (y1 + y2) / (x1 + x2)
    let dy = gf2m_add(y1, y2);
    let dx_inv = gf2m_inv(&dx, poly, degree).expect("dx is non-zero");
    let lambda = gf2m_mul(&dy, &dx_inv, poly, degree);

    // xR = λ² + λ + x1 + x2 + a
    let lambda_sq = gf2m_sq(&lambda, poly, degree);
    let mut xr = gf2m_add(&lambda_sq, &lambda);
    xr.bitxor_assign(x1);
    xr.bitxor_assign(x2);
    xr.bitxor_assign(a);

    // yR = λ(x1 + xR) + xR + y1
    let x1_xr = gf2m_add(x1, &xr);
    let lambda_term = gf2m_mul(&lambda, &x1_xr, poly, degree);
    let mut yr = gf2m_add(&lambda_term, &xr);
    yr.bitxor_assign(y1);

    AffinePoint::new(xr, yr)
}

/// Point doubling for binary Weierstrass curves in affine coordinates.
///
/// Uses the standard formula for P ≠ O, xP ≠ 0 (Hankerson et al., §3.1):
/// ```text
/// λ = xP + yP / xP
/// xR = λ² + λ + a
/// yR = xP² + (λ + 1)·xR
/// ```
///
/// If `xP = 0` then `2P = ∞` (P is its own inverse).
fn double_binary(p: &AffinePoint, a: &BigUint, poly: &BigUint, degree: usize) -> AffinePoint {
    if p.is_infinity() {
        return AffinePoint::infinity();
    }
    if p.x.is_zero() {
        // xP = 0 implies −P = (0, yP) = P, so 2P = ∞.
        return AffinePoint::infinity();
    }

    let x1 = &p.x;
    let y1 = &p.y;

    // λ = x1 + y1 / x1
    let x1_inv = gf2m_inv(x1, poly, degree).expect("x is non-zero");
    let y1_over_x1 = gf2m_mul(y1, &x1_inv, poly, degree);
    let lambda = gf2m_add(x1, &y1_over_x1);

    // xR = λ² + λ + a
    let lambda_sq = gf2m_sq(&lambda, poly, degree);
    let mut xr = gf2m_add(&lambda_sq, &lambda);
    xr.bitxor_assign(a);

    // yR = x1² + (λ + 1)·xR
    let x1_sq = gf2m_sq(x1, poly, degree);
    let lambda_plus_1 = gf2m_add(&lambda, &BigUint::one());
    let lambda_plus_1_xr = gf2m_mul(&lambda_plus_1, &xr, poly, degree);
    let yr = gf2m_add(&x1_sq, &lambda_plus_1_xr);

    AffinePoint::new(xr, yr)
}

/// Scalar multiplication for binary curves using left-to-right double-and-add
/// in affine coordinates (no Jacobian optimisation).
fn scalar_mul_binary(curve: &CurveParams, point: &AffinePoint, k: &BigUint) -> AffinePoint {
    if k.is_zero() || point.is_infinity() {
        return AffinePoint::infinity();
    }

    let mut result = AffinePoint::infinity();
    for i in (0..k.bits()).rev() {
        result = curve.double(&result);
        if k.bit(i) {
            result = curve.add(&result, point);
        }
    }
    result
}

// ─── CurveParams ────────────────────────────────────────────────────────────

impl CurveParams {
    /// Construct curve parameters from raw field values.
    ///
    /// Returns `None` if the field prime `p` or subgroup order `n` is even,
    /// which would prevent building a Montgomery context.  Well-formed
    /// cryptographic curves always have an odd prime field and odd prime order,
    /// so `None` indicates a programming error in the caller.
    #[must_use]
    pub fn new(
        field_prime: BigUint,
        curve_a: BigUint,
        curve_b: BigUint,
        subgroup_order: BigUint,
        cofactor: u64,
        base_x: BigUint,
        base_y: BigUint,
    ) -> Option<Self> {
        let field = MontgomeryCtx::new(&field_prime)?;
        let scalar = MontgomeryCtx::new(&subgroup_order)?;
        let coord_len = field_prime.bits().div_ceil(8);
        Some(Self {
            p: field_prime,
            a: curve_a,
            b: curve_b,
            n: subgroup_order,
            h: cofactor,
            gx: base_x,
            gy: base_y,
            field: FieldCtx::Prime(field),
            _scalar: scalar,
            coord_len,
        })
    }

    /// Construct binary-curve parameters for a short-Weierstrass curve over
    /// GF(2^m): `y² + xy = x³ + ax² + b`.
    ///
    /// - `poly` is the irreducible polynomial of degree `degree`, encoded as a
    ///   `BigUint` bit-pattern.
    /// - `n` must be an odd prime (the scalar-field Montgomery context
    ///   requires this).
    ///
    /// Returns `None` if `n` is even (which would indicate malformed curve
    /// parameters).
    #[must_use]
    pub fn new_binary(
        modulus_poly: BigUint,
        degree: usize,
        curve_a: BigUint,
        curve_b: BigUint,
        subgroup_order: BigUint,
        cofactor: u64,
        base_point: (BigUint, BigUint),
    ) -> Option<Self> {
        let (base_x, base_y) = base_point;
        let scalar = MontgomeryCtx::new(&subgroup_order)?;
        let coord_len = degree.div_ceil(8);
        let field_prime = modulus_poly.clone();
        Some(Self {
            p: field_prime,
            a: curve_a,
            b: curve_b,
            n: subgroup_order,
            h: cofactor,
            gx: base_x,
            gy: base_y,
            field: FieldCtx::Binary {
                poly: modulus_poly,
                degree,
            },
            _scalar: scalar,
            coord_len,
        })
    }

    /// Return a reference to the prime-field Montgomery context.
    ///
    /// # Panics
    ///
    /// Panics if called on a binary-curve `CurveParams`.  Internal callers
    /// must only invoke this from code paths that are gated on
    /// `FieldCtx::Prime`.
    fn prime_ctx(&self) -> &MontgomeryCtx {
        match &self.field {
            FieldCtx::Prime(ctx) => ctx,
            FieldCtx::Binary { .. } => {
                panic!("prime_ctx called on a binary-field curve")
            }
        }
    }

    /// Return the field degree `m` if this is a binary-extension-field curve,
    /// or `None` for a prime-field curve.
    #[must_use]
    pub fn gf2m_degree(&self) -> Option<usize> {
        match &self.field {
            FieldCtx::Binary { degree, .. } => Some(*degree),
            FieldCtx::Prime(_) => None,
        }
    }

    /// The standard base point `G = (Gx, Gy)`.
    #[must_use]
    pub fn base_point(&self) -> AffinePoint {
        AffinePoint::new(self.gx.clone(), self.gy.clone())
    }

    /// Return `true` if `point` lies on this curve.
    ///
    /// For prime-field curves verifies `y² ≡ x³ + ax + b (mod p)`.
    /// For binary-field curves verifies `y² + xy = x³ + ax² + b` in GF(2^m).
    /// The point at infinity trivially passes.
    #[must_use]
    pub fn is_on_curve(&self, point: &AffinePoint) -> bool {
        if point.infinity {
            return true;
        }
        match &self.field {
            FieldCtx::Prime(ctx) => {
                // lhs = y²
                let lhs = ctx.square(&point.y);
                // rhs = x³ + a·x + b
                let x2 = ctx.square(&point.x);
                let x3 = ctx.mul(&x2, &point.x);
                let ax = ctx.mul(&self.a, &point.x);
                let rhs = field_add(&field_add(&x3, &ax, &self.p), &self.b, &self.p);
                lhs == rhs
            }
            FieldCtx::Binary { poly, degree } => {
                is_on_curve_binary(&point.x, &point.y, &self.a, &self.b, poly, *degree)
            }
        }
    }

    /// Negate a point.
    ///
    /// Prime curves: `(x, y)` → `(x, −y mod p)`.
    /// Binary curves: `(x, y)` → `(x, x ⊕ y)` (since −1 = 1 in GF(2)).
    #[must_use]
    pub fn negate(&self, point: &AffinePoint) -> AffinePoint {
        if point.infinity {
            return point.clone();
        }
        match &self.field {
            FieldCtx::Prime(_) => AffinePoint::new(point.x.clone(), field_neg(&point.y, &self.p)),
            FieldCtx::Binary { .. } => {
                // −P = (xP, xP ⊕ yP)
                let neg_y = gf2m_add(&point.x, &point.y);
                AffinePoint::new(point.x.clone(), neg_y)
            }
        }
    }

    /// Add two affine curve points.
    #[must_use]
    pub fn add(&self, p: &AffinePoint, q: &AffinePoint) -> AffinePoint {
        match &self.field {
            FieldCtx::Prime(_) => {
                let pj = JacobianPoint::from_affine(p);
                let qj = JacobianPoint::from_affine(q);
                point_add_jacobian(self, &pj, &qj).to_affine(self)
            }
            FieldCtx::Binary { poly, degree } => add_binary(p, q, &self.a, poly, *degree),
        }
    }

    /// Double an affine curve point (`2P`).
    #[must_use]
    pub fn double(&self, p: &AffinePoint) -> AffinePoint {
        match &self.field {
            FieldCtx::Prime(_) => {
                let pj = JacobianPoint::from_affine(p);
                point_double_jacobian(self, &pj).to_affine(self)
            }
            FieldCtx::Binary { poly, degree } => double_binary(p, &self.a, poly, *degree),
        }
    }

    /// Scalar multiplication `k·P`.
    ///
    /// Returns the point at infinity when `k = 0` or `P = ∞`.
    #[must_use]
    pub fn scalar_mul(&self, point: &AffinePoint, k: &BigUint) -> AffinePoint {
        match &self.field {
            FieldCtx::Prime(_) => scalar_mul_jacobian(self, point, k),
            FieldCtx::Binary { .. } => scalar_mul_binary(self, point, k),
        }
    }

    /// Compute the ECDH shared point `d·Q`.
    ///
    /// In Diffie-Hellman, Alice holds private scalar `d` and receives Bob's
    /// public point `Q = d_B·G`; the shared secret is the x-coordinate of
    /// `d·Q = d·d_B·G`.
    #[must_use]
    pub fn diffie_hellman(
        &self,
        private_scalar: &BigUint,
        public_point: &AffinePoint,
    ) -> AffinePoint {
        self.scalar_mul(public_point, private_scalar)
    }

    /// Sample a uniform random scalar in `[1, n)`.
    ///
    /// This is the standard private-key range for ECDH and ECDSA.  The scalar
    /// is sampled by rejection sampling over the `n`-bit range, which is the
    /// FIPS 186-5 recommended method.
    ///
    /// # Panics
    ///
    /// Panics only if the curve order `n` is malformed (`n <= 1`), which would
    /// indicate a bug in the curve parameters.
    pub fn random_scalar<R: Csprng>(&self, rng: &mut R) -> BigUint {
        // random_nonzero_below returns None only if n ≤ 1, which cannot happen
        // for any valid cryptographic curve.
        random_nonzero_below(rng, &self.n)
            .expect("curve order n is always > 1 for any valid cryptographic curve")
    }

    /// Generate a random key pair `(d, Q)` where `Q = d·G`.
    ///
    /// Returns `(private_scalar, public_point)`.
    ///
    /// # Panics
    ///
    /// Panics only if the curve parameters are malformed in a way that makes
    /// [`random_scalar`][Self::random_scalar] fail.
    pub fn generate_keypair<R: Csprng>(&self, rng: &mut R) -> (BigUint, AffinePoint) {
        let d = self.random_scalar(rng);
        let q = self.scalar_mul(&self.base_point(), &d);
        (d, q)
    }

    /// Compute `k⁻¹ mod n` (modular inverse of a scalar modulo the subgroup order).
    ///
    /// Used in ECDSA signing.  Returns `None` if `k = 0` (which the caller
    /// must prevent; a zero nonce breaks ECDSA signing regardless).
    #[must_use]
    pub fn scalar_invert(&self, k: &BigUint) -> Option<BigUint> {
        mod_inverse(k, &self.n)
    }

    /// Encode a point as an uncompressed SEC 1 byte string.
    ///
    /// Format: `04 || x (coord_len bytes big-endian) || y (coord_len bytes big-endian)`.
    ///
    /// The leading `04` tag is the SEC 1 v2.0 uncompressed-point identifier.
    /// The total length is `1 + 2·coord_len` bytes.  The point at infinity
    /// encodes as the single byte `00`.
    #[must_use]
    pub fn encode_point(&self, point: &AffinePoint) -> Vec<u8> {
        if point.infinity {
            return vec![0x00];
        }
        let mut out = Vec::with_capacity(1 + 2 * self.coord_len);
        out.push(0x04);
        out.extend_from_slice(&pad_to(point.x.to_be_bytes(), self.coord_len));
        out.extend_from_slice(&pad_to(point.y.to_be_bytes(), self.coord_len));
        out
    }

    /// Encode a point in compressed SEC 1 form.
    ///
    /// Prime curves: format `02 || x` if `y` is even, `03 || x` if `y` is odd.
    /// Binary curves: format `02 || x` if LSB(y·x⁻¹) = 0, `03 || x` otherwise
    /// (per FIPS 186-4 §4.3.6; falls back to `02` when `x = 0`).
    ///
    /// The point at infinity encodes as `00`.
    ///
    /// # Panics
    ///
    /// Panics only if an internal binary-field invariant is violated after the
    /// explicit `x = 0` guard, which would indicate a bug in the compression
    /// logic.
    #[must_use]
    pub fn encode_point_compressed(&self, point: &AffinePoint) -> Vec<u8> {
        if point.infinity {
            return vec![0x00];
        }
        let parity = match &self.field {
            FieldCtx::Prime(_) => point.y.is_odd(),
            FieldCtx::Binary { poly, degree } => {
                if point.x.is_zero() {
                    false
                } else {
                    let x_inv =
                        gf2m_inv(&point.x, poly, *degree).expect("x is non-zero in binary curve");
                    let z = gf2m_mul(&point.y, &x_inv, poly, *degree);
                    z.is_odd()
                }
            }
        };
        let tag = if parity { 0x03u8 } else { 0x02u8 };
        let mut out = Vec::with_capacity(1 + self.coord_len);
        out.push(tag);
        out.extend_from_slice(&pad_to(point.x.to_be_bytes(), self.coord_len));
        out
    }

    /// Decode an uncompressed or compressed SEC 1 point.
    ///
    /// Returns `None` for any of:
    /// - wrong byte length for the tag,
    /// - unrecognised tag byte,
    /// - coordinates that fail the on-curve check,
    /// - prime-field compressed encoding on a curve with `p ≢ 3 (mod 4)`,
    /// - binary-field compressed encoding with an invalid x-coordinate.
    #[must_use]
    pub fn decode_point(&self, bytes: &[u8]) -> Option<AffinePoint> {
        if bytes == [0x00] {
            return Some(AffinePoint::infinity());
        }
        match bytes.first()? {
            0x04 => {
                // Uncompressed: 1 + 2·coord_len bytes (same for prime and binary).
                let expected_len = 1 + 2 * self.coord_len;
                if bytes.len() != expected_len {
                    return None;
                }
                let coord_bytes = &bytes[1..];
                let x = BigUint::from_be_bytes(&coord_bytes[..self.coord_len]);
                let y = BigUint::from_be_bytes(&coord_bytes[self.coord_len..]);
                let pt = AffinePoint::new(x, y);
                if self.is_on_curve(&pt) {
                    Some(pt)
                } else {
                    None
                }
            }
            tag @ (0x02 | 0x03) => {
                // Compressed: 1 + coord_len bytes.
                let expected_len = 1 + self.coord_len;
                if bytes.len() != expected_len {
                    return None;
                }
                let x = BigUint::from_be_bytes(&bytes[1..]);
                let odd_tag = *tag == 0x03;
                match &self.field {
                    FieldCtx::Prime(_) => {
                        let y = self.field_sqrt_from_x(&x, odd_tag)?;
                        Some(AffinePoint::new(x, y))
                    }
                    FieldCtx::Binary { poly, degree } => {
                        self.decompress_binary_point(&x, odd_tag, poly, *degree)
                    }
                }
            }
            _ => None,
        }
    }

    /// Recover a binary-curve y-coordinate from a compressed x and parity bit.
    ///
    /// Uses the standard FIPS 186-4 decompression algorithm:
    /// 1. Compute β = x + a + b·x⁻² in GF(2^m).
    /// 2. Solve z² + z = β via the half-trace (valid for odd m and Tr(β) = 0).
    /// 3. Recover y = z·x; select z or z+1 based on `odd_z` (LSB of y·x⁻¹).
    /// 4. Verify the point lies on the curve.
    fn decompress_binary_point(
        &self,
        x: &BigUint,
        odd_z: bool,
        poly: &BigUint,
        degree: usize,
    ) -> Option<AffinePoint> {
        if x.is_zero() {
            // x = 0 implies 2P = ∞; decompression for this edge case requires
            // a field square root which we omit (not used by any FIPS base point).
            return None;
        }
        // β = x + a + b·x⁻²
        let x_inv = gf2m_inv(x, poly, degree)?;
        let x_inv2 = gf2m_sq(&x_inv, poly, degree);
        let b_x_inv2 = gf2m_mul(&self.b, &x_inv2, poly, degree);
        let beta = gf2m_add(&gf2m_add(x, &self.a), &b_x_inv2);

        // Solve z² + z = β.
        let z0 = gf2m_half_trace(&beta, poly, degree);
        // The two solutions differ by 1; choose by LSB parity.
        let z = if z0.is_odd() == odd_z {
            z0
        } else {
            gf2m_add(&z0, &BigUint::one())
        };

        let y = gf2m_mul(&z, x, poly, degree);
        let pt = AffinePoint::new(x.clone(), y);
        if self.is_on_curve(&pt) {
            Some(pt)
        } else {
            None
        }
    }

    /// Recover the `y`-coordinate from `x` using the curve equation, selecting
    /// the root with the requested parity.
    ///
    /// For a prime `p ≡ 3 (mod 4)`, the square root of `u mod p` is
    /// `u^{(p+1)/4} mod p` — a single modular exponentiation.  This covers
    /// P-256, P-384, and secp256k1 (all have `p ≡ 3 mod 4`).
    ///
    /// Returns `None` if `x` produces no square root in `F_p` (the `x`
    /// coordinate is not on the curve) or if `p ≢ 3 (mod 4)`.
    fn field_sqrt_from_x(&self, x: &BigUint, odd_y: bool) -> Option<BigUint> {
        let ctx = self.prime_ctx();

        // Curve equation: rhs = x³ + a·x + b (mod p).
        let x2 = ctx.square(x);
        let x3 = ctx.mul(&x2, x);
        let ax = ctx.mul(&self.a, x);
        let rhs = field_add(&field_add(&x3, &ax, &self.p), &self.b, &self.p);

        // Verify p ≡ 3 (mod 4) so the exponent (p+1)/4 is an integer.
        if self.p.rem_u64(4) != 3 {
            return None;
        }
        let exp = {
            let p_plus_1 = self.p.add_ref(&BigUint::one());
            // (p + 1) / 4 is an integer because p ≡ 3 (mod 4) implies
            // p + 1 ≡ 0 (mod 4).
            let (q, _) = p_plus_1.div_rem(&BigUint::from_u64(4));
            q
        };

        let y_candidate = ctx.pow(&rhs, &exp);

        // Verify that the candidate is actually a square root (not every x
        // has a square root mod p; about half do).
        if ctx.square(&y_candidate) != rhs {
            return None;
        }

        // Select the root with the requested parity.
        let y = if y_candidate.is_odd() == odd_y {
            y_candidate
        } else {
            field_neg(&y_candidate, &self.p)
        };
        Some(y)
    }
}

// ─── Named curves ────────────────────────────────────────────────────────────

/// Parse a compact hexadecimal string (spaces ignored) into a `BigUint`.
///
/// Used only for named-curve constant construction; panics on invalid input,
/// which would indicate a bug in the constant tables below.
fn from_hex(hex: &str) -> BigUint {
    // Strip spaces so the hex strings in the constants below can be written
    // as the familiar 8-nibble groups that match the NIST/SEC 2 specifications.
    let cleaned: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(
        cleaned.len().is_multiple_of(2),
        "hex string must have even length: {cleaned}"
    );
    let bytes: Vec<u8> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex digit"))
        .collect();
    BigUint::from_be_bytes(&bytes)
}

/// NIST P-256 (secp256r1).
///
/// References: NIST FIPS 186-5, SEC 2 v2.0 §2.4.2.
///
/// Curve equation: y² = x³ − 3x + b  (mod p), equivalently a = p − 3.
///
/// Security level: ~128-bit classical, ~64-bit quantum (Grover).
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn p256() -> CurveParams {
    // p = 2^256 − 2^224 + 2^192 + 2^96 − 1
    let p = from_hex(
        "FFFFFFFF 00000001 00000000 00000000 \
         00000000 FFFFFFFF FFFFFFFF FFFFFFFF",
    );
    // a = p − 3 (the NIST P-curves use a = −3 for an efficient doubling formula)
    let a = from_hex(
        "FFFFFFFF 00000001 00000000 00000000 \
         00000000 FFFFFFFF FFFFFFFF FFFFFFFC",
    );
    let b = from_hex(
        "5AC635D8 AA3A93E7 B3EBBD55 769886BC \
         651D06B0 CC53B0F6 3BCE3C3E 27D2604B",
    );
    // n = prime order of the base-point subgroup
    let n = from_hex(
        "FFFFFFFF 00000000 FFFFFFFF FFFFFFFF \
         BCE6FAAD A7179E84 F3B9CAC2 FC632551",
    );
    let gx = from_hex(
        "6B17D1F2 E12C4247 F8BCE6E5 63A440F2 \
         77037D81 2DEB33A0 F4A13945 D898C296",
    );
    let gy = from_hex(
        "4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 \
         2BCE3357 6B315ECE CBB64068 37BF51F5",
    );
    CurveParams::new(p, a, b, n, 1, gx, gy).expect("P-256 parameters are well-formed")
}

/// NIST P-384 (secp384r1).
///
/// References: NIST FIPS 186-5, SEC 2 v2.0 §2.5.1.
///
/// Curve equation: y² = x³ − 3x + b  (mod p).
///
/// Security level: ~192-bit classical, ~96-bit quantum (Grover).
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn p384() -> CurveParams {
    // p = 2^384 − 2^128 − 2^96 + 2^32 − 1
    let p = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE \
         FFFFFFFF 00000000 00000000 FFFFFFFF",
    );
    // a = p − 3
    let a = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE \
         FFFFFFFF 00000000 00000000 FFFFFFFC",
    );
    let b = from_hex(
        "B3312FA7 E23EE7E4 988E056B E3F82D19 \
         181D9C6E FE814112 0314088F 5013875A \
         C656398D 8A2ED19D 2A85C8ED D3EC2AEF",
    );
    let n = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF C7634D81 F4372DDF \
         581A0DB2 48B0A77A ECEC196A CCC52973",
    );
    let gx = from_hex(
        "AA87CA22 BE8B0537 8EB1C71E F320AD74 \
         6E1D3B62 8BA79B98 59F741E0 82542A38 \
         5502F25D BF55296C 3A545E38 72760AB7",
    );
    let gy = from_hex(
        "3617DE4A 96262C6F 5D9E98BF 9292DC29 \
         F8F41DBD 289A147C E9DA3113 B5F0B8C0 \
         0A60B1CE 1D7E819D 7A431D7C 90EA0E5F",
    );
    CurveParams::new(p, a, b, n, 1, gx, gy).expect("P-384 parameters are well-formed")
}

/// Koblitz curve secp256k1.
///
/// Reference: SEC 2 v2.0 §2.4.1.  Used by Bitcoin, Ethereum, and related
/// protocols.
///
/// Curve equation: y² = x³ + 7  (mod p), i.e. a = 0, b = 7.
///
/// Security level: ~128-bit classical, ~64-bit quantum (Grover).
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn secp256k1() -> CurveParams {
    // p = 2^256 − 2^32 − 2^9 − 2^8 − 2^7 − 2^6 − 2^4 − 1
    let p = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F",
    );
    // a = 0: the curve has no linear term, giving a particularly fast doubling
    // formula (the 3·X² + a·Z⁴ term reduces to just 3·X²).
    let a = BigUint::zero();
    // b = 7
    let b = BigUint::from_u64(7);
    let n = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE \
         BAAEDCE6 AF48A03B BFD25E8C D0364141",
    );
    let gx = from_hex(
        "79BE667E F9DCBBAC 55A06295 CE870B07 \
         029BFCDB 2DCE28D9 59F2815B 16F81798",
    );
    let gy = from_hex(
        "483ADA77 26A3C465 5DA4FBFC 0E1108A8 \
         FD17B448 A6855419 9C47D08F FB10D4B8",
    );
    CurveParams::new(p, a, b, n, 1, gx, gy).expect("secp256k1 parameters are well-formed")
}

/// NIST P-192 (secp192r1).
///
/// Reference: NIST FIPS 186-5.  Largely superseded by P-256 in modern
/// deployments, but still encountered in legacy systems and TLS stacks.
///
/// Curve equation: y² = x³ − 3x + b  (mod p).
///
/// Security level: ~96-bit classical, ~48-bit quantum (Grover).
///
/// Note: p ≡ 3 (mod 4), so compressed-point decoding is supported.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn p192() -> CurveParams {
    // p = 2^192 − 2^64 − 1
    let p = from_hex("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFF");
    // a = p − 3
    let a = from_hex("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFC");
    let b = from_hex("64210519 E59C80E7 0FA7E9AB 72243049 FEB8DEEC C146B9B1");
    let n = from_hex("FFFFFFFF FFFFFFFF FFFFFFFF 99DEF836 146BC9B1 B4D22831");
    let gx = from_hex("188DA80E B03090F6 7CBF20EB 43A18800 F4FF0AFD 82FF1012");
    let gy = from_hex("07192B95 FFC8DA78 631011ED 6B24CDD5 73F977A1 1E794811");
    CurveParams::new(p, a, b, n, 1, gx, gy).expect("P-192 parameters are well-formed")
}

/// NIST P-224 (secp224r1).
///
/// Reference: NIST FIPS 186-5.  A 224-bit curve that offers ~112-bit
/// classical security.
///
/// Curve equation: y² = x³ − 3x + b  (mod p).
///
/// **Note**: p ≡ 1 (mod 4) for P-224, so the fast Blum-modulus square-root
/// shortcut used by [`CurveParams::decode_point`] for compressed points is
/// unavailable.  Compressed-point encoding still works; decoding returns
/// `None`.  Use uncompressed encoding for P-224 interoperability.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn p224() -> CurveParams {
    // p = 2^224 − 2^96 + 1
    let p = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         00000000 00000000 00000001",
    );
    // a = p − 3
    let a = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE \
         FFFFFFFF FFFFFFFF FFFFFFFE",
    );
    let b = from_hex(
        "B4050A85 0C04B3AB F5413256 5044B0B7 \
         D7BFD8BA 270B3943 2355FFB4",
    );
    let n = from_hex(
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFF16A2 \
         E0B8F03E 13DD2945 5C5C2A3D",
    );
    let gx = from_hex(
        "B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 \
         56C21122 343280D6 115C1D21",
    );
    let gy = from_hex(
        "BD376388 B5F723FB 4C22DFE6 CD4375A0 \
         5A074764 44D58199 85007E34",
    );
    CurveParams::new(p, a, b, n, 1, gx, gy).expect("P-224 parameters are well-formed")
}

/// NIST P-521 (secp521r1).
///
/// References: NIST FIPS 186-5, SEC 2 v2.0 §2.6.1.
///
/// The field prime is the Mersenne prime 2^521 − 1.  At ~256-bit classical
/// security it is the highest-security NIST curve and is used in
/// applications demanding long-term security.
///
/// Curve equation: y² = x³ − 3x + b  (mod p).
///
/// Note: p ≡ 3 (mod 4) (since 2^521 − 1 ≡ −1 ≡ 3 mod 4), so compressed
/// point decoding is supported.  Field elements and coordinates occupy 66
/// bytes (521 bits rounds up to 66 bytes).
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn p521() -> CurveParams {
    // p = 2^521 − 1  (a Mersenne prime: one leading bit, 65 bytes of 0xFF)
    let p = from_hex(
        "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF",
    );
    // a = p − 3
    let a = from_hex(
        "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC",
    );
    let b = from_hex(
        "0051 953EB961 8E1C9A1F 929A21A0 B68540EE \
         A2DA725B 99B315F3 B8B48991 8EF109E1 \
         56193951 EC7E937B 1652C0BD 3BB1BF07 \
         3573DF88 3D2C34F1 EF451FD4 6B503F00",
    );
    let n = from_hex(
        "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
         FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFA \
         51868783 BF2F966B 7FCC0148 F709A5D0 \
         3BB5C9B8 899C47AE BB6FB71E 91386409",
    );
    let gx = from_hex(
        "00C6 858E06B7 0404E9CD 9E3ECB66 2395B442 \
         9C648139 053FB521 F828AF60 6B4D3DBA \
         A14B5E77 EFE75928 FE1DC127 A2FFA8DE \
         3348B3C1 856A429B F97E7E31 C2E5BD66",
    );
    let gy = from_hex(
        "0118 39296A78 9A3BC004 5C8A5FB4 2C7D1BD9 \
         98F54449 579B4468 17AFBD17 273E662C \
         97EE7299 5EF42640 C550B901 3FAD0761 \
         353C7086 A272C240 88BE9476 9FD16650",
    );
    CurveParams::new(p, a, b, n, 1, gx, gy).expect("P-521 parameters are well-formed")
}

// ─── FIPS 186-4 Binary curves ────────────────────────────────────────────────
//
// All ten curves use the binary Weierstrass form y² + xy = x³ + ax² + b over
// GF(2^m).  Parameters are from FIPS 186-4 Appendix D.  The irreducible
// polynomials are:
//
//   GF(2^163): x^163 + x^7  + x^6 + x^3 + 1
//   GF(2^233): x^233 + x^74 + 1
//   GF(2^283): x^283 + x^12 + x^7 + x^5 + 1
//   GF(2^409): x^409 + x^87 + 1
//   GF(2^571): x^571 + x^10 + x^5 + x^2 + 1

/// NIST B-163 (FIPS 186-4 Appendix D.1.2.1).
///
/// Binary Weierstrass curve over GF(2^163).  Security level ~80-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn b163() -> CurveParams {
    let poly = from_hex("0800000000000000000000000000000000000000C9");
    let a = BigUint::one();
    let b = from_hex("020A601907B8C953CA1481EB10512F78744A3205FD");
    let n = from_hex("040000000000000000000292FE77E70C12A4234C33");
    let gx = from_hex("03F0EBA16286A2D57EA0991168D4994637E8343E36");
    let gy = from_hex("00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1");
    CurveParams::new_binary(poly, 163, a, b, n, 2, (gx, gy))
        .expect("B-163 parameters are well-formed")
}

/// NIST K-163 (FIPS 186-4 Appendix D.1.2.2).
///
/// Koblitz binary curve over GF(2^163).  Security level ~80-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn k163() -> CurveParams {
    let poly = from_hex("0800000000000000000000000000000000000000C9");
    let a = BigUint::one();
    let b = BigUint::one();
    let n = from_hex("04000000000000000000020108A2E0CC0D99F8A5EF");
    let gx = from_hex("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8");
    let gy = from_hex("0289070FB05D38FF58321F2E800536D538CCDAA3D9");
    CurveParams::new_binary(poly, 163, a, b, n, 2, (gx, gy))
        .expect("K-163 parameters are well-formed")
}

/// NIST B-233 (FIPS 186-4 Appendix D.1.2.3).
///
/// Binary Weierstrass curve over GF(2^233).  Security level ~112-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn b233() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [233, 74, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::one();
    let b = from_hex("0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD");
    let n = from_hex("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7");
    let gx = from_hex("00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B");
    let gy = from_hex("01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052");
    CurveParams::new_binary(poly, 233, a, b, n, 2, (gx, gy))
        .expect("B-233 parameters are well-formed")
}

/// NIST K-233 (FIPS 186-4 Appendix D.1.2.4).
///
/// Koblitz binary curve over GF(2^233).  Security level ~112-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn k233() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [233, 74, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::zero();
    let b = BigUint::one();
    let n = from_hex("008000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF");
    let gx = from_hex("017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126");
    let gy = from_hex("01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3");
    CurveParams::new_binary(poly, 233, a, b, n, 4, (gx, gy))
        .expect("K-233 parameters are well-formed")
}

/// NIST B-283 (FIPS 186-4 Appendix D.1.2.5).
///
/// Binary Weierstrass curve over GF(2^283).  Security level ~128-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn b283() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [283, 12, 7, 5, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::one();
    let b = from_hex("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5");
    let n = from_hex("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307");
    let gx = from_hex("05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053");
    let gy = from_hex("03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4");
    CurveParams::new_binary(poly, 283, a, b, n, 2, (gx, gy))
        .expect("B-283 parameters are well-formed")
}

/// NIST K-283 (FIPS 186-4 Appendix D.1.2.6).
///
/// Koblitz binary curve over GF(2^283).  Security level ~128-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn k283() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [283, 12, 7, 5, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::zero();
    let b = BigUint::one();
    let n = from_hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61");
    let gx = from_hex("0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836");
    let gy = from_hex("01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259");
    CurveParams::new_binary(poly, 283, a, b, n, 4, (gx, gy))
        .expect("K-283 parameters are well-formed")
}

/// NIST B-409 (FIPS 186-4 Appendix D.1.2.7).
///
/// Binary Weierstrass curve over GF(2^409).  Security level ~192-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn b409() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [409, 87, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::one();
    let b = from_hex(
        "0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
    );
    let n = from_hex(
        "010000000000000000000000000000000000000000000000012F7B6E4B64E2C26F2B04E76B1B9D77B6CCBB99EE3A7BCED5CB4ECB",
    );
    let gx = from_hex(
        "015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7",
    );
    let gy = from_hex(
        "0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706",
    );
    CurveParams::new_binary(poly, 409, a, b, n, 2, (gx, gy))
        .expect("B-409 parameters are well-formed")
}

/// NIST K-409 (FIPS 186-4 Appendix D.1.2.8).
///
/// Koblitz binary curve over GF(2^409).  Security level ~192-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn k409() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [409, 87, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::zero();
    let b = BigUint::one();
    let n = from_hex(
        "007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
    );
    let gx = from_hex(
        "0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746",
    );
    let gy = from_hex(
        "01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
    );
    CurveParams::new_binary(poly, 409, a, b, n, 4, (gx, gy))
        .expect("K-409 parameters are well-formed")
}

/// NIST B-571 (FIPS 186-4 Appendix D.1.2.9).
///
/// Binary Weierstrass curve over GF(2^571).  Security level ~256-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn b571() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [571, 10, 5, 2, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::one();
    let b = from_hex(
        "02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
    );
    let n = from_hex(
        "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
    );
    let gx = from_hex(
        "0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19",
    );
    let gy = from_hex(
        "037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B",
    );
    CurveParams::new_binary(poly, 571, a, b, n, 2, (gx, gy))
        .expect("B-571 parameters are well-formed")
}

/// NIST K-571 (FIPS 186-4 Appendix D.1.2.10).
///
/// Koblitz binary curve over GF(2^571).  Security level ~256-bit classical.
///
/// # Panics
///
/// Panics only if the embedded curve constants are malformed, which would
/// indicate a bug in this module.
#[must_use]
pub fn k571() -> CurveParams {
    let mut poly = BigUint::zero();
    for bit in [571, 10, 5, 2, 0] {
        poly.set_bit(bit);
    }
    let a = BigUint::zero();
    let b = BigUint::one();
    let n = from_hex(
        "020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
    );
    let gx = from_hex(
        "026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972",
    );
    let gy = from_hex(
        "0349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3",
    );
    CurveParams::new_binary(poly, 571, a, b, n, 4, (gx, gy))
        .expect("K-571 parameters are well-formed")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── P-256 ──────────────────────────────────────────────────────────────

    #[test]
    fn p256_base_point_on_curve() {
        let curve = p256();
        let g = curve.base_point();
        assert!(
            curve.is_on_curve(&g),
            "P-256 base point G must satisfy y² = x³ + ax + b"
        );
    }

    #[test]
    fn p256_double_equals_add_self() {
        // 2G computed via doubling must equal G + G computed via addition.
        let curve = p256();
        let g = curve.base_point();
        let via_double = curve.double(&g);
        let via_add = curve.add(&g, &g);
        assert_eq!(
            via_double, via_add,
            "2G via double must equal G+G via add for P-256"
        );
        assert!(curve.is_on_curve(&via_double), "2G must lie on P-256");
    }

    #[test]
    fn p256_scalar_mul_matches_repeated_add() {
        // 4G via scalar_mul must equal 2G + 2G via add.
        let curve = p256();
        let g = curve.base_point();
        let four_g_scalar = curve.scalar_mul(&g, &BigUint::from_u64(4));
        let two_g = curve.double(&g);
        let four_g_add = curve.add(&two_g, &two_g);
        assert_eq!(
            four_g_scalar, four_g_add,
            "4G via scalar_mul must equal 2G+2G"
        );
    }

    #[test]
    fn p256_order_times_base_point_is_infinity() {
        // n·G = ∞ by definition of the subgroup order.
        let curve = p256();
        let g = curve.base_point();
        let n = curve.n.clone();
        let result = curve.scalar_mul(&g, &n);
        assert!(
            result.is_infinity(),
            "n·G must be the point at infinity for P-256"
        );
    }

    #[test]
    fn p256_negation_sums_to_infinity() {
        // P + (−P) = ∞.
        let curve = p256();
        let g = curve.base_point();
        let neg_g = curve.negate(&g);
        let sum = curve.add(&g, &neg_g);
        assert!(sum.is_infinity(), "G + (−G) must be the point at infinity");
    }

    #[test]
    fn p256_encode_decode_uncompressed_roundtrip() {
        let curve = p256();
        let g = curve.base_point();
        let encoded = curve.encode_point(&g);
        let decoded = curve
            .decode_point(&encoded)
            .expect("decode must succeed for a valid point");
        assert_eq!(
            decoded, g,
            "uncompressed encode/decode must be the identity"
        );
    }

    #[test]
    fn p256_encode_decode_compressed_roundtrip() {
        let curve = p256();
        let g = curve.base_point();
        let encoded = curve.encode_point_compressed(&g);
        let decoded = curve
            .decode_point(&encoded)
            .expect("compressed decode must succeed");
        assert_eq!(decoded, g, "compressed encode/decode must be the identity");
    }

    #[test]
    fn p256_infinity_encodes_as_single_zero_byte() {
        let curve = p256();
        let inf = AffinePoint::infinity();
        let enc = curve.encode_point(&inf);
        assert_eq!(enc, vec![0x00]);
        let dec = curve.decode_point(&enc).expect("decode of infinity");
        assert!(dec.is_infinity());
    }

    #[test]
    fn p256_decode_rejects_bad_length() {
        let curve = p256();
        let g = curve.base_point();
        let mut enc = curve.encode_point(&g);
        enc.pop(); // truncate by one byte
        assert!(
            curve.decode_point(&enc).is_none(),
            "truncated encoding must be rejected"
        );
    }

    #[test]
    fn p256_decode_rejects_off_curve_point() {
        let curve = p256();
        // Start with a valid uncompressed encoding and corrupt the y coordinate.
        let g = curve.base_point();
        let mut enc = curve.encode_point(&g);
        let last = enc.last_mut().unwrap();
        *last ^= 0xff; // flip the low byte of y
        assert!(
            curve.decode_point(&enc).is_none(),
            "off-curve point must be rejected"
        );
    }

    // ── P-384 ──────────────────────────────────────────────────────────────

    #[test]
    fn p384_base_point_on_curve() {
        let curve = p384();
        assert!(curve.is_on_curve(&curve.base_point()));
    }

    #[test]
    fn p384_double_equals_add_self() {
        let curve = p384();
        let g = curve.base_point();
        assert_eq!(curve.double(&g), curve.add(&g, &g));
    }

    #[test]
    fn p384_order_times_base_point_is_infinity() {
        let curve = p384();
        let n = curve.n.clone();
        let result = curve.scalar_mul(&curve.base_point(), &n);
        assert!(result.is_infinity());
    }

    // ── secp256k1 ──────────────────────────────────────────────────────────

    #[test]
    fn secp256k1_base_point_on_curve() {
        let curve = secp256k1();
        assert!(curve.is_on_curve(&curve.base_point()));
    }

    #[test]
    fn secp256k1_double_equals_add_self() {
        let curve = secp256k1();
        let g = curve.base_point();
        assert_eq!(curve.double(&g), curve.add(&g, &g));
    }

    #[test]
    fn secp256k1_order_times_base_point_is_infinity() {
        let curve = secp256k1();
        let n = curve.n.clone();
        let result = curve.scalar_mul(&curve.base_point(), &n);
        assert!(result.is_infinity());
    }

    #[test]
    fn secp256k1_encode_decode_compressed_roundtrip() {
        let curve = secp256k1();
        let g = curve.base_point();
        let enc = curve.encode_point_compressed(&g);
        let dec = curve.decode_point(&enc).expect("decode must succeed");
        assert_eq!(dec, g);
    }

    // ── ECDH smoke test ────────────────────────────────────────────────────

    #[test]
    fn p256_ecdh_shared_secret_agrees() {
        use crate::CtrDrbgAes256;

        let curve = p256();
        let mut rng = CtrDrbgAes256::new(&[0xab; 48]);

        let (d_a, q_a) = curve.generate_keypair(&mut rng);
        let (d_b, q_b) = curve.generate_keypair(&mut rng);

        // Both parties should derive the same shared point.
        let shared_a = curve.diffie_hellman(&d_a, &q_b);
        let shared_b = curve.diffie_hellman(&d_b, &q_a);
        assert_eq!(shared_a, shared_b, "ECDH shared points must agree");
        assert!(
            !shared_a.is_infinity(),
            "ECDH shared point must not be infinity"
        );
        assert!(
            curve.is_on_curve(&shared_a),
            "ECDH shared point must lie on the curve"
        );
    }

    // ── scalar_invert ──────────────────────────────────────────────────────

    // ── P-192 ──────────────────────────────────────────────────────────────

    #[test]
    fn p192_base_point_on_curve() {
        let curve = p192();
        assert!(curve.is_on_curve(&curve.base_point()));
    }

    #[test]
    fn p192_double_equals_add_self() {
        let curve = p192();
        let g = curve.base_point();
        assert_eq!(curve.double(&g), curve.add(&g, &g));
    }

    #[test]
    fn p192_encode_decode_uncompressed_roundtrip() {
        let curve = p192();
        let g = curve.base_point();
        let enc = curve.encode_point(&g);
        let dec = curve.decode_point(&enc).expect("P-192 uncompressed decode");
        assert_eq!(dec, g);
    }

    #[test]
    fn p192_encode_decode_compressed_roundtrip() {
        let curve = p192();
        let g = curve.base_point();
        let enc = curve.encode_point_compressed(&g);
        let dec = curve.decode_point(&enc).expect("P-192 compressed decode");
        assert_eq!(dec, g);
    }

    // ── P-224 ──────────────────────────────────────────────────────────────

    #[test]
    fn p224_base_point_on_curve() {
        let curve = p224();
        assert!(curve.is_on_curve(&curve.base_point()));
    }

    #[test]
    fn p224_double_equals_add_self() {
        let curve = p224();
        let g = curve.base_point();
        assert_eq!(curve.double(&g), curve.add(&g, &g));
    }

    #[test]
    fn p224_uncompressed_roundtrip() {
        // P-224 has p ≡ 1 (mod 4); only uncompressed encoding is supported.
        let curve = p224();
        let g = curve.base_point();
        let enc = curve.encode_point(&g);
        let dec = curve.decode_point(&enc).expect("P-224 uncompressed decode");
        assert_eq!(dec, g);
    }

    #[test]
    fn p224_compressed_decode_returns_none() {
        // Compressed decoding is intentionally unsupported for P-224.
        let curve = p224();
        let enc = curve.encode_point_compressed(&curve.base_point());
        assert!(
            curve.decode_point(&enc).is_none(),
            "P-224 compressed decoding must return None (p ≡ 1 mod 4)"
        );
    }

    // ── P-521 ──────────────────────────────────────────────────────────────

    #[test]
    fn p521_base_point_on_curve() {
        let curve = p521();
        assert!(curve.is_on_curve(&curve.base_point()));
    }

    #[test]
    fn p521_double_equals_add_self() {
        let curve = p521();
        let g = curve.base_point();
        assert_eq!(curve.double(&g), curve.add(&g, &g));
    }

    #[test]
    fn p521_encode_decode_compressed_roundtrip() {
        let curve = p521();
        let g = curve.base_point();
        let enc = curve.encode_point_compressed(&g);
        let dec = curve.decode_point(&enc).expect("P-521 compressed decode");
        assert_eq!(dec, g);
    }

    // ── scalar_invert ──────────────────────────────────────────────────────

    #[test]
    fn p256_scalar_invert_roundtrip() {
        // k * k⁻¹ ≡ 1 (mod n)
        let curve = p256();
        let k = BigUint::from_u64(0x1234_5678_9abc_def0);
        let k_inv = curve
            .scalar_invert(&k)
            .expect("k is non-zero and coprime with n");
        // Verify: k * k_inv mod n == 1
        let product = BigUint::mod_mul(&k, &k_inv, &curve.n);
        assert_eq!(product, BigUint::one(), "k * k⁻¹ must equal 1 mod n");
    }

    // ── Binary curves — base-point on-curve ───────────────────────────────

    macro_rules! binary_base_point_on_curve {
        ($name:ident, $constructor:ident) => {
            #[test]
            fn $name() {
                let curve = $constructor();
                let g = curve.base_point();
                assert!(
                    curve.is_on_curve(&g),
                    "{} base point must satisfy y² + xy = x³ + ax² + b",
                    stringify!($constructor)
                );
            }
        };
    }

    binary_base_point_on_curve!(b163_base_point_on_curve, b163);
    binary_base_point_on_curve!(k163_base_point_on_curve, k163);
    binary_base_point_on_curve!(b233_base_point_on_curve, b233);
    binary_base_point_on_curve!(k233_base_point_on_curve, k233);
    binary_base_point_on_curve!(b283_base_point_on_curve, b283);
    binary_base_point_on_curve!(k283_base_point_on_curve, k283);
    binary_base_point_on_curve!(b409_base_point_on_curve, b409);
    binary_base_point_on_curve!(k409_base_point_on_curve, k409);
    binary_base_point_on_curve!(b571_base_point_on_curve, b571);
    binary_base_point_on_curve!(k571_base_point_on_curve, k571);

    // ── Binary curves — double-add consistency ────────────────────────────

    macro_rules! binary_double_add_consistency {
        ($name:ident, $constructor:ident) => {
            #[test]
            fn $name() {
                let curve = $constructor();
                let g = curve.base_point();
                let via_double = curve.double(&g);
                let via_add = curve.add(&g, &g);
                assert_eq!(
                    via_double,
                    via_add,
                    "2G via double must equal G+G via add for {}",
                    stringify!($constructor)
                );
                assert!(
                    curve.is_on_curve(&via_double),
                    "2G must lie on {}",
                    stringify!($constructor)
                );
            }
        };
    }

    binary_double_add_consistency!(b163_double_add_consistency, b163);
    binary_double_add_consistency!(k163_double_add_consistency, k163);
    binary_double_add_consistency!(b233_double_add_consistency, b233);
    binary_double_add_consistency!(k233_double_add_consistency, k233);
    binary_double_add_consistency!(b283_double_add_consistency, b283);
    binary_double_add_consistency!(k283_double_add_consistency, k283);
    // Skip the slow 409/571 curves in base tests; covered by order tests below.

    // ── Binary curves — negation ──────────────────────────────────────────

    #[test]
    fn b163_negation_sums_to_infinity() {
        let curve = b163();
        let g = curve.base_point();
        let neg_g = curve.negate(&g);
        let sum = curve.add(&g, &neg_g);
        assert!(sum.is_infinity(), "G + (-G) must be infinity on B-163");
    }

    #[test]
    fn k163_negation_sums_to_infinity() {
        let curve = k163();
        let g = curve.base_point();
        let neg_g = curve.negate(&g);
        let sum = curve.add(&g, &neg_g);
        assert!(sum.is_infinity(), "G + (-G) must be infinity on K-163");
    }

    // ── Binary curves — order: n·G = ∞ ───────────────────────────────────

    macro_rules! binary_order_test {
        ($name:ident, $constructor:ident) => {
            #[test]
            fn $name() {
                let curve = $constructor();
                let g = curve.base_point();
                let n = curve.n.clone();
                let result = curve.scalar_mul(&g, &n);
                assert!(
                    result.is_infinity(),
                    "n·G must be the point at infinity for {}",
                    stringify!($constructor)
                );
            }
        };
    }

    binary_order_test!(b163_order_times_base_is_infinity, b163);
    binary_order_test!(k163_order_times_base_is_infinity, k163);
    binary_order_test!(b233_order_times_base_is_infinity, b233);
    binary_order_test!(k233_order_times_base_is_infinity, k233);

    // ── Binary curves — encode/decode round-trips ─────────────────────────

    #[test]
    fn b163_encode_decode_uncompressed() {
        let curve = b163();
        let g = curve.base_point();
        let enc = curve.encode_point(&g);
        let dec = curve.decode_point(&enc).expect("B-163 uncompressed decode");
        assert_eq!(dec, g);
    }

    #[test]
    fn k163_encode_decode_uncompressed() {
        let curve = k163();
        let g = curve.base_point();
        let enc = curve.encode_point(&g);
        let dec = curve.decode_point(&enc).expect("K-163 uncompressed decode");
        assert_eq!(dec, g);
    }

    #[test]
    fn b163_encode_decode_compressed() {
        let curve = b163();
        let g = curve.base_point();
        let enc = curve.encode_point_compressed(&g);
        let dec = curve.decode_point(&enc).expect("B-163 compressed decode");
        assert_eq!(dec, g);
    }

    #[test]
    fn k163_encode_decode_compressed() {
        let curve = k163();
        let g = curve.base_point();
        let enc = curve.encode_point_compressed(&g);
        let dec = curve.decode_point(&enc).expect("K-163 compressed decode");
        assert_eq!(dec, g);
    }

    // ── Binary curves — ECDH agreement ───────────────────────────────────

    #[test]
    fn b163_ecdh_shared_secret_agrees() {
        use crate::CtrDrbgAes256;
        let curve = b163();
        let mut rng = CtrDrbgAes256::new(&[0x42; 48]);
        let (da, qa) = curve.generate_keypair(&mut rng);
        let (db, qb) = curve.generate_keypair(&mut rng);
        let shared_a = curve.diffie_hellman(&da, &qb);
        let shared_b = curve.diffie_hellman(&db, &qa);
        assert_eq!(shared_a, shared_b, "B-163 ECDH shared points must agree");
        assert!(!shared_a.is_infinity());
        assert!(curve.is_on_curve(&shared_a));
    }

    #[test]
    fn k283_ecdh_shared_secret_agrees() {
        use crate::CtrDrbgAes256;
        let curve = k283();
        let mut rng = CtrDrbgAes256::new(&[0x7F; 48]);
        let (da, qa) = curve.generate_keypair(&mut rng);
        let (db, qb) = curve.generate_keypair(&mut rng);
        let shared_a = curve.diffie_hellman(&da, &qb);
        let shared_b = curve.diffie_hellman(&db, &qa);
        assert_eq!(shared_a, shared_b, "K-283 ECDH shared points must agree");
        assert!(!shared_a.is_infinity());
    }
}
