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
//! - Named-curve constructors: the NIST prime curves [`p192`], [`p224`],
//!   [`p256`], [`p384`], [`p521`], the Koblitz curve [`secp256k1`], and the
//!   NIST binary curves [`b163`]…[`b571`] and [`k163`]…[`k571`].
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
//! Field operations delegate to the same [`MontgomeryContext`] that backs RSA,
//! `ElGamal`, and `DSA` elsewhere in the crate.  [`CurveParams`] stores one
//! `MontgomeryContext` for the field prime `p` (used in point arithmetic) and one
//! for the subgroup order `n` (used in scalar arithmetic), both pre-built at
//! construction time.
//!
//! ## Side-channel note
//!
//! The scalar multiplication in this module (a fixed 4-bit window over
//! Jacobian coordinates on prime curves, López–Dahab coordinates on binary
//! curves) is **not constant-time**.  Table indices and the number of
//! additions depend on the secret scalar, so the current implementation is
//! unsuitable in an adversarial environment where a side-channel attacker can
//! observe timing or power consumption.  A constant-time ladder should replace
//! it before exposing scalar multiplication to such an environment.

use crate::public_key::primes::{is_probable_prime_untrusted, random_nonzero_below};
use crate::Csprng;
use rump::finite_field::Gf2m;
use rump::modular::{
    mod_inverse, mod_sqrt, MontgomeryContext, MontgomeryResidue, MontgomeryScratch,
};
use rump::BigUint;

// ─── Core types ─────────────────────────────────────────────────────────────

/// Discriminates between prime-field and binary-extension-field arithmetic.
///
/// Prime-field curves use Montgomery arithmetic via [`MontgomeryContext`].
/// Binary-field curves carry a [`Gf2m`] context: the irreducible polynomial
/// with its degree derived from it, and the field arithmetic as methods.
#[derive(Clone, Debug)]
pub(crate) enum FieldCtx {
    /// Short-Weierstrass curve over a prime field `F_p`.
    Prime(PrimeFieldCtx),
    /// Short-Weierstrass curve over a binary extension field GF(2^m).
    Binary(Gf2m),
}

/// Montgomery arithmetic for one prime-field curve.
///
/// Bundles the [`MontgomeryContext`] for `p` with the two residues every
/// Jacobian ladder step needs: the curve coefficient `a` encoded once, and
/// the zero residue so the `Z = 0` infinity test is a plain comparison.
///
/// Every residue in a curve computation comes from this one context, so the
/// `ContextMismatch` the residue operations report is unreachable here; the
/// methods below unwrap it and keep the formulas readable.
#[derive(Clone, Debug)]
pub(crate) struct PrimeFieldCtx {
    /// Montgomery context for arithmetic mod `p`.
    ctx: MontgomeryContext,
    /// Curve coefficient `a`, encoded once into the Montgomery domain.
    a_mont: MontgomeryResidue,
    /// The zero residue of the field.
    zero: MontgomeryResidue,
}

impl PrimeFieldCtx {
    const SAME_CTX: &'static str = "curve residues share the curve's field context";

    fn new(ctx: MontgomeryContext, curve_a: &BigUint) -> Self {
        let a_mont = ctx.to_residue(curve_a);
        let zero = ctx.to_residue(&BigUint::zero());
        Self { ctx, a_mont, zero }
    }

    /// `a·b` in the Montgomery domain, reusing `scratch` across the ladder.
    #[inline]
    fn mul(
        &self,
        a: &MontgomeryResidue,
        b: &MontgomeryResidue,
        scratch: &mut MontgomeryScratch,
    ) -> MontgomeryResidue {
        self.ctx
            .mul_residue_with(a, b, scratch)
            .expect(Self::SAME_CTX)
    }

    /// `a²` in the Montgomery domain, reusing `scratch` across the ladder.
    #[inline]
    fn sqr(&self, a: &MontgomeryResidue, scratch: &mut MontgomeryScratch) -> MontgomeryResidue {
        self.ctx
            .square_residue_with(a, scratch)
            .expect(Self::SAME_CTX)
    }

    /// `a + b` in the Montgomery domain (the encoding is linear).
    #[inline]
    fn add(&self, a: &MontgomeryResidue, b: &MontgomeryResidue) -> MontgomeryResidue {
        self.ctx.add_residue(a, b).expect(Self::SAME_CTX)
    }

    /// `a − b` in the Montgomery domain.
    #[inline]
    fn sub(&self, a: &MontgomeryResidue, b: &MontgomeryResidue) -> MontgomeryResidue {
        self.ctx.sub_residue(a, b).expect(Self::SAME_CTX)
    }

    /// Whether `a` is the zero residue.
    #[inline]
    fn is_zero(&self, a: &MontgomeryResidue) -> bool {
        *a == self.zero
    }

    /// The zero residue of the field.
    #[inline]
    fn zero(&self) -> &MontgomeryResidue {
        &self.zero
    }

    /// The one residue of the field.
    #[inline]
    fn one(&self) -> MontgomeryResidue {
        self.ctx.one()
    }

    /// The curve coefficient `a` as a residue.
    #[inline]
    fn a_mont(&self) -> &MontgomeryResidue {
        &self.a_mont
    }

    /// Encode an ordinary value into the Montgomery domain.
    #[inline]
    fn to_residue(&self, value: &BigUint) -> MontgomeryResidue {
        self.ctx.to_residue(value)
    }

    /// The underlying context, for one-shot arithmetic on ordinary values.
    #[inline]
    fn ctx(&self) -> &MontgomeryContext {
        &self.ctx
    }

    /// Decode a residue back to an ordinary value in `[0, p)`.
    #[inline]
    fn decode(&self, a: &MontgomeryResidue) -> BigUint {
        self.ctx.from_residue(a).expect(Self::SAME_CTX)
    }
}

/// Parameters for a short-Weierstrass elliptic curve y² = x³ + ax + b (mod p).
///
/// All coordinates and coefficients are ordinary residues in `[0, p)`.  The
/// two `MontgomeryContext` fields are pre-built at construction and shared by
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
    /// Cofactor `h`.  The prime curves here have `h = 1`; the binary B/K
    /// curves have `h = 2` or `4`, which is why decoders check subgroup
    /// membership ([`Self::is_valid_public_point`]).
    pub h: u64,
    /// x-coordinate of the standard base point `G`.
    pub gx: BigUint,
    /// y-coordinate of the standard base point `G`.
    pub gy: BigUint,
    /// Field context: Montgomery arithmetic for prime fields, polynomial
    /// arithmetic for binary extension fields.
    ///
    /// For prime curves, this holds a precomputed [`MontgomeryContext`] for
    /// arithmetic mod `p`.  For binary curves, this holds the irreducible
    /// polynomial and degree; `p` stores the polynomial as a bit-pattern.
    pub(crate) field: FieldCtx,
    /// Precomputed Montgomery context for scalar arithmetic mod `n`,
    /// reached through [`Self::scalar_ctx`] by the signature schemes for
    /// their products modulo the subgroup order.
    scalar: MontgomeryContext,
    /// Byte length of a field element: `⌈p.bits() / 8⌉`.
    ///
    /// Used for fixed-length point encoding; coordinates are zero-padded to
    /// this length so that every encoded coordinate has the same width.
    pub coord_len: usize,
}

/// The field of explicit domain parameters, as a serialized key names it:
/// the modulus of a prime field, or the reduction polynomial and degree of a
/// binary field. [`CurveParams::from_explicit`] takes one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplicitField {
    /// `F_p` for the odd prime `p`.
    Prime(BigUint),
    /// `F_2^m` under a reduction polynomial `f(x)` of degree `m`.
    Binary {
        /// `f(x)` as a bit pattern, bit `i` the coefficient of `x^i`.
        modulus: BigUint,
        /// The degree `m` of `f(x)`.
        degree: usize,
    },
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
    x: MontgomeryResidue,
    y: MontgomeryResidue,
    z: MontgomeryResidue,
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
    fn infinity(fld: &PrimeFieldCtx) -> Self {
        // X and Y are irrelevant when Z = 0; the encoded one is already cached
        // on the context.
        Self {
            x: fld.one(),
            y: fld.one(),
            z: fld.zero().clone(),
        }
    }

    fn is_infinity(&self, fld: &PrimeFieldCtx) -> bool {
        fld.is_zero(&self.z)
    }

    /// Lift an affine point to Jacobian coordinates with `Z = 1`, in the
    /// Montgomery domain.
    ///
    /// Every coordinate of a [`JacobianPoint`] is a [`MontgomeryResidue`] so
    /// the add/double formulas run on [`MontgomeryContext::mul_residue`] /
    /// [`MontgomeryContext::square_residue`] — one reduction per multiply, no
    /// per-operation encode/decode — across the whole scalar multiplication.
    /// `X = x·1² = x` and `Y = y·1³ = y`, so encoding `x`, `y`, and the
    /// constant `1` (as `Z`) is all that is required.
    fn from_affine(fld: &PrimeFieldCtx, p: &AffinePoint) -> Self {
        if p.infinity {
            return Self::infinity(fld);
        }
        Self {
            x: fld.to_residue(&p.x),
            y: fld.to_residue(&p.y),
            z: fld.one(),
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
        let fld = curve.prime_field();
        if self.is_infinity(fld) {
            return AffinePoint::infinity();
        }

        let ctx = fld.ctx();
        // Coordinates are Montgomery residues; decode to ordinary residues.
        // The remaining inversion runs in the ordinary domain — it happens
        // once per scalar multiplication, so its cost is negligible next to
        // the add/double loop.
        let x = fld.decode(&self.x);
        let y = fld.decode(&self.y);
        let z = fld.decode(&self.z);

        // Fast path: Z = 1 (as set by from_affine) needs no inversion.
        if z.is_one() {
            return AffinePoint::new(x, y);
        }

        let p = &curve.p;

        // z_inv = Z^{p-2} mod p  (Fermat inversion over a prime field)
        let p_minus_2 = p.sub(&BigUint::from_u64(2));
        let z_inv = ctx.pow(&z, &p_minus_2);

        // z_inv2 = Z^{-2}  and  z_inv3 = Z^{-3}
        let z_inv2 = ctx.square(&z_inv);
        let z_inv3 = ctx.mul(&z_inv2, &z_inv);

        let x_aff = ctx.mul(&x, &z_inv2);
        let y_aff = ctx.mul(&y, &z_inv3);

        AffinePoint::new(x_aff, y_aff)
    }
}

// ─── Field helpers ──────────────────────────────────────────────────────────

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
fn point_double_jacobian(
    fld: &PrimeFieldCtx,
    p: &JacobianPoint,
    scratch: &mut MontgomeryScratch,
) -> JacobianPoint {
    if p.is_infinity(fld) {
        return JacobianPoint::infinity(fld);
    }

    // All coordinates are Montgomery residues: mul/sqr stay in the domain,
    // and add/sub are linear so they carry through unchanged
    // (aR + bR = (a+b)R).

    // Y² and Y⁴
    let y2 = fld.sqr(&p.y, scratch);
    let y4 = fld.sqr(&y2, scratch);

    // A = 4·X·Y²
    let xy2 = fld.mul(&p.x, &y2, scratch);
    let two_xy2 = fld.add(&xy2, &xy2);
    let a = fld.add(&two_xy2, &two_xy2);

    // X²; Z² and Z⁴
    let x2 = fld.sqr(&p.x, scratch);
    let z2 = fld.sqr(&p.z, scratch);
    let z4 = fld.sqr(&z2, scratch);

    // B = 3·X² + a·Z⁴
    let three_x2 = fld.add(&fld.add(&x2, &x2), &x2);
    let a_coeff_z4 = fld.mul(fld.a_mont(), &z4, scratch);
    let b = fld.add(&three_x2, &a_coeff_z4);

    // X' = B² − 2·A
    let b2 = fld.sqr(&b, scratch);
    let two_a = fld.add(&a, &a);
    let x_new = fld.sub(&b2, &two_a);

    // Y' = B·(A − X') − 8·Y⁴
    let a_minus_x = fld.sub(&a, &x_new);
    let b_times = fld.mul(&b, &a_minus_x, scratch);
    let two_y4 = fld.add(&y4, &y4);
    let four_y4 = fld.add(&two_y4, &two_y4);
    let eight_y4 = fld.add(&four_y4, &four_y4);
    let y_new = fld.sub(&b_times, &eight_y4);

    // Z' = 2·Y·Z
    let yz = fld.mul(&p.y, &p.z, scratch);
    let z_new = fld.add(&yz, &yz);

    JacobianPoint {
        x: x_new,
        y: y_new,
        z: z_new,
    }
}

/// Point addition in Jacobian coordinates.
///
/// Uses the Cohen–Miyaji–Ono 1998 Jacobian addition (their formula (5)) in
/// the common-subexpression order the Explicit-Formulas Database lists as
/// `add-1998-cmo-2`, with `HH = H²`, `HHH = H·HH`, and `V = U₁·HH`:
///
/// ```text
/// U₁ = X₁·Z₂²,   U₂ = X₂·Z₁²
/// S₁ = Y₁·Z₂³,   S₂ = Y₂·Z₁³
/// H  = U₂ − U₁,  R  = S₂ − S₁
/// X₃ = R² − HHH − 2·V
/// Y₃ = R·(V − X₃) − S₁·HHH
/// Z₃ = H·Z₁·Z₂
/// ```
///
/// The `H = 0` branch handles both the doubling case (`R = 0` too, meaning
/// `P₁ = P₂`) and the point-at-infinity case (`R ≠ 0`, meaning `P₁ = −P₂`).
fn point_add_jacobian(
    fld: &PrimeFieldCtx,
    p1: &JacobianPoint,
    p2: &JacobianPoint,
    scratch: &mut MontgomeryScratch,
) -> JacobianPoint {
    if p1.is_infinity(fld) {
        return JacobianPoint {
            x: p2.x.clone(),
            y: p2.y.clone(),
            z: p2.z.clone(),
        };
    }
    if p2.is_infinity(fld) {
        return JacobianPoint {
            x: p1.x.clone(),
            y: p1.y.clone(),
            z: p1.z.clone(),
        };
    }

    // Coordinates are Montgomery residues throughout (see `from_affine`):
    // mul/sqr keep the domain, add/sub are linear.

    let z1_2 = fld.sqr(&p1.z, scratch);
    let z2_2 = fld.sqr(&p2.z, scratch);
    let z1_3 = fld.mul(&z1_2, &p1.z, scratch);
    let z2_3 = fld.mul(&z2_2, &p2.z, scratch);

    let u1 = fld.mul(&p1.x, &z2_2, scratch);
    let u2 = fld.mul(&p2.x, &z1_2, scratch);
    let s1 = fld.mul(&p1.y, &z2_3, scratch);
    let s2 = fld.mul(&p2.y, &z1_3, scratch);

    let h = fld.sub(&u2, &u1);
    let r = fld.sub(&s2, &s1);

    if fld.is_zero(&h) {
        return if fld.is_zero(&r) {
            // P₁ = P₂: use the doubling formula instead of the addition
            // formula (which has a division by H = 0 and would give garbage).
            point_double_jacobian(fld, p1, scratch)
        } else {
            // P₁ = −P₂: the sum is the point at infinity.
            JacobianPoint::infinity(fld)
        };
    }

    let h2 = fld.sqr(&h, scratch);
    let h3 = fld.mul(&h2, &h, scratch);
    let u1h2 = fld.mul(&u1, &h2, scratch);

    // X₃ = R² − H³ − 2·U₁·H²
    let r2 = fld.sqr(&r, scratch);
    let two_u1h2 = fld.add(&u1h2, &u1h2);
    let x3 = fld.sub(&fld.sub(&r2, &h3), &two_u1h2);

    // Y₃ = R·(U₁·H² − X₃) − S₁·H³
    let u1h2_minus_x3 = fld.sub(&u1h2, &x3);
    let r_term = fld.mul(&r, &u1h2_minus_x3, scratch);
    let s1h3 = fld.mul(&s1, &h3, scratch);
    let y3 = fld.sub(&r_term, &s1h3);

    // Z₃ = H·Z₁·Z₂
    let hz1 = fld.mul(&h, &p1.z, scratch);
    let z3 = fld.mul(&hz1, &p2.z, scratch);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Fixed window width (in bits) for prime-curve scalar multiplication.
///
/// A 4-bit window uses a 15-entry precomputed table (`1·P … 15·P`) and folds
/// four scalar bits per iteration, cutting the number of point additions from
/// roughly `bits/2` (plain double-and-add) to `bits/4` plus the small
/// precomputation, while keeping the same `bits` doublings.
const PRIME_WINDOW_BITS: usize = 4;

/// Scalar multiplication `k·P` via a left-to-right fixed 4-bit window in
/// Jacobian coordinates.
///
/// The loop stays in Jacobian coordinates from start to finish and converts
/// back to affine exactly once at the end, paying one field inversion for the
/// whole multiplication.  Each window contributes four doublings and at most
/// one addition of a precomputed multiple `d·P` (`1 ≤ d ≤ 15`).
///
/// **Side-channel note**: the table index and the branch that skips zero
/// digits both depend on `k`.  This is not constant-time; see the
/// module-level note.  The result is the unique point `k·P`, hence identical
/// to any correct double-and-add.
fn scalar_mul_jacobian(curve: &CurveParams, point: &AffinePoint, k: &BigUint) -> AffinePoint {
    if k.is_zero() || point.is_infinity() {
        return AffinePoint::infinity();
    }

    let fld = curve.prime_field();
    // One scratch buffer serves every multiply and square in the ladder.
    let mut scratch = MontgomeryScratch::new();

    // Precompute table[d] = d·P for d = 1 … 15 (index 0 is the unused
    // identity slot so that `table[digit]` indexes directly by digit value).
    let table_len = 1usize << PRIME_WINDOW_BITS;
    // table[1] = P; table[d] = table[d-1] + P. (`JacobianPoint` isn't `Clone`,
    // so the base point is re-derived rather than copied — both are `1·P`.)
    let p_jac = JacobianPoint::from_affine(fld, point);
    let mut table: Vec<JacobianPoint> = Vec::with_capacity(table_len);
    table.push(JacobianPoint::infinity(fld));
    table.push(JacobianPoint::from_affine(fld, point));
    for d in 2..table_len {
        let next = point_add_jacobian(fld, &table[d - 1], &p_jac, &mut scratch);
        table.push(next);
    }

    let nbits = k.bits();
    let nwindows = nbits.div_ceil(PRIME_WINDOW_BITS);
    let mut result = JacobianPoint::infinity(fld);

    // Scan windows from most significant to least significant.
    for wi in (0..nwindows).rev() {
        for _ in 0..PRIME_WINDOW_BITS {
            result = point_double_jacobian(fld, &result, &mut scratch);
        }
        // Assemble the window's digit from its PRIME_WINDOW_BITS scalar bits.
        let base = wi * PRIME_WINDOW_BITS;
        let mut digit = 0usize;
        for j in 0..PRIME_WINDOW_BITS {
            if k.bit(base + j) {
                digit |= 1 << j;
            }
        }
        if digit != 0 {
            result = point_add_jacobian(fld, &result, &table[digit], &mut scratch);
        }
    }

    result.to_affine(curve)
}

// ─── Binary-curve affine arithmetic ─────────────────────────────────────────

/// On-curve check for binary Weierstrass curves: `y² + xy = x³ + ax² + b`.
fn is_on_curve_binary(x: &BigUint, y: &BigUint, a: &BigUint, b: &BigUint, field: &Gf2m) -> bool {
    // lhs = y² + x·y
    let y2 = field.square(y);
    let xy = field.mul(x, y);
    let lhs = Gf2m::add(&y2, &xy);
    // rhs = x³ + a·x² + b
    let x2 = field.square(x);
    let x3 = field.mul(x, &x2);
    let ax2 = field.mul(a, &x2);
    let rhs = Gf2m::add(&Gf2m::add(&x3, &ax2), b);
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
fn add_binary(p: &AffinePoint, q: &AffinePoint, a: &BigUint, field: &Gf2m) -> AffinePoint {
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

    let dx = Gf2m::add(x1, x2);
    if dx.is_zero() {
        // x1 = x2: either P = Q (double) or Q = −P (sum = ∞).
        let dy = Gf2m::add(y1, y2);
        return if dy.is_zero() {
            // y1 = y2 and x1 = x2 → P = Q.
            double_binary(p, a, field)
        } else {
            // Q = −P (since −P = (xP, xP ⊕ yP), so xP ⊕ yP = yQ when xP = xQ
            // and the sum is the identity).
            AffinePoint::infinity()
        };
    }

    // λ = (y1 + y2) / (x1 + x2)
    let dy = Gf2m::add(y1, y2);
    let dx_inv = field.inverse(&dx).expect("dx is non-zero");
    let lambda = field.mul(&dy, &dx_inv);

    // xR = λ² + λ + x1 + x2 + a
    let lambda_sq = field.square(&lambda);
    let mut xr = Gf2m::add(&lambda_sq, &lambda);
    xr.bitxor_assign(x1);
    xr.bitxor_assign(x2);
    xr.bitxor_assign(a);

    // yR = λ(x1 + xR) + xR + y1
    let x1_xr = Gf2m::add(x1, &xr);
    let lambda_term = field.mul(&lambda, &x1_xr);
    let mut yr = Gf2m::add(&lambda_term, &xr);
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
fn double_binary(p: &AffinePoint, a: &BigUint, field: &Gf2m) -> AffinePoint {
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
    let x1_inv = field.inverse(x1).expect("x is non-zero");
    let y1_over_x1 = field.mul(y1, &x1_inv);
    let lambda = Gf2m::add(x1, &y1_over_x1);

    // xR = λ² + λ + a
    let lambda_sq = field.square(&lambda);
    let mut xr = Gf2m::add(&lambda_sq, &lambda);
    xr.bitxor_assign(a);

    // yR = x1² + (λ + 1)·xR
    let x1_sq = field.square(x1);
    let lambda_plus_1 = Gf2m::add(&lambda, &BigUint::one());
    let lambda_plus_1_xr = field.mul(&lambda_plus_1, &xr);
    let yr = Gf2m::add(&x1_sq, &lambda_plus_1_xr);

    AffinePoint::new(xr, yr)
}

// ─── Binary-curve López–Dahab projective arithmetic ─────────────────────────

/// López–Dahab projective coordinates `(X : Y : Z)` for binary curves.
///
/// The affine point `(x, y)` corresponds to `(X, Y, Z)` with `x = X/Z` and
/// `y = Y/Z²`, for any non-zero `Z`.  Unlike the affine formulas in
/// [`add_binary`]/[`double_binary`], which each pay a full binary
/// extended-GCD inversion per step, this representation is inversion-free in
/// the inner loop: a whole scalar multiplication needs only one inversion, at
/// the very end, when converting the result back to affine.  The point at
/// infinity is represented with `Z = 0`.
struct LDPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl LDPoint {
    /// The point at infinity in López–Dahab form (`Z = 0`).
    fn infinity() -> Self {
        Self {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Project back to affine coordinates: `x = X/Z`, `y = Y/Z²`.
    ///
    /// This is the single field inversion paid by a whole scalar
    /// multiplication (versus roughly one per ladder step in the affine
    /// formulation).
    fn to_affine(&self, field: &Gf2m) -> AffinePoint {
        if self.is_infinity() {
            return AffinePoint::infinity();
        }
        // Fast path: Z = 1 (a freshly lifted affine point) needs no inversion.
        if self.z.is_one() {
            return AffinePoint::new(self.x.clone(), self.y.clone());
        }
        let z_inv = field
            .inverse(&self.z)
            .expect("Z is non-zero off the identity");
        let z_inv2 = field.square(&z_inv);
        let x = field.mul(&self.x, &z_inv);
        let y = field.mul(&self.y, &z_inv2);
        AffinePoint::new(x, y)
    }
}

/// Point doubling in López–Dahab coordinates on `y² + xy = x³ + ax² + b`.
///
/// Standard formulas (Hankerson–Menezes–Vanstone, *Guide to ECC*, Alg. 3.24):
///
/// ```text
/// Z₃ = X₁²·Z₁²
/// X₃ = X₁⁴ + b·Z₁⁴
/// Y₃ = b·Z₁⁴·Z₃ + X₃·(a·Z₃ + Y₁² + b·Z₁⁴)
/// ```
///
/// When `X₁ = 0` the affine point is 2-torsion (`x = 0`), so `2P = ∞`; this is
/// signalled automatically by `Z₃ = 0`.
fn ld_double(p: &LDPoint, a: &BigUint, b: &BigUint, field: &Gf2m) -> LDPoint {
    if p.is_infinity() {
        return LDPoint::infinity();
    }

    let x1_2 = field.square(&p.x);
    let z1_2 = field.square(&p.z);

    // Z₃ = X₁²·Z₁²
    let z3 = field.mul(&x1_2, &z1_2);
    if z3.is_zero() {
        // X₁ = 0 → affine x = 0 → 2P = ∞.
        return LDPoint::infinity();
    }

    // b·Z₁⁴
    let z1_4 = field.square(&z1_2);
    let b_z1_4 = field.mul(b, &z1_4);

    // X₃ = X₁⁴ + b·Z₁⁴
    let x1_4 = field.square(&x1_2);
    let x3 = Gf2m::add(&x1_4, &b_z1_4);

    // Y₃ = b·Z₁⁴·Z₃ + X₃·(a·Z₃ + Y₁² + b·Z₁⁴)
    let y1_2 = field.square(&p.y);
    let a_z3 = field.mul(a, &z3);
    let inner = Gf2m::add(&Gf2m::add(&a_z3, &y1_2), &b_z1_4);
    let term1 = field.mul(&b_z1_4, &z3);
    let term2 = field.mul(&x3, &inner);
    let y3 = Gf2m::add(&term1, &term2);

    LDPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Mixed addition `P + Q` with `P` in López–Dahab coordinates and `Q = (x₂, y₂)`
/// affine, on `y² + xy = x³ + ax² + b`.
///
/// Standard mixed LD/affine formulas (Hankerson–Menezes–Vanstone, Alg. 3.25):
///
/// ```text
/// A = Y₁ + y₂·Z₁²      B = X₁ + x₂·Z₁      C = Z₁·B
/// D = B²·(C + a·Z₁²)   Z₃ = C²             E = A·C
/// X₃ = A² + D + E
/// F = X₃ + x₂·Z₃       G = (x₂ + y₂)·Z₃²
/// Y₃ = (E + Z₃)·F + G
/// ```
///
/// `B = 0` means `x₁ = x₂`: then either `Q = P` (fall back to doubling) or
/// `Q = −P` (the sum is `∞`).
fn ld_add_mixed(
    p: &LDPoint,
    qx: &BigUint,
    qy: &BigUint,
    a: &BigUint,
    b: &BigUint,
    field: &Gf2m,
) -> LDPoint {
    if p.is_infinity() {
        // ∞ + Q = Q, lifted with Z = 1.
        return LDPoint {
            x: qx.clone(),
            y: qy.clone(),
            z: BigUint::one(),
        };
    }

    let z1_2 = field.square(&p.z);

    // A = Y₁ + y₂·Z₁²
    let y2_z1_2 = field.mul(qy, &z1_2);
    let a_int = Gf2m::add(&p.y, &y2_z1_2);

    // B = X₁ + x₂·Z₁
    let x2_z1 = field.mul(qx, &p.z);
    let b_int = Gf2m::add(&p.x, &x2_z1);

    if b_int.is_zero() {
        // x₁ = x₂: doubling (Q = P) or identity (Q = −P).
        return if a_int.is_zero() {
            ld_double(p, a, b, field)
        } else {
            LDPoint::infinity()
        };
    }

    // C = Z₁·B
    let c = field.mul(&p.z, &b_int);

    // D = B²·(C + a·Z₁²)
    let b_sq = field.square(&b_int);
    let a_z1_2 = field.mul(a, &z1_2);
    let d = field.mul(&b_sq, &Gf2m::add(&c, &a_z1_2));

    // Z₃ = C²
    let z3 = field.square(&c);

    // E = A·C
    let e = field.mul(&a_int, &c);

    // X₃ = A² + D + E
    let a_sq = field.square(&a_int);
    let x3 = Gf2m::add(&Gf2m::add(&a_sq, &d), &e);

    // F = X₃ + x₂·Z₃
    let x2_z3 = field.mul(qx, &z3);
    let f = Gf2m::add(&x3, &x2_z3);

    // G = (x₂ + y₂)·Z₃²
    let z3_2 = field.square(&z3);
    let g = field.mul(&Gf2m::add(qx, qy), &z3_2);

    // Y₃ = (E + Z₃)·F + G
    let y3 = Gf2m::add(&field.mul(&Gf2m::add(&e, &z3), &f), &g);

    LDPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Scalar multiplication for binary curves using left-to-right double-and-add
/// in López–Dahab projective coordinates.
///
/// The inner loop is inversion-free; the only binary-field inversion is the
/// single one in [`LDPoint::to_affine`] at the end. Affine coordinates would
/// need an extended-GCD inversion in every add and double, roughly one per
/// scalar bit.
fn scalar_mul_binary(curve: &CurveParams, point: &AffinePoint, k: &BigUint) -> AffinePoint {
    if k.is_zero() || point.is_infinity() {
        return AffinePoint::infinity();
    }

    let field = match &curve.field {
        FieldCtx::Binary(field) => field,
        FieldCtx::Prime(_) => panic!("scalar_mul_binary called on a prime-field curve"),
    };
    let a = &curve.a;
    let b = &curve.b;
    let qx = &point.x;
    let qy = &point.y;

    let mut result = LDPoint::infinity();
    for i in (0..k.bits()).rev() {
        result = ld_double(&result, a, b, field);
        if k.bit(i) {
            result = ld_add_mixed(&result, qx, qy, a, b, field);
        }
    }

    result.to_affine(field)
}

// ─── SEC 1 domain-parameter validation ───────────────────────────────────────

/// The constructors of the named curves this module defines. Parameters
/// equal to one of these, field for field, are valid by SEC 1 §3.1.1.2 and
/// §3.1.2.2 method 3: SEC 2 and FIPS 186-4 attest them, and this module's
/// tests run the validation primitive over every one.
const NAMED_CURVES: [fn() -> CurveParams; 16] = [
    p192, p224, p256, p384, p521, secp256k1, b163, k163, b233, k233, b283, k283, b409, k409, b571,
    k571,
];

/// The security level `t` that SEC 1 §3.1.1.2.1 step 1 pairs with a prime
/// field of `bits = ⌈log2 p⌉`: `2t` for `80 < t < 256`, 521 for `t = 256`
/// and 192 for `t = 80`. `None` for a width the primitive does not admit.
fn prime_field_security_level(bits: usize) -> Option<u32> {
    match bits {
        192 => Some(80),
        224 => Some(112),
        256 => Some(128),
        384 => Some(192),
        521 => Some(256),
        _ => None,
    }
}

/// The security level `t` that SEC 1 §3.1.2.2.1 step 1 pairs with a binary
/// field of degree `m`: `m ∈ {163, 233, 239, 283, 409, 571}` with
/// `2t < m < 2t′`, `t′` the next level above `t` in `{112, 128, 192, 256, 512}`.
/// `None` for a degree the primitive does not admit.
fn binary_field_security_level(degree: usize) -> Option<u32> {
    match degree {
        163 => Some(80),
        233 | 239 => Some(112),
        283 => Some(128),
        409 => Some(192),
        571 => Some(256),
        _ => None,
    }
}

/// SEC 1 §2.1.2 Table 1, the reduction polynomials of `F_2^m`, each as its
/// degree and the exponents of its nonzero terms.
const SEC1_REDUCTION_POLYNOMIALS: [(usize, &[usize]); 7] = [
    (163, &[163, 7, 6, 3, 0]),
    (233, &[233, 74, 0]),
    (239, &[239, 36, 0]),
    (239, &[239, 158, 0]),
    (283, &[283, 12, 7, 5, 0]),
    (409, &[409, 87, 0]),
    (571, &[571, 10, 5, 2, 0]),
];

/// The binary polynomial with the given nonzero terms, as a bit pattern.
fn binary_polynomial(exponents: &[usize]) -> BigUint {
    let top = exponents.iter().copied().max().unwrap_or(0);
    let mut bytes = vec![0u8; top / 8 + 1];
    for &e in exponents {
        let byte = bytes.len() - 1 - e / 8;
        bytes[byte] |= 1 << (e % 8);
    }
    BigUint::from_be_bytes(&bytes)
}

/// Whether `h = ⌊(√q + 1)² / n⌋` (SEC 1 §3.1.1.2.1 step 6, §3.1.2.2.1 step 7),
/// decided in integers: `(√q + 1)² = q + 1 + 2√q`, so `hn ≤ (√q + 1)²`
/// exactly when `hn ≤ q + 1` or `(hn − q − 1)² ≤ 4q`, and `(h + 1)n > (√q + 1)²`
/// exactly when `(h + 1)n > q + 1` and `((h + 1)n − q − 1)² > 4q`.
fn cofactor_is_hasse_quotient(h: u64, n: &BigUint, q: &BigUint) -> bool {
    let Some(h_plus_one) = h.checked_add(1) else {
        return false;
    };
    let q_plus_one = q.add(&BigUint::one());
    let four_q = q.mul(&BigUint::from_u64(4));
    let lower = n.mul(&BigUint::from_u64(h));
    let upper = n.mul(&BigUint::from_u64(h_plus_one));
    let lower_holds = lower <= q_plus_one || lower.sub(&q_plus_one).square() <= four_q;
    let upper_holds = upper > q_plus_one && upper.sub(&q_plus_one).square() > four_q;
    lower_holds && upper_holds
}

/// Whether `h ≤ 2^(t/8)`, the cofactor bound of SEC 1 §3.1.1.2.1 step 6 and
/// §3.1.2.2.1 step 7 at security level `t`.
fn cofactor_within_security_level(h: u64, t: u32) -> bool {
    h <= 1u64 << (t / 8)
}

/// Whether the multiplicative order of `base` modulo `n` is at least
/// `bound`: `base^B ≢ 1 (mod n)` for every `1 ≤ B < bound`, decided by
/// `bound − 1` multiplications modulo `n`.
///
/// SEC 1 §3.1.1.2.1 step 8 applies this with `base = p` and `bound = 100`,
/// §3.1.2.2.1 step 9 with `base = 2` and `bound = 100m`. The embedding degree
/// of the order-`n` subgroup is the order of `q` modulo `n`, the smallest `k`
/// with `n | q^k − 1`. Over `F_p` it is `ord_n(p)` itself, bounded directly.
/// Over `F_2^m` it is `ord_n(2^m) = ord_n(2) / gcd(ord_n(2), m) ≥
/// ord_n(2) / m`, so `ord_n(2) ≥ 100m` again gives an embedding degree of at
/// least 100. Both bounds keep the Menezes–Okamoto–Vanstone and Frey–Rück
/// reductions from moving the discrete logarithm into a field small enough
/// to attack.
fn multiplicative_order_at_least(base: &BigUint, n: &BigUint, bound: usize) -> bool {
    let base = base.rem(n);
    let mut power = base.clone();
    for _ in 1..bound {
        if power.is_one() {
            return false;
        }
        power = BigUint::mod_mul(&power, &base, n);
    }
    true
}

/// Whether the curve is anomalous, `#E(F_q) = hn = q`, the case the
/// Semaev–Smart–Satoh–Araki reduction solves in linear time by mapping the
/// group into the additive group of `F_q`. SEC 1 §3.1.2.2.1 step 9 writes
/// the exclusion as `nh ≠ 2^m`; §3.1.1.2.1 step 8 writes it as `n ≠ p`, and
/// under step 6 the two agree, since `n = p` forces
/// `h = ⌊(√p + 1)²/p⌋ = 1`.
fn is_anomalous(n: &BigUint, h: u64, q: &BigUint) -> bool {
    n.mul(&BigUint::from_u64(h)) == *q
}

// ─── CurveParams ────────────────────────────────────────────────────────────

impl CurveParams {
    /// Construct curve parameters from raw field values the caller vouches
    /// for: the named-curve constructors and callers that generated the
    /// parameters themselves. Parameters that arrive from outside the process
    /// go through [`Self::from_explicit`], which validates them.
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
        if subgroup_order <= BigUint::one() {
            return None;
        }
        let field = MontgomeryContext::new(&field_prime).ok()?;
        let scalar = MontgomeryContext::new(&subgroup_order).ok()?;
        let coord_len = field_prime.bits().div_ceil(8);
        let field = PrimeFieldCtx::new(field, &curve_a);
        Some(Self {
            p: field_prime,
            a: curve_a,
            b: curve_b,
            n: subgroup_order,
            h: cofactor,
            gx: base_x,
            gy: base_y,
            field: FieldCtx::Prime(field),
            scalar,
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
    /// Returns `None` if `n ≤ 1` or even, if `poly` is not irreducible over
    /// GF(2) (a reducible modulus gives a ring with zero divisors, and the
    /// point formulas would then hit an uninvertible element), if its degree
    /// is not `degree`, or if `degree` is even. The last is a choice of
    /// solver, not a limit of the arithmetic: point decompression solves
    /// `z² + z = β` (SEC 1 §2.3.4 step 2.4.3, which leaves the method open)
    /// by the half-trace of IEEE Std 1363-2000 A.4.7, a solver for odd `m`
    /// only, and every degree SEC 1 §3.1.2.2.1 admits, `{163, 233, 239, 283,
    /// 409, 571}`, is odd, so nothing standard is excluded.
    ///
    /// The irreducibility test costs work quadratic in the polynomial's
    /// size; [`Self::from_explicit`] bounds that size before calling here.
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
        if subgroup_order <= BigUint::one() || degree.is_multiple_of(2) {
            return None;
        }
        let scalar = MontgomeryContext::new(&subgroup_order).ok()?;
        if !Gf2m::is_irreducible(&modulus_poly) {
            return None;
        }
        let gf2m = Gf2m::new(modulus_poly)?;
        if gf2m.degree() != degree {
            return None;
        }
        let coord_len = degree.div_ceil(8);
        let field_prime = gf2m.modulus().clone();
        Some(Self {
            p: field_prime,
            a: curve_a,
            b: curve_b,
            n: subgroup_order,
            h: cofactor,
            gx: base_x,
            gy: base_y,
            field: FieldCtx::Binary(gf2m),
            scalar,
            coord_len,
        })
    }

    /// Domain parameters received from outside the process, as a key blob or
    /// XML document carries them.
    ///
    /// Nothing is built until the input is within the sizes the SEC 1
    /// primitives admit, so the work an input of any length can cause is
    /// that of one curve at an admitted size: step 1 of §3.1.1.2.1 fixes
    /// `⌈log2 p⌉`, step 1 of §3.1.2.2.1 fixes `m`, with `f(x)` required to
    /// have degree exactly `m`; steps 2 and 3 keep the coefficients and base
    /// point inside the field; and Hasse's bound `n ≤ hn ≤ (√q + 1)² < 4q`
    /// keeps `n` within two bits of `q`. Only then are the parameters built
    /// as [`Self::new`] or [`Self::new_binary`] builds them: a Montgomery
    /// context or an irreducibility test on at most 572 bits.
    ///
    /// They are accepted on one of the two grounds SEC 1 §3.1.1.2 and
    /// §3.1.2.2 allow an entity that did not generate them: they equal,
    /// field for field, a named curve of SEC 2 and FIPS 186-4 that this
    /// module defines (method 3, a trusted party's assurance), or they pass
    /// [`Self::validate_domain_parameters`] (method 1). `None` otherwise.
    #[must_use]
    pub fn from_explicit(
        field: ExplicitField,
        curve_a: BigUint,
        curve_b: BigUint,
        subgroup_order: BigUint,
        cofactor: u64,
        base_x: BigUint,
        base_y: BigUint,
    ) -> Option<Self> {
        let elements = [&curve_a, &curve_b, &base_x, &base_y];
        let field_bits = match &field {
            ExplicitField::Prime(p) => {
                prime_field_security_level(p.bits())?;
                if elements.into_iter().any(|v| v >= p) {
                    return None;
                }
                p.bits()
            }
            ExplicitField::Binary { modulus, degree } => {
                binary_field_security_level(*degree)?;
                if modulus.bits() != degree + 1 || elements.into_iter().any(|v| v.bits() > *degree)
                {
                    return None;
                }
                *degree
            }
        };
        if subgroup_order.bits() > field_bits + 2 {
            return None;
        }
        let curve = match field {
            ExplicitField::Prime(p) => Self::new(
                p,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                base_x,
                base_y,
            )?,
            ExplicitField::Binary { modulus, degree } => Self::new_binary(
                modulus,
                degree,
                curve_a,
                curve_b,
                subgroup_order,
                cofactor,
                (base_x, base_y),
            )?,
        };
        (curve.is_named_curve() || curve.validate_domain_parameters()).then_some(curve)
    }

    /// Whether these parameters equal, field for field, one of the named
    /// curves this module defines.
    fn is_named_curve(&self) -> bool {
        NAMED_CURVES.iter().any(|build| self.same_curve(&build()))
    }

    /// The SEC 1 v2.0 domain-parameter validation primitive, every step:
    /// §3.1.1.2.1 over `F_p` or §3.1.2.2.1 over `F_2^m`, at the security
    /// level `t` the field size implies. Step 1 admits only
    /// `⌈log2 p⌉ ∈ {192, 224, 256, 384, 521}` and
    /// `m ∈ {163, 233, 239, 283, 409, 571}` under a reduction polynomial of
    /// SEC 1 Table 1; the remaining steps check that `p` and `n` are prime
    /// (by the hardened test for untrusted candidates), that the coefficients
    /// and base point are reduced, that the curve is non-singular
    /// (`4a³ + 27b² ≢ 0` or `b ≠ 0`), that `G` lies on it, that `h ≤ 2^(t/8)`
    /// and `h = ⌊(√q + 1)²/n⌋`, that `nG = O`, and that the curve is neither
    /// anomalous nor of small embedding degree.
    ///
    /// Over `F_p` the two primality tests are most of the cost: about 3.6 ms
    /// for P-256 and 15 ms for P-521 in a release build on an Apple M4 Pro.
    /// Over `F_2^m` the field needs no primality test, but the last step's
    /// `100m − 1` multiplications modulo `n` weigh as much as the test on
    /// `n` and the scalar multiplication `nG` together on B-163 (2.5 ms in
    /// all) and a third of B-571's 19 ms. A debug build takes 16 to 32 times
    /// as long. [`Self::from_explicit`] runs the primitive on parameters
    /// that are not a named curve.
    #[must_use]
    pub fn validate_domain_parameters(&self) -> bool {
        match &self.field {
            FieldCtx::Prime(field) => self.prime_domain_is_valid(field),
            FieldCtx::Binary(field) => self.binary_domain_is_valid(field),
        }
    }

    /// SEC 1 §3.1.1.2.1, steps 1 to 8 in order.
    fn prime_domain_is_valid(&self, field: &PrimeFieldCtx) -> bool {
        let p = &self.p;
        let Some(t) = prime_field_security_level(p.bits()) else {
            return false;
        };
        if !p.is_odd() || !is_probable_prime_untrusted(p) {
            return false;
        }
        if [&self.a, &self.b, &self.gx, &self.gy]
            .into_iter()
            .any(|v| v >= p)
        {
            return false;
        }
        let ctx = field.ctx();
        let a_cubed = ctx.mul(&ctx.square(&self.a), &self.a);
        let b_squared = ctx.square(&self.b);
        let discriminant = BigUint::mod_add(
            &BigUint::mod_mul(&BigUint::from_u64(4), &a_cubed, p),
            &BigUint::mod_mul(&BigUint::from_u64(27), &b_squared, p),
            p,
        );
        if discriminant.is_zero() {
            return false;
        }
        let g = self.base_point();
        if !self.is_on_curve(&g) {
            return false;
        }
        if !is_probable_prime_untrusted(&self.n) {
            return false;
        }
        if !cofactor_within_security_level(self.h, t)
            || !cofactor_is_hasse_quotient(self.h, &self.n, p)
        {
            return false;
        }
        if !self.scalar_mul(&g, &self.n).is_infinity() {
            return false;
        }
        multiplicative_order_at_least(p, &self.n, 100) && !is_anomalous(&self.n, self.h, p)
    }

    /// SEC 1 §3.1.2.2.1, steps 1 to 9 in order. Irreducibility of the
    /// reduction polynomial is established by [`Self::new_binary`]; step 2
    /// here requires it to be one of Table 1's.
    fn binary_domain_is_valid(&self, field: &Gf2m) -> bool {
        let m = field.degree();
        let Some(t) = binary_field_security_level(m) else {
            return false;
        };
        if !SEC1_REDUCTION_POLYNOMIALS
            .iter()
            .any(|(degree, terms)| *degree == m && binary_polynomial(terms) == *field.modulus())
        {
            return false;
        }
        if [&self.a, &self.b, &self.gx, &self.gy]
            .into_iter()
            .any(|v| v.bits() > m)
        {
            return false;
        }
        if self.b.is_zero() {
            return false;
        }
        let g = self.base_point();
        if !self.is_on_curve(&g) {
            return false;
        }
        if !is_probable_prime_untrusted(&self.n) {
            return false;
        }
        let mut q = BigUint::one();
        q.shl_bits(m);
        if !cofactor_within_security_level(self.h, t)
            || !cofactor_is_hasse_quotient(self.h, &self.n, &q)
        {
            return false;
        }
        if !self.scalar_mul(&g, &self.n).is_infinity() {
            return false;
        }
        multiplicative_order_at_least(&BigUint::from_u64(2), &self.n, 100 * m)
            && !is_anomalous(&self.n, self.h, &q)
    }

    /// Return a reference to the prime-field Montgomery context.
    ///
    /// # Panics
    ///
    /// Panics if called on a binary-curve `CurveParams`.  Internal callers
    /// must only invoke this from code paths that are gated on
    /// `FieldCtx::Prime`.
    fn prime_field(&self) -> &PrimeFieldCtx {
        match &self.field {
            FieldCtx::Prime(fld) => fld,
            FieldCtx::Binary(_) => {
                panic!("prime_field called on a binary-field curve")
            }
        }
    }

    /// Return the prime field's Montgomery context, for one-shot modular
    /// arithmetic on ordinary values.
    ///
    /// # Panics
    ///
    /// Panics on a binary-curve `CurveParams`, like [`Self::prime_field`].
    fn prime_ctx(&self) -> &MontgomeryContext {
        self.prime_field().ctx()
    }

    /// Return the Montgomery context for arithmetic modulo the subgroup
    /// order `n` — the modulus the signature schemes multiply in.
    pub(crate) fn scalar_ctx(&self) -> &MontgomeryContext {
        &self.scalar
    }

    /// Return the field degree `m` if this is a binary-extension-field curve,
    /// or `None` for a prime-field curve.
    #[must_use]
    pub fn gf2m_degree(&self) -> Option<usize> {
        match &self.field {
            FieldCtx::Binary(field) => Some(field.degree()),
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
            FieldCtx::Prime(fld) => {
                let ctx = fld.ctx();
                // lhs = y²
                let lhs = ctx.square(&point.y);
                // rhs = x³ + a·x + b
                let x2 = ctx.square(&point.x);
                let x3 = ctx.mul(&x2, &point.x);
                let ax = ctx.mul(&self.a, &point.x);
                let rhs = BigUint::mod_add(&BigUint::mod_add(&x3, &ax, &self.p), &self.b, &self.p);
                lhs == rhs
            }
            FieldCtx::Binary(field) => {
                is_on_curve_binary(&point.x, &point.y, &self.a, &self.b, field)
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
            FieldCtx::Prime(_) => {
                AffinePoint::new(point.x.clone(), BigUint::mod_neg(&point.y, &self.p))
            }
            FieldCtx::Binary(_) => {
                // −P = (xP, xP ⊕ yP)
                let neg_y = Gf2m::add(&point.x, &point.y);
                AffinePoint::new(point.x.clone(), neg_y)
            }
        }
    }

    /// Add two affine curve points.
    #[must_use]
    pub fn add(&self, p: &AffinePoint, q: &AffinePoint) -> AffinePoint {
        match &self.field {
            FieldCtx::Prime(fld) => {
                let mut scratch = MontgomeryScratch::new();
                let pj = JacobianPoint::from_affine(fld, p);
                let qj = JacobianPoint::from_affine(fld, q);
                point_add_jacobian(fld, &pj, &qj, &mut scratch).to_affine(self)
            }
            FieldCtx::Binary(field) => add_binary(p, q, &self.a, field),
        }
    }

    /// Double an affine curve point (`2P`).
    #[must_use]
    pub fn double(&self, p: &AffinePoint) -> AffinePoint {
        match &self.field {
            FieldCtx::Prime(fld) => {
                let mut scratch = MontgomeryScratch::new();
                let pj = JacobianPoint::from_affine(fld, p);
                point_double_jacobian(fld, &pj, &mut scratch).to_affine(self)
            }
            FieldCtx::Binary(field) => double_binary(p, &self.a, field),
        }
    }

    /// Scalar multiplication `k·P`.
    ///
    /// Returns the point at infinity when `k = 0` or `P = ∞`.
    #[must_use]
    pub fn scalar_mul(&self, point: &AffinePoint, k: &BigUint) -> AffinePoint {
        match &self.field {
            FieldCtx::Prime(_) => scalar_mul_jacobian(self, point, k),
            FieldCtx::Binary(_) => scalar_mul_binary(self, point, k),
        }
    }

    /// Returns `true` if `point` lies in the prime-order subgroup (`n·point = O`).
    ///
    /// Decoders should reject peer points that fail this check: on curves with
    /// cofactor `h > 1` (here the binary curves, `h = 2` or `4`) an on-curve
    /// low-order point would otherwise enable a small-subgroup attack against a
    /// static key, leaking `d mod ord(point)`. Prime NIST curves have `h = 1`,
    /// where every on-curve point already satisfies this.
    #[must_use]
    pub fn is_in_prime_subgroup(&self, point: &AffinePoint) -> bool {
        self.scalar_mul(point, &self.n).is_infinity()
    }

    /// `true` if `v` is a reduced field element: `v < p` on a prime field,
    /// `deg(v) < m` on GF(2^m).
    ///
    /// The Montgomery context reduces any representative on encode, so a
    /// coordinate of `x + p` would pass the curve equation while breaking
    /// point equality and fixed-width encoding; SEC 1 §2.3.4 requires
    /// decoders to reject it.
    fn coordinate_is_canonical(&self, v: &BigUint) -> bool {
        match &self.field {
            FieldCtx::Prime(_) => v < &self.p,
            FieldCtx::Binary(field) => v.bits() <= field.degree(),
        }
    }

    /// Full public-key validation (SEC 1 §3.2.2.1, SP 800-56A Rev. 3
    /// §5.6.2.3.3): the point is not `∞`, both coordinates are canonical, it
    /// satisfies the curve equation, and it lies in the prime-order subgroup.
    ///
    /// Every decoder that accepts a point from outside the process must use
    /// this rather than [`Self::is_on_curve`] alone. The prime-field Jacobian
    /// formulas never read `b`, so they multiply a point of any curve
    /// `y² = x³ + ax + b′` over the same `p` as if it lay on this one (the
    /// invalid-curve attack); the López–Dahab formulas do read `b`, so on a
    /// point off the curve they perform no group operation at all, and no
    /// statement about this curve covers what they return. On the cofactor
    /// curves (`h = 2` or `4`) a low-order point is on the curve. Any of
    /// these would hand an attacker `d` modulo a small order per query. Nor
    /// is [`Self::is_in_prime_subgroup`] enough: `n·∞ = ∞`, and
    /// [`Self::decode_point`] rightly returns `∞` for the octet `00` (SEC 1
    /// §2.3.4 step 1), but `∞` is never a public key. Under `Q = ∞` ECDSA
    /// verification reduces to `u₁·G`, which anyone can satisfy.
    #[must_use]
    pub fn is_valid_public_point(&self, point: &AffinePoint) -> bool {
        !point.infinity
            && self.coordinate_is_canonical(&point.x)
            && self.coordinate_is_canonical(&point.y)
            && self.is_on_curve(point)
            && self.is_in_prime_subgroup(point)
    }

    /// The public point `Q = d·G` for a private scalar `d` handed in from
    /// outside, or `None` unless `1 ≤ d ≤ n − 1` (SEC 1 §3.2.1) and `Q` is a
    /// valid public key ([`Self::is_valid_public_point`]).
    ///
    /// With valid domain parameters every such `Q` is valid; parameters the
    /// caller built with [`Self::new`] carry no such guarantee, and if their
    /// `n` is a multiple of the order of `G`, `d·G` can be `∞`, a public key
    /// every public-key decoder refuses. Every private-key constructor that
    /// takes `d` goes through here, so no key pair is ever formed around it.
    pub(crate) fn public_point_for_scalar(&self, d: &BigUint) -> Option<AffinePoint> {
        if d.is_zero() || d >= &self.n {
            return None;
        }
        let q = self.scalar_mul(&self.base_point(), d);
        self.is_valid_public_point(&q).then_some(q)
    }

    /// `true` if `other` describes the same curve: same field, coefficients,
    /// base point, order, and cofactor.
    ///
    /// Key agreement must check this before combining a private scalar with
    /// a peer's point; a peer key that validated against *its own* embedded
    /// curve is otherwise a point on an arbitrary curve.
    #[must_use]
    pub fn same_curve(&self, other: &Self) -> bool {
        self.p == other.p
            && self.a == other.a
            && self.b == other.b
            && self.n == other.n
            && self.h == other.h
            && self.gx == other.gx
            && self.gy == other.gy
            && self.gf2m_degree() == other.gf2m_degree()
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

    /// The canonical representative of the field element `v` denotes: the
    /// residue in `[0, p)`, or the polynomial of degree below `m`. The
    /// identity on every coordinate this module produces; only a value a
    /// caller assembled from a representative outside the field is reduced.
    fn canonical_coordinate(&self, v: &BigUint) -> BigUint {
        match &self.field {
            FieldCtx::Prime(_) if v >= &self.p => v.rem(&self.p),
            FieldCtx::Binary(field) if v.bits() > field.degree() => {
                // The product reduces its operands; 1 leaves the class alone.
                field.mul(v, &BigUint::one())
            }
            FieldCtx::Prime(_) | FieldCtx::Binary(_) => v.clone(),
        }
    }

    /// Encode a point as an uncompressed SEC 1 §2.3.3 octet string:
    /// `04 || X || Y` with each coordinate in `coord_len` big-endian octets
    /// (step 3, the field-element conversion of §2.3.5), or the single octet
    /// `00` for `∞` (step 1).
    ///
    /// The coordinates are encoded as the field elements they denote: a
    /// representative outside `[0, p)`, or of degree `m` or more, is reduced
    /// first, so the encoding is total, and
    /// `decode_point(encode_point(P)) == P` exactly when `P` carries
    /// canonical coordinates, as every point this module produces does.
    #[must_use]
    pub fn encode_point(&self, point: &AffinePoint) -> Vec<u8> {
        if point.infinity {
            return vec![0x00];
        }
        let x = self.canonical_coordinate(&point.x);
        let y = self.canonical_coordinate(&point.y);
        let mut out = Vec::with_capacity(1 + 2 * self.coord_len);
        out.push(0x04);
        out.extend_from_slice(&x.to_be_bytes_padded(self.coord_len));
        out.extend_from_slice(&y.to_be_bytes_padded(self.coord_len));
        out
    }

    /// Encode a point in compressed SEC 1 §2.3.3 form (step 2): `02 || X` or
    /// `03 || X`, the tag carrying `ỹ`. Over `F_p`, `ỹ = y mod 2` (step
    /// 2.2.1); over `F_2^m`, `ỹ = 0` when `x = 0` and otherwise the constant
    /// term of `z = y·x⁻¹` (step 2.2.2). The identity encodes as `00`.
    ///
    /// Coordinates are reduced to their canonical representatives first, as
    /// in [`Self::encode_point`], so the encoding is total.
    ///
    /// # Panics
    ///
    /// Only if the binary field fails to invert a canonical non-zero `x`,
    /// which an irreducible reduction polynomial rules out.
    #[must_use]
    pub fn encode_point_compressed(&self, point: &AffinePoint) -> Vec<u8> {
        if point.infinity {
            return vec![0x00];
        }
        let x = self.canonical_coordinate(&point.x);
        let y = self.canonical_coordinate(&point.y);
        let parity = match &self.field {
            FieldCtx::Prime(_) => y.is_odd(),
            FieldCtx::Binary(_) if x.is_zero() => false,
            FieldCtx::Binary(field) => {
                let x_inv = field
                    .inverse(&x)
                    .expect("a canonical non-zero element of a field has an inverse");
                field.mul(&y, &x_inv).is_odd()
            }
        };
        let tag = if parity { 0x03u8 } else { 0x02u8 };
        let mut out = Vec::with_capacity(1 + self.coord_len);
        out.push(tag);
        out.extend_from_slice(&x.to_be_bytes_padded(self.coord_len));
        out
    }

    /// Decode a SEC 1 §2.3.4 octet string: `00` to `∞` (step 1), `02`/`03`
    /// followed by `coord_len` octets as a compressed point (step 2), `04`
    /// followed by `2·coord_len` octets as an uncompressed one (step 3).
    ///
    /// Returns `None`, the routine's "invalid", for any of:
    /// - a length that matches no form, or a first octet other than these,
    /// - a coordinate that is not a field element (`≥ p`, or of degree `≥ m`
    ///   over `F_2^m`; §2.3.6),
    /// - uncompressed coordinates that fail the curve equation (step 3.5),
    /// - a compressed `x` with no `y` on the curve: over `F_p` an `α` with no
    ///   square root, or the root `0` under the tag `03` (step 2.4.1 then
    ///   gives `y = p`, outside the field); over `F_2^m` a `β` with no root
    ///   of `z² + z = β` (step 2.4.3).
    ///
    /// The point decoded need not be a valid public key:
    /// [`Self::is_valid_public_point`] refuses `∞` and the 2-torsion points
    /// `(x, 0)` and `(0, √b)` that this routine decodes as the standard
    /// directs.
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
                if !self.coordinate_is_canonical(&x) || !self.coordinate_is_canonical(&y) {
                    return None;
                }
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
                if !self.coordinate_is_canonical(&x) {
                    return None;
                }
                let odd_tag = *tag == 0x03;
                match &self.field {
                    FieldCtx::Prime(_) => {
                        let y = self.field_sqrt_from_x(&x, odd_tag)?;
                        Some(AffinePoint::new(x, y))
                    }
                    FieldCtx::Binary(field) => self.decompress_binary_point(&x, odd_tag, field),
                }
            }
            _ => None,
        }
    }

    /// SEC 1 §2.3.4 step 2.4 over `F_2^m`: the `y` that a compressed `x` and
    /// the tag bit `ỹ` determine.
    ///
    /// - Step 2.4.2: `x = 0` gives `y = b^(2^(m−1))`, the square root of `b`
    ///   ([`Gf2m::sqrt`]). The tag carries nothing here, since §2.3.3 step
    ///   2.2.2 encodes such a point with `ỹ = 0`, and the step reads it
    ///   under either tag. `(0, √b)` is its own negative, so it has order 2:
    ///   it decodes, and [`Self::is_valid_public_point`] refuses it.
    /// - Step 2.4.3: otherwise `β = x + a + b·x⁻²` and `z` is a root of
    ///   `z² + z = β`, here the half-trace of IEEE Std 1363-2000 A.4.7, which
    ///   is a root exactly when `Tr(β) = 0`; `y = x·z` or `x·(z + 1)`,
    ///   whichever root has constant term `ỹ`.
    ///
    /// The point is checked against the curve equation before it is
    /// returned; when `z² + z = β` has no root that check is what yields
    /// "invalid".
    fn decompress_binary_point(
        &self,
        x: &BigUint,
        odd_z: bool,
        field: &Gf2m,
    ) -> Option<AffinePoint> {
        if x.is_zero() {
            return Some(AffinePoint::new(BigUint::zero(), field.sqrt(&self.b)));
        }
        // β = x + a + b·x⁻²
        let x_inv = field.inverse(x)?;
        let x_inv2 = field.square(&x_inv);
        let b_x_inv2 = field.mul(&self.b, &x_inv2);
        let beta = Gf2m::add(&Gf2m::add(x, &self.a), &b_x_inv2);

        // The two roots of z² + z = β differ by 1; ỹ picks the constant term.
        let z0 = field.half_trace(&beta);
        let z = if z0.is_odd() == odd_z {
            z0
        } else {
            Gf2m::add(&z0, &BigUint::one())
        };

        let y = field.mul(&z, x);
        let pt = AffinePoint::new(x.clone(), y);
        self.is_on_curve(&pt).then_some(pt)
    }

    /// SEC 1 §2.3.4 step 2.4.1 over `F_p`: the `y` that a compressed `x` and
    /// the tag bit `ỹ` determine. With `α = x³ + ax + b` and `β` a square
    /// root of `α` modulo `p` (`rump::modular::mod_sqrt`, every odd prime
    /// field included, the root verified by squaring before it is returned),
    /// `y = β` when `β ≡ ỹ (mod 2)` and `y = p − β` otherwise.
    ///
    /// `None` when `α` has no square root, and when `β = 0` under `ỹ = 1`:
    /// the step then gives `y = p`, which is not a field element. The point
    /// `(x, 0)` has order 2 and one encoding, under the tag `02`.
    fn field_sqrt_from_x(&self, x: &BigUint, odd_y: bool) -> Option<BigUint> {
        let ctx = self.prime_ctx();

        let x2 = ctx.square(x);
        let x3 = ctx.mul(&x2, x);
        let ax = ctx.mul(&self.a, x);
        let alpha = BigUint::mod_add(&BigUint::mod_add(&x3, &ax, &self.p), &self.b, &self.p);

        let beta = mod_sqrt(&alpha, &self.p)?;
        if beta.is_odd() == odd_y {
            Some(beta)
        } else if beta.is_zero() {
            None
        } else {
            Some(BigUint::mod_neg(&beta, &self.p))
        }
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
    BigUint::from_str_radix(&cleaned, 16).expect("named-curve constant is valid hex")
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
    // Subgroup order n from FIPS 186-4 §D.1.3.4.2 (Curve B-409), converted
    // from the published decimal; it equals RFC 6979 §A.2.16's q.
    let n = from_hex(
        "010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
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

    /// Every named curve's base point lies on the curve and has the stated
    /// order, `n·G = ∞`. The differential ladder tests share one `n` between
    /// both sides, so a wrong order constant passes them; this checks `n`
    /// against the group itself.
    #[test]
    fn named_curves_base_point_is_on_curve_with_order_n() {
        let curves: [(&str, CurveParams); 16] = [
            ("P-192", p192()),
            ("P-224", p224()),
            ("P-256", p256()),
            ("P-384", p384()),
            ("P-521", p521()),
            ("secp256k1", secp256k1()),
            ("B-163", b163()),
            ("K-163", k163()),
            ("B-233", b233()),
            ("K-233", k233()),
            ("B-283", b283()),
            ("K-283", k283()),
            ("B-409", b409()),
            ("K-409", k409()),
            ("B-571", b571()),
            ("K-571", k571()),
        ];
        for (name, curve) in curves {
            let g = curve.base_point();
            assert!(curve.is_on_curve(&g), "{name}: G is not on the curve");
            assert!(
                curve.scalar_mul(&g, &curve.n).is_infinity(),
                "{name}: n·G is not the point at infinity"
            );
        }
    }

    /// Every named curve passes the SEC 1 validation primitive itself, not
    /// the named-curve lookup: the constants the constructors carry satisfy
    /// the standard's arithmetic requirements, step by step.
    #[test]
    fn named_curves_pass_the_sec1_validation_primitive() {
        for build in NAMED_CURVES {
            let curve = build();
            assert!(
                curve.validate_domain_parameters(),
                "field of {} bits, degree {:?}",
                curve.p.bits(),
                curve.gf2m_degree()
            );
        }
    }

    /// `from_explicit` on parameters that are not a named curve runs the
    /// primitive: P-256 and B-163 with `−G` as base point are sound curves no
    /// name covers and pass; a single defect at any step is refused.
    #[test]
    fn explicit_parameters_are_accepted_only_by_the_sec1_primitive() {
        let named = p256();
        let prime = |a: &BigUint, b: &BigUint, n: &BigUint, h: u64, gy: &BigUint| {
            CurveParams::from_explicit(
                ExplicitField::Prime(named.p.clone()),
                a.clone(),
                b.clone(),
                n.clone(),
                h,
                named.gx.clone(),
                gy.clone(),
            )
        };
        let neg_gy = named.p.sub(&named.gy);
        let sound = prime(&named.a, &named.b, &named.n, 1, &neg_gy).expect("P-256 under −G");
        assert!(!sound.is_named_curve());
        assert!(prime(&named.a, &named.b, &named.n, 1, &named.gy)
            .expect("P-256")
            .is_named_curve());
        // Step 2: a coefficient at p.
        assert!(prime(&named.p, &named.b, &named.n, 1, &neg_gy).is_none());
        // Step 4: G off the curve.
        let b_plus_one = named.b.add(&BigUint::one());
        assert!(prime(&named.a, &b_plus_one, &named.n, 1, &neg_gy).is_none());
        // Steps 5 and 7: a composite order that still annihilates G.
        let tripled = named.n.mul(&BigUint::from_u64(3));
        assert!(prime(&named.a, &named.b, &tripled, 1, &neg_gy).is_none());
        // Step 6: a cofactor the Hasse interval excludes.
        assert!(prime(&named.a, &named.b, &named.n, 2, &neg_gy).is_none());
        // Step 1: a field width the primitive does not admit.
        assert!(CurveParams::from_explicit(
            ExplicitField::Prime(BigUint::from_u64(17)),
            BigUint::from_u64(2),
            BigUint::from_u64(2),
            BigUint::from_u64(19),
            1,
            BigUint::from_u64(5),
            BigUint::one(),
        )
        .is_none());

        let named = b163();
        let binary = |b: &BigUint, n: &BigUint, h: u64, gy: &BigUint| {
            CurveParams::from_explicit(
                ExplicitField::Binary {
                    modulus: named.p.clone(),
                    degree: 163,
                },
                named.a.clone(),
                b.clone(),
                n.clone(),
                h,
                named.gx.clone(),
                gy.clone(),
            )
        };
        // −G = (x, x ⊕ y) on a binary curve.
        let neg_gy = Gf2m::add(&named.gx, &named.gy);
        let sound = binary(&named.b, &named.n, named.h, &neg_gy).expect("B-163 under −G");
        assert!(!sound.is_named_curve());
        // Step 4: b = 0.
        assert!(binary(&BigUint::zero(), &named.n, named.h, &neg_gy).is_none());
        // Steps 6 and 8: a composite order.
        let tripled = named.n.mul(&BigUint::from_u64(3));
        assert!(binary(&named.b, &tripled, named.h, &neg_gy).is_none());
        // Step 7: the wrong cofactor.
        assert!(binary(&named.b, &named.n, 4, &neg_gy).is_none());
    }

    /// The integer decision of `h = ⌊(√q + 1)²/n⌋` agrees with a
    /// floating-point evaluation wherever the latter is exact, and the
    /// neighbours `h ± 1` are refused.
    #[test]
    fn hasse_quotient_cofactor_agrees_with_a_floating_point_reference() {
        for q in [17u64, 101, 1009, 65_537, 1_000_003] {
            let root = (q as f64).sqrt();
            let big_q = BigUint::from_u64(q);
            let candidates = (1..300).chain(q.saturating_sub(60).max(1)..q + 60);
            for n in candidates {
                let h = ((root + 1.0).powi(2) / n as f64).floor() as u64;
                let big_n = BigUint::from_u64(n);
                assert!(
                    cofactor_is_hasse_quotient(h, &big_n, &big_q),
                    "q {q}, n {n}, h {h}"
                );
                assert!(
                    !cofactor_is_hasse_quotient(h + 1, &big_n, &big_q),
                    "q {q}, n {n}"
                );
                if h > 0 {
                    assert!(
                        !cofactor_is_hasse_quotient(h - 1, &big_n, &big_q),
                        "q {q}, n {n}"
                    );
                }
            }
        }
    }

    /// The multiplicative-order bound: 2 has order 3 modulo 7 and order 10
    /// modulo 11, so the bound decides exactly at those orders. Table 1's
    /// polynomials rebuild from their terms into the named curves' moduli.
    #[test]
    fn multiplicative_order_bound_and_table_1_polynomials() {
        let two = BigUint::from_u64(2);
        let seven = BigUint::from_u64(7);
        let eleven = BigUint::from_u64(11);
        assert!(multiplicative_order_at_least(&two, &seven, 3));
        assert!(!multiplicative_order_at_least(&two, &seven, 4));
        assert!(multiplicative_order_at_least(&two, &eleven, 10));
        assert!(!multiplicative_order_at_least(&two, &eleven, 11));
        // 9 ≡ 2 (mod 7): the base is reduced first.
        assert!(!multiplicative_order_at_least(
            &BigUint::from_u64(9),
            &seven,
            4
        ));

        assert_eq!(binary_polynomial(&[163, 7, 6, 3, 0]), b163().p);
        assert_eq!(binary_polynomial(&[233, 74, 0]), k233().p);
        assert_eq!(binary_polynomial(&[283, 12, 7, 5, 0]), b283().p);
        assert_eq!(binary_polynomial(&[409, 87, 0]), k409().p);
        assert_eq!(binary_polynomial(&[571, 10, 5, 2, 0]), b571().p);
    }

    /// `from_explicit` decides admissibility before it builds anything, so an
    /// input of any size costs the work of a curve at an admitted size. A
    /// reduction polynomial of degree 64001, an admitted degree claimed for
    /// that polynomial, a 1 MiB field prime and a 1 MiB order are refused
    /// with no irreducibility test, Montgomery context or primality test run
    /// on them, which a debug build shows by finishing inside
    /// `test_utils::REFUSAL_BOUND`.
    #[test]
    fn oversized_explicit_parameters_are_refused_before_any_arithmetic() {
        let named = p256();
        let one = BigUint::one();
        let mut huge_poly = BigUint::one();
        huge_poly.shl_bits(64001);
        huge_poly = huge_poly.add(&BigUint::from_u64(0b11));
        let mut huge_prime = BigUint::one();
        huge_prime.shl_bits(8 * 1024 * 1024);
        huge_prime = huge_prime.add(&one);
        let binary = |modulus: &BigUint, degree: usize| {
            CurveParams::from_explicit(
                ExplicitField::Binary {
                    modulus: modulus.clone(),
                    degree,
                },
                one.clone(),
                one.clone(),
                BigUint::from_u64(7),
                2,
                one.clone(),
                one.clone(),
            )
        };
        let prime = |p: &BigUint, n: &BigUint| {
            CurveParams::from_explicit(
                ExplicitField::Prime(p.clone()),
                named.a.clone(),
                named.b.clone(),
                n.clone(),
                1,
                named.gx.clone(),
                named.gy.clone(),
            )
        };
        let elapsed = crate::test_utils::fastest_of_three(|| {
            assert!(binary(&huge_poly, 64001).is_none());
            assert!(binary(&huge_poly, 163).is_none());
            assert!(prime(&huge_prime, &named.n).is_none());
            assert!(prime(&named.p, &huge_prime).is_none());
        });
        assert!(
            elapsed < crate::test_utils::REFUSAL_BOUND,
            "refusal took {elapsed:?}"
        );
    }

    /// SEC 1 §2.3.4 step 2.4.2: on a binary curve the compressed `x = 0`
    /// decodes to `(0, b^(2^(m−1))) = (0, √b)` under either tag, and §2.3.3
    /// step 2.2.2 encodes that point with the tag `02`. It is its own
    /// negative, so it has order 2: it decodes from each of its encodings
    /// and is refused as a public key. On the Koblitz curves `b = 1`, so the
    /// point is `(0, 1)`.
    #[test]
    fn binary_two_torsion_point_round_trips_through_compression() {
        for build in [k163, k233, k283, k409, k571, b163, b233, b283, b409, b571] {
            let curve = build();
            let FieldCtx::Binary(field) = &curve.field else {
                panic!("binary curve");
            };
            let point = AffinePoint::new(BigUint::zero(), field.sqrt(&curve.b));
            assert!(curve.is_on_curve(&point));
            assert_eq!(curve.negate(&point), point);
            assert!(curve.double(&point).is_infinity());
            if curve.b.is_one() {
                assert_eq!(point.y, BigUint::one());
            }
            let compressed = curve.encode_point_compressed(&point);
            assert_eq!(compressed[0], 0x02);
            assert!(compressed[1..].iter().all(|&octet| octet == 0));
            assert_eq!(curve.decode_point(&compressed), Some(point.clone()));
            let mut other_tag = compressed.clone();
            other_tag[0] = 0x03;
            assert_eq!(curve.decode_point(&other_tag), Some(point.clone()));
            assert_eq!(
                curve.decode_point(&curve.encode_point(&point)),
                Some(point.clone())
            );
            assert!(!curve.is_in_prime_subgroup(&point));
            assert!(!curve.is_valid_public_point(&point));
        }
    }

    /// The encoders encode the field elements the coordinates denote: a
    /// representative outside the field, which `is_on_curve` accepts through
    /// the reducing arithmetic, is reduced first, so encoding is total and
    /// the point decodes to its canonical form.
    #[test]
    fn encoding_reduces_non_canonical_coordinates() {
        let curve = p256();
        let g = curve.base_point();
        let shifted = AffinePoint::new(g.x.add(&curve.p), g.y.add(&curve.p));
        assert!(curve.is_on_curve(&shifted));
        assert_ne!(shifted, g);
        assert_eq!(curve.encode_point(&shifted), curve.encode_point(&g));
        assert_eq!(
            curve.encode_point_compressed(&shifted),
            curve.encode_point_compressed(&g)
        );
        assert_eq!(
            curve.decode_point(&curve.encode_point(&shifted)),
            Some(g.clone())
        );

        let curve = b163();
        let g = curve.base_point();
        // x + f(x) is another representative of x, of degree 163.
        let shifted = AffinePoint::new(Gf2m::add(&g.x, &curve.p), Gf2m::add(&g.y, &curve.p));
        assert!(curve.is_on_curve(&shifted));
        assert_ne!(shifted, g);
        assert_eq!(curve.encode_point(&shifted), curve.encode_point(&g));
        assert_eq!(
            curve.encode_point_compressed(&shifted),
            curve.encode_point_compressed(&g)
        );
        assert_eq!(
            curve.decode_point(&curve.encode_point_compressed(&shifted)),
            Some(g)
        );
    }

    /// SEC 1 §2.3.4 step 2.4.1 on a 2-torsion point: `y² = x³ + x` over
    /// `F_23` (24 points; `(18, 10)` has order 3) has `(0, 0)`, whose
    /// `β = 0`. Under the tag `02` it decodes; under `03` the step gives
    /// `y = 23 − 0 = 23`, no field element, so the decoder refuses it rather
    /// than return `(0, 0)` a second time.
    #[test]
    fn prime_compressed_two_torsion_has_one_encoding() {
        let curve = CurveParams::new(
            BigUint::from_u64(23),
            BigUint::one(),
            BigUint::zero(),
            BigUint::from_u64(3),
            8,
            BigUint::from_u64(18),
            BigUint::from_u64(10),
        )
        .expect("toy curve");
        let g = curve.base_point();
        assert!(curve.is_on_curve(&g));
        assert!(curve.scalar_mul(&g, &curve.n).is_infinity());
        let torsion = AffinePoint::new(BigUint::zero(), BigUint::zero());
        assert!(curve.is_on_curve(&torsion));
        assert!(curve.double(&torsion).is_infinity());
        assert_eq!(curve.encode_point_compressed(&torsion), [0x02, 0x00]);
        assert_eq!(curve.decode_point(&[0x02, 0x00]), Some(torsion.clone()));
        assert_eq!(curve.decode_point(&[0x03, 0x00]), None);
        assert!(!curve.is_valid_public_point(&torsion));
        // An ordinary point and its negative still decode under their tags.
        let neg_g = curve.negate(&g);
        assert_eq!(
            curve.decode_point(&curve.encode_point_compressed(&g)),
            Some(g)
        );
        assert_eq!(
            curve.decode_point(&curve.encode_point_compressed(&neg_g)),
            Some(neg_g)
        );
    }

    /// Step 6's first clause on its own, `h ≤ 2^(t/8)`: P-256 (`t = 128`)
    /// admits `h ≤ 65536`, and with `h = 65537` the parameters are refused.
    #[test]
    fn cofactor_above_the_security_level_is_refused() {
        assert!(cofactor_within_security_level(65536, 128));
        assert!(!cofactor_within_security_level(65537, 128));
        assert!(cofactor_within_security_level(1024, 80));
        assert!(!cofactor_within_security_level(1025, 80));
        let named = p256();
        assert!(CurveParams::from_explicit(
            ExplicitField::Prime(named.p.clone()),
            named.a.clone(),
            named.b.clone(),
            named.n.clone(),
            65537,
            named.gx.clone(),
            named.p.sub(&named.gy),
        )
        .is_none());
    }

    /// Step 1 on a composite field size: P-256's `p + 2` is a 256-bit odd
    /// multiple of 3 (`p ≡ 1 (mod 3)`), the hardened primality test rejects
    /// it, and so does `from_explicit`.
    #[test]
    fn composite_field_prime_is_refused() {
        let named = p256();
        let composite = named.p.add(&BigUint::from_u64(2));
        assert_eq!(composite.rem_u64(3), 0);
        assert_eq!(composite.bits(), 256);
        assert!(composite.is_odd());
        assert!(!is_probable_prime_untrusted(&composite));
        assert!(CurveParams::from_explicit(
            ExplicitField::Prime(composite),
            named.a.clone(),
            named.b.clone(),
            named.n.clone(),
            1,
            named.gx.clone(),
            named.gy.clone(),
        )
        .is_none());
    }

    /// Step 7 in isolation: P-256 with `n` replaced by the next prime above
    /// it passes steps 1 to 6 (`n′` is prime and the Hasse quotient is still
    /// 1) and fails only because `n′G ≠ O`.
    #[test]
    fn order_that_does_not_annihilate_the_base_point_is_refused() {
        let named = p256();
        let two = BigUint::from_u64(2);
        let mut next = named.n.add(&two);
        while !is_probable_prime_untrusted(&next) {
            next = next.add(&two);
        }
        assert!(cofactor_is_hasse_quotient(1, &next, &named.p));
        let claimed = CurveParams::new(
            named.p.clone(),
            named.a.clone(),
            named.b.clone(),
            next.clone(),
            1,
            named.gx.clone(),
            named.gy.clone(),
        )
        .expect("odd prime order");
        assert!(!claimed
            .scalar_mul(&claimed.base_point(), &next)
            .is_infinity());
        assert!(!claimed.validate_domain_parameters());
        assert!(CurveParams::from_explicit(
            ExplicitField::Prime(named.p.clone()),
            named.a.clone(),
            named.b.clone(),
            next,
            1,
            named.gx.clone(),
            named.gy.clone(),
        )
        .is_none());
    }

    /// The anomalous test `hn = q`: P-256's `n` against itself and against
    /// `p`, and a binary-field order with `nh = 2^m`.
    #[test]
    fn anomalous_curves_are_recognised_at_the_helper() {
        let named = p256();
        assert!(is_anomalous(&named.n, 1, &named.n));
        assert!(!is_anomalous(&named.n, 1, &named.p));
        assert!(!is_anomalous(&named.n, 2, &named.n));
        let mut q = BigUint::one();
        q.shl_bits(163);
        let mut n = BigUint::one();
        n.shl_bits(161);
        assert!(is_anomalous(&n, 4, &q));
        assert!(!is_anomalous(&n, 2, &q));
        let k163 = k163();
        assert!(!is_anomalous(&k163.n, k163.h, &q));
    }

    /// A curve that passes steps 1 to 7 and fails step 8 on its embedding
    /// degree. Derived offline in integer arithmetic: `y² = x³ + 1` over
    /// `F_p` with `p ≡ 2 (mod 3)` is supersingular, `#E(F_p) = p + 1`. Let
    /// `n` be the least prime above `⌈2^191/6⌉` with `p = 6n − 1` also
    /// prime; then `p` has 192 bits, `p ≡ 2 (mod 3)`, `#E = 6n`, and
    /// `h = 6 = ⌊(√p + 1)²/n⌋`. `Q = (4, √65)` lies on the curve with
    /// `6Q ≠ O`, so `G = 6Q` has order `n`. Since `p ≡ −1 (mod n)`,
    /// `p² ≡ 1 (mod n)`: the embedding degree is 2, the pairing reduction
    /// applies, and step 8 refuses the curve.
    #[test]
    fn supersingular_curve_is_refused_by_the_embedding_degree_step() {
        let p = from_hex("8000000000000000000000000000000000000000000000e1");
        let n = from_hex("15555555555555555555555555555555555555555555557b");
        let gx = from_hex("07446a2b2373d55fb6a29485637bda00d4f202173147c11e");
        let gy = from_hex("227b9fecf919cbbbde06d20142d845c542c12dba187b6487");
        let (a, b, h) = (BigUint::zero(), BigUint::one(), 6u64);
        assert_eq!(n.mul(&BigUint::from_u64(h)), p.add(&BigUint::one()));
        assert_eq!(p.rem_u64(3), 2);
        let curve = CurveParams::new(
            p.clone(),
            a.clone(),
            b.clone(),
            n.clone(),
            h,
            gx.clone(),
            gy.clone(),
        )
        .expect("odd p and n");
        // Steps 1 to 7 hold.
        assert_eq!(prime_field_security_level(p.bits()), Some(80));
        assert!(is_probable_prime_untrusted(&p));
        assert!(is_probable_prime_untrusted(&n));
        let g = curve.base_point();
        assert!(curve.is_on_curve(&g));
        assert!(cofactor_within_security_level(h, 80));
        assert!(cofactor_is_hasse_quotient(h, &n, &p));
        assert!(curve.scalar_mul(&g, &n).is_infinity());
        assert!(!is_anomalous(&n, h, &p));
        // Step 8: p has order 2 modulo n.
        assert_eq!(p.rem(&n), n.sub(&BigUint::one()));
        assert!(multiplicative_order_at_least(&p, &n, 2));
        assert!(!multiplicative_order_at_least(&p, &n, 3));
        assert!(!curve.validate_domain_parameters());
        assert!(CurveParams::from_explicit(ExplicitField::Prime(p), a, b, n, h, gx, gy).is_none());
    }

    /// The Hasse-quotient decision at the sizes it is used at: for every
    /// named curve the stated cofactor is `⌊(√q + 1)²/n⌋` and neither
    /// neighbour is.
    #[test]
    fn hasse_quotient_holds_for_every_named_curve_and_no_neighbour() {
        for build in NAMED_CURVES {
            let curve = build();
            let q = match curve.gf2m_degree() {
                Some(m) => {
                    let mut q = BigUint::one();
                    q.shl_bits(m);
                    q
                }
                None => curve.p.clone(),
            };
            assert!(cofactor_is_hasse_quotient(curve.h, &curve.n, &q));
            assert!(!cofactor_is_hasse_quotient(curve.h + 1, &curve.n, &q));
            assert!(!cofactor_is_hasse_quotient(curve.h - 1, &curve.n, &q));
        }
    }

    /// A reducible or even-degree binary-field modulus must be refused at
    /// construction: with zero divisors in the ring the point formulas hit an
    /// uninvertible element and would panic on an attacker-supplied key blob.
    #[test]
    fn new_binary_rejects_reducible_or_even_degree_modulus() {
        let n = BigUint::from_u64(7);
        let one = BigUint::one();
        let base = (one.clone(), one.clone());
        // x³ + 1 = (x + 1)(x² + x + 1): reducible.
        assert!(CurveParams::new_binary(
            BigUint::from_u64(0b1001),
            3,
            one.clone(),
            one.clone(),
            n.clone(),
            1,
            base.clone()
        )
        .is_none());
        // x⁴ + x + 1 is irreducible but of even degree: no half-trace.
        assert!(CurveParams::new_binary(
            BigUint::from_u64(0b10011),
            4,
            one.clone(),
            one.clone(),
            n.clone(),
            1,
            base.clone()
        )
        .is_none());
        // x³ + x + 1: irreducible, odd degree.
        assert!(CurveParams::new_binary(
            BigUint::from_u64(0b1011),
            3,
            one.clone(),
            one.clone(),
            n.clone(),
            1,
            base
        )
        .is_some());
        // A subgroup order of 1 makes scalar sampling impossible.
        assert!(CurveParams::new_binary(
            BigUint::from_u64(0b1011),
            3,
            one.clone(),
            one.clone(),
            one.clone(),
            1,
            (one.clone(), one)
        )
        .is_none());
    }

    /// `x + p` satisfies the curve equation once the Montgomery context
    /// reduces it, but it is not a canonical field element: it breaks point
    /// equality and fixed-width encoding, and SEC 1 requires its rejection.
    #[test]
    fn public_point_validation_rejects_non_canonical_coordinates() {
        let curve = p256();
        let shifted = AffinePoint::new(curve.gx.add(&curve.p), curve.gy.clone());
        assert!(curve.is_on_curve(&shifted));
        assert!(!curve.is_valid_public_point(&shifted));
        assert!(curve.is_valid_public_point(&curve.base_point()));
        assert!(!curve.is_valid_public_point(&AffinePoint::infinity()));
    }

    #[test]
    fn same_curve_distinguishes_named_curves() {
        assert!(p256().same_curve(&p256()));
        assert!(!p256().same_curve(&p384()));
        assert!(!p256().same_curve(&secp256k1()));
        assert!(!b163().same_curve(&k163()));
    }

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
        let curve = p224();
        let g = curve.base_point();
        let enc = curve.encode_point(&g);
        let dec = curve.decode_point(&enc).expect("P-224 uncompressed decode");
        assert_eq!(dec, g);
    }

    #[test]
    fn p224_compressed_roundtrip() {
        // P-224 has p ≡ 1 (mod 4), so decompression takes the general
        // Tonelli–Shanks path in rump::mod_sqrt rather than the
        // (p+1)/4 shortcut.
        let curve = p224();
        let g = curve.base_point();
        let enc = curve.encode_point_compressed(&g);
        let dec = curve.decode_point(&enc).expect("P-224 compressed decode");
        assert_eq!(dec, g);

        // Scalar multiples exercise both parities of y.
        for k in [2u64, 3, 5, 27] {
            let point = curve.scalar_mul(&g, &BigUint::from_u64(k));
            let enc = curve.encode_point_compressed(&point);
            let dec = curve.decode_point(&enc).expect("compressed round trip");
            assert_eq!(dec, point);
        }
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

    // ── Differential test: windowed / López–Dahab scalar_mul vs an affine
    //    double-and-add reference ───────────────────────────────────────────
    //
    // For every curve `curve.scalar_mul(G, k)` (a 4-bit fixed window in
    // Jacobian coordinates on prime curves, López–Dahab projective
    // coordinates on binary curves) is compared with `reference_scalar_mul`,
    // a bit-serial double-and-add over affine formulas: on prime curves the
    // chord-and-tangent formulas of `affine_add_prime` below, one modular
    // inversion per step and no code in common with the Jacobian path; on
    // binary curves `add_binary`/`double_binary`, which share nothing with
    // the López–Dahab formulas. The comparison therefore checks the
    // projective formulas as well as the window bookkeeping. Scalars include
    // the edge cases 0, 1, 2, n−1, n, n+1 plus deterministic pseudo-random
    // full-width values, so every window boundary is exercised.

    /// A tiny deterministic xorshift64* PRNG for reproducible test scalars.
    struct XorShift64 {
        state: u64,
    }

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            // Avoid the fixed point at 0.
            Self { state: seed | 1 }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        /// A pseudo-random `BigUint` of `byte_len` bytes.
        fn random_biguint(&mut self, byte_len: usize) -> BigUint {
            let mut bytes = vec![0u8; byte_len];
            for b in bytes.iter_mut() {
                *b = (self.next_u64() & 0xff) as u8;
            }
            BigUint::from_be_bytes(&bytes)
        }
    }

    /// Chord-and-tangent addition on `y² = x³ + ax + b` over `F_p` in affine
    /// coordinates, one modular inversion per step (SEC 1 §2.2.1):
    /// `λ = (y₂ − y₁)/(x₂ − x₁)`, or `(3x₁² + a)/(2y₁)` when `P = Q`;
    /// `x₃ = λ² − x₁ − x₂`, `y₃ = λ(x₁ − x₃) − y₁`. `P + (−P) = ∞`, which
    /// covers doubling a point with `y = 0`.
    fn affine_add_prime(curve: &CurveParams, p: &AffinePoint, q: &AffinePoint) -> AffinePoint {
        if p.is_infinity() {
            return q.clone();
        }
        if q.is_infinity() {
            return p.clone();
        }
        let m = &curve.p;
        let mul = |a: &BigUint, b: &BigUint| BigUint::mod_mul(a, b, m);
        let sub = |a: &BigUint, b: &BigUint| BigUint::mod_sub(a, b, m);
        let add = |a: &BigUint, b: &BigUint| BigUint::mod_add(a, b, m);
        let (numerator, denominator) = if p.x == q.x {
            if add(&p.y, &q.y).is_zero() {
                return AffinePoint::infinity();
            }
            let three_x_squared = mul(&BigUint::from_u64(3), &mul(&p.x, &p.x));
            (add(&three_x_squared, &curve.a), add(&p.y, &p.y))
        } else {
            (sub(&q.y, &p.y), sub(&q.x, &p.x))
        };
        let lambda = mul(
            &numerator,
            &mod_inverse(&denominator, m).expect("non-zero denominator"),
        );
        let x3 = sub(&sub(&mul(&lambda, &lambda), &p.x), &q.x);
        let y3 = sub(&mul(&lambda, &sub(&p.x, &x3)), &p.y);
        AffinePoint::new(x3, y3)
    }

    /// Reference scalar multiplication: bit-serial left-to-right
    /// double-and-add over affine formulas, [`affine_add_prime`] on prime
    /// curves and [`add_binary`]/[`double_binary`] on binary ones. Neither
    /// shares code with the projective paths under test.
    fn reference_scalar_mul(curve: &CurveParams, point: &AffinePoint, k: &BigUint) -> AffinePoint {
        if k.is_zero() || point.is_infinity() {
            return AffinePoint::infinity();
        }
        match &curve.field {
            FieldCtx::Prime(_) => {
                let mut result = AffinePoint::infinity();
                for i in (0..k.bits()).rev() {
                    result = affine_add_prime(curve, &result, &result);
                    if k.bit(i) {
                        result = affine_add_prime(curve, &result, point);
                    }
                }
                result
            }
            FieldCtx::Binary(_) => {
                let mut result = AffinePoint::infinity();
                for i in (0..k.bits()).rev() {
                    result = curve.double(&result);
                    if k.bit(i) {
                        result = curve.add(&result, point);
                    }
                }
                result
            }
        }
    }

    /// Assert `scalar_mul` agrees with the reference on edge and random scalars.
    fn differential_check(curve: &CurveParams, seed: u64, random_count: usize) {
        let g = curve.base_point();
        let n = &curve.n;
        let one = BigUint::one();
        let byte_len = n.bits().div_ceil(8);

        let mut scalars: Vec<BigUint> = vec![
            BigUint::zero(),
            one.clone(),
            BigUint::from_u64(2),
            n.sub(&one),
            n.clone(),
            n.add(&one),
        ];
        let mut rng = XorShift64::new(seed);
        for _ in 0..random_count {
            scalars.push(rng.random_biguint(byte_len));
        }

        for k in &scalars {
            let got = curve.scalar_mul(&g, k);
            let want = reference_scalar_mul(curve, &g, k);
            assert_eq!(
                got,
                want,
                "scalar_mul disagreed with reference double-and-add for k = {:02x?}",
                k.to_be_bytes()
            );
            // Every result must also lie on the curve (or be ∞).
            assert!(
                curve.is_on_curve(&got),
                "scalar_mul produced an off-curve point for k = {:02x?}",
                k.to_be_bytes()
            );
        }
    }

    const DIFF_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

    macro_rules! differential_test {
        ($name:ident, $constructor:ident, $count:expr) => {
            #[test]
            fn $name() {
                differential_check(&$constructor(), DIFF_SEED, $count);
            }
        };
    }

    // Prime curves (windowed path). The reference is cheap here, so use a
    // generous number of random scalars.
    differential_test!(diff_p192, p192, 32);
    differential_test!(diff_p224, p224, 32);
    differential_test!(diff_p256, p256, 32);
    differential_test!(diff_secp256k1, secp256k1, 32);
    differential_test!(diff_p384, p384, 24);
    differential_test!(diff_p521, p521, 24);

    // Binary curves (López–Dahab path).
    differential_test!(diff_b163, b163, 10);
    differential_test!(diff_k163, k163, 10);
    differential_test!(diff_b233, b233, 8);
    differential_test!(diff_k233, k233, 8);
    differential_test!(diff_b283, b283, 6);
    differential_test!(diff_k283, k283, 6);
    differential_test!(diff_b409, b409, 3);
    differential_test!(diff_k409, k409, 3);
    differential_test!(diff_b571, b571, 2);
    differential_test!(diff_k571, k571, 2);

    /// SEC 1 §2.3.4 step 1 decodes the octet `00` to `∞`, which passes the
    /// subgroup test (`n·∞ = ∞`) but never public-key validation (§3.2.2.1
    /// step 1). A private scalar yields a public point only when `d·G` is a
    /// valid one, which fails when the stated `n` is not the order of `G`.
    #[test]
    fn identity_decodes_but_is_never_a_valid_public_point() {
        let curve = p256();
        let identity = curve.decode_point(&[0x00]).expect("SEC 1 §2.3.4 step 1");
        assert!(identity.is_infinity());
        assert!(curve.is_in_prime_subgroup(&identity));
        assert!(!curve.is_valid_public_point(&identity));
        assert!(curve.is_valid_public_point(&curve.base_point()));

        assert_eq!(
            curve.public_point_for_scalar(&BigUint::one()),
            Some(curve.base_point())
        );
        assert!(curve.public_point_for_scalar(&BigUint::zero()).is_none());
        assert!(curve.public_point_for_scalar(&curve.n).is_none());

        // P-256 claiming the order 3n: d = n is in range, and n·G = ∞.
        let tripled = CurveParams::new(
            curve.p.clone(),
            curve.a.clone(),
            curve.b.clone(),
            curve.n.mul(&BigUint::from_u64(3)),
            curve.h,
            curve.gx.clone(),
            curve.gy.clone(),
        )
        .expect("3n is odd");
        assert_eq!(
            tripled.public_point_for_scalar(&BigUint::one()),
            Some(tripled.base_point())
        );
        assert!(tripled.public_point_for_scalar(&curve.n).is_none());
    }
}
