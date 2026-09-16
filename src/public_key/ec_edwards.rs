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
//! Points are encoded as RFC 8032 §5.1.2 and §5.2.2 encode them: `y` as a
//! little-endian string of `b` bits with the low bit of `x` (its sign) in the
//! most-significant bit, where `b` is the least multiple of 8 above the bit
//! length of `p`. That is 256 bits (32 octets) for Ed25519's 255-bit `p` and
//! 456 bits (57 octets) for Ed448's 448-bit `p`; the sign bit never overlaps
//! `y`, whose bits all lie below the bit length of `p`.
//!
//! ## Domain parameters
//!
//! [`TwistedEdwardsCurve::new`] builds a curve from parameters the caller
//! vouches for. Parameters that arrive from outside the process go through
//! [`TwistedEdwardsCurve::from_explicit`], which validates them as SEC 1
//! §3.1.1.2.1 validates short-Weierstrass parameters, with the cheap size
//! checks first so a hostile encoding cannot buy a long computation.
//!
//! ## Side-channel note
//!
//! Scalar multiplication is variable-time: the fixed-window ladders select
//! precomputed entries by secret scalar windows, their iteration count follows
//! the scalar's bit length, and the doubling formula branches on a neutral
//! accumulator. The generic path and the specialized Ed25519 base-point path
//! are alike in this, so this code is **not constant-time** and is unsuitable
//! where timing or power measurements of the scalar are possible.
//!
//! ## Field square root
//!
//! Point decompression recovers `x` from `x² = (y² − 1) / (d·y² − a)` and
//! takes the square root with `rump::modular::mod_sqrt`, which works in any
//! odd prime field, so one path serves Ed25519 (`p ≡ 5 (mod 8)`) and curves
//! such as Ed448 (`p ≡ 3 (mod 4)`) alike. When `x²` is a non-residue the
//! decode fails; otherwise the root whose low bit matches the encoded sign
//! bit is kept, as in RFC 8032 §5.1.3 step 4.

use crate::public_key::primes::{is_probable_prime_untrusted, random_nonzero_below};
use crate::Csprng;
use rump::modular::mod_inverse;
use rump::modular::{mod_sqrt, MontgomeryContext, MontgomeryResidue, MontgomeryScratch};
use rump::number_theory::legendre;
use rump::BigUint;
use std::sync::OnceLock;

/// The largest field prime [`TwistedEdwardsCurve::from_explicit`] accepts, in
/// bits. This is a denial-of-service bound, not a security parameter: the
/// primality tests and the `[n]G` ladder that validation runs cost time
/// proportional to a power of the field size, and the bound caps what an
/// imported key can make the parser spend. Every standardised Edwards curve
/// (Ed25519's 255-bit `p`, Ed448's 448-bit `p`) lies well inside it.
pub const MAX_EXPLICIT_FIELD_BITS: usize = 1024;

/// The largest cofactor [`TwistedEdwardsCurve::from_explicit`] accepts. Both
/// RFC 8032 curves have `h ≤ 8` (`8` for Ed25519, `4` for Ed448).
pub const MAX_EXPLICIT_COFACTOR: u64 = 8;

// ─── Core types ─────────────────────────────────────────────────────────────

/// Parameters for a twisted Edwards curve `a·x² + y² = 1 + d·x²·y² (mod p)`.
///
/// All constants are ordinary residues in `[0, p)`.  Two [`MontgomeryContext`]
/// values are pre-built at construction: one for field arithmetic mod `p` and
/// one for scalar arithmetic mod `n`.  Montgomery encodings of `a` and
/// `2·d mod p` are also cached because the extended-coordinate formulas
/// multiply by them in the hot path.
#[derive(Clone, Debug)]
pub struct TwistedEdwardsCurve {
    /// Field prime `p`.
    pub p: BigUint,
    /// Curve coefficient `a`.  For Ed25519 this is `p − 1` (i.e. `−1 mod p`).
    pub a: BigUint,
    /// Curve coefficient `d`.
    pub d: BigUint,
    /// Prime order of the base-point subgroup.
    pub n: BigUint,
    /// x-coordinate of the standard base point `G`.
    pub gx: BigUint,
    /// y-coordinate of the standard base point `G`.
    pub gy: BigUint,
    /// Montgomery arithmetic for the field mod `p`, with the residues the
    /// extended-coordinate formulas multiply by in the hot path.
    pub(crate) field: EdwardsFieldCtx,
    /// Precomputed Montgomery context for scalar arithmetic mod `n`,
    /// reached through [`Self::scalar_ctx`] by the signature schemes for
    /// their products modulo the subgroup order.
    scalar: MontgomeryContext,
    /// Octet length of a point encoding: `⌈(p.bits() + 1) / 8⌉`, which is
    /// `b / 8` in RFC 8032's terms. The extra bit over the length of `p`
    /// holds the sign of `x`; it is the most-significant bit of the last
    /// octet, which no bit of a canonical `y < p` reaches.
    pub coord_len: usize,
}

/// Montgomery arithmetic for a twisted Edwards curve's prime field.
///
/// Bundles the [`MontgomeryContext`] for `p` with the residues the
/// extended-coordinate formulas need ready-made: the curve coefficient `a`,
/// the doubled coefficient `2·d` (which feeds the unified addition formula),
/// and the zero residue so neutral checks are plain comparisons.
///
/// Every residue in a curve computation comes from this one context, so the
/// `ContextMismatch` the residue operations report is unreachable here; the
/// methods below unwrap it and keep the formulas readable.
#[derive(Clone, Debug)]
pub(crate) struct EdwardsFieldCtx {
    /// Montgomery context for arithmetic mod `p`.
    ctx: MontgomeryContext,
    /// Curve coefficient `a`, encoded once into the Montgomery domain.
    a_mont: MontgomeryResidue,
    /// `true` when `a ≡ −1 (mod p)`, which selects the cheaper `a = −1`
    /// addition formula (Ed25519); other `a` take the general formula.
    a_is_minus_one: bool,
    /// `d mod p`, encoded once into the Montgomery domain.
    d_mont: MontgomeryResidue,
    /// `2·d mod p`, encoded once into the Montgomery domain.
    d2_mont: MontgomeryResidue,
    /// The zero residue of the field.
    zero: MontgomeryResidue,
}

impl EdwardsFieldCtx {
    const SAME_CTX: &'static str = "curve residues share the curve's field context";

    fn new(ctx: MontgomeryContext, a: &BigUint, d: &BigUint, d2: &BigUint) -> Self {
        let a_mont = ctx.to_residue(a);
        let a_is_minus_one = *a == ctx.modulus().sub(&BigUint::one());
        let d_mont = ctx.to_residue(d);
        let d2_mont = ctx.to_residue(d2);
        let zero = ctx.to_residue(&BigUint::zero());
        Self {
            ctx,
            a_mont,
            a_is_minus_one,
            d_mont,
            d2_mont,
            zero,
        }
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

    /// `d mod p` as a residue, which the general-`a` addition multiplies by.
    #[inline]
    fn d_mont(&self) -> &MontgomeryResidue {
        &self.d_mont
    }

    /// `2·d mod p` as a residue, which the `a = −1` addition multiplies by.
    #[inline]
    fn d2_mont(&self) -> &MontgomeryResidue {
        &self.d2_mont
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
#[derive(Clone, Debug)]
struct ExtendedPoint {
    x: MontgomeryResidue,
    y: MontgomeryResidue,
    z: MontgomeryResidue,
    t: MontgomeryResidue,
}

const SCALAR_WINDOW_BITS: usize = 4;
const ED25519_BASE_WINDOW_BITS: usize = 8;
const CACHED_PUBLIC_WINDOW_BITS: usize = 8;

/// Cached precompute table for repeated variable-base scalar multiplication.
///
/// Carries the [`EdwardsFieldCtx`] that built it: the table's residues are
/// bound to that exact context (rump checks residue provenance, not modulus
/// equality), so cached multiplication always runs on the table's own field
/// state, whichever structurally-equal curve instance asks for it.
#[derive(Clone, Debug)]
pub(crate) struct EdwardsMulTable {
    fld: EdwardsFieldCtx,
    table: Vec<ExtendedPoint>,
    window_bits: usize,
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
    /// The neutral element `(0, 1, 1, 0)` in extended coordinates, as
    /// residues of `fld`.
    fn neutral(fld: &EdwardsFieldCtx) -> Self {
        Self {
            x: fld.zero().clone(),
            y: fld.one(),
            z: fld.one(),
            t: fld.zero().clone(),
        }
    }

    fn is_neutral(&self, fld: &EdwardsFieldCtx) -> bool {
        fld.is_zero(&self.x) && self.y == self.z
    }

    /// Lift an affine point to extended coordinates with `Z = 1`, encoding
    /// every coordinate into the Montgomery domain.
    ///
    /// For affine `(x, y)`: extended `(x, y, 1, x·y)`.
    /// For the neutral element `(0, 1)`: extended `(0, 1, 1, 0)`.
    fn from_affine(p: &EdwardsPoint, fld: &EdwardsFieldCtx) -> Self {
        if p.neutral {
            return Self::neutral(fld);
        }
        let x = fld.to_residue(&p.x);
        let y = fld.to_residue(&p.y);
        let t = fld.mul(&x, &y, &mut MontgomeryScratch::new());
        Self {
            x,
            y,
            z: fld.one(),
            t,
        }
    }

    /// Convert back to affine coordinates (and out of the Montgomery domain).
    ///
    /// Recovers `x = X/Z` and `y = Y/Z` via Fermat inversion
    /// `Z⁻¹ = Z^{p−2} mod p`.  The projective neutral `(0 : Z : Z : 0)` is
    /// canonicalized back to the affine identity `(0, 1)` so the explicit
    /// `neutral` flag always stays in sync with the coordinates.
    ///
    /// `Z = 0` names no point. The addition law is complete on the curves
    /// this module admits (see [`point_add_extended`]), so `Z = 0` cannot
    /// arise from curve points; it can arise from coordinates that were never
    /// on the curve, fed in through [`EdwardsPoint::new`] unchecked. Such a
    /// value comes back as the affine pair `(0, 0)`, which lies on no twisted
    /// Edwards curve (`a·0 + 0 ≠ 1`), so [`TwistedEdwardsCurve::is_on_curve`]
    /// reports it rather than passing garbage off as a point.
    fn to_affine(&self, fld: &EdwardsFieldCtx) -> EdwardsPoint {
        if self.is_neutral(fld) {
            return EdwardsPoint::neutral();
        }
        if fld.is_zero(&self.z) {
            return EdwardsPoint::new(BigUint::zero(), BigUint::zero());
        }

        let ctx = fld.ctx();

        // Fast path: a freshly lifted affine point keeps `Z = 1` until it
        // actually goes through a non-trivial addition or doubling.  In that
        // case there is no need to pay for a Fermat inversion.
        if self.z == ctx.one() {
            return EdwardsPoint::new(fld.decode(&self.x), fld.decode(&self.y));
        }

        let x = fld.decode(&self.x);
        let y = fld.decode(&self.y);
        let z = fld.decode(&self.z);

        let p_minus_2 = ctx.modulus().sub(&BigUint::from_u64(2));
        let z_inv = ctx.pow(&z, &p_minus_2);

        let x = ctx.mul(&x, &z_inv);
        let y = ctx.mul(&y, &z_inv);

        EdwardsPoint::new(x, y)
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
/// `P₁ = −P₂` (result is the neutral). It is *complete*, working for every
/// pair of curve points, under the condition RFC 8032 §5.1.4 states for it,
/// from §3.1 of Hisil, Wong, Carter and Dawson's "Twisted Edwards Curves
/// Revisited": `a` a square and `d` a non-square in the field. With `a = −1`
/// that requires `p ≡ 1 (mod 4)`; Ed25519's `p = 2²⁵⁵ − 19 ≡ 5 (mod 8)`
/// satisfies it, and its `d` is a non-square.
///
/// That formula is specific to `a = −1`. For any other `a` the function
/// takes the general unified addition of the same paper (§3.1, `add-2008-hwcd`
/// in the EFD): `A = X₁X₂`, `B = Y₁Y₂`, `C = d·T₁T₂`, `D = Z₁Z₂`,
/// `E = (X₁+Y₁)(X₂+Y₂) − A − B`, `F = D − C`, `G = D + C`, `H = B − a·A`,
/// one multiplication by `a` dearer and complete under the same condition
/// (Ed448: `a = 1`, `d = −39081` a non-square). [`TwistedEdwardsCurve::from_explicit`]
/// admits only curves that meet it.
fn point_add_extended(
    fld: &EdwardsFieldCtx,
    p1: &ExtendedPoint,
    p2: &ExtendedPoint,
    scratch: &mut MontgomeryScratch,
) -> ExtendedPoint {
    if !fld.a_is_minus_one {
        let a = fld.mul(&p1.x, &p2.x, scratch);
        let b = fld.mul(&p1.y, &p2.y, scratch);
        let t2d = fld.mul(&p2.t, fld.d_mont(), scratch);
        let c = fld.mul(&p1.t, &t2d, scratch);
        let d = fld.mul(&p1.z, &p2.z, scratch);
        let x1y1 = fld.add(&p1.x, &p1.y);
        let x2y2 = fld.add(&p2.x, &p2.y);
        let e = fld.sub(&fld.sub(&fld.mul(&x1y1, &x2y2, scratch), &a), &b);
        let f = fld.sub(&d, &c);
        let g = fld.add(&d, &c);
        let a_a = fld.mul(fld.a_mont(), &a, scratch);
        let h = fld.sub(&b, &a_a);
        return ExtendedPoint {
            x: fld.mul(&e, &f, scratch),
            y: fld.mul(&g, &h, scratch),
            z: fld.mul(&f, &g, scratch),
            t: fld.mul(&e, &h, scratch),
        };
    }

    // A = (Y₁ − X₁)·(Y₂ − X₂)
    let y1_m_x1 = fld.sub(&p1.y, &p1.x);
    let y2_m_x2 = fld.sub(&p2.y, &p2.x);
    let a = fld.mul(&y1_m_x1, &y2_m_x2, scratch);

    // B = (Y₁ + X₁)·(Y₂ + X₂)
    let y1_p_x1 = fld.add(&p1.y, &p1.x);
    let y2_p_x2 = fld.add(&p2.y, &p2.x);
    let b = fld.mul(&y1_p_x1, &y2_p_x2, scratch);

    // C = T₁·2d·T₂  (using the precomputed residue d2 = 2d mod p)
    let t2_scaled = fld.mul(&p2.t, fld.d2_mont(), scratch);
    let c = fld.mul(&p1.t, &t2_scaled, scratch);

    // D = Z₁·2·Z₂  =  2·(Z₁·Z₂)
    let z1z2 = fld.mul(&p1.z, &p2.z, scratch);
    let d = fld.add(&z1z2, &z1z2);

    // E = B−A,  F = D−C,  G = D+C,  H = B+A
    let e = fld.sub(&b, &a);
    let f = fld.sub(&d, &c);
    let g = fld.add(&d, &c);
    let h = fld.add(&b, &a); // a = −1: H = B − a·A = B + A

    ExtendedPoint {
        x: fld.mul(&e, &f, scratch),
        y: fld.mul(&g, &h, scratch),
        z: fld.mul(&f, &g, scratch),
        t: fld.mul(&e, &h, scratch),
    }
}

/// Point doubling via the unified addition formula with `P₁ = P₂`.
///
/// Uses the dedicated "dbl-2008-hwcd" formula for extended twisted Edwards
/// coordinates. For the built-in Ed25519 domain (`a = -1`) this saves field
/// multiplications compared with reusing the unified addition formula.
fn point_double_extended(
    fld: &EdwardsFieldCtx,
    p1: &ExtendedPoint,
    scratch: &mut MontgomeryScratch,
) -> ExtendedPoint {
    if p1.is_neutral(fld) {
        return ExtendedPoint::neutral(fld);
    }

    let a = fld.sqr(&p1.x, scratch);
    let b = fld.sqr(&p1.y, scratch);
    let z2 = fld.sqr(&p1.z, scratch);
    let c = fld.add(&z2, &z2);
    let d = fld.mul(fld.a_mont(), &a, scratch);
    let x_plus_y = fld.add(&p1.x, &p1.y);
    let e = {
        let sum_sq = fld.sqr(&x_plus_y, scratch);
        fld.sub(&fld.sub(&sum_sq, &a), &b)
    };
    let g = fld.add(&d, &b);
    let f = fld.sub(&g, &c);
    let h = fld.sub(&d, &b);

    ExtendedPoint {
        x: fld.mul(&e, &f, scratch),
        y: fld.mul(&g, &h, scratch),
        t: fld.mul(&e, &h, scratch),
        z: fld.mul(&f, &g, scratch),
    }
}

/// Extract a `width`-bit little-endian window from `k`, starting at `bit_offset`.
#[inline]
fn scalar_window(k: &BigUint, bit_offset: usize, width: usize) -> usize {
    let mut value = 0usize;
    for bit in 0..width {
        if k.bit(bit_offset + bit) {
            value |= 1usize << bit;
        }
    }
    value
}

fn precompute_window_table(
    fld: &EdwardsFieldCtx,
    point: &ExtendedPoint,
    window_bits: usize,
) -> Vec<ExtendedPoint> {
    let table_size = 1usize << window_bits;
    let mut scratch = MontgomeryScratch::new();
    let mut table = Vec::with_capacity(table_size);
    table.push(ExtendedPoint::neutral(fld));
    table.push(point.clone());
    for _ in 2..table_size {
        let next = point_add_extended(
            fld,
            table.last().expect("table non-empty"),
            point,
            &mut scratch,
        );
        table.push(next);
    }
    table
}

fn scalar_mul_with_table(
    fld: &EdwardsFieldCtx,
    k: &BigUint,
    table: &[ExtendedPoint],
    window_bits: usize,
) -> EdwardsPoint {
    if k.is_zero() {
        return EdwardsPoint::neutral();
    }

    // One scratch buffer serves every multiply and square in the ladder.
    let mut scratch = MontgomeryScratch::new();
    let mut result = ExtendedPoint::neutral(fld);
    let windows = k.bits().div_ceil(window_bits);
    for window_index in (0..windows).rev() {
        for _ in 0..window_bits {
            result = point_double_extended(fld, &result, &mut scratch);
        }
        let value = scalar_window(k, window_index * window_bits, window_bits);
        result = point_add_extended(fld, &result, &table[value], &mut scratch);
    }

    result.to_affine(fld)
}

fn cached_ed25519() -> &'static TwistedEdwardsCurve {
    static CURVE: OnceLock<TwistedEdwardsCurve> = OnceLock::new();
    CURVE.get_or_init(ed25519)
}

fn is_ed25519_curve(curve: &TwistedEdwardsCurve) -> bool {
    let reference = cached_ed25519();
    curve.p == reference.p
        && curve.a == reference.a
        && curve.d == reference.d
        && curve.n == reference.n
        && curve.gx == reference.gx
        && curve.gy == reference.gy
}

fn ed25519_base_table() -> &'static [ExtendedPoint] {
    static TABLE: OnceLock<Vec<ExtendedPoint>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            let curve = cached_ed25519();
            let base = ExtendedPoint::from_affine(&curve.base_point(), &curve.field);
            precompute_window_table(&curve.field, &base, ED25519_BASE_WINDOW_BITS)
        })
        .as_slice()
}

/// Scalar multiplication `k·P` via a fixed-window left-to-right method.
///
/// The loop stays in extended coordinates throughout; a single conversion
/// to affine is paid at the end. One table-backed addition per window
/// replaces the conditional additions of bit-by-bit double-and-add.
///
/// **Side-channel note**: this ladder is variable-time in the scalar. The
/// window count follows `k.bits()`, the table index is a window of `k`, and
/// [`point_double_extended`] branches on a neutral accumulator, which the
/// leading zero windows of a short scalar keep neutral.
fn scalar_mul_extended(
    curve: &TwistedEdwardsCurve,
    point: &EdwardsPoint,
    k: &BigUint,
) -> EdwardsPoint {
    if k.is_zero() || point.is_neutral() {
        return EdwardsPoint::neutral();
    }

    let p_ext = ExtendedPoint::from_affine(point, &curve.field);
    let table = precompute_window_table(&curve.field, &p_ext, SCALAR_WINDOW_BITS);
    scalar_mul_with_table(&curve.field, k, &table, SCALAR_WINDOW_BITS)
}

// ─── Domain-parameter validation ────────────────────────────────────────────

/// Whether `h = ⌊(√p + 1)² / n⌋` (SEC 1 §3.1.1.2.1 step 6), decided in
/// integers: `(√p + 1)² = p + 1 + 2√p`, so `hn ≤ (√p + 1)²` exactly when
/// `hn ≤ p + 1` or `(hn − p − 1)² ≤ 4p`, and `(h + 1)n > (√p + 1)²` exactly
/// when `(h + 1)n > p + 1` and `((h + 1)n − p − 1)² > 4p`.
fn cofactor_is_hasse_quotient(h: u64, n: &BigUint, p: &BigUint) -> bool {
    let Some(h_plus_one) = h.checked_add(1) else {
        return false;
    };
    let p_plus_one = p.add(&BigUint::one());
    let four_p = p.mul(&BigUint::from_u64(4));
    let lower = n.mul(&BigUint::from_u64(h));
    let upper = n.mul(&BigUint::from_u64(h_plus_one));
    let lower_holds = lower <= p_plus_one || lower.sub(&p_plus_one).square() <= four_p;
    let upper_holds = upper > p_plus_one && upper.sub(&p_plus_one).square() > four_p;
    lower_holds && upper_holds
}

/// Whether `base^B ≢ 1 (mod n)` for every `1 ≤ B < bound`: SEC 1
/// §3.1.1.2.1 step 7 with `base = p` and `bound = 100`. This excludes the
/// curves whose embedding degree is small enough for the
/// Menezes–Okamoto–Vanstone and Frey–Rück reductions.
fn no_small_embedding_degree(base: &BigUint, n: &BigUint, bound: usize) -> bool {
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

// ─── TwistedEdwardsCurve ────────────────────────────────────────────────────

impl TwistedEdwardsCurve {
    /// Construct curve parameters from raw field values the caller vouches
    /// for: the named-curve constructor and callers that generated the
    /// parameters themselves. Parameters that arrive from outside the process
    /// go through [`Self::from_explicit`], which validates them.
    ///
    /// Returns `None` if the field prime `p` or subgroup order `n` is even,
    /// which prevents building a `MontgomeryContext`, or is `1`, which would
    /// leave no scalar for [`Self::random_scalar`] to draw from.
    #[must_use]
    pub fn new(
        p: BigUint,
        a: BigUint,
        d: BigUint,
        n: BigUint,
        gx: BigUint,
        gy: BigUint,
    ) -> Option<Self> {
        if p <= BigUint::one() || n <= BigUint::one() {
            return None;
        }
        let field = MontgomeryContext::new(&p).ok()?;
        let scalar = MontgomeryContext::new(&n).ok()?;
        let coord_len = (p.bits() + 1).div_ceil(8);
        let d2 = {
            let v = d.add(&d);
            if v.cmp(&p).is_ge() {
                v.sub(&p)
            } else {
                v
            }
        };
        let field = EdwardsFieldCtx::new(field, &a, &d, &d2);
        Some(Self {
            p,
            a,
            d,
            n,
            gx,
            gy,
            field,
            scalar,
            coord_len,
        })
    }

    /// Construct curve parameters that arrived from outside the process,
    /// validating them first.
    ///
    /// This is the twisted Edwards analogue of SEC 1 §3.1.1.2.1's validation
    /// primitive. The checks run cheapest first, so a hostile encoding is
    /// refused before it can buy a long computation:
    ///
    /// 1. The named Ed25519 parameters are accepted by comparison.
    /// 2. `p` has at most [`MAX_EXPLICIT_FIELD_BITS`] bits (the
    ///    denial-of-service bound), `n` at most `p.bits() + 1` (Hasse's bound
    ///    puts `n ≤ #E < (√p + 1)² < 2p`), and `a`, `d`, `gx`, `gy` are reduced
    ///    below `p`, with `a` and `d` non-zero and `a ≠ d` (otherwise the
    ///    equation is not a twisted Edwards curve).
    /// 3. `p` and `n` are odd primes by the hardened test, and `n ≠ p`
    ///    (SEC 1 step 8 excludes anomalous curves).
    /// 4. `a` is a square and `d` a non-square modulo `p`: the condition
    ///    under which the addition law is complete (RFC 8032 §5.1.4, citing
    ///    §3.1 of Hisil, Wong, Carter and Dawson).
    /// 5. `G` lies on the curve.
    /// 6. The cofactor `h = ⌊(√p + 1)² / n⌋`, decided in integers as SEC 1
    ///    step 6 does, is at most [`MAX_EXPLICIT_COFACTOR`] and even: every
    ///    twisted Edwards curve contains the point `(0, −1)` of order 2, so
    ///    the group order `h·n` is even while `n` is odd.
    /// 7. `n` has no small embedding degree: `p^B ≢ 1 (mod n)` for
    ///    `1 ≤ B < 100` (SEC 1 step 7).
    /// 8. `[n]G` is the neutral element (SEC 1 step 5), the one scalar
    ///    multiplication, bounded by the sizes checked above.
    ///
    /// Returns `None` when any check fails.
    #[must_use]
    pub fn from_explicit(
        p: BigUint,
        a: BigUint,
        d: BigUint,
        n: BigUint,
        gx: BigUint,
        gy: BigUint,
    ) -> Option<Self> {
        let named = cached_ed25519();
        if p == named.p
            && a == named.a
            && d == named.d
            && n == named.n
            && gx == named.gx
            && gy == named.gy
        {
            return Some(named.clone());
        }

        // Sizes and ranges: constant work in the encoding's length.
        if p.bits() > MAX_EXPLICIT_FIELD_BITS || n.bits() > p.bits() + 1 {
            return None;
        }
        if [&a, &d, &gx, &gy].into_iter().any(|v| v >= &p) {
            return None;
        }
        if a.is_zero() || d.is_zero() || a == d {
            return None;
        }
        if n == p {
            return None;
        }

        // Primality of p and n, then the Montgomery contexts.
        if !p.is_odd() || !is_probable_prime_untrusted(&p) {
            return None;
        }
        if !n.is_odd() || !is_probable_prime_untrusted(&n) {
            return None;
        }
        let curve = Self::new(p, a, d, n, gx, gy)?;

        // Completeness of the addition law: a a square, d a non-square.
        if legendre(&curve.a, &curve.p) != Some(1) || legendre(&curve.d, &curve.p) != Some(-1) {
            return None;
        }

        let g = curve.base_point();
        if !curve.is_on_curve(&g) {
            return None;
        }

        let h = (1..=MAX_EXPLICIT_COFACTOR)
            .find(|&h| cofactor_is_hasse_quotient(h, &curve.n, &curve.p))?;
        if h % 2 != 0 {
            return None;
        }

        if !no_small_embedding_degree(&curve.p, &curve.n, 100) {
            return None;
        }

        // The one full scalar multiplication, last.
        if !scalar_mul_extended(&curve, &g, &curve.n).is_neutral() {
            return None;
        }
        Some(curve)
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
        let ctx = self.field.ctx();
        let x2 = ctx.square(&point.x);
        let y2 = ctx.square(&point.y);
        // lhs = a·x² + y²
        let ax2 = ctx.mul(&self.a, &x2);
        let lhs = BigUint::mod_add(&ax2, &y2, &self.p);
        // rhs = 1 + d·x²·y²
        let x2y2 = ctx.mul(&x2, &y2);
        let dx2y2 = ctx.mul(&self.d, &x2y2);
        let rhs = BigUint::mod_add(&BigUint::one(), &dx2y2, &self.p);
        lhs == rhs
    }

    /// `true` if `point` is a canonical point of this curve: the neutral
    /// element, or a pair with both coordinates reduced below `p` (as RFC
    /// 8032 §5.1.3 requires of encodings and SEC 1 §3.2.2.1 of field
    /// elements) that satisfies the curve equation.
    ///
    /// Canonicity is checked before the curve equation: `is_on_curve` reduces
    /// its inputs mod `p`, so a coordinate `x + p` would otherwise pass as `x`.
    /// Membership in the prime-order subgroup is not checked; that is
    /// [`Self::is_valid_public_point`].
    #[must_use]
    pub fn is_canonical_point(&self, point: &EdwardsPoint) -> bool {
        point.is_neutral() || (point.x < self.p && point.y < self.p && self.is_on_curve(point))
    }

    /// `true` if `point` is a usable public point on this curve: not the
    /// neutral element, canonical and on the curve
    /// ([`Self::is_canonical_point`]), and in the prime-order subgroup.
    ///
    /// Every Edwards key and ciphertext decoder in the crate validates through
    /// this one predicate.
    #[must_use]
    pub fn is_valid_public_point(&self, point: &EdwardsPoint) -> bool {
        !point.is_neutral() && self.is_canonical_point(point) && self.is_in_prime_subgroup(point)
    }

    /// `true` if `n·P` is the neutral element, so `P` lies in the subgroup of
    /// prime order `n`.
    #[must_use]
    pub fn is_in_prime_subgroup(&self, point: &EdwardsPoint) -> bool {
        self.scalar_mul(point, &self.n).is_neutral()
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
        EdwardsPoint::new(BigUint::mod_neg(&point.x, &self.p), point.y.clone())
    }

    /// Add two affine curve points.
    #[must_use]
    pub fn add(&self, p: &EdwardsPoint, q: &EdwardsPoint) -> EdwardsPoint {
        let pe = ExtendedPoint::from_affine(p, &self.field);
        let qe = ExtendedPoint::from_affine(q, &self.field);
        point_add_extended(&self.field, &pe, &qe, &mut MontgomeryScratch::new())
            .to_affine(&self.field)
    }

    /// Double an affine curve point (`2P`).
    #[must_use]
    pub fn double(&self, p: &EdwardsPoint) -> EdwardsPoint {
        let pe = ExtendedPoint::from_affine(p, &self.field);
        point_double_extended(&self.field, &pe, &mut MontgomeryScratch::new())
            .to_affine(&self.field)
    }

    /// `[2^k]P`: `k` doublings in extended coordinates, then one conversion
    /// back to affine.
    ///
    /// This is how a cofactor `2^c` is applied; RFC 8032 §5.1.7 multiplies
    /// both sides of its verification equation by `[8]`.
    #[must_use]
    pub(crate) fn mul_by_pow2(&self, p: &EdwardsPoint, k: u32) -> EdwardsPoint {
        let mut scratch = MontgomeryScratch::new();
        let mut acc = ExtendedPoint::from_affine(p, &self.field);
        for _ in 0..k {
            acc = point_double_extended(&self.field, &acc, &mut scratch);
        }
        acc.to_affine(&self.field)
    }

    /// Scalar multiplication `k·P`.
    ///
    /// Returns the neutral element when `k = 0` or `P` is neutral.
    #[must_use]
    pub fn scalar_mul(&self, point: &EdwardsPoint, k: &BigUint) -> EdwardsPoint {
        if !point.neutral && point.x == self.gx && point.y == self.gy {
            return self.scalar_mul_base(k);
        }
        scalar_mul_extended(self, point, k)
    }

    /// Scalar multiplication `k·G` with a dedicated fixed-base path.
    ///
    /// For the built-in Ed25519 domain this uses a cached 8-bit precompute
    /// table for the standard base point, avoiding per-call table generation.
    /// Other Edwards domains fall back to the generic scalar multiplier.
    #[must_use]
    pub fn scalar_mul_base(&self, k: &BigUint) -> EdwardsPoint {
        if k.is_zero() {
            return EdwardsPoint::neutral();
        }
        if is_ed25519_curve(self) {
            // Run the ladder on the cached curve, not `self`: the static
            // table's residues belong to the cached curve's Montgomery
            // context, and rump ties a residue to the exact context that made
            // it (provenance, not modulus equality). The result is affine
            // ordinary coordinates, so it is context-free.
            return scalar_mul_with_table(
                &cached_ed25519().field,
                k,
                ed25519_base_table(),
                ED25519_BASE_WINDOW_BITS,
            );
        }
        scalar_mul_extended(self, &self.base_point(), k)
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
        let q = self.scalar_mul_base(&d);
        (d, q)
    }

    /// Build a cached table for repeated scalar multiplies by a fixed point.
    #[must_use]
    pub(crate) fn precompute_mul_table(&self, point: &EdwardsPoint) -> EdwardsMulTable {
        let point_ext = ExtendedPoint::from_affine(point, &self.field);
        EdwardsMulTable {
            fld: self.field.clone(),
            table: precompute_window_table(&self.field, &point_ext, CACHED_PUBLIC_WINDOW_BITS),
            window_bits: CACHED_PUBLIC_WINDOW_BITS,
        }
    }

    /// Multiply by a point represented by a cached precompute table.
    ///
    /// The ladder runs on the table's own field context, not on `self`'s:
    /// the table's residues are bound to the context that made them (see
    /// [`EdwardsMulTable`]). `self` is required to be a curve over the same
    /// field, which the debug build asserts; the result is affine ordinary
    /// coordinates and so belongs to any structurally-equal curve instance.
    #[must_use]
    pub(crate) fn scalar_mul_cached(&self, table: &EdwardsMulTable, k: &BigUint) -> EdwardsPoint {
        debug_assert!(
            *table.fld.ctx().modulus() == self.p,
            "cached table belongs to a curve over another field"
        );
        scalar_mul_with_table(&table.fld, k, &table.table, table.window_bits)
    }

    /// Compare the structural Edwards parameters, ignoring cached Montgomery state.
    #[must_use]
    pub fn same_curve(&self, other: &Self) -> bool {
        self.p == other.p
            && self.a == other.a
            && self.d == other.d
            && self.n == other.n
            && self.gx == other.gx
            && self.gy == other.gy
    }

    /// Return the Montgomery context for arithmetic modulo the subgroup
    /// order `n` — the modulus the signature schemes multiply in.
    pub(crate) fn scalar_ctx(&self) -> &MontgomeryContext {
        &self.scalar
    }

    /// Compute `k⁻¹ mod n`.  Returns `None` if `k = 0`.
    #[must_use]
    pub fn scalar_invert(&self, k: &BigUint) -> Option<BigUint> {
        mod_inverse(k, &self.n)
    }

    /// Encode a point as RFC 8032 §5.1.2 (Ed25519) and §5.2.2 (Ed448) do.
    ///
    /// Output: `coord_len` octets, little-endian `y`, with the low bit of `x`
    /// stored in the most-significant bit of the last octet (bit
    /// `8·coord_len − 1`). That bit lies above every bit of `y < p`, since
    /// `coord_len` is `⌈(p.bits() + 1) / 8⌉`: 32 octets for Ed25519 and 57
    /// for Ed448, whose §5.2.2 says "the final octet is always zero" before
    /// the sign is copied in.
    ///
    /// The neutral element `(0, 1)` encodes as the encoding of `y = 1` with
    /// sign 0: a first octet of `0x01` and the rest zero.
    #[must_use]
    pub fn encode_point(&self, point: &EdwardsPoint) -> Vec<u8> {
        // For the neutral element (0, 1): y = 1, x = 0 (even); encoding is
        // 01 00 00 ... 00 in little-endian.
        let (x_ref, y_ref) = if point.neutral {
            (&BigUint::zero(), &BigUint::one())
        } else {
            (&point.x, &point.y)
        };

        // y in little-endian, written straight into one buffer: encoding a
        // shared point (Edwards-DH) leaves no second copy behind.
        let mut out = y_ref.to_le_bytes_padded(self.coord_len);

        // Set MSB of last byte to the LSB (sign) of x.
        if x_ref.is_odd() {
            *out.last_mut().expect("coord_len > 0") |= 0x80;
        }
        out
    }

    /// Decode a point from its RFC 8032 §5.1.3 (Ed25519) or §5.2.3 (Ed448)
    /// encoding.
    ///
    /// The sign of `x` is the most-significant bit of the last octet, bit
    /// `8·coord_len − 1` (bit 255 for Ed25519, bit 455 for Ed448, as those
    /// sections say); `y` is the rest, read little-endian. Returns `None` for
    /// input of another length, for `y ≥ p` (step 1, which also refuses any
    /// set bit between the length of `p` and the sign bit, since such a `y`
    /// exceeds `p`), for a `y` whose `x²` has no square root on this curve
    /// (step 3), and for `x = 0` with the sign bit set (step 4). The root
    /// comes from `rump::mod_sqrt`, so every odd prime field decodes.
    #[must_use]
    pub fn decode_point(&self, bytes: &[u8]) -> Option<EdwardsPoint> {
        if bytes.len() != self.coord_len {
            return None;
        }
        let x_odd = (bytes[self.coord_len - 1] & 0x80) != 0;
        let mut y_le = bytes.to_vec();
        *y_le.last_mut().expect("length > 0") &= 0x7f;
        let y = BigUint::from_le_bytes(&y_le);
        if y >= self.p {
            return None;
        }
        let x = self.field_recover_x(&y, x_odd)?;
        if x.is_zero() && x_odd {
            return None;
        }
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
    /// The square root comes from `rump::modular::mod_sqrt`, which handles any
    /// odd prime `p`; the root is negated when its parity differs from `x_odd`.
    ///
    /// Returns `None` if `x²` has no square root in `F_p`.
    fn field_recover_x(&self, y: &BigUint, x_odd: bool) -> Option<BigUint> {
        let ctx = self.field.ctx();

        // x² = (y² − 1) / (d·y² − a)
        // For a = p − 1 (i.e. a = −1): d·y² − a = d·y² + 1.
        let y2 = ctx.square(y);
        let numerator = BigUint::mod_sub(&y2, &BigUint::one(), &self.p);
        let dy2 = ctx.mul(&self.d, &y2);
        let denominator = BigUint::mod_sub(&dy2, &self.a, &self.p); // d·y² − a

        // Compute x² = numerator / denominator via Fermat inversion.
        let p_minus_2 = self.p.sub(&BigUint::from_u64(2));
        let denom_inv = ctx.pow(&denominator, &p_minus_2);
        let x_squared = ctx.mul(&numerator, &denom_inv);

        // Compute the square root of x_squared mod p.
        let x_candidate = mod_sqrt(&x_squared, &self.p)?;

        // Select the root with the requested sign.
        let x = if x_candidate.is_odd() == x_odd {
            x_candidate
        } else {
            BigUint::mod_neg(&x_candidate, &self.p)
        };
        Some(x)
    }
}

// ─── Named curves ────────────────────────────────────────────────────────────

/// Parse a compact hexadecimal string (spaces ignored) into a `BigUint`.
fn from_hex(hex: &str) -> BigUint {
    let cleaned: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    BigUint::from_str_radix(&cleaned, 16).expect("named-curve constant is valid hex")
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
    let a = p.sub(&BigUint::one());
    // d = −121665/121666 mod p  (the specific constant from RFC 8032)
    let d = from_hex("52036CEE 2B6FFE73 8CC74079 7779E898 00700A4D 4141D8AB 75EB4DCA 135978A3");
    // n = 2^252 + 27742317777372353535851937790883648493
    //   (the prime order of the Ed25519 base-point subgroup, called ℓ in RFC 8032)
    let n = from_hex("10000000 00000000 00000000 00000000 14DEF9DE A2F79CD6 5812631A 5CF5D3ED");
    // Base point G = (Gx, Gy)
    // Gy = 4/5 mod p; Gx is the positive (even) square root derived from Gy.
    let gx = from_hex("216936D3 CD6E53FE C0A4E231 FDD6DC5C 692CC760 9525A7B2 C9562D60 8F25D51A");
    let gy = from_hex("6666666666666666 66666666666666666666666666666666 6666666666666658");
    TwistedEdwardsCurve::new(p, a, d, n, gx, gy).expect("Ed25519 parameters are well-formed")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decode_hex;

    /// The Ed448 parameters of RFC 8032 §5.2.1, in the RFC's decimal:
    /// `(p, a, d, n, gx, gy)` with `a = 1` and `d = −39081`.
    fn ed448_parameters() -> (BigUint, BigUint, BigUint, BigUint, BigUint, BigUint) {
        let decimal = |s: &str| BigUint::from_str_radix(s, 10).expect("decimal");
        let p = decimal(
            "726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439",
        );
        let a = BigUint::one();
        let d = p.sub(&BigUint::from_u64(39081));
        let n = decimal(
            "181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779",
        );
        let gx = decimal(
            "224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710",
        );
        let gy = decimal(
            "298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660",
        );
        (p, a, d, n, gx, gy)
    }

    /// Ed448 as a caller-vouched curve.
    fn ed448() -> TwistedEdwardsCurve {
        let (p, a, d, n, gx, gy) = ed448_parameters();
        TwistedEdwardsCurve::new(p, a, d, n, gx, gy).expect("Ed448 parameters")
    }

    /// Ed448 (RFC 8032 §5.2.1) has `a = 1`, so it exercises the general
    /// twisted-Edwards addition rather than the `a = −1` shortcut. The base
    /// point must lie on the curve, addition must agree with doubling, and
    /// `n·G` must be the neutral element while `(n + 1)·G = G`.
    #[test]
    fn general_a_addition_agrees_with_doubling_on_ed448() {
        let curve = ed448();
        let n = curve.n.clone();
        let g = curve.base_point();
        assert!(curve.is_on_curve(&g));

        let two_g = curve.double(&g);
        assert_eq!(curve.add(&g, &g), two_g);
        assert!(curve.is_on_curve(&two_g));
        assert_eq!(curve.add(&two_g, &g), curve.add(&g, &two_g));

        assert!(curve.scalar_mul(&g, &n).is_neutral());
        assert_eq!(curve.scalar_mul(&g, &n.add(&BigUint::one())), g);
    }

    /// RFC 8032 §5.2.2: an Ed448 point is 57 octets, `y` in the first 56 and
    /// a final octet that is zero but for the sign of `x`. `p` has 448 bits,
    /// so a 56-octet encoding would have no room for the sign; the multiples
    /// `k·G`, `k = 1..=12`, must round-trip whichever parity `x` has, and
    /// both parities must occur among them.
    #[test]
    fn ed448_encodes_in_57_octets_and_round_trips_both_parities() {
        let curve = ed448();
        assert_eq!(curve.p.bits(), 448);
        assert_eq!(curve.coord_len, 57);
        let g = curve.base_point();
        let (mut odd, mut even) = (0, 0);
        for k in 1u64..=12 {
            let point = curve.scalar_mul(&g, &BigUint::from_u64(k));
            let encoding = curve.encode_point(&point);
            assert_eq!(encoding.len(), 57, "{k}G");
            assert_eq!(
                encoding[56] & 0x7f,
                0,
                "{k}G: final octet carries only the sign"
            );
            if point.x.is_odd() {
                odd += 1;
                assert_eq!(encoding[56], 0x80, "{k}G has odd x");
            } else {
                even += 1;
                assert_eq!(encoding[56], 0x00, "{k}G has even x");
            }
            let decoded = curve.decode_point(&encoding).expect("decode k·G");
            assert_eq!(decoded, point, "{k}G round trip");
            // The point with the other sign is −k·G, not k·G.
            let mut flipped = encoding.clone();
            flipped[56] ^= 0x80;
            assert_eq!(
                curve.decode_point(&flipped).expect("decode −k·G"),
                curve.negate(&point),
                "{k}G with the sign flipped"
            );
        }
        assert!(odd > 0 && even > 0, "{odd} odd, {even} even");
    }

    /// The first Ed448 public key of RFC 8032 §7.4 decodes by §5.2.3 to a
    /// point on the curve, in the prime-order subgroup, that encodes back to
    /// the same 57 octets.
    #[test]
    fn ed448_decodes_the_rfc8032_section_7_4_public_key() {
        let curve = ed448();
        let encoding = decode_hex(concat!(
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778",
            "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        ));
        assert_eq!(encoding.len(), 57);
        let point = curve.decode_point(&encoding).expect("§7.4 public key");
        assert!(curve.is_on_curve(&point));
        assert!(curve.is_valid_public_point(&point));
        assert!(point.x.is_odd(), "the final octet 0x80 says x is odd");
        assert_eq!(curve.encode_point(&point), encoding);
    }

    /// Ed448 also refuses what §5.2.3 refuses: 56 octets, a `y ≥ p` (here
    /// `p` itself, whose bit 448 would sit in the final octet), and any bit
    /// in the final octet other than the sign.
    #[test]
    fn ed448_decode_refuses_non_canonical_encodings() {
        let curve = ed448();
        let g = curve.base_point();
        let encoding = curve.encode_point(&g);
        assert!(curve.decode_point(&encoding[..56]).is_none());
        assert!(curve
            .decode_point(&curve.p.to_le_bytes_padded(57))
            .is_none());
        for bit in 0..7 {
            let mut altered = encoding.clone();
            altered[56] |= 1 << bit;
            assert!(curve.decode_point(&altered).is_none(), "bit {bit}");
        }
    }

    /// `from_explicit` takes the named Ed25519 parameters by comparison, and
    /// Ed448's by validation: both are real curves and pass every check.
    #[test]
    fn from_explicit_accepts_ed25519_and_ed448() {
        let named = ed25519();
        let explicit = TwistedEdwardsCurve::from_explicit(
            named.p.clone(),
            named.a.clone(),
            named.d.clone(),
            named.n.clone(),
            named.gx.clone(),
            named.gy.clone(),
        )
        .expect("Ed25519");
        assert!(explicit.same_curve(&named));

        let (p, a, d, n, gx, gy) = ed448_parameters();
        let explicit = TwistedEdwardsCurve::from_explicit(p, a, d, n, gx, gy).expect("Ed448");
        assert!(explicit.same_curve(&ed448()));
    }

    /// Ed25519's parameters with `n` replaced by `3n`: odd, within the size
    /// bound, `[3n]G` is neutral, `G` is on the curve, and the Hasse
    /// quotient is `⌊8n/3n⌋ = 2`, so primality of `n` is the one check that
    /// fails.
    #[test]
    fn from_explicit_refuses_a_composite_order() {
        let named = ed25519();
        let three_n = named.n.mul(&BigUint::from_u64(3));
        assert!(named.scalar_mul_base(&three_n).is_neutral());
        assert!(cofactor_is_hasse_quotient(2, &three_n, &named.p));
        assert!(TwistedEdwardsCurve::from_explicit(
            named.p.clone(),
            named.a.clone(),
            named.d.clone(),
            three_n,
            named.gx.clone(),
            named.gy.clone(),
        )
        .is_none());
    }

    /// The other parameter faults each fail their own step: an oversized
    /// `p`, an `n` above `p.bits() + 1`, `a = d`, a square `d`, a base point
    /// off the curve, and an order that is prime but not `G`'s (Ed25519's
    /// `n` with Ed448's other parameters fails at the cofactor, since
    /// `(√p + 1)²/n` is far above 8).
    #[test]
    fn from_explicit_refuses_each_parameter_fault() {
        let named = ed25519();
        let explicit = |p: &BigUint, a: &BigUint, d: &BigUint, n: &BigUint, gx: &BigUint, gy| {
            TwistedEdwardsCurve::from_explicit(
                p.clone(),
                a.clone(),
                d.clone(),
                n.clone(),
                gx.clone(),
                gy,
            )
        };
        let (p, a, d, n, gx, gy) = (&named.p, &named.a, &named.d, &named.n, &named.gx, &named.gy);

        let mut huge_n = BigUint::one();
        huge_n.shl_bits(400_000);
        huge_n = huge_n.add(&BigUint::one());
        assert!(explicit(p, a, d, &huge_n, gx, gy.clone()).is_none());

        let mut huge_p = BigUint::one();
        huge_p.shl_bits(MAX_EXPLICIT_FIELD_BITS);
        huge_p = huge_p.add(&BigUint::one());
        assert!(explicit(&huge_p, a, d, n, gx, gy.clone()).is_none());

        assert!(explicit(p, d, d, n, gx, gy.clone()).is_none());
        // 4 is a square; the d check comes before the base-point check.
        assert!(explicit(p, a, &BigUint::from_u64(4), n, gx, gy.clone()).is_none());
        assert!(explicit(p, a, d, n, gx, gy.add(&BigUint::one())).is_none());

        let (p448, a448, d448, _, gx448, gy448) = ed448_parameters();
        assert!(explicit(&p448, &a448, &d448, n, &gx448, gy448).is_none());
    }

    /// `new` refuses `n = 1`, for which there is no scalar in `[1, n)` to
    /// draw, and `p = 1`, which is no field.
    #[test]
    fn new_refuses_unit_moduli() {
        let named = ed25519();
        assert!(TwistedEdwardsCurve::new(
            named.p.clone(),
            named.a.clone(),
            named.d.clone(),
            BigUint::one(),
            named.gx.clone(),
            named.gy.clone(),
        )
        .is_none());
        assert!(TwistedEdwardsCurve::new(
            BigUint::one(),
            named.a.clone(),
            named.d.clone(),
            named.n.clone(),
            named.gx.clone(),
            named.gy.clone(),
        )
        .is_none());
    }

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
        assert_eq!(
            four_g_scalar, four_g_add,
            "4G via scalar_mul must equal 2G+2G"
        );
    }

    #[test]
    fn ed25519_scalar_mul_base_matches_generic_base_path() {
        let curve = ed25519();
        let g = curve.base_point();
        let scalar = BigUint::from_u64(77);
        let via_base = curve.scalar_mul_base(&scalar);
        let via_generic = scalar_mul_extended(&curve, &g, &scalar);
        assert_eq!(
            via_base, via_generic,
            "fixed-base path must match generic path"
        );
    }

    #[test]
    fn ed25519_order_times_base_point_is_neutral() {
        // n·G = neutral element by definition of the subgroup order.
        let curve = ed25519();
        let g = curve.base_point();
        let n = curve.n.clone();
        let result = curve.scalar_mul(&g, &n);
        assert!(
            result.is_neutral(),
            "n·G must be the neutral element for Ed25519"
        );
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

    /// Regression values for small base-point multiples. `1·G` is the encoding
    /// of RFC 8032 §5.1's base point (`y = 4/5`, `x` even). The other
    /// encodings have no external source: this implementation produced them,
    /// and they guard against unintended change rather than standing as
    /// independent known answers.
    #[test]
    fn ed25519_basepoint_multiples_match_regression_encodings() {
        let curve = ed25519();
        let g = curve.base_point();
        let fixtures = [
            (
                1_u64,
                "5866666666666666666666666666666666666666666666666666666666666666",
            ),
            (
                2_u64,
                "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
            ),
            (
                3_u64,
                "d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712",
            ),
            (
                4_u64,
                "2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d047",
            ),
            (
                5_u64,
                "edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df",
            ),
            (
                7_u64,
                "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1",
            ),
            (
                11_u64,
                "1337036ac32d8f30d4589c3c1c595812ce0fff40e37c6f5a97ab213f318290ad",
            ),
            (
                77_u64,
                "aa6df914f7a0f04e7f852adf459873f17dba5b1671ea62e82cc10ed6aecc489c",
            ),
            (
                82_u64,
                "b03ed935d1de5bba7f51574b9fd88239083116ff867ee8562ae990c487579623",
            ),
        ];

        for (scalar, encoding_hex) in fixtures {
            let point = curve.scalar_mul(&g, &BigUint::from_u64(scalar));
            let encoding = curve.encode_point(&point);
            assert_eq!(
                encoding,
                decode_hex(encoding_hex),
                "{scalar}G encoding mismatch"
            );
            let decoded = curve
                .decode_point(&encoding)
                .expect("decode known multiple");
            assert_eq!(decoded, point, "{scalar}G decode mismatch");
        }
    }

    #[test]
    fn ed25519_neutral_encodes_correctly() {
        let curve = ed25519();
        let neutral = EdwardsPoint::neutral();
        let enc = curve.encode_point(&neutral);
        // Neutral is (0, 1); encoding is LE(1) = 01 00 00 ... 00 (32 bytes).
        assert_eq!(
            enc[0], 0x01,
            "first byte of neutral encoding must be 1 (LE)"
        );
        assert!(
            enc[1..].iter().all(|&b| b == 0),
            "remaining bytes of neutral must be 0"
        );
    }

    #[test]
    fn ed25519_neutral_roundtrip_preserves_identity() {
        let curve = ed25519();
        let neutral = EdwardsPoint::neutral();
        let enc = curve.encode_point(&neutral);
        let dec = curve.decode_point(&enc).expect("decode neutral");
        assert!(
            dec.is_neutral(),
            "decode_point must preserve the neutral element"
        );
    }

    #[test]
    fn ed25519_decode_rejects_bad_length() {
        let curve = ed25519();
        let g = curve.base_point();
        let mut enc = curve.encode_point(&g);
        enc.pop();
        assert!(
            curve.decode_point(&enc).is_none(),
            "truncated encoding must be rejected"
        );
    }

    #[test]
    fn ed25519_decode_rejects_neutral_with_sign_bit_set() {
        let curve = ed25519();
        let mut enc = curve.encode_point(&EdwardsPoint::neutral());
        *enc.last_mut().expect("32-byte encoding") |= 0x80;
        assert!(
            curve.decode_point(&enc).is_none(),
            "RFC 8032 forbids x = 0 with the sign bit set"
        );
    }

    #[test]
    fn ed25519_decode_rejects_non_canonical_y() {
        let curve = ed25519();
        let enc = curve.p.to_le_bytes_padded(curve.coord_len);
        assert!(
            curve.decode_point(&enc).is_none(),
            "compressed encodings must reject y >= p"
        );
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
        assert!(
            !shared_a.is_neutral(),
            "ECDH shared point must not be neutral"
        );
        assert!(
            curve.is_on_curve(&shared_a),
            "ECDH shared point must lie on Ed25519"
        );
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
