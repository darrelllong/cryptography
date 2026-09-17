//! X25519 ECDH per RFC 7748 §5 over Curve25519.
//!
//! Constant-time scalar multiplication on the Montgomery form of Curve25519,
//! `y^2 = x^3 + 486662 x^2 + x` over `GF(2^255 - 19)`. The Montgomery ladder
//! operates on `u`-coordinates only; conditional swaps are driven by scalar
//! bits without data-dependent branching or indexing, and field arithmetic
//! uses a fixed 5×51-bit limb form so each operation has constant access
//! pattern.
//!
//! What holds this in place is the emitted code: `scripts/ct_codegen.sh`
//! classifies every conditional branch in the release assembly of
//! `X25519::scalar_mult` and of the functions it calls, and
//! `scripts/ct_budgets/` records the count each target's reading accounted
//! for. Every branch is the loop over bits 254 down to 0, an index check that
//! loop bound already implies, or a loop of `fe_pow_public`, whose windows are
//! digits of the public exponent `p − 2`. None takes the scalar or `u` as
//! input.
//!
//! Unlike the rest of `crate::vt`, X25519 here is intended to be
//! constant-time. It is exposed under `crate::vt` because the surrounding
//! key-handling code (PEM/DER blobs, error paths) shares conventions with
//! the rest of the public-key surface, but the scalar-mult primitive itself
//! is hardened against timing side channels on the secret scalar.
//!
//! Keys have their raw byte forms and the standard encodings of RFC 8410: the
//! public key as a `SubjectPublicKeyInfo` (§4) and the private key as a PKCS #8
//! `OneAsymmetricKey` (§7), in DER or as RFC 7468 `PUBLIC KEY` and
//! `PRIVATE KEY` text.
//!
//! References:
//! - RFC 7748, "Elliptic Curves for Security", §5 X25519 / §5.2 test vectors.
//! - RFC 8410, "Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for
//!   Use in the Internet X.509 Public Key Infrastructure", §3, §4, §7.
//! - D. J. Bernstein, "Curve25519: new Diffie-Hellman speed records" (2006).

use crate::ct::zeroize_slice;
use crate::public_key::curve_pkix::{self, ID_X25519};
use crate::public_key::pkix::{pem_decode, pem_encode, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL};
use crate::Csprng;

/// Length in bytes of an X25519 scalar / u-coordinate / shared secret.
pub const X25519_LEN: usize = 32;

/// The field element's five limbs of 51 bits (`5 × 51 = 255`), and the scalar
/// bits the ladder walks: 254 down to 0, the rest fixed by clamping.
const LIMBS: usize = 5;
const LIMB_BITS: u32 = 51;
const SCALAR_TOP_BIT: usize = 254;

/// RFC 7748 §5 `decodeScalar25519`: clear the three low bits, clear the top
/// bit, set bit 254.
const CLAMP_LOW_MASK: u8 = 0xf8;
const CLAMP_HIGH_MASK: u8 = 0x7f;
const CLAMP_HIGH_SET: u8 = 0x40;

const MASK51: u64 = (1u64 << LIMB_BITS) - 1;

// Field modulus p = 2^255 - 19 in 5x51 limbs.
//   limb 0 = 2^51 - 19 = 0x7_ffff_ffff_ffed
//   limbs 1..4 = 2^51 - 1 = 0x7_ffff_ffff_ffff
const P_LIMBS: [u64; LIMBS] = [
    0x7_ffff_ffff_ffed,
    0x7_ffff_ffff_ffff,
    0x7_ffff_ffff_ffff,
    0x7_ffff_ffff_ffff,
    0x7_ffff_ffff_ffff,
];

/// Field element modulo `p = 2^255 - 19`, stored in five limbs of radix 2^51.
///
/// Representation is "relaxed" — limbs may exceed 2^51 between operations as
/// long as the bound is respected by the next operation. `to_bytes`
/// canonicalises before serialising.
#[derive(Clone, Copy, Debug)]
struct Fe([u64; LIMBS]);

impl Fe {
    const ZERO: Fe = Fe([0; LIMBS]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);
}

#[inline(always)]
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    Fe([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
    ])
}

#[inline(always)]
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // Add 4*p to keep every limb non-negative without changing the residue.
    // 4*p = 2^257 - 76; per-limb: limb0 = 2^53 - 76, limbs 1..4 = 2^53 - 4.
    Fe([
        a.0[0] + 0x1f_ffff_ffff_ffb4 - b.0[0],
        a.0[1] + 0x1f_ffff_ffff_fffc - b.0[1],
        a.0[2] + 0x1f_ffff_ffff_fffc - b.0[2],
        a.0[3] + 0x1f_ffff_ffff_fffc - b.0[3],
        a.0[4] + 0x1f_ffff_ffff_fffc - b.0[4],
    ])
}

/// Schoolbook 5×5 limb multiply mod `p`, with two-pass carry reduction.
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a.0[0] as u128;
    let a1 = a.0[1] as u128;
    let a2 = a.0[2] as u128;
    let a3 = a.0[3] as u128;
    let a4 = a.0[4] as u128;

    let b0 = b.0[0] as u128;
    let b1 = b.0[1] as u128;
    let b2 = b.0[2] as u128;
    let b3 = b.0[3] as u128;
    let b4 = b.0[4] as u128;

    // Pre-multiply the cross terms by 19 (= 2^255 wrap-around factor).
    let b1_19 = 19 * b1;
    let b2_19 = 19 * b2;
    let b3_19 = 19 * b3;
    let b4_19 = 19 * b4;

    let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    fe_carry_u128(r0, r1, r2, r3, r4)
}

#[inline(always)]
fn fe_carry_u128(mut r0: u128, mut r1: u128, mut r2: u128, mut r3: u128, mut r4: u128) -> Fe {
    let mask = (1u128 << 51) - 1;
    r1 += r0 >> 51;
    r0 &= mask;
    r2 += r1 >> 51;
    r1 &= mask;
    r3 += r2 >> 51;
    r2 &= mask;
    r4 += r3 >> 51;
    r3 &= mask;
    let carry = r4 >> 51;
    r4 &= mask;
    r0 += 19 * carry;
    r1 += r0 >> 51;
    r0 &= mask;
    Fe([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
}

#[inline(always)]
fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_pow2k(a: &Fe, k: u32) -> Fe {
    let mut t = *a;
    for _ in 0..k {
        t = fe_sq(&t);
    }
    t
}

/// Multiply by the Montgomery-ladder constant `(A + 2)/4 = 121665`.
fn fe_mul_a24(a: &Fe) -> Fe {
    const A24: u128 = 121_665;
    let r0 = (a.0[0] as u128) * A24;
    let r1 = (a.0[1] as u128) * A24;
    let r2 = (a.0[2] as u128) * A24;
    let r3 = (a.0[3] as u128) * A24;
    let r4 = (a.0[4] as u128) * A24;
    fe_carry_u128(r0, r1, r2, r3, r4)
}

/// Little-endian bytes of the public exponent `p - 2 = 2^255 - 21`.
///
/// `2^255 - 21 = (2^255 - 1) - 20`. `2^255 - 1` is 255 one bits, and
/// `20 = 0b1_0100` only clears bits 2 and 4 of its all-ones low byte, with no
/// borrow: `0xff - 0x14 = 0xeb`. Bytes 1..=30 stay `0xff`; bit 255 is clear, so
/// the top byte is `0x7f`.
const P_MINUS_2_LE: [u8; X25519_LEN] = {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xeb;
    bytes[31] = 0x7f;
    bytes
};

/// `base^exponent` for a public little-endian `exponent`, in constant time
/// with respect to `base`.
///
/// Fixed 4-bit windows, most significant first. Every window costs exactly
/// four squarings and one multiplication by `base^digit` from a table, and the
/// table index is a digit of the public exponent, so neither the operation
/// sequence nor the memory access pattern depends on `base`. A zero digit
/// still multiplies (by `base^0 = 1`), which keeps the sequence uniform.
fn fe_pow_public(base: &Fe, exponent: &[u8; X25519_LEN]) -> Fe {
    // powers[d] = base^d for each 4-bit digit d.
    let mut powers = [Fe::ONE; 16];
    for d in 1..powers.len() {
        powers[d] = fe_mul(&powers[d - 1], base);
    }

    let mut acc = Fe::ONE;
    for byte in exponent.iter().rev() {
        for digit in [byte >> 4, byte & 0x0f] {
            acc = fe_pow2k(&acc, 4);
            acc = fe_mul(&acc, &powers[usize::from(digit)]);
        }
    }

    for power in &mut powers {
        zeroize_slice(&mut power.0);
    }
    acc
}

/// Compute `z^(p-2) = z^(2^255 - 21)` (modular inverse for nonzero z).
///
/// RFC 7748 §5 ends the ladder with `x_2 * (z_2^(p - 2))`. By Fermat's little
/// theorem `z^(p-2) = z^-1` for nonzero `z`; zero maps to zero.
fn fe_invert(z: &Fe) -> Fe {
    fe_pow_public(z, &P_MINUS_2_LE)
}

/// Constant-time conditional swap: if `swap == 1`, swap `a` and `b`; if `0`,
/// no change. Touches every limb regardless of `swap`.
#[inline(always)]
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..LIMBS {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Decode 32 LE bytes into a field element. Per RFC 7748 §5, the high bit of
/// the most-significant byte is masked off first.
fn fe_from_bytes(bytes: &[u8; X25519_LEN]) -> Fe {
    let mut buf = *bytes;
    buf[31] &= 0x7f;
    let load = |off: usize| -> u64 {
        let mut x = [0u8; 8];
        x.copy_from_slice(&buf[off..off + 8]);
        u64::from_le_bytes(x)
    };
    Fe([
        load(0) & MASK51,
        (load(6) >> 3) & MASK51,
        (load(12) >> 6) & MASK51,
        (load(19) >> 1) & MASK51,
        (load(24) >> 12) & MASK51,
    ])
}

/// Encode a field element into 32 LE bytes, fully canonicalised mod `p`.
///
/// The conditional subtraction of `p` is mask-driven, and the mask goes
/// through [`crate::ct::select_u64`]: written as a plain select, the compiler
/// emitted a conditional branch on the borrow, which is a branch on the value
/// being encoded.
fn fe_to_bytes(a: &Fe) -> [u8; X25519_LEN] {
    let mut t = a.0;
    // Two carry passes bring t into [0, 2*p).
    for _ in 0..2 {
        let c = t[0] >> 51;
        t[0] &= MASK51;
        t[1] += c;
        let c = t[1] >> 51;
        t[1] &= MASK51;
        t[2] += c;
        let c = t[2] >> 51;
        t[2] &= MASK51;
        t[3] += c;
        let c = t[3] >> 51;
        t[3] &= MASK51;
        t[4] += c;
        let c = t[4] >> 51;
        t[4] &= MASK51;
        t[0] += 19 * c;
    }
    // After two passes each limb is < 2^52 and t < 2*p.
    // Conditionally subtract p: compute t - p using wrapping arithmetic and
    // borrow propagation. If t < p (borrow=1), keep t; else use t - p.
    let mut s = [0u64; 5];
    let mut borrow: u64 = 0;
    for i in 0..LIMBS {
        let diff = t[i].wrapping_sub(P_LIMBS[i]).wrapping_sub(borrow);
        s[i] = diff & MASK51;
        // Bit 63 of `diff` is set iff t[i] < P_LIMBS[i] + borrow (wraparound).
        // Inputs are < 2^52, P_LIMBS[i] < 2^51, borrow ∈ {0,1}, so the only
        // way bit 63 ends up set is via underflow.
        borrow = (diff >> 63) & 1;
    }
    let select_t = 0u64.wrapping_sub(borrow);
    let mut out = [0u64; LIMBS];
    for i in 0..LIMBS {
        out[i] = crate::ct::select_u64(select_t, t[i], s[i]);
    }

    // Pack five 51-bit limbs into 32 LE bytes.
    let mut bytes = [0u8; X25519_LEN];
    bytes[0] = out[0] as u8;
    bytes[1] = (out[0] >> 8) as u8;
    bytes[2] = (out[0] >> 16) as u8;
    bytes[3] = (out[0] >> 24) as u8;
    bytes[4] = (out[0] >> 32) as u8;
    bytes[5] = (out[0] >> 40) as u8;
    bytes[6] = ((out[0] >> 48) | (out[1] << 3)) as u8;
    bytes[7] = (out[1] >> 5) as u8;
    bytes[8] = (out[1] >> 13) as u8;
    bytes[9] = (out[1] >> 21) as u8;
    bytes[10] = (out[1] >> 29) as u8;
    bytes[11] = (out[1] >> 37) as u8;
    bytes[12] = ((out[1] >> 45) | (out[2] << 6)) as u8;
    bytes[13] = (out[2] >> 2) as u8;
    bytes[14] = (out[2] >> 10) as u8;
    bytes[15] = (out[2] >> 18) as u8;
    bytes[16] = (out[2] >> 26) as u8;
    bytes[17] = (out[2] >> 34) as u8;
    bytes[18] = (out[2] >> 42) as u8;
    bytes[19] = ((out[2] >> 50) | (out[3] << 1)) as u8;
    bytes[20] = (out[3] >> 7) as u8;
    bytes[21] = (out[3] >> 15) as u8;
    bytes[22] = (out[3] >> 23) as u8;
    bytes[23] = (out[3] >> 31) as u8;
    bytes[24] = (out[3] >> 39) as u8;
    bytes[25] = ((out[3] >> 47) | (out[4] << 4)) as u8;
    bytes[26] = (out[4] >> 4) as u8;
    bytes[27] = (out[4] >> 12) as u8;
    bytes[28] = (out[4] >> 20) as u8;
    bytes[29] = (out[4] >> 28) as u8;
    bytes[30] = (out[4] >> 36) as u8;
    bytes[31] = (out[4] >> 44) as u8;
    // `t`, `s`, and `out` hold the encoded value in limb form; called from
    // the ladder, that value is the shared secret.
    zeroize_slice(&mut t[..]);
    zeroize_slice(&mut s[..]);
    zeroize_slice(&mut out[..]);
    bytes
}

/// RFC 7748 §5 `decodeScalar25519`: clamp the 32-byte scalar in place.
fn clamp_scalar(scalar: &mut [u8; X25519_LEN]) {
    scalar[0] &= CLAMP_LOW_MASK;
    scalar[X25519_LEN - 1] &= CLAMP_HIGH_MASK;
    scalar[X25519_LEN - 1] |= CLAMP_HIGH_SET;
}

/// X25519 Montgomery ladder. Computes `scalar * u` per RFC 7748 §5 with
/// constant-time scalar processing.
fn x25519_inner(scalar: &[u8; X25519_LEN], u: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    let mut k = *scalar;
    clamp_scalar(&mut k);

    let x1 = fe_from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap: u64 = 0;
    // One ladder step's intermediates. They live outside the loop so the
    // final step's values, which determine the result, can be wiped below.
    let mut a = Fe::ZERO;
    let mut aa = Fe::ZERO;
    let mut b = Fe::ZERO;
    let mut bb = Fe::ZERO;
    let mut e = Fe::ZERO;
    let mut c = Fe::ZERO;
    let mut d = Fe::ZERO;
    let mut da = Fe::ZERO;
    let mut cb = Fe::ZERO;
    let mut da_plus_cb = Fe::ZERO;
    let mut da_minus_cb = Fe::ZERO;
    let mut da_minus_cb_sq = Fe::ZERO;
    let mut a24_e = Fe::ZERO;
    let mut aa_plus_a24e = Fe::ZERO;

    // Process bits 254 down to 0. Bits above 254 are forced to zero by the
    // clamp; bit 254 is forced to 1 (so swap on that bit is well-defined).
    for t in (0..=SCALAR_TOP_BIT).rev() {
        let byte = t / 8;
        let bit = t % 8;
        let k_t = ((k[byte] >> bit) & 1) as u64;
        swap ^= k_t;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = k_t;

        a = fe_add(&x2, &z2);
        aa = fe_sq(&a);
        b = fe_sub(&x2, &z2);
        bb = fe_sq(&b);
        e = fe_sub(&aa, &bb);
        c = fe_add(&x3, &z3);
        d = fe_sub(&x3, &z3);
        da = fe_mul(&d, &a);
        cb = fe_mul(&c, &b);
        da_plus_cb = fe_add(&da, &cb);
        da_minus_cb = fe_sub(&da, &cb);
        x3 = fe_sq(&da_plus_cb);
        da_minus_cb_sq = fe_sq(&da_minus_cb);
        z3 = fe_mul(&x1, &da_minus_cb_sq);
        x2 = fe_mul(&aa, &bb);
        a24_e = fe_mul_a24(&e);
        aa_plus_a24e = fe_add(&aa, &a24_e);
        z2 = fe_mul(&e, &aa_plus_a24e);
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let mut z2_inv = fe_invert(&z2);
    let mut result = fe_mul(&x2, &z2_inv);

    zeroize_slice(&mut k[..]);
    let out = fe_to_bytes(&result);
    // The final ladder state is `scalar·u` in projective form, and the last
    // step's intermediates determine it: wipe them with the clamped scalar.
    // (`swap` needs no wipe: it ends as the scalar's bit 0, which clamping
    // clears.)
    for fe in [
        &mut x2,
        &mut z2,
        &mut x3,
        &mut z3,
        &mut z2_inv,
        &mut result,
        &mut a,
        &mut aa,
        &mut b,
        &mut bb,
        &mut e,
        &mut c,
        &mut d,
        &mut da,
        &mut cb,
        &mut da_plus_cb,
        &mut da_minus_cb,
        &mut da_minus_cb_sq,
        &mut a24_e,
        &mut aa_plus_a24e,
    ] {
        zeroize_slice(&mut fe.0);
    }
    out
}

/// The canonical encoding of the u-coordinate `bytes` names, read as RFC 7748
/// §5 reads one: bit 255 masked, and a non-canonical value (2^255 − 19 through
/// 2^255 − 1) reduced modulo p. Two strings name the same u-coordinate
/// exactly when their canonical encodings are equal.
fn canonical_u(bytes: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    fe_to_bytes(&fe_from_bytes(bytes))
}

/// Top-level X25519 functional surface (RFC 7748 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519;

impl X25519 {
    /// Compute `scalar * u` per RFC 7748 §5. The scalar is clamped before use.
    /// Constant-time in `scalar` and `u`.
    #[must_use]
    pub fn scalar_mult(scalar: &[u8; X25519_LEN], u: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
        x25519_inner(scalar, u)
    }

    /// Compute `scalar * G` where `G` is the X25519 base point (`u = 9`).
    #[must_use]
    pub fn scalar_mult_base(scalar: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
        let mut base = [0u8; X25519_LEN];
        base[0] = 9;
        x25519_inner(scalar, &base)
    }

    /// Generate a new X25519 key pair from `rng`. The private scalar is
    /// 32 random bytes pre-clamping; clamping is applied at use time.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R) -> (X25519PublicKey, X25519PrivateKey) {
        let mut secret = [0u8; X25519_LEN];
        rng.fill_bytes(&mut secret);
        let public_bytes = X25519::scalar_mult_base(&secret);
        let pair = (X25519PublicKey(public_bytes), X25519PrivateKey(secret));
        // `secret` was copied into the private key; wipe the stack original.
        zeroize_slice(&mut secret[..]);
        pair
    }
}

/// X25519 private key: 32 raw bytes. Zeroised on drop.
#[derive(Clone)]
pub struct X25519PrivateKey([u8; X25519_LEN]);

impl PartialEq for X25519PrivateKey {
    /// Compares the scalars in constant time.
    fn eq(&self, other: &Self) -> bool {
        crate::ct::constant_time_eq_mask(&self.0, &other.0) == u8::MAX
    }
}

impl Eq for X25519PrivateKey {}

/// X25519 public key: a 32-byte canonical u-coordinate.
///
/// Every constructor stores the canonical encoding of the u-coordinate its
/// input names, read as RFC 7748 §5 reads one (bit 255 masked, a
/// non-canonical value taken as reduced modulo `p`), so two keys naming the
/// same u-coordinate are equal, and [`Self::to_raw_bytes`] and the RFC 8410
/// encodings carry the canonical form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519PublicKey([u8; X25519_LEN]);

impl X25519PrivateKey {
    /// Construct from raw scalar bytes (caller-supplied entropy required).
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X25519_LEN]) -> Self {
        Self(*bytes)
    }

    /// Construct from a mutable buffer; the caller's buffer is zeroised after
    /// the private scalar is copied.
    #[must_use]
    pub fn from_raw_bytes_wiping(bytes: &mut [u8; X25519_LEN]) -> Self {
        let key = Self(*bytes);
        zeroize_slice(&mut bytes[..]);
        key
    }

    /// Return the raw 32-byte scalar.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X25519_LEN] {
        self.0
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> X25519PublicKey {
        X25519PublicKey(X25519::scalar_mult_base(&self.0))
    }

    /// Diffie-Hellman: compute shared secret with `peer`. Returns `None` if
    /// the result is the all-zero u-coordinate (low-order point), per the
    /// conservative recommendation in RFC 7748 §6.1.
    ///
    /// Timing: `scripts/ct_codegen.sh` finds one conditional branch in this
    /// operation beyond the ladder's own, on both targets it has been run on
    /// — the test of that all-zero check, which the code folds over all 32
    /// bytes before testing once, so the branch decides only the value this
    /// returns.
    #[must_use]
    pub fn agree(&self, peer: &X25519PublicKey) -> Option<[u8; X25519_LEN]> {
        let shared = X25519::scalar_mult(&self.0, &peer.0);
        let nonzero: u8 = shared.iter().fold(0u8, |acc, &b| acc | b);
        if nonzero == 0 {
            None
        } else {
            Some(shared)
        }
    }

    /// Encode as the RFC 8410 §7 `OneAsymmetricKey` (PKCS #8) in DER: version
    /// 1, `id-X25519` with the parameters absent (§3), and the 32-byte scalar
    /// as `CurvePrivateKey`. The public key is left out, since the scalar
    /// derives it.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        curve_pkix::private_key_to_pkcs8(&ID_X25519, &self.0)
    }

    /// Encode as RFC 7468 `PRIVATE KEY` text (§10) around
    /// [`Self::to_pkcs8_der`].
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode(PRIVATE_KEY_LABEL, self.to_pkcs8_der())
    }

    /// Decode an RFC 8410 §7 `OneAsymmetricKey` in any X.690 BER encoding, DER
    /// included: RFC 5958 §2 says "receivers MUST support BER". The key is then
    /// checked as [`Self::from_pkcs8_der`] checks it.
    #[must_use]
    pub fn from_pkcs8_ber(ber: &[u8]) -> Option<Self> {
        crate::public_key::pkix::pkcs8_ber(ber, Self::from_pkcs8_der)
    }

    /// Decode an RFC 8410 §7 `OneAsymmetricKey` from strict DER with no
    /// trailing bytes: version 1 or 2, `id-X25519` with the parameters absent
    /// (§3), and a 32-byte `CurvePrivateKey`. As with [`Self::from_raw_bytes`],
    /// every 32-byte string is a scalar (RFC 7748 §5 clamps it at use). A
    /// version 2 `publicKey` must be 32 bytes naming the u-coordinate this
    /// scalar derives, as RFC 7748 §5 reads a u-coordinate: bit 255 masked,
    /// and a non-canonical value taken as reduced modulo p. Attributes are
    /// ignored.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let (scalar, public_key) = curve_pkix::private_key_from_pkcs8(der, &ID_X25519, X25519_LEN)?;
        // Filled in place, so no by-value copy of the scalar is left behind.
        let mut bytes = [0u8; X25519_LEN];
        bytes.copy_from_slice(scalar);
        let key = Self::from_raw_bytes_wiping(&mut bytes);
        match public_key {
            Some(public_key) => {
                let u: &[u8; X25519_LEN] = public_key.try_into().ok()?;
                (canonical_u(u) == key.to_public_key().0).then_some(key)
            }
            None => Some(key),
        }
    }

    /// Decode RFC 7468 `PRIVATE KEY` text (§10) with [`Self::from_pkcs8_der`].
    #[must_use]
    pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        pem_decode(PRIVATE_KEY_LABEL, pem, Self::from_pkcs8_der)
    }
}

impl core::fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519PrivateKey(<redacted>)")
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0[..]);
    }
}

impl X25519PublicKey {
    /// Wrap an externally-supplied u-coordinate as a public key. No
    /// validation is performed; X25519 is defined for every 32-byte input
    /// after the high bit is masked, and the key stores the canonical
    /// encoding of the u-coordinate `bytes` names.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X25519_LEN]) -> Self {
        Self(canonical_u(bytes))
    }

    /// Return the canonical 32-byte u-coordinate.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X25519_LEN] {
        self.0
    }

    /// Encode as the RFC 8410 §4 `SubjectPublicKeyInfo` in DER: `id-X25519`
    /// with the parameters absent (§3) and the 32-byte u-coordinate as the
    /// `subjectPublicKey`.
    #[must_use]
    pub fn to_spki_der(self) -> Vec<u8> {
        curve_pkix::public_key_to_spki(&ID_X25519, &self.0)
    }

    /// Encode as RFC 7468 `PUBLIC KEY` text (§13) around [`Self::to_spki_der`].
    #[must_use]
    pub fn to_spki_pem(self) -> String {
        pem_encode(PUBLIC_KEY_LABEL, self.to_spki_der())
    }

    /// Decode an RFC 8410 §4 `SubjectPublicKeyInfo` from strict DER with no
    /// trailing bytes: `id-X25519` with the parameters absent (§3) and a
    /// 32-byte key. As with [`Self::from_raw_bytes`], every 32-byte string is
    /// accepted, since RFC 7748 §5 defines X25519 on all of them, and the
    /// canonical u-coordinate is stored.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let u = curve_pkix::public_key_from_spki(der, &ID_X25519, X25519_LEN)?;
        Some(Self::from_raw_bytes(u.try_into().ok()?))
    }

    /// Decode RFC 7468 `PUBLIC KEY` text (§13) with [`Self::from_spki_der`].
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        pem_decode(PUBLIC_KEY_LABEL, pem, Self::from_spki_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key::io::der_octet_string;
    use crate::public_key::pkix::{AlgorithmIdentifier, OneAsymmetricKey};
    use crate::test_utils::{decode_hex_array, openssl3, ScratchFile};

    /// RFC 7748 §5.2 first single-step vector.
    #[test]
    fn rfc7748_section5_2_vector_1() {
        let k = decode_hex_array::<32>(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );
        let u = decode_hex_array::<32>(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        );
        let expected = decode_hex_array::<32>(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );
        assert_eq!(X25519::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 second single-step vector.
    #[test]
    fn rfc7748_section5_2_vector_2() {
        let k = decode_hex_array::<32>(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        );
        let u = decode_hex_array::<32>(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        );
        let expected = decode_hex_array::<32>(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        );
        assert_eq!(X25519::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 iteration.
    #[test]
    fn rfc7748_section5_2_iter_1() {
        let mut k = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k;
        let next = X25519::scalar_mult(&k, &u);
        u = k;
        k = next;
        let expected = decode_hex_array::<32>(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        );
        assert_eq!(k, expected);
        // Silence unused-warning on `u`: it would be the next u-coordinate input.
        let _ = u;
    }

    /// RFC 7748 §5.2 iterated test, after 1000 iterations.
    #[test]
    fn rfc7748_section5_2_iter_1000() {
        let mut k = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k;
        for _ in 0..1000 {
            let next = X25519::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = decode_hex_array::<32>(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        );
        assert_eq!(k, expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 000 000 iterations.
    /// Slow (~minutes in debug, ~seconds in release); gated `#[ignore]`.
    /// Run with: `cargo test --release -- --ignored x25519_iter_1m`.
    #[test]
    #[ignore = "RFC 7748 1M-iteration test; run with --release --ignored"]
    fn rfc7748_section5_2_iter_1m_x25519() {
        let mut k = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k;
        for _ in 0..1_000_000 {
            let next = X25519::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = decode_hex_array::<32>(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
        );
        assert_eq!(k, expected);
    }

    /// Round-trip: A * (B * G) == B * (A * G).
    #[test]
    fn ecdh_roundtrip() {
        let a = decode_hex_array::<32>(
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        let b = decode_hex_array::<32>(
            "0202020202020202020202020202020202020202020202020202020202020202",
        );
        let pa = X25519::scalar_mult_base(&a);
        let pb = X25519::scalar_mult_base(&b);
        let sa = X25519::scalar_mult(&a, &pb);
        let sb = X25519::scalar_mult(&b, &pa);
        assert_eq!(sa, sb);
    }

    /// All-zero output for a low-order input must be flagged by `agree`.
    #[test]
    fn agree_rejects_low_order_zero_output() {
        let secret = X25519PrivateKey::from_raw_bytes(&[0x55u8; 32]);
        // u = 0 is a low-order point; scalar_mult(_, 0) returns 0.
        let zero_pub = X25519PublicKey::from_raw_bytes(&[0u8; 32]);
        assert!(secret.agree(&zero_pub).is_none());
    }

    /// Sanity: bytes -> Fe -> bytes round-trips for canonical inputs.
    #[test]
    fn fe_bytes_roundtrip() {
        let bytes = decode_hex_array::<32>(
            "0100000000000000000000000000000000000000000000000000000000000000",
        );
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe.0, [1, 0, 0, 0, 0]);
        assert_eq!(fe_to_bytes(&fe), bytes);

        let bytes = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe.0, [9, 0, 0, 0, 0]);
        assert_eq!(fe_to_bytes(&fe), bytes);
    }

    /// Sanity: fe_mul(1, x) == x (canonical).
    #[test]
    fn fe_mul_by_one_is_identity() {
        let x = fe_from_bytes(&decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        ));
        let out = fe_mul(&Fe::ONE, &x);
        assert_eq!(fe_to_bytes(&out), fe_to_bytes(&x));
    }

    /// Sanity: fe_mul(2, fe_invert(2)) == 1.
    #[test]
    fn fe_invert_simple() {
        let two = Fe([2, 0, 0, 0, 0]);
        let inv = fe_invert(&two);
        let prod = fe_mul(&two, &inv);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(fe_to_bytes(&prod), one);
    }

    /// Field-arithmetic sanity: x * x^(-1) ≡ 1 for a few inputs.
    #[test]
    fn field_invert_inverse_of_self() {
        for seed in [1u8, 2, 7, 99, 0xfe] {
            let mut bytes = [0u8; 32];
            bytes[0] = seed;
            bytes[5] = seed.wrapping_add(3);
            bytes[17] = seed ^ 0xa5;
            let x = fe_from_bytes(&bytes);
            let inv = fe_invert(&x);
            let prod = fe_mul(&x, &inv);
            assert_eq!(fe_to_bytes(&prod), {
                let mut one = [0u8; 32];
                one[0] = 1;
                one
            });
        }
    }

    /// RFC 8410 §10.2: a certificate for an X25519 key, as printed. Errata 6936
    /// and 7070 report DER faults in its extensions, and 6936 its 66-character
    /// lines, which RFC 7468 §2 lets a parser accept; none concern its key.
    const RFC8410_X25519_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX\n\
        N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD\n\
        DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj\n\
        ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg\n\
        BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v\n\
        /BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg\n\
        w1AH9efZBw==\n\
        -----END CERTIFICATE-----\n";

    #[test]
    fn canonical_u_reads_u_coordinates_as_rfc7748_section_5_does() {
        let mut five = [0u8; 32];
        five[0] = 5;
        // p + 5 = 2^255 − 14, the non-canonical encoding of 5.
        let mut p_plus_5 = [0xffu8; 32];
        p_plus_5[0] = 0xf2;
        p_plus_5[31] = 0x7f;
        // Both, with bit 255 set, which §5 masks.
        let mut five_high = five;
        five_high[31] |= 0x80;
        let mut p_plus_5_high = p_plus_5;
        p_plus_5_high[31] |= 0x80;
        for encoding in [five, p_plus_5, five_high, p_plus_5_high] {
            assert_eq!(canonical_u(&encoding), five, "{encoding:02x?}");
        }
        // p = 2^255 − 19 names 0.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(canonical_u(&p), [0u8; 32]);
    }

    #[test]
    fn private_key_equality_is_by_value() {
        let key = X25519PrivateKey::from_raw_bytes(&[0x42; 32]);
        let same = X25519PrivateKey::from_raw_bytes(&[0x42; 32]);
        let mut other_bytes = [0x42; 32];
        other_bytes[1] ^= 0x01;
        let other = X25519PrivateKey::from_raw_bytes(&other_bytes);
        assert!(key == same);
        assert!(key != other);
    }

    /// A public key built from a non-canonical u-coordinate, or one with
    /// bit 255 set, equals and re-encodes as the key built from the
    /// canonical form, and agrees to the same shared secret.
    #[test]
    fn public_key_import_canonicalises_the_u_coordinate() {
        let mut five = [0u8; 32];
        five[0] = 5;
        let mut p_plus_5 = [0xffu8; 32];
        p_plus_5[0] = 0xf2;
        p_plus_5[31] = 0xff;
        let canonical = X25519PublicKey::from_raw_bytes(&five);
        let reduced = X25519PublicKey::from_raw_bytes(&p_plus_5);
        assert_eq!(reduced, canonical);
        assert_eq!(reduced.to_raw_bytes(), five);
        assert_eq!(
            X25519PublicKey::from_spki_der(&reduced.to_spki_der()),
            Some(canonical)
        );
        let secret = X25519PrivateKey::from_raw_bytes(&[0x33; 32]);
        assert_eq!(secret.agree(&reduced), secret.agree(&canonical));
    }

    /// RFC 7748 §6.1: Alice's private key.
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

    /// RFC 7748 §6.1: Alice's public key, X25519(a, 9).
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    /// RFC 7748 §6.1: Bob's public key.
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    #[test]
    fn spki_decodes_the_rfc8410_section_10_2_certificate_key() {
        let certificate = pem_decode("CERTIFICATE", RFC8410_X25519_CERTIFICATE, |der| {
            Some(der.to_vec())
        })
        .expect("RFC 7468 text");
        // The §10.2 dump puts the SubjectPublicKeyInfo at offset 115: a
        // two-byte header and 42 bytes of contents.
        let spki = &certificate[115..159];
        let public = X25519PublicKey::from_spki_der(spki).expect("§10.2 key");
        // The certificate's key is RFC 7748 §6.1's Alice's.
        assert_eq!(public.to_raw_bytes(), decode_hex_array::<32>(ALICE_PUBLIC));
        assert_eq!(public.to_spki_der(), spki);
        assert_eq!(
            X25519PublicKey::from_spki_pem(&public.to_spki_pem()),
            Some(public)
        );
    }

    #[test]
    fn pkcs8_ber_accepts_an_indefinite_length_container() {
        let private = X25519PrivateKey::from_raw_bytes(&decode_hex_array::<32>(ALICE_PRIVATE));
        let der = private.to_pkcs8_der();
        let ber = crate::test_utils::der_to_indefinite_length(&der);
        assert!(X25519PrivateKey::from_pkcs8_der(&ber).is_none());
        assert_eq!(
            X25519PrivateKey::from_pkcs8_ber(&ber),
            Some(private.clone())
        );
        assert_eq!(X25519PrivateKey::from_pkcs8_ber(&der), Some(private));
    }

    #[test]
    fn pkcs8_round_trips_and_a_version_2_public_key_must_match() {
        let private = X25519PrivateKey::from_raw_bytes(&decode_hex_array::<32>(ALICE_PRIVATE));
        let public = private.to_public_key();
        assert_eq!(public.to_raw_bytes(), decode_hex_array::<32>(ALICE_PUBLIC));
        let der = private.to_pkcs8_der();
        assert_eq!(
            der[..16],
            [
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
                0x04, 0x20
            ]
        );
        assert_eq!(der[16..], private.to_raw_bytes());
        assert_eq!(
            X25519PrivateKey::from_pkcs8_der(&der),
            Some(private.clone())
        );
        assert_eq!(
            X25519PrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem()),
            Some(private.clone())
        );
        assert!(X25519PrivateKey::from_pkcs8_pem(&public.to_spki_pem()).is_none());

        let with_public = |public_key: &[u8]| {
            OneAsymmetricKey::new(
                AlgorithmIdentifier::new(&ID_X25519, None),
                &der_octet_string(&private.to_raw_bytes()),
                Some(public_key),
            )
            .to_der()
        };
        assert_eq!(
            X25519PrivateKey::from_pkcs8_der(&with_public(&public.to_raw_bytes())),
            Some(private.clone())
        );
        // Alice's key with bit 255 set names the same u-coordinate, since RFC
        // 7748 §5 masks that bit, so it matches too.
        let alice = public.to_raw_bytes();
        let mut high_bit = alice;
        high_bit[31] |= 0x80;
        assert_eq!(
            X25519PrivateKey::from_pkcs8_der(&with_public(&high_bit)),
            Some(private.clone())
        );
        // Bob's key and a truncated key do not.
        let bob = decode_hex_array::<32>(BOB_PUBLIC);
        for mismatched in [&bob[..], &alice[..31]] {
            assert!(X25519PrivateKey::from_pkcs8_der(&with_public(mismatched)).is_none());
        }
    }

    /// OpenSSL's X25519 key parses and re-encodes byte for byte; OpenSSL reads
    /// the crate's keys, derives the same public key, re-emits the same
    /// encodings, and computes the same shared secret.
    #[test]
    fn openssl_x25519_keys_interoperate() {
        const TEST: &str = "openssl_x25519_keys_interoperate";
        let Some(theirs_pem) = openssl3(&["genpkey", "-algorithm", "X25519"], b"").or_skip(TEST)
        else {
            return;
        };
        let run = |args: &[&str], stdin: &[u8]| {
            openssl3(args, stdin)
                .or_skip(TEST)
                .expect("openssl works once genpkey did")
        };
        let theirs = X25519PrivateKey::from_pkcs8_pem(
            std::str::from_utf8(&theirs_pem).expect("PEM is ASCII"),
        )
        .expect("OpenSSL's PKCS #8 X25519 key");
        assert_eq!(theirs.to_pkcs8_pem().as_bytes(), theirs_pem);
        let theirs_spki = run(&["pkey", "-pubout", "-outform", "DER"], &theirs_pem);
        let theirs_public =
            X25519PublicKey::from_spki_der(&theirs_spki).expect("OpenSSL's SubjectPublicKeyInfo");
        assert_eq!(theirs_public, theirs.to_public_key());
        assert_eq!(theirs_public.to_spki_der(), theirs_spki);

        let ours = X25519PrivateKey::from_raw_bytes(&decode_hex_array::<32>(ALICE_PRIVATE));
        let public = ours.to_public_key();
        let ours_pem = ours.to_pkcs8_pem();
        assert_eq!(
            run(&["pkey", "-pubout", "-outform", "DER"], ours_pem.as_bytes()),
            public.to_spki_der()
        );
        assert_eq!(
            run(&["pkey", "-outform", "DER"], ours_pem.as_bytes()),
            ours.to_pkcs8_der()
        );
        assert_eq!(
            run(
                &["pkey", "-pubin", "-outform", "DER"],
                public.to_spki_pem().as_bytes()
            ),
            public.to_spki_der()
        );
        let text = run(&["pkey", "-text", "-noout"], ours_pem.as_bytes());
        assert!(String::from_utf8_lossy(&text).contains("X25519 Private-Key"));

        let key_file = ScratchFile::new(TEST, "key.pem", ours_pem.as_bytes());
        let peer_file = ScratchFile::new(TEST, "peer.pem", theirs_public.to_spki_pem().as_bytes());
        let shared = run(
            &[
                "pkeyutl",
                "-derive",
                "-inkey",
                key_file.arg(),
                "-peerkey",
                peer_file.arg(),
            ],
            b"",
        );
        let expected = ours
            .agree(&theirs_public)
            .expect("OpenSSL's random key is not of low order");
        assert_eq!(shared, expected);
        assert_eq!(theirs.agree(&public), Some(expected));
    }
}
