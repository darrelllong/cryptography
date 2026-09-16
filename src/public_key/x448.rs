//! X448 ECDH per RFC 7748 §5 over Curve448.
//!
//! Constant-time scalar multiplication on the Montgomery form of Curve448,
//! `y^2 = x^3 + 156326 x^2 + x` over `GF(2^448 - 2^224 - 1)`. The Montgomery
//! ladder operates on `u`-coordinates only; conditional swaps are driven by
//! scalar bits without data-dependent branching or indexing, and field
//! arithmetic uses a fixed 8×56-bit limb form so each operation has constant
//! access pattern.
//!
//! Like the X25519 module, this is a constant-time exception within
//! `crate::vt`; the surrounding key-handling conventions match the rest of
//! the public-key surface, but the scalar-mult primitive is hardened against
//! timing side channels.
//!
//! Keys have their raw byte forms and the standard encodings of RFC 8410: the
//! public key as a `SubjectPublicKeyInfo` (§4) and the private key as a PKCS #8
//! `OneAsymmetricKey` (§7), in DER or as RFC 7468 `PUBLIC KEY` and
//! `PRIVATE KEY` text.
//!
//! References:
//! - RFC 7748, "Elliptic Curves for Security", §5 X448 / §5.2 test vectors.
//! - RFC 8410, "Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for
//!   Use in the Internet X.509 Public Key Infrastructure", §3, §4, §7.
//! - M. Hamburg, "Ed448-Goldilocks, a new elliptic curve" (2015).

use crate::ct::zeroize_slice;
use crate::public_key::curve_pkix::{self, ID_X448};
use crate::public_key::pkix::{pem_decode, pem_encode, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL};
use crate::Csprng;

/// Length in bytes of an X448 scalar / u-coordinate / shared secret.
pub const X448_LEN: usize = 56;

const MASK56: u64 = (1u64 << 56) - 1;

// Field modulus p = 2^448 - 2^224 - 1 in 8x56 limbs.
//   limbs 0..3 = 2^56 - 1   (bits 0..223)
//   limb 4     = 2^56 - 2   (bit 224 = 0; bits 225..279 set)
//   limbs 5..7 = 2^56 - 1   (bits 280..447)
const P_LIMBS: [u64; 8] = [
    0xff_ffff_ffff_ffff,
    0xff_ffff_ffff_ffff,
    0xff_ffff_ffff_ffff,
    0xff_ffff_ffff_ffff,
    0xff_ffff_ffff_fffe,
    0xff_ffff_ffff_ffff,
    0xff_ffff_ffff_ffff,
    0xff_ffff_ffff_ffff,
];

/// Field element modulo `p = 2^448 - 2^224 - 1`, stored in eight limbs of
/// radix 2^56.
#[derive(Clone, Copy, Debug)]
struct Fe([u64; 8]);

impl Fe {
    const ZERO: Fe = Fe([0; 8]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0]);
}

#[inline(always)]
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 8];
    for (i, slot) in r.iter_mut().enumerate() {
        *slot = a.0[i] + b.0[i];
    }
    Fe(r)
}

#[inline(always)]
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // Add 4*p to keep every limb non-negative. 4*p in 8x56:
    //   limbs 0..3, 5..7: 4*(2^56 - 1) = 2^58 - 4 = 0x3ff_ffff_ffff_fffc
    //   limb 4:           4*(2^56 - 2) = 2^58 - 8 = 0x3ff_ffff_ffff_fff8
    let off: [u64; 8] = [
        0x3ff_ffff_ffff_fffc,
        0x3ff_ffff_ffff_fffc,
        0x3ff_ffff_ffff_fffc,
        0x3ff_ffff_ffff_fffc,
        0x3ff_ffff_ffff_fff8,
        0x3ff_ffff_ffff_fffc,
        0x3ff_ffff_ffff_fffc,
        0x3ff_ffff_ffff_fffc,
    ];
    let mut r = [0u64; 8];
    for i in 0..8 {
        r[i] = a.0[i] + off[i] - b.0[i];
    }
    Fe(r)
}

/// Schoolbook 8×8 limb multiply mod `p`, with two-pass carry reduction.
///
/// Reduction uses 2^448 ≡ 2^224 + 1 (mod p), i.e. limb position k for k ≥ 8
/// folds into limbs k-8 and k-4.
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u128; 15];
    for i in 0..8 {
        for j in 0..8 {
            t[i + j] += (a.0[i] as u128) * (b.0[j] as u128);
        }
    }
    fe_reduce_u128(&t)
}

#[inline(always)]
fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

#[inline(always)]
fn fe_reduce_u128(t: &[u128; 15]) -> Fe {
    let mut p = *t;
    // Fold high limbs: for k in 14..=8, p[k-8] += p[k] and p[k-4] += p[k].
    // Process from high to low so each fold is consumed before its operand
    // is overwritten by a later fold.
    for k in (8..=14).rev() {
        let hi = p[k];
        p[k] = 0;
        p[k - 8] += hi;
        p[k - 4] += hi;
    }
    // Now p[0..7] holds the reduced (but un-carried) limbs.
    let mask = (1u128 << 56) - 1;
    let mut r = [0u128; 8];
    r[..8].copy_from_slice(&p[..8]);

    // First carry pass through limbs 0..7.
    let c0 = r[0] >> 56;
    r[0] &= mask;
    r[1] += c0;
    let c1 = r[1] >> 56;
    r[1] &= mask;
    r[2] += c1;
    let c2 = r[2] >> 56;
    r[2] &= mask;
    r[3] += c2;
    let c3 = r[3] >> 56;
    r[3] &= mask;
    r[4] += c3;
    let c4 = r[4] >> 56;
    r[4] &= mask;
    r[5] += c4;
    let c5 = r[5] >> 56;
    r[5] &= mask;
    r[6] += c5;
    let c6 = r[6] >> 56;
    r[6] &= mask;
    r[7] += c6;
    let c7 = r[7] >> 56;
    r[7] &= mask;
    // c7 represents the contribution of bit 448 and above, which by the prime
    // structure 2^448 ≡ 2^224 + 1 folds back into limb 0 and limb 4.
    r[0] += c7;
    r[4] += c7;

    // Second pass to settle any new carries from the wrap-back.
    let c0 = r[0] >> 56;
    r[0] &= mask;
    r[1] += c0;
    let c1 = r[1] >> 56;
    r[1] &= mask;
    r[2] += c1;
    let c2 = r[2] >> 56;
    r[2] &= mask;
    r[3] += c2;
    let c3 = r[3] >> 56;
    r[3] &= mask;
    r[4] += c3;
    let c4 = r[4] >> 56;
    r[4] &= mask;
    r[5] += c4;
    let c5 = r[5] >> 56;
    r[5] &= mask;
    r[6] += c5;
    let c6 = r[6] >> 56;
    r[6] &= mask;
    r[7] += c6;
    let c7 = r[7] >> 56;
    r[7] &= mask;
    r[0] += c7;
    r[4] += c7;

    Fe([
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
        r[5] as u64,
        r[6] as u64,
        r[7] as u64,
    ])
}

fn fe_pow2k(a: &Fe, k: u32) -> Fe {
    let mut t = *a;
    for _ in 0..k {
        t = fe_sq(&t);
    }
    t
}

/// Multiply by the Montgomery-ladder constant `(A + 2)/4 = 39081`.
fn fe_mul_a24(a: &Fe) -> Fe {
    const A24: u128 = 39_081;
    let mut t = [0u128; 15];
    for (i, slot) in t.iter_mut().take(8).enumerate() {
        *slot = (a.0[i] as u128) * A24;
    }
    fe_reduce_u128(&t)
}

/// Compute `z^(p-2)` for `p = 2^448 - 2^224 - 1`.
///
/// Uses the chain `z^(p-2) = z * A^4 * B^(2^225)` where
/// `A = z^(2^222 - 1)` and `B = z^(2^223 - 1) = sq(A) * z`.
fn fe_invert(z: &Fe) -> Fe {
    // Build f(n) = z^(2^n - 1) for n in {2, 4, 8, 16, 32, 64, 128} via
    // repeated doubling, then chain up to f(222).
    let f2 = {
        let t = fe_sq(z); // z^2
        fe_mul(&t, z) // z^3 = z^(2^2 - 1)
    };
    let f4 = fe_mul(&fe_pow2k(&f2, 2), &f2); // z^(2^4 - 1)
    let f8 = fe_mul(&fe_pow2k(&f4, 4), &f4); // z^(2^8 - 1)
    let f16 = fe_mul(&fe_pow2k(&f8, 8), &f8); // z^(2^16 - 1)
    let f32 = fe_mul(&fe_pow2k(&f16, 16), &f16); // z^(2^32 - 1)
    let f64 = fe_mul(&fe_pow2k(&f32, 32), &f32); // z^(2^64 - 1)
    let f128 = fe_mul(&fe_pow2k(&f64, 64), &f64); // z^(2^128 - 1)
    let f192 = fe_mul(&fe_pow2k(&f128, 64), &f64); // z^(2^192 - 1)
    let f208 = fe_mul(&fe_pow2k(&f192, 16), &f16); // z^(2^208 - 1)
    let f216 = fe_mul(&fe_pow2k(&f208, 8), &f8); // z^(2^216 - 1)
    let f220 = fe_mul(&fe_pow2k(&f216, 4), &f4); // z^(2^220 - 1)
    let a = fe_mul(&fe_pow2k(&f220, 2), &f2); // A = z^(2^222 - 1)

    // B = sq(A) * z = z^(2^223 - 1).
    let b = fe_mul(&fe_sq(&a), z);

    // result = z * A^4 * B^(2^225) = z^(p - 2).
    let a4 = fe_pow2k(&a, 2);
    let b_high = fe_pow2k(&b, 225);
    let t = fe_mul(&a4, &b_high);
    fe_mul(&t, z)
}

/// Constant-time conditional swap.
#[inline(always)]
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..8 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Decode 56 LE bytes into a field element (no high-bit masking; X448
/// uses the full 448-bit u-coordinate).
fn fe_from_bytes(bytes: &[u8; X448_LEN]) -> Fe {
    let mut limbs = [0u64; 8];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let off = i * 7;
        let mut buf = [0u8; 8];
        buf[..7].copy_from_slice(&bytes[off..off + 7]);
        *limb = u64::from_le_bytes(buf);
    }
    Fe(limbs)
}

/// Encode a field element as 56 LE bytes, fully canonicalised mod `p`.
fn fe_to_bytes(a: &Fe) -> [u8; X448_LEN] {
    let mut t = a.0;
    // Two carry passes bring t into [0, 2*p).
    for _ in 0..2 {
        let c = t[0] >> 56;
        t[0] &= MASK56;
        t[1] += c;
        let c = t[1] >> 56;
        t[1] &= MASK56;
        t[2] += c;
        let c = t[2] >> 56;
        t[2] &= MASK56;
        t[3] += c;
        let c = t[3] >> 56;
        t[3] &= MASK56;
        t[4] += c;
        let c = t[4] >> 56;
        t[4] &= MASK56;
        t[5] += c;
        let c = t[5] >> 56;
        t[5] &= MASK56;
        t[6] += c;
        let c = t[6] >> 56;
        t[6] &= MASK56;
        t[7] += c;
        let c = t[7] >> 56;
        t[7] &= MASK56;
        t[0] += c;
        t[4] += c;
    }

    // Conditional subtract of p, constant time.
    let mut s = [0u64; 8];
    let mut borrow: u64 = 0;
    for i in 0..8 {
        let diff = t[i].wrapping_sub(P_LIMBS[i]).wrapping_sub(borrow);
        s[i] = diff & MASK56;
        // Bit 63 of `diff` is set iff t[i] < P_LIMBS[i] + borrow (wraparound).
        // After two carry passes each t[i] < 2^57 and P_LIMBS[i] < 2^56, so
        // bit 63 reflects underflow only.
        borrow = (diff >> 63) & 1;
    }
    let select_t = 0u64.wrapping_sub(borrow);
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = (t[i] & select_t) | (s[i] & !select_t);
    }

    // Pack 8 limbs of 56 bits each = 448 bits = 56 bytes; clean 7-byte boundaries.
    let mut bytes = [0u8; X448_LEN];
    for (i, limb) in out.iter().enumerate() {
        let off = i * 7;
        let mut v = limb.to_le_bytes();
        bytes[off..off + 7].copy_from_slice(&v[..7]);
        zeroize_slice(&mut v[..]);
    }
    // `t`, `s`, and `out` hold the encoded value in limb form; called from
    // the ladder, that value is the shared secret.
    zeroize_slice(&mut t[..]);
    zeroize_slice(&mut s[..]);
    zeroize_slice(&mut out[..]);
    bytes
}

/// RFC 7748 §5 `decodeScalar448`: clamp the 56-byte scalar in place.
fn clamp_scalar(scalar: &mut [u8; X448_LEN]) {
    scalar[0] &= 252;
    scalar[55] |= 128;
}

/// X448 Montgomery ladder.
fn x448_inner(scalar: &[u8; X448_LEN], u: &[u8; X448_LEN]) -> [u8; X448_LEN] {
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

    // Loop bits 447..0. After clamp, bit 447 is 1.
    for t in (0..=447).rev() {
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
/// §5 reads one: a non-canonical value (2^448 − 2^224 − 1 through 2^448 − 1)
/// reduced modulo p. Two strings name the same u-coordinate
/// exactly when their canonical encodings are equal.
fn canonical_u(bytes: &[u8; X448_LEN]) -> [u8; X448_LEN] {
    fe_to_bytes(&fe_from_bytes(bytes))
}

/// Top-level X448 functional surface (RFC 7748 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X448;

impl X448 {
    /// Compute `scalar * u` per RFC 7748 §5. The scalar is clamped before use.
    /// Constant-time in `scalar` and `u`.
    #[must_use]
    pub fn scalar_mult(scalar: &[u8; X448_LEN], u: &[u8; X448_LEN]) -> [u8; X448_LEN] {
        x448_inner(scalar, u)
    }

    /// Compute `scalar * G` where `G` is the X448 base point (`u = 5`).
    #[must_use]
    pub fn scalar_mult_base(scalar: &[u8; X448_LEN]) -> [u8; X448_LEN] {
        let mut base = [0u8; X448_LEN];
        base[0] = 5;
        x448_inner(scalar, &base)
    }

    /// Generate a new X448 key pair from `rng`.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R) -> (X448PublicKey, X448PrivateKey) {
        let mut secret = [0u8; X448_LEN];
        rng.fill_bytes(&mut secret);
        let public_bytes = X448::scalar_mult_base(&secret);
        let pair = (X448PublicKey(public_bytes), X448PrivateKey(secret));
        // `secret` was copied into the private key; wipe the stack original.
        zeroize_slice(&mut secret[..]);
        pair
    }
}

/// X448 private key: 56 raw bytes. Zeroised on drop.
#[derive(Clone)]
pub struct X448PrivateKey([u8; X448_LEN]);

impl PartialEq for X448PrivateKey {
    /// Compares the scalars in constant time.
    fn eq(&self, other: &Self) -> bool {
        crate::ct::constant_time_eq_mask(&self.0, &other.0) == u8::MAX
    }
}

impl Eq for X448PrivateKey {}

/// X448 public key: a 56-byte canonical u-coordinate.
///
/// Every constructor stores the canonical encoding of the u-coordinate its
/// input names, read as RFC 7748 §5 reads one (a non-canonical value taken
/// as reduced modulo `p`), so two keys naming the same u-coordinate are
/// equal, and [`Self::to_raw_bytes`] and the RFC 8410 encodings carry the
/// canonical form.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct X448PublicKey([u8; X448_LEN]);

impl X448PrivateKey {
    /// Construct from raw scalar bytes (caller-supplied entropy required).
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X448_LEN]) -> Self {
        Self(*bytes)
    }

    /// Construct from a mutable buffer; the caller's buffer is zeroised after
    /// the private scalar is copied.
    #[must_use]
    pub fn from_raw_bytes_wiping(bytes: &mut [u8; X448_LEN]) -> Self {
        let key = Self(*bytes);
        zeroize_slice(&mut bytes[..]);
        key
    }

    /// Return the raw 56-byte scalar.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X448_LEN] {
        self.0
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> X448PublicKey {
        X448PublicKey(X448::scalar_mult_base(&self.0))
    }

    /// Diffie-Hellman: compute shared secret with `peer`. Returns `None` if
    /// the result is the all-zero u-coordinate (low-order point), per the
    /// conservative recommendation in RFC 7748 §6.2.
    #[must_use]
    pub fn agree(&self, peer: &X448PublicKey) -> Option<[u8; X448_LEN]> {
        let shared = X448::scalar_mult(&self.0, &peer.0);
        let nonzero: u8 = shared.iter().fold(0u8, |acc, &b| acc | b);
        if nonzero == 0 {
            None
        } else {
            Some(shared)
        }
    }

    /// Encode as the RFC 8410 §7 `OneAsymmetricKey` (PKCS #8) in DER: version
    /// 1, `id-X448` with the parameters absent (§3), and the 56-byte scalar as
    /// `CurvePrivateKey`. The public key is left out, since the scalar derives
    /// it.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        curve_pkix::private_key_to_pkcs8(&ID_X448, &self.0)
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
    /// trailing bytes: version 1 or 2, `id-X448` with the parameters absent
    /// (§3), and a 56-byte `CurvePrivateKey`. As with [`Self::from_raw_bytes`],
    /// every 56-byte string is a scalar (RFC 7748 §5 clamps it at use). A
    /// version 2 `publicKey` must be 56 bytes naming the u-coordinate this
    /// scalar derives, as RFC 7748 §5 reads a u-coordinate: a non-canonical
    /// value taken as reduced modulo p. Attributes are ignored.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let (scalar, public_key) = curve_pkix::private_key_from_pkcs8(der, &ID_X448, X448_LEN)?;
        // Filled in place, so no by-value copy of the scalar is left behind.
        let mut bytes = [0u8; X448_LEN];
        bytes.copy_from_slice(scalar);
        let key = Self::from_raw_bytes_wiping(&mut bytes);
        match public_key {
            Some(public_key) => {
                let u: &[u8; X448_LEN] = public_key.try_into().ok()?;
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

impl core::fmt::Debug for X448PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X448PrivateKey(<redacted>)")
    }
}

impl core::fmt::Debug for X448PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "X448PublicKey({:02x?})", &self.0[..])
    }
}

impl Drop for X448PrivateKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0[..]);
    }
}

impl X448PublicKey {
    /// Wrap an externally-supplied u-coordinate as a public key. X448 is
    /// defined for every 56-byte input; the key stores the canonical
    /// encoding of the u-coordinate `bytes` names.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X448_LEN]) -> Self {
        Self(canonical_u(bytes))
    }

    /// Return the canonical 56-byte u-coordinate.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X448_LEN] {
        self.0
    }

    /// Encode as the RFC 8410 §4 `SubjectPublicKeyInfo` in DER: `id-X448`
    /// with the parameters absent (§3) and the 56-byte u-coordinate as the
    /// `subjectPublicKey`.
    #[must_use]
    pub fn to_spki_der(self) -> Vec<u8> {
        curve_pkix::public_key_to_spki(&ID_X448, &self.0)
    }

    /// Encode as RFC 7468 `PUBLIC KEY` text (§13) around [`Self::to_spki_der`].
    #[must_use]
    pub fn to_spki_pem(self) -> String {
        pem_encode(PUBLIC_KEY_LABEL, self.to_spki_der())
    }

    /// Decode an RFC 8410 §4 `SubjectPublicKeyInfo` from strict DER with no
    /// trailing bytes: `id-X448` with the parameters absent (§3) and a 56-byte
    /// key. As with [`Self::from_raw_bytes`], every 56-byte string is
    /// accepted, since RFC 7748 §5 defines X448 on all of them, and the
    /// canonical u-coordinate is stored.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let u = curve_pkix::public_key_from_spki(der, &ID_X448, X448_LEN)?;
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
    use crate::public_key::x25519::X25519PrivateKey;
    use crate::test_utils::{decode_hex_array, openssl3, ScratchFile};

    /// Sanity: bytes -> Fe -> bytes round-trips for canonical inputs.
    #[test]
    fn fe_bytes_roundtrip() {
        let mut bytes = [0u8; 56];
        bytes[0] = 5; // X448 base point u-coordinate
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe_to_bytes(&fe), bytes);

        bytes[0] = 1;
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe_to_bytes(&fe), bytes);
    }

    /// Sanity: fe_mul(2, fe_invert(2)) == 1.
    #[test]
    fn fe_invert_simple() {
        let two = Fe([2, 0, 0, 0, 0, 0, 0, 0]);
        let inv = fe_invert(&two);
        let prod = fe_mul(&two, &inv);
        let mut one = [0u8; 56];
        one[0] = 1;
        assert_eq!(fe_to_bytes(&prod), one);
    }

    /// RFC 7748 §5.2 first single-step vector for X448.
    #[test]
    fn rfc7748_section5_2_vector_1() {
        let k = decode_hex_array::<56>(concat!(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0",
            "d1aae121700a779c984c24f8cdd78fbff44943eba368f54b",
            "29259a4f1c600ad3"
        ));
        let u = decode_hex_array::<56>(concat!(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f",
            "020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada1",
            "8aa7a7fb4ef8a086"
        ));
        let expected = decode_hex_array::<56>(concat!(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d754",
            "6d5f239fe14fbaadeb445fc66a01b0779d98223961111e21",
            "766282f73dd96b6f"
        ));
        assert_eq!(X448::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 second single-step vector for X448.
    #[test]
    fn rfc7748_section5_2_vector_2() {
        let k = decode_hex_array::<56>(concat!(
            "203d494428b8399352665ddca42f9de8fef600908e0d461c",
            "b021f8c538345dd77c3e4806e25f46d3315c44e0a5b43712",
            "82dd2c8d5be3095f"
        ));
        let u = decode_hex_array::<56>(concat!(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1",
            "e9b6201b165d015894e56c4d3570bee52fe205e28a78b91c",
            "dfbde71ce8d157db"
        ));
        let expected = decode_hex_array::<56>(concat!(
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30",
            "fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c9",
            "54514e99da7c179d"
        ));
        assert_eq!(X448::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 iteration.
    #[test]
    fn rfc7748_section5_2_iter_1() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let u = k;
        let next = X448::scalar_mult(&k, &u);
        let expected = decode_hex_array::<56>(concat!(
            "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2",
            "ae2b846a4d23a8cd0db897086239492caf350b51f833868b",
            "9bc2b3bca9cf4113"
        ));
        assert_eq!(next, expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1000 iterations.
    #[test]
    fn rfc7748_section5_2_iter_1000() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for _ in 0..1000 {
            let next = X448::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = decode_hex_array::<56>(concat!(
            "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b",
            "975e09d4af6c67cf10d087202db88286e2b79fceea3ec353",
            "ef54faa26e219f38"
        ));
        assert_eq!(k, expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 000 000 iterations.
    /// Slow; gated `#[ignore]`. Run with: `cargo test --release -- --ignored x448_iter_1m`.
    #[test]
    #[ignore = "RFC 7748 1M-iteration test; run with --release --ignored"]
    fn rfc7748_section5_2_iter_1m_x448() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for _ in 0..1_000_000 {
            let next = X448::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = decode_hex_array::<56>(concat!(
            "077f453681caca3693198420bbe515cae0002472519b3e67",
            "661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d6",
            "9bd9d9d66b997e37"
        ));
        assert_eq!(k, expected);
    }

    /// Round-trip: A * (B * G) == B * (A * G).
    #[test]
    fn ecdh_roundtrip() {
        let a = [0x11u8; 56];
        let b = [0x22u8; 56];
        let pa = X448::scalar_mult_base(&a);
        let pb = X448::scalar_mult_base(&b);
        let sa = X448::scalar_mult(&a, &pb);
        let sb = X448::scalar_mult(&b, &pa);
        assert_eq!(sa, sb);
    }

    /// All-zero output for u=0 must be flagged by `agree`.
    #[test]
    fn agree_rejects_low_order_zero_output() {
        let secret = X448PrivateKey::from_raw_bytes(&[0x55u8; 56]);
        let zero_pub = X448PublicKey::from_raw_bytes(&[0u8; 56]);
        assert!(secret.agree(&zero_pub).is_none());
    }

    #[test]
    fn private_key_equality_is_by_value() {
        let key = X448PrivateKey::from_raw_bytes(&[0x42; X448_LEN]);
        let same = X448PrivateKey::from_raw_bytes(&[0x42; X448_LEN]);
        let mut other_bytes = [0x42; X448_LEN];
        other_bytes[1] ^= 0x01;
        let other = X448PrivateKey::from_raw_bytes(&other_bytes);
        assert!(key == same);
        assert!(key != other);
    }

    /// A public key built from a non-canonical u-coordinate equals, and
    /// re-encodes as, the key built from its canonical form.
    #[test]
    fn public_key_import_canonicalises_the_u_coordinate() {
        let mut five = [0u8; 56];
        five[0] = 5;
        let mut p_plus_5 = [0u8; 56];
        p_plus_5[0] = 4;
        p_plus_5[28..].fill(0xff);
        let canonical = X448PublicKey::from_raw_bytes(&five);
        let reduced = X448PublicKey::from_raw_bytes(&p_plus_5);
        assert_eq!(reduced, canonical);
        assert_eq!(reduced.to_raw_bytes(), five);
        assert_eq!(
            X448PublicKey::from_spki_der(&reduced.to_spki_der()),
            Some(canonical)
        );
    }

    #[test]
    fn canonical_u_reduces_non_canonical_u_coordinates() {
        let mut five = [0u8; 56];
        five[0] = 5;
        assert_eq!(canonical_u(&five), five);
        // p + 5 = 2^448 − 2^224 + 4, the non-canonical encoding of 5.
        let mut p_plus_5 = [0u8; 56];
        p_plus_5[0] = 4;
        p_plus_5[28..].fill(0xff);
        assert_eq!(canonical_u(&p_plus_5), five);
        // 2^448 − 1 = p + 2^224, the largest non-canonical value.
        let mut two_to_224 = [0u8; 56];
        two_to_224[28] = 1;
        assert_eq!(canonical_u(&[0xff; 56]), two_to_224);
    }

    /// RFC 7748 §6.2: Alice's private key, in the RFC's two halves.
    const RFC7748_ALICE_PRIVATE: &str = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
        d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";

    /// RFC 7748 §6.2: Alice's public key, X448(a, 5).
    const RFC7748_ALICE_PUBLIC: &str = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
        22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";

    /// RFC 7748 §6.2: Bob's public key.
    const RFC7748_BOB_PUBLIC: &str = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
        27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";

    #[test]
    fn spki_and_pkcs8_round_trip_in_rfc8410_framing() {
        let private =
            X448PrivateKey::from_raw_bytes(&decode_hex_array::<56>(RFC7748_ALICE_PRIVATE));
        let public = private.to_public_key();
        assert_eq!(
            public.to_raw_bytes(),
            decode_hex_array::<56>(RFC7748_ALICE_PUBLIC)
        );

        // SEQUENCE { SEQUENCE { OID 1.3.101.111 }, BIT STRING { 00, u } }.
        let spki = public.to_spki_der();
        assert_eq!(
            spki[..12],
            [0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00]
        );
        assert_eq!(spki[12..], public.to_raw_bytes());
        assert_eq!(X448PublicKey::from_spki_der(&spki), Some(public));
        assert_eq!(
            X448PublicKey::from_spki_pem(&public.to_spki_pem()),
            Some(public)
        );

        // SEQUENCE { INTEGER 0, SEQUENCE { OID }, OCTET STRING { OCTET STRING { k } } }.
        let pkcs8 = private.to_pkcs8_der();
        assert_eq!(
            pkcs8[..16],
            [
                0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a,
                0x04, 0x38
            ]
        );
        assert_eq!(pkcs8[16..], private.to_raw_bytes());
        assert_eq!(
            X448PrivateKey::from_pkcs8_der(&pkcs8),
            Some(private.clone())
        );
        assert_eq!(
            X448PrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem()),
            Some(private.clone())
        );

        // An X25519 key is not an X448 key.
        let x25519 = X25519PrivateKey::from_raw_bytes(&[0x11; 32]);
        assert!(X448PrivateKey::from_pkcs8_der(&x25519.to_pkcs8_der()).is_none());
        assert!(X448PublicKey::from_spki_der(&x25519.to_public_key().to_spki_der()).is_none());
    }

    #[test]
    fn pkcs8_ber_accepts_an_indefinite_length_container() {
        let private =
            X448PrivateKey::from_raw_bytes(&decode_hex_array::<56>(RFC7748_ALICE_PRIVATE));
        let der = private.to_pkcs8_der();
        let ber = crate::test_utils::der_to_indefinite_length(&der);
        assert!(X448PrivateKey::from_pkcs8_der(&ber).is_none());
        assert_eq!(X448PrivateKey::from_pkcs8_ber(&ber), Some(private.clone()));
        assert_eq!(X448PrivateKey::from_pkcs8_ber(&der), Some(private));
    }

    #[test]
    fn pkcs8_version_2_public_key_must_match() {
        let private =
            X448PrivateKey::from_raw_bytes(&decode_hex_array::<56>(RFC7748_ALICE_PRIVATE));
        let alice = private.to_public_key().to_raw_bytes();
        let with_public = |public_key: &[u8]| {
            OneAsymmetricKey::new(
                AlgorithmIdentifier::new(&ID_X448, None),
                &der_octet_string(&private.to_raw_bytes()),
                Some(public_key),
            )
            .to_der()
        };
        assert_eq!(
            X448PrivateKey::from_pkcs8_der(&with_public(&alice)),
            Some(private.clone())
        );
        let bob = decode_hex_array::<56>(RFC7748_BOB_PUBLIC);
        for mismatched in [&bob[..], &alice[..55]] {
            assert!(X448PrivateKey::from_pkcs8_der(&with_public(mismatched)).is_none());
        }
    }

    /// OpenSSL's X448 key parses and re-encodes byte for byte; OpenSSL reads
    /// the crate's keys, derives the same public key, re-emits the same
    /// encodings, and computes the same shared secret.
    #[test]
    fn openssl_x448_keys_interoperate() {
        const TEST: &str = "openssl_x448_keys_interoperate";
        let Some(theirs_pem) = openssl3(&["genpkey", "-algorithm", "X448"], b"").or_skip(TEST)
        else {
            return;
        };
        let run = |args: &[&str], stdin: &[u8]| {
            openssl3(args, stdin)
                .or_skip(TEST)
                .expect("openssl works once genpkey did")
        };
        let theirs =
            X448PrivateKey::from_pkcs8_pem(std::str::from_utf8(&theirs_pem).expect("PEM is ASCII"))
                .expect("OpenSSL's PKCS #8 X448 key");
        assert_eq!(theirs.to_pkcs8_pem().as_bytes(), theirs_pem);
        let theirs_spki = run(&["pkey", "-pubout", "-outform", "DER"], &theirs_pem);
        let theirs_public =
            X448PublicKey::from_spki_der(&theirs_spki).expect("OpenSSL's SubjectPublicKeyInfo");
        assert_eq!(theirs_public, theirs.to_public_key());
        assert_eq!(theirs_public.to_spki_der(), theirs_spki);

        let ours = X448PrivateKey::from_raw_bytes(&decode_hex_array::<56>(RFC7748_ALICE_PRIVATE));
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
        assert!(String::from_utf8_lossy(&text).contains("X448 Private-Key"));

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
