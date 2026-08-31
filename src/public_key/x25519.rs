//! X25519 ECDH per RFC 7748 §5 over Curve25519.
//!
//! Constant-time scalar multiplication on the Montgomery form of Curve25519,
//! `y^2 = x^3 + 486662 x^2 + x` over `GF(2^255 - 19)`. The Montgomery ladder
//! operates on `u`-coordinates only; conditional swaps are driven by scalar
//! bits without data-dependent branching or indexing, and field arithmetic
//! uses a fixed 5×51-bit limb form so each operation has constant access
//! pattern.
//!
//! Unlike the rest of `crate::vt`, X25519 here is intended to be
//! constant-time. It is exposed under `crate::vt` because the surrounding
//! key-handling code (PEM/DER blobs, error paths) shares conventions with
//! the rest of the public-key surface, but the scalar-mult primitive itself
//! is hardened against timing side channels on the secret scalar.
//!
//! References:
//! - RFC 7748, "Elliptic Curves for Security", §5 X25519 / §5.2 test vectors.
//! - D. J. Bernstein, "Curve25519: new Diffie-Hellman speed records" (2006).

use crate::ct::zeroize_slice;
use crate::Csprng;

/// Length in bytes of an X25519 scalar / u-coordinate / shared secret.
pub const X25519_LEN: usize = 32;

const MASK51: u64 = (1u64 << 51) - 1;

// Field modulus p = 2^255 - 19 in 5x51 limbs.
//   limb 0 = 2^51 - 19 = 0x7_ffff_ffff_ffed
//   limbs 1..4 = 2^51 - 1 = 0x7_ffff_ffff_ffff
const P_LIMBS: [u64; 5] = [
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
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
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

/// Compute `z^(p-2) = z^(2^255 - 21)` (modular inverse for nonzero z).
fn fe_invert(z: &Fe) -> Fe {
    // Bernstein's standard 254-square / 11-multiply chain for x^(p-2).
    let z2 = fe_sq(z);
    let t = fe_pow2k(&z2, 2);
    let z9 = fe_mul(&t, z);
    let z11 = fe_mul(&z9, &z2);
    let t = fe_sq(&z11);
    let z2_5_0 = fe_mul(&t, &z9);

    let t = fe_pow2k(&z2_5_0, 5);
    let z2_10_0 = fe_mul(&t, &z2_5_0);

    let t = fe_pow2k(&z2_10_0, 10);
    let z2_20_0 = fe_mul(&t, &z2_10_0);

    let t = fe_pow2k(&z2_20_0, 20);
    let t = fe_mul(&t, &z2_20_0);

    let t = fe_pow2k(&t, 10);
    let z2_50_0 = fe_mul(&t, &z2_10_0);

    let t = fe_pow2k(&z2_50_0, 50);
    let z2_100_0 = fe_mul(&t, &z2_50_0);

    let t = fe_pow2k(&z2_100_0, 100);
    let t = fe_mul(&t, &z2_100_0);

    let t = fe_pow2k(&t, 50);
    let t = fe_mul(&t, &z2_50_0);

    let t = fe_pow2k(&t, 5);
    fe_mul(&t, &z11)
}

/// Constant-time conditional swap: if `swap == 1`, swap `a` and `b`; if `0`,
/// no change. Touches every limb regardless of `swap`.
#[inline(always)]
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Decode 32 LE bytes into a field element. Per RFC 7748 §5, the high bit of
/// the most-significant byte is masked off first.
fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
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
/// Constant-time: the conditional subtraction of `p` is mask-driven.
fn fe_to_bytes(a: &Fe) -> [u8; 32] {
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
    for i in 0..5 {
        let diff = t[i].wrapping_sub(P_LIMBS[i]).wrapping_sub(borrow);
        s[i] = diff & MASK51;
        // Bit 63 of `diff` is set iff t[i] < P_LIMBS[i] + borrow (wraparound).
        // Inputs are < 2^52, P_LIMBS[i] < 2^51, borrow ∈ {0,1}, so the only
        // way bit 63 ends up set is via underflow.
        borrow = (diff >> 63) & 1;
    }
    let select_t = 0u64.wrapping_sub(borrow);
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = (t[i] & select_t) | (s[i] & !select_t);
    }

    // Pack five 51-bit limbs into 32 LE bytes.
    let mut bytes = [0u8; 32];
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
    bytes
}

/// RFC 7748 §5 `decodeScalar25519`: clamp the 32-byte scalar in place.
fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// X25519 Montgomery ladder. Computes `scalar * u` per RFC 7748 §5 with
/// constant-time scalar processing.
fn x25519_inner(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    clamp_scalar(&mut k);

    let x1 = fe_from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap: u64 = 0;

    // Process bits 254 down to 0. Bits above 254 are forced to zero by the
    // clamp; bit 254 is forced to 1 (so swap on that bit is well-defined).
    for t in (0..=254).rev() {
        let byte = t / 8;
        let bit = t % 8;
        let k_t = ((k[byte] >> bit) & 1) as u64;
        swap ^= k_t;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = k_t;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let da_plus_cb = fe_add(&da, &cb);
        let da_minus_cb = fe_sub(&da, &cb);
        x3 = fe_sq(&da_plus_cb);
        let da_minus_cb_sq = fe_sq(&da_minus_cb);
        z3 = fe_mul(&x1, &da_minus_cb_sq);
        x2 = fe_mul(&aa, &bb);
        let a24_e = fe_mul_a24(&e);
        let aa_plus_a24e = fe_add(&aa, &a24_e);
        z2 = fe_mul(&e, &aa_plus_a24e);
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let z2_inv = fe_invert(&z2);
    let result = fe_mul(&x2, &z2_inv);

    // Wipe the clamped scalar copy.
    zeroize_slice(&mut k[..]);
    fe_to_bytes(&result)
}

/// Top-level X25519 functional surface (RFC 7748 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519;

impl X25519 {
    /// Compute `scalar * u` per RFC 7748 §5. The scalar is clamped before use.
    /// Constant-time in `scalar` and `u`.
    #[must_use]
    pub fn scalar_mult(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        x25519_inner(scalar, u)
    }

    /// Compute `scalar * G` where `G` is the X25519 base point (`u = 9`).
    #[must_use]
    pub fn scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
        let mut base = [0u8; 32];
        base[0] = 9;
        x25519_inner(scalar, &base)
    }

    /// Generate a new X25519 key pair from `rng`. The private scalar is
    /// 32 random bytes pre-clamping; clamping is applied at use time.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R) -> (X25519PublicKey, X25519PrivateKey) {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let public_bytes = X25519::scalar_mult_base(&secret);
        (X25519PublicKey(public_bytes), X25519PrivateKey(secret))
    }
}

/// X25519 private key: 32 raw bytes. Zeroised on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct X25519PrivateKey([u8; 32]);

/// X25519 public key: a 32-byte canonical u-coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519PublicKey([u8; X25519_LEN]);

impl X25519PrivateKey {
    /// Construct from raw scalar bytes (caller-supplied entropy required).
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Construct from a mutable buffer; the caller's buffer is zeroised after
    /// the private scalar is copied.
    #[must_use]
    pub fn from_raw_bytes_wiping(bytes: &mut [u8; 32]) -> Self {
        let key = Self(*bytes);
        zeroize_slice(&mut bytes[..]);
        key
    }

    /// Return the raw 32-byte scalar.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; 32] {
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
    #[must_use]
    pub fn agree(&self, peer: &X25519PublicKey) -> Option<[u8; 32]> {
        let shared = X25519::scalar_mult(&self.0, &peer.0);
        let nonzero: u8 = shared.iter().fold(0u8, |acc, &b| acc | b);
        if nonzero == 0 {
            None
        } else {
            Some(shared)
        }
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
    /// after the high bit is masked.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Return the raw 32-byte u-coordinate.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr32(s: &str) -> [u8; 32] {
        let v = unhex(s);
        assert_eq!(v.len(), 32);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// RFC 7748 §5.2 first single-step vector.
    #[test]
    fn rfc7748_section5_2_vector_1() {
        let k = arr32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = arr32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = arr32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(X25519::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 second single-step vector.
    #[test]
    fn rfc7748_section5_2_vector_2() {
        let k = arr32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = arr32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = arr32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(X25519::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 iteration.
    #[test]
    fn rfc7748_section5_2_iter_1() {
        let mut k = arr32("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        let next = X25519::scalar_mult(&k, &u);
        u = k;
        k = next;
        let expected = arr32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(k, expected);
        // Silence unused-warning on `u`: it would be the next u-coordinate input.
        let _ = u;
    }

    /// RFC 7748 §5.2 iterated test, after 1000 iterations.
    #[test]
    fn rfc7748_section5_2_iter_1000() {
        let mut k = arr32("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1000 {
            let next = X25519::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = arr32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
        assert_eq!(k, expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 000 000 iterations.
    /// Slow (~minutes in debug, ~seconds in release); gated `#[ignore]`.
    /// Run with: `cargo test --release -- --ignored x25519_iter_1m`.
    #[test]
    #[ignore = "RFC 7748 1M-iteration test; run with --release --ignored"]
    fn rfc7748_section5_2_iter_1m_x25519() {
        let mut k = arr32("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1_000_000 {
            let next = X25519::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = arr32("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
        assert_eq!(k, expected);
    }

    /// Round-trip: A * (B * G) == B * (A * G).
    #[test]
    fn ecdh_roundtrip() {
        let a = arr32("0101010101010101010101010101010101010101010101010101010101010101");
        let b = arr32("0202020202020202020202020202020202020202020202020202020202020202");
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
        let bytes = arr32("0100000000000000000000000000000000000000000000000000000000000000");
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe.0, [1, 0, 0, 0, 0]);
        assert_eq!(fe_to_bytes(&fe), bytes);

        let bytes = arr32("0900000000000000000000000000000000000000000000000000000000000000");
        let fe = fe_from_bytes(&bytes);
        assert_eq!(fe.0, [9, 0, 0, 0, 0]);
        assert_eq!(fe_to_bytes(&fe), bytes);
    }

    /// Sanity: fe_mul(1, x) == x (canonical).
    #[test]
    fn fe_mul_by_one_is_identity() {
        let x = fe_from_bytes(&arr32(
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
}
