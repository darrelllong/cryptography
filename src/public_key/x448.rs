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
//! References:
//! - RFC 7748, "Elliptic Curves for Security", §5 X448 / §5.2 test vectors.
//! - M. Hamburg, "Ed448-Goldilocks, a new elliptic curve" (2015).

use crate::ct::zeroize_slice;
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
        let v = limb.to_le_bytes();
        bytes[off..off + 7].copy_from_slice(&v[..7]);
    }
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

    // Loop bits 447..0. After clamp, bit 447 is 1.
    for t in (0..=447).rev() {
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

    zeroize_slice(&mut k[..]);
    fe_to_bytes(&result)
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
        (X448PublicKey(public_bytes), X448PrivateKey(secret))
    }
}

/// X448 private key: 56 raw bytes. Zeroised on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct X448PrivateKey([u8; X448_LEN]);

/// X448 public key: a 56-byte canonical u-coordinate.
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
    /// Wrap an externally-supplied u-coordinate as a public key.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X448_LEN]) -> Self {
        Self(*bytes)
    }

    /// Return the raw 56-byte u-coordinate.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X448_LEN] {
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

    fn arr56(s: &str) -> [u8; 56] {
        let v = unhex(s);
        assert_eq!(v.len(), 56);
        let mut a = [0u8; 56];
        a.copy_from_slice(&v);
        a
    }

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
        let k = arr56(concat!(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0",
            "d1aae121700a779c984c24f8cdd78fbff44943eba368f54b",
            "29259a4f1c600ad3"
        ));
        let u = arr56(concat!(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f",
            "020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada1",
            "8aa7a7fb4ef8a086"
        ));
        let expected = arr56(concat!(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d754",
            "6d5f239fe14fbaadeb445fc66a01b0779d98223961111e21",
            "766282f73dd96b6f"
        ));
        assert_eq!(X448::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 second single-step vector for X448.
    #[test]
    fn rfc7748_section5_2_vector_2() {
        let k = arr56(concat!(
            "203d494428b8399352665ddca42f9de8fef600908e0d461c",
            "b021f8c538345dd77c3e4806e25f46d3315c44e0a5b43712",
            "82dd2c8d5be3095f"
        ));
        let u = arr56(concat!(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1",
            "e9b6201b165d015894e56c4d3570bee52fe205e28a78b91c",
            "dfbde71ce8d157db"
        ));
        let expected = arr56(concat!(
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
        let expected = arr56(concat!(
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
        let expected = arr56(concat!(
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
        let expected = arr56(concat!(
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
}
