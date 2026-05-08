//! NTRU-HPS-4096-821 implemented in safe, idiomatic Rust from the round-3
//! NTRU specification (Chen, Chung, Hülsing, Lange, Lyubashevsky, Saito,
//! Schanck, Schwabe, Stehlé, Whyte, Xagawa, Yamakawa, Zhang; NIST PQC,
//! 2020-10-16).
//!
//! This module provides:
//! - the HPS-4096-821 parameter set ($N = 821$, $q = 4096$,
//!   weight `= q/8 - 2 = 510`)
//! - key generation, encapsulation, decapsulation (CCA KEM)
//! - strict wire-format byte encodings for `pk`, `sk`, `ct`, `ss`
//!
//! See [`crate::public_key::ntru_hps509`] for the full algorithmic
//! description; HPS-4096-821 differs in ring degree, in the larger `q`
//! (which selects a 12-bit-per-coefficient `Sq` packing rather than
//! 11-bit), and in the doubled fixed-weight count. Polynomial inversion
//! follows Bernstein–Yang (TCHES 2019); the fixed-weight sampler uses
//! Batcher's bitonic sorting network (1968).
//!
//! Validation:
//! the `count = 0` entry of the round-3 KAT `PQCkemKAT_1590.rsp` is
//! reproduced byte-for-byte by the inline test.
//!
//! Side channels:
//! polynomial multiplication uses the variable-time Karatsuba split shared
//! across all four NTRU parameter sets. This module is exposed under
//! `crate::vt` to make that property explicit.

use core::fmt;

use crate::hash::sha3::Sha3_256;
use crate::hash::Digest;
use crate::Csprng;

// ---- parameter constants ---------------------------------------------------

const N: usize = 821;
const LOGQ: usize = 12;
const Q: u32 = 1 << LOGQ;
const Q16: u16 = Q as u16;
const Q_MASK: u16 = (Q as u16).wrapping_sub(1);
const WEIGHT: usize = (Q as usize) / 8 - 2; // 254

const PRFKEYBYTES: usize = 32;
const SHAREDKEYBYTES: usize = 32;

const SAMPLE_IID_BYTES: usize = N - 1; // 508
const SAMPLE_FT_BYTES: usize = (30 * (N - 1) + 7) / 8; // 1905
const SAMPLE_FG_BYTES: usize = SAMPLE_IID_BYTES + SAMPLE_FT_BYTES; // 2413
const SAMPLE_RM_BYTES: usize = SAMPLE_IID_BYTES + SAMPLE_FT_BYTES; // 2413

const PACK_DEG: usize = N - 1; // 508
const PACK_TRINARY_BYTES: usize = (PACK_DEG + 4) / 5; // 102

const OWCPA_MSGBYTES: usize = 2 * PACK_TRINARY_BYTES; // 204
const OWCPA_PUBLICKEYBYTES: usize = (LOGQ * PACK_DEG + 7) / 8; // 699
const OWCPA_SECRETKEYBYTES: usize = 2 * PACK_TRINARY_BYTES + OWCPA_PUBLICKEYBYTES; // 903
const OWCPA_BYTES: usize = (LOGQ * PACK_DEG + 7) / 8; // 699

/// Public-key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = OWCPA_PUBLICKEYBYTES; // 699
/// Private-key length in bytes (includes implicit-rejection PRF key).
pub const PRIVATE_KEY_BYTES: usize = OWCPA_SECRETKEYBYTES + PRFKEYBYTES; // 935
/// Ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = OWCPA_BYTES; // 699
/// Shared-secret length in bytes.
pub const SHARED_SECRET_BYTES: usize = SHAREDKEYBYTES; // 32

// ---- polynomial type -------------------------------------------------------

#[derive(Clone, Copy)]
struct Poly {
    coeffs: [u16; N],
}

impl Poly {
    fn zero() -> Self {
        Self { coeffs: [0u16; N] }
    }
}

use crate::public_key::ntru_pqc_shared::{
    cmov, crypto_sort_int32, mod3, both_negative_mask_i16,
};

#[inline(always)]
fn modq(x: u16) -> u16 {
    x & Q_MASK
}

fn poly_mod_3_phi_n(r: &mut Poly) {
    let last = r.coeffs[N - 1];
    for c in r.coeffs.iter_mut() {
        *c = mod3(*c + 2 * last);
    }
}

fn poly_mod_q_phi_n(r: &mut Poly) {
    let last = r.coeffs[N - 1];
    for c in r.coeffs.iter_mut() {
        *c = c.wrapping_sub(last);
    }
}

// ---- Z3 <-> Zq coefficient remapping ---------------------------------------

fn poly_z3_to_zq(r: &mut Poly) {
    // {0, 1, 2} -> {0, 1, q-1}
    for c in r.coeffs.iter_mut() {
        *c |= (0u16.wrapping_sub(*c >> 1)) & Q_MASK;
    }
}

fn poly_trinary_zq_to_z3(r: &mut Poly) {
    // {0, 1, q-1} -> {0, 1, 2}
    for c in r.coeffs.iter_mut() {
        *c = modq(*c);
        *c = 3 & (*c ^ (*c >> (LOGQ - 1)));
    }
}

// ---- multiplication in R_q -------------------------------------------------

fn poly_rq_mul(r: &mut Poly, a: &Poly, b: &Poly) {
    crate::public_key::ntru_poly_mul::poly_mul_cyclic(&mut r.coeffs, &a.coeffs, &b.coeffs);
}

fn poly_sq_mul(r: &mut Poly, a: &Poly, b: &Poly) {
    poly_rq_mul(r, a, b);
    poly_mod_q_phi_n(r);
}

fn poly_s3_mul(r: &mut Poly, a: &Poly, b: &Poly) {
    poly_rq_mul(r, a, b);
    poly_mod_3_phi_n(r);
}

// ---- Rq -> S3 coefficient projection ---------------------------------------

fn poly_rq_to_s3(r: &mut Poly, a: &Poly) {
    for i in 0..N {
        let mut c = modq(a.coeffs[i]);
        let flag = c >> (LOGQ - 1);
        // -q mod 3 = -2^k mod 3 = 1 << (1 - (k & 1))
        c = c.wrapping_add(flag << (1 - (LOGQ & 1)));
        r.coeffs[i] = c;
    }
    poly_mod_3_phi_n(r);
}

// ---- lift(m) for HPS: trivial Z_3 -> Z_q embedding -------------------------

fn poly_lift(r: &mut Poly, a: &Poly) {
    r.coeffs = a.coeffs;
    poly_z3_to_zq(r);
}

// ---- constant-time inverse in R_2 = F_2[x] / (x^N - 1) ---------------------
//
// Bernstein and Yang's constant-time gcd recursion (TCHES 2019, "Fast
// constant-time gcd computation and modular inversion"): a swap-and-shift
// loop on (f, g) over F_2[x] that converges to (gcd, 0) while threading
// (v, w) so v · a ≡ gcd (mod x^N - 1) at exit. The 2(N-1)-1 iteration count
// is the worst-case bound from the cited paper.

fn poly_r2_inv(r: &mut Poly, a: &Poly) {
    let mut f = [0u16; N];
    let mut g = [0u16; N];
    let mut v = [0u16; N];
    let mut w = [0u16; N];
    w[0] = 1;
    for fi in f.iter_mut() {
        *fi = 1;
    }
    for i in 0..N - 1 {
        g[N - 2 - i] = (a.coeffs[i] ^ a.coeffs[N - 1]) & 1;
    }
    g[N - 1] = 0;
    let mut delta: i16 = 1;

    for _ in 0..(2 * (N - 1) - 1) {
        // shift v
        for i in (1..N).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;

        let sign = (g[0] & f[0]) as i16;
        let swap = both_negative_mask_i16(-delta, -(g[0] as i16));
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for i in 0..N {
            let t = (swap as u16) & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            let t = (swap as u16) & (v[i] ^ w[i]);
            v[i] ^= t;
            w[i] ^= t;
        }
        for i in 0..N {
            g[i] ^= (sign as u16) & f[i];
        }
        for i in 0..N {
            w[i] ^= (sign as u16) & v[i];
        }
        for i in 0..N - 1 {
            g[i] = g[i + 1];
        }
        g[N - 1] = 0;
    }

    for i in 0..N - 1 {
        r.coeffs[i] = v[N - 2 - i];
    }
    r.coeffs[N - 1] = 0;
}

// ---- constant-time inverse in S_3 = F_3[x] / Phi_n(x) ----------------------
//
// Same Bernstein–Yang gcd recursion as poly_r2_inv but over F_3 instead of
// F_2. mod3_u8 keeps coefficients canonical after every step.

#[inline]
fn mod3_u8(a: u8) -> u8 {
    let a = (a >> 2) + (a & 3); // 0..=4
    let t = (a as i16) - 3;
    let c = t >> 5;
    (t ^ (c & ((a as i16) ^ t))) as u8
}

fn poly_s3_inv(r: &mut Poly, a: &Poly) {
    let mut f = [0u16; N];
    let mut g = [0u16; N];
    let mut v = [0u16; N];
    let mut w = [0u16; N];
    w[0] = 1;
    for fi in f.iter_mut() {
        *fi = 1;
    }
    for i in 0..N - 1 {
        g[N - 2 - i] =
            mod3_u8(((a.coeffs[i] & 3) + 2 * (a.coeffs[N - 1] & 3)) as u8) as u16;
    }
    g[N - 1] = 0;
    let mut delta: i16 = 1;

    for _ in 0..(2 * (N - 1) - 1) {
        for i in (1..N).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;

        let sign = mod3_u8((2 * g[0] * f[0]) as u8) as u16;
        let swap = both_negative_mask_i16(-delta, -(g[0] as i16));
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for i in 0..N {
            let t = (swap as u16) & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            let t = (swap as u16) & (v[i] ^ w[i]);
            v[i] ^= t;
            w[i] ^= t;
        }
        for i in 0..N {
            g[i] = mod3_u8((g[i] + sign * f[i]) as u8) as u16;
        }
        for i in 0..N {
            w[i] = mod3_u8((w[i] + sign * v[i]) as u8) as u16;
        }
        for i in 0..N - 1 {
            g[i] = g[i + 1];
        }
        g[N - 1] = 0;
    }

    let sign = f[0] as u16;
    for i in 0..N - 1 {
        r.coeffs[i] = mod3_u8((sign * v[N - 2 - i]) as u8) as u16;
    }
    r.coeffs[N - 1] = 0;
}

// ---- inverse in R_q = Z_q[x] / (x^N - 1) via Hensel lift from R_2 ----------
//
// Standard Newton-style 2-adic lift: given a · b ≡ 1 (mod 2^k), the update
// b ← b · (2 - a · b) doubles the precision to (mod 2^{2k}). Four lift
// iterations carry an R_2 inverse to precision 2^16, which subsumes the
// largest q in this NTRU family (q = 8192 = 2^13). All arithmetic is u16
// wrapping; the final mod-q reduction happens at use sites.

fn poly_r2_inv_to_rq_inv(r: &mut Poly, ai: &Poly, a: &Poly) {
    let mut b = Poly::zero();
    for i in 0..N {
        b.coeffs[i] = 0u16.wrapping_sub(a.coeffs[i]);
    }
    r.coeffs = ai.coeffs;

    let mut c = Poly::zero();
    let mut s = Poly::zero();

    // ai := ai * (2 - a*ai), four times.
    poly_rq_mul(&mut c, r, &b);
    c.coeffs[0] = c.coeffs[0].wrapping_add(2);
    poly_rq_mul(&mut s, &c, r);

    poly_rq_mul(&mut c, &s, &b);
    c.coeffs[0] = c.coeffs[0].wrapping_add(2);
    poly_rq_mul(r, &c, &s);

    poly_rq_mul(&mut c, r, &b);
    c.coeffs[0] = c.coeffs[0].wrapping_add(2);
    poly_rq_mul(&mut s, &c, r);

    poly_rq_mul(&mut c, &s, &b);
    c.coeffs[0] = c.coeffs[0].wrapping_add(2);
    poly_rq_mul(r, &c, &s);
}

fn poly_rq_inv(r: &mut Poly, a: &Poly) {
    let mut ai2 = Poly::zero();
    poly_r2_inv(&mut ai2, a);
    poly_r2_inv_to_rq_inv(r, &ai2, a);
}

// ---- S_3 packing: 5 trits per byte in base 3 -------------------------------

fn poly_s3_tobytes(msg: &mut [u8], a: &Poly) {
    debug_assert_eq!(msg.len(), PACK_TRINARY_BYTES);
    let full = PACK_DEG / 5;
    for i in 0..full {
        let mut c = (a.coeffs[5 * i + 4] & 0xff) as u8;
        c = (3u8.wrapping_mul(c)).wrapping_add(a.coeffs[5 * i + 3] as u8);
        c = (3u8.wrapping_mul(c)).wrapping_add(a.coeffs[5 * i + 2] as u8);
        c = (3u8.wrapping_mul(c)).wrapping_add(a.coeffs[5 * i + 1] as u8);
        c = (3u8.wrapping_mul(c)).wrapping_add(a.coeffs[5 * i] as u8);
        msg[i] = c;
    }
    if PACK_DEG > full * 5 {
        // tail: coefficients PACK_DEG - 5*full ..  go into msg[full]
        let mut c: u8 = 0;
        let start = 5 * full;
        let mut j = (PACK_DEG - start) as isize - 1;
        while j >= 0 {
            c = (3u8.wrapping_mul(c)).wrapping_add(a.coeffs[start + j as usize] as u8);
            j -= 1;
        }
        msg[full] = c;
    }
}

fn poly_s3_frombytes(r: &mut Poly, msg: &[u8]) {
    debug_assert_eq!(msg.len(), PACK_TRINARY_BYTES);
    let full = PACK_DEG / 5;
    for i in 0..full {
        let c = msg[i] as u32;
        r.coeffs[5 * i] = c as u16;
        r.coeffs[5 * i + 1] = ((c * 171) >> 9) as u16; // /3
        r.coeffs[5 * i + 2] = ((c * 57) >> 9) as u16; // /9
        r.coeffs[5 * i + 3] = ((c * 19) >> 9) as u16; // /27
        r.coeffs[5 * i + 4] = ((c * 203) >> 14) as u16; // /81
    }
    if PACK_DEG > full * 5 {
        let mut c = msg[full] as u32;
        let mut j = 0;
        while 5 * full + j < PACK_DEG {
            r.coeffs[5 * full + j] = c as u16;
            c = (c * 171) >> 9;
            j += 1;
        }
    }
    r.coeffs[N - 1] = 0;
    poly_mod_3_phi_n(r);
}

// ---- S_q packing: 12 bits per coefficient ---------------------------------
//
// Two 12-bit S_q coefficients pack into 3 bytes. PACK_DEG = 820 is even so
// no tail handling is needed.

fn poly_sq_tobytes(r: &mut [u8], a: &Poly) {
    debug_assert_eq!(r.len(), OWCPA_PUBLICKEYBYTES);
    for i in 0..PACK_DEG / 2 {
        let c0 = modq(a.coeffs[2 * i]);
        let c1 = modq(a.coeffs[2 * i + 1]);
        r[3 * i] = (c0 & 0xff) as u8;
        r[3 * i + 1] = ((c0 >> 8) | ((c1 & 0x0f) << 4)) as u8;
        r[3 * i + 2] = (c1 >> 4) as u8;
    }
}

fn poly_sq_frombytes(r: &mut Poly, a: &[u8]) {
    debug_assert!(a.len() >= OWCPA_PUBLICKEYBYTES);
    for i in 0..PACK_DEG / 2 {
        r.coeffs[2 * i] = (a[3 * i] as u16) | (((a[3 * i + 1] as u16) & 0x0f) << 8);
        r.coeffs[2 * i + 1] =
            ((a[3 * i + 1] as u16) >> 4) | (((a[3 * i + 2] as u16) & 0xff) << 4);
    }
    r.coeffs[N - 1] = 0;
}

fn poly_rq_sum_zero_tobytes(r: &mut [u8], a: &Poly) {
    poly_sq_tobytes(r, a);
}

fn poly_rq_sum_zero_frombytes(r: &mut Poly, a: &[u8]) {
    poly_sq_frombytes(r, a);
    // Restore r[N-1] so coefficient sum is zero mod q (the high bits of the
    // last byte of `a` are also asserted zero by owcpa_check_ciphertext).
    r.coeffs[N - 1] = 0;
    let mut acc: u16 = 0;
    for i in 0..PACK_DEG {
        acc = acc.wrapping_sub(r.coeffs[i]);
    }
    r.coeffs[N - 1] = acc;
}

// ---- IID-uniform-mod-3 sampler ---------------------------------------------
//
// Each input byte is reduced mod 3, giving Pr[0] = 86/256 and
// Pr[+1] = Pr[-1] = 85/256 — close enough to uniform for the spec's
// security analysis.

fn sample_iid(r: &mut Poly, uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_IID_BYTES);
    for i in 0..N - 1 {
        r.coeffs[i] = mod3(uniform_bytes[i] as u16);
    }
    r.coeffs[N - 1] = 0;
}

// ---- T_fixed sampler: tag-and-sort for uniform fixed-weight ternary ---------
//
// Tag the first WEIGHT/2 entries with +1 (low bits 01), the next WEIGHT/2
// with -1 (low bits 10), and the rest with 0; the high 30 bits of each tag
// are independent random bits drawn from the input stream. Sorting by full
// 32-bit tag value yields a uniform permutation of the assigned trinary
// labels into the output positions.

fn sample_fixed_type(r: &mut Poly, u: &[u8]) {
    debug_assert_eq!(u.len(), SAMPLE_FT_BYTES);
    let mut s = vec![0i32; N - 1];

    // The reference packs 30 bits per word from the byte stream, in groups
    // of four words per fifteen bytes.
    let blocks = (N - 1) / 4;
    for i in 0..blocks {
        let base = 15 * i;
        s[4 * i] = ((u[base] as i32) << 2)
            | ((u[base + 1] as i32) << 10)
            | ((u[base + 2] as i32) << 18)
            | ((u[base + 3] as u32 as i32) << 26);
        s[4 * i + 1] = (((u[base + 3] as i32) & 0xc0) >> 4)
            | ((u[base + 4] as i32) << 4)
            | ((u[base + 5] as i32) << 12)
            | ((u[base + 6] as i32) << 20)
            | ((u[base + 7] as u32 as i32) << 28);
        s[4 * i + 2] = (((u[base + 7] as i32) & 0xf0) >> 2)
            | ((u[base + 8] as i32) << 6)
            | ((u[base + 9] as i32) << 14)
            | ((u[base + 10] as i32) << 22)
            | ((u[base + 11] as u32 as i32) << 30);
        s[4 * i + 3] = ((u[base + 11] as i32) & 0xfc)
            | ((u[base + 12] as i32) << 8)
            | ((u[base + 13] as i32) << 16)
            | ((u[base + 14] as u32 as i32) << 24);
    }
    // Tail when (N - 1) is not a multiple of 4. For N = 821, (N-1) = 820 has
    // remainder 0, so the tail is empty — but leave the branch for clarity.
    if (N - 1) > blocks * 4 {
        let i = blocks;
        let base = 15 * i;
        s[4 * i] = ((u[base] as i32) << 2)
            | ((u[base + 1] as i32) << 10)
            | ((u[base + 2] as i32) << 18)
            | ((u[base + 3] as u32 as i32) << 26);
        s[4 * i + 1] = (((u[base + 3] as i32) & 0xc0) >> 4)
            | ((u[base + 4] as i32) << 4)
            | ((u[base + 5] as i32) << 12)
            | ((u[base + 6] as i32) << 20)
            | ((u[base + 7] as u32 as i32) << 28);
    }

    // Tag bottom two bits with the intended trinary value: half +1 (0b01),
    // half -1 (0b10 = 2 mod 4), rest 0.
    for i in 0..WEIGHT / 2 {
        s[i] |= 1;
    }
    for i in WEIGHT / 2..WEIGHT {
        s[i] |= 2;
    }

    crypto_sort_int32(&mut s);

    for i in 0..N - 1 {
        r.coeffs[i] = (s[i] & 3) as u16;
    }
    r.coeffs[N - 1] = 0;
}

fn sample_fg(f: &mut Poly, g: &mut Poly, uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_FG_BYTES);
    sample_iid(f, &uniform_bytes[..SAMPLE_IID_BYTES]);
    sample_fixed_type(g, &uniform_bytes[SAMPLE_IID_BYTES..]);
}

fn sample_rm(r: &mut Poly, m: &mut Poly, uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_RM_BYTES);
    sample_iid(r, &uniform_bytes[..SAMPLE_IID_BYTES]);
    sample_fixed_type(m, &uniform_bytes[SAMPLE_IID_BYTES..]);
}

// ---- OWCPA validity checks -------------------------------------------------

fn owcpa_check_ciphertext(ciphertext: &[u8]) -> i32 {
    // The tail byte has 8 - ((LOGQ * PACK_DEG) & 7) high bits of padding that
    // must be zero.
    let bits_used = (LOGQ * PACK_DEG) & 7;
    let mask: u16 = if bits_used == 0 {
        0
    } else {
        0xff << (8 - bits_used)
    };
    let t = (ciphertext[CIPHERTEXT_BYTES - 1] as u16) & mask;
    // Return 0 on success (t == 0), 1 on any non-zero bit.
    (1 & ((!t).wrapping_add(1) >> 15)) as i32
}

fn owcpa_check_r(r: &Poly) -> i32 {
    // Valid r has r[i] in {0, 1, q-1} and r[N-1] == 0.
    let mut t: u32 = 0;
    for i in 0..N - 1 {
        let c = r.coeffs[i];
        // c+1 in {0,1,2,3} <=> c in {-1, 0, 1, 2}; AND with (q-4) tests for
        // any out-of-range bit.
        t |= ((c.wrapping_add(1)) & (Q16.wrapping_sub(4))) as u32;
        // c+2 == 4 means c = 2; AND with 4 isolates that bit.
        t |= (c.wrapping_add(2) & 4) as u32;
    }
    t |= r.coeffs[N - 1] as u32;
    (1 & ((!t).wrapping_add(1) >> 31)) as i32
}

fn owcpa_check_m(m: &Poly) -> i32 {
    // m must be in S3 with weight WEIGHT, balanced +/- counts.
    let mut ps: u16 = 0;
    let mut ms: u16 = 0;
    for i in 0..N {
        ps = ps.wrapping_add(m.coeffs[i] & 1);
        ms = ms.wrapping_add(m.coeffs[i] & 2);
    }
    let mut t: u32 = 0;
    t |= (ps ^ (ms >> 1)) as u32;
    t |= (ms ^ (WEIGHT as u16)) as u32;
    (1 & ((!t).wrapping_add(1) >> 31)) as i32
}

// ---- OWCPA core: keygen, encrypt, decrypt ----------------------------------

fn owcpa_keypair(pk: &mut [u8], sk: &mut [u8], seed: &[u8]) {
    debug_assert_eq!(pk.len(), OWCPA_PUBLICKEYBYTES);
    debug_assert_eq!(sk.len(), OWCPA_SECRETKEYBYTES);
    debug_assert_eq!(seed.len(), SAMPLE_FG_BYTES);

    let mut f = Poly::zero();
    let mut g = Poly::zero();
    sample_fg(&mut f, &mut g, seed);

    let mut invf_mod3 = Poly::zero();
    poly_s3_inv(&mut invf_mod3, &f);
    poly_s3_tobytes(&mut sk[..PACK_TRINARY_BYTES], &f);
    poly_s3_tobytes(
        &mut sk[PACK_TRINARY_BYTES..2 * PACK_TRINARY_BYTES],
        &invf_mod3,
    );

    poly_z3_to_zq(&mut f);
    poly_z3_to_zq(&mut g);
    // HPS branch: g <- 3 * g (mod q)
    for i in 0..N {
        g.coeffs[i] = g.coeffs[i].wrapping_mul(3);
    }

    let mut gf = Poly::zero();
    poly_rq_mul(&mut gf, &g, &f);

    let mut invgf = Poly::zero();
    poly_rq_inv(&mut invgf, &gf);

    let mut tmp = Poly::zero();
    let mut invh = Poly::zero();
    poly_rq_mul(&mut tmp, &invgf, &f);
    poly_sq_mul(&mut invh, &tmp, &f);
    poly_sq_tobytes(&mut sk[2 * PACK_TRINARY_BYTES..], &invh);

    let mut h = Poly::zero();
    poly_rq_mul(&mut tmp, &invgf, &g);
    poly_rq_mul(&mut h, &tmp, &g);
    poly_rq_sum_zero_tobytes(pk, &h);
}

fn owcpa_enc(c: &mut [u8], r: &Poly, m: &Poly, pk: &[u8]) {
    debug_assert_eq!(c.len(), OWCPA_BYTES);
    debug_assert_eq!(pk.len(), OWCPA_PUBLICKEYBYTES);
    let mut h = Poly::zero();
    poly_rq_sum_zero_frombytes(&mut h, pk);

    let mut ct = Poly::zero();
    poly_rq_mul(&mut ct, r, &h);

    let mut liftm = Poly::zero();
    poly_lift(&mut liftm, m);
    for i in 0..N {
        ct.coeffs[i] = ct.coeffs[i].wrapping_add(liftm.coeffs[i]);
    }

    poly_rq_sum_zero_tobytes(c, &ct);
}

fn owcpa_dec(rm: &mut [u8], ciphertext: &[u8], secretkey: &[u8]) -> i32 {
    debug_assert_eq!(rm.len(), OWCPA_MSGBYTES);
    debug_assert_eq!(ciphertext.len(), CIPHERTEXT_BYTES);
    debug_assert_eq!(secretkey.len(), OWCPA_SECRETKEYBYTES);

    let mut c = Poly::zero();
    poly_rq_sum_zero_frombytes(&mut c, ciphertext);

    let mut f = Poly::zero();
    poly_s3_frombytes(&mut f, &secretkey[..PACK_TRINARY_BYTES]);
    poly_z3_to_zq(&mut f);

    let mut cf = Poly::zero();
    poly_rq_mul(&mut cf, &c, &f);

    let mut mf = Poly::zero();
    poly_rq_to_s3(&mut mf, &cf);

    let mut finv3 = Poly::zero();
    poly_s3_frombytes(&mut finv3, &secretkey[PACK_TRINARY_BYTES..2 * PACK_TRINARY_BYTES]);

    let mut m = Poly::zero();
    poly_s3_mul(&mut m, &mf, &finv3);
    poly_s3_tobytes(&mut rm[PACK_TRINARY_BYTES..], &m);

    let mut fail = 0i32;
    fail |= owcpa_check_ciphertext(ciphertext);
    fail |= owcpa_check_m(&m);

    // b = c - lift(m)
    let mut liftm = Poly::zero();
    poly_lift(&mut liftm, &m);
    let mut b = Poly::zero();
    for i in 0..N {
        b.coeffs[i] = c.coeffs[i].wrapping_sub(liftm.coeffs[i]);
    }

    // r = b / h mod (q, Phi_n)
    let mut invh = Poly::zero();
    poly_sq_frombytes(&mut invh, &secretkey[2 * PACK_TRINARY_BYTES..]);
    let mut r = Poly::zero();
    poly_sq_mul(&mut r, &b, &invh);

    fail |= owcpa_check_r(&r);

    poly_trinary_zq_to_z3(&mut r);
    poly_s3_tobytes(&mut rm[..PACK_TRINARY_BYTES], &r);

    fail
}

// ---- CCA KEM wrapper: SXY/Sch18 Fujisaki-Okamoto-style transform -----------

fn kem_keypair_seeded<R: Csprng>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
) {
    debug_assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
    debug_assert_eq!(sk.len(), PRIVATE_KEY_BYTES);

    let mut seed = vec![0u8; SAMPLE_FG_BYTES];
    rng.fill_bytes(&mut seed);
    owcpa_keypair(pk, &mut sk[..OWCPA_SECRETKEYBYTES], &seed);

    rng.fill_bytes(&mut sk[OWCPA_SECRETKEYBYTES..]);
}

fn kem_enc_seeded<R: Csprng>(
    c: &mut [u8; CIPHERTEXT_BYTES],
    k: &mut [u8; SHARED_SECRET_BYTES],
    pk: &[u8; PUBLIC_KEY_BYTES],
    rng: &mut R,
) {
    let mut rm_seed = vec![0u8; SAMPLE_RM_BYTES];
    rng.fill_bytes(&mut rm_seed);

    let mut r = Poly::zero();
    let mut m = Poly::zero();
    sample_rm(&mut r, &mut m, &rm_seed);

    let mut rm = [0u8; OWCPA_MSGBYTES];
    poly_s3_tobytes(&mut rm[..PACK_TRINARY_BYTES], &r);
    poly_s3_tobytes(&mut rm[PACK_TRINARY_BYTES..], &m);

    let digest = Sha3_256::new().chain(&rm).finalize();
    k.copy_from_slice(&digest);

    poly_z3_to_zq(&mut r);
    owcpa_enc(c, &r, &m, pk);
}

fn kem_dec(
    k: &mut [u8; SHARED_SECRET_BYTES],
    c: &[u8; CIPHERTEXT_BYTES],
    sk: &[u8; PRIVATE_KEY_BYTES],
) {
    let mut rm = [0u8; OWCPA_MSGBYTES];
    let fail = owcpa_dec(&mut rm, c, &sk[..OWCPA_SECRETKEYBYTES]);

    let digest = Sha3_256::new().chain(&rm).finalize();
    k.copy_from_slice(&digest);

    // Implicit-rejection key: SHA3-256(prf || c)
    let mut buf = [0u8; PRFKEYBYTES + CIPHERTEXT_BYTES];
    buf[..PRFKEYBYTES].copy_from_slice(&sk[OWCPA_SECRETKEYBYTES..]);
    buf[PRFKEYBYTES..].copy_from_slice(c);
    let reject = Sha3_256::new().chain(&buf).finalize();

    cmov(k, &reject, fail as u8);
}

// ---- public API -------------------------------------------------------------

/// NTRU-HPS-4096-821 public key.
#[derive(Clone, Eq, PartialEq)]
pub struct NtruHps821PublicKey {
    bytes: [u8; PUBLIC_KEY_BYTES],
}

/// NTRU-HPS-4096-821 private key.
///
/// Includes the implicit-rejection PRF key in the trailing 32 bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct NtruHps821PrivateKey {
    bytes: [u8; PRIVATE_KEY_BYTES],
}

/// NTRU-HPS-4096-821 ciphertext.
#[derive(Clone, Eq, PartialEq)]
pub struct NtruHps821Ciphertext {
    bytes: [u8; CIPHERTEXT_BYTES],
}

/// NTRU-HPS-4096-821 shared secret (32 bytes).
#[derive(Clone, Eq, PartialEq)]
pub struct NtruHps821SharedSecret {
    bytes: [u8; SHARED_SECRET_BYTES],
}

impl NtruHps821PublicKey {
    /// Decode a public key from its canonical wire bytes.
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return None;
        }
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        out.copy_from_slice(bytes);
        Some(Self { bytes: out })
    }

    /// Wire-byte encoding of the public key.
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.bytes
    }

    /// Borrow the wire bytes without copying.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.bytes
    }
}

impl NtruHps821PrivateKey {
    /// Decode a private key from its canonical wire bytes.
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PRIVATE_KEY_BYTES {
            return None;
        }
        let mut out = [0u8; PRIVATE_KEY_BYTES];
        out.copy_from_slice(bytes);
        Some(Self { bytes: out })
    }

    /// Wire-byte encoding of the private key.
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; PRIVATE_KEY_BYTES] {
        self.bytes
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_BYTES] {
        &self.bytes
    }
}

impl NtruHps821Ciphertext {
    /// Decode a ciphertext from its canonical wire bytes.
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return None;
        }
        let mut out = [0u8; CIPHERTEXT_BYTES];
        out.copy_from_slice(bytes);
        Some(Self { bytes: out })
    }

    /// Wire-byte encoding of the ciphertext.
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        self.bytes
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
        &self.bytes
    }
}

impl NtruHps821SharedSecret {
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; SHARED_SECRET_BYTES] {
        self.bytes
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for NtruHps821PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NtruHps821PrivateKey(<redacted>)")
    }
}

impl fmt::Debug for NtruHps821SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NtruHps821SharedSecret(<redacted>)")
    }
}

impl fmt::Debug for NtruHps821PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtruHps821PublicKey").finish()
    }
}

impl fmt::Debug for NtruHps821Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtruHps821Ciphertext").finish()
    }
}

/// Namespace for NTRU-HPS-4096-821 KEM operations.
pub struct NtruHps821;

impl NtruHps821 {
    /// Generate a key pair using `rng` for both the `(f, g)` seed and the
    /// implicit-rejection PRF key.
    pub fn keygen<R: Csprng>(rng: &mut R) -> (NtruHps821PublicKey, NtruHps821PrivateKey) {
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; PRIVATE_KEY_BYTES];
        kem_keypair_seeded(&mut pk, &mut sk, rng);
        (
            NtruHps821PublicKey { bytes: pk },
            NtruHps821PrivateKey { bytes: sk },
        )
    }

    /// Encapsulate a fresh shared secret against `pk`.
    pub fn encaps<R: Csprng>(
        pk: &NtruHps821PublicKey,
        rng: &mut R,
    ) -> (NtruHps821Ciphertext, NtruHps821SharedSecret) {
        let mut ct = [0u8; CIPHERTEXT_BYTES];
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        kem_enc_seeded(&mut ct, &mut ss, &pk.bytes, rng);
        (
            NtruHps821Ciphertext { bytes: ct },
            NtruHps821SharedSecret { bytes: ss },
        )
    }

    /// Decapsulate `ct` against `sk`. Returns the same shared secret as the
    /// encapsulator on success and a deterministic implicit-rejection value
    /// otherwise.
    pub fn decaps(
        sk: &NtruHps821PrivateKey,
        ct: &NtruHps821Ciphertext,
    ) -> NtruHps821SharedSecret {
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        kem_dec(&mut ss, &ct.bytes, &sk.bytes);
        NtruHps821SharedSecret { bytes: ss }
    }
}

// ---- helper Sha3_256 chain (round-3 reference uses one-shot hash) ---------

trait DigestChain: Digest + Sized {
    fn chain(self, data: &[u8]) -> Self {
        let mut me = self;
        me.update(data);
        me
    }
}

impl<D: Digest> DigestChain for D {}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::CtrDrbgAes256;



    #[test]
    fn parameter_byte_lengths() {
        assert_eq!(PUBLIC_KEY_BYTES, 1230);
        assert_eq!(PRIVATE_KEY_BYTES, 1590);
        assert_eq!(CIPHERTEXT_BYTES, 1230);
        assert_eq!(SHARED_SECRET_BYTES, 32);
        assert_eq!(SAMPLE_FG_BYTES, 3895);
        assert_eq!(SAMPLE_FT_BYTES, 3075);
        assert_eq!(PACK_TRINARY_BYTES, 164);
        assert_eq!(WEIGHT, 510);
    }

    #[test]
    fn roundtrip_random() {
        let mut drbg = CtrDrbgAes256::new(&[0x42u8; 48]);
        let (pk, sk) = NtruHps821::keygen(&mut drbg);
        let (ct, ss_a) = NtruHps821::encaps(&pk, &mut drbg);
        let ss_b = NtruHps821::decaps(&sk, &ct);
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn roundtrip_multiple_seeds() {
        for seed in [0x00u8, 0x55, 0xaa, 0xff] {
            let mut drbg = CtrDrbgAes256::new(&[seed; 48]);
            let (pk, sk) = NtruHps821::keygen(&mut drbg);
            let (ct, ss_a) = NtruHps821::encaps(&pk, &mut drbg);
            let ss_b = NtruHps821::decaps(&sk, &ct);
            assert_eq!(
                ss_a.as_bytes(),
                ss_b.as_bytes(),
                "seed byte 0x{seed:02x}"
            );
        }
    }

    #[test]
    fn implicit_rejection_on_corrupted_ciphertext() {
        let mut drbg = CtrDrbgAes256::new(&[0x99u8; 48]);
        let (pk, sk) = NtruHps821::keygen(&mut drbg);
        let (ct, ss_a) = NtruHps821::encaps(&pk, &mut drbg);
        let mut bad = ct.to_wire_bytes();
        bad[0] ^= 0x01;
        let bad_ct = NtruHps821Ciphertext::from_wire_bytes(&bad).unwrap();
        let ss_bad = NtruHps821::decaps(&sk, &bad_ct);
        assert_ne!(ss_bad.as_bytes(), ss_a.as_bytes());
        // Implicit rejection is deterministic for a fixed (sk, ct).
        let ss_bad2 = NtruHps821::decaps(&sk, &bad_ct);
        assert_eq!(ss_bad.as_bytes(), ss_bad2.as_bytes());
    }

    #[test]
    fn wire_format_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0x21u8; 48]);
        let (pk, sk) = NtruHps821::keygen(&mut drbg);
        let (ct, _) = NtruHps821::encaps(&pk, &mut drbg);
        let pk_bytes = pk.to_wire_bytes();
        let sk_bytes = sk.to_wire_bytes();
        let ct_bytes = ct.to_wire_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_BYTES);
        assert_eq!(sk_bytes.len(), PRIVATE_KEY_BYTES);
        assert_eq!(ct_bytes.len(), CIPHERTEXT_BYTES);
        let pk2 = NtruHps821PublicKey::from_wire_bytes(&pk_bytes).unwrap();
        let sk2 = NtruHps821PrivateKey::from_wire_bytes(&sk_bytes).unwrap();
        let ct2 = NtruHps821Ciphertext::from_wire_bytes(&ct_bytes).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk, sk2);
        assert_eq!(ct, ct2);
    }

    /// Validates a sampled subset of the 100 entries in
    /// `KAT/ntruhps4096821/PQCkemKAT_1590.rsp` (round 3, 2020-10-16).
    /// See [`nist_kat_full`] for the full sweep.
    #[test]
    fn nist_kat_sampled_counts() {
        let rsp = include_str!(
            "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps4096821/PQCkemKAT_1590.rsp"
        );
        for &count in crate::public_key::ntru_pqc_shared::KAT_SAMPLED_COUNTS {
            run_kat_count(rsp, count);
        }
    }

    #[test]
    #[ignore]
    fn nist_kat_full() {
        let rsp = include_str!(
            "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps4096821/PQCkemKAT_1590.rsp"
        );
        for count in 0..100 {
            run_kat_count(rsp, count);
        }
    }

    fn run_kat_count(rsp: &str, count: usize) {
        let entry = crate::public_key::ntru_pqc_shared::parse_kat_entry(rsp, count)
            .unwrap_or_else(|| panic!("KAT count={count} missing"));
        assert_eq!(entry.seed.len(), 48, "seed length");
        let mut seed = [0u8; 48];
        seed.copy_from_slice(&entry.seed);
        let mut drbg = CtrDrbgAes256::new(&seed);

        let (pk, sk) = NtruHps821::keygen(&mut drbg);
        assert_eq!(pk.to_wire_bytes().as_slice(), entry.pk.as_slice(), "pk @ count={count}");
        assert_eq!(sk.to_wire_bytes().as_slice(), entry.sk.as_slice(), "sk @ count={count}");

        let (ct, ss) = NtruHps821::encaps(&pk, &mut drbg);
        assert_eq!(ct.to_wire_bytes().as_slice(), entry.ct.as_slice(), "ct @ count={count}");
        assert_eq!(ss.to_wire_bytes().as_slice(), entry.ss.as_slice(), "ss @ count={count}");

        let ss2 = NtruHps821::decaps(&sk, &ct);
        assert_eq!(ss.as_bytes(), ss2.as_bytes(), "decaps @ count={count}");
    }
}
