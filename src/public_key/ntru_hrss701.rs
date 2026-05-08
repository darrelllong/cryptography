//! NTRU-HRSS-701 implemented in safe, idiomatic Rust from the round-3 NTRU
//! specification (Chen, Chung, Hülsing, Lange, Lyubashevsky, Saito, Schanck,
//! Schwabe, Stehlé, Whyte, Xagawa, Yamakawa, Zhang; NIST PQC, 2020-10-16).
//!
//! This module provides:
//! - the HRSS-701 parameter set ($N = 701$, $q = 8192$)
//! - key generation, encapsulation, decapsulation (CCA KEM)
//! - strict wire-format byte encodings for `pk`, `sk`, `ct`, `ss`
//!
//! Differences from the HPS family (see [`crate::public_key::ntru_hps509`]):
//! - both `f` and `g` are drawn from the `Sample_iid_plus` distribution
//!   (sample IID, then conditionally negate even-indexed coefficients so
//!   that `<x · r, r> >= 0`); HPS uses fixed-weight sampling for `g`.
//! - the secret-key formula uses `g <- 3 · (x - 1) · g` instead of the HPS
//!   `g <- 3 · g`; correspondingly `lift(m) = ((m / (x - 1)) mod (3, Phi_n))
//!   · (x - 1)` rather than the trivial Z_3 → Z_q embedding.
//! - the message-space check on `m` is dropped; any element of `S_3` is a
//!   valid HRSS message.
//! - $q = 8192$ selects a 13-bit-per-coefficient `Sq` packing.
//!
//! Inversion in `R_2` and `S_3` follows Bernstein and Yang (TCHES 2019);
//! SHA3-256 and AES-256 CTR-DRBG come from this crate's `hash` and `cprng`
//! modules; no C/FFI backends are used.
//!
//! Validation:
//! the `count = 0` entry of the round-3 KAT `PQCkemKAT_1450.rsp` is
//! reproduced byte-for-byte by the inline test.
//!
//! Side channels:
//! the constant-time Bernstein–Yang inverters, the Batcher fixed-weight
//! sort (HPS only), `cmov`, and the SHA3 / CTR-DRBG implementations are all
//! data-independent. The polynomial multiplier in
//! [`crate::public_key::ntru_poly_mul`] is *not*: its schoolbook base case
//! has an early-`continue` on zero coefficients, which leaks the zero
//! pattern of the secret operands `f`, `r`, and `m` whenever they pass
//! through it. The module is exposed under [`crate::vt`] for that reason.



use crate::hash::sha3::Sha3_256;
use crate::Csprng;

// ---- parameter constants ---------------------------------------------------

const N: usize = 701;
const LOGQ: usize = 13;
const Q: u32 = 1 << LOGQ;
const Q16: u16 = Q as u16;
const Q_MASK: u16 = (Q as u16).wrapping_sub(1);

const PRFKEYBYTES: usize = 32;
const SHAREDKEYBYTES: usize = 32;

const SAMPLE_IID_BYTES: usize = N - 1; // 700
const SAMPLE_FG_BYTES: usize = 2 * SAMPLE_IID_BYTES; // 1400
const SAMPLE_RM_BYTES: usize = 2 * SAMPLE_IID_BYTES; // 1400

const PACK_DEG: usize = N - 1; // 700
const PACK_TRINARY_BYTES: usize = (PACK_DEG + 4) / 5; // 140

const OWCPA_MSGBYTES: usize = 2 * PACK_TRINARY_BYTES; // 280
const OWCPA_PUBLICKEYBYTES: usize = (LOGQ * PACK_DEG + 7) / 8; // 1138
const OWCPA_SECRETKEYBYTES: usize = 2 * PACK_TRINARY_BYTES + OWCPA_PUBLICKEYBYTES; // 1418
const OWCPA_BYTES: usize = (LOGQ * PACK_DEG + 7) / 8; // 1138

/// Public-key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = OWCPA_PUBLICKEYBYTES; // 1138
/// Private-key length in bytes (includes implicit-rejection PRF key).
pub const PRIVATE_KEY_BYTES: usize = OWCPA_SECRETKEYBYTES + PRFKEYBYTES; // 1450
/// Ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = OWCPA_BYTES; // 1138
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
    cmov, mod3, DigestChain,
    poly_mod_3_phi_n as shared_poly_mod_3_phi_n,
    poly_mod_q_phi_n as shared_poly_mod_q_phi_n,
    poly_r2_inv as shared_poly_r2_inv,
    poly_r2_inv_to_rq_inv as shared_poly_r2_inv_to_rq_inv,
    poly_rq_inv as shared_poly_rq_inv,
    poly_rq_mul as shared_poly_rq_mul,
    poly_rq_to_s3 as shared_poly_rq_to_s3,
    poly_s3_frombytes as shared_poly_s3_frombytes,
    poly_s3_inv as shared_poly_s3_inv,
    poly_s3_mul as shared_poly_s3_mul,
    poly_s3_tobytes as shared_poly_s3_tobytes,
    poly_sq_frombytes_logq13 as shared_poly_sq_frombytes_logq13,
    poly_sq_mul as shared_poly_sq_mul,
    poly_sq_tobytes_logq13 as shared_poly_sq_tobytes_logq13,
    poly_trinary_zq_to_z3 as shared_poly_trinary_zq_to_z3,
    poly_z3_to_zq as shared_poly_z3_to_zq,
};

#[inline(always)]
fn modq(x: u16) -> u16 {
    x & Q_MASK
}

fn poly_mod_3_phi_n(r: &mut Poly) { shared_poly_mod_3_phi_n::<N>(&mut r.coeffs); }

fn poly_mod_q_phi_n(r: &mut Poly) { shared_poly_mod_q_phi_n::<N>(&mut r.coeffs); }

// ---- Z3 <-> Zq coefficient remapping ---------------------------------------

fn poly_z3_to_zq(r: &mut Poly) { shared_poly_z3_to_zq::<N>(&mut r.coeffs, Q_MASK); }

fn poly_trinary_zq_to_z3(r: &mut Poly) { shared_poly_trinary_zq_to_z3::<N, LOGQ>(&mut r.coeffs); }

// ---- multiplication in R_q -------------------------------------------------

fn poly_rq_mul(r: &mut Poly, a: &Poly, b: &Poly) { shared_poly_rq_mul::<N>(&mut r.coeffs, &a.coeffs, &b.coeffs); }

fn poly_sq_mul(r: &mut Poly, a: &Poly, b: &Poly) { shared_poly_sq_mul::<N>(&mut r.coeffs, &a.coeffs, &b.coeffs); }

fn poly_s3_mul(r: &mut Poly, a: &Poly, b: &Poly) { shared_poly_s3_mul::<N>(&mut r.coeffs, &a.coeffs, &b.coeffs); }

// ---- Rq -> S3 coefficient projection ---------------------------------------

fn poly_rq_to_s3(r: &mut Poly, a: &Poly) { shared_poly_rq_to_s3::<N, LOGQ>(&mut r.coeffs, &a.coeffs); }

// ---- lift(m) for HPS: trivial Z_3 -> Z_q embedding -------------------------

fn poly_lift(r: &mut Poly, a: &Poly) {
    // HRSS lift: compute b = a / (x - 1) mod (3, Phi_n) and then r = (x-1)*b.
    //
    // Define z by <z * x^i, x - 1> = delta_{i,0} mod 3:
    //   t      = -1/N mod 3 = -N mod 3 = 3 - (N mod 3)
    //   z[0]   = 2 - t mod 3
    //   z[1]   = 0   mod 3
    //   z[j]   = z[j-1] + t mod 3
    // Then b[k] = <z * x^k, a>.
    let t: u16 = (3 - (N % 3)) as u16;

    let mut b = Poly::zero();
    b.coeffs[0] = a.coeffs[0]
        .wrapping_mul(2u16.wrapping_sub(t))
        .wrapping_add(a.coeffs[1].wrapping_mul(0))
        .wrapping_add(a.coeffs[2].wrapping_mul(t));
    b.coeffs[1] = a.coeffs[1]
        .wrapping_mul(2u16.wrapping_sub(t))
        .wrapping_add(a.coeffs[2].wrapping_mul(0));
    b.coeffs[2] = a.coeffs[2].wrapping_mul(2u16.wrapping_sub(t));

    let mut zj: u16 = 0; // z[1]
    for i in 3..N {
        b.coeffs[0] = b.coeffs[0].wrapping_add(a.coeffs[i].wrapping_mul(zj.wrapping_add(2 * t)));
        b.coeffs[1] = b.coeffs[1].wrapping_add(a.coeffs[i].wrapping_mul(zj.wrapping_add(t)));
        b.coeffs[2] = b.coeffs[2].wrapping_add(a.coeffs[i].wrapping_mul(zj));
        zj = (zj.wrapping_add(t)) % 3;
    }
    b.coeffs[1] = b.coeffs[1].wrapping_add(a.coeffs[0].wrapping_mul(zj.wrapping_add(t)));
    b.coeffs[2] = b.coeffs[2].wrapping_add(a.coeffs[0].wrapping_mul(zj));
    b.coeffs[2] = b.coeffs[2].wrapping_add(a.coeffs[1].wrapping_mul(zj.wrapping_add(t)));

    for i in 3..N {
        b.coeffs[i] = b.coeffs[i - 3].wrapping_add(
            2u16.wrapping_mul(
                a.coeffs[i]
                    .wrapping_add(a.coeffs[i - 1])
                    .wrapping_add(a.coeffs[i - 2]),
            ),
        );
    }

    poly_mod_3_phi_n(&mut b);
    poly_z3_to_zq(&mut b);

    // r := (x - 1) * b
    r.coeffs[0] = 0u16.wrapping_sub(b.coeffs[0]);
    for i in 0..N - 1 {
        r.coeffs[i + 1] = b.coeffs[i].wrapping_sub(b.coeffs[i + 1]);
    }
}

// ---- constant-time inverse in R_2 = F_2[x] / (x^N - 1) ---------------------
//
// Bernstein and Yang's constant-time gcd recursion (TCHES 2019, "Fast
// constant-time gcd computation and modular inversion"): a swap-and-shift
// loop on (f, g) over F_2[x] that converges to (gcd, 0) while threading
// (v, w) so v · a ≡ gcd (mod x^N - 1) at exit. The 2(N-1)-1 iteration count
// is the worst-case bound from the cited paper.

fn poly_r2_inv(r: &mut Poly, a: &Poly) { shared_poly_r2_inv::<N>(&mut r.coeffs, &a.coeffs); }

// ---- constant-time inverse in S_3 = F_3[x] / Phi_n(x) ----------------------
//
// Same Bernstein–Yang gcd recursion as poly_r2_inv but over F_3 instead of
// F_2. `mod3_u8` (in `ntru_pqc_shared`) keeps coefficients canonical
// after every step.

fn poly_s3_inv(r: &mut Poly, a: &Poly) { shared_poly_s3_inv::<N>(&mut r.coeffs, &a.coeffs); }

// ---- inverse in R_q = Z_q[x] / (x^N - 1) via Hensel lift from R_2 ----------
//
// Standard Newton-style 2-adic lift: given a · b ≡ 1 (mod 2^k), the update
// b ← b · (2 - a · b) doubles the precision to (mod 2^{2k}). Four lift
// iterations carry an R_2 inverse to precision 2^16, which subsumes the
// largest q in this NTRU family (q = 8192 = 2^13). All arithmetic is u16
// wrapping; the final mod-q reduction happens at use sites.

fn poly_r2_inv_to_rq_inv(r: &mut Poly, ai: &Poly, a: &Poly) { shared_poly_r2_inv_to_rq_inv::<N>(&mut r.coeffs, &ai.coeffs, &a.coeffs); }

fn poly_rq_inv(r: &mut Poly, a: &Poly) { shared_poly_rq_inv::<N>(&mut r.coeffs, &a.coeffs); }

// ---- S_3 packing: 5 trits per byte in base 3 -------------------------------

fn poly_s3_tobytes(msg: &mut [u8], a: &Poly) { shared_poly_s3_tobytes::<N>(msg, &a.coeffs); }

fn poly_s3_frombytes(r: &mut Poly, msg: &[u8]) { shared_poly_s3_frombytes::<N>(&mut r.coeffs, msg); }

// ---- S_q packing: 11 bits per coefficient ---------------------------------
//
// Eight 11-bit S_q coefficients pack into 11 bytes. The remainder of
// PACK_DEG mod 8 is handled by the trailing match arms.

fn poly_sq_tobytes(r: &mut [u8], a: &Poly) { shared_poly_sq_tobytes_logq13::<N>(r, &a.coeffs); }

fn poly_sq_frombytes(r: &mut Poly, a: &[u8]) { shared_poly_sq_frombytes_logq13::<N>(&mut r.coeffs, a); }

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

// ---- HRSS Sample_iid_plus distribution -------------------------------------
//
// Sample r via the IID-uniform-mod-3 distribution, then conditionally
// negate the even-indexed coefficients so that <x · r, r> >= 0. This is the
// only sampling distribution HRSS uses (replacing the HPS mix of IID for f
// and fixed-weight for g/m).

fn sample_iid_plus(r: &mut Poly, uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_IID_BYTES);
    sample_iid(r, uniform_bytes);

    // Map {0, 1, 2} -> {0, 1, 2^16 - 1}
    for i in 0..N - 1 {
        let c = r.coeffs[i];
        r.coeffs[i] = c | (0u16.wrapping_sub(c >> 1));
    }

    // s = <x * r, r>; r[N-1] is zero.
    let mut s: u16 = 0;
    for i in 0..N - 1 {
        s = s.wrapping_add(
            ((r.coeffs[i + 1] as u32).wrapping_mul(r.coeffs[i] as u32)) as u16,
        );
    }

    // sign(s) — sign(0) = 1; the C uses `1 | (-(s>>15))`.
    let s_sign: u16 = 1 | 0u16.wrapping_sub(s >> 15);

    let mut i = 0;
    while i < N {
        r.coeffs[i] = ((s_sign as u32).wrapping_mul(r.coeffs[i] as u32)) as u16;
        i += 2;
    }

    // Map {0, 1, 2^16-1} -> {0, 1, 2}
    for i in 0..N {
        r.coeffs[i] = 3 & (r.coeffs[i] ^ (r.coeffs[i] >> 15));
    }
}

fn sample_fg(f: &mut Poly, g: &mut Poly, uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_FG_BYTES);
    sample_iid_plus(f, &uniform_bytes[..SAMPLE_IID_BYTES]);
    sample_iid_plus(g, &uniform_bytes[SAMPLE_IID_BYTES..]);
}

fn sample_rm(r: &mut Poly, m: &mut Poly, uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_RM_BYTES);
    sample_iid(r, &uniform_bytes[..SAMPLE_IID_BYTES]);
    sample_iid(m, &uniform_bytes[SAMPLE_IID_BYTES..]);
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
    // HRSS branch: g <- 3 * (x - 1) * g  (mod q)
    for i in (1..N).rev() {
        g.coeffs[i] = (3u16).wrapping_mul(g.coeffs[i - 1].wrapping_sub(g.coeffs[i]));
    }
    g.coeffs[0] = 0u16.wrapping_sub((3u16).wrapping_mul(g.coeffs[0]));

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
    // HRSS does not check m: any element of S3 is a valid message.

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

    let reject = Sha3_256::new()
        .chain(&sk[OWCPA_SECRETKEYBYTES..])
        .chain(c)
        .finalize();

    cmov(k, &reject, fail as u8);
}


// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHrss701,
    public_key = NtruHrss701PublicKey,
    private_key = NtruHrss701PrivateKey,
    ciphertext = NtruHrss701Ciphertext,
    shared_secret = NtruHrss701SharedSecret,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhrss701/PQCkemKAT_1450.rsp",
}
