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
    cmov, DigestChain,
    kem_dec as shared_kem_dec,
    owcpa_check_ciphertext as shared_owcpa_check_ciphertext,
    owcpa_check_m as shared_owcpa_check_m,
    owcpa_check_r as shared_owcpa_check_r,
    poly_lift_hps as shared_poly_lift_hps,
    poly_rq_inv as shared_poly_rq_inv,
    poly_rq_mul as shared_poly_rq_mul,
    poly_rq_sum_zero_adjust as shared_poly_rq_sum_zero_adjust,
    poly_rq_to_s3 as shared_poly_rq_to_s3,
    poly_s3_frombytes as shared_poly_s3_frombytes,
    poly_s3_inv as shared_poly_s3_inv,
    poly_s3_mul as shared_poly_s3_mul,
    poly_s3_tobytes as shared_poly_s3_tobytes,
    poly_sq_frombytes_logq12 as shared_poly_sq_frombytes_logq12,
    poly_sq_mul as shared_poly_sq_mul,
    poly_sq_tobytes_logq12 as shared_poly_sq_tobytes_logq12,
    poly_trinary_zq_to_z3 as shared_poly_trinary_zq_to_z3,
    poly_z3_to_zq as shared_poly_z3_to_zq,
    sample_fixed_type as shared_sample_fixed_type,
    sample_iid as shared_sample_iid,
};




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

fn poly_lift(r: &mut Poly, a: &Poly) { shared_poly_lift_hps::<N>(&mut r.coeffs, &a.coeffs, Q_MASK); }

// ---- constant-time inverse in R_2 = F_2[x] / (x^N - 1) ---------------------
//
// Bernstein and Yang's constant-time gcd recursion (TCHES 2019, "Fast
// constant-time gcd computation and modular inversion"): a swap-and-shift
// loop on (f, g) over F_2[x] that converges to (gcd, 0) while threading
// (v, w) so v · a ≡ gcd (mod x^N - 1) at exit. The 2(N-1)-1 iteration count
// is the worst-case bound from the cited paper.


// ---- constant-time inverse in S_3 = F_3[x] / Phi_n(x) ----------------------
//
// Same Bernstein–Yang gcd recursion as poly_r2_inv but over F_3 instead of
// F_2. mod3_u8 keeps coefficients canonical after every step.

fn poly_s3_inv(r: &mut Poly, a: &Poly) { shared_poly_s3_inv::<N>(&mut r.coeffs, &a.coeffs); }

// ---- inverse in R_q = Z_q[x] / (x^N - 1) via Hensel lift from R_2 ----------
//
// Standard Newton-style 2-adic lift: given a · b ≡ 1 (mod 2^k), the update
// b ← b · (2 - a · b) doubles the precision to (mod 2^{2k}). Four lift
// iterations carry an R_2 inverse to precision 2^16, which subsumes the
// largest q in this NTRU family (q = 8192 = 2^13). All arithmetic is u16
// wrapping; the final mod-q reduction happens at use sites.


fn poly_rq_inv(r: &mut Poly, a: &Poly) { shared_poly_rq_inv::<N>(&mut r.coeffs, &a.coeffs); }

// ---- S_3 packing: 5 trits per byte in base 3 -------------------------------

fn poly_s3_tobytes(msg: &mut [u8], a: &Poly) { shared_poly_s3_tobytes::<N>(msg, &a.coeffs); }

fn poly_s3_frombytes(r: &mut Poly, msg: &[u8]) { shared_poly_s3_frombytes::<N>(&mut r.coeffs, msg); }

// ---- S_q packing: 12 bits per coefficient ---------------------------------
//
// Two 12-bit S_q coefficients pack into 3 bytes. PACK_DEG = 820 is even so
// no tail handling is needed.

fn poly_sq_tobytes(r: &mut [u8], a: &Poly) { shared_poly_sq_tobytes_logq12::<N>(r, &a.coeffs); }

fn poly_sq_frombytes(r: &mut Poly, a: &[u8]) { shared_poly_sq_frombytes_logq12::<N>(&mut r.coeffs, a); }

fn poly_rq_sum_zero_tobytes(r: &mut [u8], a: &Poly) {
    poly_sq_tobytes(r, a);
}

fn poly_rq_sum_zero_frombytes(r: &mut Poly, a: &[u8]) {
    poly_sq_frombytes(r, a);
    shared_poly_rq_sum_zero_adjust::<N>(&mut r.coeffs);
}

// ---- IID-uniform-mod-3 sampler ---------------------------------------------
//
// Each input byte is reduced mod 3, giving Pr[0] = 86/256 and
// Pr[+1] = Pr[-1] = 85/256 — close enough to uniform for the spec's
// security analysis.

fn sample_iid(r: &mut Poly, uniform_bytes: &[u8]) { shared_sample_iid::<N>(&mut r.coeffs, uniform_bytes); }

// ---- T_fixed sampler: tag-and-sort for uniform fixed-weight ternary ---------
//
// Tag the first WEIGHT/2 entries with +1 (low bits 01), the next WEIGHT/2
// with -1 (low bits 10), and the rest with 0; the high 30 bits of each tag
// are independent random bits drawn from the input stream. Sorting by full
// 32-bit tag value yields a uniform permutation of the assigned trinary
// labels into the output positions.

fn sample_fixed_type(r: &mut Poly, u: &[u8]) { shared_sample_fixed_type::<N>(&mut r.coeffs, u, WEIGHT); }

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
    shared_owcpa_check_ciphertext::<N, LOGQ>(ciphertext)
}

fn owcpa_check_r(r: &Poly) -> i32 {
    shared_owcpa_check_r::<N, LOGQ>(&r.coeffs)
}

fn owcpa_check_m(m: &Poly) -> i32 {
    shared_owcpa_check_m::<N>(&m.coeffs, WEIGHT)
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
    shared_kem_dec(k, c, sk, OWCPA_MSGBYTES, OWCPA_SECRETKEYBYTES, owcpa_dec);
}


// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHps821,
    public_key = NtruHps821PublicKey,
    private_key = NtruHps821PrivateKey,
    ciphertext = NtruHps821Ciphertext,
    shared_secret = NtruHps821SharedSecret,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps4096821/PQCkemKAT_1590.rsp",
}
