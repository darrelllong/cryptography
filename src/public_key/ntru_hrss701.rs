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
//! Side channels: see [`crate::public_key::ntru_pqc_shared`]. HRSS-701
//! uses iid-only sampling, so the Batcher fixed-weight sort referenced
//! there is not on its hot path.




// ---- parameter constants ---------------------------------------------------

const N: usize = 701;
const LOGQ: usize = 13;
const Q: u32 = 1 << LOGQ;
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

// ---- lift(m) for HRSS: (x - 1) * (a / (x - 1) mod (3, Phi_n)) --------------

fn poly_lift_hrss(r: &mut [u16; N], a: &[u16; N]) {
    // HRSS lift: compute b = a / (x - 1) mod (3, Phi_n) and then r = (x-1)*b.
    //
    // Define z by <z * x^i, x - 1> = delta_{i,0} mod 3:
    //   t      = -1/N mod 3 = -N mod 3 = 3 - (N mod 3)
    //   z[0]   = 2 - t mod 3
    //   z[1]   = 0   mod 3
    //   z[j]   = z[j-1] + t mod 3
    // Then b[k] = <z * x^k, a>.
    let t: u16 = (3 - (N % 3)) as u16;

    // z[1] = 0 (drops the a[1]·0 and a[2]·0 cross-terms in b[0]/b[1]).
    let mut b = [0u16; N];
    b[0] = a[0]
        .wrapping_mul(2u16.wrapping_sub(t))
        .wrapping_add(a[2].wrapping_mul(t));
    b[1] = a[1].wrapping_mul(2u16.wrapping_sub(t));
    b[2] = a[2].wrapping_mul(2u16.wrapping_sub(t));

    let mut zj: u16 = 0; // z[1]
    for i in 3..N {
        b[0] = b[0].wrapping_add(a[i].wrapping_mul(zj.wrapping_add(2 * t)));
        b[1] = b[1].wrapping_add(a[i].wrapping_mul(zj.wrapping_add(t)));
        b[2] = b[2].wrapping_add(a[i].wrapping_mul(zj));
        // `t` and `zj` are public constants of the loop iteration, so a
        // hardware modulo is fine here; the rest of the file routes
        // mod-3 reductions through `crate::public_key::ntru_pqc_shared::mod3`
        // because they take secret-derived inputs.
        zj = (zj.wrapping_add(t)) % 3;
    }
    b[1] = b[1].wrapping_add(a[0].wrapping_mul(zj.wrapping_add(t)));
    b[2] = b[2].wrapping_add(a[0].wrapping_mul(zj));
    b[2] = b[2].wrapping_add(a[1].wrapping_mul(zj.wrapping_add(t)));

    for i in 3..N {
        b[i] = b[i - 3].wrapping_add(
            2u16.wrapping_mul(a[i].wrapping_add(a[i - 1]).wrapping_add(a[i - 2])),
        );
    }

    crate::public_key::ntru_pqc_shared::poly_mod_3_phi_n::<N>(&mut b);
    crate::public_key::ntru_pqc_shared::poly_z3_to_zq::<N>(&mut b, Q_MASK);

    // r := (x - 1) * b
    r[0] = 0u16.wrapping_sub(b[0]);
    for i in 0..N - 1 {
        r[i + 1] = b[i].wrapping_sub(b[i + 1]);
    }
}

// ---- HRSS Sample_iid_plus distribution -------------------------------------
//
// Sample r via the IID-uniform-mod-3 distribution, then conditionally
// negate the even-indexed coefficients so that <x · r, r> >= 0. This is the
// only sampling distribution HRSS uses (replacing the HPS mix of IID for f
// and fixed-weight for g/m).

fn sample_iid_plus(r: &mut [u16; N], uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), SAMPLE_IID_BYTES);
    crate::public_key::ntru_pqc_shared::sample_iid::<N>(r, uniform_bytes);

    // Map {0, 1, 2} -> {0, 1, 2^16 - 1}
    for i in 0..N - 1 {
        let c = r[i];
        r[i] = c | (0u16.wrapping_sub(c >> 1));
    }

    // s = <x * r, r>; r[N-1] is zero.
    let mut s: u16 = 0;
    for i in 0..N - 1 {
        s = s.wrapping_add(((r[i + 1] as u32).wrapping_mul(r[i] as u32)) as u16);
    }

    // sign(s) — sign(0) = 1; the C uses `1 | (-(s>>15))`.
    let s_sign: u16 = 1 | 0u16.wrapping_sub(s >> 15);

    let mut i = 0;
    while i < N {
        r[i] = ((s_sign as u32).wrapping_mul(r[i] as u32)) as u16;
        i += 2;
    }

    // Map {0, 1, 2^16-1} -> {0, 1, 2}
    for i in 0..N {
        r[i] = 3 & (r[i] ^ (r[i] >> 15));
    }
}

// ---- variant marker -------------------------------------------------------

struct Hrss701Variant;

impl crate::public_key::ntru_pqc_shared::NtruVariant<N, LOGQ> for Hrss701Variant {
    const Q_MASK: u16 = Q_MASK;
    const SAMPLE_FG_BYTES: usize = SAMPLE_FG_BYTES;
    const SAMPLE_RM_BYTES: usize = SAMPLE_RM_BYTES;
    const PACK_TRINARY_BYTES: usize = PACK_TRINARY_BYTES;
    const OWCPA_PUBLICKEYBYTES: usize = OWCPA_PUBLICKEYBYTES;
    const OWCPA_SECRETKEYBYTES: usize = OWCPA_SECRETKEYBYTES;
    const OWCPA_BYTES: usize = OWCPA_BYTES;
    const OWCPA_MSGBYTES: usize = OWCPA_MSGBYTES;

    fn sample_fg(f: &mut [u16; N], g: &mut [u16; N], seed: &[u8]) {
        debug_assert_eq!(seed.len(), SAMPLE_FG_BYTES);
        sample_iid_plus(f, &seed[..SAMPLE_IID_BYTES]);
        sample_iid_plus(g, &seed[SAMPLE_IID_BYTES..]);
    }

    fn sample_rm(r: &mut [u16; N], m: &mut [u16; N], seed: &[u8]) {
        debug_assert_eq!(seed.len(), SAMPLE_RM_BYTES);
        crate::public_key::ntru_pqc_shared::sample_iid::<N>(r, &seed[..SAMPLE_IID_BYTES]);
        crate::public_key::ntru_pqc_shared::sample_iid::<N>(m, &seed[SAMPLE_IID_BYTES..]);
    }

    fn update_g_after_z3_to_zq(g: &mut [u16; N]) {
        // HRSS branch: g <- 3 * (x - 1) * g  (mod q)
        for i in (1..N).rev() {
            g[i] = (3u16).wrapping_mul(g[i - 1].wrapping_sub(g[i]));
        }
        g[0] = 0u16.wrapping_sub((3u16).wrapping_mul(g[0]));
    }

    fn poly_lift(r: &mut [u16; N], a: &[u16; N]) {
        poly_lift_hrss(r, a);
    }

    fn check_m(_m: &[u16; N]) -> i32 {
        // HRSS accepts any S_3 element.
        0
    }

    fn poly_sq_tobytes(r: &mut [u8], a: &[u16; N]) {
        crate::public_key::ntru_pqc_shared::poly_sq_tobytes_logq13::<N>(r, a);
    }

    fn poly_sq_frombytes(r: &mut [u16; N], a: &[u8]) {
        crate::public_key::ntru_pqc_shared::poly_sq_frombytes_logq13::<N>(r, a);
    }
}

// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHrss701,
    public_key = NtruHrss701PublicKey,
    private_key = NtruHrss701PrivateKey,
    ciphertext = NtruHrss701Ciphertext,
    shared_secret = NtruHrss701SharedSecret,
    variant = Hrss701Variant,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhrss701/PQCkemKAT_1450.rsp",
}
