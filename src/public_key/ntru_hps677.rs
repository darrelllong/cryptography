//! NTRU-HPS-2048-677 implemented in safe, idiomatic Rust from the round-3
//! NTRU specification (Chen, Chung, Hülsing, Lange, Lyubashevsky, Saito,
//! Schanck, Schwabe, Stehlé, Whyte, Xagawa, Yamakawa, Zhang; NIST PQC,
//! 2020-10-16).
//!
//! This module provides:
//! - the HPS-2048-677 parameter set ($N = 677$, $q = 2048$,
//!   weight `= q/8 - 2 = 254`)
//! - key generation, encapsulation, decapsulation (CCA KEM)
//! - strict wire-format byte encodings for `pk`, `sk`, `ct`, `ss`
//!
//! See [`crate::public_key::ntru_hps509`] for the full algorithmic
//! description; HPS-2048-677 differs from HPS-2048-509 only in the ring
//! degree and the resulting byte sizes. Polynomial inversion follows
//! Bernstein–Yang (TCHES 2019); the fixed-weight sampler uses Batcher's
//! bitonic sorting network (1968); SHA3-256 and AES-256 CTR-DRBG come from
//! this crate's `hash` and `cprng` modules.
//!
//! Validation:
//! the `count = 0` entry of the round-3 KAT `PQCkemKAT_1234.rsp` is
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



use crate::Csprng;

// ---- parameter constants ---------------------------------------------------

const N: usize = 677;
const LOGQ: usize = 11;
const Q: u32 = 1 << LOGQ;
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

// ---- variant marker -------------------------------------------------------

struct Hps677Variant;

impl crate::public_key::ntru_pqc_shared::NtruVariant<N, LOGQ> for Hps677Variant {
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
        crate::public_key::ntru_pqc_shared::sample_iid::<N>(f, &seed[..SAMPLE_IID_BYTES]);
        crate::public_key::ntru_pqc_shared::sample_fixed_type::<N>(
            g,
            &seed[SAMPLE_IID_BYTES..],
            WEIGHT,
        );
    }

    fn sample_rm(r: &mut [u16; N], m: &mut [u16; N], seed: &[u8]) {
        debug_assert_eq!(seed.len(), SAMPLE_RM_BYTES);
        crate::public_key::ntru_pqc_shared::sample_iid::<N>(r, &seed[..SAMPLE_IID_BYTES]);
        crate::public_key::ntru_pqc_shared::sample_fixed_type::<N>(
            m,
            &seed[SAMPLE_IID_BYTES..],
            WEIGHT,
        );
    }

    fn update_g_after_z3_to_zq(g: &mut [u16; N]) {
        for i in 0..N {
            g[i] = g[i].wrapping_mul(3);
        }
    }

    fn poly_lift(r: &mut [u16; N], a: &[u16; N]) {
        crate::public_key::ntru_pqc_shared::poly_lift_hps::<N>(r, a, Q_MASK);
    }

    fn check_m(m: &[u16; N]) -> i32 {
        crate::public_key::ntru_pqc_shared::owcpa_check_m::<N>(m, WEIGHT)
    }

    fn poly_sq_tobytes(r: &mut [u8], a: &[u16; N]) {
        crate::public_key::ntru_pqc_shared::poly_sq_tobytes_logq11::<N>(r, a);
    }

    fn poly_sq_frombytes(r: &mut [u16; N], a: &[u8]) {
        crate::public_key::ntru_pqc_shared::poly_sq_frombytes_logq11::<N>(r, a);
    }
}

// ---- CCA KEM wrapper (delegated entirely to the shared FO transform) -------

fn kem_keypair_seeded<R: Csprng>(pk: &mut [u8], sk: &mut [u8], rng: &mut R) {
    crate::public_key::ntru_pqc_shared::kem_keypair_seeded::<Hps677Variant, R, N, LOGQ>(
        pk, sk, rng,
    );
}

fn kem_enc_seeded<R: Csprng>(
    c: &mut [u8; CIPHERTEXT_BYTES],
    k: &mut [u8; SHARED_SECRET_BYTES],
    pk: &[u8; PUBLIC_KEY_BYTES],
    rng: &mut R,
) {
    crate::public_key::ntru_pqc_shared::kem_enc_seeded::<Hps677Variant, R, N, LOGQ>(c, k, pk, rng);
}

fn kem_dec(
    k: &mut [u8; SHARED_SECRET_BYTES],
    c: &[u8; CIPHERTEXT_BYTES],
    sk: &[u8; PRIVATE_KEY_BYTES],
) {
    crate::public_key::ntru_pqc_shared::kem_dec::<Hps677Variant, N, LOGQ>(k, c, sk);
}


// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHps677,
    public_key = NtruHps677PublicKey,
    private_key = NtruHps677PrivateKey,
    ciphertext = NtruHps677Ciphertext,
    shared_secret = NtruHps677SharedSecret,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps2048677/PQCkemKAT_1234.rsp",
}
