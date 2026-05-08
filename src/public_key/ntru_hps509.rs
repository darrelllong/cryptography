//! NTRU-HPS-2048-509 implemented in safe, idiomatic Rust from the round-3
//! NTRU specification (Chen, Chung, Hülsing, Lange, Lyubashevsky, Saito,
//! Schanck, Schwabe, Stehlé, Whyte, Xagawa, Yamakawa, Zhang; NIST PQC,
//! 2020-10-16).
//!
//! This module provides:
//! - the HPS-2048-509 parameter set ($N = 509$, $q = 2048$,
//!   weight `= q/8 - 2 = 254`)
//! - key generation, encapsulation, decapsulation (CCA KEM)
//! - strict wire-format byte encodings for `pk`, `sk`, `ct`, `ss`
//!
//! Construction:
//! - Ring $\mathbb{Z}_q[x] / (x^N - 1)$ with operations projected onto
//!   $\mathbb{Z}_q[x] / \Phi_n(x)$ where $\Phi_n(x) = (x^N - 1) / (x - 1)$ for the
//!   `Sq` and `S3` views.
//! - One-way CPA-secure encryption (OWCPA) under the trapdoor `(f, g)` with
//!   public key $h = g/f$ in `R_q`, encryption `c = r·h + lift(m)`,
//!   decryption recovering `(r, m)`.
//! - CCA KEM via the SXY/Sch18 Fujisaki-Okamoto-style transform: shared key
//!   `K = SHA3-256(r || m)`, with deterministic implicit rejection
//!   `K = SHA3-256(prf || c)` on any decapsulation failure.
//!
//! Implementation notes:
//! - polynomial arithmetic and packings are implemented in-tree
//! - inversion in $R_2 = \mathbb{F}_2[x] / (x^N - 1)$ and in $S_3 = \mathbb{F}_3[x] / \Phi_n(x)$
//!   uses the constant-time gcd recursion of Bernstein and Yang ("Fast
//!   constant-time gcd computation and modular inversion", TCHES 2019)
//! - the fixed-weight `T_fixed` sampler tags each candidate coefficient with
//!   30 random bits and a 2-bit trinary intent, then sorts by tag using
//!   Batcher's bitonic sorting network (Batcher, "Sorting networks and
//!   their applications", AFIPS 1968)
//! - SHA3-256 and AES-256 CTR-DRBG come from this crate's `hash` and `cprng`
//!   modules; no C/FFI backends are used
//!
//! Validation:
//! the `count = 0` entry of the round-3 KAT `PQCkemKAT_935.rsp` is reproduced
//! byte-for-byte by the inline test, including the published `pk`, `sk`,
//! `ct`, and `ss`.
//!
//! Side channels: see [`crate::public_key::ntru_pqc_shared`] for the
//! per-primitive constant-time / variable-time analysis covering all four
//! NIST PQC NTRU modules. This module is exposed under [`crate::vt`]
//! because the shared polynomial multiplier is not constant-time.



// ---- parameter constants ---------------------------------------------------

const N: usize = 509;
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

struct Hps509Variant;

impl crate::public_key::ntru_pqc_shared::NtruVariant<N, LOGQ> for Hps509Variant {
    const Q_MASK: u16 = Q_MASK;
    const WEIGHT: usize = WEIGHT;
    const SAMPLE_FG_BYTES: usize = SAMPLE_FG_BYTES;
    const SAMPLE_RM_BYTES: usize = SAMPLE_RM_BYTES;
    const PACK_TRINARY_BYTES: usize = PACK_TRINARY_BYTES;
    const OWCPA_PUBLICKEYBYTES: usize = OWCPA_PUBLICKEYBYTES;
    const OWCPA_SECRETKEYBYTES: usize = OWCPA_SECRETKEYBYTES;
    const OWCPA_BYTES: usize = OWCPA_BYTES;
    const OWCPA_MSGBYTES: usize = OWCPA_MSGBYTES;

    // HPS-default `sample_fg` / `sample_rm` / `update_g_after_z3_to_zq` /
    // `poly_lift` / `check_m` are inherited from the trait — only the
    // LOGQ-11 Sq packer is set here.

    fn poly_sq_tobytes(r: &mut [u8], a: &[u16; N]) {
        crate::public_key::ntru_pqc_shared::poly_sq_tobytes_logq11::<N>(r, a);
    }

    fn poly_sq_frombytes(r: &mut [u16; N], a: &[u8]) {
        crate::public_key::ntru_pqc_shared::poly_sq_frombytes_logq11::<N>(r, a);
    }
}

// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHps509,
    public_key = NtruHps509PublicKey,
    private_key = NtruHps509PrivateKey,
    ciphertext = NtruHps509Ciphertext,
    shared_secret = NtruHps509SharedSecret,
    variant = Hps509Variant,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps2048509/PQCkemKAT_935.rsp",
}
