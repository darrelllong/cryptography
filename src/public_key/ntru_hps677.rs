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
//! Side channels: see [`crate::public_key::ntru_pqc_shared`].




// ---- parameter constants ---------------------------------------------------

const N: usize = 677;
const LOGQ: usize = 11;
const Q: u32 = 1 << LOGQ;
const Q_MASK: u16 = (Q as u16).wrapping_sub(1);
const WEIGHT: usize = (Q as usize) / 8 - 2;

const PRFKEYBYTES: usize = 32;
const SHAREDKEYBYTES: usize = 32;

const SAMPLE_IID_BYTES: usize = N - 1;
const SAMPLE_FT_BYTES: usize = (30 * (N - 1) + 7) / 8;
const SAMPLE_FG_BYTES: usize = SAMPLE_IID_BYTES + SAMPLE_FT_BYTES;
const SAMPLE_RM_BYTES: usize = SAMPLE_IID_BYTES + SAMPLE_FT_BYTES;

const PACK_DEG: usize = N - 1;
const PACK_TRINARY_BYTES: usize = (PACK_DEG + 4) / 5;

const OWCPA_MSGBYTES: usize = 2 * PACK_TRINARY_BYTES;
const OWCPA_PUBLICKEYBYTES: usize = (LOGQ * PACK_DEG + 7) / 8;
const OWCPA_SECRETKEYBYTES: usize = 2 * PACK_TRINARY_BYTES + OWCPA_PUBLICKEYBYTES;
const OWCPA_BYTES: usize = (LOGQ * PACK_DEG + 7) / 8;

/// Public-key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = OWCPA_PUBLICKEYBYTES;
/// Private-key length in bytes (includes implicit-rejection PRF key).
pub const PRIVATE_KEY_BYTES: usize = OWCPA_SECRETKEYBYTES + PRFKEYBYTES;
/// Ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = OWCPA_BYTES;
/// Shared-secret length in bytes.
pub const SHARED_SECRET_BYTES: usize = SHAREDKEYBYTES;

// ---- variant marker -------------------------------------------------------

struct Hps677Variant;

impl crate::public_key::ntru_pqc_shared::NtruVariant<N, LOGQ> for Hps677Variant {
    const Q_MASK: u16 = Q_MASK;
    const WEIGHT: usize = WEIGHT;
    const SAMPLE_FG_BYTES: usize = SAMPLE_FG_BYTES;
    const SAMPLE_RM_BYTES: usize = SAMPLE_RM_BYTES;
    const PACK_TRINARY_BYTES: usize = PACK_TRINARY_BYTES;
    const OWCPA_PUBLICKEYBYTES: usize = OWCPA_PUBLICKEYBYTES;
    const OWCPA_SECRETKEYBYTES: usize = OWCPA_SECRETKEYBYTES;
    const OWCPA_BYTES: usize = OWCPA_BYTES;
    const OWCPA_MSGBYTES: usize = OWCPA_MSGBYTES;

    fn poly_sq_tobytes(r: &mut [u8], a: &[u16; N]) {
        crate::public_key::ntru_pqc_shared::poly_sq_tobytes_logq11::<N>(r, a);
    }

    fn poly_sq_frombytes(r: &mut [u16; N], a: &[u8]) {
        crate::public_key::ntru_pqc_shared::poly_sq_frombytes_logq11::<N>(r, a);
    }
}

// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHps677,
    public_key = NtruHps677PublicKey,
    private_key = NtruHps677PrivateKey,
    ciphertext = NtruHps677Ciphertext,
    shared_secret = NtruHps677SharedSecret,
    variant = Hps677Variant,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps2048677/PQCkemKAT_1234.rsp",
}
