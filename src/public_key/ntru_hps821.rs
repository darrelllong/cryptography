//! NTRU-HPS-4096-821 — round-3 NTRU parameter set $(N = 821, q = 4096,
//! \text{weight} = q/8 - 2 = 510)$.
//!
//! Algorithmic core, OWCPA + FO-style KEM, and side-channel inventory
//! are documented in [`crate::public_key::ntru_pqc_shared`]; this file
//! is the parameter binding plus the LOGQ-12 Sq packer override (a
//! 12-bit-per-coefficient packing rather than the 11-bit form used by
//! HPS-509 / HPS-677).
//!
//! Validated against all 100 entries of the round-3 KAT file
//! `PQCkemKAT_1590.rsp` (sampled subset by default; full sweep under
//! `--ignored`).




// ---- parameter constants ---------------------------------------------------

const N: usize = 821;
const LOGQ: usize = 12;
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

struct Hps821Variant;

impl crate::public_key::ntru_pqc_shared::NtruVariant<N, LOGQ> for Hps821Variant {
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
        crate::public_key::ntru_pqc_shared::poly_sq_tobytes_logq12::<N>(r, a);
    }

    fn poly_sq_frombytes(r: &mut [u16; N], a: &[u8]) {
        crate::public_key::ntru_pqc_shared::poly_sq_frombytes_logq12::<N>(r, a);
    }
}

// ---- public API + standard tests (macro-generated) -------------------------

crate::public_key::ntru_pqc_shared::define_pqc_kem! {
    namespace = NtruHps821,
    public_key = NtruHps821PublicKey,
    private_key = NtruHps821PrivateKey,
    ciphertext = NtruHps821Ciphertext,
    shared_secret = NtruHps821SharedSecret,
    variant = Hps821Variant,
    kat_path = "../../.ntru-upstream/NIST-PQ-Submission-NTRU-20201016/KAT/ntruhps4096821/PQCkemKAT_1590.rsp",
}
