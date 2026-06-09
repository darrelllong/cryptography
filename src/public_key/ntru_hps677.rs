//! NTRU-HPS-2048-677 — round-3 NTRU parameter set $(N = 677, q = 2048,
//! \text{weight} = q/8 - 2 = 254)$.
//!
//! Algorithmic core, OWCPA + FO-style KEM, and side-channel inventory
//! are documented in [`crate::public_key::ntru_pqc_shared`]; this file
//! is the parameter binding plus the LOGQ-11 Sq packer override.
//!
//! Validated against all 100 entries of the round-3 KAT file
//! `PQCkemKAT_1234.rsp` (sampled subset by default; full sweep under
//! `--ignored`).




// ---- parameter constants ---------------------------------------------------

const N: usize = 677;
const LOGQ: usize = 11;
const Q: u32 = 1 << LOGQ;
const Q_MASK: u16 = (Q as u16).wrapping_sub(1);
const WEIGHT: usize = (Q as usize) / 8 - 2;

const PRFKEYBYTES: usize = 32;
const SHAREDKEYBYTES: usize = 32;

const SAMPLE_IID_BYTES: usize = N - 1;
const SAMPLE_FT_BYTES: usize = (30 * (N - 1)).div_ceil(8);
const SAMPLE_FG_BYTES: usize = SAMPLE_IID_BYTES + SAMPLE_FT_BYTES;
const SAMPLE_RM_BYTES: usize = SAMPLE_IID_BYTES + SAMPLE_FT_BYTES;

const PACK_DEG: usize = N - 1;
const PACK_TRINARY_BYTES: usize = PACK_DEG.div_ceil(5);

const OWCPA_MSGBYTES: usize = 2 * PACK_TRINARY_BYTES;
const OWCPA_PUBLICKEYBYTES: usize = (LOGQ * PACK_DEG).div_ceil(8);
const OWCPA_SECRETKEYBYTES: usize = 2 * PACK_TRINARY_BYTES + OWCPA_PUBLICKEYBYTES;
const OWCPA_BYTES: usize = (LOGQ * PACK_DEG).div_ceil(8);

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
    kat_path = "../../kat/ntruhps677.rsp",
}
