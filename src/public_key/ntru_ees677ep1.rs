//! NTRUEncrypt-EES677EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-256).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 677$, $q = 2048$, $p = 3$,
//! $df = 157$, $dg = 225$, $dm0 = 157$, $db = 192$ bits, SHA-256,
//! OID `[0, 5, 3]`. Wire sizes pk/sk/ct = 931 / 1101 / 931 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes677Ep1,
    public_key = NtruEes677Ep1PublicKey,
    private_key = NtruEes677Ep1PrivateKey,
    ciphertext = NtruEes677Ep1Ciphertext,
    n = 677,
    trapdoor = TrapdoorKind::Dense { df: 157 },
    dg = 225,
    dm0 = 157,
    db_bits = 192,
    c_bits = 11,
    min_calls_r = 27,
    min_calls_mask = 9,
    pklen_bits = 192,
    oid = [0, 5, 3],
    hash = HashKind::Sha256,
    pk_bytes = 931,
    sk_packed_bytes = 170,
    ct_bytes = 931,
    regression_digest = "02ca8c6db314023ab4823f66741376b9174d5df6b6d964036e856ca31368cb59",
}
