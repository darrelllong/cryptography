//! NTRUEncrypt-EES1087EP2 (IEEE Std 1363.1-2008, dense trapdoor, SHA-256).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 1087$, $q = 2048$, $p = 3$,
//! $df = 120$, $dg = 362$, $dm0 = 120$, $db = 256$ bits, SHA-256,
//! OID `[0, 6, 3]`. Wire sizes pk/sk/ct = 1495 / 1767 / 1495 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes1087Ep2,
    public_key = NtruEes1087Ep2PublicKey,
    private_key = NtruEes1087Ep2PrivateKey,
    ciphertext = NtruEes1087Ep2Ciphertext,
    n = 1087,
    trapdoor = TrapdoorKind::Dense { df: 120 },
    dg = 362,
    dm0 = 120,
    db_bits = 256,
    c_bits = 13,
    min_calls_r = 25,
    min_calls_mask = 14,
    pklen_bits = 256,
    oid = [0, 6, 3],
    hash = HashKind::Sha256,
    pk_bytes = 1495,
    sk_packed_bytes = 272,
    ct_bytes = 1495,
    regression_digest = "7518eea678d6c3aedc17dabcbbac87bb0a56cb072a014dc9422a3b46d437ead4",
}
