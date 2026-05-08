//! NTRUEncrypt-EES1087EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-256).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 1087$, $q = 2048$, $p = 3$,
//! $df = 63$, $dg = 362$, $dm0 = 63$, $db = 192$ bits, SHA-256,
//! OID `[0, 5, 5]`. Wire sizes pk/sk/ct = 1495 / 1767 / 1495 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes1087Ep1,
    public_key = NtruEes1087Ep1PublicKey,
    private_key = NtruEes1087Ep1PrivateKey,
    ciphertext = NtruEes1087Ep1Ciphertext,
    n = 1087,
    trapdoor = TrapdoorKind::Dense { df: 63 },
    dg = 362,
    dm0 = 63,
    db_bits = 192,
    c_bits = 13,
    min_calls_r = 13,
    min_calls_mask = 14,
    pklen_bits = 192,
    oid = [0, 5, 5],
    hash = HashKind::Sha256,
    pk_bytes = 1495,
    sk_packed_bytes = 272,
    ct_bytes = 1495,
    regression_digest = "eddd55be894194553c59741586a0b80460969264df090de584d0db8cb50562c5",
}
