//! NTRUEncrypt-EES1499EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-256).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 1499$, $q = 2048$, $p = 3$,
//! $df = 79$, $dg = 499$, $dm0 = 79$, $db = 256$ bits, SHA-256,
//! OID `[0, 6, 5]`. Wire sizes pk/sk/ct = 2062 / 2437 / 2062 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes1499Ep1,
    public_key = NtruEes1499Ep1PublicKey,
    private_key = NtruEes1499Ep1PrivateKey,
    ciphertext = NtruEes1499Ep1Ciphertext,
    n = 1499,
    trapdoor = TrapdoorKind::Dense { df: 79 },
    dg = 499,
    dm0 = 79,
    db_bits = 256,
    c_bits = 13,
    min_calls_r = 17,
    min_calls_mask = 19,
    pklen_bits = 256,
    oid = [0, 6, 5],
    hash = HashKind::Sha256,
    pk_bytes = 2062,
    sk_packed_bytes = 375,
    ct_bytes = 2062,
    regression_digest = "127ad524127229757385e781080ff2abc357322117554d26c02a29c1eb090c3b",
}
