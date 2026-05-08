//! NTRUEncrypt-EES401EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-1).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 401$, $q = 2048$, $p = 3$,
//! $df = 113$, $dg = 133$, $dm0 = 113$, $db = 112$ bits, SHA-1, OID
//! `[0, 2, 4]`. Wire sizes pk/sk/ct = 552 / 653 / 552 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes401Ep1,
    public_key = NtruEes401Ep1PublicKey,
    private_key = NtruEes401Ep1PrivateKey,
    ciphertext = NtruEes401Ep1Ciphertext,
    n = 401,
    trapdoor = TrapdoorKind::Dense { df: 113 },
    dg = 133,
    dm0 = 113,
    db_bits = 112,
    c_bits = 11,
    min_calls_r = 32,
    min_calls_mask = 9,
    pklen_bits = 114,
    oid = [0, 2, 4],
    hash = HashKind::Sha1,
    pk_bytes = 552,
    sk_packed_bytes = 101,
    ct_bytes = 552,
}
