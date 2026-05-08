//! NTRUEncrypt-EES541EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-1).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 541$, $q = 2048$, $p = 3$,
//! $df = 49$, $dg = 180$, $dm0 = 49$, $db = 112$ bits, SHA-1,
//! OID `[0, 2, 5]`. Wire sizes pk/sk/ct = 744 / 880 / 744 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes541Ep1,
    public_key = NtruEes541Ep1PublicKey,
    private_key = NtruEes541Ep1PrivateKey,
    ciphertext = NtruEes541Ep1Ciphertext,
    n = 541,
    trapdoor = TrapdoorKind::Dense { df: 49 },
    dg = 180,
    dm0 = 49,
    db_bits = 112,
    c_bits = 12,
    min_calls_r = 15,
    min_calls_mask = 11,
    pklen_bits = 112,
    oid = [0, 2, 5],
    hash = HashKind::Sha1,
    pk_bytes = 744,
    sk_packed_bytes = 136,
    ct_bytes = 744,
}
