//! NTRUEncrypt-EES1171EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-256).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 1171$, $q = 2048$, $p = 3$,
//! $df = 106$, $dg = 390$, $dm0 = 106$, $db = 256$ bits, SHA-256,
//! OID `[0, 6, 4]`. Wire sizes pk/sk/ct = 1611 / 1904 / 1611 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes1171Ep1,
    public_key = NtruEes1171Ep1PublicKey,
    private_key = NtruEes1171Ep1PrivateKey,
    ciphertext = NtruEes1171Ep1Ciphertext,
    n = 1171,
    trapdoor = TrapdoorKind::Dense { df: 106 },
    dg = 390,
    dm0 = 106,
    db_bits = 256,
    c_bits = 12,
    min_calls_r = 20,
    min_calls_mask = 15,
    pklen_bits = 256,
    oid = [0, 6, 4],
    hash = HashKind::Sha256,
    pk_bytes = 1611,
    sk_packed_bytes = 293,
    ct_bytes = 1611,
    regression_digest = "413273c938e0c8bb5d5f59a209808812ee05256ac58df04f6da0db2cb104a2b4",
}
