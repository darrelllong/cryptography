//! NTRUEncrypt-EES443EP1 (IEEE Std 1363.1-2008, product-form trapdoor, SHA-256).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 443$, $q = 2048$, $p = 3$,
//! product-form $df_1 = 9, df_2 = 8, df_3 = 5$, $dg = 148$, $dm0 = 115$,
//! $db = 128$ bits, SHA-256, OID `[0, 3, 17]`. Wire sizes pk/sk/ct =
//! 610 / 660 / 610 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes443Ep1,
    public_key = NtruEes443Ep1PublicKey,
    private_key = NtruEes443Ep1PrivateKey,
    ciphertext = NtruEes443Ep1Ciphertext,
    n = 443,
    trapdoor = TrapdoorKind::ProductForm { df1: 9, df2: 8, df3: 5 },
    dg = 148,
    dm0 = 115,
    db_bits = 128,
    c_bits = 9,
    min_calls_r = 8,
    min_calls_mask = 5,
    pklen_bits = 128,
    oid = [0, 3, 17],
    hash = HashKind::Sha256,
    pk_bytes = 610,
    sk_packed_bytes = 50,
    ct_bytes = 610,
    regression_digest = "df03381ce496d0754035929805cb6a844f234fae8d5e3245bc9a4047ca076bc4",
}
