//! NTRUEncrypt-EES449EP1 (IEEE Std 1363.1-2008, dense trapdoor, SHA-1).
//!
//! Parameters (IEEE 1363.1 Annex A): $N = 449$, $q = 2048$, $p = 3$,
//! $df = 134$, $dg = 149$, $dm0 = 134$, $db = 128$ bits, SHA-1,
//! OID `[0, 3, 3]`. Wire sizes pk/sk/ct = 618 / 731 / 618 bytes.
//!
//! All algebra and SVES-3 padding live in
//! [`crate::public_key::ntru_ees_core`]; this file is the parameter binding.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes449Ep1,
    public_key = NtruEes449Ep1PublicKey,
    private_key = NtruEes449Ep1PrivateKey,
    ciphertext = NtruEes449Ep1Ciphertext,
    n = 449,
    trapdoor = TrapdoorKind::Dense { df: 134 },
    dg = 149,
    dm0 = 134,
    db_bits = 128,
    c_bits = 9,
    min_calls_r = 31,
    min_calls_mask = 9,
    pklen_bits = 128,
    oid = [0, 3, 3],
    hash = HashKind::Sha1,
    pk_bytes = 618,
    sk_packed_bytes = 113,
    ct_bytes = 618,
}
