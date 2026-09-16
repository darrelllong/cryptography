//! NTRUEncrypt SVES-3 parameter set `ees443ep1` (128-bit security;
//! product-form private key, SHA-256).
//!
//! $N = 443$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F = F_1 F_2 + F_3$, $F_i \in T(d_i, d_i)$, $(d_1, d_2, d_3) = (9, 8, 5)$;
//! $g \in T(149, 148)$; $d_{m_0} = 115$;
//! $db = 256$ bits; $c = 9$; pkLen $= 128$ bits; OID `00 03 11`.
//! Wire sizes: public-key blob 615, private-key blob 665 (index-list $F$),
//! ciphertext 610 octets; messages of at most 49 octets.
//!
//! `ees443ep1` is a product-form set of EESS #1 v3.1 (2015), added after
//! IEEE Std 1363.1-2008. libntru uses $db = 128$ for it, which does not
//! interoperate; Table 5 specifies 256.
//!
//! As specified, ciphertexts for this set are malleable. This crate rejects
//! the tampered ciphertexts with a check beyond the text that no honest
//! ciphertext fails: see the decryption convention in
//! [`crate::public_key::ntru_ees_core`].
//!
//! Every value is from EESS #1 v3.1 §10.3.6, Table 5 (`ees443ep1`).
//! The algorithm and encodings live in [`crate::public_key::ntru_ees_core`];
//! `tests/vectors/ntru_ees_sves3_reference.txt` checks this set against the
//! reference implementation in both directions.

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes443Ep1,
    public_key = NtruEes443Ep1PublicKey,
    private_key = NtruEes443Ep1PrivateKey,
    ciphertext = NtruEes443Ep1Ciphertext,
    name = "ees443ep1",
    n = 443,
    trapdoor = TrapdoorKind::ProductForm { df1: 9, df2: 8, df3: 5 },
    dg = 148,
    dm0 = 115,
    db_bits = 256,
    c_bits = 9,
    min_calls_r = 8,
    min_calls_mask = 5,
    pklen_bits = 128,
    oid = [0x00, 0x03, 0x11],
    hash = HashKind::Sha256,
    public_key_bytes = 615,
    private_key_bytes = 665,
    ciphertext_bytes = 610,
    max_message_bytes = 49,
}
