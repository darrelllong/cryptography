//! NTRUEncrypt SVES-3 parameter set `ees1499ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 256-bit security, dense private key, SHA-256).
//!
//! $N = 1499$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(79, 79)$; $g \in T(500, 499)$; $d_{m_0} = 79$;
//! $db = 256$ bits; $c = 13$; pkLen $= 256$ bits; OID `00 06 05`.
//! Wire sizes: public-key blob 2067, private-key blob 2285 (index-list $F$),
//! ciphertext 2062 octets; messages of at most 247 octets.
//!
//! As specified, ciphertexts for this set are malleable. This crate rejects
//! the tampered ciphertexts with a check beyond the text that no honest
//! ciphertext fails: see the decryption convention in
//! [`crate::public_key::ntru_ees_core`].
//!
//! The IEEE Std 1363.1-2008 parameter tables are not drawn on. $N$, $df$,
//! $db$, $c$, pkLen, the OID, the hash and maxMsgLenBytes are confirmed
//! against the reference implementation by
//! `tests/vectors/ntru_ees_sves3_reference.txt`, and $dg$ by key pair
//! validation of its keys; $dm_0$ is only constrained where a recorded
//! encryption had to redraw $b$. minCallsR and minCallsMask are the precomputation
//! rule's values (see [`crate::public_key::ntru_ees_core`]); they set how many
//! hash blocks are computed up front, not the output. The algorithm and
//! encodings live in [`crate::public_key::ntru_ees_core`].

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes1499Ep1,
    public_key = NtruEes1499Ep1PublicKey,
    private_key = NtruEes1499Ep1PrivateKey,
    ciphertext = NtruEes1499Ep1Ciphertext,
    name = "ees1499ep1",
    n = 1499,
    trapdoor = TrapdoorKind::Dense { df: 79 },
    dg = 499,
    dm0 = 79,
    db_bits = 256,
    c_bits = 13,
    min_calls_r = 12,
    min_calls_mask = 12,
    pklen_bits = 256,
    oid = [0x00, 0x06, 0x05],
    hash = HashKind::Sha256,
    public_key_bytes = 2067,
    private_key_bytes = 2285,
    ciphertext_bytes = 2062,
    max_message_bytes = 247,
}
