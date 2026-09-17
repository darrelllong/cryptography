//! NTRUEncrypt SVES-3 parameter set `ees1087ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 192-bit security, dense private key, SHA-256).
//!
//! $N = 1087$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(63, 63)$; $g \in T(363, 362)$; $d_{m_0} = 63$;
//! $db = 192$ bits; $c = 13$; pkLen $= 192$ bits; OID `00 05 05`.
//! Wire sizes: public-key blob 1500, private-key blob 1674 (index-list $F$),
//! ciphertext 1495 octets; messages of at most 178 octets.
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
    namespace = NtruEes1087Ep1,
    public_key = NtruEes1087Ep1PublicKey,
    private_key = NtruEes1087Ep1PrivateKey,
    ciphertext = NtruEes1087Ep1Ciphertext,
    name = "ees1087ep1",
    n = 1087,
    trapdoor = TrapdoorKind::Dense { df: 63 },
    dg = 362,
    dm0 = 63,
    db_bits = 192,
    c_bits = 13,
    min_calls_r = 10,
    min_calls_mask = 9,
    pklen_bits = 192,
    oid = [0x00, 0x05, 0x05],
    hash = HashKind::Sha256,
    public_key_bytes = 1500,
    private_key_bytes = 1674,
    ciphertext_bytes = 1495,
    max_message_bytes = 178,
}
