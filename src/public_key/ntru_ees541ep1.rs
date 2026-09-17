//! NTRUEncrypt SVES-3 parameter set `ees541ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 112-bit security, dense private key, SHA-1).
//!
//! $N = 541$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(49, 49)$; $g \in T(181, 180)$; $d_{m_0} = 49$;
//! $db = 112$ bits; $c = 12$; pkLen $= 112$ bits; OID `00 02 05`.
//! Wire sizes: public-key blob 749, private-key blob 858 (trit-packed $F$),
//! ciphertext 744 octets; messages of at most 86 octets.
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
    namespace = NtruEes541Ep1,
    public_key = NtruEes541Ep1PublicKey,
    private_key = NtruEes541Ep1PrivateKey,
    ciphertext = NtruEes541Ep1Ciphertext,
    name = "ees541ep1",
    n = 541,
    trapdoor = TrapdoorKind::Dense { df: 49 },
    dg = 180,
    dm0 = 49,
    db_bits = 112,
    c_bits = 12,
    min_calls_r = 13,
    min_calls_mask = 7,
    pklen_bits = 112,
    oid = [0x00, 0x02, 0x05],
    hash = HashKind::Sha1,
    public_key_bytes = 749,
    private_key_bytes = 858,
    ciphertext_bytes = 744,
    max_message_bytes = 86,
}
