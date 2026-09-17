//! NTRUEncrypt SVES-3 parameter set `ees401ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 112-bit security, dense private key, SHA-1).
//!
//! $N = 401$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(113, 113)$; $g \in T(134, 133)$; $d_{m_0} = 113$;
//! $db = 112$ bits; $c = 11$; pkLen $= 112$ bits; OID `00 02 04`.
//! Wire sizes: public-key blob 557, private-key blob 638 (trit-packed $F$),
//! ciphertext 552 octets; messages of at most 60 octets.
//!
//! pkLen is 112 bits, as for `ees401ep2` (EESS #1 v3.1 Table 1, the same
//! $N$ at the same security level) and as the reference implementation
//! requires. libntru lists 114, but it also truncates to 14 octets.
//!
//! The IEEE Std 1363.1-2008 parameter tables are not drawn on. $N$, $df$,
//! $db$, $c$, pkLen, the OID, the hash and maxMsgLenBytes are confirmed
//! against the reference implementation by
//! `tests/vectors/ntru_ees_sves3_reference.txt`, and $dg$ by key pair
//! validation of its keys; $dm_0$ is only constrained where a recorded
//! encryption had to redraw $b$. minCallsR and minCallsMask match the 2013
//! reference release and libntru; the 2015 reference release uses other
//! values. They set how many hash blocks are computed up front, not the
//! output, so the vectors cannot tell them apart. The algorithm and
//! encodings live in [`crate::public_key::ntru_ees_core`].

crate::public_key::ntru_ees_core::define_ees_set! {
    namespace = NtruEes401Ep1,
    public_key = NtruEes401Ep1PublicKey,
    private_key = NtruEes401Ep1PrivateKey,
    ciphertext = NtruEes401Ep1Ciphertext,
    name = "ees401ep1",
    n = 401,
    trapdoor = TrapdoorKind::Dense { df: 113 },
    dg = 133,
    dm0 = 113,
    db_bits = 112,
    c_bits = 11,
    min_calls_r = 32,
    min_calls_mask = 9,
    pklen_bits = 112,
    oid = [0x00, 0x02, 0x04],
    hash = HashKind::Sha1,
    public_key_bytes = 557,
    private_key_bytes = 638,
    ciphertext_bytes = 552,
    max_message_bytes = 60,
}
