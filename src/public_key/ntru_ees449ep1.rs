//! NTRUEncrypt SVES-3 parameter set `ees449ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 128-bit security, dense private key, SHA-1).
//!
//! $N = 449$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(134, 134)$; $g \in T(150, 149)$; $d_{m_0} = 134$;
//! $db = 128$ bits; $c = 9$; pkLen $= 128$ bits; OID `00 03 03`.
//! Wire sizes: public-key blob 623, private-key blob 713 (trit-packed $F$),
//! ciphertext 618 octets; messages of at most 67 octets.
//!
//! The IEEE Std 1363.1-2008 parameter tables were not available. $N$, $df$,
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
    namespace = NtruEes449Ep1,
    public_key = NtruEes449Ep1PublicKey,
    private_key = NtruEes449Ep1PrivateKey,
    ciphertext = NtruEes449Ep1Ciphertext,
    name = "ees449ep1",
    n = 449,
    trapdoor = TrapdoorKind::Dense { df: 134 },
    dg = 149,
    dm0 = 134,
    db_bits = 128,
    c_bits = 9,
    min_calls_r = 31,
    min_calls_mask = 9,
    pklen_bits = 128,
    oid = [0x00, 0x03, 0x03],
    hash = HashKind::Sha1,
    public_key_bytes = 623,
    private_key_bytes = 713,
    ciphertext_bytes = 618,
    max_message_bytes = 67,
}
