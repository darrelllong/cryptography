//! NTRUEncrypt SVES-3 parameter set `ees1171ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 256-bit security, dense private key, SHA-256).
//!
//! $N = 1171$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(106, 106)$; $g \in T(391, 390)$; $d_{m_0} = 106$;
//! $db = 256$ bits; $c = 12$; pkLen $= 256$ bits; OID `00 06 04`.
//! Wire sizes: public-key blob 1616, private-key blob 1851 (trit-packed $F$),
//! ciphertext 1611 octets; messages of at most 186 octets.
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
    namespace = NtruEes1171Ep1,
    public_key = NtruEes1171Ep1PublicKey,
    private_key = NtruEes1171Ep1PrivateKey,
    ciphertext = NtruEes1171Ep1Ciphertext,
    name = "ees1171ep1",
    n = 1171,
    trapdoor = TrapdoorKind::Dense { df: 106 },
    dg = 390,
    dm0 = 106,
    db_bits = 256,
    c_bits = 12,
    min_calls_r = 20,
    min_calls_mask = 15,
    pklen_bits = 256,
    oid = [0x00, 0x06, 0x04],
    hash = HashKind::Sha256,
    public_key_bytes = 1616,
    private_key_bytes = 1851,
    ciphertext_bytes = 1611,
    max_message_bytes = 186,
}
