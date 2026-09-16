//! NTRUEncrypt SVES-3 parameter set `ees1087ep2` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 256-bit security, dense private key, SHA-256).
//!
//! $N = 1087$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(120, 120)$; $g \in T(363, 362)$; $d_{m_0} = 120$;
//! $db = 256$ bits; $c = 13$; pkLen $= 256$ bits; OID `00 06 03`.
//! Wire sizes: public-key blob 1500, private-key blob 1718 (trit-packed $F$),
//! ciphertext 1495 octets; messages of at most 170 octets.
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
    namespace = NtruEes1087Ep2,
    public_key = NtruEes1087Ep2PublicKey,
    private_key = NtruEes1087Ep2PrivateKey,
    ciphertext = NtruEes1087Ep2Ciphertext,
    name = "ees1087ep2",
    n = 1087,
    trapdoor = TrapdoorKind::Dense { df: 120 },
    dg = 362,
    dm0 = 120,
    db_bits = 256,
    c_bits = 13,
    min_calls_r = 25,
    min_calls_mask = 14,
    pklen_bits = 256,
    oid = [0x00, 0x06, 0x03],
    hash = HashKind::Sha256,
    public_key_bytes = 1500,
    private_key_bytes = 1718,
    ciphertext_bytes = 1495,
    max_message_bytes = 170,
}
