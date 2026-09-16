//! NTRUEncrypt SVES-3 parameter set `ees677ep1` (IEEE Std 1363.1-2008 /
//! ANSI X9.98; 192-bit security, dense private key, SHA-256).
//!
//! $N = 677$, $q = 2048$, $p = 3$; private key $f = 1 + 3F$ with
//! $F \in T(157, 157)$; $g \in T(226, 225)$; $d_{m_0} = 157$;
//! $db = 192$ bits; $c = 11$; pkLen $= 192$ bits; OID `00 05 03`.
//! Wire sizes: public-key blob 936, private-key blob 1072 (trit-packed $F$),
//! ciphertext 931 octets; messages of at most 101 octets.
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
    namespace = NtruEes677Ep1,
    public_key = NtruEes677Ep1PublicKey,
    private_key = NtruEes677Ep1PrivateKey,
    ciphertext = NtruEes677Ep1Ciphertext,
    name = "ees677ep1",
    n = 677,
    trapdoor = TrapdoorKind::Dense { df: 157 },
    dg = 225,
    dm0 = 157,
    db_bits = 192,
    c_bits = 11,
    min_calls_r = 27,
    min_calls_mask = 9,
    pklen_bits = 192,
    oid = [0x00, 0x05, 0x03],
    hash = HashKind::Sha256,
    public_key_bytes = 936,
    private_key_bytes = 1072,
    ciphertext_bytes = 931,
    max_message_bytes = 101,
}
