//! NTRU-HPS-2048-509: the round-3 NTRU parameter set ntruhps2048509 (spec §1.6: n = 509,
//! q = 2048, family ntru-hps).
//!
//! The whole scheme lives in [`crate::public_key::ntru_pqc_shared`], which
//! implements the round-3 NTRU specification directly; that module's
//! documentation covers provenance, representation, and side channels. This
//! file only names the parameters. Its tests reproduce the round-3 package's
//! known-answer file `kat/ntruhps509.rsp`: eight sampled entries in a debug build,
//! all 100 in a release build, and all 100 in any build under `--ignored`.

crate::public_key::ntru_pqc_shared::define_ntru_kem! {
    n = 509,
    log_q = 11,
    family = Hps,
    namespace = NtruHps509,
    public_key = NtruHps509PublicKey,
    private_key = NtruHps509PrivateKey,
    ciphertext = NtruHps509Ciphertext,
    shared_secret = NtruHps509SharedSecret,
    kat_path = "../../kat/ntruhps509.rsp",
}
