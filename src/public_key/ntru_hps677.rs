//! NTRU-HPS-2048-677: the round-3 NTRU parameter set ntruhps2048677 (spec §1.6: n = 677,
//! q = 2048, family ntru-hps).
//!
//! The whole scheme lives in [`crate::public_key::ntru_pqc_shared`], which
//! implements the round-3 NTRU specification directly; that module's
//! documentation covers provenance, representation, and side channels. This
//! file only names the parameters. Its tests reproduce the round-3 package's
//! known-answer file `kat/ntruhps677.rsp`: eight sampled entries in a debug build,
//! all 100 in a release build, and all 100 in any build under `--ignored`.

crate::public_key::ntru_pqc_shared::define_ntru_kem! {
    n = 677,
    log_q = 11,
    family = Hps,
    namespace = NtruHps677,
    public_key = NtruHps677PublicKey,
    private_key = NtruHps677PrivateKey,
    ciphertext = NtruHps677Ciphertext,
    shared_secret = NtruHps677SharedSecret,
    kat_path = "../../kat/ntruhps677.rsp",
}
