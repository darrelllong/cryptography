//! NTRU-HPS-4096-821: the round-3 NTRU parameter set ntruhps4096821 (spec §1.6: n = 821,
//! q = 4096, family ntru-hps).
//!
//! The whole scheme lives in [`crate::public_key::ntru_pqc_shared`], which
//! implements the round-3 NTRU specification directly; that module's
//! documentation covers provenance, representation, and side channels. This
//! file only names the parameters. Its tests reproduce the round-3 package's
//! known-answer file `kat/ntruhps821.rsp`: eight sampled entries in a debug build,
//! all 100 in a release build, and all 100 in any build under `--ignored`.

crate::public_key::ntru_pqc_shared::define_ntru_kem! {
    n = 821,
    log_q = 12,
    family = Hps,
    namespace = NtruHps821,
    public_key = NtruHps821PublicKey,
    private_key = NtruHps821PrivateKey,
    ciphertext = NtruHps821Ciphertext,
    shared_secret = NtruHps821SharedSecret,
    kat_path = "../../kat/ntruhps821.rsp",
}
