//! NTRU-HRSS-701: the round-3 NTRU parameter set ntruhrss701 (spec §1.6: n = 701,
//! q = 8192, family ntru-hrss).
//!
//! The whole scheme lives in [`crate::public_key::ntru_pqc_shared`], which
//! implements the round-3 NTRU specification directly; that module's
//! documentation covers provenance, representation, and side channels. This
//! file only names the parameters. Its tests reproduce the round-3 package's
//! known-answer file `kat/ntruhrss701.rsp`: eight sampled entries in a debug build,
//! all 100 in a release build, and all 100 in any build under `--ignored`.

crate::public_key::ntru_pqc_shared::define_ntru_kem! {
    n = 701,
    log_q = 13,
    family = Hrss,
    namespace = NtruHrss701,
    public_key = NtruHrss701PublicKey,
    private_key = NtruHrss701PrivateKey,
    ciphertext = NtruHrss701Ciphertext,
    shared_secret = NtruHrss701SharedSecret,
    kat_path = "../../kat/ntruhrss701.rsp",
}
