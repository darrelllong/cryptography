//! Deterministic random bit generators.
//!
//! The generator here is `CTR_DRBG` from NIST SP 800-90A Rev. 1 over AES-256
//! without a derivation function, as the generic [`ctr_drbg::CtrDrbg`] with
//! two instantiations: [`ctr_drbg::CtrDrbgAes256`] on the T-table AES-256
//! (variable-time) and [`ctr_drbg::CtrDrbgAes256Ct`] on the constant-time
//! AES-256. Both are deterministic once seeded; neither is an entropy source.

pub mod ctr_drbg;
