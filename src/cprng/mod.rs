//! Deterministic random bit generators.
//!
//! Three mechanisms of NIST SP 800-90A Rev. 1 and one construction from the
//! literature, all deterministic once seeded; none is an entropy source, and
//! none reads the operating system:
//!
//! - `CTR_DRBG` over AES-256 without a derivation function, as the generic
//!   [`ctr_drbg::CtrDrbg`] with two instantiations: [`ctr_drbg::CtrDrbgAes256`]
//!   on the T-table AES-256 (variable-time) and [`ctr_drbg::CtrDrbgAes256Ct`]
//!   on the constant-time AES-256.
//! - `Hash_DRBG` over SHA-256 ([`hash_drbg::HashDrbg`], §10.1.1).
//! - `HMAC_DRBG` over HMAC-SHA-256 ([`hmac_drbg::HmacDrbg`], §10.1.2).
//! - Fast-key-erasure ChaCha20 ([`fast_key_erasure::FastKeyErasure`], after
//!   D. J. Bernstein, "Fast-key-erasure random-number generators", 2017).
//!
//! Seeding from the operating system, per-thread instances and application
//! sampling are the `rng-entropy` crate's; it adapts these cores.

use core::fmt;

pub mod ctr_drbg;
pub mod fast_key_erasure;
pub mod hash_drbg;
pub mod hmac_drbg;

/// A request the SP 800-90A mechanisms refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrbgError {
    /// The reseed counter has passed the reseed interval of 2^48 requests
    /// (§10.1.1.4 and §10.1.2.5 step 1): reseed before generating again.
    ReseedRequired,
    /// More than `max_number_of_bits_per_request`, 2^19 bits, was requested.
    RequestTooLarge,
    /// The entropy input is shorter than the security strength (256 bits),
    /// or the nonce shorter than half of it (§8.6.7, §10.1 Table 2).
    InputTooShort,
}

impl fmt::Display for DrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReseedRequired => "DRBG reseed required",
            Self::RequestTooLarge => "DRBG request exceeds 2^19 bits",
            Self::InputTooShort => "DRBG entropy input or nonce shorter than required",
        })
    }
}

impl std::error::Error for DrbgError {}

/// `reseed_interval` for the SHA-256 mechanisms (§10.1 Table 2): 2^48 requests.
pub const RESEED_INTERVAL: u64 = 1 << 48;

/// `max_number_of_bits_per_request` (§10.1 Table 2), in bytes: 2^19 bits.
pub const MAX_REQUEST_BYTES: usize = 1 << 16;

/// Minimum entropy input for 256-bit security strength, in bytes.
const MIN_ENTROPY_BYTES: usize = 32;

/// Minimum nonce for 256-bit security strength, in bytes (§8.6.7: half the
/// security strength).
const MIN_NONCE_BYTES: usize = 16;
