//! Multiprecision integers, re-exported from the [`rump`] crate.
//!
//! The arithmetic itself — `u64`-limb representation, Knuth Algorithm D
//! division, Montgomery multiplication with a public Montgomery domain,
//! schoolbook and Karatsuba kernels — lives in
//! [rump](https://github.com/darrelllong/rump), extracted from this crate so
//! it can serve non-cryptographic consumers and so the crate boundary keeps
//! the API clean. rump carries the same guarantees this module always made:
//! pure safe Rust apart from one audited volatile-scrub helper, limbs wiped
//! on drop, and explicitly variable-time operation.
//!
//! This module remains so existing paths (`public_key::bigint::BigUint`,
//! [`crate::vt`]) stay valid.

pub use rump::{BigInt, BigUint, MontgomeryCtx, Sign};
