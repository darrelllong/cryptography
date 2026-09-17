//! The crate's tag comparison, behind a symbol of its own.
//!
//! `scripts/ct_codegen.sh` reads the release assembly of [`verify_tag`] to
//! check that the only conditional branches are over the tag's public length.

use cryptography::{Hmac, Sha256};

/// Verify `tag` over `data` under `key`, the shortest public path to
/// `ct::constant_time_eq_mask`.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn verify_tag(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    Hmac::<Sha256>::verify(key, data, tag)
}
