//! The crate's constant-time claims, each behind a symbol of its own.
//!
//! `scripts/ct_codegen.sh` reads the release assembly of these functions and
//! lists the conditional branches in each. A claim holds for a target when the
//! only branches are over public lengths and loop counts: no branch may test a
//! key, a secret scalar, a tag or a plaintext byte.

use cryptography::vt::{X25519, X448};
use cryptography::{Aes128Ct, Hmac, Sha256};

/// Verify `tag` over `data` under `key`: the shortest public path to
/// `ct::constant_time_eq_mask`, which every MAC and AEAD tag check uses.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn verify_tag(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    Hmac::<Sha256>::verify(key, data, tag)
}

/// Encrypt one block with the bitsliced AES-128, whose claim is that no table
/// index or branch depends on the key or the block.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn aes128_ct_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    Aes128Ct::new(key).encrypt_block(block)
}

/// X25519 over a secret scalar: RFC 7748's Montgomery ladder, whose claim is a
/// fixed schedule with mask-driven swaps.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn x25519_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    X25519::scalar_mult(scalar, point)
}

/// X448 over a secret scalar, the same claim on Curve448.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn x448_scalar_mult(scalar: &[u8; 56], point: &[u8; 56]) -> [u8; 56] {
    X448::scalar_mult(scalar, point)
}
