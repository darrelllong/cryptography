//! The crate's constant-time claims, each behind a symbol of its own.
//!
//! `scripts/ct_codegen.sh` reads the release assembly of these functions and
//! lists the conditional branches in each. A claim holds for a target when the
//! only branches are over public lengths and loop counts: no branch may test a
//! key, a secret scalar, a tag or a plaintext byte.

use cryptography::modes::chacha20_poly1305::ChaCha20Poly1305;
use cryptography::ChaCha20;
use cryptography::vt::{X25519, X25519PrivateKey, X25519PublicKey, X448};
use cryptography::{
    Aes128Ct, Camellia128Ct, Cast128Ct, DesCt, GrasshopperCt, Hmac, MagmaCt, Present80Ct, SeedCt,
    Serpent128, Sha256, Sm4Ct, Twofish128Ct,
};

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

/// Open an RFC 8439 AEAD message: a complete operation, whose claim is that
/// only the authentication result — the value it returns — decides anything.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn chacha20poly1305_open(
    aead: &ChaCha20Poly1305,
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    aead.decrypt_in_place(nonce, aad, data, tag)
}

/// A complete X25519 key agreement: the ladder, and RFC 7748 §6.1's refusal of
/// an all-zero shared secret, whose outcome this function returns.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn x25519_agree(
    secret: &X25519PrivateKey,
    peer: &X25519PublicKey,
) -> Option<[u8; 32]> {
    secret.agree(peer)
}

// The block ciphers' constant-time types, each claiming a round function and
// key schedule with no secret-dependent branch or table index.

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn camellia128_ct_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    Camellia128Ct::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn cast128_ct_encrypt_block(key: &[u8; 16], block: &[u8; 8]) -> [u8; 8] {
    Cast128Ct::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn des_ct_encrypt_block(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    // A weak key is refused before the cipher exists, so the probe carries
    // that refusal's branch too.
    DesCt::new(key)
        .expect("probe key is not weak")
        .encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn grasshopper_ct_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    GrasshopperCt::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn magma_ct_encrypt_block(key: &[u8; 32], block: &[u8; 8]) -> [u8; 8] {
    MagmaCt::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn present80_ct_encrypt_block(key: &[u8; 10], block: &[u8; 8]) -> [u8; 8] {
    Present80Ct::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn seed_ct_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    SeedCt::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn sm4_ct_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    Sm4Ct::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn twofish128_ct_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    Twofish128Ct::new(key).encrypt_block(block)
}

#[inline(never)]
#[no_mangle]
pub extern "Rust" fn serpent128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    Serpent128::new(key).encrypt_block(block)
}

/// The ChaCha20 keystream over a caller's buffer, and the Poly1305 MAC over a
/// message: the two halves of the AEAD, each claiming that only lengths decide
/// anything.
#[inline(never)]
#[no_mangle]
pub extern "Rust" fn chacha20_keystream(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    ChaCha20::new(key, nonce).apply_keystream(data);
}
