//! Drop-time wiping, observed.
//!
//! `tests/wipe_policy.rs` and the manifest gate in `src/scrub.rs` establish
//! what the sources and the manifest say. This file looks at the bytes: a
//! secret-bearing value is written into storage this test owns, dropped in
//! place, and the storage is read back. Before the drop the storage holds the
//! secret; after it, every byte must be zero.
//!
//! The reads go through raw pointers, which is why this is the one file under
//! `tests/` the unsafe gate in `src/scrub.rs` admits.

use core::mem::{size_of, MaybeUninit};
use core::ptr;

use cryptography::vt::{MlKemSharedSecret, X25519PrivateKey};
use cryptography::{Aes256, Aes256Ct, ChaCha20, CtrDrbgAes256, Hmac, Poly1305, Sha256};

/// The bytes of a `T`'s storage before and after `drop_in_place`.
///
/// The storage is zero-filled before the value is moved in, so every byte of
/// it, padding included, holds an initialised value that the read-back may
/// observe. Each type this file inspects also has `size_of` equal to the sum
/// of its fields, which the callers assert, so there is no padding for the
/// typed write to leave in an unspecified state.
fn bytes_before_and_after_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let mut slot = MaybeUninit::<T>::uninit();
    // SAFETY: `slot` is `size_of::<T>()` bytes of storage this function owns;
    // filling it with zero bytes and then writing a `T` into it are both
    // in-bounds writes to memory `MaybeUninit` allows to hold anything.
    unsafe {
        ptr::write_bytes(slot.as_mut_ptr().cast::<u8>(), 0, size_of::<T>());
        slot.as_mut_ptr().write(value);
    }
    let before = read_back(&slot);
    // SAFETY: `slot` holds a valid `T` written just above, and nothing reads
    // it as a `T` again; the storage stays allocated until `slot` goes out
    // of scope, so the byte reads below stay in bounds.
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    let after = read_back(&slot);
    (before, after)
}

/// Every byte of the storage, read one volatile byte at a time so the reads
/// happen as written and are not reasoned about from the value's history.
fn read_back<T>(slot: &MaybeUninit<T>) -> Vec<u8> {
    let base = slot.as_ptr().cast::<u8>();
    (0..size_of::<T>())
        .map(|offset| {
            // SAFETY: `offset` is below `size_of::<T>()`, so the read is
            // inside `slot`, and every byte of `slot` was initialised by the
            // zero fill in `bytes_before_and_after_drop`.
            unsafe { ptr::read_volatile(base.add(offset)) }
        })
        .collect()
}

/// Assert the experiment's two halves: the secret was there, and it is gone.
///
/// `secret_bytes_at_least` is how many nonzero bytes the live value must
/// show, so a type that never held the secret in its own storage cannot pass
/// by having nothing to wipe.
fn assert_wiped<T>(what: &str, value: T, expected_size: usize, secret_bytes_at_least: usize) {
    assert_eq!(
        size_of::<T>(),
        expected_size,
        "{what}: layout is not the sum of its fields; this test assumes no padding"
    );
    let (before, after) = bytes_before_and_after_drop(value);
    let live = before.iter().filter(|byte| **byte != 0).count();
    assert!(
        live >= secret_bytes_at_least,
        "{what}: only {live} nonzero bytes while live; the secret is not in this storage"
    );
    let leftover = after.iter().filter(|byte| **byte != 0).count();
    assert_eq!(
        leftover, 0,
        "{what}: {leftover} of {expected_size} bytes still nonzero after drop"
    );
}

const KEY_32: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

/// A plain array has no `Drop`, so its bytes survive `drop_in_place`: the
/// instrument reads back what is there and does not report zeros on its own.
#[test]
fn control_a_plain_array_is_not_wiped_by_drop() {
    let (before, after) = bytes_before_and_after_drop(KEY_32);
    assert_eq!(before, KEY_32);
    assert_eq!(after, KEY_32);
}

#[test]
fn aes256_round_keys_are_zero_after_drop() {
    // Two schedules of 60 words each.
    assert_wiped("Aes256", Aes256::new(&KEY_32), 2 * 60 * 4, 400);
}

#[test]
fn aes256ct_round_keys_are_zero_after_drop() {
    assert_wiped("Aes256Ct", Aes256Ct::new(&KEY_32), 2 * 60 * 4, 400);
}

/// `ChaCha20` is `#[repr(C)]` with its key-bearing state (16 words) and its
/// buffered keystream block (64 bytes) first; the offset and exhaustion flag
/// that follow carry no secret, and the struct's tail padding is not a field,
/// so only the leading 128 bytes are inspected.
#[test]
fn chacha20_state_and_keystream_block_are_zero_after_drop() {
    const SECRET_BYTES: usize = 16 * 4 + 64;
    let mut cipher = ChaCha20::new(&KEY_32, &[0x24; 12]);
    let mut buffer = [0u8; 10];
    cipher.apply_keystream(&mut buffer);
    let (before, after) = bytes_before_and_after_drop(cipher);
    let live = before[..SECRET_BYTES]
        .iter()
        .filter(|byte| **byte != 0)
        .count();
    assert!(
        live >= 100,
        "ChaCha20: only {live} nonzero secret bytes while live"
    );
    let leftover = after[..SECRET_BYTES]
        .iter()
        .filter(|byte| **byte != 0)
        .count();
    assert_eq!(
        leftover, 0,
        "ChaCha20: {leftover} of {SECRET_BYTES} state and block bytes nonzero after drop"
    );
}

#[test]
fn ctr_drbg_key_and_v_are_zero_after_drop() {
    let mut seed = [0u8; 48];
    seed[..32].copy_from_slice(&KEY_32);
    seed[32..].copy_from_slice(&KEY_32[..16]);
    let mut rng = CtrDrbgAes256::new(&seed);
    let mut discard = [0u8; 64];
    cryptography::Csprng::fill_bytes(&mut rng, &mut discard);
    // One forward AES-256 schedule (60 words), V (16 bytes), the reseed
    // counter (u64).
    assert_wiped("CtrDrbgAes256", rng, 60 * 4 + 16 + 8, 200);
}

#[test]
fn hmac_sha256_keyed_states_are_zero_after_drop() {
    // Two SHA-256 cores, each: state (8 words), block (64 bytes), position
    // (usize) and bit length (u64). After keying, each core's chaining state
    // is a function of the key and its bit length is 512.
    let core = 8 * 4 + 64 + size_of::<usize>() + 8;
    assert_wiped("Hmac<Sha256>", Hmac::<Sha256>::new(&KEY_32), 2 * core, 48);
}

#[test]
fn poly1305_key_is_zero_after_drop() {
    assert_wiped("Poly1305", Poly1305::new(&KEY_32), 32, 24);
}

#[test]
fn x25519_private_key_is_zero_after_drop() {
    let private = X25519PrivateKey::from_raw_bytes(&KEY_32);
    assert_wiped("X25519PrivateKey", private, 32, 24);
}

#[test]
fn ml_kem_shared_secret_is_zero_after_drop() {
    let secret = MlKemSharedSecret::from_wire_bytes(&KEY_32).expect("32 bytes");
    assert_wiped("MlKemSharedSecret", secret, 32, 24);
}
