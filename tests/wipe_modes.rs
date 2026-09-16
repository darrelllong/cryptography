//! The mode and AEAD types wipe their key material on drop, and the
//! `new_wiping` constructors wipe the caller's key without changing the
//! result.
//!
//! Each type below holds nothing but key material (an expanded cipher, CMAC
//! subkeys, a one-time key), so after `ptr::drop_in_place` its whole storage
//! must read as zero. The per-call internals that the public types build and
//! drop inside one operation, the GHASH `SubkeyTable`, the OCB offset table,
//! the Poly1305 `TagState` and the GCM-SIV per-nonce keys, are private to the
//! crate and are observed the same way by the unit tests in `src/modes/`.

use core::mem::MaybeUninit;
use cryptography::modes::{Aes128GcmSiv, Aes256GcmSivCt};
use cryptography::{
    Aes128, Ccm, ChaCha20Poly1305, Cmac, Eax, Gcm, GcmVt, Gmac, Ocb, Poly1305, Siv, Xts,
};

/// The count of non-zero bytes in `T`'s storage before and after it is
/// dropped in place.
fn nonzero_bytes_before_and_after_drop<T>(value: T) -> (usize, usize) {
    let mut slot = MaybeUninit::new(value);
    let size = core::mem::size_of::<T>();
    // SAFETY: `slot` is initialised and the byte view covers exactly its
    // storage, which stays allocated (holding initialised bytes) until `slot`
    // goes out of scope; nothing uses the value after the drop except this
    // byte-level inspection.
    unsafe {
        let bytes = core::slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size);
        let before = bytes.iter().filter(|&&b| b != 0).count();
        core::ptr::drop_in_place(slot.as_mut_ptr());
        let after = bytes.iter().filter(|&&b| b != 0).count();
        (before, after)
    }
}

/// `value` holds key material (its image is not all zero) and none of it
/// survives the drop.
fn assert_wiped_on_drop<T>(value: T, what: &str) {
    let (before, after) = nonzero_bytes_before_and_after_drop(value);
    assert!(
        before > 0,
        "{what}: the live value is all zero, nothing to observe"
    );
    assert_eq!(after, 0, "{what}: {after} non-zero bytes left after drop");
}

const KEY16: [u8; 16] = [0x5a; 16];
const KEY32: [u8; 32] = [0xa5; 32];

#[test]
fn gcm_wipes_its_cipher_on_drop() {
    assert_wiped_on_drop(Gcm::new(Aes128::new(&KEY16)), "Gcm<Aes128>");
    assert_wiped_on_drop(GcmVt::new(Aes128::new(&KEY16)), "GcmVt<Aes128>");
    assert_wiped_on_drop(Gmac::new(Aes128::new(&KEY16)), "Gmac<Aes128>");
}

#[test]
fn cmac_wipes_its_subkeys_and_cipher_on_drop() {
    assert_wiped_on_drop(Cmac::new(Aes128::new(&KEY16)), "Cmac<Aes128>");
}

#[test]
fn ccm_eax_ocb_wipe_on_drop() {
    assert_wiped_on_drop(Ccm::<_, 16>::new(Aes128::new(&KEY16)), "Ccm<Aes128>");
    assert_wiped_on_drop(Eax::new(Aes128::new(&KEY16)), "Eax<Aes128>");
    assert_wiped_on_drop(Ocb::<_, 16>::new(Aes128::new(&KEY16)), "Ocb<Aes128>");
}

#[test]
fn siv_and_xts_wipe_both_ciphers_on_drop() {
    assert_wiped_on_drop(
        Siv::new(
            Aes128::new(&KEY16),
            Aes128::new(&KEY32[..16].try_into().unwrap()),
        ),
        "Siv<Aes128>",
    );
    assert_wiped_on_drop(
        Xts::new(
            Aes128::new(&KEY16),
            Aes128::new(&KEY32[..16].try_into().unwrap()),
        ),
        "Xts<Aes128>",
    );
}

#[test]
fn gcm_siv_wipes_its_key_generating_key_on_drop() {
    assert_wiped_on_drop(Aes128GcmSiv::new(&KEY16), "Aes128GcmSiv");
    assert_wiped_on_drop(Aes256GcmSivCt::new(&KEY32), "Aes256GcmSivCt");
}

#[test]
fn poly1305_and_chacha20_poly1305_wipe_their_keys_on_drop() {
    assert_wiped_on_drop(Poly1305::new(&KEY32), "Poly1305");
    assert_wiped_on_drop(ChaCha20Poly1305::new(&KEY32), "ChaCha20Poly1305");
}

/// `Poly1305::new_wiping` zeroes the caller's key and tags exactly as `new`
/// from the same key does.
#[test]
fn poly1305_new_wiping_zeroes_the_key_and_keeps_the_tag() {
    let reference = Poly1305::new(&KEY32);
    let mut key = KEY32;
    let mac = Poly1305::new_wiping(&mut key);
    assert_eq!(key, [0u8; 32]);
    let msg = b"the one message this key may tag";
    assert_eq!(mac.compute(msg), reference.compute(msg));
}

/// `ChaCha20Poly1305::new_wiping` zeroes the caller's key and seals exactly
/// as `new` from the same key does.
#[test]
fn chacha20_poly1305_new_wiping_zeroes_the_key_and_keeps_the_output() {
    let reference = ChaCha20Poly1305::new(&KEY32);
    let mut key = KEY32;
    let aead = ChaCha20Poly1305::new_wiping(&mut key);
    assert_eq!(key, [0u8; 32]);
    let nonce = [0x24u8; 12];
    assert_eq!(
        aead.encrypt(&nonce, b"header", b"payload"),
        reference.encrypt(&nonce, b"header", b"payload")
    );
}
