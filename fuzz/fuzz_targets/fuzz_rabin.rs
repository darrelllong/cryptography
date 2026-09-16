//! Rabin with a 512-bit key generated once from a fixed seed: the raw
//! integer round trip and the byte round trip, on messages up to 32 bytes.
//! The byte API reads the message as a big-endian integer and returns its
//! minimal encoding, so a message is compared without its leading zero
//! octets (an empty message comes back as `0x00`).
#![no_main]

use cryptography::{
    public_key::rabin::{Rabin, RabinPrivateKey, RabinPublicKey},
    vt::BigUint,
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<(RabinPublicKey, RabinPrivateKey)> = OnceLock::new();

fn key() -> &'static (RabinPublicKey, RabinPrivateKey) {
    KEY.get_or_init(|| {
        let mut rng = CtrDrbgAes256::new(&[0x3Cu8; 48]);
        Rabin::generate(&mut rng, 512).expect("512-bit Rabin key")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (pk, sk) = key();
    let message = &data[..data.len().min(32)];
    let minimal = BigUint::from_be_bytes(message).to_be_bytes();

    if let Some(ciphertext) = pk.encrypt(message) {
        assert_eq!(
            sk.decrypt(&ciphertext).as_deref(),
            Some(minimal.as_slice()),
            "Rabin: decrypt(encrypt(m)) != m"
        );
    }
    if let Some(ciphertext) = pk.encrypt_bytes(message) {
        assert_eq!(
            sk.decrypt_bytes(&ciphertext).as_deref(),
            Some(minimal.as_slice()),
            "Rabin: decrypt_bytes(encrypt_bytes(m)) != m"
        );
    }
    let raw = BigUint::from_be_bytes(&message[..message.len().min(4)]);
    if let Some(ciphertext) = pk.encrypt_raw(&raw) {
        let recovered = sk
            .decrypt_raw(&ciphertext)
            .expect("a ciphertext of ours decrypts");
        assert!(
            recovered == raw || pk.encrypt_raw(&recovered).as_ref() == Some(&ciphertext),
            "Rabin: decrypt_raw gave a value that is not a square root of the ciphertext"
        );
    }
});
