//! Fuzz ECIES: parse a private-key blob, derive the public key, and verify the
//! encrypt/decrypt roundtrip.
//!
//! The first 48 bytes provide the CSPRNG seed; the next portion is tried as an
//! ECIES private-key blob; the remainder is the plaintext to encrypt.
//! Invariant: decrypt(encrypt(msg, rng)) == msg
#![no_main]

use cryptography::{public_key::ecies::EciesPrivateKey, CtrDrbgAes256};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED + 2 {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().unwrap();
    let rest = &data[SEED..];

    // First half of rest: private-key blob; second half: plaintext.
    let mid = rest.len() / 2;
    let key_blob = &rest[..mid];
    let plaintext = &rest[mid..];

    let sk = match EciesPrivateKey::from_key_blob(key_blob) {
        Some(k) => k,
        None => return,
    };
    let pk = sk.to_public_key();

    let mut rng = CtrDrbgAes256::new(&seed);
    let ciphertext = pk.encrypt(plaintext, &mut rng);

    let recovered = sk
        .decrypt(&ciphertext)
        .expect("ECIES: decrypt(encrypt(msg)) returned None");
    assert_eq!(recovered, plaintext, "ECIES: decrypt(encrypt(msg)) != msg");
});
