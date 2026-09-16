//! Finite-field Diffie-Hellman from fuzzer-supplied key blobs.
//!
//! Layout: `[u16 length][private-key blob][second blob]`. `fuzz/seeds/fuzz_dh`
//! seeds the blobs with toy keys. The first blob must parse as a private key
//! or the input ends. Agreement with its own public key must not panic. The
//! second blob is tried as a public key (agreement must not panic, whatever
//! group it names) and as a private key: two private keys in the same group
//! agree on the same element.
#![no_main]

use cryptography::public_key::dh::{DhPrivateKey, DhPublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let rest = &data[2..];
    if rest.len() < len {
        return;
    }
    let (blob1, blob2) = rest.split_at(len);
    let Some(sk1) = DhPrivateKey::from_key_blob(blob1) else {
        return;
    };
    let pk1 = sk1.to_public_key();
    let _ = sk1.agree_element(&pk1);

    if let Some(peer) = DhPublicKey::from_key_blob(blob2) {
        let _ = sk1.agree_element(&peer);
    }
    if let Some(sk2) = DhPrivateKey::from_key_blob(blob2) {
        let pk2 = sk2.to_public_key();
        if sk1.modulus() == sk2.modulus() && sk1.generator() == sk2.generator() {
            assert_eq!(
                sk1.agree_element(&pk2),
                sk2.agree_element(&pk1),
                "DH: agreement is symmetric within one group"
            );
        }
    }
});
