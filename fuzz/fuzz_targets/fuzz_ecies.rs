//! ECIES from a fuzzer-supplied private key: parse a key blob, encrypt under
//! the recommended setup with an input-seeded DRBG, decrypt, and refuse a
//! ciphertext with one flipped bit.
//!
//! Layout: `[48-byte DRBG seed][flip position][flip bit][u16 blob length]
//! [private-key blob][plaintext]`. `fuzz/seeds/fuzz_ecies` seeds the blob.
#![no_main]

use cryptography::{
    public_key::ecies::{EciesPrivateKey, EciesSetup},
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED + 4 {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().expect("48 bytes");
    let at = usize::from(data[SEED]);
    let bit = data[SEED + 1];
    let len = usize::from(u16::from_be_bytes([data[SEED + 2], data[SEED + 3]]));
    let rest = &data[SEED + 4..];
    if rest.len() < len {
        return;
    }
    let (blob, plaintext) = rest.split_at(len);

    let Some(sk) = EciesPrivateKey::from_key_blob(blob) else {
        return;
    };
    let pk = sk.to_public_key();
    let mut rng = CtrDrbgAes256::new(&seed);
    // Only invalid domain parameters make encryption fail under the
    // recommended setup.
    let Ok(ciphertext) = pk.encrypt(EciesSetup::RECOMMENDED, plaintext, &[], &[], &mut rng) else {
        return;
    };
    assert_eq!(
        sk.decrypt(EciesSetup::RECOMMENDED, &ciphertext, &[], &[])
            .as_deref(),
        Some(plaintext),
        "ECIES: the honest ciphertext decrypts"
    );
    let mut bad = ciphertext.clone();
    let index = at % bad.len();
    bad[index] ^= 1 << (bit % 8);
    assert!(
        sk.decrypt(EciesSetup::RECOMMENDED, &bad, &[], &[])
            .is_none(),
        "ECIES: a ciphertext with one flipped bit decrypted"
    );
});
