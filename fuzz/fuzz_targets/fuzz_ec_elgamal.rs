//! Fuzz EC-ElGamal: full encrypt/decrypt roundtrip on P-256.
//!
//! A keypair is generated from a corpus-seeded CSPRNG.  The bytes-based API
//! (Koblitz point embedding) is exercised.  Invariant, since the embedding
//! carries the message as an integer and `decrypt` documents that leading
//! zero bytes are not preserved:
//!   sk.decrypt(pk.encrypt(msg, rng)) == msg without its leading zero bytes
#![no_main]

use cryptography::{
    public_key::{ec::p256, ec_elgamal::EcElGamal},
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().unwrap();
    let message = &data[SEED..];

    let mut rng = CtrDrbgAes256::new(&seed);
    let (pk, sk) = EcElGamal::generate(p256(), &mut rng);

    // encrypt may return None if the message cannot be Koblitz-embedded.
    let ct = match pk.encrypt(message, &mut rng) {
        Some(c) => c,
        None => return,
    };

    let recovered = sk
        .decrypt(&ct)
        .expect("freshly encrypted ciphertext is valid");
    let significant = &message[message.iter().take_while(|&&b| b == 0).count()..];
    assert_eq!(
        recovered, significant,
        "EC-ElGamal P-256: decrypt(encrypt(msg)) != msg without leading zeros"
    );
});
