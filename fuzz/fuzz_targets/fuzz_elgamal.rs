//! Fuzz ElGamal: build a keypair from arbitrary big-integer inputs and, when
//! construction succeeds, verify encrypt/decrypt roundtrip.
//!
//! from_secret_exponent checks primality internally, so most inputs return
//! None — that is fine; we are primarily testing no-panic on arbitrary inputs.
//! When construction succeeds the roundtrip invariant is enforced:
//!   decrypt_raw(encrypt_with_nonce(m, r)) == m
#![no_main]

use cryptography::public_key::{elgamal::ElGamal};
use cryptography::vt::BigUint;
use libfuzzer_sys::fuzz_target;

const CHUNK: usize = 32;
const MIN: usize = CHUNK * 5; // prime, generator, secret, message, ephemeral

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let prime = BigUint::from_be_bytes(&data[..CHUNK]);
    let generator = BigUint::from_be_bytes(&data[CHUNK..CHUNK * 2]);
    let secret = BigUint::from_be_bytes(&data[CHUNK * 2..CHUNK * 3]);
    let message = BigUint::from_be_bytes(&data[CHUNK * 3..CHUNK * 4]);
    let ephemeral = BigUint::from_be_bytes(&data[CHUNK * 4..CHUNK * 5]);

    let (pk, sk) = match ElGamal::from_secret_exponent(&prime, &generator, &secret) {
        Some(kp) => kp,
        None => return,
    };

    // encrypt may return None if ephemeral or message is out of range.
    let ct = match pk.encrypt_with_nonce(&message, &ephemeral) {
        Some(c) => c,
        None => return,
    };

    let recovered = sk.decrypt_raw(&ct);
    assert_eq!(recovered, message, "ElGamal: decrypt_raw(encrypt_with_nonce(m)) != m");
});
