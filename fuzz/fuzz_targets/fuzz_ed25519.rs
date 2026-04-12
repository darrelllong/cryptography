//! Fuzz Ed25519: sign/verify roundtrip and wrong-message rejection.
//!
//! The keypair is derived deterministically from a 32-byte seed.  Invariants:
//! 1. verify(pk, msg, sign(sk, msg)) == true.
//! 2. verify(pk, msg', sign(sk, msg)) == false  (msg' has one flipped bit).
#![no_main]

use cryptography::public_key::ed25519::Ed25519;
use libfuzzer_sys::fuzz_target;

const SEED: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED + 1 {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().unwrap();
    let message = &data[SEED..];

    let (pk, sk) = Ed25519::from_seed(seed);

    // Invariant 1: sign then verify.
    let sig = sk.sign_message(message);
    assert!(
        pk.verify_message(message, &sig),
        "Ed25519: verify returned false for a freshly generated signature",
    );

    // Invariant 2: wrong-message rejection.
    if !message.is_empty() {
        let mut bad = message.to_vec();
        bad[0] ^= 1;
        assert!(
            !pk.verify_message(&bad, &sig),
            "Ed25519: verify returned true for a one-bit-flipped message",
        );
    }
});
