//! Fuzz EdDSA (generic twisted-Edwards) on the ed25519 curve using SHA-512.
//!
//! Invariants match fuzz_ecdsa: sign-verify roundtrip and wrong-message
//! rejection.
#![no_main]

use cryptography::{
    public_key::{bigint::BigUint, ec_edwards::ed25519, eddsa::EdDsa},
    Sha512,
};
use libfuzzer_sys::fuzz_target;

const SCALAR: usize = 32;
const NONCE: usize = 32;
const MIN: usize = SCALAR + NONCE + 1;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let secret = BigUint::from_be_bytes(&data[..SCALAR]);
    let nonce = BigUint::from_be_bytes(&data[SCALAR..SCALAR + NONCE]);
    let message = &data[SCALAR + NONCE..];

    let (pk, sk) = match EdDsa::from_secret_scalar(ed25519(), &secret) {
        Some(kp) => kp,
        None => return,
    };

    let sig = match sk.sign_message_with_nonce::<Sha512>(message, &nonce) {
        Some(s) => s,
        None => return,
    };

    assert!(
        pk.verify_message::<Sha512>(message, &sig),
        "EdDSA ed25519/SHA-512: verify returned false for a freshly generated signature",
    );

    if !message.is_empty() {
        let mut bad = message.to_vec();
        bad[0] ^= 1;
        assert!(
            !pk.verify_message::<Sha512>(&bad, &sig),
            "EdDSA ed25519/SHA-512: verify returned true for a one-bit-flipped message",
        );
    }
});
