//! Fuzz ECDSA sign/verify on P-256.
//!
//! The key scalar, nonce, and digest are each 32 bytes from the corpus.
//! Invariants:
//! 1. verify(pk, hash, sign(sk, digest, k)) == true.
//! 2. verify(pk, bad_hash, sign(sk, digest, k)) == false  (first byte flipped).
#![no_main]

use cryptography::public_key::{bigint::BigUint, ec::p256, ecdsa::Ecdsa};
use libfuzzer_sys::fuzz_target;

const SCALAR: usize = 32;
const NONCE: usize = 32;
const DIGEST: usize = 32;
const MIN: usize = SCALAR + NONCE + DIGEST;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let secret = BigUint::from_be_bytes(&data[..SCALAR]);
    let nonce = BigUint::from_be_bytes(&data[SCALAR..SCALAR + NONCE]);
    let digest = &data[SCALAR + NONCE..SCALAR + NONCE + DIGEST];
    let hash_bigint = BigUint::from_be_bytes(digest);

    let (pk, sk) = match Ecdsa::from_secret_scalar(p256(), &secret) {
        Some(kp) => kp,
        None => return,
    };

    let sig = match sk.sign_digest_with_nonce(digest, &nonce) {
        Some(s) => s,
        None => return,
    };

    // Invariant 1.
    assert!(
        pk.verify_digest_scalar(&hash_bigint, &sig),
        "ECDSA P-256: verify returned false for a freshly generated signature",
    );

    // Invariant 2: one-byte modification must be rejected.
    let mut bad_digest = digest.to_vec();
    bad_digest[0] ^= 1;
    let bad_hash = BigUint::from_be_bytes(&bad_digest);
    assert!(
        !pk.verify_digest_scalar(&bad_hash, &sig),
        "ECDSA P-256: verify returned true for a modified digest",
    );
});
