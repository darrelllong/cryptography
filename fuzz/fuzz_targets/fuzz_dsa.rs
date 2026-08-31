//! Fuzz DSA: parse a private-key blob, then exercise sign/verify.
//!
//! The first half of the input is tried as a DSA private-key blob.  If it
//! parses, the public key is derived from it and a sign/verify roundtrip is
//! performed using the second half as the digest and nonce source.
#![no_main]

use cryptography::public_key::{dsa::DsaPrivateKey};
use cryptography::vt::BigUint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let mid = data.len() / 2;
    let (blob, rest) = data.split_at(mid);

    let sk = match DsaPrivateKey::from_key_blob(blob) {
        Some(k) => k,
        None => return,
    };
    let pk = sk.to_public_key();

    // Derive nonce and digest from the second half of the input.
    let nonce_bytes = rest.get(..32).unwrap_or(rest);
    let nonce = BigUint::from_be_bytes(nonce_bytes);
    let digest = rest.get(32..).unwrap_or(&[]);

    let sig = match sk.sign_digest_with_nonce(digest, &nonce) {
        Some(s) => s,
        None => return,
    };

    let hash = BigUint::from_be_bytes(digest);
    assert!(
        pk.verify_digest_scalar(&hash, &sig),
        "DSA: verify returned false for a freshly generated signature",
    );
});
