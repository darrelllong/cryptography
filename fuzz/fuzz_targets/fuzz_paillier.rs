//! Fuzz Paillier: encrypt/decrypt roundtrip and homomorphic addition.
//!
//! Keys use the hardcoded prime pair p=1009, q=1013 so the operations are
//! always exercised regardless of corpus content.  The nonces are drawn from
//! the corpus to maximise coverage of the modular arithmetic paths.
//!
//! Invariants:
//! 1. decrypt(encrypt(m, r)) == m.
//! 2. decrypt(add_ciphertexts(enc(1,r1), enc(2,r2))) == 3   (homomorphic add).
#![no_main]

use cryptography::public_key::{
    bigint::BigUint,
    paillier::{Paillier, PaillierPrivateKey, PaillierPublicKey},
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<(PaillierPublicKey, PaillierPrivateKey)> = OnceLock::new();

fn key() -> &'static (PaillierPublicKey, PaillierPrivateKey) {
    KEY.get_or_init(|| {
        let p = BigUint::from_u64(1009);
        let q = BigUint::from_u64(1013);
        Paillier::from_primes(&p, &q).expect("Paillier keygen with p=1009,q=1013 failed")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (pk, sk) = key();

    // Nonces from corpus; message kept small so it is always < n ≈ 1 022 117.
    let nonce = BigUint::from_be_bytes(data.get(..32).unwrap_or(data));
    let msg = BigUint::from_u64(data[0] as u64 + 1); // 1..=256

    // Invariant 1: roundtrip.
    if let Some(ct) = pk.encrypt_with_nonce(&msg, &nonce) {
        let recovered = sk.decrypt_raw(&ct);
        assert_eq!(recovered, msg, "Paillier: decrypt(encrypt(m)) != m");
    }

    // Invariant 2: homomorphic add  enc(1) + enc(2) = enc(3).
    let nonce2 = BigUint::from_be_bytes(data.get(32..64).unwrap_or(data));
    let one = BigUint::from_u64(1);
    let two = BigUint::from_u64(2);
    if let (Some(ct1), Some(ct2)) = (
        pk.encrypt_with_nonce(&one, &nonce),
        pk.encrypt_with_nonce(&two, &nonce2),
    ) {
        if let Some(ct_sum) = pk.add_ciphertexts(&ct1, &ct2) {
            let sum = sk.decrypt_raw(&ct_sum);
            assert_eq!(
                sum,
                BigUint::from_u64(3),
                "Paillier: homomorphic add dec(enc(1)+enc(2)) != 3",
            );
        }
    }
});
