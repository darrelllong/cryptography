//! Fuzz RSA-PKCS1: OAEP-SHA-1 roundtrip and PSS-SHA-256 sign/verify.
//!
//! An RSA-1024 keypair is generated once (via a fixed seed) and cached.
//! For every corpus entry:
//! - OAEP-SHA-1: encrypt→decrypt must round-trip (if the message fits).
//! - PSS-SHA-256: sign→verify must succeed; a one-byte-modified message must
//!   be rejected.
#![no_main]

use cryptography::{
    public_key::{
        rsa::{Rsa, RsaPrivateKey, RsaPublicKey},
        rsa_pkcs1::{RsaOaep, RsaPss},
    },
    CtrDrbgAes256, Sha1, Sha256,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<(RsaPublicKey, RsaPrivateKey)> = OnceLock::new();

fn key() -> &'static (RsaPublicKey, RsaPrivateKey) {
    KEY.get_or_init(|| {
        let mut rng = CtrDrbgAes256::new(&[0u8; 48]);
        Rsa::generate(&mut rng, 1024).expect("RSA-1024 key generation failed")
    })
}

// SHA-1 output = 20 bytes (OAEP seed); SHA-256 output = 32 bytes (PSS salt).
const SHA1_OUT: usize = 20;
const SHA256_OUT: usize = 32;
const HDR: usize = SHA1_OUT + SHA256_OUT;

fuzz_target!(|data: &[u8]| {
    if data.len() < HDR {
        return;
    }
    let (pk, sk) = key();

    let oaep_seed = &data[..SHA1_OUT];
    let pss_salt = &data[SHA1_OUT..HDR];
    let message = &data[HDR..];

    // OAEP-SHA-1 roundtrip.
    if let Some(ciphertext) = RsaOaep::<Sha1>::encrypt(pk, b"", message, oaep_seed) {
        let plaintext = RsaOaep::<Sha1>::decrypt(sk, b"", &ciphertext)
            .expect("OAEP: decrypt returned None for a valid ciphertext");
        assert_eq!(plaintext, message, "OAEP: roundtrip mismatch");
    }

    // PSS-SHA-256 roundtrip.
    if let Some(sig) = RsaPss::<Sha256>::sign(sk, message, pss_salt) {
        assert!(
            RsaPss::<Sha256>::verify(pk, message, &sig),
            "PSS: verify returned false for a freshly generated signature",
        );
        if !message.is_empty() {
            let mut bad = message.to_vec();
            bad[0] ^= 1;
            assert!(
                !RsaPss::<Sha256>::verify(pk, &bad, &sig),
                "PSS: verify returned true for a modified message",
            );
        }
    }
});
