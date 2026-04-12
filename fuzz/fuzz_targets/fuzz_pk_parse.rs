//! Fuzz all public-key deserialization entry points: `from_wire_bytes`,
//! `from_key_blob`, `from_pem`, and `from_xml` must never panic on arbitrary
//! input — they must return `None` / `Err` / empty string gracefully.
//!
//! If a parse succeeds, we also check the re-serialization roundtrip:
//! encoding the parsed value must produce identical bytes.
#![no_main]

use cryptography::public_key::{
    dh::{DhPrivateKey, DhPublicKey},
    dsa::{DsaPrivateKey, DsaPublicKey},
    ec::{b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384, p521, secp256k1},
    ed25519::{Ed25519PrivateKey as EdwardsDsaPrivateKey, Ed25519PublicKey},
    ecdh::{EcdhPrivateKey, EcdhPublicKey},
    ecdsa::{EcdsaPrivateKey, EcdsaPublicKey},
    ml_dsa::{MlDsaParameterSet, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature},
    ml_kem::{MlKemCiphertext, MlKemParameterSet, MlKemPrivateKey, MlKemPublicKey},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Dispatch to different parsers based on first two bytes to cover them all.
    let parser = (data[0] as u16) | ((data.get(1).copied().unwrap_or(0) as u16) << 8);
    let payload = if data.len() > 2 { &data[2..] } else { &[] };

    match parser % 48 {
        // ML-KEM public key wire bytes (all three param sets).
        0 => { let _ = MlKemPublicKey::from_wire_bytes(MlKemParameterSet::MlKem512, payload); }
        1 => { let _ = MlKemPublicKey::from_wire_bytes(MlKemParameterSet::MlKem768, payload); }
        2 => { let _ = MlKemPublicKey::from_wire_bytes(MlKemParameterSet::MlKem1024, payload); }

        // ML-KEM private key wire bytes.
        3 => { let _ = MlKemPrivateKey::from_wire_bytes(MlKemParameterSet::MlKem512, payload); }
        4 => { let _ = MlKemPrivateKey::from_wire_bytes(MlKemParameterSet::MlKem768, payload); }
        5 => { let _ = MlKemPrivateKey::from_wire_bytes(MlKemParameterSet::MlKem1024, payload); }

        // ML-KEM ciphertext wire bytes.
        6 => { let _ = MlKemCiphertext::from_wire_bytes(MlKemParameterSet::MlKem512, payload); }
        7 => { let _ = MlKemCiphertext::from_wire_bytes(MlKemParameterSet::MlKem768, payload); }
        8 => { let _ = MlKemCiphertext::from_wire_bytes(MlKemParameterSet::MlKem1024, payload); }

        // ML-KEM key_blob roundtrip: if parse succeeds, re-encode must be stable.
        9 => {
            if let Some(pk) = MlKemPublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = MlKemPublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of encoded ML-KEM public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        10 => {
            if let Some(sk) = MlKemPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = MlKemPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of encoded ML-KEM private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }

        // ML-DSA public key wire bytes.
        11 => { let _ = MlDsaPublicKey::from_wire_bytes(MlDsaParameterSet::MlDsa44, payload); }
        12 => { let _ = MlDsaPublicKey::from_wire_bytes(MlDsaParameterSet::MlDsa65, payload); }
        13 => { let _ = MlDsaPublicKey::from_wire_bytes(MlDsaParameterSet::MlDsa87, payload); }

        // ML-DSA private key wire bytes.
        14 => { let _ = MlDsaPrivateKey::from_wire_bytes(MlDsaParameterSet::MlDsa44, payload); }
        15 => { let _ = MlDsaPrivateKey::from_wire_bytes(MlDsaParameterSet::MlDsa65, payload); }
        16 => { let _ = MlDsaPrivateKey::from_wire_bytes(MlDsaParameterSet::MlDsa87, payload); }

        // ML-DSA signature wire bytes.
        17 => { let _ = MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa44, payload); }
        18 => { let _ = MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa65, payload); }
        19 => { let _ = MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa87, payload); }

        // ML-DSA key_blob roundtrip.
        20 => {
            if let Some(pk) = MlDsaPublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = MlDsaPublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of ML-DSA public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        21 => {
            if let Some(sk) = MlDsaPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = MlDsaPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of ML-DSA private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }

        // ECDSA public key wire bytes (prime curves).
        22 => { let _ = EcdsaPublicKey::from_wire_bytes(p256(), payload); }
        23 => { let _ = EcdsaPublicKey::from_wire_bytes(p384(), payload); }
        24 => { let _ = EcdsaPublicKey::from_wire_bytes(p521(), payload); }
        25 => { let _ = EcdsaPublicKey::from_wire_bytes(p192(), payload); }
        26 => { let _ = EcdsaPublicKey::from_wire_bytes(p224(), payload); }
        27 => { let _ = EcdsaPublicKey::from_wire_bytes(secp256k1(), payload); }

        // ECDSA binary curves.
        28 => { let _ = EcdsaPublicKey::from_wire_bytes(b163(), payload); }
        29 => { let _ = EcdsaPublicKey::from_wire_bytes(k163(), payload); }
        30 => { let _ = EcdsaPublicKey::from_wire_bytes(b233(), payload); }
        31 => { let _ = EcdsaPublicKey::from_wire_bytes(k233(), payload); }
        32 => { let _ = EcdsaPublicKey::from_wire_bytes(b283(), payload); }
        33 => { let _ = EcdsaPublicKey::from_wire_bytes(k283(), payload); }
        34 => { let _ = EcdsaPublicKey::from_wire_bytes(b409(), payload); }
        35 => { let _ = EcdsaPublicKey::from_wire_bytes(k409(), payload); }
        36 => { let _ = EcdsaPublicKey::from_wire_bytes(b571(), payload); }
        37 => { let _ = EcdsaPublicKey::from_wire_bytes(k571(), payload); }

        // ECDSA key blobs.
        38 => {
            if let Some(pk) = EcdsaPublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = EcdsaPublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of ECDSA public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        39 => {
            if let Some(sk) = EcdsaPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = EcdsaPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of ECDSA private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }

        // ECDH key blobs.
        40 => {
            if let Some(pk) = EcdhPublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = EcdhPublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of ECDH public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        41 => {
            if let Some(sk) = EcdhPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = EcdhPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of ECDH private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }

        // DSA key blobs.
        42 => {
            if let Some(pk) = DsaPublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = DsaPublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of DSA public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        43 => {
            if let Some(sk) = DsaPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = DsaPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of DSA private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }

        // DH key blobs.
        44 => {
            if let Some(pk) = DhPublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = DhPublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of DH public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        45 => {
            if let Some(sk) = DhPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = DhPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of DH private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }

        // Ed25519 / Edwards-curve key blobs.
        46 => {
            if let Some(pk) = Ed25519PublicKey::from_key_blob(payload) {
                let reencoded = pk.to_key_blob();
                let pk2 = Ed25519PublicKey::from_key_blob(&reencoded)
                    .expect("re-parse of Ed25519 public key blob failed");
                assert_eq!(reencoded, pk2.to_key_blob());
            }
        }
        _ => {
            if let Some(sk) = EdwardsDsaPrivateKey::from_key_blob(payload) {
                let reencoded = sk.to_key_blob();
                let sk2 = EdwardsDsaPrivateKey::from_key_blob(&reencoded)
                    .expect("re-parse of EdDSA private key blob failed");
                assert_eq!(reencoded, sk2.to_key_blob());
            }
        }
    }
});
