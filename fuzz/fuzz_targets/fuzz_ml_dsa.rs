//! Fuzz ML-DSA (FIPS 204 / CRYSTALS-Dilithium) for all three parameter sets.
//!
//! Three invariants are checked:
//! 1. Sign-verify: a freshly generated signature must verify against the
//!    correct public key and message.
//! 2. Wrong-message rejection: the same signature must NOT verify against a
//!    one-bit-flipped message (unless the message is empty).
//! 3. Serialization roundtrip: wire-encode then re-parse keys and signature;
//!    verify still works.
//!
//! Uses deterministic `keygen_from_seed` and `sign_with_randomness`.
#![no_main]

use cryptography::public_key::ml_dsa::{MlDsa, MlDsaParameterSet};
use libfuzzer_sys::fuzz_target;

// keygen seed = 32 bytes; sign randomness = 32 bytes; min input for message = 1 byte.
const SEED: usize = 32;
const RAND: usize = 32;
const MIN: usize = 1 + SEED + RAND;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let params = match data[0] % 3 {
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    };

    let seed: [u8; SEED] = data[1..1 + SEED].try_into().unwrap();
    let randomness: [u8; RAND] = data[1 + SEED..MIN].try_into().unwrap();
    let message = &data[MIN..];

    // Keygen from deterministic seed.
    let (pk, sk) = match MlDsa::keygen_from_seed(params, &seed) {
        Some(kp) => kp,
        None => return,
    };

    // Sign with deterministic randomness.
    let sig = match MlDsa::sign_with_randomness(&sk, message, &randomness) {
        Some(s) => s,
        None => return,
    };

    // Invariant 1: verify(pk, msg, sig) == true.
    assert!(
        MlDsa::verify(&pk, message, &sig),
        "ML-DSA {:?}: verify returned false for a freshly generated signature",
        params,
    );

    // Invariant 2: verify(pk, flipped_msg, sig) == false (if message is non-empty).
    if !message.is_empty() {
        let mut bad_msg = message.to_vec();
        bad_msg[0] ^= 1;
        assert!(
            !MlDsa::verify(&pk, &bad_msg, &sig),
            "ML-DSA {:?}: verify returned true for a message with one flipped bit",
            params,
        );
    }

    // Invariant 3: serialization roundtrip — keys and signature survive wire encoding.
    let pk_bytes = pk.to_wire_bytes();
    let sk_bytes = sk.to_wire_bytes();
    let sig_bytes = sig.to_wire_bytes();

    let pk2 = cryptography::public_key::ml_dsa::MlDsaPublicKey::from_wire_bytes(params, &pk_bytes)
        .expect("pk wire roundtrip failed");
    let sk2 =
        cryptography::public_key::ml_dsa::MlDsaPrivateKey::from_wire_bytes(params, &sk_bytes)
            .expect("sk wire roundtrip failed");
    let sig2 =
        cryptography::public_key::ml_dsa::MlDsaSignature::from_wire_bytes(params, &sig_bytes)
            .expect("sig wire roundtrip failed");

    assert!(
        MlDsa::verify(&pk2, message, &sig2),
        "ML-DSA {:?}: verify with re-parsed keys/sig failed",
        params,
    );

    // Re-sign with re-parsed private key; must also verify.
    let sig3 = MlDsa::sign_with_randomness(&sk2, message, &randomness)
        .expect("re-sign with re-parsed sk failed");
    assert_eq!(
        sig_bytes,
        sig3.to_wire_bytes(),
        "ML-DSA {:?}: re-sign with re-parsed sk gave different signature",
        params,
    );
});
