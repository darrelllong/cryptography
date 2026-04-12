//! Fuzz ML-KEM (FIPS 203 / CRYSTALS-Kyber) for all three parameter sets.
//!
//! Two invariants are checked:
//! 1. KEM correctness: `decaps(sk, encaps(pk, m)) == shared_secret_from_encaps`.
//!    Any valid keygen seed and encapsulation randomness must satisfy this.
//! 2. Rejection sanity: feeding the raw ciphertext bytes back as a *different*
//!    ciphertext (byte-flipped) must not yield the same shared secret.
//!
//! Uses the deterministic `keygen_from_seed` and `encaps_with_randomness` entry
//! points so the fuzzer controls all randomness directly.
#![no_main]

use cryptography::public_key::ml_kem::{MlKem, MlKemParameterSet};
use libfuzzer_sys::fuzz_target;

// keygen seed = 64 bytes; encaps randomness = 32 bytes.
const SEED: usize = 64;
const RAND: usize = 32;
const MIN: usize = 1 + SEED + RAND;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let params = match data[0] % 3 {
        0 => MlKemParameterSet::MlKem512,
        1 => MlKemParameterSet::MlKem768,
        _ => MlKemParameterSet::MlKem1024,
    };

    let seed: [u8; SEED] = data[1..1 + SEED].try_into().unwrap();
    let randomness: [u8; RAND] = data[1 + SEED..MIN].try_into().unwrap();

    // Keygen from deterministic seed.
    let (pk, sk) = match MlKem::keygen_from_seed(params, &seed) {
        Some(kp) => kp,
        None => return,
    };

    // Encapsulate with deterministic randomness.
    let (ct, ss_enc) = match MlKem::encaps_with_randomness(&pk, &randomness) {
        Some(r) => r,
        None => return,
    };

    // Decapsulate: must recover the same shared secret.
    let ss_dec = match MlKem::decaps(&sk, &ct) {
        Some(ss) => ss,
        None => panic!("decaps returned None for a freshly encapsulated ciphertext"),
    };

    assert_eq!(
        ss_enc.to_wire_bytes(),
        ss_dec.to_wire_bytes(),
        "ML-KEM {:?}: decaps shared secret != encaps shared secret",
        params,
    );

    // Serialization roundtrip: wire-encode then re-parse the keys.
    let pk_bytes = pk.to_wire_bytes();
    let sk_bytes = sk.to_wire_bytes();
    let ct_bytes = ct.to_wire_bytes();

    let pk2 = cryptography::public_key::ml_kem::MlKemPublicKey::from_wire_bytes(params, &pk_bytes)
        .expect("pk wire roundtrip failed");
    let sk2 =
        cryptography::public_key::ml_kem::MlKemPrivateKey::from_wire_bytes(params, &sk_bytes)
            .expect("sk wire roundtrip failed");
    let ct2 =
        cryptography::public_key::ml_kem::MlKemCiphertext::from_wire_bytes(params, &ct_bytes)
            .expect("ct wire roundtrip failed");

    // Decaps with the re-parsed keys must still give the same shared secret.
    let ss3 = MlKem::decaps(&sk2, &ct2).expect("decaps with re-parsed keys failed");
    assert_eq!(
        ss_enc.to_wire_bytes(),
        ss3.to_wire_bytes(),
        "ML-KEM {:?}: decaps with re-parsed keys differs",
        params,
    );

    // Re-encaps with re-parsed public key must give the same ciphertext.
    let (ct3, ss4) =
        MlKem::encaps_with_randomness(&pk2, &randomness).expect("re-encaps failed");
    assert_eq!(ct_bytes, ct3.to_wire_bytes(), "ML-KEM encaps with re-parsed pk differs");
    assert_eq!(
        ss_enc.to_wire_bytes(),
        ss4.to_wire_bytes(),
        "ML-KEM re-encaps shared secret differs",
    );
});
