//! ML-KEM (FIPS 203) for all three parameter sets, from fuzzer-chosen key
//! seeds and encapsulation randomness.
//!
//! Layout: `[set][flip position][flip bit][64-byte keygen seed][32-byte
//! encapsulation randomness]`. Decapsulation of the honest ciphertext gives
//! the encapsulated key, with the keys as generated and after a wire
//! round trip; the same randomness under the re-parsed public key gives the
//! same ciphertext. A ciphertext with one flipped bit decapsulates to a
//! different key (implicit rejection, Algorithm 18 step 12), and a public key
//! with one flipped bit is refused by the parser or, since `H(ek)` enters
//! the key derivation `G(m ‖ H(ek))`, yields a different shared key under
//! the same randomness.
#![no_main]

use cryptography::public_key::ml_kem::{
    MlKem, MlKemCiphertext, MlKemParameterSet, MlKemPrivateKey, MlKemPublicKey,
};
use cryptography::CtrDrbgAes256;
use libfuzzer_sys::fuzz_target;

const SEED: usize = 64;
const RAND: usize = 32;
const MIN: usize = 3 + SEED + RAND;

fn flipped(bytes: &[u8], at: usize, bit: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let index = at % out.len();
    out[index] ^= 1 << (bit % 8);
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let params = match data[0] % 3 {
        0 => MlKemParameterSet::MlKem512,
        1 => MlKemParameterSet::MlKem768,
        _ => MlKemParameterSet::MlKem1024,
    };
    let at = usize::from(data[1]);
    let bit = data[2];
    let seed: [u8; SEED] = data[3..3 + SEED].try_into().expect("64 bytes");
    let randomness: [u8; RAND] = data[3 + SEED..MIN].try_into().expect("32 bytes");

    let (pk, sk) = MlKem::keygen_from_seed(params, &seed);
    let (ct, shared) = MlKem::encaps_with_randomness(&pk, &randomness);
    let shared = shared.to_wire_bytes();
    assert_eq!(
        MlKem::decaps(&sk, &ct)
            .expect("matching parameter sets")
            .to_wire_bytes(),
        shared,
        "{params:?}: decapsulation of the honest ciphertext"
    );

    let pk_bytes = pk.to_wire_bytes();
    let sk_bytes = sk.to_wire_bytes();
    let ct_bytes = ct.to_wire_bytes();
    let pk2 = MlKemPublicKey::from_wire_bytes(params, &pk_bytes).expect("own public key parses");
    // Fixed-seed randomness for the import's pair-wise consistency test only.
    let sk2 =
        MlKemPrivateKey::from_wire_bytes(params, &sk_bytes, &mut CtrDrbgAes256::new(&[0u8; 48]))
            .expect("own private key parses");
    let ct2 = MlKemCiphertext::from_wire_bytes(params, &ct_bytes).expect("own ciphertext parses");
    assert_eq!(
        pk2.to_wire_bytes(),
        pk_bytes,
        "{params:?}: public key re-encodes"
    );
    assert_eq!(
        sk2.to_wire_bytes(),
        sk_bytes,
        "{params:?}: private key re-encodes"
    );
    assert_eq!(
        MlKem::decaps(&sk2, &ct2)
            .expect("matching parameter sets")
            .to_wire_bytes(),
        shared,
        "{params:?}: decapsulation with re-parsed keys"
    );
    let (ct3, shared3) = MlKem::encaps_with_randomness(&pk2, &randomness);
    assert_eq!(
        ct3.to_wire_bytes(),
        ct_bytes,
        "{params:?}: encapsulation under the re-parsed public key"
    );
    assert_eq!(
        shared3.to_wire_bytes(),
        shared,
        "{params:?}: key under the re-parsed public key"
    );

    let bad_ct = MlKemCiphertext::from_wire_bytes(params, &flipped(&ct_bytes, at, bit))
        .expect("a ciphertext of the right length parses");
    assert_ne!(
        MlKem::decaps(&sk, &bad_ct)
            .expect("matching parameter sets")
            .to_wire_bytes(),
        shared,
        "{params:?}: a flipped ciphertext decapsulated to the honest key"
    );

    if let Some(bad_pk) = MlKemPublicKey::from_wire_bytes(params, &flipped(&pk_bytes, at, bit)) {
        let (_, shared4) = MlKem::encaps_with_randomness(&bad_pk, &randomness);
        assert_ne!(
            shared4.to_wire_bytes(),
            shared,
            "{params:?}: a flipped public key gave the same shared key"
        );
    }
});
