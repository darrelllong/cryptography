//! ML-DSA (FIPS 204) for all three parameter sets, from fuzzer-chosen key
//! seeds, signing randomness, context and message.
//!
//! Layout: `[set][flip position][flip bit][32-byte keygen seed][32-byte
//! signing randomness][context length byte][context][message]`. A signature
//! verifies under its message and context, with the keys as generated and
//! after a wire round trip, and the re-parsed private key signs identically.
//! It does not verify under a message with one flipped bit, under the empty
//! context when the context was not empty, with one flipped bit in the
//! signature (or the parser refuses it), or under a public key with one
//! flipped bit (or the parser refuses that).
#![no_main]

use cryptography::public_key::ml_dsa::{
    MlDsa, MlDsaParameterSet, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature,
};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 32;
const RAND: usize = 32;
const MIN: usize = 3 + SEED + RAND + 1;

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
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    };
    let at = usize::from(data[1]);
    let bit = data[2];
    let seed: [u8; SEED] = data[3..3 + SEED].try_into().expect("32 bytes");
    let randomness: [u8; RAND] = data[3 + SEED..3 + SEED + RAND]
        .try_into()
        .expect("32 bytes");
    let rest = &data[MIN - 1..];
    let context_len = usize::from(rest[0]).min(rest.len() - 1);
    let (context, message) = rest[1..].split_at(context_len);

    let (pk, sk) = MlDsa::keygen_from_seed(params, &seed);
    let sig = MlDsa::sign_with_randomness_and_context(&sk, message, &randomness, context)
        .expect("a context of at most 255 bytes signs");
    let verify = |pk: &MlDsaPublicKey, message: &[u8], sig: &MlDsaSignature| {
        MlDsa::verify_with_context(pk, message, sig, context).expect("context of at most 255 bytes")
    };
    assert!(
        verify(&pk, message, &sig),
        "{params:?}: the honest signature verifies"
    );

    let mut bad_message = message.to_vec();
    if !bad_message.is_empty() {
        let index = at % bad_message.len();
        bad_message[index] ^= 1 << (bit % 8);
        assert!(
            !verify(&pk, &bad_message, &sig),
            "{params:?}: a flipped message verified"
        );
    }
    if !context.is_empty() {
        assert!(
            !MlDsa::verify(&pk, message, &sig),
            "{params:?}: verified under the wrong context"
        );
    }

    let pk_bytes = pk.to_wire_bytes();
    let sk_bytes = sk.to_wire_bytes();
    let sig_bytes = sig.to_wire_bytes();
    let pk2 = MlDsaPublicKey::from_wire_bytes(params, &pk_bytes).expect("own public key parses");
    let sk2 = MlDsaPrivateKey::from_wire_bytes(params, &sk_bytes).expect("own private key parses");
    let sig2 = MlDsaSignature::from_wire_bytes(params, &sig_bytes).expect("own signature parses");
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
        sig2.to_wire_bytes(),
        sig_bytes,
        "{params:?}: signature re-encodes"
    );
    assert!(
        verify(&pk2, message, &sig2),
        "{params:?}: verification after the wire round trip"
    );
    let sig3 = MlDsa::sign_with_randomness_and_context(&sk2, message, &randomness, context)
        .expect("a context of at most 255 bytes signs");
    assert_eq!(
        sig3.to_wire_bytes(),
        sig_bytes,
        "{params:?}: the re-parsed private key signs differently"
    );

    if let Some(bad_sig) = MlDsaSignature::from_wire_bytes(params, &flipped(&sig_bytes, at, bit)) {
        assert!(
            !verify(&pk, message, &bad_sig),
            "{params:?}: a flipped signature verified"
        );
    }
    if let Some(bad_pk) = MlDsaPublicKey::from_wire_bytes(params, &flipped(&pk_bytes, at, bit)) {
        assert!(
            !verify(&bad_pk, message, &sig),
            "{params:?}: verified under a flipped public key"
        );
    }
});
