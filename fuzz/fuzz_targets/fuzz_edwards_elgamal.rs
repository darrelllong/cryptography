//! Fuzz Edwards-ElGamal (twisted Edwards, ed25519): integer encrypt/decrypt
//! roundtrip.
//!
//! encrypt_int embeds a u64 into the curve group; decrypt_int recovers it via
//! baby-step-giant-step DLOG up to a fixed bound.  Invariant:
//!   decrypt_int(encrypt_int(m), MAX_MSG) == Some(m)   for  m < MAX_MSG
#![no_main]

use cryptography::{
    public_key::{ec_edwards::ed25519, edwards_elgamal::EdwardsElGamal},
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;
const MAX_MSG: u64 = 256;

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED + 1 {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().unwrap();
    let msg_int = data[SEED] as u64; // 0-255, always < MAX_MSG

    let mut rng = CtrDrbgAes256::new(&seed);
    let (pk, sk) = EdwardsElGamal::generate(ed25519(), &mut rng);

    let ct = pk.encrypt_int(msg_int, &mut rng);
    let recovered = sk.decrypt_int(&ct, MAX_MSG);

    assert_eq!(
        recovered,
        Some(msg_int),
        "Edwards-ElGamal ed25519: decrypt_int(encrypt_int({msg_int}), {MAX_MSG}) returned {recovered:?}",
    );
});
