//! Fuzz ECDH key agreement on P-256.
//!
//! Two independent keypairs are generated from corpus-seeded CSPRNGs.
//! Invariant: sk1.agree(pk2) == sk2.agree(pk1)  (Diffie-Hellman property).
#![no_main]

use cryptography::{
    public_key::{ec::p256, ecdh::Ecdh},
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;
const MIN: usize = SEED * 2;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let s1: [u8; SEED] = data[..SEED].try_into().unwrap();
    let s2: [u8; SEED] = data[SEED..MIN].try_into().unwrap();

    let mut rng1 = CtrDrbgAes256::new(&s1);
    let mut rng2 = CtrDrbgAes256::new(&s2);

    let (pk1, sk1) = Ecdh::generate(p256(), &mut rng1);
    let (pk2, sk2) = Ecdh::generate(p256(), &mut rng2);

    let ss1 = sk1.agree_x_coordinate(&pk2);
    let ss2 = sk2.agree_x_coordinate(&pk1);

    assert_eq!(
        ss1, ss2,
        "ECDH P-256: DH property violated: sk1.agree(pk2) != sk2.agree(pk1)",
    );
});
