//! Edwards-curve Diffie-Hellman on ed25519: two key pairs from input-seeded
//! DRBGs agree on the same compressed point; a public key re-encodes to the
//! bytes it was parsed from; and arbitrary bytes presented as a public key
//! are either refused or a valid point that agreement accepts.
#![no_main]

use cryptography::{
    public_key::{
        ec_edwards::ed25519,
        edwards_dh::{EdwardsDh, EdwardsDhPublicKey},
    },
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 * SEED {
        return;
    }
    let s1: [u8; SEED] = data[..SEED].try_into().expect("48 bytes");
    let s2: [u8; SEED] = data[SEED..2 * SEED].try_into().expect("48 bytes");
    let hostile = &data[2 * SEED..];

    let (pk1, sk1) = EdwardsDh::generate(ed25519(), &mut CtrDrbgAes256::new(&s1));
    let (pk2, sk2) = EdwardsDh::generate(ed25519(), &mut CtrDrbgAes256::new(&s2));
    assert_eq!(
        sk1.agree_compressed_point(&pk2),
        sk2.agree_compressed_point(&pk1),
        "Edwards-DH: agreement is symmetric"
    );

    let wire = pk1.to_wire_bytes();
    let again =
        EdwardsDhPublicKey::from_wire_bytes(ed25519(), &wire).expect("own public key parses");
    assert_eq!(
        again.to_wire_bytes(),
        wire,
        "Edwards-DH: public key re-encodes"
    );

    if let Some(peer) = EdwardsDhPublicKey::from_wire_bytes(ed25519(), hostile) {
        assert_eq!(
            peer.to_wire_bytes(),
            hostile,
            "Edwards-DH: an accepted encoding is canonical"
        );
        assert!(
            sk1.agree_compressed_point(&peer).is_some(),
            "Edwards-DH: agreement refused a point the parser validated"
        );
    }
});
