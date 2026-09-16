//! ECDH on every named curve: two key pairs from input-seeded DRBGs agree on
//! the same x-coordinate; a public key re-encodes to the bytes it was parsed
//! from; arbitrary bytes presented as a peer key are refused, or accepted as
//! a point that agreement then completes without panicking (the parser
//! accepts compressed and uncompressed forms, so an accepted encoding need
//! not be the canonical one).
//!
//! Layout: `[curve][48-byte seed][48-byte seed][hostile public key bytes]`.
#![no_main]

use cryptography::{
    public_key::{
        ec::{
            b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384,
            p521, secp256k1, CurveParams,
        },
        ecdh::{Ecdh, EcdhPublicKey},
    },
    CtrDrbgAes256,
};
use libfuzzer_sys::fuzz_target;

const CURVES: [fn() -> CurveParams; 16] = [
    p192, p224, p256, p384, p521, secp256k1, b163, k163, b233, k233, b283, k283, b409, k409, b571,
    k571,
];
const SEED: usize = 48;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 2 * SEED {
        return;
    }
    let curve = CURVES[usize::from(data[0]) % CURVES.len()];
    let s1: [u8; SEED] = data[1..1 + SEED].try_into().expect("48 bytes");
    let s2: [u8; SEED] = data[1 + SEED..1 + 2 * SEED].try_into().expect("48 bytes");
    let hostile = &data[1 + 2 * SEED..];

    let (pk1, sk1) = Ecdh::generate(curve(), &mut CtrDrbgAes256::new(&s1));
    let (pk2, sk2) = Ecdh::generate(curve(), &mut CtrDrbgAes256::new(&s2));
    assert_eq!(
        sk1.agree_x_coordinate(&pk2),
        sk2.agree_x_coordinate(&pk1),
        "ECDH: agreement is symmetric"
    );

    let wire = pk1.to_wire_bytes();
    let again = EcdhPublicKey::from_wire_bytes(curve(), &wire).expect("own public key parses");
    assert_eq!(again.to_wire_bytes(), wire, "ECDH: public key re-encodes");

    if let Some(peer) = EcdhPublicKey::from_wire_bytes(curve(), hostile) {
        let _ = sk1.agree_x_coordinate(&peer);
    }
});
