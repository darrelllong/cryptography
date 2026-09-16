//! X25519 and X448 (RFC 7748) on arbitrary scalars and u-coordinates.
//!
//! Layout: `[curve][scalar][scalar][u]`. The functions must accept any bytes:
//! the scalar is clamped inside (§5, "decodeScalar25519/448"), and for X25519
//! the top bit of `u` is ignored, so a scalar already clamped and a `u` with
//! that bit cleared give the same result. Two scalars agree on the shared
//! point through each other's public keys, and the keyed `agree` returns
//! `None` exactly when the shared u-coordinate is all zeros (§6.1, the
//! small-order check).
#![no_main]

use cryptography::public_key::x25519::{X25519PrivateKey, X25519PublicKey, X25519};
use cryptography::public_key::x448::{X448PrivateKey, X448PublicKey, X448};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&curve, rest)) = data.split_first() else {
        return;
    };
    if curve % 2 == 0 {
        if rest.len() < 96 {
            return;
        }
        let a: [u8; 32] = rest[..32].try_into().expect("32 bytes");
        let b: [u8; 32] = rest[32..64].try_into().expect("32 bytes");
        let u: [u8; 32] = rest[64..96].try_into().expect("32 bytes");

        let mut clamped = a;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let mut masked = u;
        masked[31] &= 127;
        let out = X25519::scalar_mult(&a, &u);
        assert_eq!(
            out,
            X25519::scalar_mult(&clamped, &u),
            "X25519: scalar clamping"
        );
        assert_eq!(
            out,
            X25519::scalar_mult(&a, &masked),
            "X25519: top bit of u ignored"
        );

        let pa = X25519::scalar_mult_base(&a);
        let pb = X25519::scalar_mult_base(&b);
        assert_eq!(
            X25519::scalar_mult(&a, &pb),
            X25519::scalar_mult(&b, &pa),
            "X25519: agreement is symmetric"
        );

        let key = X25519PrivateKey::from_raw_bytes(&a);
        let peer = X25519PublicKey::from_raw_bytes(&u);
        let agreed = key.agree(&peer);
        assert_eq!(
            agreed.is_none(),
            out == [0u8; 32],
            "X25519: agree refuses exactly the zero output"
        );
        if let Some(shared) = agreed {
            assert_eq!(shared, out);
        }
        assert_eq!(
            key.to_public_key().to_raw_bytes(),
            pa,
            "X25519: public key is the base-point multiple"
        );
    } else {
        if rest.len() < 168 {
            return;
        }
        let a: [u8; 56] = rest[..56].try_into().expect("56 bytes");
        let b: [u8; 56] = rest[56..112].try_into().expect("56 bytes");
        let u: [u8; 56] = rest[112..168].try_into().expect("56 bytes");

        let mut clamped = a;
        clamped[0] &= 252;
        clamped[55] |= 128;
        let out = X448::scalar_mult(&a, &u);
        assert_eq!(
            out,
            X448::scalar_mult(&clamped, &u),
            "X448: scalar clamping"
        );

        let pa = X448::scalar_mult_base(&a);
        let pb = X448::scalar_mult_base(&b);
        assert_eq!(
            X448::scalar_mult(&a, &pb),
            X448::scalar_mult(&b, &pa),
            "X448: agreement is symmetric"
        );

        let key = X448PrivateKey::from_raw_bytes(&a);
        let peer = X448PublicKey::from_raw_bytes(&u);
        let agreed = key.agree(&peer);
        assert_eq!(
            agreed.is_none(),
            out == [0u8; 56],
            "X448: agree refuses exactly the zero output"
        );
        if let Some(shared) = agreed {
            assert_eq!(shared, out);
        }
        assert_eq!(
            key.to_public_key().to_raw_bytes(),
            pa,
            "X448: public key is the base-point multiple"
        );
    }
});
