//! RFC 7748, "Elliptic Curves for Security" (A. Langley, M. Hamburg,
//! S. Turner, January 2016), section 6: the X25519 and X448 Diffie-Hellman
//! test vectors (Alice's and Bob's private and public keys and their shared
//! secret).
//!
//! The section 5.2 single-step vectors and the 1- and 1000-iteration results
//! are already pinned by the unit tests in `src/public_key/x25519.rs` and
//! `src/public_key/x448.rs` (the 1 000 000-iteration results too, behind
//! `#[ignore]`), so only section 6 is added here. Each exchange is checked both
//! through the raw scalar-multiplication functions and through the key types.

mod common;

use common::decode_hex_array;
use cryptography::vt::{
    X25519PrivateKey, X25519PublicKey, X448PrivateKey, X448PublicKey, X25519, X448,
};

// RFC 7748 section 6.1, "Curve25519", test vector.
const X25519_ALICE_PRIVATE: &str =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const X25519_ALICE_PUBLIC: &str =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const X25519_BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const X25519_BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const X25519_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

// RFC 7748 section 6.2, "Curve448", test vector. Each value is printed on two
// 56-digit lines in the RFC; the halves are kept apart here the same way.
const X448_ALICE_PRIVATE: &str = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
    d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
const X448_ALICE_PUBLIC: &str = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
    22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
const X448_BOB_PRIVATE: &str = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
    6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
const X448_BOB_PUBLIC: &str = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
    27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
const X448_SHARED: &str = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
    b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

/// RFC 7748 section 6.1: X25519(a, 9), X25519(b, 9) and the shared K.
#[test]
fn section_6_1_x25519() {
    let a: [u8; 32] = decode_hex_array(X25519_ALICE_PRIVATE);
    let b: [u8; 32] = decode_hex_array(X25519_BOB_PRIVATE);
    let alice_public: [u8; 32] = decode_hex_array(X25519_ALICE_PUBLIC);
    let bob_public: [u8; 32] = decode_hex_array(X25519_BOB_PUBLIC);
    let shared: [u8; 32] = decode_hex_array(X25519_SHARED);
    let mut nine = [0u8; 32];
    nine[0] = 9;

    assert_eq!(X25519::scalar_mult(&a, &nine), alice_public, "X25519(a, 9)");
    assert_eq!(X25519::scalar_mult(&b, &nine), bob_public, "X25519(b, 9)");
    assert_eq!(
        X25519::scalar_mult_base(&a),
        alice_public,
        "scalar_mult_base(a)"
    );
    assert_eq!(
        X25519::scalar_mult_base(&b),
        bob_public,
        "scalar_mult_base(b)"
    );
    assert_eq!(
        X25519::scalar_mult(&a, &bob_public),
        shared,
        "X25519(a, K_B)"
    );
    assert_eq!(
        X25519::scalar_mult(&b, &alice_public),
        shared,
        "X25519(b, K_A)"
    );

    let alice = X25519PrivateKey::from_raw_bytes(&a);
    let bob = X25519PrivateKey::from_raw_bytes(&b);
    assert_eq!(alice.to_public_key().to_raw_bytes(), alice_public);
    assert_eq!(bob.to_public_key().to_raw_bytes(), bob_public);
    assert_eq!(
        alice.agree(&X25519PublicKey::from_raw_bytes(&bob_public)),
        Some(shared)
    );
    assert_eq!(
        bob.agree(&X25519PublicKey::from_raw_bytes(&alice_public)),
        Some(shared)
    );
}

/// RFC 7748 section 6.2: X448(a, 5), X448(b, 5) and the shared K.
#[test]
fn section_6_2_x448() {
    let a: [u8; 56] = decode_hex_array(X448_ALICE_PRIVATE);
    let b: [u8; 56] = decode_hex_array(X448_BOB_PRIVATE);
    let alice_public: [u8; 56] = decode_hex_array(X448_ALICE_PUBLIC);
    let bob_public: [u8; 56] = decode_hex_array(X448_BOB_PUBLIC);
    let shared: [u8; 56] = decode_hex_array(X448_SHARED);
    let mut five = [0u8; 56];
    five[0] = 5;

    assert_eq!(X448::scalar_mult(&a, &five), alice_public, "X448(a, 5)");
    assert_eq!(X448::scalar_mult(&b, &five), bob_public, "X448(b, 5)");
    assert_eq!(
        X448::scalar_mult_base(&a),
        alice_public,
        "scalar_mult_base(a)"
    );
    assert_eq!(
        X448::scalar_mult_base(&b),
        bob_public,
        "scalar_mult_base(b)"
    );
    assert_eq!(X448::scalar_mult(&a, &bob_public), shared, "X448(a, K_B)");
    assert_eq!(X448::scalar_mult(&b, &alice_public), shared, "X448(b, K_A)");

    let alice = X448PrivateKey::from_raw_bytes(&a);
    let bob = X448PrivateKey::from_raw_bytes(&b);
    assert_eq!(alice.to_public_key().to_raw_bytes(), alice_public);
    assert_eq!(bob.to_public_key().to_raw_bytes(), bob_public);
    assert_eq!(
        alice.agree(&X448PublicKey::from_raw_bytes(&bob_public)),
        Some(shared)
    );
    assert_eq!(
        bob.agree(&X448PublicKey::from_raw_bytes(&alice_public)),
        Some(shared)
    );
}
