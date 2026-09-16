//! ECDSA on every named curve, from a fuzzer-chosen secret scalar, nonce and
//! digest.
//!
//! Layout: `[curve][secret scalar][nonce][digest]`, the three fields each as
//! wide as the curve's order rounded up to bytes, the scalar and nonce
//! masked to the order's bit width so that about half the draws are in
//! range and the rest exercise the range checks. A signature
//! verifies under its digest reduced as FIPS 186-4 §6.4 reduces it (the
//! leftmost `min(N, outlen)` bits), the low-`s` form verifies too, a digest
//! with one flipped bit does not verify, and the DER form re-encodes to the
//! bytes it was parsed from.
#![no_main]

use cryptography::public_key::ec::{
    b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384, p521,
    secp256k1, CurveParams,
};
use cryptography::public_key::ecdsa::{Ecdsa, EcdsaSignature};
use cryptography::vt::BigUint;
use libfuzzer_sys::fuzz_target;

const CURVES: [fn() -> CurveParams; 16] = [
    p192, p224, p256, p384, p521, secp256k1, b163, k163, b233, k233, b283, k283, b409, k409, b571,
    k571,
];

/// FIPS 186-4 §6.4 step 2: the leftmost `min(N, outlen)` bits of the digest.
fn digest_representative(digest: &[u8], n_bits: usize) -> BigUint {
    let mut value = BigUint::from_be_bytes(digest);
    let digest_bits = digest.len() * 8;
    if digest_bits > n_bits {
        value.shr_bits(digest_bits - n_bits);
    }
    value
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let curve = CURVES[usize::from(selector) % CURVES.len()]();
    let n_bits = curve.n.bits();
    let width = n_bits.div_ceil(8);
    if rest.len() < 3 * width {
        return;
    }
    let masked = |bytes: &[u8]| {
        let mut v = bytes.to_vec();
        v[0] &= 0xFFu8 >> (8 * width - n_bits);
        BigUint::from_be_bytes(&v)
    };
    let secret = masked(&rest[..width]);
    let nonce = masked(&rest[width..2 * width]);
    let digest = &rest[2 * width..3 * width];

    let Some((pk, sk)) = Ecdsa::from_secret_scalar(curve.clone(), &secret) else {
        return;
    };
    let Some(sig) = sk.sign_digest_with_nonce(digest, &nonce) else {
        return;
    };
    let e = digest_representative(digest, n_bits);
    assert!(
        pk.verify_digest_scalar(&e, &sig),
        "ECDSA: the honest signature verifies"
    );
    assert!(
        pk.verify_digest_scalar(&e, &sig.to_low_s(&curve)),
        "ECDSA: the low-s form verifies"
    );

    let mut bad = digest.to_vec();
    bad[0] ^= 1;
    assert!(
        !pk.verify_digest_scalar(&digest_representative(&bad, n_bits), &sig),
        "ECDSA: a flipped digest verified"
    );

    let der = sig.to_der();
    let again = EcdsaSignature::from_der(&der).expect("own DER parses");
    assert_eq!(again.to_der(), der, "ECDSA: ECDSA-Sig-Value re-encodes");
});
