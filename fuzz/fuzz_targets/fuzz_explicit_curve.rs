//! Explicit elliptic-curve domain parameters, the invalid-curve surface.
//!
//! `CurveParams::from_explicit` is what accepts parameters this crate did not
//! choose, so it is the gate an invalid-curve attack has to pass. Layout:
//! `[selector][u16 len][value]...` — seven values in the order `p`/`f(x)`,
//! `a`, `b`, `n`, `h`, `Gx`, `Gy`, with the selector picking the field kind
//! and, when the input is short, a named curve whose parameters are perturbed
//! instead. Perturbing a real curve is what reaches the deep checks: random
//! bytes almost never give a field size the security-level step admits.
//!
//! What must hold of an accepted curve: the base point lies on it and in the
//! prime-order subgroup, so it is a valid public point; the order is what
//! annihilates the base point; and the answer does not depend on how the
//! parameters arrived, so a curve accepted here equals the named curve when
//! nothing was perturbed.
#![no_main]

use cryptography::public_key::ec::{
    p192, p224, p256, p384, p521, secp256k1, AffinePoint, CurveParams, ExplicitField,
};
use cryptography::vt::BigUint;
use libfuzzer_sys::fuzz_target;

/// Take a `u16`-length-prefixed field, capped so one value cannot eat the
/// input.
fn take<'a>(data: &mut &'a [u8], cap: usize) -> &'a [u8] {
    if data.len() < 2 {
        *data = &[];
        return &[];
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]])).min(cap);
    let rest = &data[2..];
    let len = len.min(rest.len());
    let (field, tail) = rest.split_at(len);
    *data = tail;
    field
}

/// The named curves a perturbation starts from.
fn named(selector: u8) -> CurveParams {
    match selector % 6 {
        0 => p192(),
        1 => p224(),
        2 => p256(),
        3 => p384(),
        4 => p521(),
        _ => secp256k1(),
    }
}

/// What an accepted curve owes, whatever produced it.
fn check_accepted(curve: &CurveParams) {
    let g = curve.base_point();
    assert!(curve.is_on_curve(&g), "the base point is off the curve");
    assert!(
        curve.is_valid_public_point(&g),
        "the base point is not a valid public point"
    );
    assert!(
        curve.scalar_mul(&g, &curve.n).is_infinity(),
        "nG is not the point at infinity"
    );
    assert!(
        curve.is_in_prime_subgroup(&g),
        "the base point is outside the prime-order subgroup"
    );
    // The point at infinity is never a public key, and the encoding of a
    // point decodes back to it.
    assert!(!curve.is_valid_public_point(&AffinePoint::infinity()));
    let encoded = curve.encode_point(&g);
    assert_eq!(curve.decode_point(&encoded).as_ref(), Some(&g));
    let compressed = curve.encode_point_compressed(&g);
    assert_eq!(curve.decode_point(&compressed).as_ref(), Some(&g));
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    if selector & 0x80 == 0 {
        // A named curve with one field replaced by the fuzzer's bytes. The
        // curve is valid until the replacement, so every check before the
        // replaced field passes and the gate is reached.
        let base = named(selector);
        let replacement = BigUint::from_be_bytes(take(&mut data, 80));
        let which = (selector >> 3) % 8;
        let (p, a, b, n, gx, gy) = (
            base.p.clone(),
            base.a.clone(),
            base.b.clone(),
            base.n.clone(),
            base.gx.clone(),
            base.gy.clone(),
        );
        let mut cofactor = base.h;
        let (p, a, b, n, gx, gy) = match which {
            0 => (replacement, a, b, n, gx, gy),
            1 => (p, replacement, b, n, gx, gy),
            2 => (p, a, replacement, n, gx, gy),
            3 => (p, a, b, replacement, gx, gy),
            4 => (p, a, b, n, replacement, gy),
            5 => (p, a, b, n, gx, replacement),
            6 => {
                cofactor = replacement.to_u64().unwrap_or(u64::MAX);
                (p, a, b, n, gx, gy)
            }
            // Nothing replaced: a named curve must pass its own gate, and
            // come back as the curve it names.
            _ => (p, a, b, n, gx, gy),
        };
        let curve =
            CurveParams::from_explicit(ExplicitField::Prime(p), a, b, n, cofactor, gx, gy);
        if which == 7 {
            let curve = curve.expect("a named curve failed its own validation");
            assert!(
                curve.same_curve(&base),
                "the same parameters gave a different curve"
            );
            check_accepted(&curve);
        } else if let Some(curve) = curve {
            check_accepted(&curve);
        }
        return;
    }

    // Seven values straight from the input, over a prime or a binary field.
    let modulus = BigUint::from_be_bytes(take(&mut data, 80));
    let a = BigUint::from_be_bytes(take(&mut data, 80));
    let b = BigUint::from_be_bytes(take(&mut data, 80));
    let n = BigUint::from_be_bytes(take(&mut data, 80));
    let gx = BigUint::from_be_bytes(take(&mut data, 80));
    let gy = BigUint::from_be_bytes(take(&mut data, 80));
    let cofactor = u64::from(selector);

    let field = if selector & 0x40 == 0 {
        ExplicitField::Prime(modulus)
    } else {
        // The degree is the fuzzer's, not the modulus's, so the mismatch
        // `from_explicit` checks for is reachable.
        let degree = usize::from(selector & 0x3f) * 16;
        ExplicitField::Binary { modulus, degree }
    };

    if let Some(curve) = CurveParams::from_explicit(field, a, b, n, cofactor, gx, gy) {
        check_accepted(&curve);
    }
});
