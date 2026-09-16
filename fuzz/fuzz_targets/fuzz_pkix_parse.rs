//! Standard key encodings under hostile input: every PKCS #8 (RFC 5958),
//! SubjectPublicKeyInfo (RFC 5280), SEC 1 / RFC 5915, RFC 3279 parameter and
//! signature parser in the crate, in DER, BER and PEM.
//!
//! The first byte selects the parser; the rest is the payload. Each arm feeds
//! the payload to the strict DER parser, to the BER parser where one exists,
//! to the PEM parser as hostile text, and to the PEM parser wrapped as a
//! well-formed PEM block around the payload. A parser may refuse anything; it
//! may not panic. When it accepts, the encoding must be idempotent: the value
//! re-encodes, the re-encoding parses, and parsing the re-encoding then
//! re-encoding again gives the same bytes.
#![no_main]

use cryptography::public_key::{
    dh::{DhParams, DhPrivateKey, DhPublicKey},
    dsa::{DsaParams, DsaPrivateKey, DsaPublicKey, DsaSignature},
    ecdh::{EcdhPrivateKey, EcdhPublicKey},
    ecdsa::{EcdsaPrivateKey, EcdsaPublicKey, EcdsaSignature},
    ecies::{EciesPrivateKey, EciesPublicKey},
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    ml_dsa::{MlDsaPrivateKey, MlDsaPublicKey},
    ml_kem::{MlKemPrivateKey, MlKemPublicKey},
    rsa::{RsaPrivateKey, RsaPublicKey},
    x25519::{X25519PrivateKey, X25519PublicKey},
    x448::{X448PrivateKey, X448PublicKey},
};
use cryptography::CtrDrbgAes256;
use libfuzzer_sys::fuzz_target;

const ARMS: u8 = 29;

/// Parse, and when that succeeds require the encoding to be idempotent.
fn idempotent<T>(
    name: &str,
    input: &[u8],
    parse: impl Fn(&[u8]) -> Option<T>,
    encode: impl Fn(&T) -> Option<Vec<u8>>,
) {
    let Some(value) = parse(input) else {
        return;
    };
    // A value with no encoding in this form (an explicit curve has no
    // named-curve container) ends the check.
    let Some(once) = encode(&value) else {
        return;
    };
    let again = parse(&once).unwrap_or_else(|| panic!("{name}: the re-encoding does not parse"));
    let twice =
        encode(&again).unwrap_or_else(|| panic!("{name}: the re-parsed value has no encoding"));
    assert_eq!(once, twice, "{name}: encoding is not idempotent");
}

/// RFC 7468 PEM around `payload` under `label`.
fn pem(label: &str, payload: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = String::new();
    for chunk in payload.chunks(3) {
        let mut word = [0u8; 3];
        word[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, word[0], word[1], word[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                body.push(ALPHABET[((bits >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                body.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// One key type in one container: DER strictly, BER if the type has a BER
/// reader, PEM as hostile text, and PEM wrapped around the payload.
macro_rules! container {
    ($name:literal, $payload:expr, $label:literal,
     der: $der:expr, ber: $ber:expr, pem: $pem:expr, to_der: $to_der:expr, to_pem: $to_pem:expr) => {{
        idempotent(concat!($name, " DER"), $payload, $der, $to_der);
        idempotent(concat!($name, " BER"), $payload, $ber, $to_der);
        let hostile = String::from_utf8_lossy($payload).into_owned();
        idempotent(
            concat!($name, " PEM text"),
            hostile.as_bytes(),
            |b| $pem(std::str::from_utf8(b).ok()?),
            $to_pem,
        );
        let wrapped = pem($label, $payload);
        idempotent(
            concat!($name, " PEM"),
            wrapped.as_bytes(),
            |b| $pem(std::str::from_utf8(b).ok()?),
            $to_pem,
        );
    }};
    ($name:literal, $payload:expr, $label:literal,
     der: $der:expr, pem: $pem:expr, to_der: $to_der:expr, to_pem: $to_pem:expr) => {{
        idempotent(concat!($name, " DER"), $payload, $der, $to_der);
        let hostile = String::from_utf8_lossy($payload).into_owned();
        idempotent(
            concat!($name, " PEM text"),
            hostile.as_bytes(),
            |b| $pem(std::str::from_utf8(b).ok()?),
            $to_pem,
        );
        let wrapped = pem($label, $payload);
        idempotent(
            concat!($name, " PEM"),
            wrapped.as_bytes(),
            |b| $pem(std::str::from_utf8(b).ok()?),
            $to_pem,
        );
    }};
}

fn rng() -> CtrDrbgAes256 {
    // Fixed seed: the import's pair-wise consistency test needs randomness,
    // the parse result does not depend on it.
    CtrDrbgAes256::new(&[0u8; 48])
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    match selector % ARMS {
        0 => container!("RSA SPKI", payload, "PUBLIC KEY",
            der: RsaPublicKey::from_spki_der, pem: RsaPublicKey::from_spki_pem,
            to_der: |k: &RsaPublicKey| Some(k.to_spki_der()),
            to_pem: |k: &RsaPublicKey| Some(k.to_spki_pem().into_bytes())),
        1 => container!("RSA PKCS #8", payload, "PRIVATE KEY",
            der: RsaPrivateKey::from_pkcs8_der, ber: RsaPrivateKey::from_pkcs8_ber,
            pem: RsaPrivateKey::from_pkcs8_pem,
            to_der: |k: &RsaPrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &RsaPrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        2 => container!("ECDSA SPKI", payload, "PUBLIC KEY",
            der: EcdsaPublicKey::from_spki_der, pem: EcdsaPublicKey::from_spki_pem,
            to_der: |k: &EcdsaPublicKey| k.to_spki_der(),
            to_pem: |k: &EcdsaPublicKey| k.to_spki_pem().map(String::into_bytes)),
        3 => container!("ECDSA SEC 1", payload, "EC PRIVATE KEY",
            der: EcdsaPrivateKey::from_sec1_der, ber: EcdsaPrivateKey::from_sec1_ber,
            pem: EcdsaPrivateKey::from_sec1_pem,
            to_der: |k: &EcdsaPrivateKey| k.to_sec1_der(),
            to_pem: |k: &EcdsaPrivateKey| k.to_sec1_pem().map(String::into_bytes)),
        4 => container!("ECDSA PKCS #8", payload, "PRIVATE KEY",
            der: EcdsaPrivateKey::from_pkcs8_der, ber: EcdsaPrivateKey::from_pkcs8_ber,
            pem: EcdsaPrivateKey::from_pkcs8_pem,
            to_der: |k: &EcdsaPrivateKey| k.to_pkcs8_der(),
            to_pem: |k: &EcdsaPrivateKey| k.to_pkcs8_pem().map(String::into_bytes)),
        5 => container!("ECDH SPKI", payload, "PUBLIC KEY",
            der: EcdhPublicKey::from_spki_der, pem: EcdhPublicKey::from_spki_pem,
            to_der: |k: &EcdhPublicKey| k.to_spki_der(),
            to_pem: |k: &EcdhPublicKey| k.to_spki_pem().map(String::into_bytes)),
        6 => container!("ECDH SEC 1", payload, "EC PRIVATE KEY",
            der: EcdhPrivateKey::from_sec1_der, ber: EcdhPrivateKey::from_sec1_ber,
            pem: EcdhPrivateKey::from_sec1_pem,
            to_der: |k: &EcdhPrivateKey| k.to_sec1_der(),
            to_pem: |k: &EcdhPrivateKey| k.to_sec1_pem().map(String::into_bytes)),
        7 => container!("ECDH PKCS #8", payload, "PRIVATE KEY",
            der: EcdhPrivateKey::from_pkcs8_der, ber: EcdhPrivateKey::from_pkcs8_ber,
            pem: EcdhPrivateKey::from_pkcs8_pem,
            to_der: |k: &EcdhPrivateKey| k.to_pkcs8_der(),
            to_pem: |k: &EcdhPrivateKey| k.to_pkcs8_pem().map(String::into_bytes)),
        8 => container!("ECIES SPKI", payload, "PUBLIC KEY",
            der: EciesPublicKey::from_spki_der, pem: EciesPublicKey::from_spki_pem,
            to_der: |k: &EciesPublicKey| k.to_spki_der(),
            to_pem: |k: &EciesPublicKey| k.to_spki_pem().map(String::into_bytes)),
        9 => container!("ECIES SEC 1", payload, "EC PRIVATE KEY",
            der: EciesPrivateKey::from_sec1_der, ber: EciesPrivateKey::from_sec1_ber,
            pem: EciesPrivateKey::from_sec1_pem,
            to_der: |k: &EciesPrivateKey| k.to_sec1_der(),
            to_pem: |k: &EciesPrivateKey| k.to_sec1_pem().map(String::into_bytes)),
        10 => container!("ECIES PKCS #8", payload, "PRIVATE KEY",
            der: EciesPrivateKey::from_pkcs8_der, ber: EciesPrivateKey::from_pkcs8_ber,
            pem: EciesPrivateKey::from_pkcs8_pem,
            to_der: |k: &EciesPrivateKey| k.to_pkcs8_der(),
            to_pem: |k: &EciesPrivateKey| k.to_pkcs8_pem().map(String::into_bytes)),
        11 => container!("DH SPKI", payload, "PUBLIC KEY",
            der: DhPublicKey::from_spki_der, pem: DhPublicKey::from_spki_pem,
            to_der: |k: &DhPublicKey| Some(k.to_spki_der()),
            to_pem: |k: &DhPublicKey| Some(k.to_spki_pem().into_bytes())),
        12 => container!("DH PKCS #8", payload, "PRIVATE KEY",
            der: DhPrivateKey::from_pkcs8_der, ber: DhPrivateKey::from_pkcs8_ber,
            pem: DhPrivateKey::from_pkcs8_pem,
            to_der: |k: &DhPrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &DhPrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        13 => container!("DSA SPKI", payload, "PUBLIC KEY",
            der: DsaPublicKey::from_spki_der, pem: DsaPublicKey::from_spki_pem,
            to_der: |k: &DsaPublicKey| Some(k.to_spki_der()),
            to_pem: |k: &DsaPublicKey| Some(k.to_spki_pem().into_bytes())),
        14 => container!("DSA PKCS #8", payload, "PRIVATE KEY",
            der: DsaPrivateKey::from_pkcs8_der, ber: DsaPrivateKey::from_pkcs8_ber,
            pem: DsaPrivateKey::from_pkcs8_pem,
            to_der: |k: &DsaPrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &DsaPrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        15 => idempotent(
            "DH DomainParameters",
            payload,
            DhParams::from_der,
            |p: &DhParams| Some(p.to_der()),
        ),
        16 => idempotent(
            "Dss-Parms",
            payload,
            DsaParams::from_der,
            |p: &DsaParams| Some(p.to_der()),
        ),
        17 => idempotent(
            "DSA Dss-Sig-Value",
            payload,
            DsaSignature::from_der,
            |s: &DsaSignature| Some(s.to_der()),
        ),
        18 => idempotent(
            "ECDSA-Sig-Value",
            payload,
            EcdsaSignature::from_der,
            |s: &EcdsaSignature| Some(s.to_der()),
        ),
        19 => container!("Ed25519 SPKI", payload, "PUBLIC KEY",
            der: Ed25519PublicKey::from_spki_der, pem: Ed25519PublicKey::from_spki_pem,
            to_der: |k: &Ed25519PublicKey| Some(k.to_spki_der()),
            to_pem: |k: &Ed25519PublicKey| Some(k.to_spki_pem().into_bytes())),
        20 => container!("Ed25519 PKCS #8", payload, "PRIVATE KEY",
            der: Ed25519PrivateKey::from_pkcs8_der, ber: Ed25519PrivateKey::from_pkcs8_ber,
            pem: Ed25519PrivateKey::from_pkcs8_pem,
            to_der: |k: &Ed25519PrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &Ed25519PrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        21 => container!("X25519 SPKI", payload, "PUBLIC KEY",
            der: X25519PublicKey::from_spki_der, pem: X25519PublicKey::from_spki_pem,
            to_der: |k: &X25519PublicKey| Some((*k).to_spki_der()),
            to_pem: |k: &X25519PublicKey| Some((*k).to_spki_pem().into_bytes())),
        22 => container!("X25519 PKCS #8", payload, "PRIVATE KEY",
            der: X25519PrivateKey::from_pkcs8_der, ber: X25519PrivateKey::from_pkcs8_ber,
            pem: X25519PrivateKey::from_pkcs8_pem,
            to_der: |k: &X25519PrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &X25519PrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        23 => container!("X448 SPKI", payload, "PUBLIC KEY",
            der: X448PublicKey::from_spki_der, pem: X448PublicKey::from_spki_pem,
            to_der: |k: &X448PublicKey| Some((*k).to_spki_der()),
            to_pem: |k: &X448PublicKey| Some((*k).to_spki_pem().into_bytes())),
        24 => container!("X448 PKCS #8", payload, "PRIVATE KEY",
            der: X448PrivateKey::from_pkcs8_der, ber: X448PrivateKey::from_pkcs8_ber,
            pem: X448PrivateKey::from_pkcs8_pem,
            to_der: |k: &X448PrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &X448PrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        25 => container!("ML-KEM SPKI", payload, "PUBLIC KEY",
            der: MlKemPublicKey::from_spki_der, pem: MlKemPublicKey::from_spki_pem,
            to_der: |k: &MlKemPublicKey| Some(k.to_spki_der()),
            to_pem: |k: &MlKemPublicKey| Some(k.to_spki_pem().into_bytes())),
        26 => container!("ML-KEM PKCS #8", payload, "PRIVATE KEY",
            der: |b: &[u8]| MlKemPrivateKey::from_pkcs8_der(b, &mut rng()),
            ber: |b: &[u8]| MlKemPrivateKey::from_pkcs8_ber(b, &mut rng()),
            pem: |s: &str| MlKemPrivateKey::from_pkcs8_pem(s, &mut rng()),
            to_der: |k: &MlKemPrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &MlKemPrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
        27 => container!("ML-DSA SPKI", payload, "PUBLIC KEY",
            der: MlDsaPublicKey::from_spki_der, pem: MlDsaPublicKey::from_spki_pem,
            to_der: |k: &MlDsaPublicKey| Some(k.to_spki_der()),
            to_pem: |k: &MlDsaPublicKey| Some(k.to_spki_pem().into_bytes())),
        _ => container!("ML-DSA PKCS #8", payload, "PRIVATE KEY",
            der: MlDsaPrivateKey::from_pkcs8_der, ber: MlDsaPrivateKey::from_pkcs8_ber,
            pem: MlDsaPrivateKey::from_pkcs8_pem,
            to_der: |k: &MlDsaPrivateKey| Some(k.to_pkcs8_der()),
            to_pem: |k: &MlDsaPrivateKey| Some(k.to_pkcs8_pem().into_bytes())),
    }
});
