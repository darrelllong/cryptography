//! RFC 8032 `Ed25519`.
//!
//! This module provides the standard Ed25519 key and signature format:
//!
//! - private key: 32-byte seed
//! - public key: 32-byte encoded Edwards point
//! - signature: 64 bytes, `R || S`
//!
//! Unlike the generic [`crate::public_key::eddsa`] layer, this module follows
//! the RFC 8032 seed-hash-and-clamp flow exactly:
//!
//! 1. `h = SHA-512(seed)`
//! 2. clamp the lower 32 bytes of `h` to derive the secret scalar `a`
//! 3. use the upper 32 bytes of `h` as the deterministic nonce prefix
//! 4. sign with `r = H(prefix || M) mod n`
//! 5. challenge `k = H(R || A || M) mod n`
//! 6. response `S = r + k·a mod n`

use core::fmt;
use std::sync::OnceLock;

use crate::public_key::bigint::BigUint;
use crate::public_key::ec_edwards::{ed25519, EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{pem_unwrap, pem_wrap, xml_unwrap, xml_wrap};
use crate::Sha512;
use crate::Csprng;

const ED25519_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ED25519 PUBLIC KEY";
const ED25519_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ED25519 PRIVATE KEY";

/// Standard 32-byte Ed25519 public key.
#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519PublicKey {
    point: EdwardsPoint,
}

/// Standard 32-byte Ed25519 private seed plus derived signing state.
#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
    scalar: BigUint,
    prefix: [u8; 32],
    public: Ed25519PublicKey,
}

/// Standard 64-byte Ed25519 signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519Signature {
    r_point: EdwardsPoint,
    s: BigUint,
}

/// Namespace wrapper for the fixed-curve Ed25519 construction.
pub struct Ed25519;

impl Ed25519PublicKey {
    /// Return the decoded Edwards public point `A`.
    #[must_use]
    pub fn public_point(&self) -> &EdwardsPoint {
        &self.point
    }

    /// Standard 32-byte compressed public key.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        curve().encode_point(&self.point)
    }

    /// Parse the standard 32-byte compressed public key.
    #[must_use]
    pub fn from_binary(bytes: &[u8]) -> Option<Self> {
        let point = decode_point_strict(bytes)?;
        if !point_in_prime_subgroup(&point) {
            return None;
        }
        Some(Self { point })
    }

    /// PEM-armored wrapper around the standard 32-byte public key.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ED25519_PUBLIC_LABEL, &self.to_binary())
    }

    /// Parse the PEM-armored public key.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let bytes = pem_unwrap(ED25519_PUBLIC_LABEL, pem)?;
        Self::from_binary(&bytes)
    }

    /// XML wrapper around the standard 32-byte public key.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let public = BigUint::from_be_bytes(&self.to_binary());
        xml_wrap("Ed25519PublicKey", &[("public", &public)])
    }

    /// Parse the XML-wrapped public key.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("Ed25519PublicKey", &["public"], xml)?.into_iter();
        let public = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let bytes = biguint_to_fixed_be(&public, 32)?;
        Self::from_binary(&bytes)
    }

    /// Verify a standard signature over the message.
    #[must_use]
    pub fn verify_message(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        if signature.s >= curve().n {
            return false;
        }
        if !point_in_prime_subgroup(&signature.r_point) {
            return false;
        }

        let challenge = challenge_scalar(&signature.r_point, &self.point, message);
        let lhs = curve().scalar_mul(&curve().base_point(), &signature.s);
        let rhs = curve().add(
            &signature.r_point,
            &curve().scalar_mul(&self.point, &challenge),
        );
        lhs == rhs
    }

    /// Verify a standard 64-byte signature.
    #[must_use]
    pub fn verify_message_bytes(&self, message: &[u8], signature: &[u8]) -> bool {
        let Some(signature) = Ed25519Signature::from_binary(signature) else {
            return false;
        };
        self.verify_message(message, &signature)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519PublicKey")
            .field(&hex_encode(&self.to_binary()))
            .finish()
    }
}

impl Ed25519PrivateKey {
    /// Return the original 32-byte secret seed.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Return the clamped secret scalar derived from the seed.
    #[must_use]
    pub fn scalar(&self) -> &BigUint {
        &self.scalar
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> Ed25519PublicKey {
        self.public.clone()
    }

    /// Standard 32-byte private-key encoding (the seed).
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Parse the standard 32-byte private-key encoding (the seed).
    #[must_use]
    pub fn from_binary(bytes: &[u8]) -> Option<Self> {
        let seed: [u8; 32] = bytes.try_into().ok()?;
        Some(expand_seed(seed))
    }

    /// PEM-armored wrapper around the standard 32-byte seed.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ED25519_PRIVATE_LABEL, &self.to_binary())
    }

    /// Parse the PEM-armored private key.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let bytes = pem_unwrap(ED25519_PRIVATE_LABEL, pem)?;
        Self::from_binary(&bytes)
    }

    /// XML wrapper around the standard 32-byte seed.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let seed = BigUint::from_be_bytes(&self.seed);
        xml_wrap("Ed25519PrivateKey", &[("seed", &seed)])
    }

    /// Parse the XML-wrapped private key.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("Ed25519PrivateKey", &["seed"], xml)?.into_iter();
        let seed = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let bytes = biguint_to_fixed_be(&seed, 32)?;
        Self::from_binary(&bytes)
    }

    /// Sign one message using the deterministic RFC 8032 nonce derivation.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> Ed25519Signature {
        let mut nonce_input = Vec::with_capacity(self.prefix.len() + message.len());
        nonce_input.extend_from_slice(&self.prefix);
        nonce_input.extend_from_slice(message);
        let r = le_bytes_to_biguint(&Sha512::digest(&nonce_input)).modulo(&curve().n);
        let r_point = curve().scalar_mul(&curve().base_point(), &r);
        let challenge = challenge_scalar(&r_point, &self.public.point, message);
        let ka = BigUint::mod_mul(&challenge, &self.scalar, &curve().n);
        let s = r.add_ref(&ka).modulo(&curve().n);
        Ed25519Signature { r_point, s }
    }

    /// Sign and return the standard 64-byte `R || S` form.
    #[must_use]
    pub fn sign_message_bytes(&self, message: &[u8]) -> Vec<u8> {
        self.sign_message(message).to_binary()
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519PrivateKey(<redacted>)")
    }
}

impl Ed25519Signature {
    /// Return the nonce point `R`.
    #[must_use]
    pub fn nonce_point(&self) -> &EdwardsPoint {
        &self.r_point
    }

    /// Return the response scalar `S`.
    #[must_use]
    pub fn response(&self) -> &BigUint {
        &self.s
    }

    /// Standard 64-byte signature encoding `R || S`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        let mut out = curve().encode_point(&self.r_point);
        out.extend_from_slice(&biguint_to_fixed_le(&self.s, 32));
        out
    }

    /// Parse the standard 64-byte signature encoding `R || S`.
    #[must_use]
    pub fn from_binary(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        let r_point = decode_point_strict(&bytes[..32])?;
        let s = le_bytes_to_biguint(&bytes[32..]);
        if s >= curve().n {
            return None;
        }
        Some(Self { r_point, s })
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519Signature")
            .field(&hex_encode(&self.to_binary()))
            .finish()
    }
}

impl Ed25519 {
    /// Generate a random Ed25519 key pair from a fresh 32-byte seed.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R) -> (Ed25519PublicKey, Ed25519PrivateKey) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let private = expand_seed(seed);
        let public = private.to_public_key();
        (public, private)
    }

    /// Derive a key pair from an explicit 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> (Ed25519PublicKey, Ed25519PrivateKey) {
        let private = expand_seed(seed);
        let public = private.to_public_key();
        (public, private)
    }
}

/// Shared Ed25519 curve parameters, cached once for the process.
fn curve() -> &'static TwistedEdwardsCurve {
    static CURVE: OnceLock<TwistedEdwardsCurve> = OnceLock::new();
    CURVE.get_or_init(ed25519)
}

/// Expand a 32-byte RFC 8032 secret seed into signing state.
fn expand_seed(seed: [u8; 32]) -> Ed25519PrivateKey {
    let digest = Sha512::digest(&seed);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    clamp_scalar(&mut scalar_bytes);
    let scalar = le_bytes_to_biguint(&scalar_bytes);

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&digest[32..64]);

    let a_point = curve().scalar_mul(&curve().base_point(), &scalar);
    let public = Ed25519PublicKey { point: a_point };

    Ed25519PrivateKey {
        seed,
        scalar,
        prefix,
        public,
    }
}

/// RFC 8032 Ed25519 scalar clamping.
fn clamp_scalar(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 63;
    bytes[31] |= 64;
}

/// Compute the Ed25519 challenge scalar `k = H(R || A || M) mod n`.
fn challenge_scalar(r_point: &EdwardsPoint, a_point: &EdwardsPoint, message: &[u8]) -> BigUint {
    let mut transcript = curve().encode_point(r_point);
    transcript.extend_from_slice(&curve().encode_point(a_point));
    transcript.extend_from_slice(message);
    le_bytes_to_biguint(&Sha512::digest(&transcript)).modulo(&curve().n)
}

/// Strict point decode: standard length, canonical `y`, on-curve, and subgroup-safe.
fn decode_point_strict(bytes: &[u8]) -> Option<EdwardsPoint> {
    if bytes.len() != 32 {
        return None;
    }
    let mut y_bytes = bytes.to_vec();
    *y_bytes.last_mut()? &= 0x7f;
    let y = le_bytes_to_biguint(&y_bytes);
    if y >= curve().p {
        return None;
    }
    let point = curve().decode_point(bytes)?;
    if point.is_neutral() {
        return None;
    }
    Some(point)
}

/// Prime-subgroup membership: `l·P = 0`.
fn point_in_prime_subgroup(point: &EdwardsPoint) -> bool {
    curve().scalar_mul(point, &curve().n).is_neutral()
}

/// Little-endian bytes to `BigUint`.
fn le_bytes_to_biguint(bytes: &[u8]) -> BigUint {
    let mut be = bytes.to_vec();
    be.reverse();
    BigUint::from_be_bytes(&be)
}

/// Fixed-width little-endian encoding.
fn biguint_to_fixed_le(value: &BigUint, len: usize) -> Vec<u8> {
    let mut be = value.to_be_bytes();
    if be.len() < len {
        let mut padded = vec![0u8; len - be.len()];
        padded.extend_from_slice(&be);
        be = padded;
    }
    be.reverse();
    be
}

fn biguint_to_fixed_be(value: &BigUint, len: usize) -> Option<Vec<u8>> {
    let bytes = value.to_be_bytes();
    if bytes.len() > len {
        return None;
    }
    if bytes.len() == len {
        return Some(bytes);
    }
    let mut padded = vec![0u8; len - bytes.len()];
    padded.extend_from_slice(&bytes);
    Some(padded)
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(TABLE[usize::from(byte >> 4)]));
        out.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
    use crate::CtrDrbgAes256;

    fn decode_hex(hex: &str) -> Vec<u8> {
        let bytes = hex.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            let hi = (chunk[0] as char).to_digit(16).expect("hex") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    #[test]
    fn rfc8032_test_vector_1() {
        let seed = decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = decode_hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let seed: [u8; 32] = seed.try_into().expect("seed length");
        let (derived_public, private) = Ed25519::from_seed(seed);
        assert_eq!(derived_public.to_binary(), public);
        assert_eq!(private.to_binary(), seed);

        let sig = private.sign_message(b"");
        assert_eq!(sig.to_binary(), signature);
        assert!(derived_public.verify_message_bytes(b"", &signature));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x42; 48]));
        let sig = private.sign_message(b"ed25519 roundtrip");
        assert!(public.verify_message(b"ed25519 roundtrip", &sig));
        assert!(!public.verify_message(b"wrong", &sig));
    }

    #[test]
    fn signature_binary_roundtrip() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x24; 48]));
        let sig = private.sign_message(b"serialize");
        let blob = sig.to_binary();
        let decoded = Ed25519Signature::from_binary(&blob).expect("decode");
        assert_eq!(decoded, sig);
        assert!(public.verify_message(b"serialize", &decoded));
    }

    #[test]
    fn key_binary_roundtrip() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x11; 48]));
        assert_eq!(
            Ed25519PublicKey::from_binary(&public.to_binary()).expect("public"),
            public
        );
        let private_round = Ed25519PrivateKey::from_binary(&private.to_binary()).expect("private");
        assert_eq!(private_round, private);
        assert_eq!(private_round.to_public_key(), public);
    }

    #[test]
    fn key_xml_roundtrip() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x2a; 48]));
        let public_round = Ed25519PublicKey::from_xml(&public.to_xml()).expect("public xml");
        let private_round = Ed25519PrivateKey::from_xml(&private.to_xml()).expect("private xml");
        assert_eq!(public_round, public);
        assert_eq!(private_round, private);
        assert_eq!(private_round.to_public_key(), public);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x77; 48]));
        let mut sig = private.sign_message_bytes(b"tamper");
        sig[63] ^= 0x01;
        assert!(!public.verify_message_bytes(b"tamper", &sig));
    }
}
