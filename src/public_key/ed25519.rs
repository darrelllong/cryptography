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
use crate::public_key::ec_edwards::{ed25519, EdwardsMulTable, EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{pem_unwrap, pem_wrap, xml_unwrap, xml_wrap};
use crate::Csprng;
use crate::Sha512;

const ED25519_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ED25519 PUBLIC KEY";
const ED25519_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ED25519 PRIVATE KEY";

/// Standard 32-byte Ed25519 public key.
#[derive(Clone)]
pub struct Ed25519PublicKey {
    point: EdwardsPoint,
    point_table: EdwardsMulTable,
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

    /// Preferred explicit name for the standard 32-byte compressed public key.
    #[must_use]
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        self.to_binary()
    }

    /// Parse the standard 32-byte compressed public key.
    #[must_use]
    pub fn from_binary(bytes: &[u8]) -> Option<Self> {
        let point = decode_point_strict(bytes)?;
        if !point_in_prime_subgroup(&point) {
            return None;
        }
        let point_table = curve().precompute_mul_table(&point);
        Some(Self { point, point_table })
    }

    /// Preferred explicit name for the standard 32-byte compressed public key.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_binary(bytes)
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
        let lhs = curve().scalar_mul_base(&signature.s);
        let rhs = curve().add(
            &signature.r_point,
            &curve().scalar_mul_cached(&self.point_table, &challenge),
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

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Eq for Ed25519PublicKey {}

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

    /// Preferred explicit name for the standard 32-byte private seed.
    #[must_use]
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        self.to_binary()
    }

    /// Parse the standard 32-byte private-key encoding (the seed).
    #[must_use]
    pub fn from_binary(bytes: &[u8]) -> Option<Self> {
        let seed: [u8; 32] = bytes.try_into().ok()?;
        Some(expand_seed(seed))
    }

    /// Preferred explicit name for the standard 32-byte private seed.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_binary(bytes)
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
        let r_point = curve().scalar_mul_base(&r);
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

    let a_point = curve().scalar_mul_base(&scalar);
    let public = Ed25519PublicKey {
        point: a_point.clone(),
        point_table: curve().precompute_mul_table(&a_point),
    };

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
    use super::{
        biguint_to_fixed_le, curve, Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    };
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

    fn assert_rfc8032_vector(
        seed_hex: &str,
        public_hex: &str,
        message_hex: &str,
        signature_hex: &str,
    ) {
        let seed = decode_hex(seed_hex);
        let public = decode_hex(public_hex);
        let message = decode_hex(message_hex);
        let signature = decode_hex(signature_hex);

        let seed: [u8; 32] = seed.try_into().expect("seed length");
        let (derived_public, private) = Ed25519::from_seed(seed);
        assert_eq!(derived_public.to_binary(), public);
        assert_eq!(private.to_binary(), seed);

        let sig = private.sign_message(&message);
        assert_eq!(sig.to_binary(), signature);
        assert!(derived_public.verify_message(&message, &sig));
        assert!(derived_public.verify_message_bytes(&message, &signature));
    }

    #[test]
    fn rfc8032_test_vectors() {
        assert_rfc8032_vector(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
        );

        assert_rfc8032_vector(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        );

        assert_rfc8032_vector(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            concat!(
                "6291d657deec24024827e69c3abe01a3",
                "0ce548a284743a445e3680d7db5ac3ac",
                "18ff9b538d16f290ae67f760984dc659",
                "4a7c15e9716ed28dc027beceea1ec40a",
            ),
        );

        assert_rfc8032_vector(
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            concat!(
                "08b8b2b733424243760fe426a4b54908",
                "632110a66c2f6591eabd3345e3e4eb98",
                "fa6e264bf09efe12ee50f8f54e9f77b1",
                "e355f6c50544e23fb1433ddf73be84d8",
                "79de7c0046dc4996d9e773f4bc9efe57",
                "38829adb26c81b37c93a1b270b20329d",
                "658675fc6ea534e0810a4432826bf58c",
                "941efb65d57a338bbd2e26640f89ffbc",
                "1a858efcb8550ee3a5e1998bd177e93a",
                "7363c344fe6b199ee5d02e82d522c4fe",
                "ba15452f80288a821a579116ec6dad2b",
                "3b310da903401aa62100ab5d1a36553e",
                "06203b33890cc9b832f79ef80560ccb9",
                "a39ce767967ed628c6ad573cb116dbef",
                "efd75499da96bd68a8a97b928a8bbc10",
                "3b6621fcde2beca1231d206be6cd9ec7",
                "aff6f6c94fcd7204ed3455c68c83f4a4",
                "1da4af2b74ef5c53f1d8ac70bdcb7ed1",
                "85ce81bd84359d44254d95629e9855a9",
                "4a7c1958d1f8ada5d0532ed8a5aa3fb2",
                "d17ba70eb6248e594e1a2297acbbb39d",
                "502f1a8c6eb6f1ce22b3de1a1f40cc24",
                "554119a831a9aad6079cad88425de6bd",
                "e1a9187ebb6092cf67bf2b13fd65f270",
                "88d78b7e883c8759d2c4f5c65adb7553",
                "878ad575f9fad878e80a0c9ba63bcbcc",
                "2732e69485bbc9c90bfbd62481d9089b",
                "eccf80cfe2df16a2cf65bd92dd597b07",
                "07e0917af48bbb75fed413d238f5555a",
                "7a569d80c3414a8d0859dc65a46128ba",
                "b27af87a71314f318c782b23ebfe808b",
                "82b0ce26401d2e22f04d83d1255dc51a",
                "ddd3b75a2b1ae0784504df543af8969b",
                "e3ea7082ff7fc9888c144da2af58429e",
                "c96031dbcad3dad9af0dcbaaaf268cb8",
                "fcffead94f3c7ca495e056a9b47acdb7",
                "51fb73e666c6c655ade8297297d07ad1",
                "ba5e43f1bca32301651339e22904cc8c",
                "42f58c30c04aafdb038dda0847dd988d",
                "cda6f3bfd15c4b4c4525004aa06eeff8",
                "ca61783aacec57fb3d1f92b0fe2fd1a8",
                "5f6724517b65e614ad6808d6f6ee34df",
                "f7310fdc82aebfd904b01e1dc54b2927",
                "094b2db68d6f903b68401adebf5a7e08",
                "d78ff4ef5d63653a65040cf9bfd4aca7",
                "984a74d37145986780fc0b16ac451649",
                "de6188a7dbdf191f64b5fc5e2ab47b57",
                "f7f7276cd419c17a3ca8e1b939ae49e4",
                "88acba6b965610b5480109c8b17b80e1",
                "b7b750dfc7598d5d5011fd2dcc5600a3",
                "2ef5b52a1ecc820e308aa342721aac09",
                "43bf6686b64b2579376504ccc493d97e",
                "6aed3fb0f9cd71a43dd497f01f17c0e2",
                "cb3797aa2a2f256656168e6c496afc5f",
                "b93246f6b1116398a346f1a641f3b041",
                "e989f7914f90cc2c7fff357876e506b5",
                "0d334ba77c225bc307ba537152f3f161",
                "0e4eafe595f6d9d90d11faa933a15ef1",
                "369546868a7f3a45a96768d40fd9d034",
                "12c091c6315cf4fde7cb68606937380d",
                "b2eaaa707b4c4185c32eddcdd306705e",
                "4dc1ffc872eeee475a64dfac86aba41c",
                "0618983f8741c5ef68d3a101e8a3b8ca",
                "c60c905c15fc910840b94c00a0b9d0",
            ),
            concat!(
                "0aab4c900501b3e24d7cdf4663326a3a",
                "87df5e4843b2cbdb67cbf6e460fec350",
                "aa5371b1508f9f4528ecea23c436d94b",
                "5e8fcd4f681e30a6ac00a9704a188a03",
            ),
        );

        assert_rfc8032_vector(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            concat!(
                "ddaf35a193617abacc417349ae204131",
                "12e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd",
                "454d4423643ce80e2a9ac94fa54ca49f",
            ),
            concat!(
                "dc2a4459e7369633a52b1bf277839a00",
                "201009a3efbf3ecb69bea2186c26b589",
                "09351fc9ac90b3ecfdfbc7c66431e030",
                "3dca179c138ac17ad9bef1177331a704",
            ),
        );
    }

    #[test]
    fn public_key_rejects_neutral_encoding() {
        let mut neutral = vec![0u8; 32];
        neutral[0] = 0x01;
        assert!(Ed25519PublicKey::from_binary(&neutral).is_none());
    }

    #[test]
    fn signature_rejects_neutral_r_encoding() {
        let mut signature = vec![0u8; 64];
        signature[0] = 0x01;
        assert!(Ed25519Signature::from_binary(&signature).is_none());
    }

    #[test]
    fn signature_rejects_non_canonical_s() {
        let (_, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x91; 48]));
        let mut signature = private.sign_message_bytes(b"non-canonical-s");
        signature[32..].copy_from_slice(&biguint_to_fixed_le(&curve().n, 32));
        assert!(Ed25519Signature::from_binary(&signature).is_none());
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
    fn raw_bytes_aliases_match_binary_encoding() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x12; 48]));
        assert_eq!(public.to_raw_bytes(), public.to_binary());
        assert_eq!(private.to_raw_bytes(), private.to_binary());
        assert_eq!(
            Ed25519PublicKey::from_raw_bytes(&public.to_raw_bytes()).expect("public raw"),
            public
        );
        assert_eq!(
            Ed25519PrivateKey::from_raw_bytes(&private.to_raw_bytes()).expect("private raw"),
            private
        );
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
