//! RFC 8032 `Ed25519`.
//!
//! This module provides the standard Ed25519 key and signature format:
//!
//! - private key: 32-byte seed
//! - public key: 32-byte encoded Edwards point
//! - signature: 64 bytes, `R || S`
//!
//! The keys also have the standard encodings of RFC 8410: the public key as a
//! `SubjectPublicKeyInfo` (§4) and the private key as a PKCS #8
//! `OneAsymmetricKey` (§7), in DER or as RFC 7468 `PUBLIC KEY` and
//! `PRIVATE KEY` text. The crate-defined `to_key_blob`, `to_pem` and `to_xml`
//! forms are unchanged.
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
//!
//! # Decoding and verification
//!
//! Point decoding is RFC 8032 §5.1.3 and nothing more, on every import path
//! (raw bytes, key blob, crate PEM and XML, RFC 8410 `SubjectPublicKeyInfo`)
//! and for the `R` of a signature. Verification is §5.1.7 with its cofactored
//! equation `[8][S]B = [8]R + [8][k]A'`. Points of small order, and points with
//! a small-order component, therefore decode, and a signature verifies exactly
//! when RFC 8032 says it is valid. Earlier versions refused the neutral point
//! and every point outside the subgroup of order `L`, and checked the
//! uncofactored `[S]B = R + [k]A'`, so they refused some valid signatures.
//! Under a public key of small order any `(R, S)` with `[8][S]B = [8]R`
//! verifies for every message, so a caller that needs a key to be bound to a
//! secret must check the key's order itself.
//!
//! # Side channels
//!
//! Despite Ed25519's reputation as a side-channel-hardened scheme, this
//! implementation is **variable-time**: signing derives `R = r·B` and the key
//! `A = a·B` through the generic Edwards scalar multiplication in
//! [`crate::public_key::ec_edwards`], which is not constant-time in the secret
//! scalar (see that module's note). It lives under [`crate::vt`] for that
//! reason and is unsuitable where an attacker can observe signing timing or
//! cache behavior. Verification operates only on public data.

/// RFC 8032 §5.1: a 32-byte seed, a 32-byte encoded public point, and a
/// 64-byte signature `R ‖ S`. The seed hash is SHA-512, whose halves are the
/// secret scalar and the nonce prefix.
const SEED_LEN: usize = 32;
const SIGNATURE_LEN: usize = 2 * SEED_LEN;

/// §5.1.5 clamping: clear the three low bits, clear the top bit, set bit 254.
const CLAMP_LOW_MASK: u8 = 0xf8;
const CLAMP_HIGH_MASK: u8 = 0x3f;
const CLAMP_HIGH_SET: u8 = 0x40;

use core::fmt;
use std::sync::OnceLock;

use crate::public_key::curve_pkix::{self, ID_ED25519};
use crate::public_key::ec_edwards::{ed25519, EdwardsMulTable, EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{pem_unwrap, pem_wrap};
use crate::public_key::pkix::{pem_decode, pem_encode, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL};
use crate::Csprng;
use crate::Sha512;
use rump::BigUint;

const ED25519_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ED25519 PUBLIC KEY";
const ED25519_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ED25519 PRIVATE KEY";

/// Standard 32-byte Ed25519 public key.
///
/// The window table for `[k]A` is built on the first verification, not on
/// import: importing a key is then a §5.1.3 decode and nothing more, and a
/// key that only gets re-encoded or compared never pays for the table.
#[derive(Clone)]
pub struct Ed25519PublicKey {
    point: EdwardsPoint,
    point_table: OnceLock<EdwardsMulTable>,
}

/// Standard 32-byte Ed25519 private seed plus derived signing state.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; SEED_LEN],
    scalar: BigUint,
    prefix: [u8; SEED_LEN],
    public: Ed25519PublicKey,
}

impl PartialEq for Ed25519PrivateKey {
    /// Compares the seeds in constant time. The scalar, prefix, and public key
    /// are all derived from the seed, so equal seeds mean equal keys.
    fn eq(&self, other: &Self) -> bool {
        crate::ct::constant_time_eq_mask(&self.seed, &other.seed) == u8::MAX
    }
}

impl Eq for Ed25519PrivateKey {}

/// Standard 64-byte Ed25519 signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519Signature {
    r_point: EdwardsPoint,
    s: BigUint,
}

/// Namespace wrapper for the fixed-curve Ed25519 construction.
///
/// # Examples
///
/// ```rust
/// use cryptography::{vt::Ed25519, CtrDrbgAes256};
///
/// let mut rng = CtrDrbgAes256::new(&[0x7bu8; 48]);
/// let (public, private) = Ed25519::generate(&mut rng);
///
/// let msg = b"ed25519 example";
/// let sig = private.sign_message(msg);
/// assert!(public.verify_message(msg, &sig));
/// ```
pub struct Ed25519;

impl Ed25519PublicKey {
    /// Return the decoded Edwards public point `A`.
    #[must_use]
    pub fn public_point(&self) -> &EdwardsPoint {
        &self.point
    }

    /// Standard 32-byte compressed public key.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        curve().encode_point(&self.point)
    }

    /// Preferred explicit name for the standard 32-byte compressed public key.
    #[must_use]
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        self.to_key_blob()
    }

    /// Parse the standard 32-byte compressed public key.
    ///
    /// Decoding is RFC 8032 §5.1.3 and nothing more. It fails when the input
    /// is not 32 octets, when `y` (the low 255 bits) is at least `p`, when
    /// `x² = (y² − 1)/(d·y² + 1)` has no square root mod `p`, or when `x = 0`
    /// and the sign bit is set. Every other string is a key, whatever the
    /// order of its point.
    ///
    /// RFC 8032 does not restrict the order of a key's point, so neither does
    /// this; §5.1.7 decides what verifies under such a key. Under a key `A'` of small order, `[8][k]A'` is the neutral point,
    /// so any `(R, S)` with `[8][S]B = [8]R` verifies for every message
    /// (`R` neutral, `S = 0`, for one): such a key binds no secret. A caller
    /// that needs the key to belong to someone should check it with
    /// [`TwistedEdwardsCurve::is_valid_public_point`] on [`Self::public_point`].
    #[must_use]
    pub fn from_key_blob(bytes: &[u8]) -> Option<Self> {
        let point = decode_point(bytes)?;
        Some(Self {
            point,
            point_table: OnceLock::new(),
        })
    }

    /// Preferred explicit name for the standard 32-byte compressed public key.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_key_blob(bytes)
    }

    /// PEM-armored wrapper around the standard 32-byte public key.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(ED25519_PUBLIC_LABEL, &self.to_key_blob())
    }

    /// Parse the PEM-armored public key.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let bytes = pem_unwrap(ED25519_PUBLIC_LABEL, pem)?;
        Self::from_key_blob(&bytes)
    }

    /// Encode as the RFC 8410 §4 `SubjectPublicKeyInfo` in DER: `id-Ed25519`
    /// with the parameters absent (§3) and the 32-byte RFC 8032 encoding of
    /// the public point as the `subjectPublicKey`.
    #[must_use]
    pub fn to_spki_der(&self) -> Vec<u8> {
        curve_pkix::public_key_to_spki(&ID_ED25519, &self.to_key_blob())
    }

    /// Encode as RFC 7468 `PUBLIC KEY` text (§13) around [`Self::to_spki_der`].
    #[must_use]
    pub fn to_spki_pem(&self) -> String {
        pem_encode(PUBLIC_KEY_LABEL, self.to_spki_der())
    }

    /// Decode an RFC 8410 §4 `SubjectPublicKeyInfo` from strict DER with no
    /// trailing bytes: `id-Ed25519` with the parameters absent (§3) and a
    /// 32-byte key that passes the same validation as [`Self::from_key_blob`].
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        Self::from_key_blob(curve_pkix::public_key_from_spki(der, &ID_ED25519, 32)?)
    }

    /// Decode RFC 7468 `PUBLIC KEY` text (§13) with [`Self::from_spki_der`].
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        pem_decode(PUBLIC_KEY_LABEL, pem, Self::from_spki_der)
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![BigUint::from_be_bytes(&self.to_key_blob())]
    }

    /// Validate the schema field and rebuild the key.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let public = fields.next()?;
        let bytes = biguint_to_fixed_be(&public, 32)?;
        Self::from_key_blob(&bytes)
    }

    /// Verify a standard signature over the message: RFC 8032 §5.1.7.
    ///
    /// `S` lies in `0 ≤ S < L` (step 1), `k` is SHA-512 of `R ‖ A ‖ M`
    /// (step 2), and the signature is valid exactly when the cofactored group
    /// equation `[8][S]B = [8]R + [8][k]A'` holds (step 3).
    ///
    /// RFC 8032 calls the uncofactored `[S]B = R + [k]A'` "sufficient, but
    /// not required": whatever satisfies it satisfies the cofactored equation
    /// (§8.8), but not conversely. When `R` or `A'` has a small-order
    /// component that `[k]` does not cancel, the uncofactored equation refuses
    /// signatures RFC 8032 defines as valid, so it is not used.
    #[must_use]
    pub fn verify_message(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        // Step 1. Every `Ed25519Signature` already has S < L; the check keeps
        // the step where the section puts it.
        if signature.s >= curve().n {
            return false;
        }
        // Step 2. §5.1.3 decodes exactly one 32-octet string to each point
        // (y < p, and no sign bit on x = 0), so encoding R and A' again gives
        // back the octets R and A that the section hashes. `k` comes back
        // reduced mod L, which step 3 cannot see: [8]A' lies in the subgroup
        // of order L, so [8][k]A' = [8][k mod L]A'.
        let k = challenge_scalar(&signature.r_point, &self.point, message);
        // Step 3, with [8]R + [8][k]A' taken as [8](R + [k]A').
        let s_b = curve().scalar_mul_base(&signature.s);
        let r_plus_k_a = curve().add(&signature.r_point, &self.mul_public_point(&k));
        curve().mul_by_pow2(&s_b, COFACTOR_LOG2) == curve().mul_by_pow2(&r_plus_k_a, COFACTOR_LOG2)
    }

    /// `[k]A` through the cached window table, built on first use.
    fn mul_public_point(&self, k: &BigUint) -> EdwardsPoint {
        let table = self
            .point_table
            .get_or_init(|| curve().precompute_mul_table(&self.point));
        curve().scalar_mul_cached(table, k)
    }

    /// Verify a standard 64-byte signature.
    #[must_use]
    pub fn verify_message_bytes(&self, message: &[u8], signature: &[u8]) -> bool {
        let Some(signature) = Ed25519Signature::from_key_blob(signature) else {
            return false;
        };
        self.verify_message(message, &signature)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519PublicKey")
            .field(&hex_encode(&self.to_key_blob()))
            .finish()
    }
}

crate::public_key::io::impl_xml_serialization!(Ed25519PublicKey, "Ed25519PublicKey", ["public"]);

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Eq for Ed25519PublicKey {}

impl Ed25519PrivateKey {
    /// Return the original 32-byte secret seed.
    #[must_use]
    pub fn seed(&self) -> &[u8; SEED_LEN] {
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
    pub fn to_key_blob(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Preferred explicit name for the standard 32-byte private seed.
    #[must_use]
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        self.to_key_blob()
    }

    /// Parse the standard 32-byte private-key encoding (the seed).
    #[must_use]
    pub fn from_key_blob(bytes: &[u8]) -> Option<Self> {
        let mut seed: [u8; SEED_LEN] = bytes.try_into().ok()?;
        let key = expand_seed(seed);
        crate::ct::zeroize_slice(seed.as_mut_slice());
        Some(key)
    }

    /// Preferred explicit name for the standard 32-byte private seed.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_key_blob(bytes)
    }

    /// PEM-armored wrapper around the standard 32-byte seed.
    #[must_use]
    pub fn to_pem(&self) -> String {
        let mut seed = self.to_key_blob();
        let pem = pem_wrap(ED25519_PRIVATE_LABEL, &seed);
        crate::ct::zeroize_slice(seed.as_mut_slice());
        pem
    }

    /// Parse the PEM-armored private key.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let mut seed = pem_unwrap(ED25519_PRIVATE_LABEL, pem)?;
        let key = Self::from_key_blob(&seed);
        crate::ct::zeroize_slice(seed.as_mut_slice());
        key
    }

    /// Encode as the RFC 8410 §7 `OneAsymmetricKey` (PKCS #8) in DER: version
    /// 1, `id-Ed25519` with the parameters absent (§3), and the 32-byte RFC
    /// 8032 §5.1.5 private key (the seed) as `CurvePrivateKey`. The public key
    /// is left out, since the seed derives it.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        curve_pkix::private_key_to_pkcs8(&ID_ED25519, &self.seed)
    }

    /// Encode as RFC 7468 `PRIVATE KEY` text (§10) around
    /// [`Self::to_pkcs8_der`].
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode(PRIVATE_KEY_LABEL, self.to_pkcs8_der())
    }

    /// Decode an RFC 8410 §7 `OneAsymmetricKey` in any X.690 BER encoding, DER
    /// included: RFC 5958 §2 says "receivers MUST support BER". The key is then
    /// checked as [`Self::from_pkcs8_der`] checks it.
    #[must_use]
    pub fn from_pkcs8_ber(ber: &[u8]) -> Option<Self> {
        crate::public_key::pkix::pkcs8_ber(ber, Self::from_pkcs8_der)
    }

    /// Decode an RFC 8410 §7 `OneAsymmetricKey` from strict DER with no
    /// trailing bytes: version 1 or 2, `id-Ed25519` with the parameters absent
    /// (§3), and a 32-byte seed as `CurvePrivateKey`. A version 2 `publicKey`
    /// must be the encoding of the public key the seed derives. Attributes are
    /// ignored.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let (seed, public_key) = curve_pkix::private_key_from_pkcs8(der, &ID_ED25519, 32)?;
        let key = Self::from_key_blob(seed)?;
        match public_key {
            Some(public_key) if public_key != key.public.to_key_blob() => None,
            _ => Some(key),
        }
    }

    /// Decode RFC 7468 `PRIVATE KEY` text (§10) with [`Self::from_pkcs8_der`].
    #[must_use]
    pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        pem_decode(PRIVATE_KEY_LABEL, pem, Self::from_pkcs8_der)
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![BigUint::from_be_bytes(&self.seed)]
    }

    /// Validate the schema field and rebuild the key.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let seed = fields.next()?;
        let mut bytes = biguint_to_fixed_be(&seed, 32)?;
        let key = Self::from_key_blob(&bytes);
        crate::ct::zeroize_slice(bytes.as_mut_slice());
        key
    }

    /// Sign one message using the deterministic RFC 8032 nonce derivation.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> Ed25519Signature {
        // `prefix || M` starts with the secret nonce prefix, and its digest is
        // the nonce `r` before reduction: both are wiped once `r` exists.
        let mut nonce_input = Vec::with_capacity(self.prefix.len() + message.len());
        nonce_input.extend_from_slice(&self.prefix);
        nonce_input.extend_from_slice(message);
        let mut nonce_digest = Sha512::digest(&nonce_input);
        crate::ct::zeroize_slice(nonce_input.as_mut_slice());
        let r = BigUint::from_le_bytes(&nonce_digest).rem(&curve().n);
        crate::ct::zeroize_slice(nonce_digest.as_mut_slice());
        let r_point = curve().scalar_mul_base(&r);
        let challenge = challenge_scalar(&r_point, &self.public.point, message);
        let ka = curve().scalar_ctx().mul(&challenge, &self.scalar);
        let s = r.add(&ka).rem(&curve().n);
        Ed25519Signature { r_point, s }
    }

    /// Sign and return the standard 64-byte `R || S` form.
    #[must_use]
    pub fn sign_message_bytes(&self, message: &[u8]) -> Vec<u8> {
        self.sign_message(message).to_key_blob()
    }
}

crate::public_key::io::impl_xml_serialization!(Ed25519PrivateKey, "Ed25519PrivateKey", ["seed"]);

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519PrivateKey(<redacted>)")
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        // WHAT: wipe seed-derived secret material that lives in fixed arrays.
        // WHY: Ed25519 keys are long-lived, and these buffers otherwise remain
        // in process memory until allocator reuse.
        crate::ct::zeroize_slice(self.seed.as_mut_slice());
        crate::ct::zeroize_slice(self.prefix.as_mut_slice());

        // WHAT: force-drop the old scalar now, then leave a benign zero value.
        // WHY: scalar is heap-backed bigint state and should not survive longer
        // than this private key object.
        self.scalar = BigUint::zero();
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
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = curve().encode_point(&self.r_point);
        out.extend_from_slice(&self.s.to_le_bytes_padded(32));
        out
    }

    /// Parse the standard 64-byte signature encoding `R || S`.
    ///
    /// This is the decoding of RFC 8032 §5.1.7 step 1: `R` is a point by
    /// §5.1.3 (see [`Ed25519PublicKey::from_key_blob`] for what that refuses)
    /// and `S` a little-endian integer in `0 ≤ S < L`. Any `R` that decodes is
    /// accepted, the neutral point and small-order points included, as RFC
    /// 8032 requires.
    #[must_use]
    pub fn from_key_blob(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return None;
        }
        let r_point = decode_point(&bytes[..SEED_LEN])?;
        let s = BigUint::from_le_bytes(&bytes[SEED_LEN..]);
        if s >= curve().n {
            return None;
        }
        Some(Self { r_point, s })
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519Signature")
            .field(&hex_encode(&self.to_key_blob()))
            .finish()
    }
}

impl Ed25519 {
    /// Generate a random Ed25519 key pair from a fresh 32-byte seed.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R) -> (Ed25519PublicKey, Ed25519PrivateKey) {
        let mut seed = [0u8; SEED_LEN];
        rng.fill_bytes(&mut seed);
        let private = expand_seed(seed);
        crate::ct::zeroize_slice(seed.as_mut_slice());
        let public = private.to_public_key();
        (public, private)
    }

    /// Derive a key pair from an explicit 32-byte seed.
    #[must_use]
    pub fn from_seed(mut seed: [u8; SEED_LEN]) -> (Ed25519PublicKey, Ed25519PrivateKey) {
        let private = expand_seed(seed);
        crate::ct::zeroize_slice(seed.as_mut_slice());
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
fn expand_seed(mut seed: [u8; SEED_LEN]) -> Ed25519PrivateKey {
    let mut digest = Sha512::digest(&seed);
    let mut scalar_bytes = [0u8; SEED_LEN];
    scalar_bytes.copy_from_slice(&digest[..32]);
    clamp_scalar(&mut scalar_bytes);
    let scalar = BigUint::from_le_bytes(&scalar_bytes);

    let mut prefix = [0u8; SEED_LEN];
    prefix.copy_from_slice(&digest[SEED_LEN..2 * SEED_LEN]);

    let point = curve().scalar_mul_base(&scalar);
    let public = Ed25519PublicKey {
        point,
        point_table: OnceLock::new(),
    };

    let key = Ed25519PrivateKey {
        seed,
        scalar,
        prefix,
        public,
    };
    // The digest holds both the scalar and the prefix; the stack copies of the
    // seed, scalar bytes, and prefix were copied into `key` and are wiped here.
    crate::ct::zeroize_slice(digest.as_mut_slice());
    crate::ct::zeroize_slice(scalar_bytes.as_mut_slice());
    crate::ct::zeroize_slice(prefix.as_mut_slice());
    crate::ct::zeroize_slice(seed.as_mut_slice());
    key
}

/// RFC 8032 Ed25519 scalar clamping.
fn clamp_scalar(bytes: &mut [u8; SEED_LEN]) {
    bytes[0] &= CLAMP_LOW_MASK;
    bytes[SEED_LEN - 1] &= CLAMP_HIGH_MASK;
    bytes[SEED_LEN - 1] |= CLAMP_HIGH_SET;
}

/// Compute the Ed25519 challenge scalar `k = H(R || A || M) mod n`.
fn challenge_scalar(r_point: &EdwardsPoint, a_point: &EdwardsPoint, message: &[u8]) -> BigUint {
    let mut transcript = curve().encode_point(r_point);
    transcript.extend_from_slice(&curve().encode_point(a_point));
    transcript.extend_from_slice(message);
    BigUint::from_le_bytes(&Sha512::digest(&transcript)).rem(&curve().n)
}

/// `c` for Ed25519 (RFC 8032 §5.1): the cofactor is `2^c = 8`.
const COFACTOR_LOG2: u32 = 3;

/// RFC 8032 §5.1.3 decoding of a 32-octet point encoding, with no further
/// checks.
///
/// [`TwistedEdwardsCurve::decode_point`] carries out that section for
/// Ed25519: a length other than 32 fails, as do `y ≥ p` (step 1), no square
/// root of `(y² − 1)/(d·y² + 1)` (steps 2 and 3), and `x = 0` with `x_0 = 1`
/// (step 4). Every other string yields its point, of whatever order.
fn decode_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    curve().decode_point(bytes)
}

fn biguint_to_fixed_be(value: &BigUint, len: usize) -> Option<Vec<u8>> {
    let mut bytes = value.to_be_bytes();
    if bytes.len() > len {
        crate::ct::zeroize_slice(bytes.as_mut_slice());
        return None;
    }
    if bytes.len() == len {
        return Some(bytes);
    }
    // The private-key XML path passes the seed through here: the unpadded
    // copy is wiped once the padded one exists.
    let mut padded = Vec::with_capacity(len);
    padded.resize(len - bytes.len(), 0u8);
    padded.extend_from_slice(&bytes);
    crate::ct::zeroize_slice(bytes.as_mut_slice());
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
        challenge_scalar, curve, Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    };
    use crate::public_key::curve_pkix::{
        private_key_to_pkcs8, public_key_to_spki, ID_ED25519, ID_X25519,
    };
    use crate::public_key::ec_edwards::EdwardsPoint;
    use crate::public_key::io::der_octet_string;
    use crate::public_key::pkix::{
        pem_decode, AlgorithmIdentifier, OneAsymmetricKey, PRIVATE_KEY_LABEL,
    };
    use crate::test_utils::{decode_hex, decode_hex_array, openssl3, ScratchFile};
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    /// One RFC 8032 §7.1 vector: the seed derives the public key, signing
    /// reproduces the signature, and the public key, imported on every path,
    /// verifies it and refuses it for another message.
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
        assert_eq!(derived_public.to_key_blob(), public);
        assert_eq!(private.to_key_blob(), seed);

        let sig = private.sign_message(&message);
        assert_eq!(sig.to_key_blob(), signature);
        assert!(derived_public.verify_message(&message, &sig));
        assert!(derived_public.verify_message_bytes(&message, &signature));

        let public: [u8; 32] = public.try_into().expect("public key length");
        let imported = import_everywhere(&public).expect("§7.1 public key");
        assert_eq!(imported, derived_public);
        assert!(imported.verify_message_bytes(&message, &signature));
        let mut other = message.clone();
        other.push(0x00);
        assert!(!imported.verify_message_bytes(&other, &signature));
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

    /// RFC 8032 §5.1.3 decodes the neutral point's encoding, `y = 1` with the
    /// sign bit clear, so every import accepts it.
    #[test]
    fn public_key_accepts_neutral_encoding() {
        let mut neutral = [0u8; 32];
        neutral[0] = 0x01;
        let key = import_everywhere(&neutral).expect("§5.1.3 decodes (0, 1)");
        assert!(key.public_point().is_neutral());
        assert_eq!(key.to_raw_bytes(), neutral);
    }

    /// §5.1.7 step 1 decodes `R = (0, 1)`, `S = 0`, so the signature parses.
    #[test]
    fn signature_accepts_neutral_r_encoding() {
        let mut signature = [0u8; 64];
        signature[0] = 0x01;
        let decoded = Ed25519Signature::from_key_blob(&signature).expect("§5.1.7 step 1");
        assert!(decoded.nonce_point().is_neutral());
        assert_eq!(decoded.to_key_blob(), signature);
    }

    /// The key `bytes` decode to on each import path (raw bytes, key blob,
    /// crate PEM, crate XML, RFC 8410 `SubjectPublicKeyInfo`), after checking
    /// that all five agree.
    fn import_everywhere(bytes: &[u8; 32]) -> Option<Ed25519PublicKey> {
        let raw = Ed25519PublicKey::from_raw_bytes(bytes);
        let paths = [
            Ed25519PublicKey::from_key_blob(bytes),
            Ed25519PublicKey::from_pem(&crate::public_key::io::pem_wrap(
                super::ED25519_PUBLIC_LABEL,
                bytes,
            )),
            Ed25519PublicKey::from_xml(&crate::public_key::io::xml_wrap(
                "Ed25519PublicKey",
                &[("public", &BigUint::from_be_bytes(bytes))],
            )),
            Ed25519PublicKey::from_spki_der(&public_key_to_spki(&ID_ED25519, bytes)),
        ];
        for decoded in paths {
            assert_eq!(decoded, raw, "import paths disagree on {bytes:02x?}");
        }
        raw
    }

    /// The 64-octet signature `R ‖ S`.
    fn signature_octets(r: &EdwardsPoint, s: &BigUint) -> Vec<u8> {
        [
            curve().encode_point(r),
            s.to_le_bytes_padded(super::SEED_LEN),
        ]
        .concat()
    }

    /// A point of order 8. The only point of order 2 is `(0, −1)` (`P = −P`
    /// forces `x = 0`), so the part of the group of order 8 is cyclic, and
    /// `[L]P` has order 8 for half of all points `P`.
    fn point_of_order_eight() -> EdwardsPoint {
        let curve = curve();
        let t = (0u64..64)
            .filter_map(|y| curve.decode_point(&BigUint::from_u64(y).to_le_bytes_padded(32)))
            .map(|point| curve.scalar_mul(&point, &curve.n))
            .find(|t| !curve.mul_by_pow2(t, 2).is_neutral())
            .expect("some [L]P has order 8");
        assert!(curve.mul_by_pow2(&t, 3).is_neutral());
        t
    }

    /// RFC 8032 §5.1.3 refuses `y ≥ p` (step 1), a `y` whose `x²` has no
    /// square root (steps 2 and 3), and `x = 0` with the sign bit set
    /// (step 4), and nothing else. Every import path and the `R` of a
    /// signature agree, and each accepted string is the encoding of its
    /// point, so §5.1.7 step 2 hashes the same octets it was given.
    #[test]
    fn decoding_refuses_exactly_what_section_5_1_3_refuses() {
        use rump::modular::MontgomeryContext;

        let curve = curve();
        let p = &curve.p;
        let octets = |value: &BigUint, sign: bool| -> [u8; 32] {
            let mut bytes: [u8; 32] = value.to_le_bytes_padded(32).try_into().expect("32 octets");
            assert_eq!(bytes[31] & 0x80, 0, "value below 2^255");
            if sign {
                bytes[31] |= 0x80;
            }
            bytes
        };
        let refused = |bytes: [u8; 32]| {
            Ed25519PublicKey::from_raw_bytes(&bytes).is_none()
                && import_everywhere(&bytes).is_none()
                && Ed25519Signature::from_key_blob(&[bytes, [0u8; 32]].concat()).is_none()
        };
        let accepted = |bytes: [u8; 32]| {
            let key = Ed25519PublicKey::from_raw_bytes(&bytes);
            let signature = Ed25519Signature::from_key_blob(&[bytes, [0u8; 32]].concat());
            key.is_some_and(|key| key.to_raw_bytes() == bytes)
                && signature.is_some_and(|signature| signature.to_key_blob()[..32] == bytes)
        };

        // Step 1: the 19 values p ≤ y < 2^255, either sign bit. Their
        // canonical twins y − p = 0 and 1 decode.
        for offset in 0u64..19 {
            let y = p.add(&BigUint::from_u64(offset));
            assert!(refused(octets(&y, false)) && refused(octets(&y, true)));
        }
        assert!(accepted(octets(&BigUint::zero(), false)));
        assert!(accepted(octets(&BigUint::one(), false)));

        // Step 4: x = 0 for y = 1 (the neutral point) and y = p − 1 (order 2).
        for y in [BigUint::one(), p.sub(&BigUint::one())] {
            assert!(accepted(octets(&y, false)));
            assert!(refused(octets(&y, true)));
        }

        // Steps 2 and 3: x² = (y² − 1)/(d·y² + 1) must be a square mod p,
        // judged here by Euler's criterion, not by the decoder's square root.
        // A nonzero square decodes under either sign.
        let ctx = MontgomeryContext::new(p).expect("p is odd");
        let mut half = p.sub(&BigUint::one());
        half.shr1();
        let p_minus_2 = p.sub(&BigUint::from_u64(2));
        let (mut squares, mut non_squares) = (0, 0);
        for y in (2u64..24).map(BigUint::from_u64) {
            let y2 = ctx.square(&y);
            let u = BigUint::mod_sub(&y2, &BigUint::one(), p);
            let v = BigUint::mod_add(&ctx.mul(&curve.d, &y2), &BigUint::one(), p);
            let x2 = ctx.mul(&u, &ctx.pow(&v, &p_minus_2));
            if ctx.pow(&x2, &half) == BigUint::one() {
                squares += 1;
                assert!(accepted(octets(&y, false)) && accepted(octets(&y, true)));
            } else {
                non_squares += 1;
                assert!(refused(octets(&y, false)) && refused(octets(&y, true)));
            }
        }
        assert!(squares > 0 && non_squares > 0);

        // A point encoding is 32 octets; a signature 64.
        assert!(Ed25519PublicKey::from_raw_bytes(&[0x01; 31]).is_none());
        assert!(Ed25519PublicKey::from_raw_bytes(&[0x01; 33]).is_none());
        assert!(Ed25519Signature::from_key_blob(&[0x01; 63]).is_none());
        assert!(Ed25519Signature::from_key_blob(&[0x01; 65]).is_none());
    }

    /// The eight points of order dividing 8 decode on every import path:
    /// §5.1.3 has no order check. Under such a key `A'`, `[8][k]A'` is
    /// neutral, so §5.1.7 accepts exactly the `(R, S)` with `[8][S]B = [8]R`,
    /// for any message.
    #[test]
    fn small_order_keys_decode_and_verify_as_section_5_1_7_defines() {
        let curve = curve();
        let t = point_of_order_eight();
        let torsion: Vec<EdwardsPoint> = (0u64..8)
            .map(|j| curve.scalar_mul(&t, &BigUint::from_u64(j)))
            .collect();
        for (i, point) in torsion.iter().enumerate() {
            assert!(torsion[..i].iter().all(|earlier| earlier != point));
        }

        let (zero, one) = (BigUint::zero(), BigUint::one());
        for (i, point) in torsion.iter().enumerate() {
            let bytes: [u8; 32] = curve.encode_point(point).try_into().expect("32 octets");
            let key = import_everywhere(&bytes).expect("§5.1.3 decodes every small-order point");
            assert_eq!(key.public_point(), point);
            // [8][0]B = [8]R for every small-order R, and [8][1]B = [8]B.
            let r = &torsion[(3 * i + 1) % 8];
            assert!(key.verify_message_bytes(b"one message", &signature_octets(r, &zero)));
            assert!(key.verify_message_bytes(b"another", &signature_octets(r, &zero)));
            let base = curve.base_point();
            assert!(key.verify_message_bytes(b"one message", &signature_octets(&base, &one)));
            // [8][1]B is not [8]R for a small-order R.
            assert!(!key.verify_message_bytes(b"one message", &signature_octets(r, &one)));
        }
    }

    /// A key `A' = A + T` or a nonce point `R + T`, `T` of order 8, used with
    /// the honest scalar of `A`: §5.1.7's cofactored equation accepts the
    /// signature. The uncofactored `[S]B = R + [k]A'` refuses it whenever `[k]T` is not neutral, which is always so for
    /// the nonce point.
    #[test]
    fn mixed_order_key_and_nonce_verify_by_the_cofactored_equation() {
        let curve = curve();
        let n = &curve.n;
        let t = point_of_order_eight();
        let (public, private) = Ed25519::from_seed([0x6d; 32]);
        let a = public.public_point().clone();
        let respond =
            |r: &BigUint, k: &BigUint| r.add(&curve.scalar_ctx().mul(k, private.scalar())).rem(n);
        let uncofactored = |r: &EdwardsPoint, s: &BigUint, key: &EdwardsPoint, k: &BigUint| {
            curve.scalar_mul_base(s) == curve.add(r, &curve.scalar_mul(key, k))
        };

        let a_mixed = curve.add(&a, &t);
        let mixed_bytes: [u8; 32] = curve.encode_point(&a_mixed).try_into().expect("32 octets");
        let mixed_key = import_everywhere(&mixed_bytes).expect("§5.1.3 decodes A + T");
        let mut uncancelled = 0;
        for i in 0u64..4 {
            let message = i.to_le_bytes();
            let r = BigUint::from_u64(0x0123_4567_89ab_cdef ^ i);
            let r_point = curve.scalar_mul_base(&r);

            let k = challenge_scalar(&r_point, &a_mixed, &message);
            let s = respond(&r, &k);
            let signature = signature_octets(&r_point, &s);
            assert!(mixed_key.verify_message_bytes(&message, &signature));
            assert!(!mixed_key.verify_message_bytes(b"other", &signature));
            let s_plus_one = s.add(&BigUint::one()).rem(n);
            assert!(
                !mixed_key.verify_message_bytes(&message, &signature_octets(&r_point, &s_plus_one))
            );
            if !curve.scalar_mul(&t, &k).is_neutral() {
                uncancelled += 1;
                assert!(!uncofactored(&r_point, &s, &a_mixed, &k));
            }

            let r_mixed = curve.add(&r_point, &t);
            let k = challenge_scalar(&r_mixed, &a, &message);
            let s = respond(&r, &k);
            assert!(public.verify_message_bytes(&message, &signature_octets(&r_mixed, &s)));
            assert!(!uncofactored(&r_mixed, &s, &a, &k));
        }
        assert!(uncancelled > 0, "every message cancelled [k]T");
    }

    /// RFC 8032 §5.1.5: a private key is any 32 octets. Every import path
    /// takes the extreme seeds, and nothing of another length.
    #[test]
    fn private_key_import_takes_any_32_octets() {
        for seed in [[0x00u8; 32], [0xff; 32]] {
            let (public, private) = Ed25519::from_seed(seed);
            assert_eq!(
                Ed25519PrivateKey::from_raw_bytes(&seed).as_ref(),
                Some(&private)
            );
            assert_eq!(
                Ed25519PrivateKey::from_pem(&private.to_pem()).as_ref(),
                Some(&private)
            );
            assert_eq!(
                Ed25519PrivateKey::from_xml(&private.to_xml()).as_ref(),
                Some(&private)
            );
            assert_eq!(
                Ed25519PrivateKey::from_pkcs8_der(&private.to_pkcs8_der()).as_ref(),
                Some(&private)
            );
            let signature = private.sign_message(b"extreme seed");
            assert!(public.verify_message(b"extreme seed", &signature));
        }
        assert!(Ed25519PrivateKey::from_raw_bytes(&[0u8; 31]).is_none());
        assert!(Ed25519PrivateKey::from_raw_bytes(&[0u8; 33]).is_none());
    }

    #[test]
    fn signature_rejects_non_canonical_s() {
        let (_, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x91; 48]));
        let mut signature = private.sign_message_bytes(b"non-canonical-s");
        signature[32..].copy_from_slice(&curve().n.to_le_bytes_padded(32));
        assert!(Ed25519Signature::from_key_blob(&signature).is_none());
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
        let blob = sig.to_key_blob();
        let decoded = Ed25519Signature::from_key_blob(&blob).expect("decode");
        assert_eq!(decoded, sig);
        assert!(public.verify_message(b"serialize", &decoded));
    }

    #[test]
    fn key_binary_roundtrip() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x11; 48]));
        assert_eq!(
            Ed25519PublicKey::from_key_blob(&public.to_key_blob()).expect("public"),
            public
        );
        let private_round =
            Ed25519PrivateKey::from_key_blob(&private.to_key_blob()).expect("private");
        assert_eq!(private_round, private);
        assert_eq!(private_round.to_public_key(), public);
    }

    #[test]
    fn raw_bytes_aliases_match_binary_encoding() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x12; 48]));
        assert_eq!(public.to_raw_bytes(), public.to_key_blob());
        assert_eq!(private.to_raw_bytes(), private.to_key_blob());
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

    #[test]
    fn private_key_equality_follows_the_seed() {
        let (_, key) = Ed25519::from_seed([0x42; 32]);
        let (_, same) = Ed25519::from_seed([0x42; 32]);
        let mut other_seed = [0x42; 32];
        other_seed[31] ^= 0x01;
        let (_, other) = Ed25519::from_seed(other_seed);
        assert!(key == same);
        assert!(key != other);
    }

    /// RFC 8410 §10.1: an Ed25519 public key.
    const RFC8410_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
        -----END PUBLIC KEY-----\n";

    /// RFC 8410 §10.3, first example: a private key, version 1.
    const RFC8410_PRIVATE_V1_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
        -----END PRIVATE KEY-----\n";

    /// RFC 8410 §10.3, second example: the same key as version 2, with an
    /// attribute and the public key. Erratum 8297 notes that the attribute's
    /// identifier is unassigned; attributes are ignored on input.
    const RFC8410_PRIVATE_V2_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
        oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n\
        Z9w7lshQhqowtrbLDFw4rXAxZuE=\n\
        -----END PRIVATE KEY-----\n";

    #[test]
    fn rfc8410_section_10_examples_decode_and_reencode_exactly() {
        let public = Ed25519PublicKey::from_spki_pem(RFC8410_PUBLIC_PEM).expect("§10.1 key");
        assert_eq!(public.to_spki_pem(), RFC8410_PUBLIC_PEM);

        let private = Ed25519PrivateKey::from_pkcs8_pem(RFC8410_PRIVATE_V1_PEM).expect("§10.3 key");
        // §10.3: "the value of the private key is D4 EE 72 DB ...".
        assert_eq!(
            private.seed(),
            &decode_hex_array::<32>(
                "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842"
            )
        );
        // The §10.3 seed derives the §10.1 public key.
        assert_eq!(private.to_public_key(), public);
        assert_eq!(private.to_pkcs8_pem(), RFC8410_PRIVATE_V1_PEM);

        let v2 =
            Ed25519PrivateKey::from_pkcs8_pem(RFC8410_PRIVATE_V2_PEM).expect("§10.3 version 2 key");
        assert_eq!(v2, private);
        // Output is version 1 without the public key.
        assert_eq!(v2.to_pkcs8_pem(), RFC8410_PRIVATE_V1_PEM);

        // The version 2 example with its public key altered no longer matches
        // its private key.
        let mut der = pem_decode(PRIVATE_KEY_LABEL, RFC8410_PRIVATE_V2_PEM, |der| {
            Some(der.to_vec())
        })
        .expect("RFC 7468 text");
        *der.last_mut().expect("non-empty") ^= 0x01;
        assert!(Ed25519PrivateKey::from_pkcs8_der(&der).is_none());
    }

    #[test]
    fn pkcs8_ber_accepts_an_indefinite_length_container() {
        let (_, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x5e; 48]));
        let der = private.to_pkcs8_der();
        let ber = crate::test_utils::der_to_indefinite_length(&der);
        assert!(Ed25519PrivateKey::from_pkcs8_der(&ber).is_none());
        assert_eq!(
            Ed25519PrivateKey::from_pkcs8_ber(&ber),
            Some(private.clone())
        );
        assert_eq!(Ed25519PrivateKey::from_pkcs8_ber(&der), Some(private));
    }

    #[test]
    fn standard_encodings_round_trip_and_apply_the_key_checks() {
        let (public, private) = Ed25519::generate(&mut CtrDrbgAes256::new(&[0x5e; 48]));
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&public.to_spki_der()),
            Some(public.clone())
        );
        assert_eq!(
            Ed25519PrivateKey::from_pkcs8_der(&private.to_pkcs8_der()),
            Some(private.clone())
        );
        assert_eq!(
            Ed25519PrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem()),
            Some(private.clone())
        );

        // Inside a SubjectPublicKeyInfo a key decodes as it does bare, by RFC
        // 8032 §5.1.3: the neutral point is a key; y = p + 1, the non-canonical
        // spelling of the same y = 1, is not.
        let mut neutral = [0u8; 32];
        neutral[0] = 0x01;
        let decoded = Ed25519PublicKey::from_spki_der(&public_key_to_spki(&ID_ED25519, &neutral));
        assert!(decoded.is_some());
        assert_eq!(decoded, Ed25519PublicKey::from_raw_bytes(&neutral));
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        assert!(
            Ed25519PublicKey::from_spki_der(&public_key_to_spki(&ID_ED25519, &non_canonical))
                .is_none()
        );
        // The same bytes under id-X25519 are another algorithm's key (§12).
        assert!(Ed25519PublicKey::from_spki_der(&public_key_to_spki(
            &ID_X25519,
            &public.to_key_blob()
        ))
        .is_none());
        assert!(Ed25519PrivateKey::from_pkcs8_der(&private_key_to_pkcs8(
            &ID_X25519,
            private.seed()
        ))
        .is_none());

        // A version 2 public key: the matching one is accepted; another key's,
        // or a truncated one, is not.
        let with_public = |public_key: &[u8]| {
            OneAsymmetricKey::new(
                AlgorithmIdentifier::new(&ID_ED25519, None),
                &der_octet_string(private.seed()),
                Some(public_key),
            )
            .to_der()
        };
        assert_eq!(
            Ed25519PrivateKey::from_pkcs8_der(&with_public(&public.to_key_blob())),
            Some(private.clone())
        );
        let (other, _) = Ed25519::from_seed([0x5f; 32]);
        assert!(Ed25519PrivateKey::from_pkcs8_der(&with_public(&other.to_key_blob())).is_none());
        assert!(
            Ed25519PrivateKey::from_pkcs8_der(&with_public(&public.to_key_blob()[..31])).is_none()
        );
    }

    /// OpenSSL's keys parse and re-encode byte for byte; OpenSSL reads the
    /// crate's keys, derives the same public key, signs with the crate's key
    /// exactly as the crate does (Ed25519 is deterministic), and verifies the
    /// crate's signature under the crate's `SubjectPublicKeyInfo`.
    #[test]
    fn openssl_ed25519_keys_and_signatures_interoperate() {
        const TEST: &str = "openssl_ed25519_keys_and_signatures_interoperate";
        let Some(theirs_pem) = openssl3(&["genpkey", "-algorithm", "ED25519"], b"").or_skip(TEST)
        else {
            return;
        };
        let theirs = Ed25519PrivateKey::from_pkcs8_pem(
            std::str::from_utf8(&theirs_pem).expect("PEM is ASCII"),
        )
        .expect("OpenSSL's PKCS #8 Ed25519 key");
        assert_eq!(theirs.to_pkcs8_pem().as_bytes(), theirs_pem);
        let theirs_spki = openssl3(&["pkey", "-pubout", "-outform", "DER"], &theirs_pem)
            .or_skip(TEST)
            .expect("pkey works once genpkey did");
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&theirs_spki),
            Some(theirs.to_public_key())
        );
        assert_eq!(theirs.to_public_key().to_spki_der(), theirs_spki);

        let (public, ours) = Ed25519::from_seed([0x3c; 32]);
        let ours_pem = ours.to_pkcs8_pem();
        let run = |args: &[&str], stdin: &[u8]| {
            openssl3(args, stdin)
                .or_skip(TEST)
                .expect("openssl works once genpkey did")
        };
        assert_eq!(
            run(&["pkey", "-pubout", "-outform", "DER"], ours_pem.as_bytes()),
            public.to_spki_der()
        );
        assert_eq!(
            run(&["pkey", "-outform", "DER"], ours_pem.as_bytes()),
            ours.to_pkcs8_der()
        );
        assert_eq!(
            run(
                &["pkey", "-pubin", "-outform", "DER"],
                public.to_spki_pem().as_bytes()
            ),
            public.to_spki_der()
        );
        let text = run(&["pkey", "-text", "-noout"], ours_pem.as_bytes());
        assert!(String::from_utf8_lossy(&text).contains("ED25519 Private-Key"));

        let message = b"RFC 8410 keys carrying RFC 8032 signatures";
        let signature = ours.sign_message_bytes(message);
        let key_file = ScratchFile::new(TEST, "key.pem", ours_pem.as_bytes());
        let public_file = ScratchFile::new(TEST, "public.pem", public.to_spki_pem().as_bytes());
        let message_file = ScratchFile::new(TEST, "message.bin", message);
        let signature_file = ScratchFile::new(TEST, "signature.bin", &signature);
        let openssl_signature = run(
            &[
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                key_file.arg(),
                "-in",
                message_file.arg(),
            ],
            b"",
        );
        assert_eq!(openssl_signature, signature);
        let verdict = run(
            &[
                "pkeyutl",
                "-verify",
                "-pubin",
                "-rawin",
                "-inkey",
                public_file.arg(),
                "-in",
                message_file.arg(),
                "-sigfile",
                signature_file.arg(),
            ],
            b"",
        );
        assert!(String::from_utf8_lossy(&verdict).contains("Signature Verified Successfully"));
    }
}
