//! Elliptic-Curve Digital Signature Algorithm (ECDSA, FIPS 186-5).
//!
//! ECDSA is the elliptic-curve analogue of DSA: rather than computing scalar
//! multiplications in a prime subgroup of `Z_p^*`, it uses the group of points
//! on a short-Weierstrass elliptic curve and produces the same `(r, s)`
//! signature shape.
//!
//! ## Algorithm summary
//!
//! **Key generation**: Choose a named curve with generator `G` and prime order
//! `n`.  Sample a uniform random scalar `d ∈ [1, n)` and set `Q = d·G`.
//! The public key is `(curve, Q)`; the private key is `(curve, d)`.
//!
//! **Signing** (given message digest representative `z` and nonce `k ∈ [1, n)`):
//! 1. Compute `(x₁, y₁) = k·G`.
//! 2. Set `r = x₁ mod n`.  If `r = 0`, retry with a new `k`.
//! 3. Set `s = k⁻¹ · (z + r·d) mod n`.  If `s = 0`, retry.
//!
//! **Verification** (given public key `Q`, representative `z`, signature `(r, s)`):
//! 1. Check `r, s ∈ [1, n)`.
//! 2. Compute `w = s⁻¹ mod n`, `u₁ = z·w mod n`, `u₂ = r·w mod n`.
//! 3. Compute `(x₁, y₁) = u₁·G + u₂·Q`.
//! 4. Accept if and only if `r ≡ x₁ (mod n)`.
//!
//! ## The value of `s`, and the low-`s` form
//!
//! Signing emits `s = k⁻¹(z + r·d) mod n` exactly as FIPS 186-5 §6.4.1 and
//! SEC 1 §4.1.3 compute it, so a deterministic signature reproduces the
//! published RFC 6979 vectors digit for digit. For every valid `(r, s)`,
//! `(r, n − s)` satisfies the same verification equation, so ECDSA signatures
//! are malleable; protocols that forbid that fix the representative with
//! `s ≤ n/2`, which [`EcdsaSignature::to_low_s`] produces. Verification
//! follows FIPS 186-5 §6.4.2 / SEC 1 §4.1.4 and accepts any `1 ≤ s < n`: a
//! verifier that rejected high-`s` would refuse about half of the conforming
//! signatures other implementations produce. Non-malleability is a protocol
//! rule, enforced by the protocol.
//!
//! ## Digests
//!
//! The digest representative is `z = bits2int(H)`: the leftmost
//! `min(N, outlen)` bits of the hash output, `N = bits(n)` (FIPS 186-5
//! §6.4.1 step 2, §6.4.2 step 2; RFC 6979 §2.3.2). An empty digest is
//! refused by signing and verification alike: no hash function produces one,
//! and it would make `z = 0`, under which the verification equation is
//! satisfiable from public data (see [`EcdsaPublicKey::verify`]).
//!
//! ## Wire form
//!
//! [`EcdsaSignature::to_der`] / [`EcdsaSignature::from_der`] are the
//! X9.62 / RFC 3279 §2.2.3 `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s
//! INTEGER }`, the encoding OpenSSL, X.509 and TLS carry.
//!
//! ## Key encodings
//!
//! The crate-defined `to_key_blob`, `to_pem` and `to_xml` forms remain the
//! defaults. A key on a named curve (P-192, P-224, P-256, P-384, P-521,
//! secp256k1, the NIST B- and K- binary curves) also has the standard
//! encodings: [`EcdsaPublicKey::to_spki_der`] (RFC 5480
//! `SubjectPublicKeyInfo`, PEM label `PUBLIC KEY`),
//! [`EcdsaPrivateKey::to_sec1_der`] (RFC 5915 `ECPrivateKey`, PEM label
//! `EC PRIVATE KEY`) and [`EcdsaPrivateKey::to_pkcs8_der`] (RFC 5958
//! `OneAsymmetricKey`, PEM label `PRIVATE KEY`), each with a PEM form and a
//! decoder.
//!
//! ## Side-channel note
//!
//! Three steps run in time that depends on their operands: the scalar
//! multiplication in [`ec`] (a fixed-window ladder whose table indices depend
//! on the bits of `k` and `d`), the inversion of the nonce
//! ([`CurveParams::scalar_invert`], a binary extended Euclid whose step count
//! depends on `k`), and [`EcdsaSignature::to_low_s`], which branches on `s`
//! (a public value, so that branch reveals nothing secret). This
//! implementation is suitable for educational and experimental use; replace
//! the ladder and the inversion with constant-time ones before deploying
//! against side-channel adversaries.
//!
//! [`ec`]: crate::public_key::ec

use core::fmt;

use crate::hash::Digest;
use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::public_key::primes::{random_nonzero_below, MAX_NONCE_DRAWS};
use crate::public_key::rfc6979::{bits_to_int, NonceGenerator};
use crate::Csprng;
use rump::BigUint;

// ─── Key and signature types ─────────────────────────────────────────────────

/// Public key for ECDSA.
///
/// Stores the curve parameters and the public point `Q = d·G`.
#[derive(Clone, Debug)]
pub struct EcdsaPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for ECDSA.
///
/// Stores the curve parameters and the secret scalar `d ∈ [1, n)`.
/// The matching public key is derived on demand via [`to_public_key`].
///
/// [`to_public_key`]: EcdsaPrivateKey::to_public_key
#[derive(Clone)]
pub struct EcdsaPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

/// Raw ECDSA signature pair `(r, s)`.
///
/// Both components are positive integers in `[1, n)` relative to the subgroup
/// order of the signing curve.  The serialized form is a DER `SEQUENCE` of
/// two `INTEGER` values, matching the shape used by [`DsaSignature`].
///
/// [`DsaSignature`]: crate::public_key::dsa::DsaSignature
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcdsaSignature {
    r: BigUint,
    s: BigUint,
}

/// Namespace wrapper for the ECDSA construction.
pub struct Ecdsa;

// ─── EcdsaPublicKey ───────────────────────────────────────────────────────────

impl EcdsaPublicKey {
    /// The curve parameters for this key.
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The public point `Q = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &AffinePoint {
        &self.q
    }

    /// Encode the public point as a compact SEC 1 point string.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Rebuild a public key from a SEC 1 point octet string (§2.3.4) plus
    /// explicit curve parameters.
    ///
    /// Returns `None` unless the point is a valid public key (SEC 1 §3.2.2.1):
    /// not the point at infinity, with coordinates in the field, on the curve,
    /// and in the prime-order subgroup. The single octet `00` decodes to the
    /// point at infinity and is refused: under `Q = ∞` verification computes
    /// `u₁·G + u₂·∞ = u₁·G`, which anyone can satisfy from public data.
    #[must_use]
    pub fn from_wire_bytes(curve: CurveParams, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        Some(Self { curve, q })
    }

    /// Convenience: hashes `message` with `H` then calls [`verify`][Self::verify].
    #[must_use]
    pub fn verify_message<H: Digest>(&self, message: &[u8], signature: &EcdsaSignature) -> bool {
        let digest = H::digest(message);
        self.verify(&digest, signature)
    }

    /// Convenience: hashes `message` with `H` then calls [`verify_bytes`][Self::verify_bytes].
    #[must_use]
    pub fn verify_message_bytes<H: Digest>(&self, message: &[u8], signature: &[u8]) -> bool {
        let digest = H::digest(message);
        self.verify_bytes(&digest, signature)
    }

    /// Verify `signature` over a raw digest byte string: FIPS 186-5 §6.4.2.
    ///
    /// The digest is reduced to the representative `z`, its leftmost
    /// `min(N, outlen)` bits with `N = bits(n)` (§6.4.2 step 2), and handed
    /// to [`Self::verify_digest_scalar`]. An empty digest is refused: no hash
    /// function produces one, and it would give `z = 0`.
    ///
    /// Under `z ≡ 0 (mod n)` the verification equation has a solution with
    /// no private key: `u₁ = z·s⁻¹ = 0`, so `u₁·G + u₂·Q = (r·s⁻¹)·Q`; for
    /// any `t`, `r = x(t·Q) mod n` and `s = r·t⁻¹ mod n` give `u₂ = t` and
    /// the check `x(t·Q) mod n = r` passes. This is a property of the
    /// equation, not of an implementation, and FIPS 186-5 has the verifier
    /// accept it: a hash output that is `0 mod n` occurs with probability
    /// about `2⁻ᴺ`, so the standard leaves the case to the hash. Only the
    /// empty digest, which is not a hash output, is refused here.
    #[must_use]
    pub fn verify(&self, digest: &[u8], signature: &EcdsaSignature) -> bool {
        if digest.is_empty() {
            return false;
        }
        let z = digest_to_scalar(digest, &self.curve.n);
        self.verify_digest_scalar(&z, signature)
    }

    /// Core ECDSA verification over a pre-reduced representative `z`
    /// (FIPS 186-5 §6.4.2 steps 3 to 8). See [`Self::verify`] for what
    /// `z ≡ 0 (mod n)` means to the equation.
    #[must_use]
    pub fn verify_digest_scalar(&self, hash: &BigUint, signature: &EcdsaSignature) -> bool {
        let n = &self.curve.n;

        // FIPS 186-5 §6.4.2 has the verifier check the validity of Q, and
        // every constructor of this type does (SEC 1 §3.2.2.1). The identity
        // is refused here as well: under Q = ∞, u₁·G + u₂·Q = u₁·G, and
        // (r, s) = (x(z·G) mod n, 1) would verify for any digest z.
        if self.q.is_infinity() {
            return false;
        }

        // FIPS 186-5 §6.4.2 step 1: both components must lie in [1, n). Any
        // s in that range is accepted; the low-s form is not a verification
        // requirement (see the module docs).
        if signature.r.is_zero() || signature.s.is_zero() || &signature.r >= n || &signature.s >= n
        {
            return false;
        }

        // Step 3: w = s⁻¹ mod n.
        let Some(w) = self.curve.scalar_invert(&signature.s) else {
            return false;
        };

        // u₁ = z·w mod n,  u₂ = r·w mod n
        let scalar_ctx = self.curve.scalar_ctx();
        let u1 = scalar_ctx.mul(hash, &w);
        let u2 = scalar_ctx.mul(&signature.r, &w);

        // (x₁, y₁) = u₁·G + u₂·Q
        let g = self.curve.base_point();
        let term1 = self.curve.scalar_mul(&g, &u1);
        let term2 = self.curve.scalar_mul(&self.q, &u2);
        let sum = self.curve.add(&term1, &term2);

        if sum.is_infinity() {
            return false;
        }

        // Accept iff r ≡ x₁ (mod n).
        sum.x.rem(n) == signature.r
    }

    /// Verify a byte-encoded signature produced by
    /// [`EcdsaPrivateKey::sign_digest_bytes`].
    #[must_use]
    pub fn verify_bytes(&self, digest: &[u8], signature: &[u8]) -> bool {
        let Some(sig) = EcdsaSignature::from_key_blob(signature) else {
            return false;
        };
        self.verify(digest, &sig)
    }
}

crate::public_key::ec_io::impl_ec_public_key_io!(
    EcdsaPublicKey,
    "CRYPTOGRAPHY ECDSA PUBLIC KEY",
    "EcdsaPublicKey"
);

// ─── EcdsaPrivateKey ──────────────────────────────────────────────────────────

impl EcdsaPrivateKey {
    /// The curve parameters for this key.
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The private scalar `d ∈ [1, n)`.
    #[must_use]
    pub fn private_scalar(&self) -> &BigUint {
        &self.d
    }

    /// Derive the matching public key `Q = d·G`.
    #[must_use]
    pub fn to_public_key(&self) -> EcdsaPublicKey {
        EcdsaPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Sign with an explicit nonce `k`.
    ///
    /// ECDSA requires a fresh `k ∈ [1, n)` for every signature. This
    /// lower-level entry point keeps the arithmetic explicit for fixed-vector
    /// tests.
    ///
    /// Reusing the same `k` for two different messages with the same key
    /// immediately reveals the private scalar. Outside of fixed vectors,
    /// prefer [`Self::sign_digest`] or [`Self::sign_message`].
    ///
    /// Returns the FIPS 186-5 §6.4.1 value `s = k⁻¹(z + r·d) mod n` itself;
    /// [`EcdsaSignature::to_low_s`] gives the `s ≤ n/2` representative.
    /// Returns `None` if `k ∉ [1, n)`, if the digest is empty (see the module
    /// docs), or if `r = 0` or `s = 0`, the cases in which §6.4.1 draws a new
    /// `k`.
    #[must_use]
    pub fn sign_digest_with_nonce(&self, digest: &[u8], nonce: &BigUint) -> Option<EcdsaSignature> {
        let n = &self.curve.n;
        if nonce.is_zero() || nonce >= n || digest.is_empty() {
            return None;
        }

        let z = digest_to_scalar(digest, n);

        // (x₁, y₁) = k·G
        let r_point = self.curve.scalar_mul(&self.curve.base_point(), nonce);
        if r_point.is_infinity() {
            return None;
        }
        let r = r_point.x.rem(n);
        if r.is_zero() {
            return None;
        }

        // s = k⁻¹ · (z + r·d) mod n
        let scalar_ctx = self.curve.scalar_ctx();
        let k_inv = self.curve.scalar_invert(nonce)?;
        let rd = scalar_ctx.mul(&r, &self.d);
        let z_plus_rd = z.add(&rd).rem(n);
        let s = scalar_ctx.mul(&k_inv, &z_plus_rd);
        if s.is_zero() {
            return None;
        }

        Some(EcdsaSignature { r, s })
    }

    /// Sign a digest using RFC 6979 deterministic nonce derivation.
    ///
    /// The nonce stream is RFC 6979 §3.2's: a candidate rejected for `r = 0`
    /// or `s = 0` advances the K/V state through step h.3 and the next one is
    /// tried, so the signature is a function of the key and digest alone. At
    /// most [`MAX_NONCE_DRAWS`] candidates are tried; an empty digest, or
    /// caller-built parameters under which every candidate fails (an `n`
    /// that is not the order of `G` can make every `k·G` reduce to `r = 0`),
    /// gives `None` rather than an unbounded search.
    #[must_use]
    pub fn sign_digest<H: Digest>(&self, digest: &[u8]) -> Option<EcdsaSignature> {
        if digest.is_empty() {
            return None;
        }
        let mut nonces = NonceGenerator::<H>::new(&self.curve.n, &self.d, digest)?;
        (0..MAX_NONCE_DRAWS).find_map(|_| self.sign_digest_with_nonce(digest, &nonces.next()))
    }

    /// Sign a digest using a fresh random nonce `k` in `[1, n)` from `rng`.
    ///
    /// FIPS 186-5 §6.4.1 has signing draw a new `k` whenever `r = 0` or
    /// `s = 0`. A working random source hits either case with probability
    /// about `2/n` per draw, so this returns after the first draw in practice
    /// and refuses, with `None`, only after [`MAX_NONCE_DRAWS`] consecutive
    /// in-range draws have all failed: the signature of a broken source that
    /// repeats a `k` zeroing `s` for this key and digest. An empty digest
    /// also gives `None`.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the nonce sampler
    /// rejects (`rump::random::random_nonzero_below`'s bound): zero, or a
    /// value at or above `n` within `n`'s bit width. Each draw is accepted
    /// with probability at least one half, so a working source reaches this
    /// with probability at most `2⁻²⁵⁶`; an all-zero source reaches it at
    /// once. Such a source is not reported as `None`.
    #[must_use]
    pub fn sign_digest_with_rng<R: Csprng>(
        &self,
        digest: &[u8],
        rng: &mut R,
    ) -> Option<EcdsaSignature> {
        if digest.is_empty() {
            return None;
        }
        (0..MAX_NONCE_DRAWS).find_map(|_| {
            let nonce = random_nonzero_below(rng, &self.curve.n)?;
            self.sign_digest_with_nonce(digest, &nonce)
        })
    }

    /// Hash one message with `H`, then sign deterministically.
    #[must_use]
    pub fn sign_message<H: Digest>(&self, message: &[u8]) -> Option<EcdsaSignature> {
        let digest = H::digest(message);
        self.sign_digest::<H>(&digest)
    }

    /// Hash one message with `H`, then sign with randomized nonces.
    ///
    /// # Panics
    ///
    /// As [`Self::sign_digest_with_rng`]: when `rng` yields 256 consecutive
    /// draws the nonce sampler rejects.
    #[must_use]
    pub fn sign_message_with_rng<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<EcdsaSignature> {
        let digest = H::digest(message);
        self.sign_digest_with_rng(&digest, rng)
    }

    /// Sign and serialize a digest using deterministic nonce derivation.
    #[must_use]
    pub fn sign_digest_bytes<H: Digest>(&self, digest: &[u8]) -> Option<Vec<u8>> {
        let sig = self.sign_digest::<H>(digest)?;
        Some(sig.to_key_blob())
    }

    /// Sign and serialize a digest using randomized nonces.
    ///
    /// # Panics
    ///
    /// As [`Self::sign_digest_with_rng`]: when `rng` yields 256 consecutive
    /// draws the nonce sampler rejects.
    #[must_use]
    pub fn sign_digest_bytes_with_rng<R: Csprng>(
        &self,
        digest: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let sig = self.sign_digest_with_rng(digest, rng)?;
        Some(sig.to_key_blob())
    }

    /// Hash one message with `H`, then sign and serialize deterministically.
    #[must_use]
    pub fn sign_message_bytes<H: Digest>(&self, message: &[u8]) -> Option<Vec<u8>> {
        let sig = self.sign_message::<H>(message)?;
        Some(sig.to_key_blob())
    }

    /// Hash one message with `H`, then sign and serialize with randomized nonces.
    ///
    /// # Panics
    ///
    /// As [`Self::sign_digest_with_rng`]: when `rng` yields 256 consecutive
    /// draws the nonce sampler rejects.
    #[must_use]
    pub fn sign_message_bytes_with_rng<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let sig = self.sign_message_with_rng::<H, R>(message, rng)?;
        Some(sig.to_key_blob())
    }
}

crate::public_key::ec_io::impl_ec_private_key_io!(
    EcdsaPrivateKey,
    "CRYPTOGRAPHY ECDSA PRIVATE KEY",
    "EcdsaPrivateKey"
);

crate::public_key::ec_pkix::impl_ec_key_encodings!(EcdsaPublicKey, EcdsaPrivateKey, Unrestricted);

impl fmt::Debug for EcdsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaPrivateKey(<redacted>)")
    }
}

// ─── EcdsaSignature ───────────────────────────────────────────────────────────

impl EcdsaSignature {
    /// The `r` component: the x-coordinate of `k·G` reduced mod `n`.
    /// Valid signatures have `r ∈ [1, n)`.
    #[must_use]
    pub fn r(&self) -> &BigUint {
        &self.r
    }

    /// The `s` component: `k⁻¹·(z + r·d) mod n`, as FIPS 186-5 §6.4.1
    /// computes it. Verification accepts any `s ∈ [1, n)`, as FIPS 186-5 and
    /// SEC 1 require; [`Self::to_low_s`] gives the `s ≤ n/2` representative.
    #[must_use]
    pub fn s(&self) -> &BigUint {
        &self.s
    }

    /// This signature with `s` replaced by `n − s` when `s > n/2`, so that
    /// `s ≤ (n − 1)/2`: the low-`s` representative of the pair `{s, n − s}`
    /// that protocols forbidding signature malleability require. `n` is the
    /// order of `curve`, the signing key's curve. A signature already in
    /// that form is returned unchanged; either form verifies under FIPS
    /// 186-5 §6.4.2.
    ///
    /// This branches on `s`, a public value.
    #[must_use]
    pub fn to_low_s(&self, curve: &CurveParams) -> Self {
        let mut half = curve.n.clone();
        half.shr1();
        let s = if self.s > half {
            curve.n.sub(&self.s)
        } else {
            self.s.clone()
        };
        Self {
            r: self.r.clone(),
            s,
        }
    }

    /// Encode as the X9.62 / RFC 3279 §2.2.3 `ECDSA-Sig-Value`:
    /// `SEQUENCE { r INTEGER, s INTEGER }` in strict DER.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        encode_biguints(&[&self.r, &self.s])
    }

    /// Decode an X9.62 / RFC 3279 §2.2.3 `ECDSA-Sig-Value`.
    ///
    /// Strict DER only (minimal lengths, minimal non-negative `INTEGER`s, no
    /// trailing bytes). Zero components are rejected here; the range check
    /// against the curve order happens during verification because the
    /// structure does not carry the curve.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(der)?.into_iter();
        let r = fields.next()?;
        let s = fields.next()?;
        if fields.next().is_some() || r.is_zero() || s.is_zero() {
            return None;
        }
        Some(Self { r, s })
    }

    /// The crate-defined signature blob. For ECDSA this is byte-identical to
    /// [`Self::to_der`]: the crate's integer-sequence framing *is* the
    /// standard `ECDSA-Sig-Value`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        self.to_der()
    }

    /// Decode the crate-defined signature blob; identical to
    /// [`Self::from_der`].
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        Self::from_der(blob)
    }
}

// ─── Ecdsa namespace ──────────────────────────────────────────────────────────

impl Ecdsa {
    /// Returns `(public_key, private_key)`: `d` uniform in `[1, n)` by
    /// rejection sampling (FIPS 186-5 §A.2.2, SEC 1 §3.2.1), `Q = d·G`.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the sampler rejects
    /// (`rump::random::random_nonzero_below`'s bound). Each draw is accepted
    /// with probability at least one half, so a working source reaches this
    /// with probability at most `2⁻²⁵⁶`; a source stuck on zero, or on values
    /// at or above `n` within its bit width, reaches it at once.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: CurveParams,
        rng: &mut R,
    ) -> (EcdsaPublicKey, EcdsaPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        let public = EcdsaPublicKey {
            curve: curve.clone(),
            q: q.clone(),
        };
        let private = EcdsaPrivateKey { curve, d, q };
        (public, private)
    }

    /// Derive a key pair from an explicit curve and secret scalar.
    ///
    /// Returns `None` if `secret` is zero or ≥ `n`, or if `secret·G` is not a
    /// valid public key (SEC 1 §3.2.2.1), which happens only when the curve's
    /// `n` is not the order of its `G`.
    #[must_use]
    pub fn from_secret_scalar(
        curve: CurveParams,
        secret: &BigUint,
    ) -> Option<(EcdsaPublicKey, EcdsaPrivateKey)> {
        let q = curve.public_point_for_scalar(secret)?;
        Some((
            EcdsaPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EcdsaPrivateKey {
                curve,
                d: secret.clone(),
                q,
            },
        ))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// The digest representative `z` of FIPS 186-5 §6.4.1 step 2 and §6.4.2
/// step 2: the leftmost `min(N, outlen)` bits of the hash output, where
/// `N = bits(n)` and `outlen` is the output's bit length, read as a
/// big-endian integer (RFC 6979 §2.3.2 `bits2int`). The shift amount comes
/// from `digest.len() * 8`, not from the trimmed width of the integer, so it
/// does not depend on leading zero bits.
fn digest_to_scalar(digest: &[u8], modulus: &BigUint) -> BigUint {
    bits_to_int(digest, modulus.bits())
}

#[cfg(test)]
mod tests {
    use super::{Ecdsa, EcdsaPrivateKey, EcdsaPublicKey, EcdsaSignature};
    use crate::public_key::ec::{b163, p256, p384, p521, secp256k1};
    use crate::public_key::io::encode_biguints;
    use crate::test_utils::decode_hex;
    use crate::{CtrDrbgAes256, Sha256, Sha384, Sha512};
    use rump::BigUint;

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0xab; 48])
    }

    crate::public_key::ec_io::ec_key_io_tests!(
        Ecdsa,
        EcdsaPublicKey,
        EcdsaPrivateKey,
        "CRYPTOGRAPHY ECDSA PUBLIC KEY",
        "CRYPTOGRAPHY ECDSA PRIVATE KEY",
        "EcdsaPublicKey",
        "EcdsaPrivateKey"
    );

    /// `y² = x³ + 2x + 2` over `F_17` with `G = (5, 1)` of order 19: the
    /// textbook curve of Paar and Pelzl, *Understanding Cryptography*
    /// (Springer, 2010), Example 9.5. Small enough to check every signature
    /// by hand.
    fn toy_curve() -> crate::public_key::ec::CurveParams {
        crate::public_key::ec::CurveParams::new(
            BigUint::from_u64(17),
            BigUint::from_u64(2),
            BigUint::from_u64(2),
            BigUint::from_u64(19),
            1,
            BigUint::from_u64(5),
            BigUint::one(),
        )
        .expect("valid toy curve")
    }

    // ── Sign-and-verify round trips ──────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"hello world";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        assert!(public.verify_message::<Sha256>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_p384() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p384(), &mut rng);
        let msg = b"p384 test message";
        let sig = private.sign_message::<Sha384>(msg).expect("sign");
        assert!(public.verify_message::<Sha384>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_secp256k1() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(secp256k1(), &mut rng);
        let msg = b"secp256k1 test";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        assert!(public.verify_message::<Sha256>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_p521() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p521(), &mut rng);
        let msg = b"p521 test message";
        let sig = private.sign_message::<Sha512>(msg).expect("sign");
        assert!(public.verify_message::<Sha512>(msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip_b163() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(b163(), &mut rng);
        let msg = b"binary curve ecdsa";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        assert!(public.verify_message::<Sha256>(msg, &sig));
    }

    // ── Deterministic signing via explicit nonce ──────────────────────────────

    #[test]
    fn sign_digest_with_nonce_is_deterministic() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = [0x42u8; 32];
        let k = BigUint::from_u64(12_345_678_901_234_567_u64);
        let sig1 = private
            .sign_digest_with_nonce(&digest, &k)
            .expect("first sign");
        let sig2 = private
            .sign_digest_with_nonce(&digest, &k)
            .expect("second sign");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_digest_with_nonce_repeatable_for_fixed_nonce() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = [0x42u8; 32];
        let nonce = BigUint::from_u64(12_345_678_901_234_567_u64);
        let lhs = private
            .sign_digest_with_nonce(&digest, &nonce)
            .expect("first");
        let rhs = private
            .sign_digest_with_nonce(&digest, &nonce)
            .expect("second");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn sign_digest_with_nonce_zero_rejected() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = [0x00u8; 32];
        assert!(private
            .sign_digest_with_nonce(&digest, &BigUint::zero())
            .is_none());
    }

    #[test]
    fn sign_digest_with_nonce_equal_to_n_rejected() {
        let curve = p256();
        let n = curve.n.clone();
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(curve, &mut rng);
        let digest = [0x01u8; 32];
        assert!(private.sign_digest_with_nonce(&digest, &n).is_none());
    }

    /// Signing returns `s = k⁻¹(z + r·d) mod n` itself: on the RFC 6979
    /// A.2.5 vector, whose published `s` is above `n/2`, the signature equals
    /// the published one. `to_low_s` replaces `s` by `n − s` exactly when
    /// `s > (n − 1)/2`, is idempotent, and leaves `s = (n − 1)/2` alone while
    /// flipping `s = (n + 1)/2` onto it.
    #[test]
    fn signing_emits_the_fips_value_and_to_low_s_flips_only_high_s() {
        let (public, private, vector) = rfc6979_p256_sample();
        let curve = private.curve();
        let mut half = curve.n.clone();
        half.shr1();
        assert!(vector.s > half, "the published s is high");

        let signed = private.sign_message::<Sha256>(b"sample").expect("sign");
        assert_eq!(signed, vector);
        let low = signed.to_low_s(curve);
        assert_eq!(low.r, signed.r);
        assert_eq!(low.s, curve.n.sub(&signed.s));
        assert!(low.s <= half);
        assert_eq!(low.to_low_s(curve), low);
        assert!(public.verify_message::<Sha256>(b"sample", &signed));
        assert!(public.verify_message::<Sha256>(b"sample", &low));

        let at_half = EcdsaSignature {
            r: BigUint::one(),
            s: half.clone(),
        };
        assert_eq!(at_half.to_low_s(curve), at_half);
        let above_half = EcdsaSignature {
            r: BigUint::one(),
            s: half.add(&BigUint::one()),
        };
        assert_eq!(above_half.to_low_s(curve), at_half);
    }

    /// An empty digest is refused by every signing and verification entry
    /// point. Under `z = 0` the verification equation is satisfiable from
    /// public data alone: for any `t`, `r = x(t·Q) mod n` and
    /// `s = r·t⁻¹ mod n` give `u₁ = 0`, `u₂ = t` and `x(t·Q) mod n = r`.
    /// A 32-octet all-zero digest has the shape of a hash output and is
    /// accepted: a genuine signature over it verifies and a tampered one does
    /// not. Its `z` is 0 as well, so the same forgery verifies against it,
    /// as FIPS 186-5 §6.4.2 has it: the equation, not the empty-digest
    /// refusal, is where the structure lives, and a hash output of zero has
    /// probability about `2⁻²⁵⁶`.
    #[test]
    fn empty_digest_is_refused_and_the_zero_representative_forgery_is_the_equations_own() {
        let curve = p256();
        let (public, private) = Ecdsa::generate(curve.clone(), &mut rng());
        let t = BigUint::from_u64(0x1234_5678_9abc);
        let r = curve.scalar_mul(public.public_point(), &t).x.rem(&curve.n);
        let s = curve
            .scalar_ctx()
            .mul(&r, &curve.scalar_invert(&t).expect("t ≠ 0"));
        let forged = EcdsaSignature { r, s };
        assert!(public.verify_digest_scalar(&BigUint::zero(), &forged));

        assert!(!public.verify(&[], &forged));
        assert!(!public.verify_bytes(&[], &forged.to_der()));
        assert!(private.sign_digest::<Sha256>(&[]).is_none());
        assert!(private
            .sign_digest_with_nonce(&[], &BigUint::from_u64(7))
            .is_none());
        assert!(private.sign_digest_with_rng(&[], &mut rng()).is_none());
        assert!(private.sign_digest_bytes::<Sha256>(&[]).is_none());

        let zeros = [0u8; 32];
        let genuine = private.sign_digest::<Sha256>(&zeros).expect("sign");
        assert!(public.verify(&zeros, &genuine));
        let tampered = EcdsaSignature {
            r: genuine.r.clone(),
            s: genuine.s.add(&BigUint::one()),
        };
        assert!(!public.verify(&zeros, &tampered));
        assert!(!public.verify(&Sha256::digest(b"other"), &genuine));
        assert!(public.verify(&zeros, &forged));
    }

    // ── Rejection tests ───────────────────────────────────────────────────────

    #[test]
    fn wrong_message_rejected() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"correct message";
        let wrong = b"wrong message";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        assert!(!public.verify_message::<Sha256>(wrong, &sig));
    }

    #[test]
    fn tampered_r_rejected() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"message";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        let bad = EcdsaSignature {
            r: sig.r.add(&BigUint::one()),
            s: sig.s.clone(),
        };
        assert!(!public.verify_message::<Sha256>(msg, &bad));
    }

    #[test]
    fn tampered_s_rejected() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"message";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        let bad = EcdsaSignature {
            r: sig.r.clone(),
            s: sig.s.add(&BigUint::one()),
        };
        assert!(!public.verify_message::<Sha256>(msg, &bad));
    }

    #[test]
    fn wrong_key_rejected() {
        let mut rng = rng();
        let (_, private1) = Ecdsa::generate(p256(), &mut rng);
        let (public2, _) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"message";
        let sig = private1.sign_message::<Sha256>(msg).expect("sign");
        assert!(!public2.verify_message::<Sha256>(msg, &sig));
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_matches_generated() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        // Signing with private and verifying with the derived public key must work.
        let msg = b"derived key test";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        assert!(derived.verify_message::<Sha256>(msg, &sig));
        // The derived public point must match the original.
        assert_eq!(derived.q, public.q);
    }

    // ── from_secret_scalar ────────────────────────────────────────────────────

    #[test]
    fn from_secret_scalar_rejects_zero() {
        assert!(Ecdsa::from_secret_scalar(p256(), &BigUint::zero()).is_none());
    }

    #[test]
    fn from_secret_scalar_rejects_out_of_range() {
        let curve = p256();
        let too_large = curve.n.clone();
        assert!(Ecdsa::from_secret_scalar(curve, &too_large).is_none());
    }

    // ── Serialization: binary ─────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(p256(), &mut rng);
        let blob = public.to_key_blob();
        let recovered = EcdsaPublicKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
        assert_eq!(recovered.curve.n, public.curve.n);
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(p256(), &mut rng);
        let bytes = public.to_wire_bytes();
        let recovered = EcdsaPublicKey::from_wire_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
        assert_eq!(recovered.curve.n, public.curve.n);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let blob = private.to_key_blob();
        let recovered = EcdsaPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
        assert_eq!(recovered.curve.n, private.curve.n);
    }

    #[test]
    fn signature_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"roundtrip test";
        let sig = private.sign_message::<Sha256>(msg).expect("sign");
        let blob = sig.to_key_blob();
        let recovered = EcdsaSignature::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered, sig);
    }

    // ── Serialization: PEM ────────────────────────────────────────────────────

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDSA PUBLIC KEY"));
        let recovered = EcdsaPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDSA PRIVATE KEY"));
        let recovered = EcdsaPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    // ── Serialization: XML ────────────────────────────────────────────────────

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdsa::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EcdsaPublicKey"));
        let recovered = EcdsaPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        assert!(xml.contains("EcdsaPrivateKey"));
        let recovered = EcdsaPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    // ── Byte-level sign_bytes / verify_bytes ──────────────────────────────────

    #[test]
    fn sign_bytes_verify_bytes_roundtrip() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let digest = Sha256::digest(b"test message bytes");
        let sig_bytes = private
            .sign_digest_bytes::<Sha256>(&digest)
            .expect("sign_digest_bytes");
        assert!(public.verify_bytes(&digest, &sig_bytes));
    }

    #[test]
    fn sign_message_bytes_verify_message_bytes_roundtrip() {
        let mut rng = rng();
        let (public, private) = Ecdsa::generate(p256(), &mut rng);
        let msg = b"end-to-end bytes test";
        let sig_bytes = private
            .sign_message_bytes::<Sha256>(msg)
            .expect("sign_message_bytes");
        assert!(public.verify_message_bytes::<Sha256>(msg, &sig_bytes));
    }

    // ── Debug impl ────────────────────────────────────────────────────────────

    #[test]
    fn private_key_debug_redacted() {
        let mut rng = rng();
        let (_, private) = Ecdsa::generate(p256(), &mut rng);
        let s = format!("{private:?}");
        assert_eq!(s, "EcdsaPrivateKey(<redacted>)");
        // The scalar itself must not appear.
        assert!(!s.contains(&format!("{:?}", private.d)));
    }

    /// RFC 6979 retries on the toy curve, checked by hand. `n = 19` has five
    /// bits, so a one-octet digest `h` gives `z = h >> 3`. The multiples of
    /// `G` used: `4G = (3, 1)`, `9G = (7, 6)`, `12G = (0, 11)`, `13G = (16, 4)`;
    /// the inverses mod 19: `13⁻¹ = 3`, `4⁻¹ = 5`. The nonces are what the
    /// SHA-256 HMAC-DRBG chain of §3.2 yields for these keys and digests.
    ///
    /// - `d = 2`, digest `08`: `z = 1`. First `k = 12`: `r = 0`, rejected.
    ///   Then `k = 13`: `r = 16`, `s = 3·(1 + 16·2) = 3·33 ≡ 3·14 = 42 ≡ 4`.
    /// - `d = 1`, digest `60`: `z = 12`. First `k = 9`: `r = 7`,
    ///   `s = 9⁻¹·(12 + 7) = 9⁻¹·19 ≡ 0`, rejected. Then `k = 4`: `r = 3`,
    ///   `s = 5·(12 + 3) = 75 ≡ 18`, the FIPS value; its low-`s` form is 1.
    #[test]
    fn deterministic_signing_retries_zero_r_and_s() {
        for (x, digest, rejected, r, s) in [(2, 0x08, 12, 16, 4), (1, 0x60, 9, 3, 18)] {
            let curve = toy_curve();
            let (public, private) = Ecdsa::from_secret_scalar(curve.clone(), &BigUint::from_u64(x))
                .expect("valid scalar");
            assert!(private
                .sign_digest_with_nonce(&[digest], &BigUint::from_u64(rejected))
                .is_none());
            let signature = private.sign_digest::<Sha256>(&[digest]).expect("retry");
            assert_eq!(signature.r, BigUint::from_u64(r));
            assert_eq!(signature.s, BigUint::from_u64(s));
            assert!(public.verify(&[digest], &signature));
            assert!(public.verify(&[digest], &signature.to_low_s(&curve)));
            assert_eq!(private.sign_digest::<Sha256>(&[digest]), Some(signature));
        }
        let (_, private) =
            Ecdsa::from_secret_scalar(toy_curve(), &BigUint::one()).expect("valid scalar");
        let low = private
            .sign_digest::<Sha256>(&[0x60])
            .expect("sign")
            .to_low_s(&toy_curve());
        assert_eq!(low.s, BigUint::one());
    }

    /// Caller-built parameters under which no nonce ever signs, so the
    /// deterministic signer must give up rather than search forever:
    /// `y² = x³ − x` over `F_17` with `G = (0, 0)`, a point of order 2, and
    /// the claimed order `n = 3`. The only nonces are `k = 1`, for which
    /// `k·G = G` has `x = 0` and so `r = 0`, and `k = 2`, for which `k·G = ∞`.
    /// Both signers return `None` after `MAX_NONCE_DRAWS` candidates. No
    /// constructor forms such a key (`public_point_for_scalar` refuses `G`
    /// under `n = 3`), so the test assembles it directly.
    #[test]
    fn deterministic_signing_gives_up_when_every_nonce_fails() {
        use crate::public_key::ec::CurveParams;
        let curve = CurveParams::new(
            BigUint::from_u64(17),
            BigUint::from_u64(16),
            BigUint::zero(),
            BigUint::from_u64(3),
            1,
            BigUint::zero(),
            BigUint::zero(),
        )
        .expect("odd p and n");
        let g = curve.base_point();
        assert!(curve.is_on_curve(&g));
        assert!(curve.double(&g).is_infinity());
        assert!(Ecdsa::from_secret_scalar(curve.clone(), &BigUint::one()).is_none());
        let private = EcdsaPrivateKey {
            curve,
            d: BigUint::one(),
            q: g,
        };
        for k in [1u64, 2] {
            assert!(private
                .sign_digest_with_nonce(&[0x5a], &BigUint::from_u64(k))
                .is_none());
        }
        assert!(private.sign_digest::<Sha256>(&[0x5a]).is_none());
        assert!(private.sign_digest_with_rng(&[0x5a], &mut rng()).is_none());
    }

    /// RFC 6979 Appendix A.2.5, P-256 / SHA-256, message "sample".
    fn rfc6979_p256_sample() -> (EcdsaPublicKey, EcdsaPrivateKey, EcdsaSignature) {
        let x = BigUint::from_be_bytes(&decode_hex(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        ));
        let (public, private) =
            Ecdsa::from_secret_scalar(p256(), &x).expect("RFC secret scalar must be valid");
        let vector = EcdsaSignature {
            r: BigUint::from_be_bytes(&decode_hex(
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            )),
            s: BigUint::from_be_bytes(&decode_hex(
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
            )),
        };
        (public, private, vector)
    }

    #[test]
    fn rfc6979_ecdsa_p256_sha256_sample_vector_verifies_as_published() {
        // The published s is above n/2. A standard verifier accepts it as-is.
        let (public, private, vector) = rfc6979_p256_sample();
        let mut half_n = private.curve.n.clone();
        half_n.shr1();
        assert!(vector.s.cmp(&half_n).is_gt(), "vector s is high-s");
        assert!(public.verify_message::<Sha256>(b"sample", &vector));
        assert!(!public.verify_message::<Sha256>(b"test", &vector));
    }

    #[test]
    fn both_s_and_n_minus_s_verify() {
        let (public, private, vector) = rfc6979_p256_sample();
        let flipped = EcdsaSignature {
            r: vector.r.clone(),
            s: private.curve.n.sub(&vector.s),
        };
        assert_ne!(flipped.s, vector.s);
        assert!(public.verify_message::<Sha256>(b"sample", &vector));
        assert!(public.verify_message::<Sha256>(b"sample", &flipped));
        // The signer emits the published (high) value; `to_low_s` is the flip.
        let ours = private.sign_message::<Sha256>(b"sample").expect("sign");
        assert_eq!(ours, vector);
        assert_eq!(ours.to_low_s(private.curve()), flipped);
        // s = n and s = 0 stay outside [1, n).
        for bad_s in [private.curve.n.clone(), BigUint::zero()] {
            let bad = EcdsaSignature {
                r: vector.r.clone(),
                s: bad_s,
            };
            assert!(!public.verify_message::<Sha256>(b"sample", &bad));
        }
    }

    #[test]
    fn der_signature_roundtrip_and_strictness() {
        let (_, _, vector) = rfc6979_p256_sample();
        let der = vector.to_der();
        // ECDSA-Sig-Value: SEQUENCE of two INTEGERs; both components here
        // have the high bit set, so each carries one sign octet.
        assert_eq!(der[0], 0x30);
        assert_eq!(der.len(), 2 + 2 * (2 + 33));
        assert_eq!(EcdsaSignature::from_der(&der), Some(vector.clone()));
        assert_eq!(vector.to_key_blob(), der);
        assert_eq!(EcdsaSignature::from_key_blob(&der), Some(vector));

        // Non-minimal INTEGER (extra leading zero), trailing byte, and a
        // zero component are all rejected.
        let mut padded = der.clone();
        padded.splice(4..4, [0x00]);
        padded[1] += 1;
        padded[3] += 1;
        assert!(EcdsaSignature::from_der(&padded).is_none());
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(EcdsaSignature::from_der(&trailing).is_none());
        let zero_s = encode_biguints(&[&BigUint::from_u64(7), &BigUint::zero()]);
        assert!(EcdsaSignature::from_der(&zero_s).is_none());
        let three = encode_biguints(&[&BigUint::one(), &BigUint::one(), &BigUint::one()]);
        assert!(EcdsaSignature::from_der(&three).is_none());
    }

    /// Cross-check against the installed OpenSSL/LibreSSL: signatures it
    /// produces (about half of them high-s, since it does not canonicalize)
    /// must verify here, and our signatures, as signed and in both forms of
    /// `{s, n − s}`, must verify there. The check skips, loudly, when no
    /// `openssl` binary is available.
    #[test]
    fn openssl_p256_sha256_interop() {
        use crate::test_utils::{openssl, ScratchFile};
        const TEST: &str = "openssl_p256_sha256_interop";

        let Some(key_pem) = openssl(
            &["ecparam", "-genkey", "-name", "prime256v1", "-noout"],
            b"",
        )
        .or_skip(TEST) else {
            return;
        };
        // SubjectPublicKeyInfo in DER: the uncompressed point 04 || X || Y is
        // the trailing 65 bytes of the subjectPublicKey BIT STRING.
        let Some(spki) = openssl(
            &[
                "ec",
                "-pubout",
                "-conv_form",
                "uncompressed",
                "-outform",
                "DER",
            ],
            &key_pem,
        )
        .or_skip(TEST) else {
            return;
        };
        assert!(spki.len() > 65, "SPKI too short: {} bytes", spki.len());
        let point = &spki[spki.len() - 65..];
        assert_eq!(point[0], 0x04, "expected an uncompressed SEC 1 point");
        let public = EcdsaPublicKey::from_wire_bytes(p256(), point).expect("OpenSSL public point");
        let Some(pub_pem) = openssl(&["ec", "-pubout"], &key_pem).or_skip(TEST) else {
            return;
        };

        // `dgst -sign` / `-verify` take the key as a file, not on stdin. The
        // private key goes to a file only its owner can read.
        let key_file = ScratchFile::new(TEST, "key.pem", &key_pem);
        let pub_file = ScratchFile::new(TEST, "pub.pem", &pub_pem);
        let key_arg = key_file.arg();
        let pub_arg = pub_file.arg();

        let mut half_n = p256().n.clone();
        half_n.shr1();
        let mut high_s = 0usize;
        for i in 0..12u32 {
            let message = format!("openssl interop message {i}");
            let sig_der = openssl(&["dgst", "-sha256", "-sign", key_arg], message.as_bytes())
                .or_skip(TEST)
                .expect("dgst -sign works once key generation did");
            let signature = EcdsaSignature::from_der(&sig_der).expect("ECDSA-Sig-Value");
            if signature.s.cmp(&half_n).is_gt() {
                high_s += 1;
            }
            assert!(
                public.verify_message::<Sha256>(message.as_bytes(), &signature),
                "OpenSSL signature {i} rejected (high-s: {})",
                signature.s.cmp(&half_n).is_gt()
            );
            assert!(!public.verify_message::<Sha256>(b"another message", &signature));
            // Both sides emit strict DER, so re-encoding is byte-exact.
            assert_eq!(signature.to_der(), sig_der);
        }
        eprintln!("{TEST}: {high_s} of 12 OpenSSL signatures were high-s");

        // Our signatures, in both canonical forms, verified by OpenSSL. The
        // private scalar is OpenSSL's: the SEC 1 ECPrivateKey holds it as the
        // 32-byte OCTET STRING after `30 77 02 01 01 04 20`.
        let key_der = openssl(&["ec", "-outform", "DER"], &key_pem)
            .or_skip(TEST)
            .expect("ec -outform DER works once key generation did");
        assert_eq!(&key_der[..7], &[0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]);
        let d = BigUint::from_be_bytes(&key_der[7..39]);
        let (_, private) = Ecdsa::from_secret_scalar(p256(), &d).expect("OpenSSL scalar");
        assert_eq!(
            private.to_public_key().public_point(),
            public.public_point()
        );
        let message = b"signed here, verified by openssl";
        let signed = private.sign_message::<Sha256>(message).expect("sign");
        let low = signed.to_low_s(&p256());
        let high = EcdsaSignature {
            r: low.r.clone(),
            s: p256().n.sub(&low.s),
        };
        assert!(signed == low || signed == high);
        for (name, signature) in [
            ("signed.der", &signed),
            ("low.der", &low),
            ("high.der", &high),
        ] {
            let sig_file = ScratchFile::new(TEST, name, &signature.to_der());
            let verdict = openssl(
                &[
                    "dgst",
                    "-sha256",
                    "-verify",
                    pub_arg,
                    "-signature",
                    sig_file.arg(),
                ],
                message,
            );
            let out = verdict
                .or_skip(TEST)
                .expect("dgst -verify runs once dgst -sign did");
            assert!(
                String::from_utf8_lossy(&out).contains("Verified OK"),
                "OpenSSL rejected our signature {name}"
            );
        }
    }

    #[test]
    fn rfc6979_ecdsa_p256_sha256_sample_vector_signs_exactly() {
        // RFC 6979, Appendix A.2.5 (ECDSA over NIST P-256), SHA-256, "sample".
        let x = BigUint::from_be_bytes(&decode_hex(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        ));
        let expected_ux = BigUint::from_be_bytes(&decode_hex(
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        ));
        let expected_uy = BigUint::from_be_bytes(&decode_hex(
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        ));
        let expected_k = BigUint::from_be_bytes(&decode_hex(
            "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
        ));
        let expected_r = BigUint::from_be_bytes(&decode_hex(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        ));
        let expected_s_rfc = BigUint::from_be_bytes(&decode_hex(
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        ));

        let (public, private) =
            Ecdsa::from_secret_scalar(p256(), &x).expect("RFC secret scalar must be valid");
        assert_eq!(public.q.x, expected_ux);
        assert_eq!(public.q.y, expected_uy);

        let message = b"sample";
        let digest = Sha256::digest(message);
        let derived_k = super::NonceGenerator::<Sha256>::new(&private.curve.n, &private.d, &digest)
            .expect("RFC nonce must derive")
            .next();
        assert_eq!(derived_k, expected_k, "RFC 6979 nonce mismatch");

        let signature = private.sign_message::<Sha256>(message).expect("sign");
        assert_eq!(signature.r, expected_r);
        assert_eq!(signature.s, expected_s_rfc);
        assert!(public.verify_message::<Sha256>(message, &signature));
    }

    // ── Public-key validation (SEC 1 §3.2.2.1) ───────────────────────────────

    /// Whether the crate's key blob, PEM and XML decoders accept `key`'s point.
    fn accepted_by(key: &EcdsaPublicKey) -> [bool; 3] {
        [
            EcdsaPublicKey::from_key_blob(&key.to_key_blob()).is_some(),
            EcdsaPublicKey::from_pem(&key.to_pem()).is_some(),
            EcdsaPublicKey::from_xml(&key.to_xml()).is_some(),
        ]
    }

    /// `spki`, a P-256 `SubjectPublicKeyInfo`, with `point` in place of its
    /// `subjectPublicKey` (every length fits the short form).
    fn spki_with_point(spki: &[u8], point: &[u8]) -> Vec<u8> {
        let algorithm = &spki[2..4 + usize::from(spki[3])];
        let bit_string_len = point.len() + 1;
        let body_len = algorithm.len() + 2 + bit_string_len;
        let mut der = vec![0x30, u8::try_from(body_len).expect("short form")];
        der.extend_from_slice(algorithm);
        der.extend_from_slice(&[
            0x03,
            u8::try_from(bit_string_len).expect("short form"),
            0x00,
        ]);
        der.extend_from_slice(point);
        der
    }

    /// AUDIT C5. Under `Q = ∞`, `u₁·G + u₂·Q = u₁·G`, so `s = 1` and
    /// `r = x(z·G) mod n` satisfy the verification equation for a digest `z`
    /// with no private key. Every import path refuses the identity (the SPKI
    /// decoders of all three EC key types included), and verification
    /// refuses it on a key assembled around them.
    #[test]
    fn identity_public_key_is_refused_and_its_public_data_forgery_fails() {
        use crate::public_key::ec::AffinePoint;
        use crate::public_key::ecdh::EcdhPublicKey;
        use crate::public_key::ecies::EciesPublicKey;

        let curve = p256();
        let digest = Sha256::digest(b"identity-key boundary");
        let z = super::digest_to_scalar(&digest, &curve.n);
        let forged = EcdsaSignature {
            r: curve.scalar_mul(&curve.base_point(), &z).x.rem(&curve.n),
            s: BigUint::one(),
        };
        assert!(!forged.r.is_zero());
        // The forgery is real: with s = 1, u₁ = z and u₂ = r, and under Q = ∞
        // the sum is z·G, whose x-coordinate is r.
        let infinity = AffinePoint::infinity();
        let sum = curve.add(
            &curve.scalar_mul(&curve.base_point(), &z),
            &curve.scalar_mul(&infinity, &forged.r),
        );
        assert_eq!(sum.x.rem(&curve.n), forged.r);

        let identity = EcdsaPublicKey {
            curve: curve.clone(),
            q: infinity,
        };
        assert_eq!(identity.to_wire_bytes(), [0x00]);
        assert!(EcdsaPublicKey::from_wire_bytes(curve.clone(), &[0x00]).is_none());
        assert_eq!(accepted_by(&identity), [false; 3]);
        assert!(identity.to_spki_der().is_none());
        assert!(!identity.verify(&digest, &forged));
        assert!(!identity.verify_bytes(&digest, &forged.to_der()));

        let (honest, private) = Ecdsa::generate(curve.clone(), &mut rng());
        let spki = honest.to_spki_der().expect("P-256 is named");
        assert_eq!(spki_with_point(&spki, &honest.to_wire_bytes()), spki);
        let identity_spki = spki_with_point(&spki, &[0x00]);
        assert!(EcdsaPublicKey::from_spki_der(&identity_spki).is_none());
        assert!(EcdhPublicKey::from_spki_der(&identity_spki).is_none());
        assert!(EciesPublicKey::from_spki_der(&identity_spki).is_none());

        // Controls: the honest key passes every path and verifies its own
        // signature, but not the forgery.
        assert!(EcdsaPublicKey::from_wire_bytes(curve, &honest.to_wire_bytes()).is_some());
        assert_eq!(accepted_by(&honest), [true; 3]);
        assert!(EcdsaPublicKey::from_spki_der(&spki).is_some());
        assert!(EcdhPublicKey::from_spki_der(&spki).is_some());
        assert!(EciesPublicKey::from_spki_der(&spki).is_some());
        let signature = private.sign_digest::<Sha256>(&digest).expect("sign");
        assert!(honest.verify(&digest, &signature));
        assert!(!honest.verify(&digest, &forged));
    }

    /// A coordinate outside the field, a point off the curve, and points
    /// outside the subgroup of order `n` are refused on every crate entry
    /// point; honest keys on the same curves are not.
    #[test]
    fn public_key_imports_refuse_every_invalid_point() {
        use crate::public_key::ec::{k163, AffinePoint};

        let mut rng = rng();
        let (p256_key, _) = Ecdsa::generate(p256(), &mut rng);
        let curve = p256_key.curve.clone();
        let q = p256_key.q.clone();

        let non_canonical = EcdsaPublicKey {
            curve: curve.clone(),
            q: AffinePoint::new(q.x.add(&curve.p), q.y.clone()),
        };
        assert_eq!(accepted_by(&non_canonical), [false; 3]);

        let off_curve = EcdsaPublicKey {
            curve: curve.clone(),
            q: AffinePoint::new(q.x.clone(), q.y.add(&BigUint::one()).rem(&curve.p)),
        };
        assert!(!curve.is_on_curve(&off_curve.q));
        assert!(EcdsaPublicKey::from_wire_bytes(curve, &off_curve.to_wire_bytes()).is_none());
        assert_eq!(accepted_by(&off_curve), [false; 3]);

        // K-163 has cofactor 2: (0, 1) has order 2, and Q + (0, 1) order 2n.
        let k163 = k163();
        let (k163_key, _) = Ecdsa::generate(k163.clone(), &mut rng);
        let order_two = AffinePoint::new(BigUint::zero(), BigUint::one());
        for point in [order_two.clone(), k163.add(&k163_key.q, &order_two)] {
            assert!(k163.is_on_curve(&point) && !k163.is_in_prime_subgroup(&point));
            let key = EcdsaPublicKey {
                curve: k163.clone(),
                q: point,
            };
            assert!(EcdsaPublicKey::from_wire_bytes(k163.clone(), &key.to_wire_bytes()).is_none());
            assert_eq!(accepted_by(&key), [false; 3]);
        }

        for key in [&p256_key, &k163_key] {
            assert!(
                EcdsaPublicKey::from_wire_bytes(key.curve.clone(), &key.to_wire_bytes()).is_some()
            );
            assert_eq!(accepted_by(key), [true; 3]);
        }
    }

    /// A random source that repeats one byte value. Under `n = 19` the nonce
    /// sampler masks a single byte to five bits, so `0x09` is the nonce
    /// `k = 9` on every draw.
    struct RepeatingRng(u8);

    impl crate::Csprng for RepeatingRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.fill(self.0);
        }
    }

    /// On the Paar–Pelzl toy curve with `d = 1`, the digest `0x60` and the
    /// nonce `k = 9` give `s = 0` (the second row of the deterministic retry
    /// test above). A source stuck on that nonce is refused after
    /// `MAX_NONCE_DRAWS` draws, with a `None`; the same key and digest sign
    /// under a working source.
    #[test]
    fn randomized_signing_refuses_a_source_stuck_on_a_zeroing_nonce() {
        let (public, private) =
            Ecdsa::from_secret_scalar(toy_curve(), &BigUint::one()).expect("valid scalar");
        let digest = [0x60];
        assert!(private
            .sign_digest_with_nonce(&digest, &BigUint::from_u64(9))
            .is_none());
        assert_eq!(
            private.sign_digest_with_rng(&digest, &mut RepeatingRng(0x09)),
            None
        );

        let mut drbg = crate::CtrDrbgAes256::new(&[0x5a; 48]);
        let signature = private
            .sign_digest_with_rng(&digest, &mut drbg)
            .expect("a working source signs");
        assert!(public.verify(&digest, &signature));
    }

    /// A source whose successive fills are scripted, counting them. Under
    /// `n = 19` each nonce draw fills one octet and masks it to five bits.
    struct ScriptedRng {
        fills: &'static [u8],
        count: usize,
    }

    impl crate::Csprng for ScriptedRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.fill(self.fills[self.count]);
            self.count += 1;
        }
    }

    /// FIPS 186-5 §6.4.1 draws a new `k` when `s = 0`. On the toy curve with
    /// `d = 1` and digest `60`, `k = 9` zeroes `s` and `k = 4` signs
    /// `(r, s) = (3, 18)` (the arithmetic is in
    /// `deterministic_signing_retries_zero_r_and_s`). A source that yields
    /// `09` and then `04` produces that signature after exactly two draws.
    #[test]
    fn randomized_signing_redraws_once_after_a_zeroing_nonce() {
        let (public, private) =
            Ecdsa::from_secret_scalar(toy_curve(), &BigUint::one()).expect("valid scalar");
        let mut source = ScriptedRng {
            fills: &[0x09, 0x04],
            count: 0,
        };
        let signature = private
            .sign_digest_with_rng(&[0x60], &mut source)
            .expect("the second draw signs");
        assert_eq!(source.count, 2, "one rejected draw, one accepted");
        assert_eq!(signature.r, BigUint::from_u64(3));
        assert_eq!(signature.s, BigUint::from_u64(18));
        assert!(public.verify(&[0x60], &signature));
    }

    /// Parameters claiming the order `3n` for P-256's `G`. `from_secret_scalar`
    /// refuses `d = n` because `d·G = ∞` is no public key, and accepts `d = 1`.
    /// The decoders refuse the encoded key one step earlier: `3n` is
    /// composite, so the parameters are neither a named curve nor valid under
    /// SEC 1 §3.1.1.2.1, and `CurveParams::from_explicit` rejects them before
    /// any scalar is read, `d = 1` included.
    #[test]
    fn private_key_whose_public_point_is_the_identity_is_refused() {
        use crate::public_key::ec::{AffinePoint, CurveParams};

        let named = p256();
        let tripled = CurveParams::new(
            named.p.clone(),
            named.a.clone(),
            named.b.clone(),
            named.n.mul(&BigUint::from_u64(3)),
            named.h,
            named.gx.clone(),
            named.gy.clone(),
        )
        .expect("3n is odd");
        let d = named.n.clone();
        assert!(tripled.scalar_mul(&tripled.base_point(), &d).is_infinity());
        assert!(Ecdsa::from_secret_scalar(tripled.clone(), &d).is_none());
        let broken = EcdsaPrivateKey {
            curve: tripled.clone(),
            d,
            q: AffinePoint::infinity(),
        };
        assert!(EcdsaPrivateKey::from_key_blob(&broken.to_key_blob()).is_none());
        assert!(EcdsaPrivateKey::from_pem(&broken.to_pem()).is_none());
        assert!(EcdsaPrivateKey::from_xml(&broken.to_xml()).is_none());
        let (_, in_range) =
            Ecdsa::from_secret_scalar(tripled, &BigUint::one()).expect("d = 1 gives Q = G");
        assert!(EcdsaPrivateKey::from_key_blob(&in_range.to_key_blob()).is_none());
    }
}
