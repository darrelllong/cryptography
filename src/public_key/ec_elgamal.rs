//! Elliptic-curve `ElGamal` encryption.
//!
//! `EC-ElGamal` is the elliptic-curve analogue of textbook `ElGamal`: rather than
//! computing exponentiations in a prime subgroup of `Z_p^*`, it uses the group
//! of points on a short-Weierstrass elliptic curve.
//!
//! ## Plaintext spaces
//!
//! Three plaintext representations are supported, each with its own
//! encrypt/decrypt pair:
//!
//! | API | Plaintext | Notes |
//! |-----|-----------|-------|
//! | `encrypt_point` / `decrypt_point` | [`AffinePoint`] | Pure group operation |
//! | `encrypt` / `decrypt` | `&[u8]` | Koblitz embedding; ≤ `⌊(bits − 1)/8⌋ − 1` bytes, `bits` the field size |
//! | `encrypt_int` / `decrypt_int` | `u64` | Homomorphic; recovers `m` in `0..bound` |
//!
//! ## Encryption
//!
//! Given a public key `(curve, Q)`, encrypting point `M` with nonce `k`:
//! ```text
//! C₁ = k·G,   C₂ = M + k·Q
//! ```
//!
//! Decryption with private scalar `d`:
//! ```text
//! M = C₂ − d·C₁   (since d·C₁ = d·k·G = k·Q)
//! ```
//!
//! Plaintext points live in the subgroup `⟨G⟩` of prime order `n`: `∞` or a
//! point that is a valid public key (SEC 1 §3.2.2.1). Every encryptor
//! guarantees that (the Koblitz embedding retries its index until it lands
//! in the subgroup, `encrypt_int` forms `m·G`), and `encrypt_point` refuses
//! any other point, because a ciphertext arriving from outside carries no
//! curve and decryption validates both of its points against the key's
//! curve and subgroup before touching `d`. On the binary curves, whose
//! cofactor is 2 or 4, an on-curve point is outside the subgroup as often as
//! not.
//!
//! ## Ciphertext encodings
//!
//! `EcElGamalCiphertext::to_key_blob` / `to_pem` / `to_xml` carry each point
//! as its SEC 1 §2.3.3 form octet and both coordinates: `0` with `x = y = 0`
//! for `∞`, `4` with the affine coordinates otherwise, as the integer fields
//! `c1form, c1x, c1y, c2form, c2x, c2y`. `C₂ = ∞` is an ordinary ciphertext
//! (it encrypts `M = −k·Q`), and the decoders refuse any other form value
//! and a form `0` with non-zero coordinates.
//!
//! ## Additive homomorphism
//!
//! EC-ElGamal is additively homomorphic over the integer-encoding (`encrypt_int`)
//! layer: if `Enc(m₁) = (C₁, C₂)` and `Enc(m₂) = (C₁', C₂')` then
//! `(C₁+C₁', C₂+C₂')` decrypts to `(m₁+m₂)·G`.  The [`add_ciphertexts`]
//! method performs this operation.
//!
//! ## Side-channel note
//!
//! The underlying scalar multiplication is not constant-time; see the note in
//! [`ec`](crate::public_key::ec).
//!
//! [`add_ciphertexts`]: EcElGamalPublicKey::add_ciphertexts

use core::fmt;

use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::Csprng;
use rump::BigUint;

const EC_ELGAMAL_CT_LABEL: &str = "CRYPTOGRAPHY EC-ELGAMAL CIPHERTEXT";

/// The SEC 1 §2.3.3 form octet a serialized ciphertext gives the identity.
const POINT_FORM_IDENTITY: u64 = 0;

/// The SEC 1 §2.3.3 form octet a serialized ciphertext gives a finite point
/// carried with both coordinates.
const POINT_FORM_UNCOMPRESSED: u64 = 4;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Public key for EC-ElGamal.
#[derive(Clone, Debug)]
pub struct EcElGamalPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for EC-ElGamal.
#[derive(Clone)]
pub struct EcElGamalPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

/// A pair of curve points `(C₁, C₂)` encoding one encrypted message.
///
/// The point-level ciphertext `(C₁, C₂)` satisfies:
/// - `C₁ = k·G`
/// - `C₂ = M + k·Q` (for a plaintext point `M`)
///
/// Two ciphertexts may be added with [`EcElGamalPublicKey::add_ciphertexts`],
/// producing a ciphertext whose decryption is the point-sum of the originals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcElGamalCiphertext {
    c1: AffinePoint,
    c2: AffinePoint,
}

/// Namespace wrapper for the `EC-ElGamal` construction.
pub struct EcElGamal;

// ─── EcElGamalPublicKey ───────────────────────────────────────────────────────

impl EcElGamalPublicKey {
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
    /// point at infinity and is refused: under `Q = ∞`,
    /// `C₂ = M + k·∞ = M` would carry the plaintext in the clear.
    #[must_use]
    pub fn from_wire_bytes(curve: CurveParams, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        Some(Self { curve, q })
    }

    /// Whether `m` may be a plaintext: the identity, or a valid public point
    /// (SEC 1 §3.2.2.1: canonical coordinates, on the curve, in the subgroup
    /// of order `n`).
    fn admits_plaintext(&self, m: &AffinePoint) -> bool {
        m.is_infinity() || self.curve.is_valid_public_point(m)
    }

    /// `(k·G, M + k·Q)`.
    fn cipher(&self, m: &AffinePoint, k: &BigUint) -> EcElGamalCiphertext {
        let g = self.curve.base_point();
        let c1 = self.curve.scalar_mul(&g, k);
        let kq = self.curve.scalar_mul(&self.q, k);
        let c2 = self.curve.add(m, &kq);
        EcElGamalCiphertext { c1, c2 }
    }

    /// `(k·G, M + k·Q)` under a fresh nonce `k` uniform in `[1, n)`, for a
    /// plaintext its caller has already placed in the subgroup `⟨G⟩`.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the nonce sampler
    /// rejects (`rump::random::random_nonzero_below`'s bound): a working
    /// source does so with probability at most `2⁻²⁵⁶`, an all-zero source at
    /// once.
    fn encrypt_subgroup_point<R: Csprng>(
        &self,
        m: &AffinePoint,
        rng: &mut R,
    ) -> EcElGamalCiphertext {
        let k = self.curve.random_scalar(rng);
        self.cipher(m, &k)
    }

    /// Encrypt a curve point `m` directly: `(k·G, M + k·Q)` for a nonce `k`
    /// drawn uniformly from `[1, n)`.
    ///
    /// `m` must be the identity or a valid public point (SEC 1 §3.2.2.1), so
    /// that it lies in the subgroup of order `n`; any other point gives
    /// `None`. A plaintext outside the subgroup would put `C₂` outside it,
    /// and [`EcElGamalPrivateKey::decrypt_point`] refuses such a ciphertext
    /// because, arriving without a curve of its own, it is indistinguishable
    /// from an attack on the private scalar.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the nonce sampler
    /// rejects (`rump::random::random_nonzero_below`'s bound). Each draw is
    /// accepted with probability at least one half, so a working source
    /// reaches this with probability at most `2⁻²⁵⁶`; a source stuck on zero
    /// reaches it at once.
    #[must_use]
    pub fn encrypt_point<R: Csprng>(
        &self,
        m: &AffinePoint,
        rng: &mut R,
    ) -> Option<EcElGamalCiphertext> {
        if !self.admits_plaintext(m) {
            return None;
        }
        Some(self.encrypt_subgroup_point(m, rng))
    }

    /// Encrypt a curve point with an explicit nonce `k`.
    ///
    /// The caller is responsible for choosing `k` uniformly in `[1, n)`.
    /// Reusing `k` for two plaintexts reveals the difference of the
    /// plaintexts, `M − M' = C₂ − C₂'`.
    ///
    /// Returns `None` if `k ∉ [1, n)` or if `m` is neither the identity nor a
    /// valid public point (see [`Self::encrypt_point`]).
    #[must_use]
    pub fn encrypt_point_with_nonce(
        &self,
        m: &AffinePoint,
        k: &BigUint,
    ) -> Option<EcElGamalCiphertext> {
        if k.is_zero() || k >= &self.curve.n || !self.admits_plaintext(m) {
            return None;
        }
        Some(self.cipher(m, k))
    }

    /// Encrypt a byte message using Koblitz point embedding.
    ///
    /// The message, zero-padded, is followed by a one-byte index `j`; the
    /// first `j` in `0..=255` for which `message ‖ j` is the x-coordinate of
    /// a point in the subgroup of order `n` gives the plaintext point (the
    /// `y` is the root of even parity that SEC 1 §2.3.4 recovers for the form
    /// octet `02`). The message may be at most `⌊(bits − 1)/8⌋ − 1` bytes,
    /// where `bits` is `⌈log2 p⌉` on a prime field and `m` on `F_2^m`
    /// (30 bytes on P-256, 19 on B-163), so that `message ‖ j` is always a
    /// field element.
    ///
    /// Returns `None` if the message is too long or if no index yields a
    /// subgroup point. Every odd prime field decompresses (the square root
    /// comes from `rump::modular::mod_sqrt`, general Tonelli–Shanks), so the
    /// second case has probability about `(1 − 1/2h)²⁵⁶` per message: below
    /// `2⁻²⁵⁶` on a prime-order curve, about `2⁻¹⁰⁶` for `h = 2` and `2⁻⁴⁹`
    /// for `h = 4`.
    ///
    /// # Panics
    ///
    /// As [`Self::encrypt_point`]: when `rng` yields 256 consecutive draws
    /// the nonce sampler rejects.
    #[must_use]
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<EcElGamalCiphertext> {
        let m_point = koblitz_encode(&self.curve, message)?;
        Some(self.encrypt_subgroup_point(&m_point, rng))
    }

    /// Encrypt a small non-negative integer for additive-homomorphic use.
    ///
    /// The plaintext integer `m` is embedded as the point `m·G`.  Decryption
    /// recovers `m` by solving the discrete logarithm of the decrypted point
    /// below a caller-supplied exclusive bound; see
    /// [`EcElGamalPrivateKey::decrypt_int`].
    ///
    /// The homomorphic property: for ciphertexts encrypting `m₁` and `m₂`
    /// respectively, [`add_ciphertexts`] produces a ciphertext for `m₁ + m₂`
    /// (as a point `(m₁ + m₂)·G`).
    ///
    /// `m·G` lies in the subgroup `G` generates, so it needs no validation.
    ///
    /// # Panics
    ///
    /// As [`Self::encrypt_point`]: when `rng` yields 256 consecutive draws
    /// the nonce sampler rejects.
    ///
    /// [`add_ciphertexts`]: Self::add_ciphertexts
    pub fn encrypt_int<R: Csprng>(&self, m: u64, rng: &mut R) -> EcElGamalCiphertext {
        let g = self.curve.base_point();
        let m_point = if m == 0 {
            AffinePoint::infinity()
        } else {
            self.curve.scalar_mul(&g, &BigUint::from_u64(m))
        };
        self.encrypt_subgroup_point(&m_point, rng)
    }

    /// Homomorphic addition: combine two ciphertexts into one whose decryption
    /// is the sum of the individual decrypted messages.
    ///
    /// For two ciphertexts `(C₁, C₂)` and `(C₁', C₂')`:
    /// ```text
    /// add_ciphertexts → (C₁ + C₁', C₂ + C₂')
    /// ```
    /// Decryption gives `(m₁ + m₂)·G` (point addition) or `M₁ + M₂` (for the
    /// point-encryption layer).
    #[must_use]
    pub fn add_ciphertexts(
        &self,
        ct1: &EcElGamalCiphertext,
        ct2: &EcElGamalCiphertext,
    ) -> EcElGamalCiphertext {
        EcElGamalCiphertext {
            c1: self.curve.add(&ct1.c1, &ct2.c1),
            c2: self.curve.add(&ct1.c2, &ct2.c2),
        }
    }
}

crate::public_key::ec_io::impl_ec_public_key_io!(
    EcElGamalPublicKey,
    "CRYPTOGRAPHY EC-ELGAMAL PUBLIC KEY",
    "EcElGamalPublicKey"
);

// ─── EcElGamalPrivateKey ──────────────────────────────────────────────────────

impl EcElGamalPrivateKey {
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
    pub fn to_public_key(&self) -> EcElGamalPublicKey {
        EcElGamalPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Decrypt a point-level ciphertext.
    ///
    /// Computes `C₂ − d·C₁`. Both components are validated against this key's
    /// curve first (canonical coordinates, on the curve, in the prime-order
    /// subgroup, and `C₁ ≠ ∞`): a ciphertext that arrived through
    /// `from_key_blob` / `from_pem` / `from_xml` carries no curve of its own,
    /// and multiplying `d` into an attacker-chosen point off the curve or in a
    /// small subgroup would leak `d`. Returns `None` for an invalid
    /// ciphertext. `Some(∞)` is a legitimate result: the encrypted identity,
    /// `M = ∞`, decrypts to `∞`.
    #[must_use]
    pub fn decrypt_point(&self, ct: &EcElGamalCiphertext) -> Option<AffinePoint> {
        if !self.curve.is_valid_public_point(&ct.c1) {
            return None;
        }
        if !ct.c2.is_infinity() && !self.curve.is_valid_public_point(&ct.c2) {
            return None;
        }
        let dc1 = self.curve.scalar_mul(&ct.c1, &self.d);
        let neg_dc1 = self.curve.negate(&dc1);
        Some(self.curve.add(&ct.c2, &neg_dc1))
    }

    /// Decrypt a byte-level ciphertext (Koblitz embedding).
    ///
    /// Returns the bytes originally passed to [`EcElGamalPublicKey::encrypt`],
    /// or `None` if the ciphertext fails validation (see
    /// [`Self::decrypt_point`]). Note that leading zero bytes are not
    /// preserved: if you encrypted `b"\x00hello"`, you get back `b"hello"`.
    /// This matches the behavior of `BigUint::to_be_bytes`.
    #[must_use]
    pub fn decrypt(&self, ct: &EcElGamalCiphertext) -> Option<Vec<u8>> {
        let m_point = self.decrypt_point(ct)?;
        Some(koblitz_decode(&self.curve, &m_point))
    }

    /// Decrypt a homomorphically encrypted integer.
    ///
    /// `bound` is an exclusive upper limit, as in the Rust range `0..bound`.
    /// The result is `Some(m)` when the decrypted point is `m·G` with
    /// `m < bound` (the least such `m`), and `None` when there is no such `m`
    /// or the ciphertext fails validation (see [`Self::decrypt_point`]). So
    /// `decrypt_int(ct, m)` does not recover `m`, and a bound of 0 recovers
    /// nothing. [`EdwardsElGamalPrivateKey::decrypt_int`] follows the same
    /// convention.
    ///
    /// The search is baby-step giant-step over `0..bound`, taking `O(√bound)`
    /// point additions and table entries; keep `bound` at most about `2²⁴`
    /// (~16 million) for practical time and memory. A `bound` above
    /// [`Self::MAX_DECRYPT_INT_BOUND`] is refused with `None` before any work.
    ///
    /// [`EdwardsElGamalPrivateKey::decrypt_int`]: crate::public_key::edwards_elgamal::EdwardsElGamalPrivateKey::decrypt_int
    #[must_use]
    pub fn decrypt_int(&self, ct: &EcElGamalCiphertext, bound: u64) -> Option<u64> {
        if bound > Self::MAX_DECRYPT_INT_BOUND {
            return None;
        }
        let m_point = self.decrypt_point(ct)?;
        bsgs_dlog(&self.curve, &m_point, bound)
    }

    /// The largest `bound` [`Self::decrypt_int`] accepts, `2^40`. Baby-step
    /// giant-step reserves `⌈√bound⌉` table entries before it starts, so the
    /// cap keeps that reservation at `2^20` entries and the work at `2^21`
    /// group operations; a larger bound is refused with `None` before any
    /// work is done.
    pub const MAX_DECRYPT_INT_BOUND: u64 = 1 << 40;
}

crate::public_key::ec_io::impl_ec_private_key_io!(
    EcElGamalPrivateKey,
    "CRYPTOGRAPHY EC-ELGAMAL PRIVATE KEY",
    "EcElGamalPrivateKey"
);

impl fmt::Debug for EcElGamalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcElGamalPrivateKey(<redacted>)")
    }
}

// ─── EcElGamalCiphertext ─────────────────────────────────────────────────────

impl EcElGamalCiphertext {
    /// Return `C₁ = k·G`.
    #[must_use]
    pub fn c1(&self) -> &AffinePoint {
        &self.c1
    }

    /// Return `C₂ = M + k·Q`.
    #[must_use]
    pub fn c2(&self) -> &AffinePoint {
        &self.c2
    }

    /// The SEC 1 §2.3.3 form octet of `point` as a serial field: `0` for
    /// the identity, `4` for a finite point carried with both coordinates.
    fn point_form(point: &AffinePoint) -> BigUint {
        BigUint::from_u64(if point.is_infinity() {
            POINT_FORM_IDENTITY
        } else {
            POINT_FORM_UNCOMPRESSED
        })
    }

    /// The point a form field and two coordinate fields encode: `∞` for form
    /// `0` with `x = y = 0`, `(x, y)` for form `4`, nothing otherwise.
    fn point_from_fields(form: &BigUint, x: BigUint, y: BigUint) -> Option<AffinePoint> {
        match form.to_u64()? {
            POINT_FORM_IDENTITY => (x.is_zero() && y.is_zero()).then(AffinePoint::infinity),
            POINT_FORM_UNCOMPRESSED => Some(AffinePoint::new(x, y)),
            _ => None,
        }
    }

    /// Schema fields for the crate-defined serialization formats:
    /// `c1form, c1x, c1y, c2form, c2x, c2y`.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            Self::point_form(&self.c1),
            self.c1.x.clone(),
            self.c1.y.clone(),
            Self::point_form(&self.c2),
            self.c2.x.clone(),
            self.c2.y.clone(),
        ]
    }

    /// Rebuild the ciphertext from schema fields.
    ///
    /// Only the form octets are checked here: a ciphertext carries no curve,
    /// so [`EcElGamalPrivateKey::decrypt_point`] validates the points against
    /// the key's curve before any secret-dependent arithmetic.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let c1form = fields.next()?;
        let c1x = fields.next()?;
        let c1y = fields.next()?;
        let c2form = fields.next()?;
        let c2x = fields.next()?;
        let c2y = fields.next()?;
        Some(Self {
            c1: Self::point_from_fields(&c1form, c1x, c1y)?,
            c2: Self::point_from_fields(&c2form, c2x, c2y)?,
        })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EcElGamalCiphertext,
    "EcElGamalCiphertext",
    ["c1form", "c1x", "c1y", "c2form", "c2x", "c2y"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EcElGamalCiphertext,
    EC_ELGAMAL_CT_LABEL,
    ["c1form", "c1x", "c1y", "c2form", "c2x", "c2y"]
);

// ─── EcElGamal namespace ─────────────────────────────────────────────────────

impl EcElGamal {
    /// Generate a random key pair on `curve`: `d` uniform in `[1, n)` by
    /// rejection sampling (SEC 1 §3.2.1), `Q = d·G`.
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
    ) -> (EcElGamalPublicKey, EcElGamalPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        (
            EcElGamalPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EcElGamalPrivateKey { curve, d, q },
        )
    }
}

// ─── Koblitz byte embedding ───────────────────────────────────────────────────

/// Encode `message` as a point of the subgroup of order `n` using the
/// Koblitz index trick.
///
/// Builds the candidate `02 ‖ message_padded ‖ j` for `j` in `0..=255` and
/// decodes it as a compressed point (SEC 1 §2.3.4) until one decodes *and*
/// is a valid public point (§3.2.2.1). The second condition is what the
/// cofactor curves need: on B-163 or K-163 half of the on-curve points lie
/// outside the subgroup, and a plaintext there would make an undecryptable
/// ciphertext. Works on every prime field (decompression takes
/// `rump::mod_sqrt`) and every binary field (the half-trace).
///
/// Message capacity: `koblitz_capacity` bytes, so that `message ‖ j` is
/// always a field element.
/// Bytes of message a Koblitz-embedded x-coordinate can carry on `curve`:
/// `message ‖ j` must stay below `2^(bits − 1)`, where `bits` is `⌈log2 p⌉`
/// on a prime field (so it is below `p`) and `m` on `F_2^m`, and `j` takes one
/// octet, so the capacity is `⌊(bits − 1)/8⌋ − 1` octets.
fn koblitz_capacity(curve: &CurveParams) -> usize {
    let bits = curve.gf2m_degree().unwrap_or_else(|| curve.p.bits());
    ((bits - 1) / 8).saturating_sub(1)
}

fn koblitz_encode(curve: &CurveParams, message: &[u8]) -> Option<AffinePoint> {
    let capacity = koblitz_capacity(curve);
    if message.len() > capacity {
        return None;
    }

    // A compressed point: the prefix, then `coord_len` bytes of x made of
    // zero padding, the message and the Koblitz index `j`.
    let mut x_buf = Vec::with_capacity(1 + curve.coord_len);
    x_buf.push(0x02);
    x_buf.resize(curve.coord_len - message.len(), 0u8);
    x_buf.extend_from_slice(message);
    x_buf.push(0u8);

    let mut found = None;
    for j in 0u8..=255 {
        *x_buf.last_mut().expect("x_buf has coord_len + 1 bytes") = j;
        if let Some(point) = curve.decode_point(&x_buf) {
            if curve.is_valid_public_point(&point) {
                found = Some(point);
                break;
            }
        }
    }
    // `x_buf` holds the plaintext being encrypted.
    crate::ct::zeroize_slice(x_buf.as_mut_slice());
    found
}

/// Recover a byte message from the x-coordinate of a Koblitz-encoded point.
///
/// Strips the last byte (the Koblitz index `j`) and leading zero bytes,
/// matching the behavior of `BigUint::to_be_bytes`.
fn koblitz_decode(curve: &CurveParams, point: &AffinePoint) -> Vec<u8> {
    if point.is_infinity() {
        return Vec::new();
    }
    // x as exactly coord_len bytes (a decrypted point's x is a field element,
    // so it fits), built in one buffer: the decrypted plaintext followed by
    // the Koblitz index byte.
    let mut x_bytes = point.x.to_be_bytes_padded(curve.coord_len);
    let message_end = x_bytes.len().saturating_sub(1); // drop the index byte

    // Strip leading zeros (matching BigUint::to_be_bytes behavior).
    let first_nonzero = x_bytes[..message_end]
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(message_end);
    let message = x_bytes[first_nonzero..message_end].to_vec();
    crate::ct::zeroize_slice(x_bytes.as_mut_slice());
    message
}

// ─── Baby-step Giant-step DL recovery ────────────────────────────────────────

/// The least `m` in `0..bound` with `m·G = target`, by baby-step giant-step,
/// or `None` if there is none.
///
/// With `s = ⌈√bound⌉`, the baby steps tabulate `j·G` for `j` in `0..s` and
/// the giant steps test `target − i·s·G` for `i` in `0..⌈bound/s⌉`. The
/// candidates `i·s + j` fill `0..s·⌈bound/s⌉`, which covers `0..bound` and
/// ends at most at `s² ≤ 2⁶⁴`, so the arithmetic cannot overflow. The grid
/// can reach past `bound` (for `bound = 17`, `s = 5` and the grid is `0..20`),
/// so a candidate at or above `bound` is refused rather than returned. The
/// first match is the least candidate, since a later giant step `i' > i`
/// gives `i'·s + j' ≥ (i + 1)·s > i·s + j`; a first match at or above `bound`
/// therefore means no `m < bound` exists.
///
/// Time and space complexity: `O(√bound)`.
fn bsgs_dlog(curve: &CurveParams, target: &AffinePoint, bound: u64) -> Option<u64> {
    if bound == 0 {
        return None;
    }
    if target.is_infinity() {
        return Some(0);
    }

    let step = ceil_sqrt_u64(bound);
    let giant_steps = bound.div_ceil(step);
    let g = curve.base_point();

    // Baby steps: table maps compressed-point bytes → the least index j with
    // that point j·G.
    let mut table = std::collections::HashMap::with_capacity(
        usize::try_from(step).expect("step fits in usize"),
    );
    let mut baby = AffinePoint::infinity();
    for j in 0u64..step {
        let key = curve.encode_point(&baby);
        table.entry(key).or_insert(j);
        baby = curve.add(&baby, &g);
    }

    // Giant step: the stride point is `step·G`.
    let stride_point = curve.scalar_mul(&g, &BigUint::from_u64(step));
    let neg_stride = curve.negate(&stride_point);

    // Walk: current = target - i·step·G = target + i·(−step·G).
    let mut current = target.clone();
    for i in 0u64..giant_steps {
        let key = curve.encode_point(&current);
        if let Some(&j) = table.get(&key) {
            let m = i * step + j;
            return (m < bound).then_some(m);
        }
        current = curve.add(&current, &neg_stride);
    }
    None
}

/// `⌈√n⌉`, at most `2³²` for any `u64`.
fn ceil_sqrt_u64(n: u64) -> u64 {
    let root = n.isqrt();
    if root * root == n {
        root
    } else {
        root + 1
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        koblitz_capacity, EcElGamal, EcElGamalCiphertext, EcElGamalPrivateKey, EcElGamalPublicKey,
    };
    use crate::public_key::ec::{b163, k163, k571, p224, p256, p384, p521, secp256k1, CurveParams};
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    crate::public_key::ec_io::ec_key_io_tests!(
        EcElGamal,
        EcElGamalPublicKey,
        EcElGamalPrivateKey,
        "CRYPTOGRAPHY EC-ELGAMAL PUBLIC KEY",
        "CRYPTOGRAPHY EC-ELGAMAL PRIVATE KEY",
        "EcElGamalPublicKey",
        "EcElGamalPrivateKey"
    );

    /// Ciphertexts carry no curve, so decryption must validate both points
    /// before touching the private scalar: `C₁ = ∞`, a non-canonical
    /// coordinate, and a point off the curve are all refused.
    #[test]
    fn decrypt_point_rejects_invalid_ciphertext_components() {
        let mut rng = crate::CtrDrbgAes256::new(&[0x3Cu8; 48]);
        let curve = crate::public_key::ec::p256();
        let (public, private) = EcElGamal::generate(curve.clone(), &mut rng);
        let ct = public
            .encrypt_point(&curve.base_point(), &mut rng)
            .expect("G is in the subgroup");
        assert!(private.decrypt_point(&ct).is_some());

        let infinity_c1 = EcElGamalCiphertext {
            c1: crate::public_key::ec::AffinePoint::infinity(),
            c2: ct.c2.clone(),
        };
        assert!(private.decrypt_point(&infinity_c1).is_none());

        let shifted_c1 = EcElGamalCiphertext {
            c1: crate::public_key::ec::AffinePoint::new(ct.c1.x.add(&curve.p), ct.c1.y.clone()),
            c2: ct.c2.clone(),
        };
        assert!(private.decrypt_point(&shifted_c1).is_none());

        let off_curve_c2 = EcElGamalCiphertext {
            c1: ct.c1.clone(),
            c2: crate::public_key::ec::AffinePoint::new(
                ct.c2.x.clone(),
                ct.c2.y.add(&BigUint::one()),
            ),
        };
        assert!(private.decrypt_point(&off_curve_c2).is_none());
        assert!(private.decrypt(&off_curve_c2).is_none());
    }

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0xcd; 48])
    }

    // ── Point-level encrypt / decrypt ─────────────────────────────────────────

    #[test]
    fn point_roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let g = public.curve().base_point();
        let m = public.curve().scalar_mul(&g, &BigUint::from_u64(42));
        let ct = public
            .encrypt_point(&m, &mut rng)
            .expect("42·G is in the subgroup");
        let recovered = private.decrypt_point(&ct).expect("valid ciphertext");
        assert_eq!(recovered, m);
    }

    #[test]
    fn point_roundtrip_infinity() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let m = crate::public_key::ec::AffinePoint::infinity();
        let ct = public
            .encrypt_point(&m, &mut rng)
            .expect("∞ is a plaintext");
        let recovered = private.decrypt_point(&ct).expect("valid ciphertext");
        assert!(recovered.is_infinity());
    }

    #[test]
    fn point_roundtrip_b163() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(b163(), &mut rng);
        let g = public.curve().base_point();
        let m = public.curve().scalar_mul(&g, &BigUint::from_u64(29));
        let ct = public
            .encrypt_point(&m, &mut rng)
            .expect("29·G is in the subgroup");
        let recovered = private.decrypt_point(&ct).expect("valid ciphertext");
        assert_eq!(recovered, m);
    }

    /// `encrypt_point` and `encrypt_point_with_nonce` take `∞` and points of
    /// the subgroup of order `n`, and nothing else: on K-163 (`h = 2`) the
    /// order-2 point `(0, 1)` and `Q + (0, 1)` are on the curve and refused,
    /// as are a point off the curve and a non-canonical coordinate; a nonce
    /// of `0` or `n` is refused with a good plaintext.
    #[test]
    fn encrypt_point_refuses_plaintexts_outside_the_subgroup() {
        use crate::public_key::ec::AffinePoint;
        let mut rng = rng();
        let curve = k163();
        let (public, _) = EcElGamal::generate(curve.clone(), &mut rng);
        let order_two = AffinePoint::new(BigUint::zero(), BigUint::one());
        let q = public.public_point().clone();
        let seven = BigUint::from_u64(7);
        assert!(public
            .encrypt_point(&AffinePoint::infinity(), &mut rng)
            .is_some());
        assert!(public.encrypt_point(&q, &mut rng).is_some());
        assert!(public.encrypt_point_with_nonce(&q, &seven).is_some());
        for bad in [
            order_two.clone(),
            curve.add(&q, &order_two),
            AffinePoint::new(q.x.clone(), q.y.add(&BigUint::one())),
            AffinePoint::new(q.x.add(&curve.p), q.y.clone()),
        ] {
            assert!(public.encrypt_point(&bad, &mut rng).is_none());
            assert!(public.encrypt_point_with_nonce(&bad, &seven).is_none());
        }
        assert!(public
            .encrypt_point_with_nonce(&q, &BigUint::zero())
            .is_none());
        assert!(public.encrypt_point_with_nonce(&q, &curve.n).is_none());
    }

    // ── Byte-level encrypt / decrypt ──────────────────────────────────────────

    #[test]
    fn bytes_roundtrip_p256() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let msg = b"hello EC-ElGamal";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        let recovered = private.decrypt(&ct).expect("valid ciphertext");
        assert_eq!(recovered, msg);
    }

    #[test]
    fn bytes_roundtrip_p384() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p384(), &mut rng);
        let msg = b"p384 message bytes";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        let recovered = private.decrypt(&ct).expect("valid ciphertext");
        assert_eq!(recovered, msg);
    }

    #[test]
    fn bytes_roundtrip_secp256k1() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(secp256k1(), &mut rng);
        let msg = b"secp256k1 test";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        let recovered = private.decrypt(&ct).expect("valid ciphertext");
        assert_eq!(recovered, msg);
    }

    /// Every message of every admissible length encrypts and decrypts on a
    /// cofactor curve, and the embedded point lies in the subgroup.
    fn bytes_round_trip_many(curve: CurveParams) {
        let mut rng = rng();
        let capacity = koblitz_capacity(&curve) + 1;
        let (public, private) = EcElGamal::generate(curve.clone(), &mut rng);
        let mut checked = 0;
        for i in 0u8..40 {
            // Below the full capacity, so `message ‖ j` is a field element
            // whatever the leading octet; that octet is kept non-zero because
            // leading zeros do not survive the integer encoding.
            let len = usize::from(i) % (capacity - 1) + 1;
            let mut message: Vec<u8> = (0..len)
                .map(|j| {
                    u8::try_from(j)
                        .expect("short")
                        .wrapping_mul(37)
                        .wrapping_add(i)
                })
                .collect();
            message[0] |= 0x01;
            let ct = public.encrypt(&message, &mut rng).expect("encrypt");
            assert!(curve.is_valid_public_point(ct.c2()), "C₂ in the subgroup");
            assert_eq!(private.decrypt(&ct).as_deref(), Some(message.as_slice()));
            checked += 1;
        }
        assert_eq!(checked, 40);
    }

    #[test]
    fn bytes_roundtrip_b163() {
        bytes_round_trip_many(b163());
    }

    #[test]
    fn bytes_roundtrip_k163() {
        bytes_round_trip_many(k163());
    }

    /// P-224 has `p ≡ 1 (mod 4)`; decompression takes the general square
    /// root, so the embedding works there too.
    #[test]
    fn bytes_roundtrip_p224() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p224(), &mut rng);
        let msg = b"p224 message bytes";
        let ct = public.encrypt(msg, &mut rng).expect("encrypt");
        assert_eq!(private.decrypt(&ct).as_deref(), Some(msg.as_slice()));
    }

    /// The Koblitz capacity is `⌊(bits − 1)/8⌋ − 1` octets: a message of
    /// exactly that length round-trips and one octet more is refused, on
    /// prime fields whose size is and is not a multiple of eight bits and on
    /// binary fields likewise.
    #[test]
    fn bytes_at_the_koblitz_capacity_round_trip_and_one_more_is_refused() {
        for (curve, expected_capacity) in [
            (p224(), 26),
            (p256(), 30),
            (secp256k1(), 30),
            (p384(), 46),
            (p521(), 64),
            (b163(), 19),
            (k571(), 70),
        ] {
            let mut rng = rng();
            let capacity = koblitz_capacity(&curve);
            assert_eq!(
                capacity,
                expected_capacity,
                "capacity of a {}-bit field",
                curve.coord_len * 8
            );
            let (public, private) = EcElGamal::generate(curve, &mut rng);
            let mut full: Vec<u8> = (0..capacity).map(|i| 0x80 | i as u8).collect();
            full[0] = 0xFF;
            let ct = public
                .encrypt(&full, &mut rng)
                .expect("a message of capacity length embeds");
            assert_eq!(private.decrypt(&ct).as_deref(), Some(full.as_slice()));
            let mut over = full.clone();
            over.push(0x01);
            assert!(
                public.encrypt(&over, &mut rng).is_none(),
                "capacity + 1 octets are refused"
            );
        }
    }

    // ── Integer / homomorphic ─────────────────────────────────────────────────

    #[test]
    fn int_roundtrip_zero() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt_int(0, &mut rng);
        let m = private.decrypt_int(&ct, 100).expect("decrypt");
        assert_eq!(m, 0);
    }

    #[test]
    fn int_roundtrip_small() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        for &val in &[1u64, 7, 42, 999, 65535] {
            let ct = public.encrypt_int(val, &mut rng);
            let m = private.decrypt_int(&ct, 100_000).expect("decrypt");
            assert_eq!(m, val, "failed for value {val}");
        }
    }

    #[test]
    fn int_out_of_range_returns_none() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        // Encrypt 1000, then try to decrypt below the bound 100.
        let ct = public.encrypt_int(1000, &mut rng);
        assert!(private.decrypt_int(&ct, 100).is_none());
    }

    /// `bound` is exclusive: `bound − 1` is recovered and `bound` is not. The
    /// bounds cover a perfect square (16, whose search grid ends at 16), grids
    /// that reach past the bound (17 → `0..20`, 26 → `0..30`, where `m = bound`
    /// is found and must be refused), and the degenerate 1 and 0.
    #[test]
    fn decrypt_int_bound_is_exclusive() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        for bound in [1u64, 16, 17, 26] {
            let below = public.encrypt_int(bound - 1, &mut rng);
            assert_eq!(
                private.decrypt_int(&below, bound),
                Some(bound - 1),
                "m = bound - 1, bound = {bound}"
            );
            let at = public.encrypt_int(bound, &mut rng);
            assert_eq!(private.decrypt_int(&at, bound), None, "m = bound = {bound}");
        }
        let zero = public.encrypt_int(0, &mut rng);
        assert_eq!(private.decrypt_int(&zero, 0), None);
    }

    #[test]
    fn ceil_sqrt_helper_is_exact_for_boundaries() {
        for (n, root) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (15, 4),
            (16, 4),
            (17, 5),
            (u64::MAX, 1 << 32),
        ] {
            assert_eq!(super::ceil_sqrt_u64(n), root, "ceil sqrt of {n}");
        }
    }

    // ── Additive homomorphism ─────────────────────────────────────────────────

    #[test]
    fn add_ciphertexts_homomorphic() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let ct1 = public.encrypt_int(7, &mut rng);
        let ct2 = public.encrypt_int(11, &mut rng);
        let combined = public.add_ciphertexts(&ct1, &ct2);
        let sum = private.decrypt_int(&combined, 100).expect("decrypt");
        assert_eq!(sum, 18);
    }

    #[test]
    fn add_ciphertexts_three_terms() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let ct1 = public.encrypt_int(100, &mut rng);
        let ct2 = public.encrypt_int(200, &mut rng);
        let ct3 = public.encrypt_int(300, &mut rng);
        let combined = public.add_ciphertexts(&public.add_ciphertexts(&ct1, &ct2), &ct3);
        let sum = private.decrypt_int(&combined, 700).expect("decrypt");
        assert_eq!(sum, 600);
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_matches() {
        let mut rng = rng();
        let (public, private) = EcElGamal::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.q, public.q);
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let blob = public.to_key_blob();
        let recovered = EcElGamalPublicKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let bytes = public.to_wire_bytes();
        let recovered = EcElGamalPublicKey::from_wire_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(p256(), &mut rng);
        let blob = private.to_key_blob();
        let recovered = EcElGamalPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn ciphertext_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt(b"test", &mut rng).expect("encrypt");
        let blob = ct.to_key_blob();
        let recovered = EcElGamalCiphertext::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered, ct);
    }

    #[test]
    fn encrypt_point_with_nonce_is_repeatable_for_fixed_nonce() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let point = p256().base_point();
        let nonce = BigUint::from_u64(11);
        let lhs = public.encrypt_point_with_nonce(&point, &nonce);
        let rhs = public.encrypt_point_with_nonce(&point, &nonce);
        assert!(lhs.is_some());
        assert_eq!(lhs, rhs);
    }

    /// `M = −k·Q` under the nonce `k` gives `C₂ = M + k·Q = ∞`, an ordinary
    /// ciphertext. It crosses the blob, PEM and XML encodings intact and
    /// decrypts to `M`; the decoders refuse a form octet other than `0` or
    /// `4`, and a form `0` whose coordinates are not both zero.
    #[test]
    fn ciphertext_with_c2_at_infinity_round_trips() {
        use crate::public_key::io::encode_biguints;
        let mut rng = rng();
        let curve = p256();
        let (public, private) = EcElGamal::generate(curve.clone(), &mut rng);
        let k = BigUint::from_u64(0x1357_9bdf);
        let kq = curve.scalar_mul(public.public_point(), &k);
        let m = curve.negate(&kq);
        let ct = public
            .encrypt_point_with_nonce(&m, &k)
            .expect("−k·Q is in the subgroup");
        assert!(ct.c2().is_infinity());
        assert_eq!(private.decrypt_point(&ct), Some(m));

        assert_eq!(
            EcElGamalCiphertext::from_key_blob(&ct.to_key_blob()),
            Some(ct.clone())
        );
        assert_eq!(
            EcElGamalCiphertext::from_pem(&ct.to_pem()),
            Some(ct.clone())
        );
        assert_eq!(
            EcElGamalCiphertext::from_xml(&ct.to_xml()),
            Some(ct.clone())
        );

        let fields = ct.serial_fields();
        assert_eq!(fields[3], BigUint::zero());
        assert!(fields[4].is_zero() && fields[5].is_zero());
        for (index, value) in [(3, 2u64), (3, 3), (0, 0), (0, 5), (4, 1)] {
            let mut altered = fields.clone();
            altered[index] = BigUint::from_u64(value);
            let refs: Vec<&BigUint> = altered.iter().collect();
            assert!(
                EcElGamalCiphertext::from_key_blob(&encode_biguints(&refs)).is_none(),
                "field {index} = {value}"
            );
        }
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("EC-ELGAMAL PUBLIC KEY"));
        let recovered = EcElGamalPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("EC-ELGAMAL PRIVATE KEY"));
        let recovered = EcElGamalPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn ciphertext_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt(b"pem test", &mut rng).expect("encrypt");
        let pem = ct.to_pem();
        let recovered = EcElGamalCiphertext::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered, ct);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EcElGamalPublicKey"));
        let recovered = EcElGamalPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        let recovered = EcElGamalPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn ciphertext_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = EcElGamal::generate(p256(), &mut rng);
        let ct = public.encrypt(b"xml test", &mut rng).expect("encrypt");
        let xml = ct.to_xml();
        let recovered = EcElGamalCiphertext::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered, ct);
    }

    // ── Debug redaction ───────────────────────────────────────────────────────

    #[test]
    fn private_key_debug_redacted() {
        let mut rng = rng();
        let (_, private) = EcElGamal::generate(p256(), &mut rng);
        let s = format!("{private:?}");
        assert_eq!(s, "EcElGamalPrivateKey(<redacted>)");
    }

    // ── Public-key validation (SEC 1 §3.2.2.1) ───────────────────────────────

    /// Whether the crate's SEC 1 wire, key blob, PEM and XML decoders accept
    /// `key`'s point.
    fn accepted_by(key: &EcElGamalPublicKey) -> [bool; 4] {
        [
            EcElGamalPublicKey::from_wire_bytes(key.curve.clone(), &key.to_wire_bytes()).is_some(),
            EcElGamalPublicKey::from_key_blob(&key.to_key_blob()).is_some(),
            EcElGamalPublicKey::from_pem(&key.to_pem()).is_some(),
            EcElGamalPublicKey::from_xml(&key.to_xml()).is_some(),
        ]
    }

    /// Under `Q = ∞`, `C₂ = M + k·∞ = M`: the ciphertext carries the
    /// plaintext. `from_wire_bytes` used to accept the identity `00`; now it,
    /// a point off the curve, and points outside the subgroup of order `n`
    /// are refused on every crate entry point. Honest keys pass.
    #[test]
    fn public_key_imports_refuse_the_identity_and_every_invalid_point() {
        use crate::public_key::ec::{k163, AffinePoint};

        let mut rng = CtrDrbgAes256::new(&[0x5a; 48]);
        let (p256_key, _) = EcElGamal::generate(p256(), &mut rng);
        let curve = p256_key.curve.clone();

        let identity = EcElGamalPublicKey {
            curve: curve.clone(),
            q: AffinePoint::infinity(),
        };
        let m = curve.scalar_mul(&curve.base_point(), &BigUint::from_u64(42));
        assert_eq!(
            identity
                .encrypt_point_with_nonce(&m, &BigUint::from_u64(7))
                .expect("42·G is a plaintext")
                .c2,
            m
        );
        assert_eq!(identity.to_wire_bytes(), [0x00]);
        assert!(EcElGamalPublicKey::from_wire_bytes(curve.clone(), &[0x00]).is_none());
        assert_eq!(accepted_by(&identity), [false; 4]);

        let off_curve = EcElGamalPublicKey {
            curve: curve.clone(),
            q: AffinePoint::new(
                p256_key.q.x.clone(),
                p256_key.q.y.add(&BigUint::one()).rem(&curve.p),
            ),
        };
        assert!(!curve.is_on_curve(&off_curve.q));
        assert_eq!(accepted_by(&off_curve), [false; 4]);

        // K-163 has cofactor 2: (0, 1) has order 2, and Q + (0, 1) order 2n.
        let k163 = k163();
        let (k163_key, _) = EcElGamal::generate(k163.clone(), &mut rng);
        let order_two = AffinePoint::new(BigUint::zero(), BigUint::one());
        for point in [order_two.clone(), k163.add(&k163_key.q, &order_two)] {
            assert!(k163.is_on_curve(&point) && !k163.is_in_prime_subgroup(&point));
            let key = EcElGamalPublicKey {
                curve: k163.clone(),
                q: point,
            };
            assert_eq!(accepted_by(&key), [false; 4]);
        }

        assert_eq!(accepted_by(&p256_key), [true; 4]);
        assert_eq!(accepted_by(&k163_key), [true; 4]);
    }

    /// Parameters claiming the order `3n` for P-256's `G`, under which
    /// `d = n` is in range but `d·G = ∞`. The decoders refuse the encoded key
    /// before reading `d`: `3n` is composite, so the parameters are neither a
    /// named curve nor valid under SEC 1 §3.1.1.2.1, and
    /// `CurveParams::from_explicit` rejects them.
    #[test]
    fn private_key_whose_public_point_is_the_identity_is_refused() {
        use crate::public_key::ec::AffinePoint;

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
        let broken = EcElGamalPrivateKey {
            curve: tripled.clone(),
            d: named.n.clone(),
            q: AffinePoint::infinity(),
        };
        assert!(EcElGamalPrivateKey::from_key_blob(&broken.to_key_blob()).is_none());
        assert!(EcElGamalPrivateKey::from_pem(&broken.to_pem()).is_none());
        assert!(EcElGamalPrivateKey::from_xml(&broken.to_xml()).is_none());
        // The same scalar and point under P-256's own parameters are accepted.
        let control = EcElGamalPrivateKey {
            curve: named.clone(),
            d: BigUint::one(),
            q: named.base_point(),
        };
        assert!(EcElGamalPrivateKey::from_key_blob(&control.to_key_blob()).is_some());
    }
}
