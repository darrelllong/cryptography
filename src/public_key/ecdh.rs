//! Elliptic-Curve Diffie-Hellman (ECDH) key exchange.
//!
//! ECDH is the standard EC key agreement protocol.  Two parties each hold a
//! static key pair `(d, Q)` with `Q = d·G` on a shared curve.  After
//! exchanging public points, both compute the same shared secret from their
//! own private scalar and the peer's public point:
//!
//! ```text
//! Alice: S = d_A · Q_B = d_A · d_B · G
//! Bob:   S = d_B · Q_A = d_A · d_B · G
//! ```
//!
//! The shared secret returned by [`EcdhPrivateKey::agree_x_coordinate`] is the **x-coordinate**
//! of the shared point `S`, zero-padded to `coord_len` bytes (per ANSI X9.63 /
//! SEC 1 v2.0).  Both parties must apply the same KDF to this raw value before
//! using it as a symmetric key.
//!
//! ## Ephemeral vs. static use
//!
//! This module exposes static key pairs for simplicity.  For ephemeral ECDH
//! (where a fresh key pair is generated per session), call
//! [`Ecdh::generate`] per handshake, use [`EcdhPrivateKey::agree_x_coordinate`],
//! then discard the ephemeral private key.  ECIES in
//! [`ecies`](crate::public_key::ecies) combines ephemeral
//! ECDH with symmetric encryption into a self-contained encryption scheme.
//!
//! A private scalar fixed outside this crate (a published test vector such
//! as the `i` and `r` of RFC 5903 section 8, or a key held by another
//! implementation) is imported with [`Ecdh::from_secret_scalar`].
//!
//! ## Key encodings
//!
//! The crate-defined `to_key_blob`, `to_pem` and `to_xml` forms remain the
//! defaults. A key on a named curve also has the standard encodings:
//! [`EcdhPublicKey::to_spki_der`] (RFC 5480 `SubjectPublicKeyInfo`),
//! [`EcdhPrivateKey::to_sec1_der`] (RFC 5915 `ECPrivateKey`) and
//! [`EcdhPrivateKey::to_pkcs8_der`] (RFC 5958 `OneAsymmetricKey`), each with
//! a PEM form and a decoder. The encoders write the unrestricted
//! `id-ecPublicKey`; the decoders also accept the key-agreement-only `id-ecDH`
//! of RFC 5480 §2.1.2.
//!
//! ## Side-channel note
//!
//! The scalar multiplication is not constant-time; see [`ec`].
//!
//! [`ec`]: crate::public_key::ec
//! [`ecies`]: crate::public_key::ecies

use core::fmt;

use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::Csprng;
use rump::BigUint;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Public key for ECDH.
///
/// The public key is the curve point `Q = d·G`.  It is exchanged openly with
/// the peer.
#[derive(Clone, Debug)]
pub struct EcdhPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for ECDH.
///
/// The private key is the scalar `d ∈ [1, n)`.  It must remain secret.
#[derive(Clone)]
pub struct EcdhPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

/// Namespace wrapper for the ECDH key-agreement construction.
pub struct Ecdh;

// ─── EcdhPublicKey ────────────────────────────────────────────────────────────

impl EcdhPublicKey {
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

    /// Encode the public point as an uncompressed SEC 1 byte string.
    ///
    /// This is the standard wire format for exchanging ECDH public keys.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Decode a public key from an uncompressed or compressed SEC 1 point
    /// octet string (§2.3.4).
    ///
    /// Returns `None` if the encoding is malformed or the point is not a valid
    /// public key (SEC 1 §3.2.2.1, SP 800-56A Rev. 3 §5.6.2.3.3): the point at
    /// infinity (the single octet `00`), a coordinate outside the field, a
    /// point off the curve, or a point outside the prime-order subgroup.
    #[must_use]
    pub fn from_wire_bytes(curve: CurveParams, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        Some(Self { curve, q })
    }
}

crate::public_key::ec_io::impl_ec_public_key_io!(
    EcdhPublicKey,
    "CRYPTOGRAPHY ECDH PUBLIC KEY",
    "EcdhPublicKey"
);

// ─── EcdhPrivateKey ───────────────────────────────────────────────────────────

impl EcdhPrivateKey {
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
    pub fn to_public_key(&self) -> EcdhPublicKey {
        EcdhPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Perform ECDH key agreement with `peer`.
    ///
    /// Computes `S = d · Q_peer` and returns the x-coordinate of `S`,
    /// zero-padded to `coord_len` bytes (the standard raw shared-secret
    /// representation).
    ///
    /// Returns `None` if `peer` lives on a different curve (its point was
    /// validated only against the curve embedded in its own encoding, so
    /// combining it with this key's scalar would be the invalid-curve
    /// attack), or if the shared point is the point at infinity, which
    /// indicates that `peer.q` is a low-order point — an invalid key or a
    /// small-subgroup attack.
    #[must_use]
    pub fn agree_x_coordinate(&self, peer: &EcdhPublicKey) -> Option<Vec<u8>> {
        if !self.curve.same_curve(&peer.curve) {
            return None;
        }
        let s = self.curve.diffie_hellman(&self.d, &peer.q);
        if s.is_infinity() {
            return None;
        }
        // A field element always fits `coord_len` bytes, so the padded
        // encoding is the whole answer; building it directly avoids a second,
        // unpadded heap copy of the shared secret.
        Some(s.x.to_be_bytes_padded(self.curve.coord_len))
    }

    /// The key with private scalar `d` on `curve` and its public point
    /// `Q = d·G`, or `None` unless `1 ≤ d < n` (SEC 1 section 3.2.1 draws `d`
    /// from `[1, n − 1]`) and `Q` is a valid public key (section 3.2.2.1),
    /// which fails only on invalid domain parameters. Every private-key
    /// constructor goes through here.
    fn from_scalar(curve: CurveParams, d: BigUint) -> Option<Self> {
        let q = curve.public_point_for_scalar(&d)?;
        Some(Self { curve, d, q })
    }
}

crate::public_key::ec_io::impl_ec_private_key_io!(
    EcdhPrivateKey,
    "CRYPTOGRAPHY ECDH PRIVATE KEY",
    "EcdhPrivateKey"
);

crate::public_key::ec_pkix::impl_ec_key_encodings!(EcdhPublicKey, EcdhPrivateKey, EcdhAllowed);

impl fmt::Debug for EcdhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdhPrivateKey(<redacted>)")
    }
}

// ─── Ecdh namespace ───────────────────────────────────────────────────────────

impl Ecdh {
    /// Generate a random ECDH key pair on `curve`: `d` uniform in `[1, n)`
    /// by rejection sampling (SEC 1 §3.2.1), `Q = d·G`.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the sampler rejects
    /// (`rump::random::random_nonzero_below`'s bound). Each draw is accepted
    /// with probability at least one half, so a working source reaches this
    /// with probability at most `2⁻²⁵⁶`; a source stuck on zero, or on values
    /// at or above `n` within its bit width, reaches it at once.
    #[must_use]
    pub fn generate<R: Csprng>(curve: CurveParams, rng: &mut R) -> (EcdhPublicKey, EcdhPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        (
            EcdhPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EcdhPrivateKey { curve, d, q },
        )
    }

    /// Derive a key pair from an explicit curve and secret scalar.
    ///
    /// The private key is `d = secret`, taken as given rather than reduced,
    /// and the public key is `Q = d·G`. This is how a scalar fixed outside
    /// this crate enters it: a published test vector such as the `i` and `r`
    /// of RFC 5903 section 8, or a key held by another implementation. Fresh
    /// keys should come from [`Ecdh::generate`].
    ///
    /// Returns `None` if `secret` is zero or ≥ `n`. SEC 1 section 3.2.1 draws
    /// `d` from `[1, n − 1]`; this is the contract of
    /// [`Ecdsa::from_secret_scalar`](crate::public_key::ecdsa::Ecdsa::from_secret_scalar)
    /// and of the ECDH private-key decoders.
    #[must_use]
    pub fn from_secret_scalar(
        curve: CurveParams,
        secret: &BigUint,
    ) -> Option<(EcdhPublicKey, EcdhPrivateKey)> {
        let private = EcdhPrivateKey::from_scalar(curve, secret.clone())?;
        Some((private.to_public_key(), private))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{Ecdh, EcdhPrivateKey, EcdhPublicKey};
    use crate::public_key::ec::{b163, p256, p384, p521, secp256k1};
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    /// A peer key whose point validated against a *different* curve must not
    /// be combined with this key's scalar: the point formulas never read `b`,
    /// so `d · Q_peer` on a foreign curve is the invalid-curve attack.
    #[test]
    fn agreement_rejects_peer_on_a_different_curve() {
        let mut rng = crate::CtrDrbgAes256::new(&[0x7Bu8; 48]);
        let (_, alice) = Ecdh::generate(crate::public_key::ec::p256(), &mut rng);
        let (bob_p384, _) = Ecdh::generate(crate::public_key::ec::p384(), &mut rng);
        let (bob_k1, _) = Ecdh::generate(crate::public_key::ec::secp256k1(), &mut rng);
        assert!(alice.agree_x_coordinate(&bob_p384).is_none());
        assert!(alice.agree_x_coordinate(&bob_k1).is_none());
    }

    /// The blob decoder must enforce canonical coordinates: `qx + p` passes
    /// the curve equation but is not a field element.
    #[test]
    fn key_blob_rejects_non_canonical_public_coordinate() {
        let mut rng = crate::CtrDrbgAes256::new(&[0x7Cu8; 48]);
        let (public, _) = Ecdh::generate(crate::public_key::ec::p256(), &mut rng);
        let shifted = EcdhPublicKey {
            curve: public.curve.clone(),
            q: crate::public_key::ec::AffinePoint::new(
                public.q.x.add(&public.curve.p),
                public.q.y.clone(),
            ),
        };
        assert!(EcdhPublicKey::from_key_blob(&shifted.to_key_blob()).is_none());
        assert!(EcdhPublicKey::from_key_blob(&public.to_key_blob()).is_some());
    }

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0x77; 48])
    }

    crate::public_key::ec_io::ec_key_io_tests!(
        Ecdh,
        EcdhPublicKey,
        EcdhPrivateKey,
        "CRYPTOGRAPHY ECDH PUBLIC KEY",
        "CRYPTOGRAPHY ECDH PRIVATE KEY",
        "EcdhPublicKey",
        "EcdhPrivateKey"
    );

    // ── Agreement ─────────────────────────────────────────────────────────────

    #[test]
    fn agreement_p256() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(p256(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(p256(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32); // P-256 coord_len
    }

    #[test]
    fn agreement_p384() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(p384(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(p384(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 48); // P-384 coord_len
    }

    #[test]
    fn agreement_secp256k1() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(secp256k1(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(secp256k1(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn agreement_p521() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(p521(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(p521(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 66); // P-521 coord_len
    }

    #[test]
    fn agreement_b163() {
        let mut rng = rng();
        let (pub_a, priv_a) = Ecdh::generate(b163(), &mut rng);
        let (pub_b, priv_b) = Ecdh::generate(b163(), &mut rng);
        let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("agree A");
        let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("agree B");
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn different_keys_give_different_secrets() {
        let mut rng = rng();
        let (_pub_a, priv_a) = Ecdh::generate(p256(), &mut rng);
        let (pub_b, _) = Ecdh::generate(p256(), &mut rng);
        let (pub_c, _) = Ecdh::generate(p256(), &mut rng);
        let s1 = priv_a.agree_x_coordinate(&pub_b).expect("agree with B");
        let s2 = priv_a.agree_x_coordinate(&pub_c).expect("agree with C");
        assert_ne!(s1, s2);
    }

    // ── from_secret_scalar ───────────────────────────────────────────────────

    /// The import accepts exactly `1 ≤ d < n`: 0, `n` and `n + 1` are refused,
    /// and the two ends of the range give `Q = G` and `Q = −G`.
    #[test]
    fn from_secret_scalar_accepts_exactly_one_through_n_minus_one() {
        let curve = p256();
        let one = BigUint::from_u64(1);
        let n = curve.n.clone();
        assert!(Ecdh::from_secret_scalar(curve.clone(), &BigUint::zero()).is_none());
        assert!(Ecdh::from_secret_scalar(curve.clone(), &n).is_none());
        assert!(Ecdh::from_secret_scalar(curve.clone(), &n.add(&one)).is_none());

        let (public, private) = Ecdh::from_secret_scalar(curve.clone(), &one).expect("d = 1");
        assert_eq!(public.q, curve.base_point());
        assert_eq!(private.d, one);
        assert_eq!(private.to_public_key().q, public.q);

        let (public, _) = Ecdh::from_secret_scalar(curve.clone(), &n.sub(&one)).expect("d = n - 1");
        assert_eq!(public.q, curve.negate(&curve.base_point()));
    }

    /// Importing a generated scalar rebuilds the generated key pair, and the
    /// imported private key agrees with a peer exactly as the original does.
    #[test]
    fn from_secret_scalar_rebuilds_a_generated_key() {
        let mut rng = rng();
        for curve in [p384(), b163()] {
            let (public, private) = Ecdh::generate(curve.clone(), &mut rng);
            let (imported_public, imported_private) =
                Ecdh::from_secret_scalar(curve.clone(), private.private_scalar())
                    .expect("a generated scalar is in range");
            assert_eq!(imported_public.q, public.q);
            assert_eq!(imported_private.d, private.d);

            let (peer_public, peer_private) = Ecdh::generate(curve, &mut rng);
            let shared = imported_private.agree_x_coordinate(&peer_public);
            assert!(shared.is_some());
            assert_eq!(shared, private.agree_x_coordinate(&peer_public));
            assert_eq!(shared, peer_private.agree_x_coordinate(&public));
        }
    }

    // ── to_bytes / from_bytes ────────────────────────────────────────────────

    #[test]
    fn to_bytes_from_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(p256(), &mut rng);
        let bytes = public.to_wire_bytes();
        assert_eq!(bytes[0], 0x04); // uncompressed prefix
        let recovered = EcdhPublicKey::from_wire_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
    }

    // ── to_public_key ─────────────────────────────────────────────────────────

    #[test]
    fn to_public_key_consistent() {
        let mut rng = rng();
        let (public, private) = Ecdh::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.q, public.q);
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(p256(), &mut rng);
        let blob = public.to_key_blob();
        let recovered = EcdhPublicKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(p256(), &mut rng);
        let blob = private.to_key_blob();
        let recovered = EcdhPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDH PUBLIC KEY"));
        let recovered = EcdhPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECDH PRIVATE KEY"));
        let recovered = EcdhPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecdh::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EcdhPublicKey"));
        let recovered = EcdhPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        let recovered = EcdhPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn debug_private_key_redacted() {
        let mut rng = rng();
        let (_, private) = Ecdh::generate(p256(), &mut rng);
        assert_eq!(format!("{private:?}"), "EcdhPrivateKey(<redacted>)");
    }

    // ── Public-key validation (SEC 1 §3.2.2.1) ───────────────────────────────

    /// Whether the crate's SEC 1 wire, key blob, PEM and XML decoders accept
    /// `key`'s point.
    fn accepted_by(key: &EcdhPublicKey) -> [bool; 4] {
        [
            EcdhPublicKey::from_wire_bytes(key.curve.clone(), &key.to_wire_bytes()).is_some(),
            EcdhPublicKey::from_key_blob(&key.to_key_blob()).is_some(),
            EcdhPublicKey::from_pem(&key.to_pem()).is_some(),
            EcdhPublicKey::from_xml(&key.to_xml()).is_some(),
        ]
    }

    /// The identity (the octet `00`, and `(0, 0)` in the integer formats),
    /// a point off the curve, and points outside the subgroup of order `n`
    /// are refused on every crate entry point, and agreement with an identity
    /// peer assembled around them yields nothing. Honest keys pass.
    #[test]
    fn public_key_imports_refuse_the_identity_and_every_invalid_point() {
        use crate::public_key::ec::{k163, AffinePoint};

        let mut rng = rng();
        let (p256_key, p256_private) = Ecdh::generate(p256(), &mut rng);
        let curve = p256_key.curve.clone();

        let identity = EcdhPublicKey {
            curve: curve.clone(),
            q: AffinePoint::infinity(),
        };
        assert_eq!(identity.to_wire_bytes(), [0x00]);
        assert!(EcdhPublicKey::from_wire_bytes(curve.clone(), &[0x00]).is_none());
        assert_eq!(accepted_by(&identity), [false; 4]);
        assert!(identity.to_spki_der().is_none());
        assert!(p256_private.agree_x_coordinate(&identity).is_none());

        let off_curve = EcdhPublicKey {
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
        let (k163_key, _) = Ecdh::generate(k163.clone(), &mut rng);
        let order_two = AffinePoint::new(BigUint::zero(), BigUint::one());
        for point in [order_two.clone(), k163.add(&k163_key.q, &order_two)] {
            assert!(k163.is_on_curve(&point) && !k163.is_in_prime_subgroup(&point));
            let key = EcdhPublicKey {
                curve: k163.clone(),
                q: point,
            };
            assert_eq!(accepted_by(&key), [false; 4]);
        }

        assert_eq!(accepted_by(&p256_key), [true; 4]);
        assert_eq!(accepted_by(&k163_key), [true; 4]);
        assert!(p256_private.agree_x_coordinate(&p256_key).is_some());
    }

    /// Parameters claiming the order `3n` for P-256's `G`. `from_secret_scalar`
    /// refuses `d = n` because `d·G = ∞` is no public key. The decoders refuse
    /// the encoded key one step earlier: `3n` is composite, so the parameters
    /// are neither a named curve nor valid under SEC 1 §3.1.1.2.1, and
    /// `CurveParams::from_explicit` rejects them before any scalar is read,
    /// which is why `d = 1` on the same parameters is refused there too.
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
        assert!(Ecdh::from_secret_scalar(tripled.clone(), &d).is_none());
        let broken = EcdhPrivateKey {
            curve: tripled.clone(),
            d,
            q: AffinePoint::infinity(),
        };
        assert!(EcdhPrivateKey::from_key_blob(&broken.to_key_blob()).is_none());
        assert!(EcdhPrivateKey::from_pem(&broken.to_pem()).is_none());
        assert!(EcdhPrivateKey::from_xml(&broken.to_xml()).is_none());
        let (_, in_range) =
            Ecdh::from_secret_scalar(tripled, &BigUint::one()).expect("d = 1 gives Q = G");
        assert!(EcdhPrivateKey::from_key_blob(&in_range.to_key_blob()).is_none());
    }
}
