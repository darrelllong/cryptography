//! Classical Diffie-Hellman (DH) key exchange over a prime-order subgroup.
//!
//! This is the finite-field Diffie-Hellman protocol from NIST SP 800-56A.
//! The mathematical structure is the same as DSA and ElGamal: a prime modulus
//! `p`, a prime subgroup order `q` dividing `p − 1`, and a generator `g` of
//! the order-`q` subgroup of `Z_p*`.
//!
//! ## Algorithm
//!
//! Two parties share domain parameters `(p, q, g)`.  Each holds a key pair:
//! ```text
//! Private key: x ∈ [1, q)
//! Public key:  y = g^x mod p
//! ```
//!
//! The shared secret is:
//! ```text
//! Alice: s = y_B^{x_A} mod p
//! Bob:   s = y_A^{x_B} mod p
//! (both equal g^{x_A · x_B} mod p)
//! ```
//!
//! The returned shared secret is the raw big-endian encoding of `s`.  Both
//! parties must apply the same KDF to this value before using it as a key.
//!
//! ## Parameter generation
//!
//! [`Dh::generate_params`] produces domain parameters using the same
//! `generate_prime_order_group` routine used by DSA.  Parameters can be
//! shared among many key pairs (unlike RSA moduli, which are per-key).
//!
//! ## Key validation
//!
//! [`DhPrivateKey::agree`] verifies that the peer's public key `y` lies in the
//! correct subgroup (`1 < y < p` and `y^q ≡ 1 mod p`) before computing the
//! shared secret.  Skipping this check enables small-subgroup attacks.

use core::fmt;

use crate::public_key::bigint::BigUint;
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{
    generate_prime_order_group, is_probable_prime, mod_pow, random_nonzero_below,
};
use crate::Csprng;

const DH_PARAMS_LABEL: &str = "CRYPTOGRAPHY DH PARAMETERS";
const DH_PUBLIC_LABEL: &str = "CRYPTOGRAPHY DH PUBLIC KEY";
const DH_PRIVATE_LABEL: &str = "CRYPTOGRAPHY DH PRIVATE KEY";

// ─── Types ───────────────────────────────────────────────────────────────────

/// Shared Diffie-Hellman domain parameters `(p, q, g)`.
///
/// A single set of parameters can be used by many key pairs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhParams {
    /// Prime modulus.
    pub p: BigUint,
    /// Prime subgroup order (`q | p − 1`).
    pub q: BigUint,
    /// Generator of the order-`q` subgroup.
    pub g: BigUint,
}

/// Public key for DH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhPublicKey {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    /// Public component `y = g^x mod p`.
    y: BigUint,
}

/// Private key for DH.
#[derive(Clone, Eq, PartialEq)]
pub struct DhPrivateKey {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    /// Private exponent `x ∈ [1, q)`.
    x: BigUint,
    /// Cached public component `y = g^x mod p`.
    y: BigUint,
}

pub struct Dh;

// ─── DhParams ─────────────────────────────────────────────────────────────────

impl DhParams {
    /// Encode in binary format: `[p, q, g]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.q, &self.g])
    }

    /// Decode from binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        if fields.next().is_some() || !validate_domain(&p, &q, &g) {
            return None;
        }
        Some(Self { p, q, g })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(DH_PARAMS_LABEL, &self.to_key_blob())
    }

    /// Returns `None` if the PEM label does not match, the payload is malformed,
    /// or the decoded parameters fail primality / subgroup checks.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_key_blob(&pem_unwrap(DH_PARAMS_LABEL, pem)?)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "DhParams",
            &[("p", &self.p), ("q", &self.q), ("g", &self.g)],
        )
    }

    /// Returns `None` if the XML is malformed or the decoded parameters fail
    /// primality / subgroup checks.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("DhParams", &["p", "q", "g"], xml)?.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        if fields.next().is_some() || !validate_domain(&p, &q, &g) {
            return None;
        }
        Some(Self { p, q, g })
    }
}

// ─── DhPublicKey ──────────────────────────────────────────────────────────────

impl DhPublicKey {
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    #[must_use]
    pub fn subgroup_order(&self) -> &BigUint {
        &self.q
    }

    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// The public component `y = g^x mod p`.
    #[must_use]
    pub fn public_component(&self) -> &BigUint {
        &self.y
    }

    #[must_use]
    pub fn params(&self) -> DhParams {
        DhParams {
            p: self.p.clone(),
            q: self.q.clone(),
            g: self.g.clone(),
        }
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode in binary format: `[p, q, g, y]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.q, &self.g, &self.y])
    }

    /// Decode from binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let y = fields.next()?;
        if fields.next().is_some() || !validate_domain(&p, &q, &g) || y <= BigUint::one() || y >= p
        {
            return None;
        }
        Some(Self { p, q, g, y })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(DH_PUBLIC_LABEL, &self.to_key_blob())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_key_blob(&pem_unwrap(DH_PUBLIC_LABEL, pem)?)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "DhPublicKey",
            &[
                ("p", &self.p),
                ("q", &self.q),
                ("g", &self.g),
                ("y", &self.y),
            ],
        )
    }

    /// Returns `None` if the XML is malformed or `y` is out of range.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("DhPublicKey", &["p", "q", "g", "y"], xml)?.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let y = fields.next()?;
        if fields.next().is_some() || !validate_domain(&p, &q, &g) || y <= BigUint::one() || y >= p
        {
            return None;
        }
        Some(Self { p, q, g, y })
    }
}

// ─── DhPrivateKey ─────────────────────────────────────────────────────────────

impl DhPrivateKey {
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    #[must_use]
    pub fn subgroup_order(&self) -> &BigUint {
        &self.q
    }

    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// The private exponent `x ∈ [1, q)`.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.x
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> DhPublicKey {
        DhPublicKey {
            p: self.p.clone(),
            q: self.q.clone(),
            g: self.g.clone(),
            y: self.y.clone(),
        }
    }

    #[must_use]
    pub fn params(&self) -> DhParams {
        DhParams {
            p: self.p.clone(),
            q: self.q.clone(),
            g: self.g.clone(),
        }
    }

    /// Compute the shared secret with a peer's public key.
    ///
    /// Returns `s = y_peer^x mod p`, or `None` if
    /// the peer key uses different domain parameters or fails subgroup validation.
    ///
    /// **Subgroup validation**: checks that `1 < y_peer < p` and that
    /// `y_peer^q ≡ 1 mod p`, rejecting low-order and small-subgroup inputs.
    #[must_use]
    pub fn agree_element(&self, peer: &DhPublicKey) -> Option<BigUint> {
        // Domain parameters must match.
        if peer.p != self.p || peer.q != self.q || peer.g != self.g {
            return None;
        }
        // Subgroup validation: reject trivial and low-order values.
        if peer.y <= BigUint::one() || peer.y >= self.p {
            return None;
        }
        let check = mod_pow(&peer.y, &self.q, &self.p);
        if check != BigUint::one() {
            return None;
        }

        Some(mod_pow(&peer.y, &self.x, &self.p))
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode in binary format: `[p, q, g, x]`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.q, &self.g, &self.x])
    }

    /// Decode from binary format.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let x = fields.next()?;
        if fields.next().is_some() || !validate_domain(&p, &q, &g) || x.is_zero() || x >= q {
            return None;
        }
        let y = mod_pow(&g, &x, &p);
        Some(Self { p, q, g, x, y })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(DH_PRIVATE_LABEL, &self.to_key_blob())
    }

    /// Returns `None` if the PEM label does not match or the payload is malformed.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        Self::from_key_blob(&pem_unwrap(DH_PRIVATE_LABEL, pem)?)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "DhPrivateKey",
            &[
                ("p", &self.p),
                ("q", &self.q),
                ("g", &self.g),
                ("x", &self.x),
            ],
        )
    }

    /// Returns `None` if the XML is malformed or `x` is zero or ≥ `q`.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("DhPrivateKey", &["p", "q", "g", "x"], xml)?.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let x = fields.next()?;
        if fields.next().is_some() || !validate_domain(&p, &q, &g) || x.is_zero() || x >= q {
            return None;
        }
        let y = mod_pow(&g, &x, &p);
        Some(Self { p, q, g, x, y })
    }
}

impl fmt::Debug for DhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DhPrivateKey(<redacted>)")
    }
}

// ─── Dh namespace ─────────────────────────────────────────────────────────────

impl Dh {
    /// Generate domain parameters `(p, q, g)` for a given key size.
    ///
    /// Uses the same prime-order subgroup generation as DSA (FIPS 186-5).
    /// The parameters can be reused across many key pairs.
    #[must_use]
    pub fn generate_params<R: Csprng>(rng: &mut R, bits: usize) -> Option<DhParams> {
        let (p, q, _cofactor, g) = generate_prime_order_group(rng, bits)?;
        Some(DhParams { p, q, g })
    }

    /// Generate a DH key pair from existing domain parameters.
    #[must_use]
    pub fn generate<R: Csprng>(params: &DhParams, rng: &mut R) -> (DhPublicKey, DhPrivateKey) {
        let x = random_nonzero_below(rng, &params.q)
            .expect("subgroup order is always > 1 for valid parameters");
        let y = mod_pow(&params.g, &x, &params.p);
        (
            DhPublicKey {
                p: params.p.clone(),
                q: params.q.clone(),
                g: params.g.clone(),
                y: y.clone(),
            },
            DhPrivateKey {
                p: params.p.clone(),
                q: params.q.clone(),
                g: params.g.clone(),
                x,
                y,
            },
        )
    }
}

// ─── Domain parameter validation ─────────────────────────────────────────────

/// Validate DH domain parameters: both `p` and `q` must be probable primes,
/// `q | p − 1`, and `g` must be a generator of the order-`q` subgroup.
fn validate_domain(p: &BigUint, q: &BigUint, g: &BigUint) -> bool {
    if !is_probable_prime(p) || !is_probable_prime(q) {
        return false;
    }
    if q >= p {
        return false;
    }
    let p_minus_one = p.sub_ref(&BigUint::one());
    if !p_minus_one.modulo(q).is_zero() {
        return false;
    }
    if g <= &BigUint::one() || g >= p {
        return false;
    }
    mod_pow(g, q, p) == BigUint::one()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{Dh, DhParams, DhPrivateKey, DhPublicKey};
    use crate::public_key::bigint::BigUint;
    use crate::CtrDrbgAes256;

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0x33; 48])
    }

    /// Small reference domain: p=23, q=11, g=4 (the same toy group used in the DSA tests).
    fn toy_params() -> super::DhParams {
        DhParams {
            p: BigUint::from_u64(23),
            q: BigUint::from_u64(11),
            g: BigUint::from_u64(4),
        }
    }

    // ── Basic key generation and agreement ────────────────────────────────────

    #[test]
    fn agreement_toy_params() {
        let params = toy_params();
        let mut rng = rng();
        let (pub_a, priv_a) = Dh::generate(&params, &mut rng);
        let (pub_b, priv_b) = Dh::generate(&params, &mut rng);
        let s_a = priv_a.agree_element(&pub_b).expect("agree A→B");
        let s_b = priv_b.agree_element(&pub_a).expect("agree B→A");
        assert_eq!(s_a, s_b);
    }

    #[test]
    fn agreement_generated_params() {
        let mut rng = rng();
        let params = Dh::generate_params(&mut rng, 512).expect("params");
        let (pub_a, priv_a) = Dh::generate(&params, &mut rng);
        let (pub_b, priv_b) = Dh::generate(&params, &mut rng);
        let s_a = priv_a.agree_element(&pub_b).expect("agree A");
        let s_b = priv_b.agree_element(&pub_a).expect("agree B");
        assert_eq!(s_a, s_b);
    }

    #[test]
    fn to_public_key_matches() {
        let params = toy_params();
        let mut rng = rng();
        let (public, private) = Dh::generate(&params, &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.y, public.y);
    }

    // ── Domain parameter mismatch ─────────────────────────────────────────────

    #[test]
    fn mismatched_params_rejected() {
        let p1 = toy_params();
        // Different prime — generate_params would be slow; reuse toy with different q.
        let p2 = DhParams {
            p: BigUint::from_u64(23),
            q: BigUint::from_u64(11),
            g: BigUint::from_u64(2), // different generator
        };
        let mut rng = rng();
        let (pub_a, _) = Dh::generate(&p1, &mut rng);
        let (_, priv_b) = Dh::generate(&p2, &mut rng);
        assert!(priv_b.agree_element(&pub_a).is_none());
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn params_binary_roundtrip() {
        let params = toy_params();
        let blob = params.to_key_blob();
        let recovered = DhParams::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered, params);
    }

    #[test]
    fn params_pem_roundtrip() {
        let params = toy_params();
        let pem = params.to_pem();
        assert!(pem.contains("DH PARAMETERS"));
        let recovered = DhParams::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered, params);
    }

    #[test]
    fn params_xml_roundtrip() {
        let params = toy_params();
        let xml = params.to_xml();
        assert!(xml.contains("DhParams"));
        let recovered = DhParams::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered, params);
    }

    #[test]
    fn public_key_binary_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (public, _) = Dh::generate(&params, &mut rng);
        let blob = public.to_key_blob();
        let recovered = DhPublicKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.y, public.y);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        let blob = private.to_key_blob();
        let recovered = DhPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.x, private.x);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (public, _) = Dh::generate(&params, &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("DH PUBLIC KEY"));
        let recovered = DhPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.y, public.y);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("DH PRIVATE KEY"));
        let recovered = DhPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.x, private.x);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (public, _) = Dh::generate(&params, &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("DhPublicKey"));
        let recovered = DhPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.y, public.y);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        let xml = private.to_xml();
        let recovered = DhPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.x, private.x);
    }

    #[test]
    fn debug_private_key_redacted() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        assert_eq!(format!("{private:?}"), "DhPrivateKey(<redacted>)");
    }
}
