//! ElGamal encryption over twisted Edwards curves.
//!
//! This is the Edwards analogue of EC-ElGamal: encrypt a point `M` by choosing
//! a nonce `k` and returning
//!
//! ```text
//! C1 = k·G
//! C2 = M + k·Q
//! ```
//!
//! Decryption subtracts `d·C1` from `C2`. The integer layer embeds `m` as
//! `m·G`, so ciphertext addition remains homomorphic for small non-negative
//! integers.

use core::fmt;

use crate::public_key::bigint::BigUint;
use crate::public_key::ec_edwards::{EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::Csprng;

const EDWARDS_ELGAMAL_PUBLIC_LABEL: &str = "CRYPTOGRAPHY EDWARDS-ELGAMAL PUBLIC KEY";
const EDWARDS_ELGAMAL_PRIVATE_LABEL: &str = "CRYPTOGRAPHY EDWARDS-ELGAMAL PRIVATE KEY";
const EDWARDS_ELGAMAL_CT_LABEL: &str = "CRYPTOGRAPHY EDWARDS-ELGAMAL CIPHERTEXT";

/// Public key for Edwards ElGamal.
#[derive(Clone, Debug)]
pub struct EdwardsElGamalPublicKey {
    curve: TwistedEdwardsCurve,
    q: EdwardsPoint,
}

/// Private key for Edwards ElGamal.
#[derive(Clone)]
pub struct EdwardsElGamalPrivateKey {
    curve: TwistedEdwardsCurve,
    d: BigUint,
}

/// Ciphertext pair `(C1, C2)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdwardsElGamalCiphertext {
    c1: EdwardsPoint,
    c2: EdwardsPoint,
}

/// Namespace wrapper for Edwards ElGamal.
pub struct EdwardsElGamal;

impl EdwardsElGamalPublicKey {
    /// Return the curve parameters.
    #[must_use]
    pub fn curve(&self) -> &TwistedEdwardsCurve {
        &self.curve
    }

    /// Return the public point `Q = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &EdwardsPoint {
        &self.q
    }

    /// Encode the public point using the curve's RFC 8032-style compressed form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Decode a public key from the compressed Edwards point form.
    #[must_use]
    pub fn from_bytes(curve: TwistedEdwardsCurve, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !validate_public_point(&curve, &q) {
            return None;
        }
        Some(Self { curve, q })
    }

    /// Encrypt a point with a freshly sampled nonce.
    #[must_use]
    pub fn encrypt_point<R: Csprng>(
        &self,
        message: &EdwardsPoint,
        rng: &mut R,
    ) -> EdwardsElGamalCiphertext {
        let k = self.curve.random_scalar(rng);
        self.encrypt_point_with_nonce(message, &k)
    }

    /// Encrypt a point with an explicit nonce `k`.
    ///
    /// Reusing `k` for two messages under one key leaks the point difference.
    #[must_use]
    pub fn encrypt_point_with_nonce(
        &self,
        message: &EdwardsPoint,
        nonce: &BigUint,
    ) -> EdwardsElGamalCiphertext {
        let c1 = self.curve.scalar_mul(&self.curve.base_point(), nonce);
        let shared = self.curve.scalar_mul(&self.q, nonce);
        let c2 = self.curve.add(message, &shared);
        EdwardsElGamalCiphertext { c1, c2 }
    }

    /// Encrypt a small non-negative integer by embedding it as `m·G`.
    #[must_use]
    pub fn encrypt_int<R: Csprng>(&self, message: u64, rng: &mut R) -> EdwardsElGamalCiphertext {
        let point = int_to_point(&self.curve, message);
        self.encrypt_point(&point, rng)
    }

    /// Homomorphically add two ciphertexts.
    #[must_use]
    pub fn add_ciphertexts(
        &self,
        lhs: &EdwardsElGamalCiphertext,
        rhs: &EdwardsElGamalCiphertext,
    ) -> EdwardsElGamalCiphertext {
        EdwardsElGamalCiphertext {
            c1: self.curve.add(&lhs.c1, &rhs.c1),
            c2: self.curve.add(&lhs.c2, &rhs.c2),
        }
    }

    /// Encode in the crate-defined binary format: `[p, a, d, n, Gx, Gy, Qx, Qy]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[
            &self.curve.p,
            &self.curve.a,
            &self.curve.d,
            &self.curve.n,
            &self.curve.gx,
            &self.curve.gy,
            &self.q.x,
            &self.q.y,
        ])
    }

    /// Decode from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let qx = fields.next()?;
        let qy = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        let q = EdwardsPoint::new(qx, qy);
        if !validate_public_point(&curve, &q) {
            return None;
        }
        Some(Self { curve, q })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_ELGAMAL_PUBLIC_LABEL, &self.to_binary())
    }

    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_ELGAMAL_PUBLIC_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "EdwardsElGamalPublicKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("d", &self.curve.d),
                ("n", &self.curve.n),
                ("gx", &self.curve.gx),
                ("gy", &self.curve.gy),
                ("qx", &self.q.x),
                ("qy", &self.q.y),
            ],
        )
    }

    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EdwardsElGamalPublicKey",
            &["p", "a", "d", "n", "gx", "gy", "qx", "qy"],
            xml,
        )?
        .into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let qx = fields.next()?;
        let qy = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        let q = EdwardsPoint::new(qx, qy);
        if !validate_public_point(&curve, &q) {
            return None;
        }
        Some(Self { curve, q })
    }
}

impl EdwardsElGamalPrivateKey {
    /// Return the curve parameters.
    #[must_use]
    pub fn curve(&self) -> &TwistedEdwardsCurve {
        &self.curve
    }

    /// Return the private scalar `d ∈ [1, n)`.
    #[must_use]
    pub fn private_scalar(&self) -> &BigUint {
        &self.d
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> EdwardsElGamalPublicKey {
        let q = self.curve.scalar_mul(&self.curve.base_point(), &self.d);
        EdwardsElGamalPublicKey {
            curve: self.curve.clone(),
            q,
        }
    }

    /// Decrypt a point ciphertext.
    #[must_use]
    pub fn decrypt_point(&self, ciphertext: &EdwardsElGamalCiphertext) -> EdwardsPoint {
        let shared = self.curve.scalar_mul(&ciphertext.c1, &self.d);
        self.curve.add(&ciphertext.c2, &self.curve.negate(&shared))
    }

    /// Recover a small non-negative integer from a ciphertext.
    #[must_use]
    pub fn decrypt_int(&self, ciphertext: &EdwardsElGamalCiphertext, max_message: u64) -> Option<u64> {
        let point = self.decrypt_point(ciphertext);
        bsgs_dlog(&self.curve, &point, max_message)
    }

    /// Encode in the crate-defined binary format: `[p, a, d, n, Gx, Gy, d_scalar]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[
            &self.curve.p,
            &self.curve.a,
            &self.curve.d,
            &self.curve.n,
            &self.curve.gx,
            &self.curve.gy,
            &self.d,
        ])
    }

    /// Decode from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let d = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        Some(Self { curve, d })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_ELGAMAL_PRIVATE_LABEL, &self.to_binary())
    }

    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_ELGAMAL_PRIVATE_LABEL, pem)?;
        Self::from_binary(&blob)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "EdwardsElGamalPrivateKey",
            &[
                ("p", &self.curve.p),
                ("a", &self.curve.a),
                ("d", &self.curve.d),
                ("n", &self.curve.n),
                ("gx", &self.curve.gx),
                ("gy", &self.curve.gy),
                ("scalar", &self.d),
            ],
        )
    }

    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EdwardsElGamalPrivateKey",
            &["p", "a", "d", "n", "gx", "gy", "scalar"],
            xml,
        )?
        .into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let d = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let curve = TwistedEdwardsCurve::new(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        Some(Self { curve, d })
    }
}

impl fmt::Debug for EdwardsElGamalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EdwardsElGamalPrivateKey(<redacted>)")
    }
}

impl EdwardsElGamalCiphertext {
    /// Return the first ciphertext component `C1 = k·G`.
    #[must_use]
    pub fn c1(&self) -> &EdwardsPoint {
        &self.c1
    }

    /// Return the second ciphertext component `C2 = M + k·Q`.
    #[must_use]
    pub fn c2(&self) -> &EdwardsPoint {
        &self.c2
    }

    /// Encode in the crate-defined binary format: `[C1x, C1y, C2x, C2y]`.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        encode_biguints(&[&self.c1.x, &self.c1.y, &self.c2.x, &self.c2.y])
    }

    /// Decode from the crate-defined binary format.
    #[must_use]
    pub fn from_binary(curve: &TwistedEdwardsCurve, blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let c1x = fields.next()?;
        let c1y = fields.next()?;
        let c2x = fields.next()?;
        let c2y = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let c1 = EdwardsPoint::new(c1x, c1y);
        let c2 = EdwardsPoint::new(c2x, c2y);
        if !curve.is_on_curve(&c1) || !curve.is_on_curve(&c2) {
            return None;
        }
        Some(Self { c1, c2 })
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_ELGAMAL_CT_LABEL, &self.to_binary())
    }

    #[must_use]
    pub fn from_pem(curve: &TwistedEdwardsCurve, pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_ELGAMAL_CT_LABEL, pem)?;
        Self::from_binary(curve, &blob)
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "EdwardsElGamalCiphertext",
            &[
                ("c1x", &self.c1.x),
                ("c1y", &self.c1.y),
                ("c2x", &self.c2.x),
                ("c2y", &self.c2.y),
            ],
        )
    }

    #[must_use]
    pub fn from_xml(curve: &TwistedEdwardsCurve, xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap(
            "EdwardsElGamalCiphertext",
            &["c1x", "c1y", "c2x", "c2y"],
            xml,
        )?
        .into_iter();
        let c1x = fields.next()?;
        let c1y = fields.next()?;
        let c2x = fields.next()?;
        let c2y = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let c1 = EdwardsPoint::new(c1x, c1y);
        let c2 = EdwardsPoint::new(c2x, c2y);
        if !curve.is_on_curve(&c1) || !curve.is_on_curve(&c2) {
            return None;
        }
        Some(Self { c1, c2 })
    }
}

impl EdwardsElGamal {
    /// Generate a fresh Edwards ElGamal key pair on `curve`.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: TwistedEdwardsCurve,
        rng: &mut R,
    ) -> (EdwardsElGamalPublicKey, EdwardsElGamalPrivateKey) {
        let d = curve.random_scalar(rng);
        let q = curve.scalar_mul(&curve.base_point(), &d);
        (
            EdwardsElGamalPublicKey {
                curve: curve.clone(),
                q,
            },
            EdwardsElGamalPrivateKey { curve, d },
        )
    }
}

fn validate_public_point(curve: &TwistedEdwardsCurve, point: &EdwardsPoint) -> bool {
    !point.is_neutral() && curve.is_on_curve(point) && curve.scalar_mul(point, &curve.n).is_neutral()
}

fn int_to_point(curve: &TwistedEdwardsCurve, value: u64) -> EdwardsPoint {
    if value == 0 {
        EdwardsPoint::neutral()
    } else {
        curve.scalar_mul(&curve.base_point(), &BigUint::from_u64(value))
    }
}

fn bsgs_dlog(curve: &TwistedEdwardsCurve, target: &EdwardsPoint, max_message: u64) -> Option<u64> {
    if target.is_neutral() {
        return Some(0);
    }
    let limit = max_message.checked_add(1)?;
    let step = (limit as f64).sqrt().ceil() as u64 + 1;
    let base = curve.base_point();

    let mut table = std::collections::HashMap::with_capacity(step as usize);
    let mut baby = EdwardsPoint::neutral();
    for j in 0..step {
        let key = curve.encode_point(&baby);
        table.entry(key).or_insert(j);
        baby = curve.add(&baby, &base);
    }

    let stride_point = curve.scalar_mul(&base, &BigUint::from_u64(step));
    let neg_stride = curve.negate(&stride_point);

    let mut current = target.clone();
    for i in 0..step {
        let key = curve.encode_point(&current);
        if let Some(&j) = table.get(&key) {
            let m = i * step + j;
            if m < limit {
                return Some(m);
            }
        }
        current = curve.add(&current, &neg_stride);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{EdwardsElGamal, EdwardsElGamalCiphertext, EdwardsElGamalPrivateKey, EdwardsElGamalPublicKey};
    use crate::public_key::ec_edwards::ed25519;
    use crate::CtrDrbgAes256;

    fn rng(seed: u8) -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[seed; 48])
    }

    #[test]
    fn integer_roundtrip_ed25519() {
        let (public, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x12));
        let ct = public.encrypt_int(7, &mut rng(0x34));
        assert_eq!(private.decrypt_int(&ct, 16), Some(7));
    }

    #[test]
    fn homomorphic_addition_ed25519() {
        let (public, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x56));
        let ct1 = public.encrypt_int(2, &mut rng(0x78));
        let ct2 = public.encrypt_int(3, &mut rng(0x9a));
        let sum = public.add_ciphertexts(&ct1, &ct2);
        assert_eq!(private.decrypt_int(&sum, 16), Some(5));
    }

    #[test]
    fn public_serialization_roundtrip() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x21));
        let bin = public.to_binary();
        let pem = public.to_pem();
        let xml = public.to_xml();
        let round_bin = EdwardsElGamalPublicKey::from_binary(&bin).expect("bin");
        let round_pem = EdwardsElGamalPublicKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsElGamalPublicKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_binary(), public.to_binary());
        assert_eq!(round_pem.to_binary(), public.to_binary());
        assert_eq!(round_xml.to_binary(), public.to_binary());
    }

    #[test]
    fn public_bytes_roundtrip() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x31));
        let bytes = public.to_bytes();
        let round = EdwardsElGamalPublicKey::from_bytes(ed25519(), &bytes).expect("bytes");
        assert_eq!(round.to_binary(), public.to_binary());
    }

    #[test]
    fn private_serialization_roundtrip() {
        let (_, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x43));
        let bin = private.to_binary();
        let pem = private.to_pem();
        let xml = private.to_xml();
        let round_bin = EdwardsElGamalPrivateKey::from_binary(&bin).expect("bin");
        let round_pem = EdwardsElGamalPrivateKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsElGamalPrivateKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_binary(), private.to_binary());
        assert_eq!(round_pem.to_binary(), private.to_binary());
        assert_eq!(round_xml.to_binary(), private.to_binary());
    }

    #[test]
    fn ciphertext_serialization_roundtrip() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x65));
        let ct = public.encrypt_int(4, &mut rng(0x87));
        let bin = ct.to_binary();
        let pem = ct.to_pem();
        let xml = ct.to_xml();
        let curve = public.curve();
        let round_bin = EdwardsElGamalCiphertext::from_binary(curve, &bin).expect("bin");
        let round_pem = EdwardsElGamalCiphertext::from_pem(curve, &pem).expect("pem");
        let round_xml = EdwardsElGamalCiphertext::from_xml(curve, &xml).expect("xml");
        assert_eq!(round_bin, ct);
        assert_eq!(round_pem, ct);
        assert_eq!(round_xml, ct);
    }

    #[test]
    fn debug_redacts_private_key() {
        let (_, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0xaa));
        assert_eq!(format!("{private:?}"), "EdwardsElGamalPrivateKey(<redacted>)");
    }
}
