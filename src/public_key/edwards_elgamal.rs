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
//! integers, and [`EdwardsElGamalPrivateKey::decrypt_int`] recovers such an
//! integer below an exclusive bound.

use core::fmt;

use crate::public_key::ec_edwards::{EdwardsMulTable, EdwardsPoint, TwistedEdwardsCurve};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::Csprng;
use rump::BigUint;

const EDWARDS_ELGAMAL_PUBLIC_LABEL: &str = "CRYPTOGRAPHY EDWARDS-ELGAMAL PUBLIC KEY";
const EDWARDS_ELGAMAL_PRIVATE_LABEL: &str = "CRYPTOGRAPHY EDWARDS-ELGAMAL PRIVATE KEY";
const EDWARDS_ELGAMAL_CT_LABEL: &str = "CRYPTOGRAPHY EDWARDS-ELGAMAL CIPHERTEXT";

/// Public key for Edwards ElGamal.
#[derive(Clone, Debug)]
pub struct EdwardsElGamalPublicKey {
    curve: TwistedEdwardsCurve,
    q: EdwardsPoint,
    q_table: EdwardsMulTable,
}

/// Private key for Edwards ElGamal.
#[derive(Clone)]
pub struct EdwardsElGamalPrivateKey {
    curve: TwistedEdwardsCurve,
    d: BigUint,
    q: EdwardsPoint,
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
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Decode a public key from the compressed Edwards point form.
    #[must_use]
    pub fn from_wire_bytes(curve: TwistedEdwardsCurve, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
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
        let c1 = self.curve.scalar_mul_base(nonce);
        let shared = self.curve.scalar_mul_cached(&self.q_table, nonce);
        let c2 = self.curve.add(message, &shared);
        EdwardsElGamalCiphertext { c1, c2 }
    }

    /// Encrypt a small non-negative integer by embedding it as `m·G`.
    ///
    /// [`EdwardsElGamalPrivateKey::decrypt_int`] recovers it under any
    /// exclusive bound greater than `message`.
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

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.curve.p.clone(),
            self.curve.a.clone(),
            self.curve.d.clone(),
            self.curve.n.clone(),
            self.curve.gx.clone(),
            self.curve.gy.clone(),
            self.q.x.clone(),
            self.q.y.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let qx = fields.next()?;
        let qy = fields.next()?;
        let curve = TwistedEdwardsCurve::from_explicit(p, a, d_curve, n, gx, gy)?;
        let q = EdwardsPoint::new(qx, qy);
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        let q_table = curve.precompute_mul_table(&q);
        Some(Self { curve, q, q_table })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EdwardsElGamalPublicKey,
    "EdwardsElGamalPublicKey",
    ["p", "a", "d", "n", "gx", "gy", "qx", "qy"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EdwardsElGamalPublicKey,
    EDWARDS_ELGAMAL_PUBLIC_LABEL,
    ["p", "a", "d", "n", "gx", "gy", "qx", "qy"]
);

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
        EdwardsElGamalPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
            q_table: self.curve.precompute_mul_table(&self.q),
        }
    }

    /// Decrypt a point ciphertext.
    #[must_use]
    pub fn decrypt_point(&self, ciphertext: &EdwardsElGamalCiphertext) -> EdwardsPoint {
        let shared = self.curve.scalar_mul(&ciphertext.c1, &self.d);
        self.curve.add(&ciphertext.c2, &self.curve.negate(&shared))
    }

    /// Recover a small non-negative integer from a ciphertext.
    ///
    /// `bound` is an exclusive upper limit, as in the Rust range `0..bound`.
    /// The result is `Some(m)` when the decrypted point is `m·G` with
    /// `m < bound` (the least such `m`), and `None` otherwise. So
    /// `decrypt_int(ciphertext, m)` does not recover `m`, and a bound of 0
    /// recovers nothing. [`EcElGamalPrivateKey::decrypt_int`] follows the same
    /// convention.
    ///
    /// The search is baby-step giant-step over `0..bound`, taking `O(√bound)`
    /// point additions and table entries. A `bound` above
    /// [`Self::MAX_DECRYPT_INT_BOUND`] is refused with `None` before any work;
    /// keep `bound` at most about `2²⁴` (~16 million) for practical time and
    /// memory.
    ///
    /// [`EcElGamalPrivateKey::decrypt_int`]: crate::public_key::ec_elgamal::EcElGamalPrivateKey::decrypt_int
    #[must_use]
    pub fn decrypt_int(&self, ciphertext: &EdwardsElGamalCiphertext, bound: u64) -> Option<u64> {
        if bound > Self::MAX_DECRYPT_INT_BOUND {
            return None;
        }
        let point = self.decrypt_point(ciphertext);
        bsgs_dlog(&self.curve, &point, bound)
    }

    /// The largest `bound` [`Self::decrypt_int`] searches: `2⁴⁰`, whose
    /// baby-step table has `⌈√bound⌉ = 2²⁰` entries. The table is reserved
    /// up front, so this caps the memory a bound can claim (a bound near
    /// `2⁶⁴` would reserve `2³²` entries, and on a 32-bit target `⌈√bound⌉`
    /// would not fit a `usize`).
    pub const MAX_DECRYPT_INT_BOUND: u64 = 1 << 40;

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.curve.p.clone(),
            self.curve.a.clone(),
            self.curve.d.clone(),
            self.curve.n.clone(),
            self.curve.gx.clone(),
            self.curve.gy.clone(),
            self.d.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let a = fields.next()?;
        let d_curve = fields.next()?;
        let n = fields.next()?;
        let gx = fields.next()?;
        let gy = fields.next()?;
        let d = fields.next()?;
        let curve = TwistedEdwardsCurve::from_explicit(p, a, d_curve, n, gx, gy)?;
        if d.is_zero() || d >= curve.n {
            return None;
        }
        let q = curve.scalar_mul_base(&d);
        Some(Self { curve, d, q })
    }
}

crate::public_key::io::impl_xml_serialization!(
    EdwardsElGamalPrivateKey,
    "EdwardsElGamalPrivateKey",
    ["p", "a", "d", "n", "gx", "gy", "scalar"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    EdwardsElGamalPrivateKey,
    EDWARDS_ELGAMAL_PRIVATE_LABEL,
    ["p", "a", "d", "n", "gx", "gy", "scalar"]
);

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
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.c1.x, &self.c1.y, &self.c2.x, &self.c2.y])
    }

    /// Decode from the crate-defined binary format.
    #[must_use]
    pub fn from_key_blob(curve: &TwistedEdwardsCurve, blob: &[u8]) -> Option<Self> {
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
        if !curve.is_valid_public_point(&c1) || !curve.is_valid_public_point(&c2) {
            return None;
        }
        Some(Self { c1, c2 })
    }

    /// Encode as PEM text armor over the binary blob, using the
    /// `CRYPTOGRAPHY EDWARDS-ELGAMAL CIPHERTEXT` label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(EDWARDS_ELGAMAL_CT_LABEL, &self.to_key_blob())
    }

    /// Decode a ciphertext from the crate-defined PEM label, validating both
    /// points against `curve`.
    ///
    /// Returns `None` if the label does not match, the payload is malformed,
    /// or either point is neutral, off the curve, or outside the order-`n`
    /// subgroup.
    #[must_use]
    pub fn from_pem(curve: &TwistedEdwardsCurve, pem: &str) -> Option<Self> {
        let blob = pem_unwrap(EDWARDS_ELGAMAL_CT_LABEL, pem)?;
        Self::from_key_blob(curve, &blob)
    }

    /// Encode as XML with root `<EdwardsElGamalCiphertext>` and the affine
    /// coordinates as `c1x`/`c1y`/`c2x`/`c2y` elements.
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

    /// Decode a ciphertext from the XML form produced by [`Self::to_xml`],
    /// validating both points against `curve`.
    ///
    /// Returns `None` if the root element, tag names, or integer encoding is
    /// invalid, or if either point is neutral, off the curve, or outside the
    /// order-`n` subgroup.
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
        if !curve.is_valid_public_point(&c1) || !curve.is_valid_public_point(&c2) {
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
        let q = curve.scalar_mul_base(&d);
        (
            EdwardsElGamalPublicKey {
                curve: curve.clone(),
                q: q.clone(),
                q_table: curve.precompute_mul_table(&q),
            },
            EdwardsElGamalPrivateKey { curve, d, q },
        )
    }
}

fn int_to_point(curve: &TwistedEdwardsCurve, value: u64) -> EdwardsPoint {
    if value == 0 {
        EdwardsPoint::neutral()
    } else {
        curve.scalar_mul_base(&BigUint::from_u64(value))
    }
}

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
/// Time and space complexity: `O(√bound)`. The caller keeps `bound` at most
/// [`EdwardsElGamalPrivateKey::MAX_DECRYPT_INT_BOUND`], so `s ≤ 2²⁰` and
/// the table reservation is bounded and fits a `usize` on every target.
fn bsgs_dlog(curve: &TwistedEdwardsCurve, target: &EdwardsPoint, bound: u64) -> Option<u64> {
    debug_assert!(bound <= EdwardsElGamalPrivateKey::MAX_DECRYPT_INT_BOUND);
    if bound == 0 {
        return None;
    }
    if target.is_neutral() {
        return Some(0);
    }

    let step = ceil_sqrt_u64(bound);
    let giant_steps = bound.div_ceil(step);
    let base = curve.base_point();

    // Baby steps: table maps encoded points → the least index j with that
    // point j·G.
    let mut table = std::collections::HashMap::with_capacity(
        usize::try_from(step).expect("step fits in usize"),
    );
    let mut baby = EdwardsPoint::neutral();
    for j in 0..step {
        let key = curve.encode_point(&baby);
        table.entry(key).or_insert(j);
        baby = curve.add(&baby, &base);
    }

    // Giant steps walk current = target − i·step·G.
    let stride_point = curve.scalar_mul(&base, &BigUint::from_u64(step));
    let neg_stride = curve.negate(&stride_point);

    let mut current = target.clone();
    for i in 0..giant_steps {
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

#[cfg(test)]
mod tests {
    use super::{
        encode_biguints, EdwardsElGamal, EdwardsElGamalCiphertext, EdwardsElGamalPrivateKey,
        EdwardsElGamalPublicKey,
    };
    use crate::public_key::ec_edwards::ed25519;
    use crate::public_key::io::xml_wrap;
    use crate::test_utils::decode_hex;
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    fn rng(seed: u8) -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[seed; 48])
    }

    #[test]
    fn integer_roundtrip_ed25519() {
        let (public, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x12));
        let ct = public.encrypt_int(7, &mut rng(0x34));
        assert_eq!(private.decrypt_int(&ct, 16), Some(7));
    }

    /// `bound` is exclusive, as for EC-ElGamal: `bound − 1` is recovered and
    /// `bound` is not, so `m = 16` is refused under 16. The bounds also cover
    /// grids that reach past the bound (17 → `0..20`,
    /// 26 → `0..30`, where `m = bound` is found and must be refused) and the
    /// degenerate 1 and 0.
    #[test]
    fn decrypt_int_bound_is_exclusive() {
        let (public, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x21));
        let mut nonces = rng(0x43);
        for bound in [1u64, 16, 17, 26] {
            let below = public.encrypt_int(bound - 1, &mut nonces);
            assert_eq!(
                private.decrypt_int(&below, bound),
                Some(bound - 1),
                "m = bound - 1, bound = {bound}"
            );
            let at = public.encrypt_int(bound, &mut nonces);
            assert_eq!(private.decrypt_int(&at, bound), None, "m = bound = {bound}");
        }
        let zero = public.encrypt_int(0, &mut nonces);
        assert_eq!(private.decrypt_int(&zero, 0), None);
    }

    #[test]
    fn homomorphic_addition_ed25519() {
        let (public, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x56));
        let ct1 = public.encrypt_int(2, &mut rng(0x78));
        let ct2 = public.encrypt_int(3, &mut rng(0x9a));
        let sum = public.add_ciphertexts(&ct1, &ct2);
        assert_eq!(private.decrypt_int(&sum, 16), Some(5));
    }

    /// Regression fixture with small multiples of `G`: public key `Q = 7·G`,
    /// message `M = 5·G`, nonce `k = 11`, so `C1 = 11·G` and
    /// `C2 = M + k·Q = 5·G + 77·G = 82·G`; decryption gives
    /// `C2 − d·C1 = 82·G − 77·G = 5·G`, and the integer decoder finds 5. The
    /// four encodings are this implementation's RFC 8032 §5.1.2 encodings of
    /// `7·G`, `5·G`, `11·G` and `82·G`, the same values `ec_edwards` pins for
    /// those base-point multiples; they have no external source and guard
    /// against unintended change, not as independent known answers.
    #[test]
    fn small_multiples_fixture_matches_the_regression_encodings_of_11g_and_82g() {
        let curve = ed25519();
        let public_bytes =
            decode_hex("b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1");
        let message_bytes =
            decode_hex("edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df");
        let public =
            EdwardsElGamalPublicKey::from_wire_bytes(curve.clone(), &public_bytes).expect("public");
        let private = EdwardsElGamalPrivateKey {
            curve: curve.clone(),
            d: BigUint::from_u64(7),
            q: curve.scalar_mul_base(&BigUint::from_u64(7)),
        };
        let message = curve.decode_point(&message_bytes).expect("message");
        let ciphertext = public.encrypt_point_with_nonce(&message, &BigUint::from_u64(11));

        assert_eq!(
            curve.encode_point(ciphertext.c1()),
            decode_hex("1337036ac32d8f30d4589c3c1c595812ce0fff40e37c6f5a97ab213f318290ad")
        );
        assert_eq!(
            curve.encode_point(ciphertext.c2()),
            decode_hex("b03ed935d1de5bba7f51574b9fd88239083116ff867ee8562ae990c487579623")
        );
        assert_eq!(
            curve.encode_point(&private.decrypt_point(&ciphertext)),
            message_bytes
        );
        assert_eq!(private.decrypt_int(&ciphertext, 16), Some(5));
    }

    /// A bound above `MAX_DECRYPT_INT_BOUND` is refused before any baby
    /// step, and one at the bound of an ordinary search still works.
    #[test]
    fn decrypt_int_refuses_bounds_above_the_limit() {
        let (public, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x2a));
        let ct = public.encrypt_int(3, &mut rng(0x2b));
        assert_eq!(
            private.decrypt_int(&ct, EdwardsElGamalPrivateKey::MAX_DECRYPT_INT_BOUND + 1),
            None
        );
        assert_eq!(private.decrypt_int(&ct, u64::MAX), None);
        assert_eq!(private.decrypt_int(&ct, 1 << 10), Some(3));
    }

    #[test]
    fn ceil_sqrt_helper_is_exact_for_boundaries() {
        assert_eq!(super::ceil_sqrt_u64(0), 0);
        assert_eq!(super::ceil_sqrt_u64(1), 1);
        assert_eq!(super::ceil_sqrt_u64(2), 2);
        assert_eq!(super::ceil_sqrt_u64(15), 4);
        assert_eq!(super::ceil_sqrt_u64(16), 4);
        assert_eq!(super::ceil_sqrt_u64(17), 5);
        assert_eq!(super::ceil_sqrt_u64(u64::MAX), 1u64 << 32);
    }

    #[test]
    fn public_serialization_roundtrip() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x21));
        let bin = public.to_key_blob();
        let pem = public.to_pem();
        let xml = public.to_xml();
        let round_bin = EdwardsElGamalPublicKey::from_key_blob(&bin).expect("bin");
        let round_pem = EdwardsElGamalPublicKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsElGamalPublicKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_key_blob(), public.to_key_blob());
        assert_eq!(round_pem.to_key_blob(), public.to_key_blob());
        assert_eq!(round_xml.to_key_blob(), public.to_key_blob());
    }

    #[test]
    fn public_bytes_roundtrip() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x31));
        let bytes = public.to_wire_bytes();
        let round = EdwardsElGamalPublicKey::from_wire_bytes(ed25519(), &bytes).expect("bytes");
        assert_eq!(round.to_key_blob(), public.to_key_blob());
    }

    #[test]
    fn private_serialization_roundtrip() {
        let (_, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0x43));
        let bin = private.to_key_blob();
        let pem = private.to_pem();
        let xml = private.to_xml();
        let round_bin = EdwardsElGamalPrivateKey::from_key_blob(&bin).expect("bin");
        let round_pem = EdwardsElGamalPrivateKey::from_pem(&pem).expect("pem");
        let round_xml = EdwardsElGamalPrivateKey::from_xml(&xml).expect("xml");
        assert_eq!(round_bin.to_key_blob(), private.to_key_blob());
        assert_eq!(round_pem.to_key_blob(), private.to_key_blob());
        assert_eq!(round_xml.to_key_blob(), private.to_key_blob());
    }

    #[test]
    fn ciphertext_serialization_roundtrip() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x65));
        let ct = public.encrypt_int(4, &mut rng(0x87));
        let bin = ct.to_key_blob();
        let pem = ct.to_pem();
        let xml = ct.to_xml();
        let curve = public.curve();
        let round_bin = EdwardsElGamalCiphertext::from_key_blob(curve, &bin).expect("bin");
        let round_pem = EdwardsElGamalCiphertext::from_pem(curve, &pem).expect("pem");
        let round_xml = EdwardsElGamalCiphertext::from_xml(curve, &xml).expect("xml");
        assert_eq!(round_bin, ct);
        assert_eq!(round_pem, ct);
        assert_eq!(round_xml, ct);
    }

    #[test]
    fn ciphertext_rejects_low_order_component() {
        let curve = ed25519();
        let base = curve.base_point();
        let order_two = crate::public_key::ec_edwards::EdwardsPoint::new(
            BigUint::zero(),
            curve.p.sub(&BigUint::one()),
        );
        let blob = encode_biguints(&[&order_two.x, &order_two.y, &base.x, &base.y]);
        assert!(
            EdwardsElGamalCiphertext::from_key_blob(&curve, &blob).is_none(),
            "ciphertext import must reject low-order components"
        );
    }

    #[test]
    fn debug_redacts_private_key() {
        let (_, private) = EdwardsElGamal::generate(ed25519(), &mut rng(0xaa));
        assert_eq!(
            format!("{private:?}"),
            "EdwardsElGamalPrivateKey(<redacted>)"
        );
    }

    /// The public-key schema fields with `p` added to field `index` (6 = `qx`,
    /// 7 = `qy`): the same point modulo `p`, encoded non-canonically.
    fn public_fields_offset_by_p(public: &EdwardsElGamalPublicKey, index: usize) -> Vec<BigUint> {
        let mut fields = public.serial_fields();
        fields[index] = fields[index].add(&public.curve.p);
        fields
    }

    fn blob_of(fields: &[BigUint]) -> Vec<u8> {
        let refs: Vec<&BigUint> = fields.iter().collect();
        encode_biguints(&refs)
    }

    fn public_xml(fields: &[BigUint]) -> String {
        let names = ["p", "a", "d", "n", "gx", "gy", "qx", "qy"];
        let pairs: Vec<(&str, &BigUint)> = names.iter().copied().zip(fields.iter()).collect();
        xml_wrap("EdwardsElGamalPublicKey", &pairs)
    }

    /// `ct`'s coordinates in `c1x, c1y, c2x, c2y` order, with `p` added to
    /// coordinate `offset` when one is given.
    fn ciphertext_coordinates(
        ct: &EdwardsElGamalCiphertext,
        p: &BigUint,
        offset: Option<usize>,
    ) -> Vec<BigUint> {
        let mut coords = vec![
            ct.c1.x.clone(),
            ct.c1.y.clone(),
            ct.c2.x.clone(),
            ct.c2.y.clone(),
        ];
        if let Some(index) = offset {
            coords[index] = coords[index].add(p);
        }
        coords
    }

    fn ciphertext_xml(coords: &[BigUint]) -> String {
        let names = ["c1x", "c1y", "c2x", "c2y"];
        let pairs: Vec<(&str, &BigUint)> = names.iter().copied().zip(coords.iter()).collect();
        xml_wrap("EdwardsElGamalCiphertext", &pairs)
    }

    #[test]
    fn public_blob_rejects_non_canonical_coordinates() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x61));
        assert!(
            EdwardsElGamalPublicKey::from_key_blob(&blob_of(&public.serial_fields())).is_some()
        );
        for index in [6, 7] {
            let blob = blob_of(&public_fields_offset_by_p(&public, index));
            assert!(
                EdwardsElGamalPublicKey::from_key_blob(&blob).is_none(),
                "blob decode accepted field {index} + p"
            );
        }
    }

    #[test]
    fn public_xml_rejects_non_canonical_coordinates() {
        let (public, _) = EdwardsElGamal::generate(ed25519(), &mut rng(0x62));
        assert!(EdwardsElGamalPublicKey::from_xml(&public_xml(&public.serial_fields())).is_some());
        for index in [6, 7] {
            let xml = public_xml(&public_fields_offset_by_p(&public, index));
            assert!(
                EdwardsElGamalPublicKey::from_xml(&xml).is_none(),
                "XML decode accepted field {index} + p"
            );
        }
    }

    #[test]
    fn ciphertext_blob_rejects_non_canonical_coordinates() {
        let curve = ed25519();
        let (public, _) = EdwardsElGamal::generate(curve.clone(), &mut rng(0x63));
        let ct = public.encrypt_int(5, &mut rng(0x64));
        let canonical = blob_of(&ciphertext_coordinates(&ct, &curve.p, None));
        assert!(EdwardsElGamalCiphertext::from_key_blob(&curve, &canonical).is_some());
        for index in 0..4 {
            let blob = blob_of(&ciphertext_coordinates(&ct, &curve.p, Some(index)));
            assert!(
                EdwardsElGamalCiphertext::from_key_blob(&curve, &blob).is_none(),
                "blob decode accepted coordinate {index} + p"
            );
        }
    }

    #[test]
    fn ciphertext_xml_rejects_non_canonical_coordinates() {
        let curve = ed25519();
        let (public, _) = EdwardsElGamal::generate(curve.clone(), &mut rng(0x65));
        let ct = public.encrypt_int(5, &mut rng(0x66));
        let canonical = ciphertext_xml(&ciphertext_coordinates(&ct, &curve.p, None));
        assert!(EdwardsElGamalCiphertext::from_xml(&curve, &canonical).is_some());
        for index in 0..4 {
            let xml = ciphertext_xml(&ciphertext_coordinates(&ct, &curve.p, Some(index)));
            assert!(
                EdwardsElGamalCiphertext::from_xml(&curve, &xml).is_none(),
                "XML decode accepted coordinate {index} + p"
            );
        }
    }
}
