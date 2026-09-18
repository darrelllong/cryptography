//! X25519 ECDH per RFC 7748 §5 over Curve25519.
//!
//! Constant-time scalar multiplication on the Montgomery form of Curve25519,
//! `y^2 = x^3 + 486662 x^2 + x` over `GF(2^255 - 19)`. The Montgomery ladder
//! operates on `u`-coordinates only; conditional swaps are driven by scalar
//! bits without data-dependent branching or indexing, and field arithmetic
//! uses a fixed 5×51-bit limb form so each operation has constant access
//! pattern.
//!
//! What holds this in place is the emitted code: `scripts/ct_codegen.sh`
//! classifies every conditional branch in the release assembly of
//! `X25519::scalar_mult` and of the functions it calls, and
//! `scripts/ct_budgets/` records the count each target's reading accounted
//! for. Every branch is the loop over bits 254 down to 0, an index check that
//! loop bound already implies, or a loop of `fe_pow_public`, whose windows are
//! digits of the public exponent `p − 2`. None takes the scalar or `u` as
//! input.
//!
//! Measurement is the other half, and it found something the machine code
//! does not explain. `scripts/ct_timing` runs the interleaved two-class
//! experiment over this ladder; its `RESULTS.md` records that one host, an
//! Apple M4 Pro, separates scalars by how often the conditional swap fires —
//! an all-zero scalar from a dense one, and alternating bits from long runs —
//! while an idle x86-64 host separates neither and no host separates two
//! scalars whose swap counts are alike. The swap count is a property of the
//! secret: the number of positions where consecutive bits differ, aggregated
//! over the whole scalar. A countermeasure that made every limb's store change
//! its value halved the statistic at an 11% cost without removing it, and was
//! not kept; `RESULTS.md` has the numbers.
//!
//! Unlike the rest of `crate::vt`, X25519 here is intended to be
//! constant-time. It is exposed under `crate::vt` because the surrounding
//! key-handling code (PEM/DER blobs, error paths) shares conventions with
//! the rest of the public-key surface, but the scalar-mult primitive itself
//! is hardened against timing side channels on the secret scalar.
//!
//! Keys have their raw byte forms and the standard encodings of RFC 8410: the
//! public key as a `SubjectPublicKeyInfo` (§4) and the private key as a PKCS #8
//! `OneAsymmetricKey` (§7), in DER or as RFC 7468 `PUBLIC KEY` and
//! `PRIVATE KEY` text.
//!
//! References:
//! - RFC 7748, "Elliptic Curves for Security", §5 X25519 / §5.2 test vectors.
//! - RFC 8410, "Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for
//!   Use in the Internet X.509 Public Key Infrastructure", §3, §4, §7.
//! - D. J. Bernstein, "Curve25519: new Diffie-Hellman speed records" (2006).

use super::fe25519::{
    fe_add, fe_cswap, fe_from_bytes, fe_invert, fe_mul, fe_mul_small, fe_sq, fe_sub, fe_to_bytes,
    fe_zeroize, Fe,
};
use crate::ct::zeroize_slice;
use crate::public_key::curve_pkix::{self, ID_X25519};
use crate::public_key::pkix::{pem_decode, pem_encode, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL};
use crate::Csprng;

/// Length in bytes of an X25519 scalar / u-coordinate / shared secret.
pub const X25519_LEN: usize = 32;

/// The scalar bits the ladder walks: 254 down to 0, the rest fixed by
/// clamping.
const SCALAR_TOP_BIT: usize = 254;

/// RFC 7748 §5 `decodeScalar25519`: clear the three low bits, clear the top
/// bit, set bit 254.
const CLAMP_LOW_MASK: u8 = 0xf8;
const CLAMP_HIGH_MASK: u8 = 0x7f;
const CLAMP_HIGH_SET: u8 = 0x40;

/// Multiply by the Montgomery-ladder constant `(A + 2)/4 = 121665`
/// (RFC 7748 §5).
#[inline]
fn fe_mul_a24(a: &Fe) -> Fe {
    const A24: u64 = 121_665;
    fe_mul_small(a, A24)
}

/// RFC 7748 §5 `decodeScalar25519`: clamp the 32-byte scalar in place.
fn clamp_scalar(scalar: &mut [u8; X25519_LEN]) {
    scalar[0] &= CLAMP_LOW_MASK;
    scalar[X25519_LEN - 1] &= CLAMP_HIGH_MASK;
    scalar[X25519_LEN - 1] |= CLAMP_HIGH_SET;
}

/// X25519 Montgomery ladder. Computes `scalar * u` per RFC 7748 §5 with
/// constant-time scalar processing.
fn x25519_inner(scalar: &[u8; X25519_LEN], u: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    let mut k = *scalar;
    clamp_scalar(&mut k);

    let x1 = fe_from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap: u64 = 0;
    // One ladder step's intermediates. They live outside the loop so the
    // final step's values, which determine the result, can be wiped below.
    let mut a = Fe::ZERO;
    let mut aa = Fe::ZERO;
    let mut b = Fe::ZERO;
    let mut bb = Fe::ZERO;
    let mut e = Fe::ZERO;
    let mut c = Fe::ZERO;
    let mut d = Fe::ZERO;
    let mut da = Fe::ZERO;
    let mut cb = Fe::ZERO;
    let mut da_plus_cb = Fe::ZERO;
    let mut da_minus_cb = Fe::ZERO;
    let mut da_minus_cb_sq = Fe::ZERO;
    let mut a24_e = Fe::ZERO;
    let mut aa_plus_a24e = Fe::ZERO;

    // Process bits 254 down to 0. Bits above 254 are forced to zero by the
    // clamp; bit 254 is forced to 1 (so swap on that bit is well-defined).
    for t in (0..=SCALAR_TOP_BIT).rev() {
        let byte = t / 8;
        let bit = t % 8;
        let k_t = ((k[byte] >> bit) & 1) as u64;
        swap ^= k_t;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = k_t;

        a = fe_add(&x2, &z2);
        aa = fe_sq(&a);
        b = fe_sub(&x2, &z2);
        bb = fe_sq(&b);
        e = fe_sub(&aa, &bb);
        c = fe_add(&x3, &z3);
        d = fe_sub(&x3, &z3);
        da = fe_mul(&d, &a);
        cb = fe_mul(&c, &b);
        da_plus_cb = fe_add(&da, &cb);
        da_minus_cb = fe_sub(&da, &cb);
        x3 = fe_sq(&da_plus_cb);
        da_minus_cb_sq = fe_sq(&da_minus_cb);
        z3 = fe_mul(&x1, &da_minus_cb_sq);
        x2 = fe_mul(&aa, &bb);
        a24_e = fe_mul_a24(&e);
        aa_plus_a24e = fe_add(&aa, &a24_e);
        z2 = fe_mul(&e, &aa_plus_a24e);
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let mut z2_inv = fe_invert(&z2);
    let mut result = fe_mul(&x2, &z2_inv);

    zeroize_slice(&mut k[..]);
    let out = fe_to_bytes(&result);
    // The final ladder state is `scalar·u` in projective form, and the last
    // step's intermediates determine it: wipe them with the clamped scalar.
    // (`swap` needs no wipe: it ends as the scalar's bit 0, which clamping
    // clears.)
    for fe in [
        &mut x2,
        &mut z2,
        &mut x3,
        &mut z3,
        &mut z2_inv,
        &mut result,
        &mut a,
        &mut aa,
        &mut b,
        &mut bb,
        &mut e,
        &mut c,
        &mut d,
        &mut da,
        &mut cb,
        &mut da_plus_cb,
        &mut da_minus_cb,
        &mut da_minus_cb_sq,
        &mut a24_e,
        &mut aa_plus_a24e,
    ] {
        fe_zeroize(fe);
    }
    out
}

/// The canonical encoding of the u-coordinate `bytes` names, read as RFC 7748
/// §5 reads one: bit 255 masked, and a non-canonical value (2^255 − 19 through
/// 2^255 − 1) reduced modulo p. Two strings name the same u-coordinate
/// exactly when their canonical encodings are equal.
fn canonical_u(bytes: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    fe_to_bytes(&fe_from_bytes(bytes))
}

/// Top-level X25519 functional surface (RFC 7748 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519;

impl X25519 {
    /// Compute `scalar * u` per RFC 7748 §5. The scalar is clamped before use.
    /// Constant-time in `scalar` and `u`.
    #[must_use]
    pub fn scalar_mult(scalar: &[u8; X25519_LEN], u: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
        x25519_inner(scalar, u)
    }

    /// Compute `scalar * G` where `G` is the X25519 base point (`u = 9`).
    #[must_use]
    pub fn scalar_mult_base(scalar: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
        let mut base = [0u8; X25519_LEN];
        base[0] = 9;
        x25519_inner(scalar, &base)
    }

    /// Generate a new X25519 key pair from `rng`. The private scalar is
    /// 32 random bytes pre-clamping; clamping is applied at use time.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R) -> (X25519PublicKey, X25519PrivateKey) {
        let mut secret = [0u8; X25519_LEN];
        rng.fill_bytes(&mut secret);
        let public_bytes = X25519::scalar_mult_base(&secret);
        let pair = (X25519PublicKey(public_bytes), X25519PrivateKey(secret));
        // `secret` was copied into the private key; wipe the stack original.
        zeroize_slice(&mut secret[..]);
        pair
    }
}

/// X25519 private key: 32 raw bytes. Zeroised on drop.
#[derive(Clone)]
pub struct X25519PrivateKey([u8; X25519_LEN]);

impl PartialEq for X25519PrivateKey {
    /// Compares the scalars in constant time.
    fn eq(&self, other: &Self) -> bool {
        crate::ct::constant_time_eq_mask(&self.0, &other.0) == u8::MAX
    }
}

impl Eq for X25519PrivateKey {}

/// X25519 public key: a 32-byte canonical u-coordinate.
///
/// Every constructor stores the canonical encoding of the u-coordinate its
/// input names, read as RFC 7748 §5 reads one (bit 255 masked, a
/// non-canonical value taken as reduced modulo `p`), so two keys naming the
/// same u-coordinate are equal, and [`Self::to_raw_bytes`] and the RFC 8410
/// encodings carry the canonical form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519PublicKey([u8; X25519_LEN]);

impl X25519PrivateKey {
    /// Construct from raw scalar bytes (caller-supplied entropy required).
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X25519_LEN]) -> Self {
        Self(*bytes)
    }

    /// Construct from a mutable buffer; the caller's buffer is zeroised after
    /// the private scalar is copied.
    #[must_use]
    pub fn from_raw_bytes_wiping(bytes: &mut [u8; X25519_LEN]) -> Self {
        let key = Self(*bytes);
        zeroize_slice(&mut bytes[..]);
        key
    }

    /// Return the raw 32-byte scalar.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X25519_LEN] {
        self.0
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn to_public_key(&self) -> X25519PublicKey {
        X25519PublicKey(X25519::scalar_mult_base(&self.0))
    }

    /// Diffie-Hellman: compute shared secret with `peer`. Returns `None` if
    /// the result is the all-zero u-coordinate (low-order point), per the
    /// conservative recommendation in RFC 7748 §6.1.
    ///
    /// Timing: `scripts/ct_codegen.sh` finds one conditional branch in this
    /// operation beyond the ladder's own, on both targets it has been run on
    /// — the test of that all-zero check, which the code folds over all 32
    /// bytes before testing once, so the branch decides only the value this
    /// returns.
    #[must_use]
    pub fn agree(&self, peer: &X25519PublicKey) -> Option<[u8; X25519_LEN]> {
        let shared = X25519::scalar_mult(&self.0, &peer.0);
        let nonzero: u8 = shared.iter().fold(0u8, |acc, &b| acc | b);
        if nonzero == 0 {
            None
        } else {
            Some(shared)
        }
    }

    /// Encode as the RFC 8410 §7 `OneAsymmetricKey` (PKCS #8) in DER: version
    /// 1, `id-X25519` with the parameters absent (§3), and the 32-byte scalar
    /// as `CurvePrivateKey`. The public key is left out, since the scalar
    /// derives it.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        curve_pkix::private_key_to_pkcs8(&ID_X25519, &self.0)
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
    /// trailing bytes: version 1 or 2, `id-X25519` with the parameters absent
    /// (§3), and a 32-byte `CurvePrivateKey`. As with [`Self::from_raw_bytes`],
    /// every 32-byte string is a scalar (RFC 7748 §5 clamps it at use). A
    /// version 2 `publicKey` must be 32 bytes naming the u-coordinate this
    /// scalar derives, as RFC 7748 §5 reads a u-coordinate: bit 255 masked,
    /// and a non-canonical value taken as reduced modulo p. Attributes are
    /// ignored.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let (scalar, public_key) = curve_pkix::private_key_from_pkcs8(der, &ID_X25519, X25519_LEN)?;
        // Filled in place, so no by-value copy of the scalar is left behind.
        let mut bytes = [0u8; X25519_LEN];
        bytes.copy_from_slice(scalar);
        let key = Self::from_raw_bytes_wiping(&mut bytes);
        match public_key {
            Some(public_key) => {
                let u: &[u8; X25519_LEN] = public_key.try_into().ok()?;
                (canonical_u(u) == key.to_public_key().0).then_some(key)
            }
            None => Some(key),
        }
    }

    /// Decode RFC 7468 `PRIVATE KEY` text (§10) with [`Self::from_pkcs8_der`].
    #[must_use]
    pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        pem_decode(PRIVATE_KEY_LABEL, pem, Self::from_pkcs8_der)
    }
}

impl core::fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519PrivateKey(<redacted>)")
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0[..]);
    }
}

impl X25519PublicKey {
    /// Wrap an externally-supplied u-coordinate as a public key. No
    /// validation is performed; X25519 is defined for every 32-byte input
    /// after the high bit is masked, and the key stores the canonical
    /// encoding of the u-coordinate `bytes` names.
    #[must_use]
    pub fn from_raw_bytes(bytes: &[u8; X25519_LEN]) -> Self {
        Self(canonical_u(bytes))
    }

    /// Return the canonical 32-byte u-coordinate.
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; X25519_LEN] {
        self.0
    }

    /// Encode as the RFC 8410 §4 `SubjectPublicKeyInfo` in DER: `id-X25519`
    /// with the parameters absent (§3) and the 32-byte u-coordinate as the
    /// `subjectPublicKey`.
    #[must_use]
    pub fn to_spki_der(self) -> Vec<u8> {
        curve_pkix::public_key_to_spki(&ID_X25519, &self.0)
    }

    /// Encode as RFC 7468 `PUBLIC KEY` text (§13) around [`Self::to_spki_der`].
    #[must_use]
    pub fn to_spki_pem(self) -> String {
        pem_encode(PUBLIC_KEY_LABEL, self.to_spki_der())
    }

    /// Decode an RFC 8410 §4 `SubjectPublicKeyInfo` from strict DER with no
    /// trailing bytes: `id-X25519` with the parameters absent (§3) and a
    /// 32-byte key. As with [`Self::from_raw_bytes`], every 32-byte string is
    /// accepted, since RFC 7748 §5 defines X25519 on all of them, and the
    /// canonical u-coordinate is stored.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let u = curve_pkix::public_key_from_spki(der, &ID_X25519, X25519_LEN)?;
        Some(Self::from_raw_bytes(u.try_into().ok()?))
    }

    /// Decode RFC 7468 `PUBLIC KEY` text (§13) with [`Self::from_spki_der`].
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        pem_decode(PUBLIC_KEY_LABEL, pem, Self::from_spki_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key::io::der_octet_string;
    use crate::public_key::pkix::{AlgorithmIdentifier, OneAsymmetricKey};
    use crate::test_utils::{decode_hex_array, openssl3, ScratchFile};

    /// RFC 7748 §5.2 first single-step vector.
    #[test]
    fn rfc7748_section5_2_vector_1() {
        let k = decode_hex_array::<32>(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );
        let u = decode_hex_array::<32>(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        );
        let expected = decode_hex_array::<32>(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );
        assert_eq!(X25519::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 second single-step vector.
    #[test]
    fn rfc7748_section5_2_vector_2() {
        let k = decode_hex_array::<32>(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        );
        let u = decode_hex_array::<32>(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        );
        let expected = decode_hex_array::<32>(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        );
        assert_eq!(X25519::scalar_mult(&k, &u), expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 iteration.
    #[test]
    fn rfc7748_section5_2_iter_1() {
        let mut k = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k;
        let next = X25519::scalar_mult(&k, &u);
        u = k;
        k = next;
        let expected = decode_hex_array::<32>(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        );
        assert_eq!(k, expected);
        // Silence unused-warning on `u`: it would be the next u-coordinate input.
        let _ = u;
    }

    /// RFC 7748 §5.2 iterated test, after 1000 iterations.
    #[test]
    fn rfc7748_section5_2_iter_1000() {
        let mut k = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k;
        for _ in 0..1000 {
            let next = X25519::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = decode_hex_array::<32>(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        );
        assert_eq!(k, expected);
    }

    /// RFC 7748 §5.2 iterated test, after 1 000 000 iterations.
    /// Slow (~minutes in debug, ~seconds in release); gated `#[ignore]`.
    /// Run with: `cargo test --release -- --ignored x25519_iter_1m`.
    #[test]
    #[ignore = "RFC 7748 1M-iteration test; run with --release --ignored"]
    fn rfc7748_section5_2_iter_1m_x25519() {
        let mut k = decode_hex_array::<32>(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k;
        for _ in 0..1_000_000 {
            let next = X25519::scalar_mult(&k, &u);
            u = k;
            k = next;
        }
        let expected = decode_hex_array::<32>(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
        );
        assert_eq!(k, expected);
    }

    /// Round-trip: A * (B * G) == B * (A * G).
    #[test]
    fn ecdh_roundtrip() {
        let a = decode_hex_array::<32>(
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        let b = decode_hex_array::<32>(
            "0202020202020202020202020202020202020202020202020202020202020202",
        );
        let pa = X25519::scalar_mult_base(&a);
        let pb = X25519::scalar_mult_base(&b);
        let sa = X25519::scalar_mult(&a, &pb);
        let sb = X25519::scalar_mult(&b, &pa);
        assert_eq!(sa, sb);
    }

    /// All-zero output for a low-order input must be flagged by `agree`.
    #[test]
    fn agree_rejects_low_order_zero_output() {
        let secret = X25519PrivateKey::from_raw_bytes(&[0x55u8; 32]);
        // u = 0 is a low-order point; scalar_mult(_, 0) returns 0.
        let zero_pub = X25519PublicKey::from_raw_bytes(&[0u8; 32]);
        assert!(secret.agree(&zero_pub).is_none());
    }

    /// Field-arithmetic sanity: x * x^(-1) ≡ 1 for a few inputs.
    #[test]
    fn field_invert_inverse_of_self() {
        for seed in [1u8, 2, 7, 99, 0xfe] {
            let mut bytes = [0u8; 32];
            bytes[0] = seed;
            bytes[5] = seed.wrapping_add(3);
            bytes[17] = seed ^ 0xa5;
            let x = fe_from_bytes(&bytes);
            let inv = fe_invert(&x);
            let prod = fe_mul(&x, &inv);
            assert_eq!(fe_to_bytes(&prod), {
                let mut one = [0u8; 32];
                one[0] = 1;
                one
            });
        }
    }

    /// RFC 8410 §10.2: a certificate for an X25519 key, as printed. Errata 6936
    /// and 7070 report DER faults in its extensions, and 6936 its 66-character
    /// lines, which RFC 7468 §2 lets a parser accept; none concern its key.
    const RFC8410_X25519_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX\n\
        N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD\n\
        DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj\n\
        ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg\n\
        BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v\n\
        /BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg\n\
        w1AH9efZBw==\n\
        -----END CERTIFICATE-----\n";

    #[test]
    fn canonical_u_reads_u_coordinates_as_rfc7748_section_5_does() {
        let mut five = [0u8; 32];
        five[0] = 5;
        // p + 5 = 2^255 − 14, the non-canonical encoding of 5.
        let mut p_plus_5 = [0xffu8; 32];
        p_plus_5[0] = 0xf2;
        p_plus_5[31] = 0x7f;
        // Both, with bit 255 set, which §5 masks.
        let mut five_high = five;
        five_high[31] |= 0x80;
        let mut p_plus_5_high = p_plus_5;
        p_plus_5_high[31] |= 0x80;
        for encoding in [five, p_plus_5, five_high, p_plus_5_high] {
            assert_eq!(canonical_u(&encoding), five, "{encoding:02x?}");
        }
        // p = 2^255 − 19 names 0.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(canonical_u(&p), [0u8; 32]);
    }

    #[test]
    fn private_key_equality_is_by_value() {
        let key = X25519PrivateKey::from_raw_bytes(&[0x42; 32]);
        let same = X25519PrivateKey::from_raw_bytes(&[0x42; 32]);
        let mut other_bytes = [0x42; 32];
        other_bytes[1] ^= 0x01;
        let other = X25519PrivateKey::from_raw_bytes(&other_bytes);
        assert!(key == same);
        assert!(key != other);
    }

    /// A public key built from a non-canonical u-coordinate, or one with
    /// bit 255 set, equals and re-encodes as the key built from the
    /// canonical form, and agrees to the same shared secret.
    #[test]
    fn public_key_import_canonicalises_the_u_coordinate() {
        let mut five = [0u8; 32];
        five[0] = 5;
        let mut p_plus_5 = [0xffu8; 32];
        p_plus_5[0] = 0xf2;
        p_plus_5[31] = 0xff;
        let canonical = X25519PublicKey::from_raw_bytes(&five);
        let reduced = X25519PublicKey::from_raw_bytes(&p_plus_5);
        assert_eq!(reduced, canonical);
        assert_eq!(reduced.to_raw_bytes(), five);
        assert_eq!(
            X25519PublicKey::from_spki_der(&reduced.to_spki_der()),
            Some(canonical)
        );
        let secret = X25519PrivateKey::from_raw_bytes(&[0x33; 32]);
        assert_eq!(secret.agree(&reduced), secret.agree(&canonical));
    }

    /// RFC 7748 §6.1: Alice's private key.
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

    /// RFC 7748 §6.1: Alice's public key, X25519(a, 9).
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    /// RFC 7748 §6.1: Bob's public key.
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    #[test]
    fn spki_decodes_the_rfc8410_section_10_2_certificate_key() {
        let certificate = pem_decode("CERTIFICATE", RFC8410_X25519_CERTIFICATE, |der| {
            Some(der.to_vec())
        })
        .expect("RFC 7468 text");
        // The §10.2 dump puts the SubjectPublicKeyInfo at offset 115: a
        // two-byte header and 42 bytes of contents.
        let spki = &certificate[115..159];
        let public = X25519PublicKey::from_spki_der(spki).expect("§10.2 key");
        // The certificate's key is RFC 7748 §6.1's Alice's.
        assert_eq!(public.to_raw_bytes(), decode_hex_array::<32>(ALICE_PUBLIC));
        assert_eq!(public.to_spki_der(), spki);
        assert_eq!(
            X25519PublicKey::from_spki_pem(&public.to_spki_pem()),
            Some(public)
        );
    }

    #[test]
    fn pkcs8_ber_accepts_an_indefinite_length_container() {
        let private = X25519PrivateKey::from_raw_bytes(&decode_hex_array::<32>(ALICE_PRIVATE));
        let der = private.to_pkcs8_der();
        let ber = crate::test_utils::der_to_indefinite_length(&der);
        assert!(X25519PrivateKey::from_pkcs8_der(&ber).is_none());
        assert_eq!(
            X25519PrivateKey::from_pkcs8_ber(&ber),
            Some(private.clone())
        );
        assert_eq!(X25519PrivateKey::from_pkcs8_ber(&der), Some(private));
    }

    #[test]
    fn pkcs8_round_trips_and_a_version_2_public_key_must_match() {
        let private = X25519PrivateKey::from_raw_bytes(&decode_hex_array::<32>(ALICE_PRIVATE));
        let public = private.to_public_key();
        assert_eq!(public.to_raw_bytes(), decode_hex_array::<32>(ALICE_PUBLIC));
        let der = private.to_pkcs8_der();
        assert_eq!(
            der[..16],
            [
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
                0x04, 0x20
            ]
        );
        assert_eq!(der[16..], private.to_raw_bytes());
        assert_eq!(
            X25519PrivateKey::from_pkcs8_der(&der),
            Some(private.clone())
        );
        assert_eq!(
            X25519PrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem()),
            Some(private.clone())
        );
        assert!(X25519PrivateKey::from_pkcs8_pem(&public.to_spki_pem()).is_none());

        let with_public = |public_key: &[u8]| {
            OneAsymmetricKey::new(
                AlgorithmIdentifier::new(&ID_X25519, None),
                &der_octet_string(&private.to_raw_bytes()),
                Some(public_key),
            )
            .to_der()
        };
        assert_eq!(
            X25519PrivateKey::from_pkcs8_der(&with_public(&public.to_raw_bytes())),
            Some(private.clone())
        );
        // Alice's key with bit 255 set names the same u-coordinate, since RFC
        // 7748 §5 masks that bit, so it matches too.
        let alice = public.to_raw_bytes();
        let mut high_bit = alice;
        high_bit[31] |= 0x80;
        assert_eq!(
            X25519PrivateKey::from_pkcs8_der(&with_public(&high_bit)),
            Some(private.clone())
        );
        // Bob's key and a truncated key do not.
        let bob = decode_hex_array::<32>(BOB_PUBLIC);
        for mismatched in [&bob[..], &alice[..31]] {
            assert!(X25519PrivateKey::from_pkcs8_der(&with_public(mismatched)).is_none());
        }
    }

    /// OpenSSL's X25519 key parses and re-encodes byte for byte; OpenSSL reads
    /// the crate's keys, derives the same public key, re-emits the same
    /// encodings, and computes the same shared secret.
    #[test]
    fn openssl_x25519_keys_interoperate() {
        const TEST: &str = "openssl_x25519_keys_interoperate";
        let Some(theirs_pem) = openssl3(&["genpkey", "-algorithm", "X25519"], b"").or_skip(TEST)
        else {
            return;
        };
        let run = |args: &[&str], stdin: &[u8]| {
            openssl3(args, stdin)
                .or_skip(TEST)
                .expect("openssl works once genpkey did")
        };
        let theirs = X25519PrivateKey::from_pkcs8_pem(
            std::str::from_utf8(&theirs_pem).expect("PEM is ASCII"),
        )
        .expect("OpenSSL's PKCS #8 X25519 key");
        assert_eq!(theirs.to_pkcs8_pem().as_bytes(), theirs_pem);
        let theirs_spki = run(&["pkey", "-pubout", "-outform", "DER"], &theirs_pem);
        let theirs_public =
            X25519PublicKey::from_spki_der(&theirs_spki).expect("OpenSSL's SubjectPublicKeyInfo");
        assert_eq!(theirs_public, theirs.to_public_key());
        assert_eq!(theirs_public.to_spki_der(), theirs_spki);

        let ours = X25519PrivateKey::from_raw_bytes(&decode_hex_array::<32>(ALICE_PRIVATE));
        let public = ours.to_public_key();
        let ours_pem = ours.to_pkcs8_pem();
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
        assert!(String::from_utf8_lossy(&text).contains("X25519 Private-Key"));

        let key_file = ScratchFile::new(TEST, "key.pem", ours_pem.as_bytes());
        let peer_file = ScratchFile::new(TEST, "peer.pem", theirs_public.to_spki_pem().as_bytes());
        let shared = run(
            &[
                "pkeyutl",
                "-derive",
                "-inkey",
                key_file.arg(),
                "-peerkey",
                peer_file.arg(),
            ],
            b"",
        );
        let expected = ours
            .agree(&theirs_public)
            .expect("OpenSSL's random key is not of low order");
        assert_eq!(shared, expected);
        assert_eq!(theirs.agree(&public), Some(expected));
    }
}
