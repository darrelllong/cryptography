//! Digital Signature Algorithm (`DSA`, FIPS 186-5).
//!
//! `DSA` is the signature analogue of the prime-order subgroup construction
//! already used for `ElGamal`: choose a prime modulus `p`, a prime subgroup
//! order `q` dividing `p - 1`, and a generator `g` of the order-`q` subgroup.
//! Signing and verification then operate entirely modulo `q`, while the group
//! actions still happen modulo `p`.

use core::fmt;

use crate::hash::Digest;
use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::io::{
    decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap,
};
use crate::public_key::primes::{
    generate_prime_order_group, is_probable_prime, mod_inverse, mod_pow, random_nonzero_below,
};
use crate::Csprng;
use crate::Hmac;

const DSA_PUBLIC_LABEL: &str = "CRYPTOGRAPHY DSA PUBLIC KEY";
const DSA_PRIVATE_LABEL: &str = "CRYPTOGRAPHY DSA PRIVATE KEY";

/// Public key for `DSA`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsaPublicKey {
    /// Prime modulus `p`.
    p: BigUint,
    /// Prime subgroup order `q`.
    q: BigUint,
    /// Generator `g` of the order-`q` subgroup.
    g: BigUint,
    /// Public component `y = g^x mod p`.
    y: BigUint,
}

/// Private key for `DSA`.
#[derive(Clone, Eq, PartialEq)]
pub struct DsaPrivateKey {
    /// Prime modulus `p`.
    p: BigUint,
    /// Prime subgroup order `q`.
    q: BigUint,
    /// Generator `g` of the order-`q` subgroup.
    g: BigUint,
    /// Secret exponent `x`.
    x: BigUint,
    /// Cached public component `y = g^x mod p`.
    y: BigUint,
}

/// Raw `DSA` signature pair `(r, s)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsaSignature {
    r: BigUint,
    s: BigUint,
}

/// Namespace wrapper for the `DSA` construction.
pub struct Dsa;

impl DsaPublicKey {
    /// Return the prime modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Return the prime subgroup order.
    #[must_use]
    pub fn subgroup_order(&self) -> &BigUint {
        &self.q
    }

    /// Return the subgroup generator.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// Return the public component `y = g^x mod p`.
    #[must_use]
    pub fn public_component(&self) -> &BigUint {
        &self.y
    }

    /// Hash one message with `H`, then verify the resulting digest.
    #[must_use]
    pub fn verify_message<H: Digest>(&self, message: &[u8], signature: &DsaSignature) -> bool {
        let digest = H::digest(message);
        self.verify(&digest, signature)
    }

    /// Hash one message with `H`, then verify a serialized signature.
    #[must_use]
    pub fn verify_message_bytes<H: Digest>(&self, message: &[u8], signature: &[u8]) -> bool {
        let digest = H::digest(message);
        self.verify_bytes(&digest, signature)
    }

    /// Verify a signature over an explicit integer representative.
    #[must_use]
    pub fn verify_digest_scalar(&self, hash: &BigUint, signature: &DsaSignature) -> bool {
        if signature.r.is_zero()
            || signature.s.is_zero()
            || signature.r >= self.q
            || signature.s >= self.q
        {
            return false;
        }

        let Some(w) = mod_inverse(&signature.s, &self.q) else {
            return false;
        };
        // FIPS 186-5 verification variables: `w = s^-1 mod q`,
        // `z = leftmost-N-bits(H(M)) mod q`, then `u1 = z * w mod q` and
        // `u2 = r * w mod q`.
        let z = hash.modulo(&self.q);
        let u1 = BigUint::mod_mul(&z, &w, &self.q);
        let u2 = BigUint::mod_mul(&signature.r, &w, &self.q);

        let g_term = mod_pow(&self.g, &u1, &self.p);
        let y_term = mod_pow(&self.y, &u2, &self.p);
        let combined = if let Some(ctx) = MontgomeryCtx::new(&self.p) {
            ctx.mul(&g_term, &y_term)
        } else {
            BigUint::mod_mul(&g_term, &y_term, &self.p)
        };

        combined.modulo(&self.q) == signature.r
    }

    /// Verify a signature over the provided digest bytes.
    ///
    /// The digest is reduced to the leftmost `N = bits(q)` bits, matching the
    /// DSA representative construction from the Digital Signature Standard.
    #[must_use]
    pub fn verify(&self, digest: &[u8], signature: &DsaSignature) -> bool {
        self.verify_digest_scalar(&digest_to_scalar(digest, &self.q), signature)
    }

    /// Verify a byte-encoded signature produced by [`DsaPrivateKey::sign_bytes`].
    #[must_use]
    pub fn verify_bytes(&self, digest: &[u8], signature: &[u8]) -> bool {
        let Some(signature) = DsaSignature::from_key_blob(signature) else {
            return false;
        };
        self.verify(digest, &signature)
    }

    /// Encode the public key in the crate-defined binary format.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.q, &self.g, &self.y])
    }

    /// Decode the public key from the crate-defined binary format.
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

    /// Encode the public key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(DSA_PUBLIC_LABEL, &self.to_key_blob())
    }

    /// Encode the public key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "DsaPublicKey",
            &[
                ("p", &self.p),
                ("q", &self.q),
                ("g", &self.g),
                ("y", &self.y),
            ],
        )
    }

    /// Decode the public key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(DSA_PUBLIC_LABEL, pem)?;
        Self::from_key_blob(&blob)
    }

    /// Decode the public key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("DsaPublicKey", &["p", "q", "g", "y"], xml)?.into_iter();
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

impl DsaPrivateKey {
    /// Return the prime modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Return the prime subgroup order.
    #[must_use]
    pub fn subgroup_order(&self) -> &BigUint {
        &self.q
    }

    /// Return the subgroup generator.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// Return the private exponent `x`.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.x
    }

    /// Derive the matching public key from this private key.
    #[must_use]
    pub fn to_public_key(&self) -> DsaPublicKey {
        DsaPublicKey {
            p: self.p.clone(),
            q: self.q.clone(),
            g: self.g.clone(),
            y: self.y.clone(),
        }
    }

    /// Sign with an explicit nonce `k`.
    ///
    /// `DSA` uses a fresh `k` in `[1, q)` for every signature. This lower-level
    /// entry point keeps the arithmetic explicit for deterministic tests.
    ///
    /// Reusing the same `k` for two different messages with the same key
    /// immediately reveals the private exponent. Outside of fixed vectors,
    /// prefer [`Self::sign_digest`] or [`Self::sign_message`].
    #[must_use]
    pub fn sign_digest_with_nonce(&self, digest: &[u8], nonce: &BigUint) -> Option<DsaSignature> {
        if nonce.is_zero() || nonce >= &self.q {
            return None;
        }

        let z = digest_to_scalar(digest, &self.q);
        let r = mod_pow(&self.g, nonce, &self.p).modulo(&self.q);
        if r.is_zero() {
            return None;
        }

        let nonce_inv = mod_inverse(nonce, &self.q)?;
        let xr = BigUint::mod_mul(&self.x, &r, &self.q);
        let sum = z.add_ref(&xr).modulo(&self.q);
        let s = BigUint::mod_mul(&nonce_inv, &sum, &self.q);
        if s.is_zero() {
            return None;
        }

        Some(DsaSignature { r, s })
    }

    /// Sign a pre-hashed digest using RFC 6979 deterministic nonce derivation.
    #[must_use]
    pub fn sign_digest<H: Digest>(&self, digest: &[u8]) -> Option<DsaSignature> {
        let nonce = rfc6979_nonce::<H>(&self.q, &self.x, digest)?;
        self.sign_digest_with_nonce(digest, &nonce)
    }

    /// Sign a digest using a fresh random nonce.
    #[must_use]
    pub fn sign_digest_with_rng<R: Csprng>(
        &self,
        digest: &[u8],
        rng: &mut R,
    ) -> Option<DsaSignature> {
        loop {
            // Retry only in the negligible edge cases where `r = 0` or
            // `s = 0`; the fresh nonce changes the arithmetic path.
            let nonce = random_nonzero_below(rng, &self.q)?;
            if let Some(signature) = self.sign_digest_with_nonce(digest, &nonce) {
                return Some(signature);
            }
        }
    }

    /// Hash one message with `H`, then sign deterministically.
    #[must_use]
    pub fn sign_message<H: Digest>(&self, message: &[u8]) -> Option<DsaSignature> {
        let digest = H::digest(message);
        self.sign_digest::<H>(&digest)
    }

    /// Hash one message with `H`, then sign with randomized nonces.
    #[must_use]
    pub fn sign_message_with_rng<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<DsaSignature> {
        let digest = H::digest(message);
        self.sign_digest_with_rng(&digest, rng)
    }

    /// Sign a digest deterministically and return serialized signature bytes.
    #[must_use]
    pub fn sign_digest_bytes<H: Digest>(&self, digest: &[u8]) -> Option<Vec<u8>> {
        let signature = self.sign_digest::<H>(digest)?;
        Some(signature.to_key_blob())
    }

    /// Sign a digest with randomized nonces and return serialized signature bytes.
    #[must_use]
    pub fn sign_digest_bytes_with_rng<H: Digest, R: Csprng>(
        &self,
        digest: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let signature = self.sign_digest_with_rng(digest, rng)?;
        Some(signature.to_key_blob())
    }

    /// Hash one message with `H`, then sign and serialize deterministically.
    #[must_use]
    pub fn sign_message_bytes<H: Digest>(&self, message: &[u8]) -> Option<Vec<u8>> {
        let signature = self.sign_message::<H>(message)?;
        Some(signature.to_key_blob())
    }

    /// Hash one message with `H`, then sign and serialize with randomized nonces.
    #[must_use]
    pub fn sign_message_bytes_with_rng<H: Digest, R: Csprng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let signature = self.sign_message_with_rng::<H, R>(message, rng)?;
        Some(signature.to_key_blob())
    }

    /// Encode the private key in the crate-defined binary format.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.p, &self.q, &self.g, &self.x])
    }

    /// Decode the private key from the crate-defined binary format.
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

    /// Encode the private key in PEM using the crate-defined label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem_wrap(DSA_PRIVATE_LABEL, &self.to_key_blob())
    }

    /// Encode the private key as the crate's flat XML form.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "DsaPrivateKey",
            &[
                ("p", &self.p),
                ("q", &self.q),
                ("g", &self.g),
                ("x", &self.x),
            ],
        )
    }

    /// Decode the private key from the crate-defined PEM label.
    #[must_use]
    pub fn from_pem(pem: &str) -> Option<Self> {
        let blob = pem_unwrap(DSA_PRIVATE_LABEL, pem)?;
        Self::from_key_blob(&blob)
    }

    /// Decode the private key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("DsaPrivateKey", &["p", "q", "g", "x"], xml)?.into_iter();
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

impl fmt::Debug for DsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DsaPrivateKey(<redacted>)")
    }
}

impl DsaSignature {
    /// Return the first signature component.
    #[must_use]
    pub fn r(&self) -> &BigUint {
        &self.r
    }

    /// Return the second signature component.
    #[must_use]
    pub fn s(&self) -> &BigUint {
        &self.s
    }

    /// Encode the signature as a DER `SEQUENCE` of `(r, s)`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.r, &self.s])
    }

    /// Decode a crate-defined binary `DSA` signature.
    ///
    /// Zero values are rejected immediately. The range checks against the
    /// subgroup order `q` happen during verification because the signature
    /// encoding does not carry `q`.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let r = fields.next()?;
        let s = fields.next()?;
        if fields.next().is_some() || r.is_zero() || s.is_zero() {
            return None;
        }
        Some(Self { r, s })
    }
}

impl Dsa {
    /// Derive a `DSA` key pair from explicit subgroup parameters and secret exponent.
    #[must_use]
    pub fn from_secret_exponent(
        prime: &BigUint,
        subgroup_order: &BigUint,
        generator: &BigUint,
        secret: &BigUint,
    ) -> Option<(DsaPublicKey, DsaPrivateKey)> {
        if !validate_domain(prime, subgroup_order, generator)
            || secret.is_zero()
            || secret >= subgroup_order
        {
            return None;
        }

        let public_component = mod_pow(generator, secret, prime);
        Some((
            DsaPublicKey {
                p: prime.clone(),
                q: subgroup_order.clone(),
                g: generator.clone(),
                y: public_component.clone(),
            },
            DsaPrivateKey {
                p: prime.clone(),
                q: subgroup_order.clone(),
                g: generator.clone(),
                x: secret.clone(),
                y: public_component.clone(),
            },
        ))
    }

    /// Generate a `DSA` key pair over a prime-order subgroup.
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R, bits: usize) -> Option<(DsaPublicKey, DsaPrivateKey)> {
        let (prime, subgroup_order, _cofactor, generator) = generate_prime_order_group(rng, bits)?;
        let secret = random_nonzero_below(rng, &subgroup_order)?;
        let public_component = mod_pow(&generator, &secret, &prime);
        Some((
            DsaPublicKey {
                p: prime.clone(),
                q: subgroup_order.clone(),
                g: generator.clone(),
                y: public_component.clone(),
            },
            DsaPrivateKey {
                p: prime,
                q: subgroup_order,
                g: generator,
                x: secret,
                y: public_component.clone(),
            },
        ))
    }
}

/// Validate the subgroup parameters used by `DSA`.
///
/// This checks that `p` and `q` are prime, that `q` divides `p - 1`, and that
/// `g` lies in the order-`q` subgroup of `Z_p^*`.
fn validate_domain(prime: &BigUint, subgroup_order: &BigUint, generator: &BigUint) -> bool {
    if !is_probable_prime(prime) || !is_probable_prime(subgroup_order) {
        return false;
    }
    if subgroup_order >= prime {
        return false;
    }
    let p_minus_one = prime.sub_ref(&BigUint::one());
    if !p_minus_one.modulo(subgroup_order).is_zero() {
        return false;
    }
    if generator <= &BigUint::one() || generator >= prime {
        return false;
    }
    let one = BigUint::one();
    mod_pow(generator, subgroup_order, prime) == one
}

/// FIPS 186-5 digest representative reduction.
///
/// The standard keeps the leftmost `N = bits(q)` bits of the hash. The shift
/// amount is derived from the original digest width, not the width after
/// leading-zero trimming.
fn digest_to_scalar(digest: &[u8], modulus: &BigUint) -> BigUint {
    let mut value = BigUint::from_be_bytes(digest);
    let hash_bits = digest.len() * 8;
    let target_bits = modulus.bits();
    if hash_bits > target_bits {
        for _ in 0..(hash_bits - target_bits) {
            value.shr1();
        }
    }
    value
}

fn int_to_octets(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    if bytes.len() >= len {
        return bytes[bytes.len() - len..].to_vec();
    }
    let mut out = vec![0u8; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn bits_to_int(input: &[u8], target_bits: usize) -> BigUint {
    let mut value = BigUint::from_be_bytes(input);
    let input_bits = input.len() * 8;
    if input_bits > target_bits {
        for _ in 0..(input_bits - target_bits) {
            value.shr1();
        }
    }
    value
}

fn bits_to_octets(input: &[u8], q: &BigUint, q_bits: usize, ro_len: usize) -> Vec<u8> {
    let z1 = bits_to_int(input, q_bits);
    let z2 = z1.modulo(q);
    int_to_octets(&z2, ro_len)
}

fn rfc6979_nonce<H: Digest>(q: &BigUint, x: &BigUint, digest: &[u8]) -> Option<BigUint> {
    if q <= &BigUint::one() {
        return None;
    }

    let q_bits = q.bits();
    let ro_len = q_bits.div_ceil(8);
    let bx = int_to_octets(x, ro_len);
    let bh = bits_to_octets(digest, q, q_bits, ro_len);

    let mut v = vec![0x01; H::OUTPUT_LEN];
    let mut k = vec![0x00; H::OUTPUT_LEN];

    let mut data = Vec::with_capacity(v.len() + 1 + bx.len() + bh.len());
    data.extend_from_slice(&v);
    data.push(0x00);
    data.extend_from_slice(&bx);
    data.extend_from_slice(&bh);
    k = Hmac::<H>::compute(&k, &data);
    v = Hmac::<H>::compute(&k, &v);

    data.clear();
    data.extend_from_slice(&v);
    data.push(0x01);
    data.extend_from_slice(&bx);
    data.extend_from_slice(&bh);
    k = Hmac::<H>::compute(&k, &data);
    v = Hmac::<H>::compute(&k, &v);

    loop {
        let mut t = Vec::with_capacity(ro_len);
        while t.len() < ro_len {
            v = Hmac::<H>::compute(&k, &v);
            let take = (ro_len - t.len()).min(v.len());
            t.extend_from_slice(&v[..take]);
        }

        let candidate = bits_to_int(&t, q_bits);
        if !candidate.is_zero() && &candidate < q {
            return Some(candidate);
        }

        data.clear();
        data.extend_from_slice(&v);
        data.push(0x00);
        k = Hmac::<H>::compute(&k, &data);
        v = Hmac::<H>::compute(&k, &v);
    }
}

#[cfg(test)]
mod tests {
    use super::{Dsa, DsaPrivateKey, DsaPublicKey, DsaSignature};
    use crate::public_key::bigint::BigUint;
    use crate::{CtrDrbgAes256, Sha256, Sha384};

    fn derive_small_reference_key() -> (DsaPublicKey, DsaPrivateKey) {
        let p = BigUint::from_u64(23);
        let q = BigUint::from_u64(11);
        let g = BigUint::from_u64(4);
        let x = BigUint::from_u64(3);
        Dsa::from_secret_exponent(&p, &q, &g, &x).expect("valid DSA key")
    }

    #[test]
    fn derive_small_reference_key_components() {
        let (public, private) = derive_small_reference_key();
        assert_eq!(public.modulus(), &BigUint::from_u64(23));
        assert_eq!(public.subgroup_order(), &BigUint::from_u64(11));
        assert_eq!(public.generator(), &BigUint::from_u64(4));
        assert_eq!(public.public_component(), &BigUint::from_u64(18));
        assert_eq!(private.exponent(), &BigUint::from_u64(3));
    }

    #[test]
    fn exact_small_signature_matches_reference() {
        let (public, private) = derive_small_reference_key();
        let nonce = BigUint::from_u64(5);
        let signature = private
            .sign_digest_with_nonce(&[0x09], &nonce)
            .expect("valid DSA nonce");
        assert_eq!(signature.r(), &BigUint::from_u64(1));
        // `q = 11` is 4 bits wide, so the 8-bit digest is reduced to its
        // leftmost 4 bits before signing. `0x09` becomes `0x0`, which makes
        // this tiny reference vector sensitive to the FIPS truncation rule.
        assert_eq!(signature.s(), &BigUint::from_u64(5));
        assert!(public.verify(&[0x09], &signature));
    }

    #[test]
    fn rejects_invalid_parameters() {
        let p = BigUint::from_u64(23);
        let q = BigUint::from_u64(5);
        let g = BigUint::from_u64(4);
        let x = BigUint::from_u64(3);
        assert!(Dsa::from_secret_exponent(&p, &q, &g, &x).is_none());

        let q = BigUint::from_u64(11);
        let bad_g = BigUint::from_u64(5);
        assert!(Dsa::from_secret_exponent(&p, &q, &bad_g, &x).is_none());
        assert!(Dsa::from_secret_exponent(&p, &q, &g, &BigUint::zero()).is_none());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let seed = [0x31u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");
        let digest = b"dsa-signature-digest";
        let signature = private.sign_digest::<Sha256>(digest).expect("signature");
        assert!(public.verify(digest, &signature));
        assert!(!public.verify(b"wrong-digest", &signature));
    }

    #[test]
    fn sign_bytes_roundtrip() {
        let seed = [0x44u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");
        let digest = b"dsa-bytes";
        let signature = private
            .sign_digest_bytes::<Sha256>(digest)
            .expect("signature bytes");
        assert!(public.verify_bytes(digest, &signature));
    }

    #[test]
    fn sign_message_roundtrip() {
        let seed = [0x45u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");
        let message = b"dsa full message";
        let signature = private
            .sign_message::<Sha256>(message)
            .expect("message signature");
        assert!(public.verify_message::<Sha256>(message, &signature));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let seed = [0x46u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");
        let digest = b"dsa-tamper";
        let mut signature = private.sign_digest::<Sha256>(digest).expect("signature");
        signature.s = signature
            .s
            .add_ref(&BigUint::one())
            .modulo(public.subgroup_order());
        if signature.s.is_zero() {
            signature.s = BigUint::one();
        }
        assert!(!public.verify(digest, &signature));
    }

    #[test]
    fn cross_key_signature_is_rejected() {
        let mut drbg_a = CtrDrbgAes256::new(&[0x47; 48]);
        let mut drbg_b = CtrDrbgAes256::new(&[0x48; 48]);
        let (public_a, private_a) = Dsa::generate(&mut drbg_a, 64).expect("first key");
        let (public_b, _) = Dsa::generate(&mut drbg_b, 64).expect("second key");
        let digest = b"dsa-cross";
        let signature = private_a.sign_digest::<Sha256>(digest).expect("signature");
        assert!(public_a.verify(digest, &signature));
        assert!(!public_b.verify(digest, &signature));
    }

    #[test]
    fn sign_digest_with_nonce_rejects_out_of_range_nonce() {
        let (_public, private) = derive_small_reference_key();
        assert!(private
            .sign_digest_with_nonce(&[0x09], &BigUint::zero())
            .is_none());
        assert!(private
            .sign_digest_with_nonce(&[0x09], private.subgroup_order())
            .is_none());
    }

    #[test]
    fn sign_digest_with_nonce_is_deterministic_for_fixed_nonce() {
        let (_public, private) = derive_small_reference_key();
        let digest = [0x09];
        let nonce = BigUint::from_u64(7);
        let lhs = private
            .sign_digest_with_nonce(&digest, &nonce)
            .expect("first explicit nonce signature");
        let rhs = private
            .sign_digest_with_nonce(&digest, &nonce)
            .expect("second explicit nonce signature");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn generate_rejects_too_few_bits() {
        let mut drbg = CtrDrbgAes256::new(&[0x49; 48]);
        for bits in 0..19 {
            assert!(Dsa::generate(&mut drbg, bits).is_none());
        }
    }

    #[test]
    fn serialization_roundtrip_preserves_verification() {
        let seed = [0x4Au8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");
        let digest = b"dsa-serialize";
        let signature = private.sign_digest::<Sha256>(digest).expect("signature");
        let public_xml = public.to_xml();
        let public_again = DsaPublicKey::from_xml(&public_xml).expect("public xml");
        assert!(public_again.verify(digest, &signature));
    }

    #[test]
    fn digest_to_scalar_truncates_by_digest_width() {
        let q = BigUint::from_u64(257); // 9-bit subgroup order
        let digest = [0x00u8, 0xff];
        let value = super::digest_to_scalar(&digest, &q);
        assert_eq!(value, BigUint::one());
    }

    #[test]
    fn serialization_roundtrip() {
        let seed = [0x55u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");

        let public_blob = public.to_key_blob();
        let public_pem = public.to_pem();
        let public_xml = public.to_xml();
        let private_blob = private.to_key_blob();
        let private_pem = private.to_pem();
        let private_xml = private.to_xml();

        let public_from_blob = DsaPublicKey::from_key_blob(&public_blob).expect("public binary");
        let public_from_pem = DsaPublicKey::from_pem(&public_pem).expect("public pem");
        let public_from_xml = DsaPublicKey::from_xml(&public_xml).expect("public xml");
        let private_from_blob =
            DsaPrivateKey::from_key_blob(&private_blob).expect("private binary");
        let private_from_pem = DsaPrivateKey::from_pem(&private_pem).expect("private pem");
        let private_from_xml = DsaPrivateKey::from_xml(&private_xml).expect("private xml");

        assert_eq!(public_from_blob, public);
        assert_eq!(public_from_pem, public);
        assert_eq!(public_from_xml, public);
        assert_eq!(private_from_blob, private);
        assert_eq!(private_from_pem, private);
        assert_eq!(private_from_xml, private);
    }

    #[test]
    fn signature_binary_roundtrip() {
        let signature = DsaSignature {
            r: BigUint::from_u64(1),
            s: BigUint::from_u64(9),
        };
        let blob = signature.to_key_blob();
        let parsed = DsaSignature::from_key_blob(&blob).expect("signature");
        assert_eq!(parsed, signature);
    }

    #[test]
    fn verify_message_matches_explicit_digest() {
        let seed = [0x4Bu8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Dsa::generate(&mut drbg, 64).expect("generated DSA key");
        let message = b"dsa-digest";
        let digest = Sha384::digest(message);
        let signature = private.sign_digest::<Sha384>(&digest).expect("signature");
        assert!(public.verify_message::<Sha384>(message, &signature));
    }
}
