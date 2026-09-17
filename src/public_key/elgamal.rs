//! `ElGamal` public-key primitive (Taher `ElGamal`, 1985).
//!
//! This keeps the published `ElGamal` arithmetic map explicit: group
//! parameters plus the multiplicative encrypt/decrypt transform. The wrapper
//! layer adds subgroup-aware key generation and byte-oriented ciphertext
//! serialization while keeping the group arithmetic itself visible and
//! auditable.
//!
//! **This is raw (textbook) `ElGamal`, a low-level primitive, not a
//! message-encryption scheme.** It is not semantically secure and it is
//! malleable, on every entry point including the byte helpers:
//!
//! - Under a key with a prime subgroup order `q`, `δ^q = m^q · (b^q)^k =
//!   m^q (mod p)`, so every ciphertext publishes `m^q`: which coset of the
//!   order-`q` subgroup the message lies in.
//! - Under a safe-prime key, with `χ(x) = x^((p − 1)/2) mod p` the quadratic
//!   character, `χ(b)` is public and gives the parity of `a`, and `χ(γ)`
//!   gives the parity of `k`; so `χ(m) = χ(δ)` when `χ(b) = 1` and
//!   `χ(m) = χ(δ) · χ(γ)` otherwise. Every ciphertext publishes whether `m`
//!   is a quadratic residue.
//! - `(γ, c·δ)` decrypts to `c·m` for any `c` an attacker chooses.
//!
//! Confidentiality of messages needs a specified composition around a group
//! operation (a KEM, a key-derivation function and an AEAD, with domain
//! separation and context binding), which this module does not provide.
//! `ElGamalPublicKey::encrypt_bytes` carries the byte string as the integer
//! `m` itself and inherits all of the above.
//!
//! No NIST standard specifies `ElGamal` encryption. The paper
//! (`pubs/elgamal-1985.pdf`) takes a large prime `p` and a primitive element
//! `g` of `Z_p*`. A key has one of two group shapes, named by its exponent
//! bound:
//!
//! - **`p − 1`, the paper's shape** ([`ElGamal::from_secret_exponent`]).
//!   Whether `g` is primitive can be decided only from the factorization of
//!   `p − 1`, so `p` must be a safe prime, `p = 2q + 1` with `q` prime. Then
//!   the orders in `Z_p*` are 1, 2, `q` and `2q`, and `g` is primitive
//!   exactly when `g ≠ p − 1` and `g^q ≠ 1`. Every constructor and parser
//!   checks that. The secret `a = q` is refused (it gives `b = p − 1`, under
//!   which `b^k = ±1`), as is the nonce `k = q`, the one that gives
//!   `γ = p − 1` and `b^k = ±1`: either would make `δ = ±m`.
//! - **A prime subgroup order `q`**, whose domain parameters come from FIPS
//!   186-4 Appendix A ([`ElGamal::generate`]) or, for tests, from a toy
//!   generator that follows no standard ([`ElGamal::generate_toy`]). Every
//!   `g`, `b` and ciphertext `γ` such a key sees is checked to lie in the
//!   order-`q` subgroup.
//!
//! ## What a ciphertext must satisfy
//!
//! A plaintext is an integer `m` in `[1, p − 1]`; `m = 0` is refused, since
//! `δ = m · b^k` would then be `0` and announce the plaintext. Decryption
//! accepts `(γ, δ)` only with `1 < γ < p − 1` and `1 ≤ δ < p`, and, for a key
//! that carries `q`, only a `γ` with `γ^q ≡ 1 (mod p)`. A `γ` of small order —
//! `p − 1`, of order 2, or an element outside the order-`q` subgroup — is a
//! small-subgroup attack on the static exponent `a`: the plaintext recovered
//! from `γ^(e − a)` would depend only on `a` modulo the small order, and each
//! such query would hand the attacker bits of `a`. Under a safe prime `p − 1`
//! is the only element of order 2, and no honest ciphertext has it.
//!
//! ## Timing
//!
//! The modular exponentiation is rump's, which is variable-time: the number
//! of multiplications in `γ^(q − a) mod p` follows the bit length and
//! Hamming weight of the exponent, and the multiplications take
//! operand-dependent paths. A sender who chooses `γ` and times decryption
//! observes a function of the static secret `a` — the quantity leaked is `a`
//! itself, through the exponentiation's dependence on it. Encryption
//! exposes the per-message `k` the same way. Nothing here is safe against an
//! adversary who can time the holder of a key.

use core::fmt;

use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::public_key::primes::{
    is_in_prime_order_subgroup, is_probable_prime_under, random_nonzero_below,
    within_group_size_bounds, FfcDomain, FfcHash, FfcParameterSize, PrimalityPolicy,
    MAX_MODULUS_BITS, MAX_NONCE_DRAWS,
};
use crate::Csprng;
use rump::modular::{mod_pow, MontgomeryContext};
use rump::BigUint;

const ELGAMAL_PUBLIC_LABEL: &str = "CRYPTOGRAPHY ELGAMAL PUBLIC KEY";
const ELGAMAL_PRIVATE_LABEL: &str = "CRYPTOGRAPHY ELGAMAL PRIVATE KEY";

/// The FIPS 186-4 A.2.3 `index` of the generators [`ElGamal::generate`]
/// derives. A.2.3's examples give 1 to digital signatures and 2 to key
/// establishment; `ElGamal` encryption, a Diffie-Hellman exchange with a fresh
/// key per message, takes 2.
const GENERATOR_INDEX: u8 = 2;

/// Public key for the `ElGamal` primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalPublicKey {
    /// Prime modulus `p`.
    p: BigUint,
    /// Exclusive upper bound for the ephemeral exponent: `p − 1` for a key
    /// over a safe prime with primitive `g`, or the prime subgroup order `q`.
    exponent_bound: BigUint,
    /// Primitive root modulo `p`, or a generator of the order-`q` subgroup.
    g: BigUint,
    /// Public component `b = g^a mod p`.
    b: BigUint,
    /// Cached Montgomery context for arithmetic modulo `p`.
    p_ctx: Option<MontgomeryContext>,
}

/// Private key for the `ElGamal` primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct ElGamalPrivateKey {
    /// Prime modulus `p`.
    p: BigUint,
    /// Exponent cycle used during decryption: `p − 1` or the subgroup order
    /// `q`, as for [`ElGamalPublicKey`].
    exponent_modulus: BigUint,
    /// Secret exponent `a`.
    a: BigUint,
    /// Cached Montgomery context for arithmetic modulo `p`.
    p_ctx: Option<MontgomeryContext>,
}

/// Raw `ElGamal` ciphertext pair `(gamma, delta)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalCiphertext {
    gamma: BigUint,
    delta: BigUint,
}

/// Namespace wrapper for the `ElGamal` construction.
pub struct ElGamal;

impl ElGamalPublicKey {
    /// Return the prime modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Return the generator `g`.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// Return the exclusive upper bound for the ephemeral exponent: the
    /// subgroup order `q` for a subgroup key, `p − 1` for a key over a safe
    /// prime with primitive `g`.
    #[must_use]
    pub fn ephemeral_exclusive_bound(&self) -> &BigUint {
        &self.exponent_bound
    }

    /// Return `b = g^a mod p`.
    #[must_use]
    pub fn public_component(&self) -> &BigUint {
        &self.b
    }

    /// Encrypt with an explicit ephemeral exponent `k`.
    ///
    /// Textbook `ElGamal` uses `k` as the per-message randomizer. This
    /// lower-level entry point keeps it explicit so callers can separate the
    /// arithmetic from the randomness when they need deterministic control.
    ///
    /// Returns `None` unless `1 ≤ m < p` and `1 ≤ k <` the key's exponent
    /// bound. `m = 0` is refused because its `δ` would be `0` (see the module
    /// docs). Under a safe-prime key the nonce `k = q` is refused too: it
    /// gives `γ = p − 1` and `b^k = ±1`, so `δ = ±m`. No other `k` in
    /// `[1, p − 1)` makes `b^k = ±1`, and in a prime-order subgroup no `k` in
    /// `[1, q)` does.
    #[must_use]
    pub fn encrypt_with_nonce(
        &self,
        message: &BigUint,
        ephemeral: &BigUint,
    ) -> Option<ElGamalCiphertext> {
        if message.is_zero() || message >= &self.p {
            return None;
        }
        if ephemeral.is_zero() || ephemeral >= &self.exponent_bound {
            return None;
        }

        let gamma = if let Some(ctx) = &self.p_ctx {
            ctx.pow(&self.g, ephemeral)
        } else {
            mod_pow(&self.g, ephemeral, &self.p)
        };
        if gamma == self.p.sub(&BigUint::one()) {
            return None;
        }
        let shared = if let Some(ctx) = &self.p_ctx {
            ctx.pow(&self.b, ephemeral)
        } else {
            mod_pow(&self.b, ephemeral, &self.p)
        };
        // Every key has an odd prime modulus, so the Montgomery context is
        // always built; the plain-arithmetic arm is the fallback rump's
        // constructor leaves for a modulus it cannot serve.
        let delta = if let Some(ctx) = &self.p_ctx {
            ctx.mul(message, &shared)
        } else {
            BigUint::mod_mul(message, &shared, &self.p)
        };
        Some(ElGamalCiphertext { gamma, delta })
    }

    /// Encrypt a byte string with a fresh random ephemeral exponent.
    ///
    /// Raw `ElGamal`: the ciphertext publishes the quadratic character (or
    /// subgroup coset) of the message integer and is malleable; see the
    /// module documentation before using it to protect a message.
    ///
    /// This is the minimal "usable" layer for textbook `ElGamal`: it samples
    /// the ephemeral exponent from `[1, q)` when the public key carries an
    /// explicit subgroup order, and from `[1, p - 1)` otherwise. The encoded
    /// integer must be in `[1, p)`, so the practical message capacity is at
    /// most `floor((bits(p) - 1) / 8)` bytes and an all-zero (or empty) byte
    /// string, which encodes `0`, is refused. Callers that need hybrid
    /// encryption or padding should build that on top.
    ///
    /// The nonce [`Self::encrypt_with_nonce`] refuses under a safe-prime key,
    /// `k = q`, is redrawn, at most [`MAX_NONCE_DRAWS`] draws in all; `None`
    /// after that.
    ///
    /// # Panics
    ///
    /// Panics on a source that stalls, as
    /// [`random_nonzero_below`] does after 256 consecutive rejected draws.
    #[must_use]
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<ElGamalCiphertext> {
        let message_int = BigUint::from_be_bytes(message);
        if message_int.is_zero() || message_int >= self.p {
            return None;
        }
        for _ in 0..MAX_NONCE_DRAWS {
            let ephemeral = random_nonzero_below(rng, &self.exponent_bound)?;
            if let Some(ciphertext) = self.encrypt_with_nonce(&message_int, &ephemeral) {
                return Some(ciphertext);
            }
        }
        None
    }

    /// Encrypt a byte string and return a serialized ciphertext blob.
    ///
    /// Raw `ElGamal`, with the limits of [`Self::encrypt`].
    ///
    /// The serialized form is a DER `SEQUENCE` containing the `(gamma, delta)`
    /// pair in order, so the byte-level API stays self-contained without
    /// hiding the two-component `ElGamal` structure.
    ///
    /// The byte string is carried as the integer it encodes, so
    /// [`ElGamalPrivateKey::decrypt_bytes`] returns that integer's shortest
    /// big-endian form: leading zero bytes are not preserved (`[0x00, 0x12]`
    /// comes back as `[0x12]`). Callers that need length-preserving
    /// transport must frame the message themselves.
    #[must_use]
    pub fn encrypt_bytes<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<Vec<u8>> {
        let ciphertext = self.encrypt(message, rng)?;
        Some(ciphertext.to_key_blob())
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.p.clone(),
            self.exponent_bound.clone(),
            self.g.clone(),
            self.b.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// Structural validation (public material), under the fixed-base
    /// primality test: the group shape ([`group_shape`]); `1 < g < p` and
    /// `1 < b < p` (`b = 1` would be a key whose ciphertexts carry the
    /// plaintext in the clear); for the safe-prime shape, `g` primitive and
    /// `b ≠ p − 1`; for the subgroup shape, `g` and `b` in the order-`q`
    /// subgroup.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let exponent_bound = fields.next()?;
        let g = fields.next()?;
        let b = fields.next()?;
        let one = BigUint::one();
        if g <= one || g >= p || b <= one || b >= p {
            return None;
        }
        let members_valid = match group_shape(&p, &exponent_bound, PrimalityPolicy::Structural)? {
            GroupShape::SafePrime { q } => is_primitive_root(&g, &p, &q) && b != p.sub(&one),
            GroupShape::PrimeOrderSubgroup => {
                is_in_prime_order_subgroup(&g, &exponent_bound, &p)
                    && is_in_prime_order_subgroup(&b, &exponent_bound, &p)
            }
        };
        if !members_valid {
            return None;
        }
        let p_ctx = MontgomeryContext::new(&p).ok();
        Some(Self {
            p,
            exponent_bound,
            g,
            b,
            p_ctx,
        })
    }
}

crate::public_key::io::impl_xml_serialization!(
    ElGamalPublicKey,
    "ElGamalPublicKey",
    ["p", "exponent-bound", "generator", "public-component"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    ElGamalPublicKey,
    ELGAMAL_PUBLIC_LABEL,
    ["p", "exponent-bound", "generator", "public-component"]
);

impl ElGamalPrivateKey {
    /// Return the prime modulus.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Return the secret exponent `a`.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.a
    }

    /// Return the exponent-cycle modulus used during decryption: the subgroup
    /// order `q`, so decryption raises `γ` to `q − a`, or `p − 1`, where
    /// Fermat's little theorem gives the same cancellation.
    #[must_use]
    pub fn exponent_modulus(&self) -> &BigUint {
        &self.exponent_modulus
    }

    /// Decrypt the raw ciphertext, or return `None` for one this key must
    /// not touch.
    ///
    /// The ciphertext is validated first: `1 < γ < p − 1`, `1 ≤ δ < p`, and,
    /// when the key carries the subgroup order `q`, `γ^q ≡ 1 (mod p)` —
    /// the same membership test the key's own `g` and `b` passed, refusing
    /// every element outside the order-`q` subgroup (see the module docs).
    /// Under a safe prime every `γ` in that range has order `q` or `2q`.
    ///
    /// Decryption then avoids an explicit modular inverse by multiplying `δ`
    /// by `γ^(q − a)` (or `γ^(p − 1 − a)` when the subgroup order is unknown).
    /// With `γ` in the order-`q` subgroup, `γ^q = 1` and
    /// `γ^(q − a) · δ = g^(k(q − a)) · m · g^(ak) = (g^q)^k · m = m`; with the
    /// exponent cycle `p − 1`, Fermat's little theorem gives the same
    /// cancellation for any `γ` in `Z_p*`.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &ElGamalCiphertext) -> Option<BigUint> {
        if !self.accepts(ciphertext) {
            return None;
        }
        let exponent = self.exponent_modulus.sub(&self.a);
        let factor = if let Some(ctx) = &self.p_ctx {
            ctx.pow(&ciphertext.gamma, &exponent)
        } else {
            mod_pow(&ciphertext.gamma, &exponent, &self.p)
        };
        Some(if let Some(ctx) = &self.p_ctx {
            ctx.mul(&factor, &ciphertext.delta)
        } else {
            BigUint::mod_mul(&factor, &ciphertext.delta, &self.p)
        })
    }

    /// The ciphertext validation of [`Self::decrypt_raw`].
    fn accepts(&self, ciphertext: &ElGamalCiphertext) -> bool {
        let (gamma, delta) = (&ciphertext.gamma, &ciphertext.delta);
        let p_minus_one = self.p.sub(&BigUint::one());
        if gamma <= &BigUint::one() || gamma >= &p_minus_one || delta.is_zero() || delta >= &self.p
        {
            return false;
        }
        // A key whose exponent modulus is q carries a subgroup: γ must be in
        // it. Under a safe prime, excluding p − 1 leaves orders q and 2q.
        self.exponent_modulus == p_minus_one
            || is_in_prime_order_subgroup(gamma, &self.exponent_modulus, &self.p)
    }

    /// Decrypt a ciphertext back into the big-endian byte string that was
    /// interpreted as the plaintext integer; `None` for a ciphertext
    /// [`Self::decrypt_raw`] refuses.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> Option<Vec<u8>> {
        Some(self.decrypt_raw(ciphertext)?.to_be_bytes())
    }

    /// Decrypt a byte-encoded ciphertext produced by
    /// [`ElGamalPublicKey::encrypt_bytes`]; `None` if the blob does not
    /// decode or [`Self::decrypt_raw`] refuses it.
    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = ElGamalCiphertext::from_key_blob(ciphertext)?;
        self.decrypt(&ciphertext)
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.p.clone(),
            self.exponent_modulus.clone(),
            self.a.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// Full validation (private material), under the hardened primality
    /// test: the group shape ([`group_shape`]) and `a ∈ [1, modulus)`, with
    /// `a ≠ q` for the safe-prime shape. The blob carries no generator, so
    /// there is no membership to check here; every `γ` decrypted under the
    /// key is checked instead.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let exponent_modulus = fields.next()?;
        let a = fields.next()?;
        let shape = group_shape(&p, &exponent_modulus, PrimalityPolicy::Hardened)?;
        if a.is_zero() || a >= exponent_modulus {
            return None;
        }
        if let GroupShape::SafePrime { q } = shape {
            if a == q {
                return None;
            }
        }
        let p_ctx = MontgomeryContext::new(&p).ok();
        Some(Self {
            p,
            exponent_modulus,
            a,
            p_ctx,
        })
    }
}

crate::public_key::io::impl_xml_serialization!(
    ElGamalPrivateKey,
    "ElGamalPrivateKey",
    ["p", "exponent-modulus", "a"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    ElGamalPrivateKey,
    ELGAMAL_PRIVATE_LABEL,
    ["p", "exponent-modulus", "a"]
);

impl fmt::Debug for ElGamalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElGamalPrivateKey(<redacted>)")
    }
}

impl ElGamalCiphertext {
    /// Return the first ciphertext component.
    #[must_use]
    pub fn gamma(&self) -> &BigUint {
        &self.gamma
    }

    /// Return the second ciphertext component.
    #[must_use]
    pub fn delta(&self) -> &BigUint {
        &self.delta
    }

    /// Encode the ciphertext as a DER `SEQUENCE` of `(gamma, delta)`.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        encode_biguints(&[&self.gamma, &self.delta])
    }

    /// Decode the ciphertext from the crate's binary `ElGamal` ciphertext form.
    ///
    /// `gamma = g^k mod p` is never zero, and `delta = m · b^k mod p` is zero
    /// only for the plaintext `0`, which [`ElGamalPublicKey::encrypt_with_nonce`]
    /// refuses, so a zero component is rejected here. The checks that need
    /// `p` — the ranges and, for a key with a subgroup, `gamma`'s membership
    /// in it — happen in [`ElGamalPrivateKey::decrypt_raw`], because the blob
    /// does not carry `p`.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let mut fields = decode_biguints(blob)?.into_iter();
        let gamma = fields.next()?;
        let delta = fields.next()?;
        if fields.next().is_some() || gamma.is_zero() || delta.is_zero() {
            return None;
        }
        Some(Self { gamma, delta })
    }
}

impl ElGamal {
    /// Derive a raw `ElGamal` key pair from explicit parameters, the shape of
    /// the 1985 paper: a prime `p` and a primitive element `g` of `Z_p*`.
    ///
    /// Checked, under the hardened primality test: `p` has at most
    /// [`MAX_MODULUS_BITS`] bits (before any arithmetic) and is a safe prime,
    /// `p = 2q + 1` with `p` and `q` prime; `g` is a primitive root,
    /// `1 < g < p − 1` with `g^q ≠ 1`; and `1 ≤ a ≤ p − 2` with `a ≠ q`, so
    /// that `b = g^a` is neither 1 nor `p − 1` (under either every ciphertext
    /// carries `±m`). Returns `None` if a check fails.
    #[must_use]
    pub fn from_secret_exponent(
        prime: &BigUint,
        generator: &BigUint,
        secret: &BigUint,
    ) -> Option<(ElGamalPublicKey, ElGamalPrivateKey)> {
        // `p − 1` is formed before `group_shape` sees `p`, so `p = 0` is
        // refused here; every other `p` below 5 fails the shape checks.
        if prime.is_zero() {
            return None;
        }
        let p_minus_one = prime.sub(&BigUint::one());
        let GroupShape::SafePrime { q } =
            group_shape(prime, &p_minus_one, PrimalityPolicy::Hardened)?
        else {
            return None;
        };
        if !is_primitive_root(generator, prime, &q)
            || secret.is_zero()
            || secret >= &p_minus_one
            || secret == &q
        {
            return None;
        }

        let public_component = mod_pow(generator, secret, prime);
        let p_ctx = MontgomeryContext::new(prime).ok();
        Some((
            ElGamalPublicKey {
                p: prime.clone(),
                exponent_bound: p_minus_one.clone(),
                g: generator.clone(),
                b: public_component,
                p_ctx: p_ctx.clone(),
            },
            ElGamalPrivateKey {
                p: prime.clone(),
                exponent_modulus: p_minus_one,
                a: secret.clone(),
                p_ctx,
            },
        ))
    }

    /// Generate an `ElGamal` key pair in a prime-order subgroup whose domain
    /// parameters FIPS 186-4 generates: `p` and `q` by Appendix A.1.1.2 with
    /// `hash`, at the `(L, N)` pair `size`, and `g` by A.2.3. Returns `None` if
    /// `hash` is shorter than `N` bits (A.1.1.2).
    ///
    /// The group is FIPS 186-4's; the scheme is not a NIST algorithm. The key
    /// formats have no place for the seed record, so a key's group cannot be
    /// revalidated by A.1.1.3 and A.2.4 afterwards. The secret `a` is uniform
    /// on `[1, q − 1]`, and `q` is stored as the exponent bound.
    ///
    /// # Panics
    ///
    /// Panics on a source that stalls, as the samplers behind parameter
    /// generation ([`random_below`](crate::public_key::primes::random_below))
    /// and key generation ([`random_nonzero_below`]) do after 256
    /// consecutive rejected draws.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        size: FfcParameterSize,
        hash: FfcHash,
    ) -> Option<(ElGamalPublicKey, ElGamalPrivateKey)> {
        let group = FfcDomain::generate_fips186_4(rng, size, hash, GENERATOR_INDEX)?;
        Some(Self::keypair_in(&group, rng))
    }

    /// Generate an `ElGamal` key pair in a small group for tests. **This is
    /// not FIPS 186-4**: the sizes are ones it does not define, and the group
    /// construction follows no standard.
    ///
    /// Accepts `bits` from 19 to 1023 and returns `None` otherwise, so every
    /// size FIPS 186-4 covers goes through [`ElGamal::generate`]. The subgroup
    /// order has `clamp(⌊bits/4⌋, 16, 256)` bits, `p = kq + 1` for a random
    /// even `k`, and `g = h^k mod p` for a random `h`.
    ///
    /// # Panics
    ///
    /// Panics on a stalled or constant source, as the prime, cofactor and
    /// exponent samplers do (see
    /// [`random_probable_prime`](crate::public_key::primes::random_probable_prime)
    /// and [`random_nonzero_below`]).
    #[must_use]
    pub fn generate_toy<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(ElGamalPublicKey, ElGamalPrivateKey)> {
        let group = FfcDomain::generate_toy(rng, bits)?;
        Some(Self::keypair_in(&group, rng))
    }

    /// A key pair in a generated group: `a` uniform on `[1, q − 1]`.
    fn keypair_in<R: Csprng>(
        group: &FfcDomain,
        rng: &mut R,
    ) -> (ElGamalPublicKey, ElGamalPrivateKey) {
        let (prime, q, generator) = (group.p(), group.q(), group.g());
        let secret = random_nonzero_below(rng, q)
            .expect("a generated group has a prime subgroup order q >= 2^15");
        let public_component = mod_pow(generator, &secret, prime);
        let p_ctx = MontgomeryContext::new(prime).ok();
        (
            ElGamalPublicKey {
                p: prime.clone(),
                exponent_bound: q.clone(),
                g: generator.clone(),
                b: public_component,
                p_ctx: p_ctx.clone(),
            },
            ElGamalPrivateKey {
                p: prime.clone(),
                exponent_modulus: q.clone(),
                a: secret,
                p_ctx,
            },
        )
    }
}

/// The two group shapes a key's exponent bound can name.
enum GroupShape {
    /// Bound `p − 1` over a safe prime `p = 2q + 1`.
    SafePrime {
        /// The prime `(p − 1) / 2`.
        q: BigUint,
    },
    /// Bound `q`, a prime within the size policy dividing `p − 1`.
    PrimeOrderSubgroup,
}

/// The group check behind every constructor and parser, for both key halves.
///
/// The size bound on `p` ([`MAX_MODULUS_BITS`]) is checked before any
/// arithmetic, and `p` must be an odd probable prime under `policy`. An
/// `exponent_bound` of `p − 1` requires `(p − 1)/2` prime under `policy` too,
/// since only the factorization of `p − 1` lets a primitive root be
/// recognized; any other bound must be a prime subgroup order `q` within the
/// size policy ([`within_group_size_bounds`]) with `q | p − 1`.
fn group_shape(
    p: &BigUint,
    exponent_bound: &BigUint,
    policy: PrimalityPolicy,
) -> Option<GroupShape> {
    if p.bits() > MAX_MODULUS_BITS || !p.is_odd() || !is_probable_prime_under(p, policy) {
        return None;
    }
    let p_minus_one = p.sub(&BigUint::one());
    if exponent_bound == &p_minus_one {
        let mut q = p_minus_one;
        q.shr1();
        return is_probable_prime_under(&q, policy).then_some(GroupShape::SafePrime { q });
    }
    let subgroup = within_group_size_bounds(p, exponent_bound)
        && exponent_bound < &p_minus_one
        && is_probable_prime_under(exponent_bound, policy)
        && p_minus_one.rem(exponent_bound).is_zero();
    subgroup.then_some(GroupShape::PrimeOrderSubgroup)
}

/// Whether `g` is a primitive root modulo the safe prime `p = 2q + 1`: the
/// orders in `Z_p*` are 1, 2, `q` and `2q`, so `g` has order `2q` exactly
/// when it is neither 1 nor `p − 1` and `g^q ≠ 1`.
fn is_primitive_root(g: &BigUint, p: &BigUint, q: &BigUint) -> bool {
    *g > BigUint::one() && *g < p.sub(&BigUint::one()) && mod_pow(g, q, p) != BigUint::one()
}

#[cfg(test)]
mod tests {
    use super::{ElGamal, ElGamalCiphertext, ElGamalPrivateKey, ElGamalPublicKey};
    use crate::public_key::io::encode_biguints;
    use crate::public_key::primes::{FfcHash, FfcParameterSize};
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    fn u(value: u64) -> BigUint {
        BigUint::from_u64(value)
    }

    /// The smallest prime-order subgroup the size policy admits: `q = 32771`,
    /// `p = 2q + 1 = 65543`, `g = 4` (a quadratic residue, so of order `q`).
    /// `a = 3` gives `b = 64`.
    const P: u64 = 65543;
    const Q: u64 = 32771;
    const G: u64 = 4;

    /// A key pair over the subgroup, in the shape `ElGamal::generate` builds:
    /// the exponent bound and modulus are `q`.
    fn subgroup_key() -> (ElGamalPublicKey, ElGamalPrivateKey) {
        let public =
            ElGamalPublicKey::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(G), &u(64)]))
                .expect("subgroup public key");
        let private = ElGamalPrivateKey::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(3)]))
            .expect("subgroup private key");
        (public, private)
    }

    #[test]
    fn byte_wrapper_refuses_zero_and_drops_leading_zeros() {
        let (public, private) =
            ElGamal::from_secret_exponent(&u(P), &u(5), &u(7)).expect("valid key");
        let mut drbg = CtrDrbgAes256::new(&[0x46; 48]);
        // The all-zero message encodes m = 0, whose delta would be 0.
        assert!(public.encrypt_bytes(&[0x00], &mut drbg).is_none());
        assert!(public.encrypt_bytes(&[0x00, 0x00], &mut drbg).is_none());
        assert!(public.encrypt_bytes(&[], &mut drbg).is_none());
        // Documented: the integer value is carried, not the byte length.
        let blob = public
            .encrypt_bytes(&[0x00, 0x12], &mut drbg)
            .expect("fits");
        assert_eq!(private.decrypt_bytes(&blob), Some(vec![0x12]));
        // Neither gamma = 0 nor delta = 0 is ever a ciphertext.
        assert!(ElGamalCiphertext::from_key_blob(&encode_biguints(&[&u(0), &u(5)])).is_none());
        assert!(ElGamalCiphertext::from_key_blob(&encode_biguints(&[&u(5), &u(0)])).is_none());
    }

    /// Decryption validates the ciphertext: in range, and, for a key that
    /// carries `q`, `γ` in the order-`q` subgroup.
    #[test]
    fn decryption_refuses_out_of_range_and_small_subgroup_gamma() {
        let (public, private) = subgroup_key();
        let message = u(1234);
        let honest = public
            .encrypt_with_nonce(&message, &u(77))
            .expect("valid ephemeral exponent");
        assert_eq!(private.decrypt_raw(&honest), Some(message.clone()));
        assert_eq!(private.decrypt(&honest), Some(message.to_be_bytes()));
        assert_eq!(
            private.decrypt_bytes(&honest.to_key_blob()),
            Some(message.to_be_bytes())
        );
        let with = |gamma: u64, delta: u64| ElGamalCiphertext {
            gamma: u(gamma),
            delta: u(delta),
        };
        let delta = honest.delta().to_u64().expect("small");
        let gamma = honest.gamma().to_u64().expect("small");
        // γ out of range: 0, 1, p, p + 1.
        for bad_gamma in [0, 1, P, P + 1] {
            assert_eq!(
                private.decrypt_raw(&with(bad_gamma, delta)),
                None,
                "γ = {bad_gamma}"
            );
        }
        // γ = p − 1 has order 2; 5 and q are quadratic non-residues, so
        // neither lies in the order-q subgroup. Each would make the
        // "plaintext" a function of a alone.
        for outside in [P - 1, 5, Q] {
            assert_eq!(
                private.decrypt_raw(&with(outside, delta)),
                None,
                "γ = {outside}"
            );
        }
        // δ out of range: 0, p, p + 1.
        for bad_delta in [0, P, P + 1] {
            assert_eq!(
                private.decrypt_raw(&with(gamma, bad_delta)),
                None,
                "δ = {bad_delta}"
            );
        }
        // δ = 1 is in range (it is the ciphertext of m = b^-k).
        assert!(private.decrypt_raw(&with(gamma, 1)).is_some());
    }

    /// A safe-prime key refuses `γ` outside `(1, p − 1)`: modulo 23 = 2·11 + 1
    /// with primitive root 5, `γ = 22` has order 2. The one nonce that would
    /// produce it, `k = q = 11`, is refused at encryption.
    #[test]
    fn safe_prime_key_refuses_gamma_of_order_two() {
        let (public, private) =
            ElGamal::from_secret_exponent(&u(23), &u(5), &u(7)).expect("valid key");
        assert!(public.encrypt_with_nonce(&u(11), &u(11)).is_none());
        let honest = public.encrypt_with_nonce(&u(11), &u(3)).expect("k = 3");
        assert_eq!(private.decrypt_raw(&honest), Some(u(11)));
        for (gamma, delta) in [(0, 5), (1, 5), (22, 5), (23, 5), (10, 0), (10, 23)] {
            let bad = ElGamalCiphertext {
                gamma: u(gamma),
                delta: u(delta),
            };
            assert_eq!(private.decrypt_raw(&bad), None, "({gamma}, {delta})");
        }
    }

    #[test]
    fn public_key_parse_rejects_tampered_fields() {
        // Safe-prime shape: p = 23 = 2·11 + 1, bound p − 1 = 22, g = 5
        // primitive, b = 5^7 = 17.
        let ok = |f: [u64; 4]| {
            let v: Vec<BigUint> = f.iter().map(|&x| u(x)).collect();
            let r: Vec<&BigUint> = v.iter().collect();
            ElGamalPublicKey::from_key_blob(&encode_biguints(&r)).is_some()
        };
        assert!(ok([23, 22, 5, 17]));
        // Subgroup shape: q = 32771, g = 4 and b = 64 both of order q.
        assert!(ok([P, Q, G, 64]));
        // Composite / even p; b = 1, b = 0, b = p; g = 1, g = p.
        for f in [
            [21, 20, 5, 17],
            [22, 21, 5, 17],
            [23, 22, 5, 1],
            [23, 22, 5, 0],
            [23, 22, 5, 23],
            [23, 22, 1, 17],
            [23, 22, 23, 17],
            // g not primitive: 2 has order 11, 22 has order 2; b = p − 1.
            [23, 22, 2, 17],
            [23, 22, 22, 17],
            [23, 22, 5, 22],
            // p − 1 bound over a prime that is not safe: 29 = 2·14 + 1, with
            // 2 a primitive root there.
            [29, 28, 2, 7],
            // Bound neither p - 1 nor a prime divisor of p - 1: 9, 7, 24, 1.
            [23, 9, 4, 18],
            [23, 7, 4, 18],
            [23, 24, 4, 18],
            [23, 1, 4, 18],
            // A prime-order subgroup below the size policy: q = 11 in Z_23*.
            [23, 11, 4, 18],
            // Bound q = 32771 but g or b outside the order-q subgroup (5 is
            // a quadratic non-residue, p - 1 has order 2); a composite bound
            // (32769); a prime bound not dividing p - 1 (32779).
            [P, Q, 5, 64],
            [P, Q, G, 5],
            [P, Q, G, P - 1],
            [P, 32769, G, 64],
            [P, 32779, G, 64],
        ] {
            assert!(!ok(f), "{f:?}");
        }
    }

    #[test]
    fn private_key_parse_rejects_tampered_fields() {
        let ok = |f: [u64; 3]| {
            let v: Vec<BigUint> = f.iter().map(|&x| u(x)).collect();
            let r: Vec<&BigUint> = v.iter().collect();
            ElGamalPrivateKey::from_key_blob(&encode_biguints(&r)).is_some()
        };
        assert!(ok([23, 22, 7]));
        assert!(ok([P, Q, 3]));
        for f in [
            [21, 20, 7],
            [22, 21, 7],
            [23, 22, 0],
            [23, 22, 22],
            // a = q gives b = p − 1; 29 is not a safe prime.
            [23, 22, 11],
            [29, 28, 3],
            [P, Q, Q],
            [P, Q, 0],
            [23, 9, 3],
            [23, 7, 3],
            [23, 24, 3],
            [23, 11, 3],
            [P, 32769, 3],
            [P, 32779, 3],
        ] {
            assert!(!ok(f), "{f:?}");
        }
    }

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(23);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &g, &a).expect("valid ElGamal key");
        assert_eq!(public.modulus(), &BigUint::from_u64(23));
        assert_eq!(public.generator(), &BigUint::from_u64(5));
        assert_eq!(public.public_component(), &BigUint::from_u64(17));
        assert_eq!(public.ephemeral_exclusive_bound(), &BigUint::from_u64(22));
        assert_eq!(private.modulus(), &BigUint::from_u64(23));
        assert_eq!(private.exponent(), &BigUint::from_u64(7));
        assert_eq!(private.exponent_modulus(), &BigUint::from_u64(22));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(23);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let k = BigUint::from_u64(3);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &g, &a).expect("valid ElGamal key");

        for msg in [1u64, 2, 11, 22] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public
                .encrypt_with_nonce(&message, &k)
                .expect("valid ephemeral exponent");
            assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
        }
        assert!(public.encrypt_with_nonce(&BigUint::zero(), &k).is_none());
        assert!(public.encrypt_with_nonce(&p, &k).is_none());
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(23);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let k = BigUint::from_u64(3);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &g, &a).expect("valid ElGamal key");
        let message = BigUint::from_u64(11);
        let ciphertext = public
            .encrypt_with_nonce(&message, &k)
            .expect("valid ephemeral exponent");
        assert_eq!(ciphertext.gamma(), &BigUint::from_u64(10));
        assert_eq!(ciphertext.delta(), &BigUint::from_u64(16));
        assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
    }

    #[test]
    fn rejects_invalid_parameters() {
        let composite = BigUint::from_u64(21);
        let generator = BigUint::from_u64(5);
        let secret = BigUint::from_u64(7);
        assert!(ElGamal::from_secret_exponent(&composite, &generator, &secret).is_none());
        // Modulo 23: g = 2 has order 11 and g = 22 order 2, so neither is
        // primitive; a = q = 11 would give b = 22. 29 is prime but not safe.
        assert!(ElGamal::from_secret_exponent(&u(23), &u(2), &secret).is_none());
        assert!(ElGamal::from_secret_exponent(&u(23), &u(22), &secret).is_none());
        assert!(ElGamal::from_secret_exponent(&u(23), &generator, &u(11)).is_none());
        assert!(ElGamal::from_secret_exponent(&u(29), &u(2), &secret).is_none());
        // p = 0, 1 and 2 are refused, not panicked on.
        for small in [0, 1, 2] {
            assert!(ElGamal::from_secret_exponent(&u(small), &generator, &secret).is_none());
        }

        let p = BigUint::from_u64(23);
        assert!(ElGamal::from_secret_exponent(&p, &BigUint::one(), &secret).is_none());
        assert!(ElGamal::from_secret_exponent(&p, &p, &secret).is_none());
        assert!(ElGamal::from_secret_exponent(&p, &generator, &BigUint::zero()).is_none());
        assert!(ElGamal::from_secret_exponent(&p, &generator, &u(22)).is_none());
        // An oversized modulus is refused before any primality test: 2^16384 + 1.
        let mut wide = BigUint::zero();
        wide.set_bit(16384);
        wide = wide.add(&BigUint::one());
        let elapsed = crate::test_utils::fastest_of_three(|| {
            assert!(ElGamal::from_secret_exponent(&wide, &generator, &secret).is_none());
            assert!(ElGamalPublicKey::from_key_blob(&encode_biguints(&[
                &wide,
                &wide.sub(&BigUint::one()),
                &generator,
                &secret
            ]))
            .is_none());
        });
        assert!(
            elapsed < crate::test_utils::REFUSAL_BOUND,
            "refusal took {elapsed:?}"
        );
    }

    #[test]
    fn rejects_invalid_ephemeral_exponent() {
        let p = BigUint::from_u64(23);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, _) = ElGamal::from_secret_exponent(&p, &g, &a).expect("valid ElGamal key");
        let message = BigUint::from_u64(11);
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::zero())
            .is_none());
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::from_u64(22))
            .is_none());
        // A subgroup key bounds k by q.
        let (public, _) = subgroup_key();
        assert!(public.encrypt_with_nonce(&message, &u(Q)).is_none());
        assert!(public.encrypt_with_nonce(&message, &u(Q - 1)).is_some());
    }

    #[test]
    fn generate_keypair_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0x33; 48]);
        let (public, private) =
            ElGamal::generate_toy(&mut drbg, 32).expect("ElGamal key generation");
        let message = BigUint::from_u64(42);
        let ciphertext = public
            .encrypt_with_nonce(&message, &BigUint::from_u64(3))
            .expect("valid ephemeral exponent");
        assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
    }

    #[test]
    fn encrypt_with_nonce_is_repeatable_for_fixed_nonce() {
        let p = BigUint::from_u64(23);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, _private) = ElGamal::from_secret_exponent(&p, &g, &a).expect("valid key");
        let message = BigUint::from_u64(11);
        let nonce = BigUint::from_u64(3);
        let lhs = public
            .encrypt_with_nonce(&message, &nonce)
            .expect("first explicit nonce encryption");
        let rhs = public
            .encrypt_with_nonce(&message, &nonce)
            .expect("second explicit nonce encryption");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn byte_wrapper_roundtrip() {
        let p = BigUint::from_u64(P);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &g, &a).expect("valid ElGamal key");
        let mut drbg = CtrDrbgAes256::new(&[0x44; 48]);
        let message = [0x12, 0x34];
        let ciphertext = public.encrypt(&message, &mut drbg).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(message.to_vec()));
    }

    #[test]
    fn generate_toy_refuses_sizes_fips_covers_or_that_cannot_be_built() {
        let mut drbg = CtrDrbgAes256::new(&[0x94; 48]);
        for bits in [15, 16, 17, 18, 1024, 2048, 3072] {
            assert!(
                ElGamal::generate_toy(&mut drbg, bits).is_none(),
                "{bits} bits"
            );
        }
    }

    #[test]
    fn generate_refuses_a_hash_shorter_than_n() {
        let mut drbg = CtrDrbgAes256::new(&[0x95; 48]);
        let short = ElGamal::generate(&mut drbg, FfcParameterSize::L2048N256, FfcHash::Sha224);
        assert!(short.is_none());
    }

    #[test]
    fn fips_group_keypair_round_trips() {
        let mut drbg = CtrDrbgAes256::new(&[0x96; 48]);
        let (public, private) =
            ElGamal::generate(&mut drbg, FfcParameterSize::L1024N160, FfcHash::Sha256)
                .expect("SHA-256 is long enough for N = 160");
        assert_eq!(public.modulus().bits(), 1024);
        assert_eq!(public.ephemeral_exclusive_bound().bits(), 160);
        let public = ElGamalPublicKey::from_key_blob(&public.to_key_blob()).expect("public blob");
        let ciphertext = public.encrypt(b"fips group", &mut drbg).expect("fits");
        assert_eq!(private.decrypt(&ciphertext), Some(b"fips group".to_vec()));
        // gamma = p - 1 is refused by the generated key too.
        let forged = ElGamalCiphertext {
            gamma: public.modulus().sub(&BigUint::one()),
            delta: ciphertext.delta().clone(),
        };
        assert_eq!(private.decrypt(&forged), None);
    }

    #[test]
    fn generate_then_random_encrypt_roundtrip() {
        let mut key_rng = CtrDrbgAes256::new(&[0x53; 48]);
        let mut enc_rng = CtrDrbgAes256::new(&[0x54; 48]);
        let (public, private) =
            ElGamal::generate_toy(&mut key_rng, 32).expect("ElGamal key generation");
        let message = [0x2a];
        let ciphertext = public
            .encrypt(&message, &mut enc_rng)
            .expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(message.to_vec()));
    }

    #[test]
    fn key_serialization_roundtrip() {
        let p = BigUint::from_u64(23);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, private) = ElGamal::from_secret_exponent(&p, &g, &a).expect("valid key");

        let public_blob = public.to_key_blob();
        let private_blob = private.to_key_blob();
        assert_eq!(
            ElGamalPublicKey::from_key_blob(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            ElGamalPrivateKey::from_key_blob(&private_blob),
            Some(private.clone())
        );

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(
            ElGamalPublicKey::from_pem(&public_pem),
            Some(public.clone())
        );
        assert_eq!(
            ElGamalPrivateKey::from_pem(&private_pem),
            Some(private.clone())
        );
        assert_eq!(ElGamalPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(ElGamalPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn generated_key_serialization_roundtrip() {
        let mut key_rng = CtrDrbgAes256::new(&[0x63; 48]);
        let mut enc_rng = CtrDrbgAes256::new(&[0x64; 48]);
        let (public, private) =
            ElGamal::generate_toy(&mut key_rng, 32).expect("ElGamal key generation");
        let message = [0x11];

        let public = ElGamalPublicKey::from_key_blob(&public.to_key_blob()).expect("public binary");
        let private = ElGamalPrivateKey::from_xml(&private.to_xml()).expect("private XML");
        let ciphertext = public
            .encrypt(&message, &mut enc_rng)
            .expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(message.to_vec()));
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let p = BigUint::from_u64(P);
        let g = BigUint::from_u64(5);
        let a = BigUint::from_u64(7);
        let (public, private) =
            ElGamal::from_secret_exponent(&p, &g, &a).expect("valid ElGamal key");
        let mut drbg = CtrDrbgAes256::new(&[0x45; 48]);
        let message = [0x12, 0x34];
        let ciphertext = public
            .encrypt_bytes(&message, &mut drbg)
            .expect("message fits");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(message.to_vec()));
    }

    /// Under a safe-prime key only `k = q` makes `b^k = ±1`, which would send
    /// `δ = ±m`. Modulo 23 with primitive root 5, for every `a` other than
    /// `q = 11`, `k = 11` is refused and every other nonce gives a ciphertext
    /// that hides `m` and decrypts to it; `encrypt` never returns the refused
    /// nonce's ciphertext.
    #[test]
    fn only_the_nonce_q_would_send_the_plaintext_and_it_is_refused() {
        let message = u(5);
        let minus_message = u(23 - 5);
        for a in (1..22).filter(|&a| a != 11) {
            let (public, private) =
                ElGamal::from_secret_exponent(&u(23), &u(5), &u(a)).expect("toy key");
            assert!(public.encrypt_with_nonce(&message, &u(11)).is_none());
            for k in (1..22).filter(|&k| k != 11) {
                let ciphertext = public
                    .encrypt_with_nonce(&message, &u(k))
                    .unwrap_or_else(|| panic!("a = {a}, k = {k}"));
                assert_ne!(ciphertext.delta, message, "a = {a}, k = {k}");
                assert_ne!(ciphertext.delta, minus_message, "a = {a}, k = {k}");
                assert_eq!(private.decrypt_raw(&ciphertext), Some(message.clone()));
            }
            let mut rng = CtrDrbgAes256::new(&[0x5e; 48]);
            for _ in 0..64 {
                let ciphertext = public.encrypt(&[5], &mut rng).expect("a nonce is found");
                assert_ne!(ciphertext.gamma, u(22));
                assert_eq!(private.decrypt_raw(&ciphertext), Some(message.clone()));
            }
        }
    }

    /// Raw `ElGamal` publishes the message's class, from public values only.
    /// Modulo 23 with primitive root 5 and `a = 7` (`χ(b) = −1`), every one of
    /// the 22 messages under each of the 20 accepted nonces gives
    /// `χ(m) = χ(δ) · χ(γ)`: 440 of 440. Under the subgroup key every
    /// ciphertext gives `δ^q = m^q`. The documentation promises nothing more.
    #[test]
    fn raw_ciphertexts_publish_the_message_class() {
        use rump::modular::mod_pow;
        let (public, _) = ElGamal::from_secret_exponent(&u(23), &u(5), &u(7)).expect("key");
        let p = public.modulus().clone();
        let half = u(11);
        let chi = |x: &BigUint| mod_pow(x, &half, &p);
        let one = BigUint::one();
        let chi_b = chi(public.public_component());
        assert_ne!(chi_b, one, "a = 7 is odd");
        let mut recovered = 0;
        for m in 1..23 {
            for k in (1..22).filter(|&k| k != 11) {
                let ciphertext = public
                    .encrypt_with_nonce(&u(m), &u(k))
                    .expect("accepted nonce");
                let from_public = if chi_b == one {
                    chi(ciphertext.delta())
                } else {
                    BigUint::mod_mul(&chi(ciphertext.delta()), &chi(ciphertext.gamma()), &p)
                };
                assert_eq!(from_public, chi(&u(m)), "m = {m}, k = {k}");
                recovered += 1;
            }
        }
        assert_eq!(recovered, 440);

        let (public, _) = subgroup_key();
        let (p, q) = (u(P), u(Q));
        for m in [2, 4, 5, 1234, P - 1] {
            for k in [1, 77, Q - 1] {
                let ciphertext = public
                    .encrypt_with_nonce(&u(m), &u(k))
                    .expect("accepted nonce");
                assert_eq!(mod_pow(ciphertext.delta(), &q, &p), mod_pow(&u(m), &q, &p));
            }
        }
    }
}
