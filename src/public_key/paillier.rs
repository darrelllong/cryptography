//! Paillier public-key primitive (Pascal Paillier, 1999).
//!
//! This keeps the Paillier arithmetic core explicit: the `L(x) = (x - 1) / n`
//! map, the Carmichael-function private exponent, and the multiplicative
//! encryption formula over `n^2`. The wrapper layer already handles nonce
//! generation, byte conversion, and ciphertext serialization, so the
//! homomorphic API stays usable without hiding the scheme's structure.
//!
//! Encryption is randomized (the nonce `r`), so equal messages give
//! different ciphertexts; but the scheme is malleable by design — that is
//! the homomorphism — so it offers no chosen-ciphertext protection, and a
//! decryptor exposed to arbitrary ciphertexts is a plaintext oracle for
//! any ciphertext an adversary can derive from another.
//!
//! The private exponent `λ = lcm(p − 1, q − 1)` drives rump's variable-time
//! exponentiation modulo `n²`, whose sequence of squarings and
//! multiplications is the exponent's window pattern; an adversary who
//! observes it (a co-resident process reading the cache or branch
//! predictor, a probe on the power rail) learns `λ`, and `λ` factors `n`.

use core::fmt;

use crate::public_key::io::{decode_biguints, encode_biguints};
use crate::public_key::primes::{
    is_probable_prime_untrusted, random_coprime_below, random_probable_prime,
};
use crate::Csprng;
use rump::modular::{mod_inverse, mod_pow, MontgomeryContext};
use rump::number_theory::{gcd, lcm};
use rump::BigUint;

const PAILLIER_PUBLIC_LABEL: &str = "CRYPTOGRAPHY PAILLIER PUBLIC KEY";
const PAILLIER_PRIVATE_LABEL: &str = "CRYPTOGRAPHY PAILLIER PRIVATE KEY";

/// Public key for the Paillier primitive.
///
/// `zeta` is the public encryption base. This implementation uses `n + 1`,
/// the standard simple choice that makes the decryption algebra especially
/// direct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaillierPublicKey {
    /// Public modulus `n = p * q`.
    n: BigUint,
    /// Cached `n^2` used by the Paillier group operations.
    n_squared: BigUint,
    /// Public encryption base, typically `n + 1`.
    zeta: BigUint,
    /// Cached Montgomery context for arithmetic modulo `n^2`.
    n_squared_ctx: Option<MontgomeryContext>,
}

/// Private key for the Paillier primitive.
///
/// `u` is the precomputed inverse of the decryption multiplier
/// `L(zeta^lambda mod n^2)` modulo `n`, stored so decryption does not have to
/// recompute it for every ciphertext.
#[derive(Clone, Eq, PartialEq)]
pub struct PaillierPrivateKey {
    /// Public modulus `n = p * q`.
    n: BigUint,
    /// Cached `n^2` used during decryption.
    n_squared: BigUint,
    /// Carmichael exponent `lambda = lcm(p - 1, q - 1)`.
    lambda: BigUint,
    /// Precomputed inverse of `L(zeta^lambda mod n^2)` modulo `n`.
    u: BigUint,
    /// Cached Montgomery context for arithmetic modulo `n^2`.
    n_squared_ctx: Option<MontgomeryContext>,
    /// Cached Montgomery context for arithmetic modulo `n`.
    n_ctx: Option<MontgomeryContext>,
}

/// Namespace wrapper for the Paillier construction.
pub struct Paillier;

impl PaillierPublicKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return the public base `zeta`.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.zeta
    }

    /// Return the largest plaintext integer accepted by the raw scheme.
    #[must_use]
    pub fn max_plaintext_exclusive(&self) -> &BigUint {
        &self.n
    }

    /// Encrypt with an explicit nonce `r`.
    ///
    /// Paillier encryption is `c = zeta^m * r^n mod n^2`. The nonce `r` must
    /// be drawn from `Z_n^*`; the higher-level `encrypt(...)` helper samples
    /// it internally, while this entry point keeps it explicit for
    /// deterministic tests and arithmetic cross-checks.
    #[must_use]
    pub fn encrypt_with_nonce(&self, message: &BigUint, nonce: &BigUint) -> Option<BigUint> {
        if message >= &self.n {
            return None;
        }
        if nonce.is_zero() || nonce >= &self.n || gcd(nonce, &self.n) != BigUint::one() {
            return None;
        }

        let left = if let Some(ctx) = &self.n_squared_ctx {
            ctx.pow(&self.zeta, message)
        } else {
            mod_pow(&self.zeta, message, &self.n_squared)
        };
        let right = if let Some(ctx) = &self.n_squared_ctx {
            ctx.pow(nonce, &self.n)
        } else {
            mod_pow(nonce, &self.n, &self.n_squared)
        };
        // `n^2` is cached in the key so the hot path does not redo the same
        // public multiplication on every operation. Valid Paillier keys
        // always use odd `n`, so `n^2` stays on the Montgomery fast path.
        // Keep the slow path as a defensive fallback for malformed
        // caller-supplied state.
        let product = if let Some(ctx) = &self.n_squared_ctx {
            ctx.mul(&left, &right)
        } else {
            BigUint::mod_mul(&left, &right, &self.n_squared)
        };
        Some(product)
    }

    /// Encrypt a byte string with a fresh random nonce from `Z_n^*`.
    #[must_use]
    pub fn encrypt<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<BigUint> {
        let message_int = BigUint::from_be_bytes(message);
        let nonce = random_coprime_below(rng, &self.n, &self.n)?;
        self.encrypt_with_nonce(&message_int, &nonce)
    }

    /// Encrypt a byte string and return the serialized ciphertext bytes.
    #[must_use]
    pub fn encrypt_bytes<R: Csprng>(&self, message: &[u8], rng: &mut R) -> Option<Vec<u8>> {
        let ciphertext = self.encrypt(message, rng)?;
        Some(encode_biguints(&[&ciphertext]))
    }

    /// Re-randomize an existing ciphertext without changing the plaintext.
    ///
    /// Multiplying by `r^n mod n^2` is an encryption of zero, so the
    /// plaintext is preserved while the random factor is refreshed.
    ///
    /// Returns `None` if the input is not in the ciphertext range `[0, n^2)`.
    #[must_use]
    pub fn rerandomize<R: Csprng>(&self, ciphertext: &BigUint, rng: &mut R) -> Option<BigUint> {
        // Range-check before touching the RNG so a rejected input consumes
        // no randomness.
        if ciphertext >= &self.n_squared {
            return None;
        }
        let nonce = random_coprime_below(rng, &self.n, &self.n)?;
        let factor = if let Some(ctx) = &self.n_squared_ctx {
            ctx.pow(&nonce, &self.n)
        } else {
            mod_pow(&nonce, &self.n, &self.n_squared)
        };
        let product = if let Some(ctx) = &self.n_squared_ctx {
            ctx.mul(ciphertext, &factor)
        } else {
            BigUint::mod_mul(ciphertext, &factor, &self.n_squared)
        };
        Some(product)
    }

    /// Combine two ciphertexts so that decryption adds the plaintexts modulo `n`.
    ///
    /// This is the defining Paillier homomorphism:
    /// `Enc(m1) * Enc(m2) = Enc(m1 + m2 mod n)`.
    ///
    /// Returns `None` if either input is not in the ciphertext range `[0, n^2)`.
    #[must_use]
    pub fn add_ciphertexts(&self, lhs: &BigUint, rhs: &BigUint) -> Option<BigUint> {
        if lhs >= &self.n_squared || rhs >= &self.n_squared {
            return None;
        }
        if let Some(ctx) = &self.n_squared_ctx {
            Some(ctx.mul(lhs, rhs))
        } else {
            Some(BigUint::mod_mul(lhs, rhs, &self.n_squared))
        }
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.n.clone(), self.zeta.clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// Structural validation (public material): `n` odd and greater than one,
    /// and the base `zeta` a unit of `Z_{n²}` in `[2, n²)` — the range
    /// [`Paillier::from_primes_with_base`] reduces it into and the condition
    /// under which `zeta^m` is invertible. Compositeness of `n` is not
    /// tested; a prime `n` breaks only the key of whoever published it.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        let zeta = fields.next()?;
        if n <= BigUint::one() || !n.is_odd() || zeta <= BigUint::one() {
            return None;
        }
        let n_squared = n.mul(&n);
        if zeta >= n_squared || gcd(&zeta, &n) != BigUint::one() {
            return None;
        }
        let n_squared_ctx = MontgomeryContext::new(&n_squared).ok();
        Some(Self {
            n,
            n_squared,
            zeta,
            n_squared_ctx,
        })
    }
}

crate::public_key::io::impl_xml_serialization!(
    PaillierPublicKey,
    "PaillierPublicKey",
    ["n", "zeta"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    PaillierPublicKey,
    PAILLIER_PUBLIC_LABEL,
    ["n", "zeta"]
);

impl PaillierPrivateKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return the Carmichael exponent `lambda = lcm(p - 1, q - 1)`.
    #[must_use]
    pub fn lambda(&self) -> &BigUint {
        &self.lambda
    }

    /// Return the precomputed decryption factor `u`.
    #[must_use]
    pub fn decryption_factor(&self) -> &BigUint {
        &self.u
    }

    /// Decrypt the raw ciphertext.
    ///
    /// Returns `None` if the input is not in the ciphertext range `[0, n²)`,
    /// the same check [`PaillierPublicKey::rerandomize`] and
    /// [`PaillierPublicKey::add_ciphertexts`] apply. Never panics. A value in
    /// range but outside `Z*_{n²}` (one sharing a factor with `n`, which
    /// only a holder of a factor of `n` can construct) is not a Paillier
    /// ciphertext and decrypts to an unspecified value.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> Option<BigUint> {
        if ciphertext >= &self.n_squared {
            return None;
        }
        let value = if let Some(ctx) = &self.n_squared_ctx {
            ctx.pow(ciphertext, &self.lambda)
        } else {
            mod_pow(ciphertext, &self.lambda, &self.n_squared)
        };
        // A valid ciphertext lies in Z*_{n^2}, so `c^lambda mod n^2` is always
        // of the form `1 + k*n` and is never zero. An invalid ciphertext with
        // `c ≡ 0 (mod n)` (e.g. `c ∈ {0, n, 2n, …}`, which an attacker can
        // submit freely) collapses to `value = 0`, and `paillier_l` would then
        // underflow on `value - 1` and panic. Reject that case up front so a
        // malformed ciphertext cannot crash the decryptor.
        if value.is_zero() {
            return Some(BigUint::zero());
        }
        // Valid Paillier ciphertexts produce values of the form `1 + k*n`
        // here, so `L(value)` is defined and extracts the linear term that
        // still carries the plaintext. `u` was precomputed as
        // `L(zeta^lambda mod n^2)^-1 mod n`, so multiplying by it explicitly
        // cancels the fixed `L(zeta^lambda)` factor left by the public base
        // and recovers the plaintext representative `m`.
        let lifted = paillier_l(&value, &self.n);
        Some(if let Some(ctx) = &self.n_ctx {
            ctx.mul(&lifted, &self.u)
        } else {
            BigUint::mod_mul(&lifted, &self.u, &self.n)
        })
    }

    /// Decrypt a ciphertext with [`Self::decrypt_raw`] and return the
    /// recovered integer's minimal big-endian encoding: no leading zero
    /// octets, and `0x00` alone for the integer zero. A message that began
    /// with zero octets, or was empty, therefore comes back without them.
    /// `None` if the ciphertext is not below `n²`.
    #[must_use]
    pub fn decrypt(&self, ciphertext: &BigUint) -> Option<Vec<u8>> {
        Some(self.decrypt_raw(ciphertext)?.to_be_bytes())
    }

    /// Decrypt a byte-encoded ciphertext produced by
    /// [`PaillierPublicKey::encrypt_bytes`]; the plaintext bytes are those
    /// of [`Self::decrypt`], and a ciphertext at or above `n²` is refused.
    #[must_use]
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut fields = decode_biguints(ciphertext)?.into_iter();
        let value = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        self.decrypt(&value)
    }

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![self.n.clone(), self.lambda.clone(), self.u.clone()]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// The blob carries no primes, so this is the internal consistency its
    /// fields allow. For `n = p·q` with odd primes and
    /// `λ = lcm(p − 1, q − 1)`: `n` is odd; `λ` is even, `1 < λ < n`, and
    /// `gcd(λ, n) = 1` (Paillier requires `gcd(n, φ(n)) = 1`); `u` is a unit
    /// modulo `n`; and, by Carmichael's theorem in `Z*_{n²}` (whose exponent
    /// divides `n·λ`), `2^{n·λ} ≡ 1 (mod n²)` — one exponentiation that a
    /// `λ` unrelated to `n` fails with overwhelming probability (a multiple
    /// of the true `λ` passes, and also decrypts correctly given a matching
    /// `u`). `u` cannot be tied to `λ` here because the base `zeta` is not
    /// carried.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let n = fields.next()?;
        let lambda = fields.next()?;
        let u = fields.next()?;
        let one = BigUint::one();
        if n <= one
            || !n.is_odd()
            || lambda.is_odd()
            || lambda <= one
            || lambda >= n
            || gcd(&lambda, &n) != one
            || u.is_zero()
            || u >= n
            || gcd(&u, &n) != one
        {
            return None;
        }
        let n_squared = n.mul(&n);
        if mod_pow(&BigUint::from_u64(2), &n.mul(&lambda), &n_squared) != one {
            return None;
        }
        let n_squared_ctx = MontgomeryContext::new(&n_squared).ok();
        let n_ctx = MontgomeryContext::new(&n).ok();
        Some(Self {
            n,
            n_squared,
            lambda,
            u,
            n_squared_ctx,
            n_ctx,
        })
    }
}

crate::public_key::io::impl_xml_serialization!(
    PaillierPrivateKey,
    "PaillierPrivateKey",
    ["n", "lambda", "u"]
);
crate::public_key::io::impl_blob_pem_serialization!(
    PaillierPrivateKey,
    PAILLIER_PRIVATE_LABEL,
    ["n", "lambda", "u"]
);

impl fmt::Debug for PaillierPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaillierPrivateKey(<redacted>)")
    }
}

impl Paillier {
    /// Derive a raw Paillier key pair from explicit primes and an explicit
    /// public base.
    ///
    /// Returns `None` if the primes are invalid, `gcd(n, (p - 1)(q - 1)) != 1`,
    /// or if the supplied base does not make the `L(zeta^lambda mod n^2)`
    /// factor invertible modulo `n`.
    #[must_use]
    pub fn from_primes_with_base(
        p: &BigUint,
        q: &BigUint,
        base: &BigUint,
    ) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        if p == q || !is_probable_prime_untrusted(p) || !is_probable_prime_untrusted(q) {
            return None;
        }

        let n = p.mul(q);
        let p_minus_one = p.sub(&BigUint::one());
        let q_minus_one = q.sub(&BigUint::one());
        let totient = p_minus_one.mul(&q_minus_one);
        if gcd(&n, &totient) != BigUint::one() {
            return None;
        }

        let lambda = lcm(&p_minus_one, &q_minus_one);
        let n_squared = n.mul(&n);
        let zeta = base.rem(&n_squared);
        if zeta <= BigUint::one() {
            return None;
        }

        let lifted = paillier_l(&mod_pow(&zeta, &lambda, &n_squared), &n);
        let u = mod_inverse(&lifted, &n)?;

        let n_squared_ctx = MontgomeryContext::new(&n_squared).ok();
        let n_ctx = MontgomeryContext::new(&n).ok();
        Some((
            PaillierPublicKey {
                n: n.clone(),
                n_squared: n_squared.clone(),
                zeta,
                n_squared_ctx: n_squared_ctx.clone(),
            },
            PaillierPrivateKey {
                n,
                n_squared,
                lambda,
                u,
                n_squared_ctx,
                n_ctx,
            },
        ))
    }

    /// Derive a Paillier key pair using the deterministic base `n + 1`.
    ///
    /// Sampling `zeta` randomly is valid, but `n + 1` is the usual simple
    /// choice and keeps this constructor deterministic.
    #[must_use]
    pub fn from_primes(
        p: &BigUint,
        q: &BigUint,
    ) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        let n = p.mul(q);
        let base = n.add(&BigUint::one());
        Self::from_primes_with_base(p, q, &base)
    }

    /// Generate a Paillier key pair using the standard `n + 1` base.
    #[must_use]
    pub fn generate<R: Csprng>(
        rng: &mut R,
        bits: usize,
    ) -> Option<(PaillierPublicKey, PaillierPrivateKey)> {
        // With fewer than 8 total bits the split can collapse to the same tiny
        // prime on both sides, so a distinct-prime key may never be found.
        if bits < 8 {
            return None;
        }

        let p_bits = bits / 2;
        let q_bits = bits - p_bits;
        loop {
            let p = random_probable_prime(rng, p_bits)?;
            let q = random_probable_prime(rng, q_bits)?;
            if let Some(keypair) = Self::from_primes(&p, &q) {
                return Some(keypair);
            }
        }
    }
}

fn paillier_l(value: &BigUint, modulus: &BigUint) -> BigUint {
    // The Paillier `L` function is only defined on values of the form
    // `1 + k*n`; valid decryption inputs satisfy exactly that congruence
    // because the binomial expansion of `(n + 1)^m` modulo `n^2` leaves only
    // the linear `m*n` term, so `zeta^m` and therefore `c^lambda` stay in the
    // `1 + nZ` slice that `L` projects back down to `Z_n`.
    // For a value outside `Z*_{n^2}` (one sharing a factor with `n`) the
    // congruence fails and the quotient is meaningless; `decrypt_raw`
    // documents that such inputs yield an unspecified value. No debug-only
    // assertion here, so the decryptor behaves identically in every build.
    let shifted = value.sub(&BigUint::one());
    let (quotient, _remainder) = shifted.div_rem(modulus);
    quotient
}

#[cfg(test)]
mod tests {
    use super::{Paillier, PaillierPrivateKey, PaillierPublicKey};
    use crate::public_key::io::encode_biguints;
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    fn u(value: u64) -> BigUint {
        BigUint::from_u64(value)
    }

    /// `c = p` shares a factor with `n`, so `c^λ mod n²` is not `≡ 1 (mod n)`
    /// and the L function has no meaning. `decrypt_raw` promises never to
    /// panic on such input, in debug builds included.
    #[test]
    fn decrypt_raw_survives_ciphertext_sharing_a_factor_with_n() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (_, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        assert!(private.decrypt_raw(&BigUint::from_u64(3)).is_some());
        assert!(private.decrypt_raw(&BigUint::from_u64(5)).is_some());
    }

    #[test]
    fn derive_small_reference_key() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        assert_eq!(public.modulus(), &BigUint::from_u64(15));
        assert_eq!(public.generator(), &BigUint::from_u64(16));
        assert_eq!(private.modulus(), &BigUint::from_u64(15));
        assert_eq!(private.lambda(), &BigUint::from_u64(4));
        assert_eq!(private.decryption_factor(), &BigUint::from_u64(4));
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let nonce = BigUint::from_u64(2);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");

        for msg in [0u64, 1, 7, 14] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public
                .encrypt_with_nonce(&message, &nonce)
                .expect("valid Paillier nonce");
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, Some(message));
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let nonce = BigUint::from_u64(2);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let message = BigUint::from_u64(7);
        let ciphertext = public
            .encrypt_with_nonce(&message, &nonce)
            .expect("valid Paillier nonce");
        assert_eq!(ciphertext, BigUint::from_u64(83));
        assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
    }

    /// A ciphertext with `c ≡ 0 (mod n)` is invalid but attacker-submittable;
    /// it drives `c^λ mod n²` to zero, where the L function is undefined.
    /// Decryption returns a defined value for it, and refuses anything at
    /// or above `n²` before exponentiating.
    #[test]
    fn decrypt_rejects_zero_congruent_ciphertext_without_panicking() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (_public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        for c in [0u64, 15, 30] {
            // c ∈ {0, n, 2n}
            let plaintext = private.decrypt_raw(&BigUint::from_u64(c));
            assert_eq!(plaintext, Some(BigUint::from_u64(0)));
        }
        for c in [225u64, 226, 1_000] {
            // c ≥ n² = 225
            assert_eq!(private.decrypt_raw(&BigUint::from_u64(c)), None);
            assert_eq!(private.decrypt(&BigUint::from_u64(c)), None);
            let framed = encode_biguints(&[&BigUint::from_u64(c)]);
            assert_eq!(private.decrypt_bytes(&framed), None);
        }
    }

    #[test]
    fn raw_paillier_is_additively_homomorphic() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let left_nonce = BigUint::from_u64(2);
        let right_nonce = BigUint::from_u64(4);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let left = BigUint::from_u64(7);
        let right = BigUint::from_u64(6);

        let left_cipher = public
            .encrypt_with_nonce(&left, &left_nonce)
            .expect("valid Paillier nonce");
        let right_cipher = public
            .encrypt_with_nonce(&right, &right_nonce)
            .expect("valid Paillier nonce");
        let modulus_squared = public.modulus().mul(public.modulus());
        let combined_cipher = BigUint::mod_mul(&left_cipher, &right_cipher, &modulus_squared);
        let decrypted = private.decrypt_raw(&combined_cipher);
        let expected = left.add(&right).rem(public.modulus());

        assert_eq!(decrypted, Some(expected));
    }

    #[test]
    fn rejects_invalid_parameters() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(7);
        assert!(Paillier::from_primes(&p, &q).is_none());

        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        assert!(Paillier::from_primes_with_base(&p, &q, &BigUint::one()).is_none());
    }

    #[test]
    fn rejects_invalid_nonce() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, _) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let message = BigUint::from_u64(7);
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::zero())
            .is_none());
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::from_u64(3))
            .is_none());
        assert!(public
            .encrypt_with_nonce(&message, &BigUint::from_u64(15))
            .is_none());
    }

    #[test]
    fn byte_wrapper_roundtrip_and_rerandomize() {
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let mut drbg = CtrDrbgAes256::new(&[0x52; 48]);
        let ciphertext = public
            .encrypt(&[0x12, 0x34], &mut drbg)
            .expect("message fits");
        let rerandomized = public
            .rerandomize(&ciphertext, &mut drbg)
            .expect("rerandomization");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x12, 0x34]));
        assert_eq!(private.decrypt(&rerandomized), Some(vec![0x12, 0x34]));
        assert_ne!(ciphertext, rerandomized);
    }

    #[test]
    fn add_ciphertexts_wrapper_matches_plaintext_addition() {
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let left = public
            .encrypt_with_nonce(&BigUint::from_u64(0x12), &BigUint::from_u64(2))
            .expect("valid nonce");
        let right = public
            .encrypt_with_nonce(&BigUint::from_u64(0x34), &BigUint::from_u64(3))
            .expect("valid nonce");
        let combined = public
            .add_ciphertexts(&left, &right)
            .expect("ciphertexts are in range");
        assert_eq!(private.decrypt(&combined), Some(vec![0x46]));
    }

    #[test]
    fn generate_keypair_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0x53; 48]);
        let (public, private) = Paillier::generate(&mut drbg, 32).expect("Paillier key generation");
        let ciphertext = public.encrypt(&[0x2a], &mut drbg).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x2a]));
        // Bytes go through the integer: leading zero octets are dropped and
        // the zero message comes back as one `0x00` octet.
        let ciphertext = public
            .encrypt(&[0x00, 0x2a], &mut drbg)
            .expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x2a]));
        let ciphertext = public.encrypt(&[], &mut drbg).expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(vec![0x00]));
    }

    /// A [`Csprng`] that must never be asked for bytes.
    struct NoDraw;

    impl crate::Csprng for NoDraw {
        fn fill_bytes(&mut self, _out: &mut [u8]) {
            panic!("rerandomize drew randomness before range-checking its input");
        }
    }

    #[test]
    fn rerandomize_range_checks_before_drawing_randomness() {
        let (public, _) = Paillier::from_primes(&u(257), &u(263)).expect("valid key");
        let invalid = public.modulus().mul(public.modulus());
        assert!(public.rerandomize(&invalid, &mut NoDraw).is_none());
    }

    #[test]
    fn public_key_parse_rejects_tampered_fields() {
        // n = 15, zeta = 16 is the reference key.
        let ok = |n: u64, zeta: u64| {
            PaillierPublicKey::from_key_blob(&encode_biguints(&[&u(n), &u(zeta)])).is_some()
        };
        assert!(ok(15, 16));
        assert!(ok(15, 224));
        // Even n, n = 1; zeta = 1, zeta = 0, zeta = n^2, zeta sharing a
        // factor with n.
        for (n, zeta) in [
            (14, 15),
            (1, 2),
            (15, 1),
            (15, 0),
            (15, 225),
            (15, 226),
            (15, 21),
        ] {
            assert!(!ok(n, zeta), "n={n} zeta={zeta}");
        }
    }

    #[test]
    fn private_key_parse_rejects_tampered_fields() {
        // n = 15, lambda = 4, u = 4 is the reference key.
        let ok = |n: u64, lambda: u64, uu: u64| {
            PaillierPrivateKey::from_key_blob(&encode_biguints(&[&u(n), &u(lambda), &u(uu)]))
                .is_some()
        };
        assert!(ok(15, 4, 4));
        for (n, lambda, uu) in [
            (14, 4, 4),  // even n
            (15, 3, 4),  // odd lambda
            (15, 0, 4),  // lambda = 0
            (15, 1, 4),  // lambda = 1
            (15, 16, 4), // lambda >= n
            (15, 6, 4),  // gcd(lambda, n) = 3
            (15, 14, 4), // even, coprime, but 2^(15*14) mod 225 != 1
            (15, 4, 0),  // u = 0
            (15, 4, 15), // u = n
            (15, 4, 5),  // gcd(u, n) = 5
        ] {
            assert!(!ok(n, lambda, uu), "n={n} lambda={lambda} u={uu}");
        }
    }

    #[test]
    fn wrappers_reject_out_of_range_ciphertexts() {
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, _) = Paillier::from_primes(&p, &q).expect("valid Paillier key");
        let invalid = public.modulus().mul(public.modulus());
        let mut drbg = CtrDrbgAes256::new(&[0x95; 48]);
        assert!(public.rerandomize(&invalid, &mut drbg).is_none());
        let valid = public
            .encrypt_with_nonce(&BigUint::from_u64(7), &BigUint::from_u64(2))
            .expect("valid nonce");
        assert!(public.add_ciphertexts(&valid, &invalid).is_none());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let p = BigUint::from_u64(3);
        let q = BigUint::from_u64(5);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid key");

        let public_blob = public.to_key_blob();
        let private_blob = private.to_key_blob();
        assert_eq!(
            PaillierPublicKey::from_key_blob(&public_blob),
            Some(public.clone())
        );
        assert_eq!(
            PaillierPrivateKey::from_key_blob(&private_blob),
            Some(private.clone())
        );

        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(
            PaillierPublicKey::from_pem(&public_pem),
            Some(public.clone())
        );
        assert_eq!(
            PaillierPrivateKey::from_pem(&private_pem),
            Some(private.clone())
        );
        assert_eq!(PaillierPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(PaillierPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn generated_key_serialization_roundtrip() {
        let mut key_rng = CtrDrbgAes256::new(&[0xb5; 48]);
        let mut enc_rng = CtrDrbgAes256::new(&[0xb6; 48]);
        let (public, private) =
            Paillier::generate(&mut key_rng, 32).expect("Paillier key generation");
        let message = [0x03];

        let public =
            PaillierPublicKey::from_key_blob(&public.to_key_blob()).expect("public binary");
        let private = PaillierPrivateKey::from_xml(&private.to_xml()).expect("private XML");
        let ciphertext = public
            .encrypt(&message, &mut enc_rng)
            .expect("message fits");
        assert_eq!(private.decrypt(&ciphertext), Some(message.to_vec()));
    }

    #[test]
    fn byte_ciphertext_roundtrip() {
        let mut drbg = CtrDrbgAes256::new(&[0x57; 48]);
        let p = BigUint::from_u64(257);
        let q = BigUint::from_u64(263);
        let (public, private) = Paillier::from_primes(&p, &q).expect("valid key");
        let ciphertext = public
            .encrypt_bytes(&[0x2a], &mut drbg)
            .expect("message fits");
        assert_eq!(private.decrypt_bytes(&ciphertext), Some(vec![0x2a]));
    }
}
