//! RSA public-key primitive (Rivest, Shamir, Adleman, 1978).
//!
//! This module exposes the core RSA trapdoor permutation directly: key
//! derivation from explicit primes plus modular exponentiation for
//! encrypt/decrypt. Standards-based message formatting lives in `rsa_pkcs1`,
//! and standard key containers live in `rsa_io`.

use core::fmt;

use crate::public_key::primes::{
    is_probable_prime_untrusted, random_nonzero_below, random_probable_prime,
};
use crate::Csprng;
use rump::modular::{mod_inverse, mod_pow, MontgomeryContext};
use rump::number_theory::{gcd, lcm};
use rump::BigUint;

/// Public key for the core RSA primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKey {
    e: BigUint,
    n: BigUint,
}

/// Private key for the core RSA primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct RsaPrivateKey {
    e: BigUint,
    d: BigUint,
    n: BigUint,
    p: BigUint,
    q: BigUint,
    d_p: BigUint,
    d_q: BigUint,
    q_inv: BigUint,
    p_ctx: MontgomeryContext,
    q_ctx: MontgomeryContext,
}

/// Namespace wrapper for the core RSA construction.
pub struct Rsa;

impl RsaPublicKey {
    #[must_use]
    pub(crate) fn from_components(e: BigUint, n: BigUint) -> Self {
        Self { e, n }
    }

    /// Return the public exponent.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.e
    }

    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Apply the raw public operation `m^e mod n`.
    ///
    /// This is textbook RSA's deterministic trapdoor permutation. It performs
    /// no padding or randomness, so equal messages produce equal ciphertexts;
    /// that lack of semantic security is exactly why OAEP exists on top of the
    /// raw arithmetic.
    ///
    /// In this crate's generated keys, `e` is `65_537` (`0x10001`), a sparse
    /// exponent with two set bits. That is why this operation is often much
    /// faster than private-key `decrypt_raw`.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> BigUint {
        mod_pow(message, &self.e, &self.n)
    }
}

impl RsaPrivateKey {
    /// Return the public exponent paired with this private key.
    #[must_use]
    pub(crate) fn public_exponent(&self) -> &BigUint {
        &self.e
    }

    /// Return the private exponent.
    #[must_use]
    pub fn exponent(&self) -> &BigUint {
        &self.d
    }

    /// Replace the private exponent with another representative of the same
    /// residue class modulo `lambda(n)`.
    ///
    /// The parsers use this to keep a key's `d` exactly as it was serialized
    /// (PKCS #1 permits any `d` with `e * d ≡ 1 (mod lambda(n))`, and keys
    /// generated with `d = e^-1 mod phi(n)` are common) so that a parse /
    /// re-encode round trip is byte-exact. The CRT exponents are congruent
    /// for every such `d`, so the cached values stay valid. The caller must
    /// have checked the congruence.
    pub(crate) fn with_exponent(mut self, d: BigUint) -> Self {
        self.d = d;
        self
    }

    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Return the first prime factor.
    #[must_use]
    pub(crate) fn prime1(&self) -> &BigUint {
        &self.p
    }

    /// Return the second prime factor.
    #[must_use]
    pub(crate) fn prime2(&self) -> &BigUint {
        &self.q
    }

    /// Return the CRT exponent `d mod (p - 1)`.
    #[must_use]
    pub(crate) fn crt_exponent1(&self) -> &BigUint {
        &self.d_p
    }

    /// Return the CRT exponent `d mod (q - 1)`.
    #[must_use]
    pub(crate) fn crt_exponent2(&self) -> &BigUint {
        &self.d_q
    }

    /// Return the CRT coefficient `q^-1 mod p`.
    #[must_use]
    pub(crate) fn crt_coefficient(&self) -> &BigUint {
        &self.q_inv
    }

    /// Apply the raw private operation with CRT recombination.
    ///
    /// This path is intentionally heavier than `encrypt_raw`: it uses large
    /// private exponents (`dP`, `dQ`) and two CRT exponentiations to recover
    /// throughput. Even with CRT, public encrypt is usually faster because the
    /// public exponent is sparse.
    ///
    /// This operation is **unblinded**: the variable-time bigint stack sees
    /// the raw ciphertext, so an adversary who can time many decryptions of
    /// chosen ciphertexts learns information correlated with the private
    /// CRT state. Prefer [`Self::decrypt_raw_blinded`] whenever a CSPRNG is
    /// available.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> BigUint {
        // RSA-CRT:
        // m1 = c^dP mod p
        // m2 = c^dQ mod q
        // h  = (qInv * (m1 - m2)) mod p
        // m  = m2 + h*q
        let c_mod_p = ciphertext.rem(&self.p);
        let c_mod_q = ciphertext.rem(&self.q);
        let m1 = self.p_ctx.pow(&c_mod_p, &self.d_p);
        let m2 = self.q_ctx.pow(&c_mod_q, &self.d_q);

        // CRT recombination: h = (m1 - m2) mod p.
        // m2 is reduced mod q but NOT mod p, so m2 can be ≥ p.
        // Reduce m2 mod p first so that the conditional subtraction stays in
        // [0, p) and `m1 + p - m2_mod_p` is always non-negative.
        let m2_mod_p = m2.rem(&self.p);
        let delta = if m1 >= m2_mod_p {
            m1.sub(&m2_mod_p)
        } else {
            m1.add(&self.p).sub(&m2_mod_p)
        };
        // Reuse the cached Montgomery context for `p` instead of the standalone
        // `BigUint::mod_mul`, which would rebuild `R mod p` / `R^2 mod p` via two
        // full-width divisions on every private operation.
        let h = self.p_ctx.mul(&self.q_inv, &delta);
        let m = m2.add(&self.q.mul(&h));

        // Bellcore / Boneh–DeMillo–Lipton fault check. A transient fault in
        // either CRT half (m1 or m2) yields an `m` with `m^e != c (mod n)`, and
        // releasing such a value lets an attacker recover a prime factor from
        // `gcd(m^e - c, n)`. Verifying `m^e == c (mod n)` costs one extra
        // public exponentiation — negligible for the usual near-2^16 exponent,
        // but up to ~modulus-width work for a key built with a large custom `e`.
        // On mismatch we fall back to the non-CRT exponentiation `c^d mod n`,
        // which is fault-isolated (it never exposes p or q individually) and
        // total, so a detected fault degrades to a correct-but-slower result
        // rather than a key-leaking one.
        //
        // Scope: this guards the CRT exponentiation only. A fault in the
        // `decrypt_raw_blinded` mask/unmask `mod_mul`s is not covered here and
        // does not need to be — such a fault has no single-prime `gcd`
        // structure and so does not leak a factor.
        let c_mod_n = ciphertext.rem(&self.n);
        if mod_pow(&m, &self.e, &self.n) == c_mod_n {
            m
        } else {
            mod_pow(&c_mod_n, &self.d, &self.n)
        }
    }

    /// Apply the raw private operation with multiplicative (base) blinding.
    ///
    /// Draws a fresh blinding factor `r`, computes
    /// `m = (c · r^e)^d · r^{-1} mod n`, so the CRT exponentiation never
    /// operates on the attacker-chosen ciphertext directly. This decorrelates
    /// the timing of the variable-time bigint stack from the ciphertext;
    /// the classic countermeasure to remote timing attacks on RSA
    /// (Brumley–Boneh 2003, after Kocher 1996).
    ///
    /// Base blinding hides the ciphertext, not the exponent: `dP`, `dQ` and,
    /// on the fault-check fallback, `d` still drive rump's variable-time
    /// exponentiation, whose sequence of squarings and multiplications is
    /// the exponent's window pattern. An adversary who observes that
    /// pattern (a co-resident process reading the cache or branch
    /// predictor, a probe on the power rail) learns the private exponent
    /// whether or not the base was blinded. This is ciphertext blinding,
    /// not a constant-time exponentiation.
    #[must_use]
    pub fn decrypt_raw_blinded<R: Csprng>(&self, ciphertext: &BigUint, rng: &mut R) -> BigUint {
        loop {
            let Some(r) = random_nonzero_below(rng, &self.n) else {
                // Only reachable for degenerate moduli (n <= 1), which the
                // constructors never produce; for a valid key the sampler
                // always succeeds.
                continue;
            };
            // gcd(r, n) != 1 would mean r shares a factor with n — for a
            // well-formed key this has probability ~ 1/p + 1/q; retry.
            let Some(r_inv) = mod_inverse(&r, &self.n) else {
                continue;
            };
            let r_e = mod_pow(&r, &self.e, &self.n);
            let blinded = BigUint::mod_mul(ciphertext, &r_e, &self.n);
            let m_blinded = self.decrypt_raw(&blinded);
            return BigUint::mod_mul(&m_blinded, &r_inv, &self.n);
        }
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaPrivateKey(<redacted>)")
    }
}

/// Largest public exponent the FIPS 186-4 generators accept: B.3.3 step 2
/// requires an odd `e` with `2^16 < e < 2^256`.
const FIPS_MAX_EXPONENT_BITS: usize = 256;

/// FIPS 186-4 B.3.1 criteria 2(b) and 2(c): a prime factor of an `nlen`-bit
/// modulus lies in `[⌈√2 · 2^(nlen/2 − 1)⌉, 2^(nlen/2) − 1]`. The sampler
/// fixes the top bit of an `nlen/2`-bit candidate, which is the upper bound;
/// the lower bound is decided exactly through its square, `p² ≥ 2^(nlen − 1)`,
/// that is, `p²` has at least `nlen` bits. No square root is taken.
fn fips_prime_in_range(prime: &BigUint, nlen: usize) -> bool {
    prime.square().bits() >= nlen
}

/// FIPS 186-4 B.3.1 criterion 2(d): `|p − q| > 2^(nlen/2 − 100)`. Below
/// `nlen = 202` the right-hand side is a fraction below one, so any two
/// distinct primes satisfy it; the toy sizes the tests use fall there.
fn fips_primes_far_apart(p: &BigUint, q: &BigUint, nlen: usize) -> bool {
    if p == q {
        return false;
    }
    let half = nlen / 2;
    if half <= 100 {
        return true;
    }
    let difference = if p > q { p.sub(q) } else { q.sub(p) };
    let mut bound = BigUint::one();
    bound.shl_bits(half - 100);
    difference > bound
}

/// FIPS 186-4 B.3.1 criterion 3(a): `d > 2^(nlen/2)`. The other half of
/// 3(a), `d < lcm(p − 1, q − 1)`, and 3(b), `e·d ≡ 1`, hold by construction
/// because `d` is the inverse of `e` modulo that lcm.
fn fips_private_exponent_large(d: &BigUint, nlen: usize) -> bool {
    let mut bound = BigUint::one();
    bound.shl_bits(nlen / 2);
    d > &bound
}

impl Rsa {
    /// Derive a raw RSA key pair from explicit primes and an explicit exponent.
    ///
    /// Returns `None` if the inputs are equal, composite, the exponent is not
    /// greater than one, or the exponent is not invertible modulo
    /// `lambda = lcm(p - 1, q - 1)`.
    #[must_use]
    pub fn from_primes_with_exponent(
        p: &BigUint,
        q: &BigUint,
        exponent: &BigUint,
    ) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        if p == q || !is_probable_prime_untrusted(p) || !is_probable_prime_untrusted(q) {
            return None;
        }
        Self::from_checked_primes(p, q, exponent)
    }

    /// Build the key pair from primes the caller has already tested. Every
    /// public constructor runs the hardened primality test exactly once per
    /// prime and then comes here.
    fn from_checked_primes(
        p: &BigUint,
        q: &BigUint,
        exponent: &BigUint,
    ) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        // RFC 8017 §3.1: the public exponent is an integer between 3 and
        // n − 1 with gcd(e, λ(n)) = 1.
        let n = p.mul(q);
        if exponent < &BigUint::from_u64(3) || exponent >= &n {
            return None;
        }

        let p_minus_one = p.sub(&BigUint::one());
        let q_minus_one = q.sub(&BigUint::one());
        let lambda = lcm(&p_minus_one, &q_minus_one);
        if gcd(exponent, &lambda) != BigUint::one() {
            return None;
        }

        let d = mod_inverse(exponent, &lambda)?;
        let d_p = d.rem(&p_minus_one);
        let d_q = d.rem(&q_minus_one);
        let q_inv = mod_inverse(q, p)?;
        let p_ctx = MontgomeryContext::new(p).ok()?;
        let q_ctx = MontgomeryContext::new(q).ok()?;

        Some((
            RsaPublicKey {
                e: exponent.clone(),
                n: n.clone(),
            },
            RsaPrivateKey {
                e: exponent.clone(),
                d,
                n,
                p: p.clone(),
                q: q.clone(),
                d_p,
                d_q,
                q_inv,
                p_ctx,
                q_ctx,
            },
        ))
    }

    /// Derive a raw RSA key pair from explicit primes using the crate's
    /// default exponent search.
    ///
    /// The search tries `e = 2^k + 1` for `k = 16, 17, …`, starting at
    /// `65_537`, the standard sparse public exponent (prime, two set bits, so
    /// the public operation stays cheap, and inside FIPS 186-5's
    /// `2^16 < e < 2^256`). It takes the first candidate coprime to
    /// `lambda = lcm(p - 1, q - 1)`, but only while the candidate is below
    /// `n`: RFC 8017 §3.1 requires `3 ≤ e < n`.
    ///
    /// Returns `None` when no candidate below `n` qualifies, which is always
    /// the case for toy moduli `n ≤ 65_537`; use
    /// [`Self::from_primes_with_exponent`] with a small exponent there.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        if p == q || !is_probable_prime_untrusted(p) || !is_probable_prime_untrusted(q) {
            return None;
        }

        let n = p.mul(q);
        let p_minus_one = p.sub(&BigUint::one());
        let q_minus_one = q.sub(&BigUint::one());
        let lambda = lcm(&p_minus_one, &q_minus_one);

        let mut exponent_bit = 16usize;
        loop {
            let mut exponent = BigUint::zero();
            exponent.set_bit(exponent_bit);
            exponent = exponent.add(&BigUint::one());
            if exponent >= n {
                return None;
            }
            if gcd(&exponent, &lambda) == BigUint::one() {
                return Self::from_checked_primes(p, q, &exponent);
            }
            exponent_bit += 1;
        }
    }

    /// Generate an RSA key pair from a CSPRNG and explicit public exponent,
    /// by the process of FIPS 186-4 B.3.3 (random probable primes) under the
    /// key-pair criteria of B.3.1.
    ///
    /// `bits` is `nlen`, the bit length of the modulus; it must be even and
    /// at least 32. B.3.3 step 1 admits only `nlen ∈ {2048, 3072}`; that
    /// restriction is not applied, so that smaller keys can be generated for
    /// experiments, but every other criterion is applied at every size:
    ///
    /// - B.3.3 step 2 / B.3.1 1(b): `e` is odd and `2^16 < e < 2^256`; `e`
    ///   is fixed before the primes are drawn (1(a)).
    /// - B.3.1 2(a): `gcd(p − 1, e) = gcd(q − 1, e) = 1`; a prime that fails
    ///   is redrawn (B.3.3 steps 4.5 and 5.6), the exponent is never changed.
    /// - B.3.1 2(b), 2(c): `⌈√2 · 2^(nlen/2 − 1)⌉ ≤ p, q ≤ 2^(nlen/2) − 1`,
    ///   which is what makes `n = p·q` exactly `nlen` bits long.
    /// - B.3.1 2(d): `|p − q| > 2^(nlen/2 − 100)`; below `nlen = 202` the
    ///   bound is fractional and the criterion reduces to `p ≠ q`.
    /// - B.3.1 3(a): `d = e⁻¹ mod lcm(p − 1, q − 1)` exceeds `2^(nlen/2)`;
    ///   otherwise both primes are redrawn, as the last paragraph of B.3.1
    ///   directs.
    ///
    /// Each prime candidate comes from `rump`'s prime sampler and is then
    /// screened with the hash-hardened Miller–Rabin test in `primes`, so this
    /// remains the crate's built-in reference key-generation path rather
    /// than a substitute for a hardened PKI stack.
    #[must_use]
    pub fn generate_with_exponent<R: Csprng>(
        rng: &mut R,
        bits: usize,
        exponent: &BigUint,
    ) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        // Below 32 total bits, the split primes become so small that the key
        // space is trivially enumerable. `nlen` must be even because both
        // primes are `nlen/2` bits long (B.3.1: len(p) = len(q) = nlen/2).
        if bits < 32 || !bits.is_multiple_of(2) {
            return None;
        }
        // B.3.3 step 2. The candidates' lower bound puts n ≥ 2^(nlen − 1), so
        // an exponent below that is also below n (RFC 8017 §3.1); without
        // that check an oversized exponent would loop forever.
        if !exponent.is_odd()
            || exponent.bits() <= 16
            || exponent.bits() > FIPS_MAX_EXPONENT_BITS
            || exponent.bits() >= bits
        {
            return None;
        }

        let half = bits / 2;
        let one = BigUint::one();
        loop {
            // B.3.3 step 4: draw p until it is in range, coprime to e
            // through p − 1, and probably prime.
            let p = loop {
                let candidate = random_probable_prime(rng, half)?;
                if fips_prime_in_range(&candidate, bits)
                    && gcd(&candidate.sub(&one), exponent) == one
                {
                    break candidate;
                }
            };
            // B.3.3 step 5: the same for q, plus the distance from p.
            let q = loop {
                let candidate = random_probable_prime(rng, half)?;
                if fips_primes_far_apart(&p, &candidate, bits)
                    && fips_prime_in_range(&candidate, bits)
                    && gcd(&candidate.sub(&one), exponent) == one
                {
                    break candidate;
                }
            };
            if let Some(keypair) = Self::from_primes_with_exponent(&p, &q, exponent) {
                if fips_private_exponent_large(keypair.1.exponent(), bits) {
                    return Some(keypair);
                }
            }
        }
    }

    /// Generate an RSA key pair with the public exponent `65_537` (F4), the
    /// standard sparse choice, by the FIPS 186-4 B.3.3 process described on
    /// [`Self::generate_with_exponent`].
    #[must_use]
    pub fn generate<R: Csprng>(rng: &mut R, bits: usize) -> Option<(RsaPublicKey, RsaPrivateKey)> {
        Self::generate_with_exponent(rng, bits, &BigUint::from_u64(65_537))
    }
}

#[cfg(test)]
mod tests {
    use super::{Rsa, RsaPrivateKey, RsaPublicKey};
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    /// The textbook key: p = 61, q = 53, n = 3233, e = 17, d = 413.
    fn textbook_key(p: &BigUint, q: &BigUint) -> (RsaPublicKey, RsaPrivateKey) {
        Rsa::from_primes_with_exponent(p, q, &BigUint::from_u64(17)).expect("valid RSA key")
    }

    /// RFC 8017 §3.1 requires `3 ≤ e < n`. The default search starts at
    /// 65 537, so the textbook modulus 61·53 = 3233 has no admissible default
    /// exponent, and an explicit exponent at or above `n` is refused.
    #[test]
    fn default_search_refuses_exponents_at_or_above_the_modulus() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        assert!(Rsa::from_primes(&p, &q).is_none());
        assert!(Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(3_233)).is_none());
        assert!(Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(65_537)).is_none());
        assert!(Rsa::from_primes_with_exponent(&p, &q, &BigUint::one()).is_none());
        assert!(Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(2)).is_none());
        assert!(Rsa::from_primes_with_exponent(&p, &q, &BigUint::from_u64(17)).is_some());
    }

    /// Primes just above 2^20 give n ≈ 2^40, where the default search takes
    /// 65 537 whenever it is coprime to λ(n).
    #[test]
    fn default_search_takes_65537_when_it_fits() {
        let p = BigUint::from_u64(1_048_583);
        let q = BigUint::from_u64(1_048_589);
        let (public, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");
        assert_eq!(public.exponent(), &BigUint::from_u64(65_537));
        let message = BigUint::from_u64(123_456_789);
        assert_eq!(private.decrypt_raw(&public.encrypt_raw(&message)), message);
    }

    #[test]
    fn generate_refuses_an_exponent_that_cannot_fit_below_n() {
        let mut drbg = CtrDrbgAes256::new(&[0x66u8; 48]);
        let mut huge = BigUint::zero();
        huge.set_bit(40);
        let huge = huge.add(&BigUint::one());
        assert!(Rsa::generate_with_exponent(&mut drbg, 40, &huge).is_none());
    }

    #[test]
    fn roundtrip_small_messages() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = textbook_key(&p, &q);

        for msg in [0u64, 1, 2, 65, 123, 3_232] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message);
            let plaintext = private.decrypt_raw(&ciphertext);
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = textbook_key(&p, &q);
        let message = BigUint::from_u64(65);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(ciphertext, BigUint::from_u64(2_790));
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    #[test]
    fn blinded_decrypt_matches_unblinded() {
        let seed = [0x21u8; 48];
        let mut rng = crate::CtrDrbgAes256::new(&seed);
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = textbook_key(&p, &q);

        for msg in [0u64, 1, 2, 65, 123, 3_232] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message);
            assert_eq!(
                private.decrypt_raw_blinded(&ciphertext, &mut rng),
                private.decrypt_raw(&ciphertext)
            );
        }
    }

    #[test]
    fn raw_rsa_is_multiplicatively_homomorphic() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = textbook_key(&p, &q);
        let left = BigUint::from_u64(12);
        let right = BigUint::from_u64(17);

        let left_cipher = public.encrypt_raw(&left);
        let right_cipher = public.encrypt_raw(&right);
        let combined_cipher = BigUint::mod_mul(&left_cipher, &right_cipher, public.modulus());
        let decrypted = private.decrypt_raw(&combined_cipher);
        let expected = BigUint::mod_mul(&left, &right, public.modulus());

        assert_eq!(decrypted, expected);
    }

    #[test]
    fn explicit_exponent_matches_classic_example() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let exponent = BigUint::from_u64(17);
        let (public, private) =
            Rsa::from_primes_with_exponent(&p, &q, &exponent).expect("valid RSA key");
        assert_eq!(public.exponent(), &BigUint::from_u64(17));
        assert_eq!(private.exponent(), &BigUint::from_u64(413));
    }

    #[test]
    fn rejects_non_invertible_exponent() {
        let p = BigUint::from_u64(11);
        let q = BigUint::from_u64(13);
        let exponent = BigUint::from_u64(3);
        assert!(Rsa::from_primes_with_exponent(&p, &q, &exponent).is_none());
    }

    /// FIPS 186-4 B.3.1 2(b)/(c) put both primes at or above
    /// `√2 · 2^(nlen/2 − 1)`, so the modulus is exactly `nlen` bits: 64 here,
    /// never 63. At this size 2(d) reduces to `p ≠ q`.
    #[test]
    fn generate_keypair_roundtrip() {
        let seed = [0x55u8; 48];
        let mut drbg = CtrDrbgAes256::new(&seed);
        let (public, private) = Rsa::generate(&mut drbg, 64).expect("generated RSA key");
        assert_eq!(public.modulus().bits(), 64);
        assert_eq!(public.exponent(), &BigUint::from_u64(65_537));
        let message = BigUint::from_u64(42);
        let ciphertext = public.encrypt_raw(&message);
        assert_eq!(private.decrypt_raw(&ciphertext), message);
    }

    /// Forty 512-bit keys, every one exactly 512 bits, with FIPS 186-4 B.3.1
    /// 2(b)–(d) and 3(a) holding on each: `p² ≥ 2^511`, `q² ≥ 2^511`,
    /// `|p − q| > 2^156`, `d > 2^256`.
    #[test]
    fn generated_keys_have_exactly_the_requested_modulus_length() {
        let mut drbg = CtrDrbgAes256::new(&[0x5au8; 48]);
        let mut distance_bound = BigUint::one();
        distance_bound.shl_bits(256 - 100);
        let mut exponent_bound = BigUint::one();
        exponent_bound.shl_bits(256);
        for _ in 0..40 {
            let (public, private) = Rsa::generate(&mut drbg, 512).expect("generated RSA key");
            assert_eq!(public.modulus().bits(), 512);
            let (p, q) = (private.prime1(), private.prime2());
            assert_eq!(p.bits(), 256);
            assert_eq!(q.bits(), 256);
            assert!(p.square().bits() >= 512);
            assert!(q.square().bits() >= 512);
            let difference = if p > q { p.sub(q) } else { q.sub(p) };
            assert!(difference > distance_bound);
            assert!(private.exponent() > &exponent_bound);
        }
    }

    /// B.3.1 requires `len(p) = len(q) = nlen/2`, so `nlen` is even; B.3.3
    /// step 2 requires an odd `e` with `2^16 < e < 2^256`.
    #[test]
    fn generate_refuses_odd_sizes_and_exponents_outside_fips_range() {
        let mut drbg = CtrDrbgAes256::new(&[0x5bu8; 48]);
        assert!(Rsa::generate(&mut drbg, 63).is_none());
        assert!(Rsa::generate(&mut drbg, 30).is_none());
        let e = BigUint::from_u64;
        assert!(Rsa::generate_with_exponent(&mut drbg, 64, &e(3)).is_none());
        assert!(Rsa::generate_with_exponent(&mut drbg, 64, &e(65_535)).is_none());
        assert!(Rsa::generate_with_exponent(&mut drbg, 64, &e(65_536)).is_none());
        assert!(Rsa::generate_with_exponent(&mut drbg, 64, &e(65_538)).is_none());
        let mut too_large = BigUint::one();
        too_large.shl_bits(256);
        too_large = too_large.add(&BigUint::one());
        assert!(Rsa::generate_with_exponent(&mut drbg, 1024, &too_large).is_none());
        let (public, _) =
            Rsa::generate_with_exponent(&mut drbg, 64, &e(65_539)).expect("odd e > 2^16");
        assert_eq!(public.exponent(), &e(65_539));
        assert_eq!(public.modulus().bits(), 64);
    }
}
