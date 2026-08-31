//! Prime generation and hardened primality testing for the public-key layer.
//!
//! The deterministic number theory (gcd, lcm, jacobi, modular exponentiation
//! and inversion, fixed-base Miller-Rabin) lives in the [`rump`]
//! multiprecision crate; callers use `rump::modular` and
//! `rump::number_theory` directly. This module holds only what rump cannot:
//! cryptographic policy — the SHAKE256-hardened primality test for untrusted
//! candidates and the discrete-log group construction helpers — plus the
//! samplers, which bridge this crate's [`Csprng`] generators to
//! [`rump::random::RandomSource`] (a bridge rump cannot own and a blanket
//! impl the orphan rule forbids here).
//!
//! A smaller `u128`-bounded Miller-Rabin helper also exists in
//! `crate::cprng::primes`; the duplication is intentional because the
//! arithmetic types and intended use-cases differ.

use crate::Csprng;
use rump::modular::mod_pow;
use rump::number_theory::is_probable_prime;
use rump::BigUint;

/// Number of candidate-derived pseudorandom Miller-Rabin rounds added by
/// [`is_probable_prime_untrusted`] on top of the fixed bases.
///
/// Each round independently catches a composite with probability ≥ 3/4
/// (Rabin), so forging a value that survives all of them requires grinding on
/// the order of `4^64 = 2^128` candidates — infeasible.
const HARDENED_HASH_ROUNDS: usize = 64;

/// Hardened Miller-Rabin for candidates from an untrusted source.
///
/// Runs the fixed small-prime bases plus [`HARDENED_HASH_ROUNDS`] additional
/// witnesses derived by hashing the candidate itself. Because those witnesses
/// are an unpredictable function of `n`, an adversary cannot construct a
/// composite that is a strong pseudoprime to a base set they can choose in
/// advance (the Arnault-style attack on fixed bases).
#[must_use]
pub fn is_probable_prime_untrusted(candidate: &BigUint) -> bool {
    if !is_probable_prime(candidate) {
        return false;
    }
    // Candidates small enough for the trial-division sieve are already
    // decided exactly; they also sit below the range the witness derivation
    // assumes (its map into [2, n-2] needs n > 4).
    if candidate.bits() <= 10 {
        return true;
    }

    hash_derived_bases(candidate, HARDENED_HASH_ROUNDS)
        .iter()
        .all(|witness| !rump::number_theory::miller_rabin_witness(candidate, witness))
}

/// Derive `count` Miller-Rabin witnesses in `[2, n-2]` as a SHAKE256 PRF of the
/// candidate, so the witness schedule cannot be predicted before `n` is fixed.
fn hash_derived_bases(candidate: &BigUint, count: usize) -> Vec<BigUint> {
    if count == 0 {
        return Vec::new();
    }
    use crate::hash::Xof;
    let n_bytes = candidate.to_be_bytes();
    // The caller screens out sieve-sized candidates, so `n - 3 >= 2` and the
    // map `2 + (h mod (n-3))` lands in [2, n-2].
    let n_minus_three = candidate.sub(&BigUint::from_u64(3));
    let two = BigUint::from_u64(2);

    let mut xof = crate::hash::sha3::Shake256::new();
    xof.update(b"cryptography-rs/miller-rabin-witness/v1");
    xof.update(&n_bytes);

    // Draw a few extra bytes beyond the candidate width so the modular
    // reduction into [0, n-3) has negligible bias.
    let mut buf = vec![0u8; n_bytes.len() + 16];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        xof.squeeze(&mut buf);
        let h = BigUint::from_be_bytes(&buf);
        out.push(two.add(&h.rem(&n_minus_three)));
    }
    out
}

/// Adapter presenting any [`Csprng`] as a [`rump::random::RandomSource`].
///
/// The trait shapes are identical; the adapter exists because a blanket
/// implementation of the foreign trait is not ours to write.
struct CsprngSource<'a, R: Csprng>(&'a mut R);

impl<R: Csprng> rump::random::RandomSource for CsprngSource<'_, R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

/// Draw a random integer in `[0, upper_exclusive)`.
#[must_use]
pub fn random_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    rump::random::random_below(&mut CsprngSource(rng), upper_exclusive)
}

/// Draw a random integer in `[1, upper_exclusive)`.
#[must_use]
pub fn random_nonzero_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    rump::random::random_nonzero_below(&mut CsprngSource(rng), upper_exclusive)
}

/// Draw a random integer in `[1, upper_exclusive)` that is coprime to `coprime_to`.
///
/// This is the nonce sampler used by schemes such as Paillier that need a
/// fresh random unit modulo `n`.
#[must_use]
pub fn random_coprime_below<R: Csprng>(
    rng: &mut R,
    upper_exclusive: &BigUint,
    coprime_to: &BigUint,
) -> Option<BigUint> {
    rump::random::random_coprime_below(&mut CsprngSource(rng), upper_exclusive, coprime_to)
}

/// Draw a probable prime with the requested bit length.
#[must_use]
pub fn random_probable_prime<R: Csprng>(rng: &mut R, bits: usize) -> Option<BigUint> {
    rump::random::random_probable_prime(&mut CsprngSource(rng), bits)
}

pub(crate) fn random_even_with_bits<R: Csprng>(rng: &mut R, bits: usize) -> Option<BigUint> {
    if bits < 2 {
        return None;
    }

    let mut bytes = vec![0u8; bits.div_ceil(8)];
    let top_bit = (bits - 1) % 8;
    let excess_bits = bytes.len() * 8 - bits;
    let top_mask = 0xff_u8 >> excess_bits;
    loop {
        rng.fill_bytes(&mut bytes);
        bytes[0] &= top_mask;
        bytes[0] |= 1u8 << top_bit;
        let last = bytes.len() - 1;
        // The cofactor is kept even so `p - 1 = kq` has the usual DSA-style
        // factorization with an explicit factor of two. In particular, an
        // odd cofactor of 1 would collapse the subgroup construction into the
        // full group, which is not the structure these finite-field schemes
        // are trying to generate.
        bytes[last] &= !1;
        let candidate = BigUint::from_be_bytes(&bytes);
        // The resulting cofactor is public, but clearing the temporary random
        // buffer keeps the helper's hygiene consistent with the rest of the
        // prime-generation code.
        crate::ct::zeroize_slice(bytes.as_mut_slice());
        if !candidate.is_zero() {
            return Some(candidate);
        }
    }
}

pub(crate) fn find_subgroup_generator<R: Csprng>(
    rng: &mut R,
    prime: &BigUint,
    cofactor: &BigUint,
) -> Option<BigUint> {
    let one = BigUint::one();
    let upper = prime.sub(&one);
    loop {
        let candidate = random_nonzero_below(rng, &upper)
            .expect("prime > 2 leaves a non-zero subgroup-generator search range");
        // Raising a random unit to the cofactor projects it into the order-`q`
        // subgroup because `(candidate^cofactor)^q = candidate^(p - 1) = 1`.
        // The only bad case is landing on the identity.
        let generator = mod_pow(&candidate, cofactor, prime);
        if generator != one {
            return Some(generator);
        }
    }
}

pub(crate) fn generate_prime_order_group<R: Csprng>(
    rng: &mut R,
    bits: usize,
) -> Option<(BigUint, BigUint, BigUint, BigUint)> {
    // With the current split, the subgroup order is at least 16 bits. We
    // therefore need at least 3 bits left for the even
    // cofactor `k` in `p = kq + 1`; otherwise `k` collapses to a fixed
    // tiny value and the requested bit length can never be reached.
    if bits < 19 {
        return None;
    }

    let subgroup_bits = (bits / 4).clamp(16, 256);
    let cofactor_bits = bits.saturating_sub(subgroup_bits);
    if cofactor_bits < 3 {
        return None;
    }
    let one = BigUint::one();
    loop {
        let q = random_probable_prime(rng, subgroup_bits)?;
        let mut attempts = 0usize;
        while attempts < 256 {
            let cofactor = random_even_with_bits(rng, cofactor_bits)?;
            let prime = cofactor.mul(&q).add(&one);
            if prime.bits() != bits || !is_probable_prime(&prime) {
                attempts += 1;
                continue;
            }

            let generator = find_subgroup_generator(rng, &prime, &cofactor)?;
            return Some((prime, q, cofactor, generator));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_probable_prime_untrusted, random_nonzero_below};
    use crate::Csprng;
    use rump::number_theory::is_probable_prime;
    use rump::BigUint;

    #[test]
    fn untrusted_hardening_rejects_pseudoprime_that_fools_fixed_bases() {
        // A014233(12) = 318665857834031151167461 is the smallest strong
        // pseudoprime to the first twelve prime bases {2,3,…,37} — exactly this
        // crate's fixed MR_BASES. The fixed-base test is therefore fooled into
        // accepting it, while the candidate-derived hardened witnesses reject
        // it. (Its prime factors exceed the trial-division sieve, so it reaches
        // the Miller-Rabin stage.)
        let ten18 = BigUint::from_u64(1_000_000_000_000_000_000);
        let spsp = BigUint::from_u64(318_665)
            .mul(&ten18)
            .add(&BigUint::from_u64(857_834_031_151_167_461));

        assert!(
            is_probable_prime(&spsp),
            "fixed-base test is expected to be fooled by A014233(12)"
        );
        assert!(
            !is_probable_prime_untrusted(&spsp),
            "hardened test must reject the pseudoprime"
        );
    }

    #[test]
    fn untrusted_still_accepts_primes_and_rejects_composites() {
        assert!(is_probable_prime_untrusted(&BigUint::from_u64(65_537)));
        assert!(is_probable_prime_untrusted(&BigUint::from_u64(
            2_147_483_647
        ))); // Mersenne prime
        assert!(!is_probable_prime_untrusted(&BigUint::from_u64(561))); // Carmichael
        assert!(!is_probable_prime_untrusted(&BigUint::from_u64(
            1_000_003 * 3
        ))); // composite
    }

    struct ZeroRng;

    impl Csprng for ZeroRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.fill(0);
        }
    }

    #[test]
    fn random_nonzero_below_rejects_unit_bound() {
        let mut rng = ZeroRng;
        assert_eq!(random_nonzero_below(&mut rng, &BigUint::one()), None);
    }
}
