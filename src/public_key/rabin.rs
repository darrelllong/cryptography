//! Rabin public-key primitive (Michael O. Rabin, 1979).
//!
//! This mirrors the companion Python code rather than the pure square map:
//! encryption prepends a fixed CRC tag and adds `n / 2` before squaring so the
//! decryptor can distinguish the intended square root among the four CRT roots.

use core::fmt;

use crate::public_key::bigint::{BigUint, MontgomeryCtx};
use crate::public_key::primes::{is_probable_prime, mod_inverse, mod_pow};

const TAG: u32 = 0x7c6d_6a7f;

/// Public key for the raw Rabin primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RabinPublicKey {
    n: BigUint,
}

/// Private key for the raw Rabin primitive.
#[derive(Clone, Eq, PartialEq)]
pub struct RabinPrivateKey {
    p: BigUint,
    q: BigUint,
}

/// Namespace wrapper for the raw Rabin construction.
pub struct Rabin;

impl RabinPublicKey {
    /// Return the modulus `n = p * q`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// Encrypt the raw integer message using the tagged Python variant.
    ///
    /// Returns `None` if the tagged payload would not fit below `n`, since the
    /// matching decryption logic only recovers payloads in that range.
    #[must_use]
    pub fn encrypt_raw(&self, message: &BigUint) -> Option<BigUint> {
        let payload = tagged_payload(message, &self.n)?;
        Some(mod_pow(&payload, &BigUint::from_u64(2), &self.n))
    }
}

impl RabinPrivateKey {
    /// Return the first Rabin prime.
    #[must_use]
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    /// Return the second Rabin prime.
    #[must_use]
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    /// Decrypt the raw Rabin ciphertext and recover the tagged message, if any
    /// of the four square roots carries the embedded CRC tag.
    #[must_use]
    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> Option<BigUint> {
        let n = self.p.mul_ref(&self.q);
        let half = half_modulus(&n);
        let tag_modulus = BigUint::from_u64(1u64 << 32);

        let p_exponent = self
            .p
            .add_ref(&BigUint::one())
            .div_rem(&BigUint::from_u64(4))
            .0;
        let q_exponent = self
            .q
            .add_ref(&BigUint::one())
            .div_rem(&BigUint::from_u64(4))
            .0;
        let m_p = mod_pow(ciphertext, &p_exponent, &self.p);
        let m_q = mod_pow(ciphertext, &q_exponent, &self.q);

        let p_coeff = mod_inverse(&self.p, &self.q)?;
        let q_coeff = mod_inverse(&self.q, &self.p)?;
        let (term_p, term_q) = if let Some(ctx) = MontgomeryCtx::new(&n) {
            (
                ctx.mul(&ctx.mul(&p_coeff, &self.p), &m_q),
                ctx.mul(&ctx.mul(&q_coeff, &self.q), &m_p),
            )
        } else {
            (
                BigUint::mod_mul(&BigUint::mod_mul(&p_coeff, &self.p, &n), &m_q, &n),
                BigUint::mod_mul(&BigUint::mod_mul(&q_coeff, &self.q, &n), &m_p, &n),
            )
        };

        let x = term_p.add_ref(&term_q).modulo(&n);
        let y = sub_mod(&term_p, &term_q, &n);

        for root in [x.clone(), neg_mod(&x, &n), y.clone(), neg_mod(&y, &n)] {
            if root < half {
                continue;
            }

            let candidate = root.sub_ref(&half);
            if candidate.rem_u64(1u64 << 32) != u64::from(TAG) {
                continue;
            }

            let (message, remainder) = candidate.div_rem(&tag_modulus);
            debug_assert_eq!(remainder, BigUint::from_u64(u64::from(TAG)));
            return Some(message);
        }

        None
    }
}

impl fmt::Debug for RabinPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RabinPrivateKey(<redacted>)")
    }
}

impl Rabin {
    /// Derive a raw Rabin key pair from explicit Rabin primes.
    ///
    /// Returns `None` unless `p` and `q` are distinct primes congruent to `3`
    /// modulo `4`, which is the condition that makes the square-root shortcut
    /// `(c^((p + 1) / 4) mod p)` valid during decryption.
    #[must_use]
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Option<(RabinPublicKey, RabinPrivateKey)> {
        if p == q || !is_probable_prime(p) || !is_probable_prime(q) {
            return None;
        }
        if p.rem_u64(4) != 3 || q.rem_u64(4) != 3 {
            return None;
        }

        Some((
            RabinPublicKey { n: p.mul_ref(q) },
            RabinPrivateKey {
                p: p.clone(),
                q: q.clone(),
            },
        ))
    }
}

fn tagged_payload(message: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let half = half_modulus(modulus);
    let tag_modulus = BigUint::from_u64(1u64 << 32);
    let tag = BigUint::from_u64(u64::from(TAG));
    let payload = message.mul_ref(&tag_modulus).add_ref(&tag).add_ref(&half);
    if &payload >= modulus {
        None
    } else {
        Some(payload)
    }
}

fn half_modulus(modulus: &BigUint) -> BigUint {
    modulus.div_rem(&BigUint::from_u64(2)).0
}

fn neg_mod(value: &BigUint, modulus: &BigUint) -> BigUint {
    if value.is_zero() {
        BigUint::zero()
    } else {
        modulus.sub_ref(value)
    }
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs.sub_ref(rhs)
    } else {
        modulus.sub_ref(&rhs.sub_ref(lhs))
    }
}

#[cfg(test)]
mod tests {
    use super::Rabin;
    use crate::public_key::bigint::BigUint;

    fn reference_primes() -> (BigUint, BigUint) {
        (BigUint::from_u64(131_071), BigUint::from_u64(131_111))
    }

    #[test]
    fn derive_reference_key() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        assert_eq!(public.modulus(), &BigUint::from_u128(17_184_849_881));
        assert_eq!(private.p(), &BigUint::from_u64(131_071));
        assert_eq!(private.q(), &BigUint::from_u64(131_111));
    }

    #[test]
    fn roundtrip_small_messages() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");

        for msg in [0u64, 1] {
            let message = BigUint::from_u64(msg);
            let ciphertext = public.encrypt_raw(&message).expect("message fits");
            let plaintext = private
                .decrypt_raw(&ciphertext)
                .expect("tagged root exists");
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn exact_small_ciphertext_matches_reference() {
        let (p, q) = reference_primes();
        let (public, private) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        let message = BigUint::from_u64(1);
        let ciphertext = public.encrypt_raw(&message).expect("message fits");
        assert_eq!(ciphertext, BigUint::from_u64(7_234_315_345));
        assert_eq!(private.decrypt_raw(&ciphertext), Some(message));
    }

    #[test]
    fn rejects_message_that_does_not_fit_tagged_payload() {
        let (p, q) = reference_primes();
        let (public, _) = Rabin::from_primes(&p, &q).expect("valid Rabin key");
        assert!(public.encrypt_raw(&BigUint::from_u64(2)).is_none());
    }

    #[test]
    fn rejects_invalid_primes() {
        let p = BigUint::from_u64(13);
        let q = BigUint::from_u64(19);
        assert!(Rabin::from_primes(&p, &q).is_none());

        let p = BigUint::from_u64(131_071);
        let composite = BigUint::from_u64(21);
        assert!(Rabin::from_primes(&p, &composite).is_none());
    }
}
