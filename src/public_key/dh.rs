//! Classical Diffie-Hellman (DH) key agreement over a prime-order subgroup.
//!
//! The arithmetic is the finite-field Diffie-Hellman primitive of NIST
//! SP 800-56A Rev. 3 (`pubs/sp800-56a-r3.pdf`, §5.7.1.1), over the structure
//! DSA also uses: a prime modulus `p`, a prime subgroup order `q` dividing
//! `p − 1`, and a generator `g` of the order-`q` subgroup of `Z_p*`. This
//! module provides that primitive, its domain parameters, and the validation
//! around them — not the key-agreement schemes of SP 800-56A §6 (no
//! key-derivation function, no key confirmation).
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
//! Alice: z = y_B^{x_A} mod p
//! Bob:   z = y_A^{x_B} mod p
//! (both equal g^{x_A · x_B} mod p)
//! ```
//!
//! [`DhPrivateKey::agree_element`] returns `z` as an integer. SP 800-56A
//! turns `z` into the shared secret `Z` with the integer-to-byte-string
//! conversion of its Appendix C.1, whose output is always as long as `p` is
//! in bytes; `BigUint::to_be_bytes` drops leading zero bytes and is not that
//! conversion. Both parties must then apply the same KDF before using the
//! result as a key.
//!
//! ## Parameter generation
//!
//! [`Dh::generate_params`] generates what SP 800-56A §5.5.1.1 calls FIPS
//! 186-type domain parameters, the way that section requires: `p` and `q` by
//! FIPS 186-4 Appendix A.1.1.2 and `g` by A.2.3 with `index = 2` (A.2.3's own
//! example value for key establishment). The parameters keep their seed
//! record ([`FfcSeed`](crate::public_key::primes::FfcSeed)) so that anyone can
//! validate them by A.1.1.3 and A.2.4
//! ([`DhParams::with_seed`]). SP 800-56A approves FIPS 186-type parameters for
//! key agreement only at its parameter-size sets FB (`L = 2048`, `N = 224`)
//! and FC (`L = 2048`, `N = 256`), so the generator refuses the other two FIPS
//! 186-4 pairs. The same section says such parameters "should only be used
//! for backward compatibility", and requires an approved safe-prime group
//! (its Appendix D) when more than 112 bits of security are wanted; those
//! groups are not implemented in this crate.
//!
//! [`Dh::generate_toy_params`] makes small groups for tests and follows
//! neither standard. Parameters of either kind can be shared among many key
//! pairs (unlike RSA moduli, which are per-key).
//!
//! ## Key generation
//!
//! [`Dh::generate`] draws `x` uniformly from `[1, q − 1]`: for FIPS 186-type
//! parameters, the distribution of SP 800-56A §5.6.1.1.4 (key-pair generation
//! by testing candidates) with `N = len(q)`.
//!
//! ## Key validation
//!
//! A [`DhParams`] can only be built by [`Dh::generate_params`],
//! [`Dh::generate_toy_params`], [`DhParams::new`], [`DhParams::with_seed`], or
//! the parsers. Explicit parameters get the hardened domain validation (`p`
//! and `q` probable prime under the SHAKE256-hardened test, `q | p − 1`, `g`
//! in the order-`q` subgroup — for `g`, FIPS 186-4 A.2.2's partial
//! validation); parameters with a seed record must also pass A.1.1.3 and
//! A.2.4, which show they were generated as the record says. That is the
//! parse-time policy of the [`public_key`](crate::public_key) module for a
//! group this crate will generate secrets over, so [`Dh::generate`] never
//! sees a degenerate group.
//!
//! Every group, standard or not, must also meet the size policy of
//! `validate_prime_order_group`: `q ≥ 2^15` and `p` of at most 16384 bits
//! ([`MIN_SUBGROUP_ORDER_BITS`], [`MAX_MODULUS_BITS`],
//! [`MAX_SUBGROUP_ORDER_BITS`]), checked before any arithmetic so that a
//! parser cannot be made to run a hardened primality test on an arbitrarily
//! wide modulus.
//!
//! [`DhPrivateKey::agree_element`] verifies that the peer's public key `y`
//! lies in the correct subgroup (`1 < y < p` and `y^q ≡ 1 mod p`) before
//! computing the shared secret, and the public-key parsers and
//! [`DhPublicKey::from_public_component`] check the same membership. That is
//! SP 800-56A §5.6.2.3.1's full public-key validation (its bound `y ≤ p − 2`
//! follows, since `p − 1` has order 2 and `q` is odd). It then refuses
//! `z ≤ 1` and `z = p − 1`, as §5.7.1.1 step 2 requires; with a peer key in
//! the odd-order subgroup neither value can occur, and the check stands as
//! the standard writes it. Skipping the subgroup check enables
//! small-subgroup attacks.
//!
//! ## Timing
//!
//! The modular exponentiation is rump's, which is variable-time: the number
//! of multiplications in `y_peer^x mod p` follows the bit length and Hamming
//! weight of the exponent, and the multiplications themselves take operand-
//! dependent paths. A peer who chooses the base `y_peer` and times
//! [`DhPrivateKey::agree_element`] therefore observes a function of the
//! static secret `x` — the quantity the timing leaks is `x` itself, through
//! the exponentiation's dependence on it. Nothing here is safe against an
//! adversary who can time the holder of a static key.
//!
//! [`MIN_SUBGROUP_ORDER_BITS`]: crate::public_key::primes::MIN_SUBGROUP_ORDER_BITS
//! [`MAX_MODULUS_BITS`]: crate::public_key::primes::MAX_MODULUS_BITS
//! [`MAX_SUBGROUP_ORDER_BITS`]: crate::public_key::primes::MAX_SUBGROUP_ORDER_BITS
//!
//! ## Key encodings
//!
//! The crate-defined `to_key_blob`, `to_pem` and `to_xml` forms remain the
//! defaults. The standard encodings sit beside them:
//! [`DhPublicKey::to_spki_der`] (RFC 3279 §2.3.3 `SubjectPublicKeyInfo` under
//! `dhpublicnumber`, PEM label `PUBLIC KEY`) and [`DhParams::to_der`] (its
//! X9.42 `DomainParameters`, with `ValidationParms` carrying a FIPS 186-4
//! seed and counter). [`DhPrivateKey::to_pkcs8_der`] writes an RFC 5958
//! `OneAsymmetricKey`, but no published standard defines a Diffie-Hellman
//! private key inside one: that encoding follows the convention OpenSSL
//! writes and reads.

use core::fmt;

use crate::public_key::primes::{
    impl_ffc_params, is_in_prime_order_subgroup, random_nonzero_below, validate_prime_order_group,
    FfcDomain, FfcHash, FfcParameterSize, PrimalityPolicy,
};
use crate::Csprng;
use rump::modular::{mod_pow, MontgomeryContext};
use rump::BigUint;

const DH_PARAMS_LABEL: &str = "CRYPTOGRAPHY DH PARAMETERS";
const DH_PUBLIC_LABEL: &str = "CRYPTOGRAPHY DH PUBLIC KEY";
const DH_PRIVATE_LABEL: &str = "CRYPTOGRAPHY DH PRIVATE KEY";

/// The FIPS 186-4 A.2.3 `index` of the generators [`Dh::generate_params`]
/// derives: the value A.2.3 gives as its example for key establishment.
const KEY_ESTABLISHMENT_INDEX: u8 = 2;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Shared Diffie-Hellman domain parameters `(p, q, g {, seed record})`.
///
/// A single set of parameters can be used by many key pairs. Every instance
/// has been validated as the module docs describe, which is why the fields
/// are private. Parameters from [`Dh::generate_params`] or
/// [`DhParams::with_seed`] carry the FIPS 186-4 seed record a third party
/// needs to validate them ([`DhParams::seed`]); others carry none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhParams {
    domain: FfcDomain,
}

/// Public key for DH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhPublicKey {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    /// Public component `y = g^x mod p`.
    y: BigUint,
    /// Cached Montgomery context for arithmetic modulo `p`.
    p_ctx: Option<MontgomeryContext>,
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
    /// Cached Montgomery context for arithmetic modulo `p`.
    p_ctx: Option<MontgomeryContext>,
}

/// Namespace wrapper for the Diffie-Hellman construction.
pub struct Dh;

// ─── DhParams ─────────────────────────────────────────────────────────────────

impl_ffc_params!(DhParams, DH_PARAMS_LABEL, "DhParams", "Diffie-Hellman");
crate::public_key::ffc_pkix::impl_ffc_parameters_der!(
    DhParams,
    Dh,
    "Encode as the RFC 3279 §2.3.3 (X9.42) `DomainParameters` in DER: `p`, \
     `g`, `q` in that order, no `j`, and, when the parameters carry a FIPS \
     186-4 seed record, `ValidationParms` holding its `domain_parameter_seed` \
     as `seed` and its `counter` as `pgenCounter`.",
    "Decode `DomainParameters` in strict DER, validating the group as \
     [`Self::new`] does. A present `j` must satisfy `p = jq + 1`. \
     `ValidationParms` has no field for the hash function or the A.2.3 \
     `index` that FIPS 186-4 A.1.1.3 and A.2.4 need, so it is checked for \
     shape only and the result carries no seed record."
);

// ─── DhPublicKey ──────────────────────────────────────────────────────────────

impl DhPublicKey {
    /// The prime modulus `p`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// The prime subgroup order `q` (a divisor of `p − 1`).
    #[must_use]
    pub fn subgroup_order(&self) -> &BigUint {
        &self.q
    }

    /// The generator `g` of the order-`q` subgroup of `Z_p*`.
    #[must_use]
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// The public component `y = g^x mod p`.
    #[must_use]
    pub fn public_component(&self) -> &BigUint {
        &self.y
    }

    /// A peer's public key from validated domain parameters and its public
    /// component `y`.
    ///
    /// `y` must lie in the order-`q` subgroup: `1 < y < p` and
    /// `y^q ≡ 1 (mod p)`, the FFC full public-key validation of SP 800-56A
    /// Rev. 3 §5.6.2.3.1. Returns `None` otherwise. The group itself was
    /// validated when `params` was built, so nothing about it is recomputed.
    #[must_use]
    pub fn from_public_component(params: &DhParams, y: BigUint) -> Option<Self> {
        let (p, q, g) = (
            params.modulus(),
            params.subgroup_order(),
            params.generator(),
        );
        if !is_in_prime_order_subgroup(&y, q, p) {
            return None;
        }
        Some(Self {
            p: p.clone(),
            q: q.clone(),
            g: g.clone(),
            y,
            p_ctx: MontgomeryContext::new(p).ok(),
        })
    }

    /// Extract the domain parameters `(p, q, g)` as a standalone [`DhParams`],
    /// suitable for generating further key pairs in the same group.
    ///
    /// A parsed public key has had only the structural (fixed-base) checks,
    /// but a `DhParams` is a group this crate will generate secrets over, so
    /// this runs the hardened validation of [`DhParams::new`] and returns
    /// `None` if the peer's parameters do not survive it. Keys store no seed
    /// record, so the parameters returned have none.
    #[must_use]
    pub fn params(&self) -> Option<DhParams> {
        DhParams::new(self.p.clone(), self.q.clone(), self.g.clone())
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.p.clone(),
            self.q.clone(),
            self.g.clone(),
            self.y.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// Structural validation: the size policy, fixed-base primality of `p`
    /// and `q`, the subgroup relations for `g`, and `y` in the order-`q`
    /// subgroup (`1 < y < p`, `y^q ≡ 1 (mod p)`).
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let y = fields.next()?;
        if !validate_prime_order_group(&p, &q, &g, PrimalityPolicy::Structural)
            || !is_in_prime_order_subgroup(&y, &q, &p)
        {
            return None;
        }
        let p_ctx = MontgomeryContext::new(&p).ok();
        Some(Self { p, q, g, y, p_ctx })
    }
}

crate::public_key::io::impl_xml_serialization!(DhPublicKey, "DhPublicKey", ["p", "q", "g", "y"]);
crate::public_key::io::impl_blob_pem_serialization!(
    DhPublicKey,
    DH_PUBLIC_LABEL,
    ["p", "q", "g", "y"]
);

// ─── DhPrivateKey ─────────────────────────────────────────────────────────────

impl DhPrivateKey {
    /// The prime modulus `p`.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// The prime subgroup order `q` (a divisor of `p − 1`).
    #[must_use]
    pub fn subgroup_order(&self) -> &BigUint {
        &self.q
    }

    /// The generator `g` of the order-`q` subgroup of `Z_p*`.
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
            p_ctx: self.p_ctx.clone(),
        }
    }

    /// Extract the domain parameters `(p, q, g)` as a standalone [`DhParams`],
    /// suitable for generating further key pairs in the same group.
    ///
    /// A private key's group has already passed the hardened validation (at
    /// generation or at parse time), so no further check is needed. Keys store
    /// no seed record, so the parameters returned have none.
    #[must_use]
    pub fn params(&self) -> DhParams {
        DhParams::from_domain(FfcDomain::from_validated_parts(
            self.p.clone(),
            self.q.clone(),
            self.g.clone(),
        ))
    }

    /// Compute the shared group element with a peer's public key: the FFC DH
    /// primitive of SP 800-56A Rev. 3 §5.7.1.1.
    ///
    /// Returns `z = y_peer^x mod p`, or `None` if the peer key uses different
    /// domain parameters, fails subgroup validation, or gives `z ≤ 1` or
    /// `z = p − 1` (§5.7.1.1 step 2). Every group here has an odd `q`, so a
    /// peer key in the subgroup yields neither value; the check is kept as
    /// the standard states it.
    ///
    /// **Subgroup validation**: checks that `1 < y_peer < p` and that
    /// `y_peer^q ≡ 1 mod p` (§5.6.2.3.1), rejecting low-order and
    /// small-subgroup inputs.
    #[must_use]
    pub fn agree_element(&self, peer: &DhPublicKey) -> Option<BigUint> {
        // Domain parameters must match.
        if peer.p != self.p || peer.q != self.q || peer.g != self.g {
            return None;
        }
        // Subgroup validation: reject trivial and low-order values.
        if !is_in_prime_order_subgroup(&peer.y, &self.q, &self.p) {
            return None;
        }
        let z = match &self.p_ctx {
            Some(ctx) => ctx.pow(&peer.y, &self.x),
            None => mod_pow(&peer.y, &self.x, &self.p),
        };
        if z <= BigUint::one() || z == self.p.sub(&BigUint::one()) {
            return None;
        }
        Some(z)
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Schema fields for the crate-defined serialization formats.
    fn serial_fields(&self) -> Vec<BigUint> {
        vec![
            self.p.clone(),
            self.q.clone(),
            self.g.clone(),
            self.x.clone(),
        ]
    }

    /// Validate schema fields and rebuild the key with its derived state.
    ///
    /// Full validation: the size policy, hardened primality of `p` and `q`,
    /// the subgroup relations for `g`, `x ∈ [1, q)`, and `y` recomputed from
    /// `x`.
    fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let x = fields.next()?;
        if !validate_prime_order_group(&p, &q, &g, PrimalityPolicy::Hardened)
            || x.is_zero()
            || x >= q
        {
            return None;
        }
        Some(Dh::key_pair(&p, &q, &g, x).1)
    }
}

crate::public_key::io::impl_xml_serialization!(DhPrivateKey, "DhPrivateKey", ["p", "q", "g", "x"]);
crate::public_key::io::impl_blob_pem_serialization!(
    DhPrivateKey,
    DH_PRIVATE_LABEL,
    ["p", "q", "g", "x"]
);
crate::public_key::ffc_pkix::impl_ffc_key_encodings!(
    DhPublicKey,
    DhPrivateKey,
    Dh,
    "RFC 3279 §2.3.3, `dhpublicnumber` with the X9.42 `DomainParameters` \
     (`p`, `g`, `q`) and the `DHPublicKey` `INTEGER` `y`",
    "No published standard defines a Diffie-Hellman private key in this \
     container; this follows the convention OpenSSL writes and reads: \
     `dhpublicnumber` with `DomainParameters`, and `x` as an `INTEGER` \
     `privateKey`, as RFC 5958 §2 gives for DSA."
);

impl fmt::Debug for DhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DhPrivateKey(<redacted>)")
    }
}

// ─── Dh namespace ─────────────────────────────────────────────────────────────

impl Dh {
    /// Generate FIPS 186-type domain parameters for key agreement (SP 800-56A
    /// Rev. 3 §5.5.1.1): `p` and `q` by FIPS 186-4 A.1.1.2 with `hash` and an
    /// `N`-bit seed drawn from `rng`, then `g` by A.2.3 with index 2. The
    /// parameters carry their seed record, so any FIPS 186-4 validator —
    /// [`DhParams::with_seed`] among them — can check them.
    ///
    /// Returns `None` unless `size` is one of SP 800-56A's FIPS 186-type
    /// parameter-size sets, FB ([`FfcParameterSize::L2048N224`]) or FC
    /// ([`FfcParameterSize::L2048N256`]), and `hash` is at least `N` bits long
    /// (FIPS 186-4 A.1.1.2) — SHA-224 or longer for FB, SHA-256 or longer for
    /// FC.
    ///
    /// # Panics
    ///
    /// Panics on a source that stalls, as the primality test's base sampler
    /// ([`random_below`](crate::public_key::primes::random_below)) does after
    /// 256 consecutive rejected draws.
    #[must_use]
    pub fn generate_params<R: Csprng>(
        rng: &mut R,
        size: FfcParameterSize,
        hash: FfcHash,
    ) -> Option<DhParams> {
        if !matches!(
            size,
            FfcParameterSize::L2048N224 | FfcParameterSize::L2048N256
        ) {
            return None;
        }
        FfcDomain::generate_fips186_4(rng, size, hash, KEY_ESTABLISHMENT_INDEX)
            .map(DhParams::from_domain)
    }

    /// Generate a small group for tests. **This is not FIPS 186-4 or
    /// SP 800-56A**: neither defines these sizes, and the construction follows
    /// no standard.
    ///
    /// Accepts `bits` from 19 to 1023 and returns `None` otherwise, so every
    /// size a standard covers goes through [`Dh::generate_params`]. The
    /// subgroup order has `clamp(⌊bits/4⌋, 16, 256)` bits, `p = kq + 1` for a
    /// random even `k`, and `g = h^k mod p` for a random `h`. No seed is kept:
    /// the parameters can be checked for structure, not for how they were made.
    ///
    /// # Panics
    ///
    /// Panics on a stalled or constant source, as the prime and cofactor
    /// samplers do (see
    /// [`random_probable_prime`](crate::public_key::primes::random_probable_prime)).
    #[must_use]
    pub fn generate_toy_params<R: Csprng>(rng: &mut R, bits: usize) -> Option<DhParams> {
        FfcDomain::generate_toy(rng, bits).map(DhParams::from_domain)
    }

    /// Generate a DH key pair from existing domain parameters.
    ///
    /// `x` is uniform on `[1, q − 1]`: for FIPS 186-type parameters, the
    /// distribution of SP 800-56A §5.6.1.1.4 with `N = len(q)`.
    ///
    /// # Panics
    ///
    /// Panics on a source that stalls, as [`random_nonzero_below`] does
    /// after 256 consecutive rejected draws.
    #[must_use]
    pub fn generate<R: Csprng>(params: &DhParams, rng: &mut R) -> (DhPublicKey, DhPrivateKey) {
        let (p, q, g) = (
            params.modulus(),
            params.subgroup_order(),
            params.generator(),
        );
        // Every `DhParams` has passed domain validation, so `q` is a prime of
        // at least 2^15 and the range `[1, q)` is never empty.
        let x = random_nonzero_below(rng, q)
            .expect("validated DH parameters have a prime subgroup order q >= 2^15");
        Self::key_pair(p, q, g, x)
    }

    /// Derive a DH key pair from explicit subgroup parameters and secret
    /// exponent: the parameters go through [`DhParams::new`] — a group this
    /// crate agrees over with the caller's secret gets the hardened
    /// validation — and the key pair through [`Dh::with_secret_exponent`].
    #[must_use]
    pub fn from_secret_exponent(
        prime: &BigUint,
        subgroup_order: &BigUint,
        generator: &BigUint,
        secret: &BigUint,
    ) -> Option<(DhPublicKey, DhPrivateKey)> {
        let params = DhParams::new(prime.clone(), subgroup_order.clone(), generator.clone())?;
        Self::with_secret_exponent(&params, secret)
    }

    /// Derive a DH key pair from validated domain parameters and the secret
    /// exponent `x`. Returns `None` unless `x ∈ [1, q − 1]`, the range SP
    /// 800-56A Rev. 3 §5.6.1.1.1 gives a static or ephemeral private key;
    /// `y = g^x mod p` is computed here.
    #[must_use]
    pub fn with_secret_exponent(
        params: &DhParams,
        secret: &BigUint,
    ) -> Option<(DhPublicKey, DhPrivateKey)> {
        let (p, q, g) = (
            params.modulus(),
            params.subgroup_order(),
            params.generator(),
        );
        if secret.is_zero() || secret >= q {
            return None;
        }
        Some(Self::key_pair(p, q, g, secret.clone()))
    }

    /// The key pair of the secret `x ∈ [1, q)` over a validated group, with
    /// its cached Montgomery context.
    fn key_pair(p: &BigUint, q: &BigUint, g: &BigUint, x: BigUint) -> (DhPublicKey, DhPrivateKey) {
        let p_ctx = MontgomeryContext::new(p).ok();
        let y = match &p_ctx {
            Some(ctx) => ctx.pow(g, &x),
            None => mod_pow(g, &x, p),
        };
        (
            DhPublicKey {
                p: p.clone(),
                q: q.clone(),
                g: g.clone(),
                y: y.clone(),
                p_ctx: p_ctx.clone(),
            },
            DhPrivateKey {
                p: p.clone(),
                q: q.clone(),
                g: g.clone(),
                x,
                y,
                p_ctx,
            },
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{Dh, DhParams, DhPrivateKey, DhPublicKey};
    use crate::public_key::io::{decode_biguints, encode_biguints};
    use crate::public_key::primes::{cavp, FfcHash, FfcParameterSize};
    use crate::CtrDrbgAes256;
    use rump::modular::MontgomeryContext;
    use rump::BigUint;

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0x33; 48])
    }

    fn u(value: u64) -> BigUint {
        BigUint::from_u64(value)
    }

    /// The smallest group the size policy admits with `p = 2q + 1`: `q =
    /// 32771` (the least prime at or above `2^15`), `p = 65543`, and `g = 4`,
    /// a quadratic residue other than `1`, so of order `q`. The same group
    /// serves the DSA tests.
    const P: u64 = 65543;
    const Q: u64 = 32771;
    const G: u64 = 4;

    fn toy_params() -> DhParams {
        DhParams::new(u(P), u(Q), u(G)).expect("toy group is a valid prime-order subgroup")
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
    fn agreement_generated_toy_params() {
        let mut rng = rng();
        let params = Dh::generate_toy_params(&mut rng, 512).expect("params");
        assert_eq!(params.modulus().bits(), 512);
        assert_eq!(params.seed(), None);
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
        assert_eq!(private.to_public_key(), public);
    }

    #[test]
    fn params_accessors_and_extraction() {
        let params = toy_params();
        assert_eq!(params.modulus(), &u(P));
        assert_eq!(params.subgroup_order(), &u(Q));
        assert_eq!(params.generator(), &u(G));
        assert_eq!(params.seed(), None);

        let mut rng = rng();
        let (public, private) = Dh::generate(&params, &mut rng);
        assert_eq!(private.params(), params);
        assert_eq!(public.params(), Some(params));
    }

    /// `x = 3` gives `y = 4^3 = 64`; agreement between `x = 3` and `x = 5` is
    /// `4^15 mod 65543`, the same from either side.
    #[test]
    fn explicit_exponents_agree() {
        let (pub_a, priv_a) = Dh::from_secret_exponent(&u(P), &u(Q), &u(G), &u(3)).expect("x = 3");
        assert_eq!(pub_a.public_component(), &u(64));
        let params = toy_params();
        let (pub_b, priv_b) = Dh::with_secret_exponent(&params, &u(5)).expect("x = 5");
        let expected = rump::modular::mod_pow(&u(G), &u(15), &u(P));
        assert_eq!(priv_a.agree_element(&pub_b), Some(expected.clone()));
        assert_eq!(priv_b.agree_element(&pub_a), Some(expected));
        assert!(Dh::with_secret_exponent(&params, &BigUint::zero()).is_none());
        assert!(Dh::with_secret_exponent(&params, &u(Q)).is_none());
        assert!(Dh::from_secret_exponent(&u(23), &u(11), &u(4), &u(3)).is_none());
    }

    #[test]
    fn from_public_component_applies_full_public_key_validation() {
        let params = toy_params();
        let (public, _) = Dh::with_secret_exponent(&params, &u(3)).expect("x = 3");
        assert_eq!(
            DhPublicKey::from_public_component(&params, u(64)),
            Some(public)
        );
        // The identity, zero, p, p − 1 (order 2), and the quadratic
        // non-residues 5 and q, all outside the subgroup.
        for y in [1, 0, P, P - 1, 5, Q] {
            assert!(
                DhPublicKey::from_public_component(&params, u(y)).is_none(),
                "y = {y}"
            );
        }
    }

    /// The order-2 subgroup `{1, 22}` of `Z_23*` (`q = 2`, `g = 22`) is
    /// refused by the size policy. Built directly, behind the constructors,
    /// its only key (`x = 1`, `y = 22`) passes the subgroup check and agrees
    /// to `z = 22 = p − 1`, which SP 800-56A §5.7.1.1 step 2 refuses.
    #[test]
    fn q_equals_two_is_refused_and_z_equals_p_minus_one_would_be_too() {
        assert!(DhParams::new(u(23), u(2), u(22)).is_none());
        let p_ctx = MontgomeryContext::new(&u(23)).ok();
        let private = DhPrivateKey {
            p: u(23),
            q: u(2),
            g: u(22),
            x: u(1),
            y: u(22),
            p_ctx: p_ctx.clone(),
        };
        let public = DhPublicKey {
            p: u(23),
            q: u(2),
            g: u(22),
            y: u(22),
            p_ctx,
        };
        assert_eq!(private.agree_element(&public), None);
    }

    // ── Parameter generation ─────────────────────────────────────────────────

    #[test]
    fn generate_params_refuses_what_the_standards_refuse() {
        let mut rng = rng();
        // FIPS 186-4 pairs outside SP 800-56A's parameter-size sets FB and FC.
        for size in [FfcParameterSize::L1024N160, FfcParameterSize::L3072N256] {
            assert!(Dh::generate_params(&mut rng, size, FfcHash::Sha256).is_none());
        }
        // A hash shorter than N (FIPS 186-4 A.1.1.2).
        assert!(
            Dh::generate_params(&mut rng, FfcParameterSize::L2048N256, FfcHash::Sha224).is_none()
        );
    }

    #[test]
    fn toy_params_refuse_sizes_a_standard_covers_or_that_cannot_be_built() {
        let mut rng = rng();
        for bits in [0, 15, 18, 1024, 2048, 3072] {
            assert!(
                Dh::generate_toy_params(&mut rng, bits).is_none(),
                "{bits} bits"
            );
        }
    }

    #[test]
    #[ignore = "FIPS 186-4 generation at 2048 bits is slow in debug; run with --release --ignored"]
    fn generated_fb_and_fc_params_validate_serialize_and_agree() {
        let mut rng = rng();
        for (size, hash) in [
            (FfcParameterSize::L2048N224, FfcHash::Sha224),
            (FfcParameterSize::L2048N256, FfcHash::Sha256),
        ] {
            let params = Dh::generate_params(&mut rng, size, hash).expect("FB and FC are approved");
            assert_eq!(params.modulus().bits(), size.l());
            assert_eq!(params.subgroup_order().bits(), size.n());
            let seed = params
                .seed()
                .expect("generated parameters carry a seed")
                .clone();
            assert_eq!(seed.index(), 2);
            let validated = DhParams::with_seed(
                params.modulus().clone(),
                params.subgroup_order().clone(),
                params.generator().clone(),
                seed,
            );
            assert_eq!(validated.as_ref(), Some(&params));
            assert_eq!(
                DhParams::from_key_blob(&params.to_key_blob()).as_ref(),
                Some(&params)
            );
            let (pub_a, priv_a) = Dh::generate(&params, &mut rng);
            let (pub_b, priv_b) = Dh::generate(&params, &mut rng);
            let shared = priv_a.agree_element(&pub_b).expect("agree A");
            assert_eq!(priv_b.agree_element(&pub_a), Some(shared));
        }
    }

    #[test]
    fn seeded_params_round_trip_and_old_blobs_still_parse() {
        let (p, q, g, seed) = cavp::fips186_4_1024_parts(2);
        let params = DhParams::with_seed(p.clone(), q.clone(), g.clone(), seed.clone())
            .expect("CAVP parameters validate");
        assert_eq!(params.seed(), Some(&seed));
        assert_eq!(
            DhParams::from_key_blob(&params.to_key_blob()),
            Some(params.clone())
        );
        let pem = params.to_pem();
        assert!(pem.contains("DH PARAMETERS"));
        assert_eq!(DhParams::from_pem(&pem), Some(params.clone()));
        let xml = params.to_xml();
        assert!(xml.contains("<counter>"));
        assert_eq!(DhParams::from_xml(&xml), Some(params.clone()));

        // A three-field blob, the only form earlier versions wrote, still
        // parses; it has no seed record.
        let old = DhParams::from_key_blob(&encode_biguints(&[&p, &q, &g])).expect("seedless blob");
        assert_eq!(old.seed(), None);
        assert_eq!(DhParams::new(p.clone(), q.clone(), g.clone()), Some(old));

        // The seed record is checked, not trusted.
        let fields = decode_biguints(&params.to_key_blob()).expect("DER");
        assert_eq!(fields.len(), 8);
        let parse_with = |position: usize, value: BigUint| {
            let mut tampered = fields.clone();
            tampered[position] = value;
            let refs: Vec<&BigUint> = tampered.iter().collect();
            DhParams::from_key_blob(&encode_biguints(&refs))
        };
        // index 1 names another generator; the next counter, another p.
        assert!(parse_with(7, u(1)).is_none());
        assert!(parse_with(6, fields[6].add(&u(1))).is_none());
        // The index-1 generator does not pass under the index-2 record.
        let index_1_generator = cavp::fips186_4_1024_parts(1).2;
        assert!(DhParams::with_seed(p, q, index_1_generator, seed).is_none());
        for count in [4, 5, 6, 7] {
            let refs: Vec<&BigUint> = fields[..count].iter().collect();
            assert!(
                DhParams::from_key_blob(&encode_biguints(&refs)).is_none(),
                "{count} fields"
            );
        }
        let mut nine: Vec<&BigUint> = fields.iter().collect();
        let zero = u(0);
        nine.push(&zero);
        assert!(DhParams::from_key_blob(&encode_biguints(&nine)).is_none());
    }

    // ── Domain validation at construction ────────────────────────────────────

    #[test]
    fn new_rejects_degenerate_groups() {
        // q = 1 and p = 0: below the size policy and no group at all.
        assert!(DhParams::new(u(P), BigUint::one(), u(G)).is_none());
        assert!(DhParams::new(BigUint::zero(), u(Q), u(G)).is_none());
        // Composite p (65545 = 5 · 13109), composite q (32769 = 3 · 10923),
        // a prime q (32779) that does not divide p - 1, a generator outside
        // the order-q subgroup (5, a quadratic non-residue), g = 1, g = p.
        assert!(DhParams::new(u(65545), u(Q), u(G)).is_none());
        assert!(DhParams::new(u(P), u(32769), u(G)).is_none());
        assert!(DhParams::new(u(P), u(32779), u(G)).is_none());
        assert!(DhParams::new(u(P), u(Q), u(5)).is_none());
        assert!(DhParams::new(u(P), u(Q), BigUint::one()).is_none());
        assert!(DhParams::new(u(P), u(Q), u(P)).is_none());
        // Valid prime-order subgroups below the size policy: q = 11 and
        // q = 2 in Z_23*.
        assert!(DhParams::new(u(23), u(11), u(4)).is_none());
        assert!(DhParams::new(u(23), u(2), u(22)).is_none());
    }

    // ── Domain parameter mismatch ─────────────────────────────────────────────

    #[test]
    fn mismatched_params_rejected() {
        let p1 = toy_params();
        // Same group, another generator of the same subgroup: 9 = 3^2 is a
        // quadratic residue other than 1, so 9^q ≡ 1 (mod 65543).
        let p2 = DhParams::new(u(P), u(Q), u(9)).expect("9 generates the order-q subgroup");
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
        assert_eq!(recovered, public);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        let blob = private.to_key_blob();
        let recovered = DhPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered, private);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (public, _) = Dh::generate(&params, &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("DH PUBLIC KEY"));
        let recovered = DhPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered, public);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("DH PRIVATE KEY"));
        let recovered = DhPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered, private);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (public, _) = Dh::generate(&params, &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("DhPublicKey"));
        let recovered = DhPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered, public);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        let xml = private.to_xml();
        let recovered = DhPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered, private);
    }

    // ── Parse-time validation: every check has a tampered blob ───────────────

    #[test]
    fn params_parse_rejects_tampered_fields() {
        // Valid: p = 65543, q = 32771, g = 4.
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(G)])).is_some());
        // Composite p (fixed-base and hardened both reject 65545 = 5 · 13109).
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(65545), &u(Q), &u(G)])).is_none());
        // Composite q; q = 1; q >= p; q not dividing p - 1; q below 2^15.
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(32769), &u(G)])).is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(1), &u(G)])).is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(P), &u(G)])).is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(32779), &u(G)])).is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(23), &u(11), &u(4)])).is_none());
        // g outside the subgroup, g = 1, g = p.
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(5)])).is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(1)])).is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(P)])).is_none());
        // Wrong field count.
        assert!(DhParams::from_key_blob(&encode_biguints(&[&u(P), &u(Q)])).is_none());
    }

    #[test]
    fn public_key_parse_rejects_tampered_fields() {
        // y = 4^3 mod 65543 = 64 is in the order-q subgroup.
        let ok = encode_biguints(&[&u(P), &u(Q), &u(G), &u(64)]);
        assert!(DhPublicKey::from_key_blob(&ok).is_some());
        // y = 1 (identity), y = 0, y = p, y = p - 1 (order 2, outside the
        // odd-order subgroup), and the quadratic non-residues 5 and q.
        for y in [0u64, 1, P, P - 1, 5, Q] {
            let blob = encode_biguints(&[&u(P), &u(Q), &u(G), &u(y)]);
            assert!(DhPublicKey::from_key_blob(&blob).is_none(), "y = {y}");
        }
        // Group-level tampering is rejected on the public key too.
        assert!(
            DhPublicKey::from_key_blob(&encode_biguints(&[&u(65545), &u(Q), &u(G), &u(64)]))
                .is_none()
        );
        assert!(
            DhPublicKey::from_key_blob(&encode_biguints(&[&u(P), &u(32769), &u(G), &u(64)]))
                .is_none()
        );
        assert!(
            DhPublicKey::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(5), &u(64)])).is_none()
        );
        assert!(
            DhPublicKey::from_key_blob(&encode_biguints(&[&u(23), &u(11), &u(4), &u(18)]))
                .is_none()
        );
    }

    #[test]
    fn private_key_parse_rejects_tampered_fields() {
        let ok = encode_biguints(&[&u(P), &u(Q), &u(G), &u(3)]);
        let private = DhPrivateKey::from_key_blob(&ok).expect("valid private key");
        assert_eq!(private.to_public_key().public_component(), &u(64));
        // x = 0 and x = q are outside [1, q).
        assert!(
            DhPrivateKey::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(G), &u(0)])).is_none()
        );
        assert!(
            DhPrivateKey::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(G), &u(Q)])).is_none()
        );
        // Group-level tampering.
        assert!(
            DhPrivateKey::from_key_blob(&encode_biguints(&[&u(65545), &u(Q), &u(G), &u(3)]))
                .is_none()
        );
        assert!(
            DhPrivateKey::from_key_blob(&encode_biguints(&[&u(P), &u(Q), &u(5), &u(3)])).is_none()
        );
        assert!(
            DhPrivateKey::from_key_blob(&encode_biguints(&[&u(23), &u(11), &u(4), &u(3)]))
                .is_none()
        );
    }

    #[test]
    fn public_params_extraction_rejects_group_that_fails_hardened_check() {
        // A014233(12) = 318665857834031151167461 is a strong pseudoprime to
        // the twelve fixed bases, so the structural check accepts a public
        // key over it while the hardened check behind `params()` does not.
        // p − 1 = 2² · 3³ · 5 · 11 · 17 · 474349721 · 6652754837; take
        // q = 6652754837 (33 bits, within the size policy) and
        // g = 2^((p−1)/q) mod p, which satisfies g^q = 2^(p−1) ≡ 1 (mod p)
        // because p is a Fermat pseudoprime to base 2.
        let ten18 = u(1_000_000_000_000_000_000);
        let p = u(318_665).mul(&ten18).add(&u(857_834_031_151_167_461));
        let q = u(6_652_754_837);
        let g = u(213_207).mul(&ten18).add(&u(412_300_168_926_015_129));
        assert_eq!(rump::modular::mod_pow(&g, &q, &p), BigUint::one());
        let blob = encode_biguints(&[&p, &q, &g, &g]);
        let public = DhPublicKey::from_key_blob(&blob).expect("structural checks pass");
        assert!(public.params().is_none());
        assert!(DhParams::from_key_blob(&encode_biguints(&[&p, &q, &g])).is_none());
    }

    #[test]
    fn debug_private_key_redacted() {
        let params = toy_params();
        let mut rng = rng();
        let (_, private) = Dh::generate(&params, &mut rng);
        assert_eq!(format!("{private:?}"), "DhPrivateKey(<redacted>)");
    }
}
