//! Prime generation, primality testing, and finite-field domain parameters
//! for the public-key layer.
//!
//! The deterministic number theory (gcd, lcm, jacobi, modular exponentiation
//! and inversion, Miller-Rabin rounds, the strong Lucas test) lives in the
//! [`rump`] multiprecision crate; callers use `rump::modular` and
//! `rump::number_theory` directly. This module holds only what rump cannot:
//!
//! - cryptographic policy: the SHAKE256-hardened primality test for untrusted
//!   candidates, the choice parsers make between it and the fixed-base
//!   test, and the size bounds on a group modulus and subgroup order
//!   ([`MAX_MODULUS_BITS`], [`MIN_SUBGROUP_ORDER_BITS`],
//!   [`MAX_SUBGROUP_ORDER_BITS`]) that every parser checks before any
//!   arithmetic;
//! - finite-field (FFC) domain parameters: generation and validation as FIPS
//!   186-4 Appendix A specifies them and, kept apart, a generator of toy
//!   groups at sizes that standard does not define;
//! - the samplers, which bridge this crate's [`Csprng`] generators to
//!   [`rump::random::RandomSource`] (a bridge rump cannot own and a blanket
//!   impl the orphan rule forbids here).
//!
//! ## FIPS 186-4 domain parameters
//!
//! FIPS 186-4 (`pubs/fips186-4.pdf`) Appendix A defines the FFC domain
//! parameters `(p, q, g {, domain_parameter_seed, counter})` that DSA uses,
//! and that SP 800-56A finite-field key agreement uses too. The public entry
//! points are `Dsa::generate_params`, `Dh::generate_params`, and the
//! parameter types' `with_seed` constructors; the steps live here:
//!
//! | FIPS 186-4 | Here |
//! |---|---|
//! | §4.2, the approved `(L, N)` pairs | [`FfcParameterSize`] |
//! | A.1.1.2, generating `p` and `q` from a seed | `generate_probable_primes`, `probable_primes_from_seed` |
//! | A.1.1.3, validating `p` and `q` against the seed and counter | `validate_probable_primes` |
//! | A.2.3, canonical generation of `g` with an `index` | `canonical_generator` |
//! | A.2.4, validating a canonical `g` | `validate_canonical_generator` |
//! | C.3 and Table C.1, probabilistic primality | `is_probable_prime_fips186_4` (generation), [`is_probable_prime_untrusted`] (validation) |
//! | what a validator needs besides `(p, q, g)` | [`FfcSeed`], [`FfcHash`] |
//!
//! Generation always derives `g` by A.2.3, never by A.2.1: the seed A.2.3
//! needs is at hand whenever `p` and `q` come from A.1.1.2, and a generator
//! nobody can validate offers nothing over one anybody can. Parameters whose
//! generator came from elsewhere are still accepted without a seed, with
//! A.2.2's partial validation of `g`.
//!
//! Where the code departs from the letter of the text it says so at the
//! departure: the primality tests (`is_probable_prime_fips186_4`,
//! `FfcDomain::with_seed`), byte-aligned seeds ([`FfcSeed`]), and the step
//! order of A.1.1.3 (`validate_probable_primes`).

use crate::{Csprng, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use rump::modular::mod_pow;
use rump::number_theory::{
    is_lucas_probable_prime, is_probable_prime, miller_rabin_with_bases, miller_rabin_witness,
};
use rump::BigUint;

/// Number of candidate-derived pseudorandom Miller-Rabin rounds added by
/// [`is_probable_prime_untrusted`] on top of the fixed bases.
///
/// Each round independently catches a composite with probability ≥ 3/4
/// (Rabin), so forging a value that survives all of them requires grinding on
/// the order of `4^64 = 2^128` candidates — infeasible.
const HARDENED_HASH_ROUNDS: usize = 64;

/// How many per-message secrets `k` a signer tries before it gives up on a
/// signature and returns `None`.
///
/// DSA (FIPS 186-4 §4.6) and ECDSA (FIPS 186-5 §6.4.1) compute a new `k`
/// when one gives `r = 0` or `s = 0`. For a fixed key and digest, `s = 0`
/// holds for one `k` in `[1, q)` and `r = 0` for the `k` whose `g^k mod p`
/// is a multiple of `q` (or, for ECDSA, whose point has `x ≡ 0 (mod n)`),
/// about one of every `q` values, so a uniform `k` is rejected with
/// probability about `2/q` and the number of rejections over `q`
/// independent draws is Poisson with mean about 2: sixty-four rejections in
/// a row has probability about `(2/q)^64`, and `q ≥ 2^15` everywhere this
/// crate signs, so the bound is never met by chance. It is met by a source
/// that repeats an in-range `k` that the key and digest reject, and by a
/// deterministic derivation (RFC 6979) over a group in which every `k` is
/// rejected; both are then reported as `None` instead of a loop that never
/// returns. A source that stalls below the range — one that repeats a value
/// the sampler itself rejects — is reported earlier, by the panic rump's
/// samplers raise after 256 consecutive rejected draws (see
/// [`random_nonzero_below`]).
pub const MAX_NONCE_DRAWS: usize = 64;

/// The most bits a prime modulus `p` may have to be accepted as a group
/// modulus anywhere in this crate: parsers, explicit constructors and
/// `FfcDomain::new` refuse a wider `p` before any arithmetic on it.
///
/// This is a resource bound, not a security parameter. A hardened primality
/// test costs about `bits^3`, so an unbounded `p` makes every parser an
/// amplifier: a few kilobytes of input demanding minutes of exponentiation.
/// The largest size any FIPS 186-4 or SP 800-56A parameter set uses is
/// `L = 3072` (FIPS 186-4 §4.2) and the largest safe-prime group of SP
/// 800-56A Rev. 3 Appendix D is 8192 bits, so the bound is above every
/// standard size while capping the work at about `(16384/3072)^3 ≈ 150`
/// times that of the largest approved group.
pub const MAX_MODULUS_BITS: usize = 16384;

/// The most bits a prime subgroup order `q` may have, on the same footing as
/// [`MAX_MODULUS_BITS`]: the largest `N` FIPS 186-4 §4.2 defines is 256, and
/// SP 800-56A Rev. 3 Appendix D's safe-prime groups have `q = (p − 1)/2`,
/// which no scheme here uses as a subgroup order.
pub const MAX_SUBGROUP_ORDER_BITS: usize = 512;

/// The fewest bits a prime subgroup order `q` may have: `q ≥ 2^15`.
///
/// Every group this crate signs or agrees over must have a subgroup large
/// enough that the per-message rejection reasoning behind
/// [`MAX_NONCE_DRAWS`] holds and that no `k`, `x` or `z` can be found by
/// enumeration in a test's lifetime: a 16-bit `q` gives `2/q < 2^-14` per
/// draw. FIPS 186-4 §4.2's smallest `N` is 160, so every standard group is
/// far above this bound; it exists to reject the degenerate groups (`q = 2`,
/// `q = 11`) that primality and subgroup checks alone would let through, and
/// the toy generators build only groups above it.
pub const MIN_SUBGROUP_ORDER_BITS: usize = 16;

/// Hardened Miller-Rabin for candidates from an untrusted source.
///
/// Runs the fixed small-prime bases plus `HARDENED_HASH_ROUNDS` additional
/// witnesses derived by hashing the candidate itself. Because those witnesses
/// are an unpredictable function of `n`, an adversary cannot construct a
/// composite that is a strong pseudoprime to a base set they can choose in
/// advance (the Arnault-style attack on fixed bases).
#[must_use]
pub fn is_probable_prime_untrusted(candidate: &BigUint) -> bool {
    if !is_probable_prime(candidate) {
        return false;
    }
    // A candidate of at most ten bits (n ≤ 1023) is already decided exactly:
    // rump's sieve holds the primes below 1000 and decides those and their
    // multiples, and the twelve fixed bases are a proof for everything else
    // below ψ₁₂ ≈ 3.19 × 10^23. Such a candidate also sits below the range
    // the witness derivation assumes (its map into [2, n-2] needs n > 4).
    if candidate.bits() <= 10 {
        return true;
    }

    hash_derived_bases(candidate, HARDENED_HASH_ROUNDS)
        .iter()
        .all(|witness| !rump::number_theory::miller_rabin_witness(candidate, witness))
}

/// Which primality test a parser applies to a value.
///
/// This is the mechanism behind the parse-time validation policy stated in
/// the [`public_key`](crate::public_key) module docs: the hardened test is
/// reserved for primes that guard a secret, and public parameters get one
/// fixed-base test so that loading a public key cannot be turned into a
/// modular-exponentiation amplifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimalityPolicy {
    /// Fixed-base Miller-Rabin ([`rump::number_theory::is_probable_prime`]).
    /// Appropriate for a public parameter: a forged pseudoprime there weakens
    /// only the key of whoever forged it.
    Structural,
    /// SHAKE256-hardened Miller-Rabin ([`is_probable_prime_untrusted`]).
    /// Required for every prime in a private key, and for any group over
    /// which this crate will generate a key pair of its own: a composite
    /// modulus that survives fixed bases splits the group by the Chinese
    /// remainder theorem into components modulo its (smaller) prime factors,
    /// where a discrete logarithm of *our* secret is far cheaper.
    Hardened,
}

/// Apply the selected primality test.
#[must_use]
pub(crate) fn is_probable_prime_under(candidate: &BigUint, policy: PrimalityPolicy) -> bool {
    match policy {
        PrimalityPolicy::Structural => is_probable_prime(candidate),
        PrimalityPolicy::Hardened => is_probable_prime_untrusted(candidate),
    }
}

/// Validate a prime-order subgroup description `(p, q, g)` as used by DSA,
/// finite-field DH, and generated ElGamal keys: the sizes are within bounds
/// ([`within_group_size_bounds`]), `p` and `q` pass the selected primality
/// test, `q < p`, `q | p - 1`, `1 < g < p`, and `g^q ≡ 1 (mod p)`.
///
/// The size bounds are checked first, before any arithmetic, so an oversized
/// input costs a bit-length comparison and nothing more.
///
/// Without a seed record this is all that can be checked. The checks on `g`
/// are FIPS 186-4 A.2.2's partial validation; those on `p` and `q` show they
/// are primes of the right shape, not that A.1.1.2 generated them (for that,
/// see `FfcDomain::with_seed`).
#[must_use]
pub(crate) fn validate_prime_order_group(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    policy: PrimalityPolicy,
) -> bool {
    if !within_group_size_bounds(p, q)
        || q >= p
        || !is_probable_prime_under(q, policy)
        || !is_probable_prime_under(p, policy)
    {
        return false;
    }
    let p_minus_one = p.sub(&BigUint::one());
    if !p_minus_one.rem(q).is_zero() {
        return false;
    }
    is_in_prime_order_subgroup(g, q, p)
}

/// The size policy every group modulus and subgroup order must meet before
/// anything is computed on them: `bits(p) ≤` [`MAX_MODULUS_BITS`] and
/// [`MIN_SUBGROUP_ORDER_BITS`] `≤ bits(q) ≤` [`MAX_SUBGROUP_ORDER_BITS`].
#[must_use]
pub(crate) fn within_group_size_bounds(p: &BigUint, q: &BigUint) -> bool {
    p.bits() <= MAX_MODULUS_BITS
        && (MIN_SUBGROUP_ORDER_BITS..=MAX_SUBGROUP_ORDER_BITS).contains(&q.bits())
}

/// Subgroup membership for an element of `Z_p^*`: `1 < y < p` and
/// `y^q ≡ 1 (mod p)`. For a generator that is FIPS 186-4 A.2.2 steps 1–2; for
/// a public key and odd `q` it is SP 800-56A Rev. 3 §5.6.2.3.1, whose bound
/// `y ≤ p − 2` follows because `p − 1` has order 2.
///
/// Rejecting `y = 1` also rejects the identity, which every subgroup contains
/// but no honest key or generator equals.
#[must_use]
pub(crate) fn is_in_prime_order_subgroup(y: &BigUint, q: &BigUint, p: &BigUint) -> bool {
    if y <= &BigUint::one() || y >= p {
        return false;
    }
    mod_pow(y, q, p) == BigUint::one()
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

// ─── FIPS 186-4 finite-field domain parameters ──────────────────────────────

/// A pair `(L, N)` of bit lengths for the prime modulus `p` and the prime
/// subgroup order `q`, from the list FIPS 186-4 §4.2 approves.
///
/// §4.2 lists exactly these four pairs, and A.1.1.2 (step 1) and A.1.1.3
/// (step 3) refuse any other, so FIPS 186-4 domain parameters exist at no
/// other size. Groups of other sizes come only from the crate's separate
/// toy generators (`Dh::generate_toy_params`, `Dsa::generate_toy_params`,
/// `ElGamal::generate_toy`), which are outside FIPS 186-4.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FfcParameterSize {
    /// `L = 1024`, `N = 160`.
    L1024N160,
    /// `L = 2048`, `N = 224`.
    L2048N224,
    /// `L = 2048`, `N = 256`.
    L2048N256,
    /// `L = 3072`, `N = 256`.
    L3072N256,
}

impl FfcParameterSize {
    /// Every approved pair, in §4.2's order.
    pub const ALL: [Self; 4] = [
        Self::L1024N160,
        Self::L2048N224,
        Self::L2048N256,
        Self::L3072N256,
    ];

    /// `L`, the bit length of `p`.
    #[must_use]
    pub const fn l(self) -> usize {
        match self {
            Self::L1024N160 => 1024,
            Self::L2048N224 | Self::L2048N256 => 2048,
            Self::L3072N256 => 3072,
        }
    }

    /// `N`, the bit length of `q`.
    #[must_use]
    pub const fn n(self) -> usize {
        match self {
            Self::L1024N160 => 160,
            Self::L2048N224 => 224,
            Self::L2048N256 | Self::L3072N256 => 256,
        }
    }

    /// The approved pair with these bit lengths, or `None` if §4.2 does not
    /// list it.
    #[must_use]
    pub fn from_lengths(l: usize, n: usize) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|size| size.l() == l && size.n() == n)
    }

    /// FIPS 186-4 Table C.1, column "M-R Tests when followed by One Lucas
    /// test": the Miller-Rabin iterations for `p` and for `q`.
    const fn miller_rabin_rounds_before_lucas(self) -> (usize, usize) {
        match self {
            Self::L1024N160 => (3, 19),
            Self::L2048N224 => (3, 24),
            Self::L2048N256 => (3, 27),
            Self::L3072N256 => (2, 27),
        }
    }
}

/// An approved hash function for generating FFC domain parameters: the SHA-2
/// family of FIPS 180-4.
///
/// FIPS 186-4 A.1.1.2 requires the hash's output length `outlen` to be at
/// least `N`, so SHA-224 and SHA-512/224 serve only the pairs with
/// `N ≤ 224`; generation and validation both refuse a shorter hash. The same
/// hash generates `p`, `q` (A.1.1.2) and `g` (A.2.3). SHA-1 is not offered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FfcHash {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
}

impl FfcHash {
    /// `outlen`, the bit length of the hash output.
    #[must_use]
    pub const fn output_bits(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha512_224 => 224,
            Self::Sha256 | Self::Sha512_256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
            Self::Sha512_224 => Sha512_224::digest(data).to_vec(),
            Self::Sha512_256 => Sha512_256::digest(data).to_vec(),
        }
    }

    /// The hash as an integer: the last arc of its object identifier under
    /// NIST's `hashAlgs` arc 2.16.840.1.101.3.4.2 (RFC 8017 Appendix A.2.4),
    /// which is how the crate-defined parameter formats record it.
    const fn hash_algs_arc(self) -> u64 {
        match self {
            Self::Sha256 => 1,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
            Self::Sha224 => 4,
            Self::Sha512_224 => 5,
            Self::Sha512_256 => 6,
        }
    }

    fn from_hash_algs_arc(arc: u64) -> Option<Self> {
        [
            Self::Sha224,
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
            Self::Sha512_224,
            Self::Sha512_256,
        ]
        .into_iter()
        .find(|hash| hash.hash_algs_arc() == arc)
    }
}

/// What a third party needs besides `(p, q, g)` to validate FFC domain
/// parameters generated by FIPS 186-4 A.1.1.2 and A.2.3: the hash function,
/// the `domain_parameter_seed`, the `counter` A.1.1.2 returned, and the
/// `index` A.2.3 derived `g` with.
///
/// None of these is secret (A.1.1.2: they "need not be kept secret"). The
/// seed is a byte string, so `seedlen` is a multiple of eight: the crate's
/// SHA-2 implementations hash bytes, and a FIPS 186-4 seed of any other bit
/// length cannot be represented here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FfcSeed {
    hash: FfcHash,
    domain_parameter_seed: Vec<u8>,
    counter: u16,
    index: u8,
}

impl FfcSeed {
    /// Collect the values. Nothing is checked here; the values are checked
    /// when they are used to validate a set of domain parameters.
    #[must_use]
    pub fn new(hash: FfcHash, domain_parameter_seed: &[u8], counter: u16, index: u8) -> Self {
        Self {
            hash,
            domain_parameter_seed: domain_parameter_seed.to_vec(),
            counter,
            index,
        }
    }

    /// The hash function that generated `p`, `q` and `g`.
    #[must_use]
    pub fn hash(&self) -> FfcHash {
        self.hash
    }

    /// The `domain_parameter_seed` of A.1.1.2.
    #[must_use]
    pub fn domain_parameter_seed(&self) -> &[u8] {
        &self.domain_parameter_seed
    }

    /// `seedlen`, the bit length of the seed.
    #[must_use]
    pub fn seedlen(&self) -> usize {
        self.domain_parameter_seed.len() * 8
    }

    /// The `counter` A.1.1.2 returned: how many candidates for `p` preceded
    /// the first prime. A.1.1.2 stops at `4L − 1` (12287 when `L = 3072`).
    #[must_use]
    pub fn counter(&self) -> u16 {
        self.counter
    }

    /// The `index` A.2.3 derived `g` with.
    #[must_use]
    pub fn index(&self) -> u8 {
        self.index
    }
}

/// `2^k`.
fn power_of_two(k: usize) -> BigUint {
    let mut value = BigUint::zero();
    value.set_bit(k);
    value
}

/// FIPS 186-4 Appendix C.3 as generation runs it: `rounds` iterations of the
/// C.3.1 Miller-Rabin test with bases drawn from `rng`, then one Lucas test —
/// Table C.1's "M-R Tests when followed by One Lucas test" option.
///
/// Two details go beyond the letter of C.3, each of the kind its "process or
/// its equivalent" admits: each can only reject, never on a prime, so every
/// prime still passes and every candidate accepted is one C.3's own procedure
/// accepts.
///
/// - Trial division by the primes below 1000 and one base-2 round
///   ([`miller_rabin_with_bases`]) run first; they settle most composite
///   candidates before any base is drawn.
/// - The bases are uniform on `[2, w − 2]`, the distribution C.3.1 steps
///   4.1–4.2 reach by rejection sampling `wlen`-bit strings.
///
/// The Lucas test is C.3.3's own, rump's [`is_lucas_probable_prime`]: the
/// first `D` in 5, −7, 9, −11, … with Jacobi symbol `(D/w) = −1`, `P = 1`,
/// `Q = (1 − D)/4`, and acceptance exactly when `U_{w+1} ≡ 0 (mod w)`. Every
/// candidate that reaches it has more than ten bits, so it is never one of
/// the small primes rump's version treats specially.
fn is_probable_prime_fips186_4<R: Csprng>(candidate: &BigUint, rounds: usize, rng: &mut R) -> bool {
    if !miller_rabin_with_bases(candidate, &[2]) {
        return false;
    }
    // Sieve-sized candidates are already decided exactly, and sit below the
    // range the base draw needs (w > 3).
    if candidate.bits() <= 10 {
        return true;
    }
    let two = BigUint::from_u64(2);
    let base_span = candidate.sub(&BigUint::from_u64(3));
    for _ in 0..rounds {
        let base = random_below(rng, &base_span)
            .expect("a candidate above the sieve leaves a non-empty base range")
            .add(&two);
        if miller_rabin_witness(candidate, &base) {
            return false;
        }
    }
    is_lucas_probable_prime(candidate)
}

/// FIPS 186-4 A.1.1.2 steps 6–7, which A.1.1.3 steps 7–8 repeat:
/// `U = Hash(domain_parameter_seed) mod 2^(N−1)` and
/// `q = 2^(N−1) + U + 1 − (U mod 2)`.
fn subgroup_order_from_seed(n: usize, hash: FfcHash, seed: &[u8]) -> BigUint {
    let u = BigUint::from_be_bytes(&hash.digest(seed)).low_bits(n - 1);
    let u_mod_2 = BigUint::from_u64(u64::from(u.is_odd()));
    power_of_two(n - 1)
        .add(&u)
        .add(&BigUint::one())
        .sub(&u_mod_2)
}

/// The candidates for `p` that a seed and `q` determine: FIPS 186-4 A.1.1.2
/// steps 3–4 and 11.1–11.5, repeated as A.1.1.3 steps 10–11 and 13.1–13.5.
struct PrimeCandidates {
    l: usize,
    hash: FfcHash,
    /// `domain_parameter_seed` as an integer.
    seed: BigUint,
    /// `seedlen / 8`.
    seed_bytes: usize,
    /// `2q`.
    twice_q: BigUint,
    /// `n = ⌈L / outlen⌉ − 1` (step 3).
    n: usize,
    /// `b = L − 1 − n·outlen` (step 4).
    b: usize,
    outlen: usize,
}

impl PrimeCandidates {
    fn new(size: FfcParameterSize, hash: FfcHash, seed: &[u8], q: &BigUint) -> Self {
        let l = size.l();
        let outlen = hash.output_bits();
        let n = l.div_ceil(outlen) - 1;
        Self {
            l,
            hash,
            seed: BigUint::from_be_bytes(seed),
            seed_bytes: seed.len(),
            twice_q: q.add(q),
            n,
            b: l - 1 - n * outlen,
            outlen,
        }
    }

    /// The candidate examined when A.1.1.2's loop variable `counter` has
    /// this value; its `offset` is then `1 + counter·(n + 1)` (steps 10 and
    /// 11.9).
    fn at(&self, counter: usize) -> BigUint {
        let offset = 1 + counter * (self.n + 1);
        let mut w = BigUint::zero();
        for j in 0..=self.n {
            // 11.1: V_j = Hash((domain_parameter_seed + offset + j) mod 2^seedlen).
            let addend = u64::try_from(offset + j).expect("offsets stay below 2^20");
            let input = self
                .seed
                .add(&BigUint::from_u64(addend))
                .low_bits(8 * self.seed_bytes)
                .to_be_bytes_padded(self.seed_bytes);
            let mut v = BigUint::from_be_bytes(&self.hash.digest(&input));
            // 11.2: the last block contributes only V_n mod 2^b.
            if j == self.n {
                v = v.low_bits(self.b);
            }
            v.shl_bits(j * self.outlen);
            w = w.add(&v);
        }
        // 11.3: X = W + 2^(L−1). W < 2^(L−1), so the sum sets bit L − 1.
        let mut x = w;
        x.set_bit(self.l - 1);
        // 11.4–11.5: c = X mod 2q and p = X − (c − 1), so p ≡ 1 (mod 2q).
        let c = x.rem(&self.twice_q);
        x.add(&BigUint::one()).sub(&c)
    }
}

/// A primality verdict for a candidate, given Table C.1's Miller-Rabin
/// iteration count for it (a test with its own schedule may ignore it).
type PrimalityTest<'t> = dyn FnMut(&BigUint, usize) -> bool + 't;

/// FIPS 186-4 A.1.1.2 steps 1–4 and 6–12 for one `domain_parameter_seed`.
///
/// Returns `(p, q, counter)`. `None` covers both of A.1.1.2's other exits:
/// INVALID (a hash output or a seed shorter than `N` bits) and "go to step
/// 5" for a fresh seed (`q` composite, or `4L` candidates for `p` without a
/// prime).
fn probable_primes_from_seed(
    size: FfcParameterSize,
    hash: FfcHash,
    seed: &[u8],
    is_prime: &mut PrimalityTest<'_>,
) -> Option<(BigUint, BigUint, u16)> {
    let (l, n) = (size.l(), size.n());
    // Step 1 is the type of `size`; step 2 and A.1.1.2's bound on outlen.
    if hash.output_bits() < n || seed.len() * 8 < n {
        return None;
    }
    let (p_rounds, q_rounds) = size.miller_rabin_rounds_before_lucas();
    // Steps 6–9.
    let q = subgroup_order_from_seed(n, hash, seed);
    if !is_prime(&q, q_rounds) {
        return None;
    }
    // Steps 10–12.
    let candidates = PrimeCandidates::new(size, hash, seed, &q);
    let lower_bound = power_of_two(l - 1);
    for counter in 0..4 * l {
        let p = candidates.at(counter);
        if p >= lower_bound && is_prime(&p, p_rounds) {
            let counter = u16::try_from(counter).expect("counter < 4L <= 12288");
            return Some((p, q, counter));
        }
    }
    None
}

/// FIPS 186-4 A.1.1.2 in full: draw `seedlen = N`-bit seeds from `rng`
/// (step 5) until one yields primes. Returns `(p, q, domain_parameter_seed,
/// counter)`, or `None` if `hash` is shorter than `N` bits.
fn generate_probable_primes<R: Csprng>(
    size: FfcParameterSize,
    hash: FfcHash,
    rng: &mut R,
) -> Option<(BigUint, BigUint, Vec<u8>, u16)> {
    if hash.output_bits() < size.n() {
        return None;
    }
    // Every approved N is a multiple of eight.
    let mut seed = vec![0u8; size.n() / 8];
    loop {
        rng.fill_bytes(&mut seed);
        let mut test = |w: &BigUint, rounds: usize| is_probable_prime_fips186_4(w, rounds, rng);
        if let Some((p, q, counter)) = probable_primes_from_seed(size, hash, &seed, &mut test) {
            return Some((p, q, seed, counter));
        }
    }
}

/// FIPS 186-4 A.1.1.3: were `p` and `q` generated by A.1.1.2 from this seed
/// with this counter?
///
/// The steps run in a different order than printed, with the same verdict:
/// A.1.1.3 accepts exactly when the candidate at position `counter` equals
/// `p` and is prime and no earlier candidate (at least `2^(L−1)`) is prime,
/// so the hash-only comparison with `p` runs before any primality test and
/// the scan of earlier candidates runs last. A tampered `p` or `counter` is
/// then rejected without testing a single candidate.
fn validate_probable_primes(
    p: &BigUint,
    q: &BigUint,
    seed: &FfcSeed,
    is_prime: &mut PrimalityTest<'_>,
) -> bool {
    // Steps 1–3.
    let Some(size) = FfcParameterSize::from_lengths(p.bits(), q.bits()) else {
        return false;
    };
    let (l, n) = (size.l(), size.n());
    // A.1.1.2 cannot have generated them with a hash shorter than N.
    if seed.hash.output_bits() < n {
        return false;
    }
    // Step 4.
    let counter = usize::from(seed.counter);
    if counter > 4 * l - 1 {
        return false;
    }
    // Steps 5–6.
    let domain_parameter_seed = seed.domain_parameter_seed.as_slice();
    if seed.seedlen() < n {
        return false;
    }
    let (p_rounds, q_rounds) = size.miller_rabin_rounds_before_lucas();
    // Steps 7–9.
    let computed_q = subgroup_order_from_seed(n, seed.hash, domain_parameter_seed);
    if computed_q != *q || !is_prime(&computed_q, q_rounds) {
        return false;
    }
    // Steps 10–15.
    let candidates = PrimeCandidates::new(size, seed.hash, domain_parameter_seed, q);
    if candidates.at(counter) != *p || !is_prime(p, p_rounds) {
        return false;
    }
    let lower_bound = power_of_two(l - 1);
    (0..counter).all(|earlier| {
        let candidate = candidates.at(earlier);
        candidate < lower_bound || !is_prime(&candidate, p_rounds)
    })
}

/// FIPS 186-4 A.2.3 steps 2–11: the canonical generator of the order-`q`
/// subgroup for this seed and `index`.
///
/// `None` is A.2.3's INVALID (the 16-bit `count` wraps before a generator
/// is found), and also covers `q ∤ p − 1`, where no element of order `q`
/// exists; A.1.1.2's primes always have `q | p − 1`.
fn canonical_generator(
    p: &BigUint,
    q: &BigUint,
    hash: FfcHash,
    domain_parameter_seed: &[u8],
    index: u8,
) -> Option<BigUint> {
    // Step 3.
    let (e, remainder) = p.sub(&BigUint::one()).div_rem(q);
    if !remainder.is_zero() {
        return None;
    }
    let two = BigUint::from_u64(2);
    let mut u = Vec::with_capacity(domain_parameter_seed.len() + 7);
    // Steps 4–6: count runs 1, 2, …, 65535 and wraps to 0 after that.
    for count in 1..=u16::MAX {
        // Step 7: U = domain_parameter_seed || "ggen" || index || count.
        u.clear();
        u.extend_from_slice(domain_parameter_seed);
        u.extend_from_slice(b"ggen");
        u.push(index);
        u.extend_from_slice(&count.to_be_bytes());
        // Steps 8–10.
        let w = BigUint::from_be_bytes(&hash.digest(&u));
        let g = mod_pow(&w, &e, p);
        if g >= two {
            return Some(g);
        }
    }
    None
}

/// FIPS 186-4 A.2.4: is `g` the canonical generator A.2.3 derives from this
/// seed and index? (A.2.4 assumes `p` and `q` already passed A.1.1.3.)
fn validate_canonical_generator(p: &BigUint, q: &BigUint, g: &BigUint, seed: &FfcSeed) -> bool {
    // Steps 2–3: 2 ≤ g ≤ p − 1 and g^q ≡ 1 (mod p).
    if !is_in_prime_order_subgroup(g, q, p) {
        return false;
    }
    // Steps 4–13.
    canonical_generator(p, q, seed.hash, &seed.domain_parameter_seed, seed.index)
        .is_some_and(|computed_g| computed_g == *g)
}

// ─── Domain-parameter state behind DhParams and DsaParams ───────────────────

/// Field names of the crate-defined parameter formats without a seed.
const DOMAIN_FIELDS: [&str; 3] = ["p", "q", "g"];

/// Field names of the crate-defined parameter formats with a FIPS 186-4
/// seed.
const SEEDED_DOMAIN_FIELDS: [&str; 8] = [
    "p",
    "q",
    "g",
    "hash",
    "seedlen",
    "domain-parameter-seed",
    "counter",
    "index",
];

/// Largest `seedlen`, in bits, the parsers accept.
///
/// FIPS 186-4 sets no maximum. This bound is the parsers' own, a resource
/// limit: the format carries `seedlen` separately from the seed's integer
/// value (a seed may begin with zero bytes), and an unbounded `seedlen` would
/// let a few bytes of input demand an arbitrarily large allocation.
const MAX_PARSED_SEEDLEN: usize = 1 << 16;

/// Validated FFC domain parameters `(p, q, g {, seed})`, the state behind the
/// scheme-level parameter types (`DhParams`, `DsaParams`).
///
/// Every value passed [`validate_prime_order_group`] under the hardened
/// policy, was generated here, or was extracted from a key that did; a value
/// with a seed was either generated by A.1.1.2 and A.2.3 or passed A.1.1.3
/// and A.2.4 against that seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FfcDomain {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    seed: Option<FfcSeed>,
}

impl FfcDomain {
    /// FIPS 186-4 A.1.1.2 for `p` and `q`, then A.2.3 with `index` for `g`.
    ///
    /// `None` only when `hash` is shorter than `N` bits.
    ///
    /// # Panics
    ///
    /// The Miller-Rabin bases of C.3.1 come from [`random_below`], which
    /// panics on a source that stalls (256 consecutive rejected draws). The
    /// seeds themselves are raw `fill_bytes` output and cannot stall: a
    /// constant source repeats one seed and, if that seed yields no primes,
    /// loops here forever, as A.1.1.2 itself would.
    pub(crate) fn generate_fips186_4<R: Csprng>(
        rng: &mut R,
        size: FfcParameterSize,
        hash: FfcHash,
        index: u8,
    ) -> Option<Self> {
        loop {
            let (p, q, domain_parameter_seed, counter) = generate_probable_primes(size, hash, rng)?;
            // A.2.3 returns INVALID only if 65535 consecutive hash outputs
            // all exponentiate into {0, 1}; if that ever happens, start over
            // from a fresh seed.
            if let Some(g) = canonical_generator(&p, &q, hash, &domain_parameter_seed, index) {
                let seed = FfcSeed {
                    hash,
                    domain_parameter_seed,
                    counter,
                    index,
                };
                return Some(Self {
                    p,
                    q,
                    g,
                    seed: Some(seed),
                });
            }
        }
    }

    /// A toy group from [`generate_toy_prime_order_group`] — not FIPS 186-4.
    ///
    /// # Panics
    ///
    /// Panics on a stalled or constant source, as [`random_probable_prime`]
    /// and [`random_nonzero_below`] do.
    pub(crate) fn generate_toy<R: Csprng>(rng: &mut R, bits: usize) -> Option<Self> {
        let (p, q, g) = generate_toy_prime_order_group(rng, bits)?;
        Some(Self {
            p,
            q,
            g,
            seed: None,
        })
    }

    /// Explicit `(p, q, g)` without a seed, under the hardened
    /// [`validate_prime_order_group`]: the size bounds first (an oversized
    /// `p` or `q` is refused before any arithmetic), then primality and
    /// structure. Without a seed, `p` and `q` can be checked only for
    /// primality and structure, and `g` only as A.2.2's partial validation
    /// allows.
    pub(crate) fn new(p: BigUint, q: BigUint, g: BigUint) -> Option<Self> {
        if !validate_prime_order_group(&p, &q, &g, PrimalityPolicy::Hardened) {
            return None;
        }
        Some(Self {
            p,
            q,
            g,
            seed: None,
        })
    }

    /// Explicit `(p, q, g)` with the seed they were generated from: FIPS
    /// 186-4 A.1.1.3 for `p` and `q`, then A.2.4 for `g`. A.1.1.3 steps 1–3
    /// admit only the four `(L, N)` pairs of §4.2, checked from the bit
    /// lengths before any arithmetic, so no input wider than 3072 bits
    /// reaches a primality test.
    ///
    /// A validator has no random bit generator to hand, so the primality
    /// tests inside A.1.1.3 are the hardened test
    /// ([`is_probable_prime_untrusted`]) rather than C.3.1's rounds with
    /// RBG-drawn bases: 64 Miller-Rabin bases derived from the candidate by
    /// SHAKE256, after the twelve fixed ones — more than the 64 rounds Table
    /// C.1 requires of the Miller-Rabin-only option at any approved size, but
    /// drawn from a function of the candidate instead of an RBG.
    pub(crate) fn with_seed(p: BigUint, q: BigUint, g: BigUint, seed: FfcSeed) -> Option<Self> {
        let mut hardened =
            |candidate: &BigUint, _rounds: usize| is_probable_prime_untrusted(candidate);
        if !validate_probable_primes(&p, &q, &seed, &mut hardened)
            || !validate_canonical_generator(&p, &q, &g, &seed)
        {
            return None;
        }
        Some(Self {
            p,
            q,
            g,
            seed: Some(seed),
        })
    }

    /// Parts that already passed the hardened validation — the group of a
    /// validated private key — without a seed.
    pub(crate) fn from_validated_parts(p: BigUint, q: BigUint, g: BigUint) -> Self {
        Self {
            p,
            q,
            g,
            seed: None,
        }
    }

    /// The prime modulus `p`.
    pub(crate) fn p(&self) -> &BigUint {
        &self.p
    }

    /// The prime subgroup order `q`.
    pub(crate) fn q(&self) -> &BigUint {
        &self.q
    }

    /// The generator `g` of the order-`q` subgroup.
    pub(crate) fn g(&self) -> &BigUint {
        &self.g
    }

    /// The FIPS 186-4 seed record, if the parameters have one.
    pub(crate) fn seed(&self) -> Option<&FfcSeed> {
        self.seed.as_ref()
    }

    /// Schema fields: `[p, q, g]`, followed with a seed by
    /// `[hash, seedlen, domain_parameter_seed, counter, index]`.
    pub(crate) fn serial_fields(&self) -> Vec<BigUint> {
        let mut fields = vec![self.p.clone(), self.q.clone(), self.g.clone()];
        if let Some(seed) = &self.seed {
            let seedlen = u64::try_from(seed.seedlen()).expect("an in-memory seed length fits u64");
            fields.extend([
                BigUint::from_u64(seed.hash.hash_algs_arc()),
                BigUint::from_u64(seedlen),
                BigUint::from_be_bytes(&seed.domain_parameter_seed),
                BigUint::from_u64(u64::from(seed.counter)),
                BigUint::from_u64(u64::from(seed.index)),
            ]);
        }
        fields
    }

    /// Validate schema fields and rebuild the parameters: three fields go
    /// through [`Self::new`], eight through [`Self::with_seed`], and any other
    /// count is rejected. The seed record must be well formed first: a known
    /// hash code, a `seedlen` that is a multiple of eight, at most
    /// [`MAX_PARSED_SEEDLEN`], and wide enough for the seed's value, a
    /// `counter` that fits 16 bits and an `index` that fits 8.
    pub(crate) fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self> {
        let mut fields = fields.into_iter();
        let p = fields.next()?;
        let q = fields.next()?;
        let g = fields.next()?;
        let Some(hash_code) = fields.next() else {
            return Self::new(p, q, g);
        };
        let hash = FfcHash::from_hash_algs_arc(hash_code.to_u64()?)?;
        let seedlen = usize::try_from(fields.next()?.to_u64()?).ok()?;
        let seed_value = fields.next()?;
        let counter = u16::try_from(fields.next()?.to_u64()?).ok()?;
        let index = u8::try_from(fields.next()?.to_u64()?).ok()?;
        if fields.next().is_some()
            || seedlen % 8 != 0
            || seedlen > MAX_PARSED_SEEDLEN
            || seed_value.bits() > seedlen
        {
            return None;
        }
        let seed = FfcSeed {
            hash,
            domain_parameter_seed: seed_value.to_be_bytes_padded(seedlen / 8),
            counter,
            index,
        };
        Self::with_seed(p, q, g, seed)
    }

    /// The crate's flat XML form under `root`, with the fields of
    /// [`Self::serial_fields`].
    pub(crate) fn to_xml(&self, root: &str) -> String {
        let fields = self.serial_fields();
        let names: &[&str] = if self.seed.is_some() {
            &SEEDED_DOMAIN_FIELDS
        } else {
            &DOMAIN_FIELDS
        };
        let pairs: Vec<(&str, &BigUint)> = names.iter().copied().zip(fields.iter()).collect();
        crate::public_key::io::xml_wrap(root, &pairs)
    }

    /// Parse either XML form under `root`, validating as
    /// [`Self::from_serial_fields`] does.
    pub(crate) fn from_xml(root: &str, xml: &str) -> Option<Self> {
        let fields = crate::public_key::io::xml_unwrap(root, &SEEDED_DOMAIN_FIELDS, xml)
            .or_else(|| crate::public_key::io::xml_unwrap(root, &DOMAIN_FIELDS, xml))?;
        Self::from_serial_fields(fields)
    }
}

/// Emit a scheme's domain-parameter type over [`FfcDomain`]: the constructors
/// (`new`, `with_seed`), the accessors (`modulus`, `subgroup_order`,
/// `generator`, `seed`), the crate-private `from_domain`, and the
/// crate-defined formats. `DsaParams` and `DhParams` are the same type over
/// the same validated state; only their names, labels and the scheme they
/// serve differ, and those are the arguments.
macro_rules! impl_ffc_params {
    ($ty:ident, $label:expr, $root:literal, $scheme:literal) => {
        impl $ty {
            #[doc = concat!(
                "Build ", $scheme, " domain parameters from explicit `(p, q, g)` without a \
                 seed record, applying the hardened validation: the size bounds \
                 (`bits(p) ≤ 16384`, `16 ≤ bits(q) ≤ 512`, checked before any \
                 arithmetic — see [`MAX_MODULUS_BITS`], [`MIN_SUBGROUP_ORDER_BITS`] and \
                 [`MAX_SUBGROUP_ORDER_BITS`]), then `p` and `q` probable prime under \
                 [`is_probable_prime_untrusted`], `q < p`, `q | p − 1`, `1 < g < p`, and \
                 `g^q ≡ 1 (mod p)`. With no seed, nothing shows how the parameters were \
                 generated; the checks on `g` are FIPS 186-4 A.2.2's partial validation. \
                 Returns `None` if any check fails.\n\n\
                 [`is_probable_prime_untrusted`]: crate::public_key::primes::is_probable_prime_untrusted\n\
                 [`MAX_MODULUS_BITS`]: crate::public_key::primes::MAX_MODULUS_BITS\n\
                 [`MIN_SUBGROUP_ORDER_BITS`]: crate::public_key::primes::MIN_SUBGROUP_ORDER_BITS\n\
                 [`MAX_SUBGROUP_ORDER_BITS`]: crate::public_key::primes::MAX_SUBGROUP_ORDER_BITS"
            )]
            #[must_use]
            pub fn new(
                p: crate::vt::BigUint,
                q: crate::vt::BigUint,
                g: crate::vt::BigUint,
            ) -> Option<Self> {
                crate::public_key::primes::FfcDomain::new(p, q, g).map(Self::from_domain)
            }

            /// Build domain parameters from explicit `(p, q, g)` and the seed
            /// record they were generated with, validating them by FIPS 186-4
            /// A.1.1.3 (`p` and `q` are the primes A.1.1.2 finds from that
            /// seed, at that counter, with that hash) and A.2.4 (`g` is the
            /// generator A.2.3 derives for that index). Returns `None` if
            /// either fails. A.1.1.3's first steps admit only the four
            /// `(L, N)` pairs of §4.2, decided from the bit lengths before
            /// any arithmetic.
            ///
            /// A.1.1.3 calls for the probabilistic primality tests of
            /// Appendix C.3, whose Miller-Rabin bases come from a random bit
            /// generator. This validation has none to hand, so it uses the
            /// crate's hardened test ([`is_probable_prime_untrusted`])
            /// instead: twelve fixed bases and then 64 derived from the
            /// candidate by SHAKE256 — at least the iterations Table C.1
            /// requires at any approved size, but not drawn from an RBG.
            ///
            /// Validation repeats the generator's search for `p`, so it costs
            /// about as much as generating the parameters did.
            ///
            /// [`is_probable_prime_untrusted`]: crate::public_key::primes::is_probable_prime_untrusted
            #[must_use]
            pub fn with_seed(
                p: crate::vt::BigUint,
                q: crate::vt::BigUint,
                g: crate::vt::BigUint,
                seed: crate::public_key::primes::FfcSeed,
            ) -> Option<Self> {
                crate::public_key::primes::FfcDomain::with_seed(p, q, g, seed).map(Self::from_domain)
            }

            /// The prime modulus `p`.
            #[must_use]
            pub fn modulus(&self) -> &crate::vt::BigUint {
                self.domain.p()
            }

            /// The prime subgroup order `q`, a divisor of `p − 1`.
            #[must_use]
            pub fn subgroup_order(&self) -> &crate::vt::BigUint {
                self.domain.q()
            }

            /// The generator `g` of the order-`q` subgroup of `Z_p*`.
            #[must_use]
            pub fn generator(&self) -> &crate::vt::BigUint {
                self.domain.g()
            }

            /// The FIPS 186-4 seed record — hash, `domain_parameter_seed`,
            /// `counter`, and A.2.3 `index` — when the parameters have one.
            #[must_use]
            pub fn seed(&self) -> Option<&crate::public_key::primes::FfcSeed> {
                self.domain.seed()
            }

            pub(crate) fn from_domain(domain: crate::public_key::primes::FfcDomain) -> Self {
                Self { domain }
            }

            /// Encode as the crate's bare DER `SEQUENCE` of non-negative
            /// `INTEGER`s: `p`, `q`, `g`, and — when the parameters carry a
            /// FIPS 186-4 seed — `hash`, `seedlen`, `domain_parameter_seed`,
            /// `counter`, `index`. `hash` is the last arc of the hash
            /// function's NIST object identifier (SHA-256 1, SHA-384 2,
            /// SHA-512 3, SHA-224 4, SHA-512/224 5, SHA-512/256 6) and
            /// `seedlen` is in bits, so a seed beginning with zero bytes
            /// keeps its length.
            #[must_use]
            pub fn to_key_blob(&self) -> ::std::vec::Vec<u8> {
                let fields = self.domain.serial_fields();
                let refs: ::std::vec::Vec<&crate::vt::BigUint> = fields.iter().collect();
                crate::public_key::io::encode_biguints(&refs)
            }

            /// Decode either form of [`Self::to_key_blob`]. Three fields are
            /// validated as [`Self::new`] validates them, eight as
            /// [`Self::with_seed`] does; a seed record must also be well
            /// formed (a known hash code, a byte-aligned `seedlen` of at most
            /// 65536 bits that holds the seed, a 16-bit `counter`, an 8-bit
            /// `index`).
            #[must_use]
            pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
                let fields = crate::public_key::io::decode_biguints(blob)?;
                crate::public_key::primes::FfcDomain::from_serial_fields(fields)
                    .map(Self::from_domain)
            }

            /// Encode as PEM text armor over [`Self::to_key_blob`], using the
            /// crate-defined label.
            #[must_use]
            pub fn to_pem(&self) -> ::std::string::String {
                crate::public_key::io::pem_wrap($label, &self.to_key_blob())
            }

            /// Decode from the crate-defined PEM label, validating as
            /// [`Self::from_key_blob`] does.
            #[must_use]
            pub fn from_pem(pem: &str) -> Option<Self> {
                let blob = crate::public_key::io::pem_unwrap($label, pem)?;
                Self::from_key_blob(&blob)
            }

            /// Encode as the crate's flat XML form (fixed field order,
            /// uppercase hexadecimal values), with the fields of
            /// [`Self::to_key_blob`].
            #[must_use]
            pub fn to_xml(&self) -> ::std::string::String {
                self.domain.to_xml($root)
            }

            /// Decode either XML form, validating as [`Self::from_key_blob`]
            /// does.
            #[must_use]
            pub fn from_xml(xml: &str) -> Option<Self> {
                crate::public_key::primes::FfcDomain::from_xml($root, xml).map(Self::from_domain)
            }
        }
    };
}
pub(crate) use impl_ffc_params;

// ─── Toy groups: outside FIPS 186-4 ─────────────────────────────────────────

/// The bit lengths [`generate_toy_prime_order_group`] accepts: from 19 (the
/// least at which its subgroup/cofactor split can reach the requested length)
/// to 1023, one below the smallest `L` FIPS 186-4 §4.2 approves, so the
/// non-standard generator never serves a size a standard covers.
pub(crate) const TOY_GROUP_BITS: core::ops::RangeInclusive<usize> = 19..=1023;

/// Generate a prime-order subgroup `(p, q, g)` of `Z_p^*` with
/// `bits(p) = bits`, at a size FIPS 186-4 does not define.
///
/// **This is not FIPS 186-4**, and nothing about it follows a standard; it
/// exists so tests can use groups small enough to generate in a debug build.
/// It splits `N = clamp(⌊L/4⌋, 16, 256)` (no approved `(L, N)` pair; the
/// floor is [`MIN_SUBGROUP_ORDER_BITS`], so every toy group passes the size
/// policy), draws a random probable-prime `q` and random even cofactors `k` until
/// `p = kq + 1` is a fixed-base probable prime of the right length, and takes
/// `g = h^k mod p` for random `h` (the shape of A.2.1, at a size A.2.1 does
/// not cover). It keeps no seed, so a third party can check the structure of
/// the result but not how it was generated.
fn generate_toy_prime_order_group<R: Csprng>(
    rng: &mut R,
    bits: usize,
) -> Option<(BigUint, BigUint, BigUint)> {
    if !TOY_GROUP_BITS.contains(&bits) {
        return None;
    }
    let subgroup_bits = (bits / 4).clamp(16, 256);
    let cofactor_bits = bits - subgroup_bits;
    let one = BigUint::one();
    loop {
        let q = random_probable_prime(rng, subgroup_bits)?;
        for _ in 0..256 {
            let cofactor = random_even_with_bits(rng, cofactor_bits)?;
            let p = cofactor.mul(&q).add(&one);
            if p.bits() != bits || !is_probable_prime(&p) {
                continue;
            }
            let g = find_subgroup_generator(rng, &p, &cofactor);
            return Some((p, q, g));
        }
    }
}

/// A random `bits`-bit even integer with its top bit set: a toy-group
/// cofactor `k` in `p = kq + 1`.
fn random_even_with_bits<R: Csprng>(rng: &mut R, bits: usize) -> Option<BigUint> {
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
        // An even cofactor gives p - 1 = kq an explicit factor of two; an
        // odd cofactor of 1 would collapse the subgroup into the full group.
        bytes[last] &= !1;
        let candidate = BigUint::from_be_bytes(&bytes);
        crate::ct::zeroize_slice(bytes.as_mut_slice());
        if !candidate.is_zero() {
            return Some(candidate);
        }
    }
}

/// `g = h^k mod p` for random `h ∈ [1, p − 1)`, retried until `g ≠ 1`.
fn find_subgroup_generator<R: Csprng>(rng: &mut R, prime: &BigUint, cofactor: &BigUint) -> BigUint {
    let one = BigUint::one();
    let upper = prime.sub(&one);
    loop {
        let candidate = random_nonzero_below(rng, &upper)
            .expect("prime > 2 leaves a non-zero subgroup-generator search range");
        // (h^k)^q = h^(p − 1) = 1, so h^k lies in the order-q subgroup; the
        // only bad case is the identity.
        let generator = mod_pow(&candidate, cofactor, prime);
        if generator != one {
            return generator;
        }
    }
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

/// Draw a random integer in `[0, upper_exclusive)`, uniformly by rejection
/// sampling ([`rump::random::random_below`]); `None` when the range is empty.
///
/// # Panics
///
/// Panics, as rump's sampler does, after 256 consecutive rejected draws.
/// Each draw is accepted with probability at least one half, so a working
/// source trips this with probability at most `2^-256`; it reports a source
/// whose output stays in the rejected region — a stalled or constant
/// generator — rather than looping on it.
#[must_use]
pub fn random_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    rump::random::random_below(&mut CsprngSource(rng), upper_exclusive)
}

/// Draw a random integer in `[1, upper_exclusive)`, uniformly
/// ([`rump::random::random_nonzero_below`]); `None` when
/// `upper_exclusive ≤ 1`.
///
/// # Panics
///
/// Panics, as rump's sampler does, after 256 consecutive rejected draws:
/// either 256 out-of-range draws in a row (see [`random_below`]) or 256
/// zero draws in a row, which a working source produces with probability at
/// most `2^-256`. This is the report a stalled source gets from every
/// generator and signer built on this function.
#[must_use]
pub fn random_nonzero_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    rump::random::random_nonzero_below(&mut CsprngSource(rng), upper_exclusive)
}

/// Draw a random integer in `[1, upper_exclusive)` that is coprime to
/// `coprime_to` ([`rump::random::random_coprime_below`]).
///
/// This is the nonce sampler used by schemes such as Paillier that need a
/// fresh random unit modulo `n`.
///
/// # Panics
///
/// Panics, as rump's sampler does, when the same rejected candidate is drawn
/// 256 times in a row (a pinned source), or as [`random_nonzero_below`]
/// does if the source stalls below the range. No bound on the number of
/// distinct rejected candidates exists here: a modulus with few units below
/// the bound legitimately rejects many draws, so a source that cycles among
/// several non-units is not detected and remains the caller's to avoid.
#[must_use]
pub fn random_coprime_below<R: Csprng>(
    rng: &mut R,
    upper_exclusive: &BigUint,
    coprime_to: &BigUint,
) -> Option<BigUint> {
    rump::random::random_coprime_below(&mut CsprngSource(rng), upper_exclusive, coprime_to)
}

/// Draw a probable prime with the requested bit length
/// ([`rump::random::random_probable_prime`]); `None` when `bits < 2`.
///
/// # Panics
///
/// Panics, as rump's sampler does, when the same composite candidate is
/// drawn 256 times in a row (a constant source), or when `64 · bits`
/// candidates in a row are all composite, which a working source produces
/// with probability below `e^-111` at any width.
#[must_use]
pub fn random_probable_prime<R: Csprng>(rng: &mut R, bits: usize) -> Option<BigUint> {
    rump::random::random_probable_prime(&mut CsprngSource(rng), bits)
}

/// NIST CAVP vectors for FIPS 186-4 domain parameters, parsed for the tests
/// of this module and of the schemes built on it.
#[cfg(test)]
pub(crate) mod cavp {
    use super::{canonical_generator, FfcHash, FfcParameterSize, FfcSeed};
    use crate::test_utils::decode_hex;
    use rump::BigUint;

    /// NIST CAVP PQGVer.rsp and PQGGen.rsp, SHA-2 groups; the file header
    /// records the source archive and what was copied.
    const CAVP_VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/fips186_4_ffc_domain_parameters.txt"
    ));

    /// One CAVP record: its section, its `[mod = …]` group, and its
    /// `key = value` lines.
    pub(crate) struct CavpRecord {
        pub(crate) section: &'static str,
        pub(crate) size: FfcParameterSize,
        pub(crate) hash: FfcHash,
        fields: Vec<(&'static str, &'static str)>,
    }

    impl CavpRecord {
        pub(crate) fn has(&self, key: &str) -> bool {
            self.fields.iter().any(|(name, _)| *name == key)
        }

        pub(crate) fn value(&self, key: &str) -> &'static str {
            self.fields
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| *value)
                .unwrap_or_else(|| panic!("{} has no {key}", self.describe()))
        }

        pub(crate) fn bytes(&self, key: &str) -> Vec<u8> {
            decode_hex(self.value(key))
        }

        pub(crate) fn integer(&self, key: &str) -> BigUint {
            BigUint::from_str_radix(self.value(key), 16)
                .unwrap_or_else(|| panic!("{}: {key} is not hexadecimal", self.describe()))
        }

        pub(crate) fn counter(&self, key: &str) -> u16 {
            self.value(key)
                .parse()
                .expect("a decimal counter below 2^16")
        }

        pub(crate) fn index(&self) -> u8 {
            u8::from_str_radix(self.value("index"), 16).expect("a one-byte hex index")
        }

        /// `Result = P (…)` is VALID and `Result = F (…)` INVALID.
        pub(crate) fn expected_valid(&self) -> bool {
            match self.value("Result").as_bytes().first() {
                Some(b'P') => true,
                Some(b'F') => false,
                _ => panic!("{}: unrecognized Result", self.describe()),
            }
        }

        pub(crate) fn describe(&self) -> String {
            let first = self.fields.first().map_or("", |(_, value)| value);
            format!(
                "{} {:?}/{:?} record {}…",
                self.section,
                self.size,
                self.hash,
                &first[..first.len().min(16)]
            )
        }

        /// A.2.3/A.2.4's `domain_parameter_seed`; for primes from Shawe-Taylor
        /// it is `firstseed || pseed || qseed` (A.2.3).
        pub(crate) fn generator_seed(&self) -> Vec<u8> {
            if self.has("domain_parameter_seed") {
                self.bytes("domain_parameter_seed")
            } else {
                [
                    self.bytes("firstseed"),
                    self.bytes("pseed"),
                    self.bytes("qseed"),
                ]
                .concat()
            }
        }
    }

    fn parse_group(spec: &str) -> (FfcParameterSize, FfcHash) {
        let mut parts = spec.split(", ");
        let mut length = |prefix: &str| -> usize {
            parts
                .next()
                .and_then(|part| part.strip_prefix(prefix))
                .and_then(|digits| digits.parse().ok())
                .unwrap_or_else(|| panic!("group {spec} lacks {prefix}"))
        };
        let l = length("L=");
        let n = length("N=");
        let hash = match parts.next() {
            Some("SHA-224") => FfcHash::Sha224,
            Some("SHA-256") => FfcHash::Sha256,
            Some("SHA-384") => FfcHash::Sha384,
            Some("SHA-512") => FfcHash::Sha512,
            other => panic!("unexpected hash {other:?} in group {spec}"),
        };
        let size = FfcParameterSize::from_lengths(l, n).expect("CAVP groups use approved sizes");
        (size, hash)
    }

    /// Every record of the section whose header starts with `section`.
    pub(crate) fn records(section: &str) -> Vec<CavpRecord> {
        let mut records = Vec::new();
        let mut current_section = "";
        let mut group = None;
        let mut fields = Vec::new();
        for line in CAVP_VECTORS.lines().chain(core::iter::once("")) {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if line.is_empty() || line.starts_with('[') {
                if !fields.is_empty() {
                    let (size, hash) = group.expect("records sit inside a [mod = …] group");
                    records.push(CavpRecord {
                        section: current_section,
                        size,
                        hash,
                        fields: core::mem::take(&mut fields),
                    });
                }
                if let Some(spec) = line
                    .strip_prefix("[mod = ")
                    .and_then(|rest| rest.strip_suffix(']'))
                {
                    group = Some(parse_group(spec));
                } else if line.starts_with('[') {
                    current_section = line;
                    group = None;
                }
                continue;
            }
            let (key, value) = line.split_once(" = ").expect("key = value");
            fields.push((key, value));
        }
        records.retain(|record| record.section.starts_with(section));
        assert!(!records.is_empty(), "no CAVP records under {section}");
        records
    }

    /// FIPS 186-4 parameters from CAVP for tests here and in the schemes built on
    /// them: the 1024-bit A.1.1.2 record with the smallest counter (so validating
    /// it stays quick in a debug build), with its A.2.3 generator for `index`.
    pub(crate) fn fips186_4_1024_parts(index: u8) -> (BigUint, BigUint, BigUint, FfcSeed) {
        let records = records("[A.1.1.2");
        let record = records
            .iter()
            .filter(|record| record.size.l() == 1024)
            .min_by_key(|record| record.counter("counter"))
            .expect("1024-bit records exist");
        let (p, q) = (record.integer("P"), record.integer("Q"));
        let seed_bytes = record.bytes("domain_parameter_seed");
        let g = canonical_generator(&p, &q, record.hash, &seed_bytes, index).expect("a generator");
        let seed = FfcSeed::new(record.hash, &seed_bytes, record.counter("counter"), index);
        (p, q, g, seed)
    }
}

#[cfg(test)]
mod tests {
    use super::cavp::{self, CavpRecord};
    use super::{
        canonical_generator, generate_toy_prime_order_group, is_in_prime_order_subgroup,
        is_probable_prime_fips186_4, is_probable_prime_untrusted, probable_primes_from_seed,
        random_nonzero_below, validate_canonical_generator, validate_prime_order_group,
        validate_probable_primes, within_group_size_bounds, FfcDomain, FfcHash, FfcParameterSize,
        FfcSeed, PrimalityPolicy, MAX_MODULUS_BITS, MAX_PARSED_SEEDLEN, MAX_SUBGROUP_ORDER_BITS,
    };
    use crate::{Csprng, CtrDrbgAes256};
    use rump::number_theory::is_probable_prime;
    use rump::BigUint;

    fn a014233_12() -> BigUint {
        // A014233(12) = 318665857834031151167461.
        let ten18 = BigUint::from_u64(1_000_000_000_000_000_000);
        BigUint::from_u64(318_665)
            .mul(&ten18)
            .add(&BigUint::from_u64(857_834_031_151_167_461))
    }

    #[test]
    fn untrusted_hardening_rejects_pseudoprime_that_fools_fixed_bases() {
        // A014233(12) = 318665857834031151167461 is the smallest strong
        // pseudoprime to the first twelve prime bases {2,3,…,37} — exactly this
        // crate's fixed MR_BASES. The fixed-base test is therefore fooled into
        // accepting it, while the candidate-derived hardened witnesses reject
        // it. (Its prime factors exceed the trial-division sieve, so it reaches
        // the Miller-Rabin stage.)
        let spsp = a014233_12();
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

    // ── FIPS 186-4: sizes, hashes, the generation-time C.3 test ─────────────

    #[test]
    fn approved_sizes_are_exactly_section_4_2() {
        let pairs: Vec<(usize, usize)> = FfcParameterSize::ALL
            .iter()
            .map(|size| (size.l(), size.n()))
            .collect();
        assert_eq!(pairs, [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]);
        for size in FfcParameterSize::ALL {
            assert_eq!(
                FfcParameterSize::from_lengths(size.l(), size.n()),
                Some(size)
            );
        }
        for (l, n) in [
            (1024, 224),
            (2048, 160),
            (3072, 224),
            (4096, 256),
            (512, 160),
        ] {
            assert_eq!(FfcParameterSize::from_lengths(l, n), None, "({l}, {n})");
        }
    }

    #[test]
    fn hash_codes_round_trip_and_unknown_codes_are_refused() {
        for hash in [
            FfcHash::Sha224,
            FfcHash::Sha256,
            FfcHash::Sha384,
            FfcHash::Sha512,
            FfcHash::Sha512_224,
            FfcHash::Sha512_256,
        ] {
            assert_eq!(
                FfcHash::from_hash_algs_arc(hash.hash_algs_arc()),
                Some(hash)
            );
            assert_eq!(hash.digest(b"abc").len() * 8, hash.output_bits());
        }
        assert_eq!(FfcHash::from_hash_algs_arc(0), None);
        assert_eq!(FfcHash::from_hash_algs_arc(7), None);
    }

    #[test]
    fn generation_primality_test_accepts_primes_and_rejects_pseudoprimes() {
        let mut rng = CtrDrbgAes256::new(&[0x41; 48]);
        let p = cavp::records("[A.1.1.2")[0].integer("P");
        assert!(is_probable_prime_fips186_4(&p, 3, &mut rng));
        // p + 2 is even; p·q is composite with no small factor.
        assert!(!is_probable_prime_fips186_4(
            &p.add(&BigUint::from_u64(2)),
            3,
            &mut rng
        ));
        let q = cavp::records("[A.1.1.2")[0].integer("Q");
        assert!(!is_probable_prime_fips186_4(&p.mul(&q), 3, &mut rng));
        // A strong pseudoprime to bases 2 through 37 survives the base-2
        // screen; zero random rounds leave only the Lucas stage to reject it.
        assert!(!is_probable_prime_fips186_4(&a014233_12(), 0, &mut rng));
        assert!(!is_probable_prime_fips186_4(&a014233_12(), 19, &mut rng));
    }

    // ── FIPS 186-4 against NIST CAVP (tests/vectors) ────────────────────────

    /// The primality test validators run inside A.1.1.3.
    fn hardened(candidate: &BigUint, _rounds: usize) -> bool {
        is_probable_prime_untrusted(candidate)
    }

    fn check_a113(record: &CavpRecord) {
        let seed = FfcSeed::new(record.hash, &record.bytes("Seed"), record.counter("c"), 0);
        let verdict = validate_probable_primes(
            &record.integer("P"),
            &record.integer("Q"),
            &seed,
            &mut hardened,
        );
        assert_eq!(verdict, record.expected_valid(), "{}", record.describe());
    }

    /// The record with the smallest counter in each 1024-bit hash group: the
    /// cheapest representatives of the records that test every candidate for
    /// `p` up to their counter, which the default run takes.
    fn cheapest_1024_bit_record_per_hash<'r>(
        records: impl Iterator<Item = &'r CavpRecord>,
        counter_key: &str,
    ) -> Vec<&'r CavpRecord> {
        let mut chosen: Vec<&CavpRecord> = Vec::new();
        for record in records.filter(|record| record.size.l() == 1024) {
            match chosen.iter_mut().find(|kept| kept.hash == record.hash) {
                Some(kept) if kept.counter(counter_key) > record.counter(counter_key) => {
                    *kept = record;
                }
                Some(_) => {}
                None => chosen.push(record),
            }
        }
        chosen
    }

    #[test]
    fn cavp_a113_every_invalid_case_and_a_valid_case_per_1024_bit_hash() {
        // Every INVALID record, at every size, is refused before a single
        // candidate for p is tested. A VALID record tests every candidate up
        // to its counter, so the default run takes the cheapest one per
        // 1024-bit hash and the ignored test below takes them all.
        let records = cavp::records("[A.1.1.3");
        assert_eq!(records.len(), 70);
        let invalid: Vec<&CavpRecord> = records
            .iter()
            .filter(|record| !record.expected_valid())
            .collect();
        assert_eq!(invalid.len(), 42);
        let valid = cheapest_1024_bit_record_per_hash(
            records.iter().filter(|record| record.expected_valid()),
            "c",
        );
        assert_eq!(valid.len(), 4);
        for record in invalid.into_iter().chain(valid) {
            check_a113(record);
        }
    }

    #[test]
    #[ignore = "A.1.1.3 on every valid record, up to 3072 bits, is slow in debug; run with --release --ignored"]
    fn cavp_a113_every_valid_case() {
        let records = cavp::records("[A.1.1.3");
        let valid: Vec<&CavpRecord> = records
            .iter()
            .filter(|record| record.expected_valid())
            .collect();
        assert_eq!(valid.len(), 28);
        for record in valid {
            check_a113(record);
        }
    }

    fn check_a112(record: &CavpRecord, rng: &mut CtrDrbgAes256) {
        let seed = record.bytes("domain_parameter_seed");
        let mut test = |candidate: &BigUint, rounds: usize| {
            is_probable_prime_fips186_4(candidate, rounds, rng)
        };
        let (p, q, counter) = probable_primes_from_seed(record.size, record.hash, &seed, &mut test)
            .unwrap_or_else(|| panic!("{}: the seed yields no primes", record.describe()));
        assert_eq!(p, record.integer("P"), "{}", record.describe());
        assert_eq!(q, record.integer("Q"), "{}", record.describe());
        assert_eq!(counter, record.counter("counter"), "{}", record.describe());
    }

    #[test]
    fn cavp_a112_seed_reproduces_p_q_and_counter_per_1024_bit_hash() {
        let mut rng = CtrDrbgAes256::new(&[0x18; 48]);
        let records = cavp::records("[A.1.1.2");
        assert_eq!(records.len(), 70);
        let cheapest = cheapest_1024_bit_record_per_hash(records.iter(), "counter");
        assert_eq!(cheapest.len(), 4);
        for record in cheapest {
            check_a112(record, &mut rng);
        }
    }

    #[test]
    #[ignore = "A.1.1.2 from every CAVP seed, up to 3072 bits, is slow in debug; run with --release --ignored"]
    fn cavp_a112_every_seed_reproduces_p_q_and_counter() {
        let mut rng = CtrDrbgAes256::new(&[0x19; 48]);
        for record in &cavp::records("[A.1.1.2") {
            check_a112(record, &mut rng);
        }
    }

    #[test]
    fn cavp_a23_canonical_generators() {
        let records = cavp::records("[A.2.3");
        assert_eq!(records.len(), 70);
        for record in &records {
            let g = canonical_generator(
                &record.integer("P"),
                &record.integer("Q"),
                record.hash,
                &record.generator_seed(),
                record.index(),
            );
            assert_eq!(g, Some(record.integer("G")), "{}", record.describe());
        }
    }

    #[test]
    fn cavp_a24_verdicts() {
        let records = cavp::records("[A.2.4");
        assert_eq!(records.len(), 70);
        let mut verdicts = [0usize; 2];
        for record in &records {
            let seed = FfcSeed::new(record.hash, &record.generator_seed(), 0, record.index());
            let verdict = validate_canonical_generator(
                &record.integer("P"),
                &record.integer("Q"),
                &record.integer("G"),
                &seed,
            );
            assert_eq!(verdict, record.expected_valid(), "{}", record.describe());
            verdicts[usize::from(verdict)] += 1;
        }
        assert_eq!(verdicts, [42, 28]);
    }

    // ── FIPS 186-4 preconditions and the seeded domain type ─────────────────

    #[test]
    fn a113_preconditions_are_enforced() {
        let (p, q, _, seed) = cavp::fips186_4_1024_parts(1);
        let bytes = seed.domain_parameter_seed().to_vec();
        let valid = |seed: &FfcSeed| validate_probable_primes(&p, &q, seed, &mut hardened);
        assert!(valid(&seed));
        // Step 4: counter > 4L − 1.
        assert!(!valid(&FfcSeed::new(seed.hash(), &bytes, 4096, 1)));
        // Step 6: seedlen < N (the seed's last byte dropped).
        assert!(!valid(&FfcSeed::new(
            seed.hash(),
            &bytes[..bytes.len() - 1],
            seed.counter(),
            1
        )));
        // A different hash, a different seed, a different counter.
        let other_hash = if seed.hash() == FfcHash::Sha256 {
            FfcHash::Sha512
        } else {
            FfcHash::Sha256
        };
        assert!(!valid(&FfcSeed::new(other_hash, &bytes, seed.counter(), 1)));
        let mut flipped = bytes.clone();
        flipped[0] ^= 1;
        assert!(!valid(&FfcSeed::new(
            seed.hash(),
            &flipped,
            seed.counter(),
            1
        )));
        assert!(!valid(&FfcSeed::new(
            seed.hash(),
            &bytes,
            seed.counter() + 1,
            1
        )));
        assert!(!valid(&FfcSeed::new(
            seed.hash(),
            &bytes,
            seed.counter() - 1,
            1
        )));
        // Steps 1–3: an (L, N) pair §4.2 does not list.
        let toy_p = BigUint::from_u64(23);
        let toy_q = BigUint::from_u64(11);
        assert!(!validate_probable_primes(
            &toy_p,
            &toy_q,
            &seed,
            &mut hardened
        ));
        // A.1.1.2's hash-length precondition: a 256-bit q can never come from
        // SHA-224, whatever the seed.
        let wide = cavp::records("[A.1.1.3")
            .into_iter()
            .find(|record| record.size.n() == 256 && record.expected_valid())
            .expect("a valid N = 256 record");
        let short_hash = FfcSeed::new(FfcHash::Sha224, &wide.bytes("Seed"), wide.counter("c"), 0);
        assert!(!validate_probable_primes(
            &wide.integer("P"),
            &wide.integer("Q"),
            &short_hash,
            &mut hardened
        ));
    }

    #[test]
    fn a112_refuses_short_hashes_and_seeds() {
        let mut rng = CtrDrbgAes256::new(&[0x20; 48]);
        let mut test = |candidate: &BigUint, rounds: usize| {
            is_probable_prime_fips186_4(candidate, rounds, &mut rng)
        };
        let size = FfcParameterSize::L2048N256;
        assert!(probable_primes_from_seed(size, FfcHash::Sha224, &[7; 32], &mut test).is_none());
        assert!(probable_primes_from_seed(size, FfcHash::Sha256, &[7; 31], &mut test).is_none());
        assert!(FfcDomain::generate_fips186_4(
            &mut CtrDrbgAes256::new(&[1; 48]),
            size,
            FfcHash::Sha224,
            1
        )
        .is_none());
        assert!(FfcDomain::generate_fips186_4(
            &mut CtrDrbgAes256::new(&[1; 48]),
            size,
            FfcHash::Sha512_224,
            1
        )
        .is_none());
    }

    #[test]
    fn seeded_domain_round_trips_and_rejects_every_tampered_field() {
        let (p, q, g, seed) = cavp::fips186_4_1024_parts(1);
        let domain = FfcDomain::with_seed(p.clone(), q.clone(), g.clone(), seed.clone())
            .expect("CAVP parameters validate");
        assert_eq!(domain.seed(), Some(&seed));
        let fields = domain.serial_fields();
        assert_eq!(fields.len(), 8);
        assert_eq!(
            FfcDomain::from_serial_fields(fields.clone()),
            Some(domain.clone())
        );
        let xml = domain.to_xml("Params");
        assert!(xml.contains("<domain-parameter-seed>"));
        assert_eq!(FfcDomain::from_xml("Params", &xml), Some(domain.clone()));

        // The seedless form is still read, and written for seedless parameters.
        let plain = FfcDomain::from_serial_fields(fields[..3].to_vec()).expect("three fields");
        assert_eq!(plain.seed(), None);
        assert_eq!(plain.serial_fields(), fields[..3].to_vec());
        assert_eq!(
            FfcDomain::from_xml("Params", &plain.to_xml("Params")),
            Some(plain)
        );

        let u = BigUint::from_u64;
        let with = |position: usize, value: BigUint| {
            let mut tampered = fields.clone();
            tampered[position] = value;
            FfcDomain::from_serial_fields(tampered)
        };
        let twice_q = q.add(&q);
        // p, q, g: another member of the same congruence class, the next odd
        // number, and another element of the subgroup.
        assert!(with(0, p.add(&twice_q)).is_none());
        assert!(with(1, q.add(&u(2))).is_none());
        assert!(with(2, BigUint::mod_mul(&g, &g, &p)).is_none());
        // hash: another approved hash, and codes that name none.
        let other_hash = if seed.hash() == FfcHash::Sha256 { 3 } else { 1 };
        for code in [other_hash, 0, 7] {
            assert!(with(3, u(code)).is_none(), "hash code {code}");
        }
        // seedlen: one more byte (a leading zero changes the seed), one fewer
        // (the value no longer fits), not byte-aligned, and over the bound.
        let seedlen = seed.seedlen() as u64;
        for bits in [
            seedlen + 8,
            seedlen - 8,
            seedlen + 1,
            (MAX_PARSED_SEEDLEN as u64) + 8,
        ] {
            assert!(with(4, u(bits)).is_none(), "seedlen {bits}");
        }
        // seed, counter, index.
        assert!(with(5, fields[5].add(&u(1))).is_none());
        let counter = u64::from(seed.counter());
        for value in [counter + 1, counter - 1, 65_536] {
            assert!(with(6, u(value)).is_none(), "counter {value}");
        }
        for value in [2, 0, 256] {
            assert!(with(7, u(value)).is_none(), "index {value}");
        }
        // Every field count but three and eight.
        for count in [0, 1, 2, 4, 5, 6, 7] {
            assert!(
                FfcDomain::from_serial_fields(fields[..count].to_vec()).is_none(),
                "{count} fields"
            );
        }
        let mut nine = fields.clone();
        nine.push(u(0));
        assert!(FfcDomain::from_serial_fields(nine).is_none());
    }

    #[test]
    fn fips_generation_at_1024_bits_validates_as_a_third_party_would() {
        let mut rng = CtrDrbgAes256::new(&[0x21; 48]);
        let domain = FfcDomain::generate_fips186_4(
            &mut rng,
            FfcParameterSize::L1024N160,
            FfcHash::Sha256,
            1,
        )
        .expect("SHA-256 is long enough for N = 160");
        let seed = domain
            .seed()
            .expect("generated parameters carry their seed")
            .clone();
        assert_eq!(seed.seedlen(), 160);
        assert_eq!(seed.index(), 1);
        assert_eq!(domain.p().bits(), 1024);
        assert_eq!(domain.q().bits(), 160);
        let revalidated = FfcDomain::with_seed(
            domain.p().clone(),
            domain.q().clone(),
            domain.g().clone(),
            seed,
        )
        .expect("A.1.1.3 and A.2.4 accept what A.1.1.2 and A.2.3 produced");
        assert_eq!(revalidated, domain);
    }

    #[test]
    #[ignore = "timing report for every approved size; run with --release --ignored --nocapture"]
    fn fips_generation_timing_at_every_approved_size() {
        let mut rng = CtrDrbgAes256::new(&[0x22; 48]);
        for size in FfcParameterSize::ALL {
            let hash = if size.n() <= 224 {
                FfcHash::Sha224
            } else {
                FfcHash::Sha256
            };
            for run in 0..3 {
                let started = std::time::Instant::now();
                let domain =
                    FfcDomain::generate_fips186_4(&mut rng, size, hash, 1).expect("generate");
                let generated = started.elapsed();
                let seed = domain.seed().expect("seed").clone();
                let started = std::time::Instant::now();
                let validated = FfcDomain::with_seed(
                    domain.p().clone(),
                    domain.q().clone(),
                    domain.g().clone(),
                    seed.clone(),
                );
                let validation = started.elapsed();
                assert_eq!(validated.as_ref(), Some(&domain));
                println!(
                    "L={} N={} {:?} run {run}: generate {:.3} s (counter {}), validate {:.3} s",
                    size.l(),
                    size.n(),
                    hash,
                    generated.as_secs_f64(),
                    seed.counter(),
                    validation.as_secs_f64()
                );
            }
        }
    }

    // ── Size policy ─────────────────────────────────────────────────────────

    /// The bounds are decided from the bit lengths alone, before any
    /// primality test: 2^16384 + 1 and a 513-bit q are refused in the time a
    /// comparison takes, the smallest admissible subgroup (q = 32771 in
    /// Z_65543*) is accepted, and prime-order subgroups below 2^15 — q = 2
    /// and q = 11 in Z_23* — are refused although every other check would
    /// pass them.
    #[test]
    fn size_policy_is_checked_before_arithmetic() {
        let u = BigUint::from_u64;
        assert!(validate_prime_order_group(
            &u(65543),
            &u(32771),
            &u(4),
            PrimalityPolicy::Structural
        ));
        assert!(validate_prime_order_group(
            &u(65543),
            &u(32771),
            &u(4),
            PrimalityPolicy::Hardened
        ));
        for (p, q, g) in [(23u64, 2u64, 22u64), (23, 11, 4)] {
            assert!(is_in_prime_order_subgroup(&u(g), &u(q), &u(p)));
            assert!(!validate_prime_order_group(
                &u(p),
                &u(q),
                &u(g),
                PrimalityPolicy::Hardened
            ));
        }
        let mut wide_p = BigUint::zero();
        wide_p.set_bit(MAX_MODULUS_BITS);
        wide_p = wide_p.add(&BigUint::one());
        let mut wide_q = BigUint::zero();
        wide_q.set_bit(MAX_SUBGROUP_ORDER_BITS);
        wide_q = wide_q.add(&BigUint::one());
        let (p, q, g, _) = cavp::fips186_4_1024_parts(1);
        let elapsed = crate::test_utils::fastest_of_three(|| {
            assert!(!within_group_size_bounds(&wide_p, &q));
            assert!(!within_group_size_bounds(&p, &wide_q));
            assert!(!validate_prime_order_group(
                &wide_p,
                &q,
                &g,
                PrimalityPolicy::Structural
            ));
            assert!(!validate_prime_order_group(
                &p,
                &wide_q,
                &g,
                PrimalityPolicy::Structural
            ));
            assert!(FfcDomain::new(wide_p.clone(), q.clone(), g.clone()).is_none());
            assert!(FfcDomain::new(p.clone(), wide_q.clone(), g.clone()).is_none());
        });
        assert!(
            elapsed < crate::test_utils::REFUSAL_BOUND,
            "an oversized group must be refused without a primality test: {elapsed:?}"
        );
        assert!(within_group_size_bounds(&p, &q));
        // The largest sizes FIPS 186-4 defines sit inside the bounds.
        let mut p3072 = BigUint::zero();
        p3072.set_bit(3071);
        let mut q256 = BigUint::zero();
        q256.set_bit(255);
        assert!(within_group_size_bounds(&p3072, &q256));
    }

    // ── Toy groups ──────────────────────────────────────────────────────────

    #[test]
    fn toy_generator_serves_only_sizes_below_fips() {
        let mut rng = CtrDrbgAes256::new(&[0x23; 48]);
        for bits in [0, 1, 18, 1024, 2048, 3072] {
            assert!(
                generate_toy_prime_order_group(&mut rng, bits).is_none(),
                "{bits}"
            );
        }
        for bits in [19, 64, 256] {
            let (p, q, g) = generate_toy_prime_order_group(&mut rng, bits).expect("toy size");
            assert_eq!(p.bits(), bits);
            let domain = FfcDomain::new(p, q, g).expect("a valid prime-order subgroup");
            assert_eq!(domain.seed(), None);
        }
    }
}
