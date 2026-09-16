//! The NIST post-quantum round-3 NTRU KEM, shared by the four recommended
//! parameter sets ([`crate::public_key::ntru_hps509`] (ntruhps2048509),
//! [`crate::public_key::ntru_hps677`] (ntruhps2048677),
//! [`crate::public_key::ntru_hps821`] (ntruhps4096821) and
//! [`crate::public_key::ntru_hrss701`] (ntruhrss701)).
//!
//! # Provenance
//!
//! Everything in this module is implemented from the specification: C. Chen,
//! O. Danba, J. Hoffstein, A. Hülsing, J. Rijneveld, J. M. Schanck, T. Saito,
//! P. Schwabe, W. Whyte, K. Xagawa, T. Yamakawa and Z. Zhang, "NTRU:
//! Algorithm Specifications and Supporting Documentation", NIST PQC round 3
//! submission, 30 September 2020 (the `Supporting_Documentation/ntru.pdf` of
//! NIST's `NTRU-Round3.zip`, kept in-tree as
//! `pubs/ntru-round3-specification.pdf`). The code is a clean-room rewrite
//! from that text (the provenance record is in `AUDIT.md`); the round-3
//! reference implementation served only as a known-answer oracle, through
//! the KAT files it produced. Functions carry the specification's names
//! in snake_case (`pack_Rq0` is [`pack_rq0`], `DPKE_Decrypt` is
//! [`dpke_decrypt`], and so on) and cite its section numbers. The
//! specification leaves the inversion routines, the sort, and all internal
//! representations to the implementer (§1.8.2, §1.9, §1.10.5); those are
//! designed here and derived in their doc comments:
//!
//! - inversion in the fields S/2 and S/3 raises to the power p^(n−1) − 2
//!   (Fermat) along an Itoh–Tsujii addition chain ([`field_inverse`]);
//! - `Sq_inverse` is the specification's Newton iteration, run modulo 2^16;
//! - the ntru-hrss `Lift` divides by Φ1 with an O(n) prefix-sum recurrence
//!   derived from the definition ([`s3_divide_by_phi1`]);
//! - `Fixed_Type` sorts with Batcher's bitonic network
//!   ([`sort_u32_constant_time`]);
//! - reductions modulo 3 fold digits in radices 2^8, 2^4 and 2^2
//!   ([`ct_mod3`]); base-3 unpacking extracts digits by comparison
//!   ([`s3_digits`]).
//!
//! The correctness evidence is external: the per-set test modules reproduce
//! the four known-answer files of the round-3 package (`kat/*.rsp`, see
//! `kat/README.md`) byte for byte — keys, ciphertexts, shared secrets and
//! decapsulation. `nist_kat` replays [`KAT_DEFAULT_COUNTS`]: eight sampled
//! entries of each 100-entry file (counts 0, 1, 7, 23, 42, 67, 83, 99) in a
//! debug build, all 100 in a release build. `nist_kat_full` replays all 100
//! in any build under `cargo test --lib ntru -- --ignored`.
//!
//! # Representation
//!
//! A polynomial is a `[u16; N]` of coefficients of 1, x, …, x^(n−1), read in
//! one of three ways, named in every signature's documentation:
//!
//! - *integer polynomial*: small integers stored as `u16` two's complement,
//!   so that arithmetic modulo 2^16 is also arithmetic modulo every q that
//!   the recommended sets use (q divides 2^16);
//! - *S/3 residues*: every coefficient in {0, 1, 2}; the canonical S/3
//!   representative (spec §1.2 item 9) is the residue polynomial whose
//!   coefficient n − 1 is 0, with 2 standing for −1;
//! - *S/2 residues*: every coefficient in {0, 1}.
//!
//! # Side channels
//!
//! Sampling of every secret polynomial, key generation, encapsulation,
//! decryption, decapsulation, and the implicit-rejection selection branch
//! only on public values (n, q, the family, loop counters and buffer
//! lengths), with one exception: key generation and encapsulation branch on
//! whether their coins sampled a zero polynomial, which lies outside the
//! sample spaces ([`sample_fg`], [`sample_rm`]), and if so discard them and
//! draw again. For a uniform source that happens with probability below
//! 2^−799 per draw, and the branch concerns only coins that are never used.
//! Secret values meet only additions, subtractions, shifts,
//! bitwise masks, and multiplications; there are no secret-indexed table
//! lookups and no `/` or `%` on secret values. The polynomial multiplier
//! ([`crate::public_key::ntru_poly_mul`]) is data-independent in the same
//! sense. Two caveats: `u16`/`u32` multiplication is constant time only where
//! the processor's multiplier is (true of the AArch64, x86-64 and RISC-V cores
//! this crate targets), and the optimizer is trusted not to turn the mask
//! arithmetic back into branches. The modules stay under [`crate::vt`], this
//! crate's namespace for public-key code without independent side-channel
//! vetting.

use crate::ct::zeroize_slice;
use crate::hash::sha3::Sha3_256;
use crate::public_key::ntru_poly_mul::poly_mul_cyclic;
use crate::Csprng;

// ===========================================================================
// Parameter sets and derived constants (spec §1.3, §1.5, §1.6)
// ===========================================================================

/// The two round-3 families of parameter sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    /// ntru-hps (spec §1.3.2): L_f = L_r = T, L_g = L_m = T(q/8 − 2), and
    /// `Lift` is the identity.
    Hps,
    /// ntru-hrss (spec §1.3.3): L_f = T+, L_g = Φ1·T+, L_r = L_m = T, and
    /// `Lift(m)` = Φ1·S3(m/Φ1).
    Hrss,
}

/// One recommended parameter set (spec §1.6). `N` is the prime n; p = 3
/// throughout, and q = 2^`LOG_Q`.
pub(crate) trait ParameterSet<const N: usize> {
    /// logq = log2(q) (spec §1.5.1).
    const LOG_Q: u32;
    /// Which family's sample spaces and `Lift` apply.
    const FAMILY: Family;
}

/// prf_key_bits / 8 (spec §1.5.17).
pub(crate) const PRF_KEY_BYTES: usize = 32;

/// kem_shared_key_bits / 8 (spec §1.5.16).
pub(crate) const SHARED_KEY_BYTES: usize = 32;

/// sample_iid_bits / 8 = n − 1 (spec §1.5.2).
pub(crate) const fn sample_iid_bytes(n: usize) -> usize {
    n - 1
}

/// sample_fixed_type_bits / 8 = 30·(n − 1) / 8 (spec §1.5.3). The division
/// is exact when n ≡ 1 (mod 4), which holds for 509, 677 and 821.
pub(crate) const fn sample_fixed_type_bytes(n: usize) -> usize {
    (30 * (n - 1)).div_ceil(8)
}

/// sample_key_bits / 8 (spec §1.5.4).
pub(crate) const fn sample_key_bytes(n: usize, family: Family) -> usize {
    match family {
        Family::Hps => sample_iid_bytes(n) + sample_fixed_type_bytes(n),
        Family::Hrss => 2 * sample_iid_bytes(n),
    }
}

/// sample_plaintext_bits / 8 (spec §1.5.5), numerically equal to
/// [`sample_key_bytes`] because `Sample_rm` draws from the same kinds of
/// sampler as `Sample_fg`.
pub(crate) const fn sample_plaintext_bytes(n: usize, family: Family) -> usize {
    sample_key_bytes(n, family)
}

/// packed_s3_bytes = ⌈(n − 1)/5⌉ (spec §1.5.6).
pub(crate) const fn packed_s3_bytes(n: usize) -> usize {
    (n - 1).div_ceil(5)
}

/// packed_sq_bytes = ⌈(n − 1)·logq/8⌉ (spec §1.5.7).
pub(crate) const fn packed_sq_bytes(n: usize, log_q: u32) -> usize {
    ((n - 1) * log_q as usize).div_ceil(8)
}

/// packed_rq0_bytes = ⌈(n − 1)·logq/8⌉ (spec §1.5.8).
pub(crate) const fn packed_rq0_bytes(n: usize, log_q: u32) -> usize {
    ((n - 1) * log_q as usize).div_ceil(8)
}

/// dpke_private_key_bytes = 2·packed_s3_bytes + packed_sq_bytes (spec §1.5.10).
pub(crate) const fn dpke_private_key_bytes(n: usize, log_q: u32) -> usize {
    2 * packed_s3_bytes(n) + packed_sq_bytes(n, log_q)
}

/// dpke_plaintext_bytes = 2·packed_s3_bytes (spec §1.5.11).
pub(crate) const fn dpke_plaintext_bytes(n: usize) -> usize {
    2 * packed_s3_bytes(n)
}

/// kem_public_key_bytes = dpke_public_key_bytes = packed_rq0_bytes
/// (spec §1.5.9, §1.5.13).
pub(crate) const fn kem_public_key_bytes(n: usize, log_q: u32) -> usize {
    packed_rq0_bytes(n, log_q)
}

/// kem_private_key_bytes = dpke_private_key_bytes + prf_key_bits/8
/// (spec §1.5.14).
pub(crate) const fn kem_private_key_bytes(n: usize, log_q: u32) -> usize {
    dpke_private_key_bytes(n, log_q) + PRF_KEY_BYTES
}

/// kem_ciphertext_bytes = dpke_ciphertext_bytes = packed_rq0_bytes
/// (spec §1.5.12, §1.5.15).
pub(crate) const fn kem_ciphertext_bytes(n: usize, log_q: u32) -> usize {
    packed_rq0_bytes(n, log_q)
}

// ===========================================================================
// Constant-time integer helpers
// ===========================================================================

/// All ones when `x != 0`, zero otherwise.
///
/// For x ≠ 0, one of x and its two's-complement negation 2^32 − x lies in
/// [2^31, 2^32), so bit 31 of `x | x.wrapping_neg()` is set; for x = 0 both
/// are zero. Negating that bit gives the mask.
#[inline]
fn ct_mask_nonzero_u32(x: u32) -> u32 {
    ((x | x.wrapping_neg()) >> 31).wrapping_neg()
}

/// All ones when `a < b`, zero otherwise.
///
/// The 64-bit difference of two 32-bit values borrows into bit 63 exactly
/// when a < b.
#[inline]
fn ct_mask_lt_u32(a: u32, b: u32) -> u32 {
    let borrow = u64::from(a).wrapping_sub(u64::from(b)) >> 63;
    (borrow as u32).wrapping_neg()
}

/// `x − m` when `x ≥ m`, otherwise `x`. Requires `x < 2m` and `m ≤ 2^31`.
///
/// With those bounds |x − m| < 2^31, so the wrapped difference has bit 31
/// set exactly when x < m; in that case m is added back.
#[inline]
fn ct_reduce_once(x: u32, m: u32) -> u32 {
    let t = x.wrapping_sub(m);
    t.wrapping_add(m & (t >> 31).wrapping_neg())
}

/// `x mod 3` for any `u16`, without division.
///
/// 2^8 ≡ 2^4 ≡ 2^2 ≡ 1 (mod 3) (255 = 3·85, 15 = 3·5, 3 = 3·1), so
/// replacing a value by the sum of its high and low parts in one of those
/// radices keeps its residue. The maximum after each step, evaluated over
/// the previous step's range, is 65535 → 510 (at 65535) → 45 (at 495 and
/// 510; the parts 31 and 15 never occur together) → 13 (at 43) → 5 (at 11),
/// and one conditional subtraction of 3 lands in {0, 1, 2}. The tests
/// recompute these maxima and check every `u16`.
#[inline]
fn ct_mod3(x: u16) -> u16 {
    let mut y = u32::from(x);
    y = (y >> 8) + (y & 0xff);
    y = (y >> 4) + (y & 0x0f);
    y = (y >> 2) + (y & 0x03);
    y = (y >> 2) + (y & 0x03);
    ct_reduce_once(y, 3) as u16
}

/// Residue in {0, 1, 2} of a small signed integer held as `u16` two's
/// complement. Requires −2^14 ≤ c < 2^14.
///
/// Adding 3·2^14 = 49152, a multiple of 3, moves [−2^14, 2^14) into
/// [2^15, 2^16) without changing the residue, and [`ct_mod3`] finishes.
#[inline]
fn ct_mod3_signed(c: u16) -> u16 {
    ct_mod3(c.wrapping_add(3 << 14))
}

/// Coefficient of the canonical R/q-representative (spec §1.2 item 7): the
/// residue of `x` mod q lifted into [−q/2, q/2), as `u16` two's complement.
///
/// Shifting left by 16 − logq discards the bits at and above logq (reduction
/// mod q); the arithmetic shift back sign-extends from bit logq − 1, which is
/// set exactly for residues in [q/2, q). Shift counts are public.
#[inline]
fn centered_mod_q(x: u16, log_q: u32) -> u16 {
    let s = 16 - log_q;
    (((x << s) as i16) >> s) as u16
}

/// The integer in {−1, 0, 1} that an S/3 residue r ∈ {0, 1, 2} stands for,
/// as `u16` two's complement: r − 3·(r >> 1), since r >> 1 is 1 only for 2.
#[inline]
fn s3_residue_to_signed(r: u16) -> u16 {
    r.wrapping_sub(3 * (r >> 1))
}

/// (a + b) mod 3 for residues a, b ∈ {0, 1, 2}; the sum is at most 4 < 2·3.
#[inline]
fn s3_add(a: u16, b: u16) -> u16 {
    ct_reduce_once(u32::from(a + b), 3) as u16
}

/// (a − b) mod 3 for residues a, b ∈ {0, 1, 2}, computed as a + 3 − b ∈ [1, 5].
#[inline]
fn s3_sub(a: u16, b: u16) -> u16 {
    ct_reduce_once(u32::from(a + 3 - b), 3) as u16
}

/// −a mod 3 for a residue a ∈ {0, 1, 2}.
#[inline]
fn s3_neg(a: u16) -> u16 {
    s3_sub(0, a)
}

/// Leaves `*lo ≤ *hi`, exchanging the two values when they are out of order,
/// with the decision carried only by a mask.
#[inline]
fn ct_compare_exchange(lo: &mut u32, hi: &mut u32) {
    let exchange = ct_mask_lt_u32(*hi, *lo);
    let diff = (*lo ^ *hi) & exchange;
    *lo ^= diff;
    *hi ^= diff;
}

/// Sorts `keys` into non-decreasing order with Batcher's bitonic sorting
/// network (K. E. Batcher, "Sorting networks and their applications", AFIPS
/// Spring Joint Computer Conference 32, 1968, pp. 307–314; D. E. Knuth, *The
/// Art of Computer Programming*, vol. 3, 2nd ed., §5.3.4).
///
/// Spec §1.10.5 note 2 requires a constant-time sort. The positions compared
/// depend only on `keys.len()`; the keys reach nothing but the masks inside
/// [`ct_compare_exchange`]. The network is defined for power-of-two widths, so
/// the keys are copied into a buffer padded with `u32::MAX`. Every padding
/// value is at least every key, so after sorting the first `keys.len()` slots
/// hold exactly the sorted keys.
pub(crate) fn sort_u32_constant_time(keys: &mut [u32]) {
    if keys.len() < 2 {
        return;
    }
    let mut buffer = vec![u32::MAX; keys.len().next_power_of_two()];
    buffer[..keys.len()].copy_from_slice(keys);
    bitonic_sort(&mut buffer, true);
    keys.copy_from_slice(&buffer[..keys.len()]);
    zeroize_slice(&mut buffer);
}

/// Batcher's recursive construction: sorting the two halves in opposite
/// directions makes the whole block bitonic (non-decreasing then
/// non-increasing), and [`bitonic_merge`] then sorts it in direction
/// `ascending`. `block.len()` is a power of two.
fn bitonic_sort(block: &mut [u32], ascending: bool) {
    if block.len() < 2 {
        return;
    }
    let (first, second) = block.split_at_mut(block.len() / 2);
    bitonic_sort(first, true);
    bitonic_sort(second, false);
    bitonic_merge(block, ascending);
}

/// Sorts a bitonic block of power-of-two length. Comparing position i with
/// position i + len/2 for every i in the first half (Batcher's "half-cleaner")
/// leaves two bitonic halves in which every element of one half is on the
/// correct side of every element of the other, so each half is merged on its
/// own.
fn bitonic_merge(block: &mut [u32], ascending: bool) {
    if block.len() < 2 {
        return;
    }
    let half = block.len() / 2;
    let (first, second) = block.split_at_mut(half);
    for (x, y) in first.iter_mut().zip(second.iter_mut()) {
        if ascending {
            ct_compare_exchange(x, y);
        } else {
            ct_compare_exchange(y, x);
        }
    }
    bitonic_merge(first, ascending);
    bitonic_merge(second, ascending);
}

// ===========================================================================
// Ring arithmetic and inversion (spec §1.9)
// ===========================================================================

/// Product of two integer polynomials in Z[x]/(x^n − 1), coefficients mod
/// 2^16. Because q divides 2^16, this is also the product in R/q.
fn poly_mul<const N: usize>(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let mut r = [0u16; N];
    poly_mul_cyclic(&mut r, a, b);
    r
}

/// Product in (Z/3)[x]/(x^n − 1) of two S/3 residue polynomials.
///
/// Each coefficient of the integer cyclic convolution is a sum of n products
/// of residues at most 2, so it is at most 4n. For n < 2^14 that is below
/// 2^16: the `u16` product is exact and [`ct_mod3`] reduces it.
fn s3_mul<const N: usize>(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    debug_assert!(4 * N < 1 << 16);
    let mut r = poly_mul(a, b);
    for c in &mut r {
        *c = ct_mod3(*c);
    }
    r
}

/// Product in (Z/2)[x]/(x^n − 1) of two S/2 residue polynomials. The low bit
/// of the product modulo 2^16 is the product modulo 2.
fn s2_mul<const N: usize>(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let mut r = poly_mul(a, b);
    for c in &mut r {
        *c &= 1;
    }
    r
}

/// Reduces an S/3 residue polynomial modulo Φn, giving the canonical S/3
/// representative (spec §1.2 item 9). Subtracting c_(n−1)·Φn lowers every
/// coefficient by c_(n−1) and clears position n − 1.
fn s3_reduce_phi_n<const N: usize>(a: &mut [u16; N]) {
    let top = a[N - 1];
    for c in a.iter_mut() {
        *c = s3_sub(*c, top);
    }
}

/// Reduces an S/2 residue polynomial modulo Φn (canonical S/2 representative,
/// spec §1.2 item 8), as in [`s3_reduce_phi_n`].
fn s2_reduce_phi_n<const N: usize>(a: &mut [u16; N]) {
    let top = a[N - 1];
    for c in a.iter_mut() {
        *c ^= top;
    }
}

/// Reduces an integer polynomial modulo (q, Φn): coefficients become residues
/// in [0, q) and position n − 1 becomes 0. This is the canonical
/// S/q-representative of spec §1.2 item 10 up to the choice of residue range,
/// which the packings do not see.
fn sq_reduce_phi_n<const N: usize>(a: &mut [u16; N], log_q: u32) {
    let q_mask = ((1u32 << log_q) - 1) as u16;
    let top = a[N - 1];
    for c in a.iter_mut() {
        *c = c.wrapping_sub(top) & q_mask;
    }
}

/// Φ1·w = (x − 1)·w for an integer polynomial w of degree at most n − 2:
/// coefficient i is w_(i−1) − w_i, with w_(−1) = w_(n−1) = 0, so no reduction
/// by x^n − 1 is involved.
fn phi1_times<const N: usize>(w: &[u16; N]) -> [u16; N] {
    debug_assert_eq!(w[N - 1], 0);
    let mut out = [0u16; N];
    let mut previous = 0u16;
    for (o, &c) in out.iter_mut().zip(w) {
        *o = previous.wrapping_sub(c);
        previous = c;
    }
    out
}

/// a(x^s) mod (x^n − 1): coefficient i moves to position i·s mod n. For s
/// coprime to n this permutes positions, and the permutation depends only on
/// the public s and n.
fn substitute_x_power<const N: usize>(a: &[u16; N], s: usize) -> [u16; N] {
    let mut out = [0u16; N];
    let mut position = 0usize;
    for &c in a {
        out[position] = c;
        position = (position + s) % N;
    }
    out
}

/// p^e mod n for public p, e and n.
fn pow_mod(p: usize, e: usize, n: usize) -> usize {
    let mut result = 1 % n;
    for _ in 0..e {
        result = result * p % n;
    }
    result
}

/// Inverse in the field (Z/p)[x]/Φn for p ∈ {2, 3} (`S2_inverse` and
/// `S3_inverse`, spec §1.9.1, which leaves the method to the implementer).
///
/// Both families require p to have order n − 1 in (Z/n)^× (spec §1.3.2,
/// §1.3.3), so Φn is irreducible modulo p and S/p is the field with p^(n−1)
/// elements. By Fermat's little theorem in that field, a^(−1) = a^(p^(n−1)−2)
/// for a ≠ 0. The power is evaluated along the addition chain of T. Itoh and
/// S. Tsujii ("A fast algorithm for computing multiplicative inverses in
/// GF(2^m) using normal bases", *Information and Computation* 78(3), 1988,
/// pp. 171–177), stated here for any p:
///
/// - Let N_k = a^(1 + p + … + p^(k−1)). Then N_1 = a and
///   N_(j+k) = (N_j)^(p^k) · N_k.
/// - In characteristic p the Frobenius map gives a(x)^p = a(x^p) (R. Lidl and
///   H. Niederreiter, *Finite Fields*, Theorem 1.46), so raising to p^k is the
///   coefficient permutation x^i ↦ x^(i·p^k mod n) of [`substitute_x_power`]
///   and costs no multiplication.
/// - p^(n−1) − 2 = p·(p − 1)·(1 + p + … + p^(n−3)) + (p − 2), hence
///   a^(−1) = ((N_(n−2))^(p−1))^p · a^(p−2).
///
/// N_(n−2) is built from the binary expansion of n − 2, top bit first:
/// k → 2k uses N_(2k) = (N_k)^(p^k)·N_k, and a set bit adds k → k + 1 with
/// N_(k+1) = (N_k)^p·a. The sequence of multiplications and permutations
/// therefore depends only on n and p (at most 2·log2(n) + 2 multiplications).
/// Working in (Z/p)[x]/(x^n − 1) and reducing modulo Φn once at the end is
/// sound because that reduction is a ring homomorphism. Input: residues mod
/// p (any representative mod Φn). Output: the canonical representative; the
/// zero element maps to zero.
fn field_inverse<const N: usize>(a: &[u16; N], p: usize) -> [u16; N] {
    debug_assert!(p == 2 || p == 3);
    debug_assert!(N >= 3);
    let mul = |x: &[u16; N], y: &[u16; N]| if p == 2 { s2_mul(x, y) } else { s3_mul(x, y) };

    let k = N - 2;
    let top_bit = usize::BITS - 1 - k.leading_zeros();
    let mut norm = *a; // N_len
    let mut len = 1usize;
    for bit in (0..top_bit).rev() {
        let mut shifted = substitute_x_power(&norm, pow_mod(p, len, N));
        norm = mul(&shifted, &norm);
        len *= 2;
        if (k >> bit) & 1 == 1 {
            shifted = substitute_x_power(&norm, p % N);
            norm = mul(&shifted, a);
            len += 1;
        }
        zeroize_slice(&mut shifted);
    }
    debug_assert_eq!(len, k);

    let mut inverse = if p == 3 { mul(&norm, &norm) } else { norm };
    inverse = substitute_x_power(&inverse, p % N);
    if p == 3 {
        inverse = mul(&inverse, a);
    }
    zeroize_slice(&mut norm);
    if p == 2 {
        s2_reduce_phi_n(&mut inverse);
    } else {
        s3_reduce_phi_n(&mut inverse);
    }
    inverse
}

/// `S2_inverse` (spec §1.9.1): inverse of an S/2 residue polynomial.
fn s2_inverse<const N: usize>(a: &[u16; N]) -> [u16; N] {
    field_inverse(a, 2)
}

/// `S3_inverse` (spec §1.9.1): inverse of an S/3 residue polynomial.
fn s3_inverse<const N: usize>(a: &[u16; N]) -> [u16; N] {
    field_inverse(a, 3)
}

/// `Sq_inverse` (spec §1.9.2): for an integer polynomial `a` that is
/// invertible modulo (2, Φn), returns b with Sq(a·b) = 1, as residues mod q
/// with coefficient n − 1 equal to 0.
///
/// Line 1 inverts modulo 2. Lines 3–6 repeat v ← v·(2 − a·v): if
/// 1 − a·v = e then 1 − a·v·(2 − a·v) = e², so each round doubles the number
/// of correct low-order bits, and after the rounds with t = 1, 2, 4, …
/// while t < logq the inverse is correct modulo 2^t ≥ q. Note 1 allows the
/// rounds in R/q; they run modulo (2^16, x^n − 1), which maps onto
/// (q, Φn) by a ring homomorphism, and 2^t ≤ 16 bits for logq ≤ 16.
fn sq_inverse<const N: usize>(a: &[u16; N], log_q: u32) -> [u16; N] {
    // Line 1: v0 = S2(S2_inverse(a)).
    let mut a_mod_2 = a.map(|c| c & 1);
    let mut v0 = s2_inverse(&a_mod_2);
    zeroize_slice(&mut a_mod_2);
    // Lines 2–6.
    let mut t = 1u32;
    while t < log_q {
        let mut e = poly_mul(a, &v0);
        for c in &mut e {
            *c = c.wrapping_neg();
        }
        e[0] = e[0].wrapping_add(2);
        v0 = poly_mul(&v0, &e);
        zeroize_slice(&mut e);
        t *= 2;
    }
    // Line 7: Sq(v0).
    sq_reduce_phi_n(&mut v0, log_q);
    v0
}

/// S3(m/Φ1) for a canonical S/3 residue polynomial m (coefficient n − 1 is
/// 0), in O(n) and without a general multiplication.
///
/// Derivation (all arithmetic mod 3). Seek w of degree ≤ n − 2 with
/// (x − 1)·w ≡ m (mod Φn). The product (x − 1)·w has coefficients
/// e_i = w_(i−1) − w_i for 0 ≤ i ≤ n − 1 (w_(−1) = w_(n−1) = 0), so
/// e_(n−1) = w_(n−2). Reducing modulo Φn subtracts e_(n−1) from every lower
/// coefficient, and matching m gives
///
/// - i = 0: −w_0 − w_(n−2) = m_0;
/// - 1 ≤ i ≤ n − 2: w_(i−1) − w_i − w_(n−2) = m_i.
///
/// By induction w_i = −P_i − (i + 1)·w_(n−2) with P_i = m_0 + … + m_i.
/// Taking i = n − 2 gives n·w_(n−2) = −P_(n−2); since n ≢ 0 (mod 3) and
/// n² ≡ 1 (mod 3), w_(n−2) = −n·P_(n−2). This agrees with spec §1.9.3
/// note 1: for m = 1 it yields w_i = i when n ≡ 1 and w_i = 1 − i when
/// n ≡ 2 (mod 3).
fn s3_divide_by_phi1<const N: usize>(m: &[u16; N]) -> [u16; N] {
    debug_assert_eq!(m[N - 1], 0);
    let mut total = 0u16;
    for &c in &m[..N - 1] {
        total = s3_add(total, c);
    }
    let n_mod_3 = (N % 3) as u16; // public
    let top = s3_neg(ct_mod3(n_mod_3 * total));

    let mut w = [0u16; N];
    let mut prefix = 0u16;
    for (i, (wi, &mi)) in w.iter_mut().zip(m).take(N - 1).enumerate() {
        prefix = s3_add(prefix, mi);
        let factor = ((i + 1) % 3) as u16; // public
        *wi = s3_neg(ct_mod3(prefix + factor * top));
    }
    w
}

/// `Lift` (spec §1.9.3). Input: S/3 residues (any representative modulo Φn).
/// Output, as an integer polynomial: S3(m) for ntru-hps, Φ1·S3(m/Φ1) for
/// ntru-hrss.
fn lift<const N: usize>(family: Family, m: &[u16; N]) -> [u16; N] {
    let mut canonical = *m;
    s3_reduce_phi_n(&mut canonical);
    let out = match family {
        Family::Hps => canonical.map(s3_residue_to_signed),
        Family::Hrss => {
            let mut w = s3_divide_by_phi1(&canonical).map(s3_residue_to_signed);
            let lifted = phi1_times(&w);
            zeroize_slice(&mut w);
            lifted
        }
    };
    zeroize_slice(&mut canonical);
    out
}

// ===========================================================================
// Encodings (spec §1.8)
// ===========================================================================

/// Writes the low `log_q` bits of each value, least significant bit first,
/// into consecutive bytes, right-padding the last byte with zeros. This is
/// `bits_to_bytes` (spec §1.8.1: bit b_1 is the low bit of the first byte)
/// applied to the bit strings of §1.8.3 and §1.8.5, step 5.
fn pack_coefficients(out: &mut [u8], values: &[u16], log_q: u32) {
    let mask = (1u32 << log_q) - 1;
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut position = 0usize;
    for &v in values {
        acc |= (u32::from(v) & mask) << acc_bits;
        acc_bits += log_q;
        while acc_bits >= 8 {
            out[position] = acc as u8;
            position += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    if acc_bits > 0 {
        out[position] = acc as u8;
        position += 1;
    }
    debug_assert_eq!(position, out.len());
}

/// Inverse of [`pack_coefficients`] (`bytes_to_bits` of spec §1.8.1, then
/// §1.8.4 and §1.8.6, step 5). Returns the bits of the final byte beyond
/// (n − 1)·logq, which a well-formed encoding leaves zero.
fn unpack_coefficients(input: &[u8], values: &mut [u16], log_q: u32) -> u32 {
    let mask = (1u32 << log_q) - 1;
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut position = 0usize;
    for v in values.iter_mut() {
        while acc_bits < log_q {
            acc |= u32::from(input[position]) << acc_bits;
            position += 1;
            acc_bits += 8;
        }
        *v = (acc & mask) as u16;
        acc >>= log_q;
        acc_bits -= log_q;
    }
    debug_assert_eq!(position, input.len());
    acc
}

/// `pack_Rq0` (spec §1.8.3). `a` is an integer polynomial with
/// a ≡ 0 (mod (q, Φ1)); coefficients 0 … n − 2 are written modulo q.
fn pack_rq0<const N: usize>(out: &mut [u8], a: &[u16; N], log_q: u32) {
    assert_eq!(out.len(), packed_rq0_bytes(N, log_q));
    pack_coefficients(out, &a[..N - 1], log_q);
}

/// `unpack_Rq0` (spec §1.8.4). Returns the polynomial as residues mod q, with
/// v_(n−1) = −(v_0 + … + v_(n−2)) as in step 6, and the padding bits of the
/// final byte (see spec §1.11.4 note 2).
fn unpack_rq0<const N: usize>(input: &[u8], log_q: u32) -> ([u16; N], u32) {
    assert_eq!(input.len(), packed_rq0_bytes(N, log_q));
    let mut v = [0u16; N];
    let padding = unpack_coefficients(input, &mut v[..N - 1], log_q);
    let mut sum = 0u16;
    for &c in &v[..N - 1] {
        sum = sum.wrapping_add(c);
    }
    v[N - 1] = sum.wrapping_neg() & ((1u32 << log_q) - 1) as u16;
    (v, padding)
}

/// `pack_Sq` (spec §1.8.5): packs Sq(a) for an integer polynomial `a`.
fn pack_sq<const N: usize>(out: &mut [u8], a: &[u16; N], log_q: u32) {
    assert_eq!(out.len(), packed_sq_bytes(N, log_q));
    let mut v = *a;
    sq_reduce_phi_n(&mut v, log_q);
    pack_coefficients(out, &v[..N - 1], log_q);
    zeroize_slice(&mut v);
}

/// `unpack_Sq` (spec §1.8.6): residues mod q, coefficient n − 1 zero. The
/// padding bits are not examined (§1.11.4 only checks the ciphertext's).
fn unpack_sq<const N: usize>(input: &[u8], log_q: u32) -> [u16; N] {
    assert_eq!(input.len(), packed_sq_bytes(N, log_q));
    let mut v = [0u16; N];
    let _padding = unpack_coefficients(input, &mut v[..N - 1], log_q);
    v
}

/// `pack_S3` (spec §1.8.7): packs S3(a) for S/3 residues `a`, five
/// coefficients per byte, byte i = Σ_(j=0..4) 3^j·v_(5i+j). Positions at or
/// beyond n contribute 0.
///
/// Index convention. Step 5 of §1.8.7 sets "(c_1, c_2, …, c_5) ∈ {0, 1, 2}^5
/// so that c_j ≡ v_(5i+j) (mod 3)" for i from 0, while §1.8.2 declares that
/// "polynomials are treated as zero indexed arrays". Read literally, c_1 of
/// byte 0 is v_1 and no byte encodes v_0, so the output would not encode
/// S3(a) as the section's output line requires. This implementation uses
/// c_j ≡ v_(5i+j−1), the one reading under which the bytes encode v_0 …
/// v_(n−2) (`unpack_S3`, §1.8.8 step 6, is read the same way). The
/// known-answer files settle it: every private key (`pack_S3(f) ‖
/// pack_S3(f_p) ‖ …`), ciphertext and shared secret (SHA3-256 of
/// `pack_S3(r) ‖ pack_S3(m)`) of all 400 entries reproduces under this
/// reading.
fn pack_s3<const N: usize>(out: &mut [u8], a: &[u16; N]) {
    assert_eq!(out.len(), packed_s3_bytes(N));
    let mut v = *a;
    s3_reduce_phi_n(&mut v);
    for (i, byte) in out.iter_mut().enumerate() {
        let mut value = 0u16;
        for j in (0..5).rev() {
            let index = 5 * i + j;
            let trit = if index < N { v[index] } else { 0 }; // public index
            value = 3 * value + trit;
        }
        *byte = value as u8;
    }
    zeroize_slice(&mut v);
}

/// The five base-3 digits, least significant first, of `byte` mod 243.
///
/// Step 5 of spec §1.8.8 has no solution for bytes 243 … 255; this decoder
/// reads them as byte − 243, the natural extension (243 ≤ byte ≤ 255 < 2·243,
/// so one conditional subtraction gives the residue). Digits are found from
/// the top: while x < 3·w, the digit of weight w is [x ≥ w] + [x ≥ 2w].
fn s3_digits(byte: u8) -> [u16; 5] {
    let mut x = ct_reduce_once(u32::from(byte), 243);
    let mut digits = [0u16; 5];
    for (j, weight) in [(4usize, 81u32), (3, 27), (2, 9), (1, 3)] {
        let digit = (1 & !ct_mask_lt_u32(x, weight)) + (1 & !ct_mask_lt_u32(x, 2 * weight));
        x -= digit * weight;
        digits[j] = digit as u16;
    }
    digits[0] = x as u16;
    digits
}

/// `unpack_S3` (spec §1.8.8): the canonical S/3 residue polynomial.
///
/// The last byte can carry digits for positions n − 1 … n + 2, which are 0 in
/// any encoding [`pack_s3`] produces. For other inputs the specification's
/// S3(v) applies: x^n ≡ 1 modulo x^n − 1 and hence modulo Φn, so position
/// n + k folds onto position k, and the reduction by Φn handles n − 1.
fn unpack_s3<const N: usize>(input: &[u8]) -> [u16; N] {
    assert_eq!(input.len(), packed_s3_bytes(N));
    let mut v = [0u16; N];
    for (i, &byte) in input.iter().enumerate() {
        let mut digits = s3_digits(byte);
        for (j, &digit) in digits.iter().enumerate() {
            let index = (5 * i + j) % N; // public index
            v[index] = s3_add(v[index], digit);
        }
        zeroize_slice(&mut digits);
    }
    s3_reduce_phi_n(&mut v);
    v
}

// ===========================================================================
// Sampling (spec §1.10)
// ===========================================================================

/// `Ternary` (spec §1.10.3): coefficient i < n − 1 is S3 of byte i (bits
/// b_(8i+1) … b_(8i+8), low bit first). Output: canonical S/3 residues.
fn ternary<const N: usize>(bits: &[u8]) -> [u16; N] {
    assert_eq!(bits.len(), sample_iid_bytes(N));
    let mut v = [0u16; N];
    for (c, &b) in v.iter_mut().zip(bits) {
        *c = ct_mod3(u16::from(b));
    }
    v
}

/// `Ternary_Plus` (spec §1.10.4). Output: canonical S/3 residues of a
/// polynomial with the non-negative correlation property.
fn ternary_plus<const N: usize>(bits: &[u8]) -> [u16; N] {
    let mut v = ternary::<N>(bits);
    // Line 2: t = Σ v_i·v_(i+1) over the integer values; |t| < n.
    let mut t = 0i32;
    for i in 0..N - 1 {
        let a = i32::from(s3_residue_to_signed(v[i]) as i16);
        let b = i32::from(s3_residue_to_signed(v[i + 1]) as i16);
        t += a * b;
    }
    // Line 3: s = −1 exactly when t < 0; the arithmetic shift of the sign bit
    // is the all-ones mask for that case.
    let negate = (t >> 31) as u16;
    // Lines 4–8: v_i ← s·v_i for even i < n − 1.
    for i in (0..N - 1).step_by(2) {
        let flipped = s3_neg(v[i]);
        v[i] ^= (v[i] ^ flipped) & negate;
    }
    v
}

/// `Fixed_Type` (spec §1.10.5) for ntru-hps with modulus 2^`log_q`. Output:
/// canonical S/3 residues with q/16 − 1 coefficients 1 and q/16 − 1
/// coefficients 2 (that is, −1).
///
/// A_i = label_i + 4·(30-bit integer from bits b_(30i+1) … b_(30i+30), low
/// bit first), with label 1 for i < q/16 − 1, label 2 for i < q/8 − 2, and
/// label 0 after, so A_i < 2^32 fits a `u32`. The output keeps A_i mod 4.
///
/// Sort order. Step 16 of §1.10.5 says only "Sort A", and steps 5, 9 and 13
/// define each A_i as a label plus Σ 2^(2+j)·b, a non-negative integer below
/// 2^32, so the text reads as non-decreasing numerical order of non-negative
/// integers. The round-3 known-answer files instead require non-decreasing
/// order of the A_i read as 32-bit two's complement integers: keys of 2^31 or
/// more (30-bit field ≥ 2^29, that is, bit b_(30i+30) set) sort before all
/// others, which changes the output whenever at least one key has that bit
/// set, that is, in every entry of the files. This implementation follows the
/// known-answer files; all 300 ntru-hps entries reproduce under this order
/// and none does under numerical order. Constant-time realization: adding
/// 2^31 modulo 2^32 (XOR of bit 31) maps [−2^31, 0) onto [0, 2^31) and
/// [0, 2^31) onto [2^31, 2^32) preserving order, so the biased keys go
/// through the unsigned network [`sort_u32_constant_time`]; the bias does not
/// touch the low two bits.
fn fixed_type<const N: usize>(bits: &[u8], log_q: u32) -> [u16; N] {
    const SIGNED_ORDER_BIAS: u32 = 1 << 31;
    assert_eq!(bits.len(), sample_fixed_type_bytes(N));
    let q = 1usize << log_q;
    let plus_ones = q / 16 - 1;
    let weight = q / 8 - 2;
    debug_assert!(weight < N);

    let mut keys = vec![0u32; N - 1];
    let mut acc = 0u64;
    let mut acc_bits = 0u32;
    let mut position = 0usize;
    for (i, key) in keys.iter_mut().enumerate() {
        while acc_bits < 30 {
            acc |= u64::from(bits[position]) << acc_bits;
            position += 1;
            acc_bits += 8;
        }
        let random = (acc & ((1 << 30) - 1)) as u32;
        acc >>= 30;
        acc_bits -= 30;
        // The label depends on the public index only.
        let label = if i < plus_ones {
            1
        } else if i < weight {
            2
        } else {
            0
        };
        *key = ((random << 2) | label) ^ SIGNED_ORDER_BIAS;
    }
    sort_u32_constant_time(&mut keys);

    let mut v = [0u16; N];
    for (c, &key) in v.iter_mut().zip(&keys) {
        *c = (key & 3) as u16;
    }
    zeroize_slice(&mut keys);
    v
}

/// `Sample_fg` (spec §1.10.1). Returns f as canonical S/3 residues (f ∈ L_f)
/// and g as an integer polynomial (g ∈ L_g), or `None` when the
/// specification's steps leave that sample space.
///
/// L_f is T for ntru-hps and T+ for ntru-hrss; L_g is T(q/8 − 2) for ntru-hps
/// and Φ1·T+ for ntru-hrss (§1.3.2, §1.3.3). T is the set of *non-zero*
/// ternary polynomials (§1.2 item 13) and T+ is a subset of it (item 14). The
/// procedure would violate those sample spaces: `Ternary` and `Ternary_Plus`
/// (§1.10.3, §1.10.4) reduce each coin byte modulo 3 and never exclude zero,
/// so f_bits can give f = 0 and, for ntru-hrss, g_bits can give g = 0.
/// (`Fixed_Type` always has weight q/8 − 2, so an ntru-hps g is never 0.) A
/// zero f or g makes G·f = 0 in `DPKE_Public_Key` (§1.11.2), whose
/// `Sq_inverse` is 0, so h = h_q = 0: every ciphertext under such a key is
/// Lift(m), from which S3 recovers m (§1.3.1). This routine refuses such
/// coins, as [`sample_rm`] refuses r = 0 and an ntru-hrss m = 0, and key
/// generation draws fresh ones ([`key_pair_with_rng`]): the (f, g) used is the
/// specification's sampler conditioned on its own sample space.
///
/// With uniform coins, 86 of the 256 byte values reduce to 0, so f = 0 has
/// probability (86/256)^(n−1): 2^−799.5 at n = 509, less for the larger sets;
/// an ntru-hrss g = 0 has the same probability, 2^−1101.6 at n = 701.
///
/// Constant time: the membership tests are branch-free; the only branch is on
/// their result, and refused coins are never used.
fn sample_fg<const N: usize>(
    family: Family,
    log_q: u32,
    fg_bits: &[u8],
) -> Option<([u16; N], [u16; N])> {
    assert_eq!(fg_bits.len(), sample_key_bytes(N, family));
    let (f_bits, g_bits) = fg_bits.split_at(sample_iid_bytes(N));
    // `ternary` and `ternary_plus` return canonical S/3 residues, so f ∈ L_f
    // exactly when f ≠ 0 (`Ternary_Plus` maps 0 to 0 and every other input
    // into T+).
    let (mut f, mut g, in_sample_space) = match family {
        Family::Hps => {
            let f = ternary::<N>(f_bits);
            let mut g_residues = fixed_type::<N>(g_bits, log_q);
            let g = g_residues.map(s3_residue_to_signed);
            zeroize_slice(&mut g_residues);
            (f, g, ct_mask_s3_in_t(&f))
        }
        Family::Hrss => {
            let f = ternary_plus::<N>(f_bits);
            let mut g0_residues = ternary_plus::<N>(g_bits);
            let mut g0 = g0_residues.map(s3_residue_to_signed);
            // Φ1·g0 = 0 exactly when g0 = 0 (g0 has degree at most n − 2).
            let g = phi1_times(&g0);
            let in_l_g = ct_mask_s3_in_t(&g0_residues);
            zeroize_slice(&mut g0_residues);
            zeroize_slice(&mut g0);
            (f, g, ct_mask_s3_in_t(&f) & in_l_g)
        }
    };
    if in_sample_space == 0 {
        zeroize_slice(&mut f);
        zeroize_slice(&mut g);
        return None;
    }
    Some((f, g))
}

/// `Sample_rm` (spec §1.10.2). Returns r ∈ L_r and m ∈ L_m as canonical S/3
/// residues, or `None` when the specification's steps leave that sample
/// space.
///
/// Sample_rm is "a routine for sampling from L_r × L_m" (§1.4.3), and L_r = T,
/// the *non-zero* ternary polynomials (§1.2 item 13), for both families. Its
/// procedure would violate that sample space: `Ternary` (§1.10.3) reduces each
/// coin byte modulo 3 and never excludes zero, so it can return r = 0, and for
/// ntru-hrss, where L_m = T as well, m = 0. (`Fixed_Type` always has weight
/// q/8 − 2, so an ntru-hps m is never 0.) Zero polynomials serve no purpose:
/// `DPKE_Decrypt` rejects them (§1.11.4 line 11, [`dpke_decrypt`]), so the
/// receiver would derive the implicit-rejection key instead of the sender's
/// shared key, and with r = 0 the ciphertext is Lift(m), from which S3
/// recovers m (§1.3.1), exposing m and the shared key. This routine refuses
/// them, and encapsulation draws fresh coins ([`encapsulate_with_rng`]): the
/// (r, m) used is the specification's sampler conditioned on its own sample
/// space.
///
/// With uniform coins, 86 of the 256 byte values reduce to 0, so r = 0 has
/// probability (86/256)^(n−1): 2^−799.5 at n = 509, less for the larger sets.
/// An ntru-hrss m = 0 has the same probability, 2^−1101.6 at n = 701.
///
/// Constant time: the membership test is branch-free; the only branch is on
/// its result, and refused coins are never used.
fn sample_rm<const N: usize>(
    family: Family,
    log_q: u32,
    rm_bits: &[u8],
) -> Option<([u16; N], [u16; N])> {
    assert_eq!(rm_bits.len(), sample_plaintext_bytes(N, family));
    let (r_bits, m_bits) = rm_bits.split_at(sample_iid_bytes(N));
    let mut r = ternary::<N>(r_bits);
    let mut m = match family {
        Family::Hps => fixed_type::<N>(m_bits, log_q),
        Family::Hrss => ternary::<N>(m_bits),
    };
    // `ternary` returns canonical S/3 residues, so r ∈ T exactly when r ≠ 0.
    let in_sample_space = ct_mask_s3_in_t(&r) & ct_mask_s3_in_l_m(family, &m, log_q);
    if in_sample_space == 0 {
        zeroize_slice(&mut r);
        zeroize_slice(&mut m);
        return None;
    }
    Some((r, m))
}

// ===========================================================================
// Membership tests for the sample spaces (spec §1.2, §1.3, §1.11.4 line 11)
// ===========================================================================

/// All ones when the S/q residue polynomial `r` (coefficient n − 1 already 0)
/// lies in T: every coefficient in {−1, 0, 1} and r ≠ 0.
///
/// A residue x ∈ [0, q) is in {q − 1, 0, 1} exactly when (x + 1) mod q is in
/// {0, 1, 2}, i.e. below 3.
fn ct_mask_sq_in_t<const N: usize>(r: &[u16; N], log_q: u32) -> u32 {
    let q_mask = (1u32 << log_q) - 1;
    let mut not_ternary = 0u32;
    let mut any_nonzero = 0u32;
    for &c in r {
        let x = u32::from(c) & q_mask;
        not_ternary |= !ct_mask_lt_u32((x + 1) & q_mask, 3);
        any_nonzero |= x;
    }
    !not_ternary & ct_mask_nonzero_u32(any_nonzero)
}

/// All ones when the canonical S/3 residue polynomial `v` lies in T: v ≠ 0.
fn ct_mask_s3_in_t<const N: usize>(v: &[u16; N]) -> u32 {
    let mut any_nonzero = 0u32;
    for &c in v {
        any_nonzero |= u32::from(c);
    }
    ct_mask_nonzero_u32(any_nonzero)
}

/// All ones when the canonical S/3 residue polynomial `m` lies in
/// T(q/8 − 2): exactly q/16 − 1 coefficients 1 and q/16 − 1 coefficients 2.
/// For a residue c, `c & 1` flags 1 and `c >> 1` flags 2.
fn ct_mask_s3_in_fixed_type<const N: usize>(m: &[u16; N], log_q: u32) -> u32 {
    let target = (1u32 << log_q) / 16 - 1;
    let mut plus = 0u32;
    let mut minus = 0u32;
    for &c in m {
        plus += u32::from(c & 1);
        minus += u32::from(c >> 1);
    }
    !ct_mask_nonzero_u32((plus ^ target) | (minus ^ target))
}

/// All ones when the canonical S/3 residue polynomial `m` lies in L_m:
/// T(q/8 − 2) for ntru-hps (spec §1.3.2), T for ntru-hrss (§1.3.3).
fn ct_mask_s3_in_l_m<const N: usize>(family: Family, m: &[u16; N], log_q: u32) -> u32 {
    match family {
        Family::Hps => ct_mask_s3_in_fixed_type(m, log_q),
        Family::Hrss => ct_mask_s3_in_t(m),
    }
}

// ===========================================================================
// Passively secure DPKE (spec §1.11)
// ===========================================================================

/// `DPKE_Key_Pair` (spec §1.11.1). Returns `None`, with neither output
/// written, when the coins sample f = 0 or an ntru-hrss g = 0, which lie
/// outside L_f × L_g ([`sample_fg`]).
#[must_use]
fn dpke_key_pair<P: ParameterSet<N>, const N: usize>(
    coins: &[u8],
    packed_private_key: &mut [u8],
    packed_public_key: &mut [u8],
) -> Option<()> {
    let s3_bytes = packed_s3_bytes(N);
    assert_eq!(
        packed_private_key.len(),
        dpke_private_key_bytes(N, P::LOG_Q)
    );
    // Line 1.
    let (mut f, mut g) = sample_fg::<N>(P::FAMILY, P::LOG_Q, coins)?;
    // Line 2.
    let mut fp = s3_inverse(&f);
    // Line 3.
    let (mut h, mut hq) = dpke_public_key::<N>(&f, &g, P::LOG_Q);
    // Line 4.
    let (packed_f, rest) = packed_private_key.split_at_mut(s3_bytes);
    let (packed_fp, packed_hq) = rest.split_at_mut(s3_bytes);
    pack_s3(packed_f, &f);
    pack_s3(packed_fp, &fp);
    pack_sq(packed_hq, &hq, P::LOG_Q);
    // Line 5.
    pack_rq0(packed_public_key, &h, P::LOG_Q);
    for secret in [&mut f, &mut g, &mut fp, &mut h, &mut hq] {
        zeroize_slice(secret);
    }
    Some(())
}

/// `DPKE_Public_Key` (spec §1.11.2). `f` is canonical S/3 residues (f ∈ L_f);
/// `g` is an integer polynomial (g ∈ L_g). Returns h with Rq(h·f) = 3·g and
/// h_q with Sq(h·h_q) = 1, as integer polynomials modulo 2^16.
///
/// With v1 = 1/(G·f) in S/q, v1·G·G = G/f and v1·f·f = f/G = 1/h in S/q; note
/// 1 explains why h also satisfies its condition in R/q. The representatives
/// in lines 2–5 are not normative, and the packings reduce them.
fn dpke_public_key<const N: usize>(f: &[u16; N], g: &[u16; N], log_q: u32) -> ([u16; N], [u16; N]) {
    let mut f_int = f.map(s3_residue_to_signed);
    // Line 1: G = 3·g.
    let mut big_g = g.map(|c| c.wrapping_mul(3));
    // Line 2: v0 = Sq(G·f).
    let mut v0 = poly_mul(&big_g, &f_int);
    // Line 3: v1 = Sq_inverse(v0).
    let mut v1 = sq_inverse(&v0, log_q);
    // Line 4: h = Rq(v1·G·G).
    let mut t = poly_mul(&v1, &big_g);
    let h = poly_mul(&t, &big_g);
    // Line 5: hq = Rq(v1·f·f).
    t = poly_mul(&v1, &f_int);
    let hq = poly_mul(&t, &f_int);
    for secret in [&mut f_int, &mut big_g, &mut v0, &mut v1, &mut t] {
        zeroize_slice(secret);
    }
    (h, hq)
}

/// `DPKE_Encrypt` (spec §1.11.3).
fn dpke_encrypt<P: ParameterSet<N>, const N: usize>(
    packed_public_key: &[u8],
    packed_rm: &[u8],
    packed_ciphertext: &mut [u8],
) {
    assert_eq!(packed_rm.len(), dpke_plaintext_bytes(N));
    // Line 1.
    let (packed_r, packed_m) = packed_rm.split_at(packed_s3_bytes(N));
    // Line 2: r = S3(unpack_S3(packed_r)), used as an integer polynomial.
    let mut r = unpack_s3::<N>(packed_r).map(s3_residue_to_signed);
    // Line 3.
    let mut m0 = unpack_s3::<N>(packed_m);
    // Line 4.
    let mut m1 = lift(P::FAMILY, &m0);
    // Line 5. The public key's padding bits carry no meaning and are ignored.
    let (h, _padding) = unpack_rq0::<N>(packed_public_key, P::LOG_Q);
    // Line 6: c = Rq(r·h + m1).
    let mut c = poly_mul(&r, &h);
    for (ci, &mi) in c.iter_mut().zip(&m1) {
        *ci = ci.wrapping_add(mi);
    }
    // Line 7.
    pack_rq0(packed_ciphertext, &c, P::LOG_Q);
    for secret in [&mut r, &mut m0, &mut m1, &mut c] {
        zeroize_slice(secret);
    }
}

/// `DPKE_Decrypt` (spec §1.11.4). Writes `packed_rm` and returns the fail
/// bit as a mask: all ones for fail = 1, zero for fail = 0.
///
/// Line 11 tests r ∈ L_r = T and m0 ∈ L_m. Spec §1.2 item 13 defines T as the
/// *non-zero* ternary polynomials of degree at most n − 2 and then calls that
/// "equivalently" the set of canonical S/3-representatives, which includes 0.
/// This implementation follows the definition: r = 0 fails, and so does
/// m0 = 0 for ntru-hrss (for ntru-hps the weight test already excludes 0).
///
/// Zero polynomials serve no purpose: with r = 0 the ciphertext is Lift(m),
/// which exposes m and the shared key, and with f = 0 or g = 0 the public key
/// is 0. Neither key generation nor encapsulation creates one, and this test
/// rejects one. Encapsulation has to exclude them explicitly because the
/// specification's sampler procedure (§1.10.2–§1.10.3) would otherwise
/// violate its own sample space L_r × L_m and produce ciphertexts that this
/// test rejects; [`sample_rm`] refuses such coins and encapsulation draws
/// again ([`sample_fg`] and [`key_pair_with_rng`] do the same for keys).
/// Note 2's padding test is also applied.
fn dpke_decrypt<P: ParameterSet<N>, const N: usize>(
    packed_private_key: &[u8],
    packed_ciphertext: &[u8],
    packed_rm: &mut [u8],
) -> u32 {
    let log_q = P::LOG_Q;
    let s3_bytes = packed_s3_bytes(N);
    assert_eq!(packed_private_key.len(), dpke_private_key_bytes(N, log_q));
    assert_eq!(packed_rm.len(), dpke_plaintext_bytes(N));
    // Line 1.
    let (packed_f, rest) = packed_private_key.split_at(s3_bytes);
    let (packed_fp, packed_hq) = rest.split_at(s3_bytes);
    // Line 2.
    let (c, padding) = unpack_rq0::<N>(packed_ciphertext, log_q);
    // Line 3: f = S3(unpack_S3(packed_f)), used as an integer polynomial.
    let mut f = unpack_s3::<N>(packed_f).map(s3_residue_to_signed);
    // Line 4.
    let mut fp = unpack_s3::<N>(packed_fp);
    // Line 5.
    let mut hq = unpack_sq::<N>(packed_hq, log_q);
    // Line 6: v1 = Rq(c·f), canonical, then read modulo 3 for line 7.
    let mut cf = poly_mul(&c, &f);
    let mut v1_mod_3 = cf.map(|x| ct_mod3_signed(centered_mod_q(x, log_q)));
    // Line 7: m0 = S3(v1·fp).
    let mut m0 = s3_mul(&v1_mod_3, &fp);
    s3_reduce_phi_n(&mut m0);
    // Line 8.
    let mut m1 = lift(P::FAMILY, &m0);
    // Line 9: r = Sq((c − m1)·hq).
    let mut difference = c;
    for (d, &mi) in difference.iter_mut().zip(&m1) {
        *d = d.wrapping_sub(mi);
    }
    let mut r = poly_mul(&difference, &hq);
    sq_reduce_phi_n(&mut r, log_q);
    // Line 10: packed_rm = pack_S3(r) ‖ pack_S3(m0), where S3(r) reads the
    // canonical S/q representative's centered coefficients modulo 3.
    let mut r_mod_3 = r.map(|x| ct_mod3_signed(centered_mod_q(x, log_q)));
    let (packed_r, packed_m) = packed_rm.split_at_mut(s3_bytes);
    pack_s3(packed_r, &r_mod_3);
    pack_s3(packed_m, &m0);
    // Lines 11–12, and note 2.
    let accept = ct_mask_sq_in_t(&r, log_q)
        & ct_mask_s3_in_l_m(P::FAMILY, &m0, log_q)
        & !ct_mask_nonzero_u32(padding);
    for secret in [
        &mut f,
        &mut fp,
        &mut hq,
        &mut cf,
        &mut v1_mod_3,
        &mut m0,
        &mut m1,
        &mut difference,
        &mut r,
        &mut r_mod_3,
    ] {
        zeroize_slice(secret);
    }
    !accept
}

// ===========================================================================
// Strongly secure KEM (spec §1.12)
// ===========================================================================

/// `Key_Pair` (spec §1.12.1) with the random bits of line 1 supplied by the
/// caller as `seed` = fg_bits ‖ prf_key: the deterministic seed-to-key-pair
/// entry point. Returns `None` when fg_bits sample f = 0 or an ntru-hrss
/// g = 0, which lie outside L_f × L_g ([`sample_fg`]). That check comes
/// first, so for such a seed neither key is computed or written.
///
/// An explicit seed cannot be redrawn, so this boundary refuses it rather
/// than emit the all-zero key pair it determines. [`key_pair_with_rng`], the
/// entry point the KEM uses, draws fresh bits instead; this one serves the
/// tests that probe the seed boundary.
#[cfg(test)]
#[must_use]
pub(crate) fn key_pair<P: ParameterSet<N>, const N: usize>(
    seed: &[u8],
    packed_private_key: &mut [u8],
    packed_public_key: &mut [u8],
) -> Option<()> {
    assert_eq!(seed.len(), sample_key_bytes(N, P::FAMILY) + PRF_KEY_BYTES);
    assert_eq!(packed_private_key.len(), kem_private_key_bytes(N, P::LOG_Q));
    // Line 1.
    let (fg_bits, prf_key) = seed.split_at(sample_key_bytes(N, P::FAMILY));
    // Lines 2–3.
    let (dpke_private_key, prf_slot) =
        packed_private_key.split_at_mut(dpke_private_key_bytes(N, P::LOG_Q));
    dpke_key_pair::<P, N>(fg_bits, dpke_private_key, packed_public_key)?;
    prf_slot.copy_from_slice(prf_key);
    Some(())
}

/// The number of coin requests [`key_pair_with_rng`] and
/// [`encapsulate_with_rng`] make before they declare the random source
/// broken.
///
/// [`sample_fg`] and [`sample_rm`] refuse one draw from a uniform source with
/// a probability ε below 2^−799 for every recommended set (derived at
/// [`encapsulate_with_rng`]), so such a source needs a second draw with
/// probability ε and has two draws refused with probability ε² < 2^−1598. Two
/// is the fewest draws that can replace refused coins at all.
///
/// The design choice behind the limit: [`Csprng`] is a public trait that
/// callers implement, so a source is not assumed sound. A source whose draws
/// are refused twice in a row is treated as broken, and the operation panics
/// rather than returning an error value or drawing further.
const COIN_DRAW_LIMIT: usize = 2;

/// `Key_Pair` (spec §1.12.1), drawing fg_bits from `rng` as one request of
/// sample_key_bits / 8 bytes and then prf_key as one request of
/// prf_key_bits / 8 bytes, the order and split the round-3 known-answer files
/// reproduce. fg_bits that [`sample_fg`] refuses are wiped and replaced by the
/// next request; prf_key is drawn once fg_bits is accepted.
///
/// # Distribution
///
/// [`sample_fg`] refuses uniform coins with the probability ε derived at
/// [`encapsulate_with_rng`] (f = 0 for ntru-hps; f = 0 or g = 0 for
/// ntru-hrss, and f_bits and g_bits are disjoint). A uniform source's requests
/// are independent, so the first accepted draw is distributed exactly as the
/// literal output conditioned on L_f × L_g, which is what Sample_fg's
/// contract, "sampling from L_f × L_g" (§1.4.3), calls for. Relative to the
/// literal procedure only that probability-ε event changes: its all-zero key
/// pair is replaced by one from a fresh draw, which puts the two output
/// distributions at statistical distance exactly ε, and with probability ε²
/// the call panics instead of returning. Every accepted key pair is one the
/// literal procedure produces from the same bits, so a known-answer file is
/// reproduced unless an entry's fg_bits fall in that event.
///
/// # Constant time
///
/// `Ternary`, `Ternary_Plus`, `Fixed_Type` and the membership mask
/// ([`ct_mask_s3_in_t`]) are branch-free, so within one draw nothing depends
/// on which or how many coefficients are zero. The only secret-dependent
/// branch is on the membership result, and what it can reveal is whether the
/// first draw was refused; that draw is wiped and never used, and for a source
/// with independent requests the bit is independent of the accepted draw.
///
/// # Panics
///
/// Panics when [`COIN_DRAW_LIMIT`] consecutive fg_bits requests are all
/// refused; the source is then treated as broken, and there is no error
/// value.
pub(crate) fn key_pair_with_rng<P: ParameterSet<N>, R: Csprng, const N: usize>(
    rng: &mut R,
    packed_private_key: &mut [u8],
    packed_public_key: &mut [u8],
) {
    assert_eq!(packed_private_key.len(), kem_private_key_bytes(N, P::LOG_Q));
    let (dpke_private_key, prf_slot) =
        packed_private_key.split_at_mut(dpke_private_key_bytes(N, P::LOG_Q));
    let mut fg_bits = vec![0u8; sample_key_bytes(N, P::FAMILY)];
    let generated = (0..COIN_DRAW_LIMIT).any(|_| {
        // Line 1, first request.
        rng.fill_bytes(&mut fg_bits);
        // Line 2.
        dpke_key_pair::<P, N>(&fg_bits, dpke_private_key, packed_public_key).is_some()
    });
    zeroize_slice(&mut fg_bits);
    assert!(
        generated,
        "NTRU key generation: {COIN_DRAW_LIMIT} consecutive coin draws sampled a zero \
         polynomial (f = 0, or g = 0 for ntru-hrss); the random source is broken"
    );
    // Line 1, second request, and line 3.
    rng.fill_bytes(prf_slot);
}

/// `Encapsulate` (spec §1.12.2) with the coins of line 1 supplied by the
/// caller: the deterministic coins-to-encapsulation entry point. Returns
/// `None` when the coins sample r = 0 or an ntru-hrss m = 0, which lie outside
/// L_r × L_m ([`sample_rm`]). That check comes first, so for such coins neither
/// the shared key nor the ciphertext is computed or written.
///
/// Explicit coins cannot be redrawn, so this boundary refuses them rather than
/// emit a ciphertext that decapsulation rejects, whose shared key the receiver
/// would never derive. [`encapsulate_with_rng`] draws fresh coins instead.
#[must_use]
fn encapsulate<P: ParameterSet<N>, const N: usize>(
    packed_public_key: &[u8],
    coins: &[u8],
    shared_key: &mut [u8; SHARED_KEY_BYTES],
    packed_ciphertext: &mut [u8],
) -> Option<()> {
    let s3_bytes = packed_s3_bytes(N);
    // Line 2.
    let (mut r, mut m) = sample_rm::<N>(P::FAMILY, P::LOG_Q, coins)?;
    // Line 3.
    let mut packed_rm = vec![0u8; dpke_plaintext_bytes(N)];
    pack_s3(&mut packed_rm[..s3_bytes], &r);
    pack_s3(&mut packed_rm[s3_bytes..], &m);
    // Line 4.
    *shared_key = Sha3_256::digest(&packed_rm);
    // Line 5.
    dpke_encrypt::<P, N>(packed_public_key, &packed_rm, packed_ciphertext);
    zeroize_slice(&mut r);
    zeroize_slice(&mut m);
    zeroize_slice(&mut packed_rm);
    Some(())
}

/// `Encapsulate` (spec §1.12.2), drawing the coins of line 1 from `rng` as one
/// request of sample_plaintext_bits / 8 bytes. Coins that [`encapsulate`]
/// refuses are wiped and replaced by the next request.
///
/// # Distribution
///
/// Let ε be the probability that the literal Sample_rm procedure, run on
/// uniform coins, leaves L_r × L_m. With p = (86/256)^(n−1), ε = p for
/// ntru-hps (r = 0; m always has weight q/8 − 2) and ε = 1 − (1 − p)² < 2p for
/// ntru-hrss (r = 0 or m = 0): 2^−799.5 at n = 509, 2^−1063.8 at n = 677,
/// 2^−1290.5 at n = 821, and below 2^−1100.6 at n = 701. A uniform source's
/// requests are independent, so the first accepted draw is distributed
/// exactly as the literal output conditioned on L_r × L_m, which is what
/// Sample_rm's contract, "sampling from L_r × L_m" (§1.4.3), calls for.
/// Relative to the literal procedure only that probability-ε event changes:
/// its outputs are replaced by a fresh draw, which puts the two output
/// distributions at statistical distance exactly ε, and with probability ε²
/// the call panics instead of returning.
///
/// Interoperability: every other step and every encoding is unchanged, and
/// every (r, m) used lies in L_r × L_m, so a decapsulation that follows
/// §1.11.4 accepts these ciphertexts, and so does one that never excludes
/// zero. An encapsulation that never excludes zero produces the same
/// ciphertext and key from the same coins, except on the probability-ε coins:
/// there it emits r = 0 (or an ntru-hrss m = 0), which this crate's
/// decapsulation rejects. A known-answer file records one draw per
/// encapsulation, so it is reproduced unless an entry's coins fall in that
/// event.
///
/// # Constant time
///
/// `Ternary`, `Fixed_Type` and the membership masks ([`ct_mask_s3_in_t`],
/// [`ct_mask_s3_in_l_m`]) are branch-free, so within one draw nothing depends
/// on which or how many coefficients are zero. The only secret-dependent
/// branch is on the membership result. What it can reveal, through timing or
/// through the number of requests `rng` receives, is the retry count: whether
/// the first draw was refused, that is, whether its r (or ntru-hrss m) was 0.
/// That draw is wiped and never used, and for a source with independent
/// requests the bit is independent of the accepted draw, so it says nothing
/// about the r, m, shared key or ciphertext that are output.
///
/// # Panics
///
/// Panics when [`COIN_DRAW_LIMIT`] consecutive draws are all refused; the
/// source is then treated as broken, and there is no error value.
pub(crate) fn encapsulate_with_rng<P: ParameterSet<N>, R: Csprng, const N: usize>(
    packed_public_key: &[u8],
    rng: &mut R,
    shared_key: &mut [u8; SHARED_KEY_BYTES],
    packed_ciphertext: &mut [u8],
) {
    let mut coins = vec![0u8; sample_plaintext_bytes(N, P::FAMILY)];
    let encapsulated = (0..COIN_DRAW_LIMIT).any(|_| {
        // Line 1.
        rng.fill_bytes(&mut coins);
        encapsulate::<P, N>(packed_public_key, &coins, shared_key, packed_ciphertext).is_some()
    });
    zeroize_slice(&mut coins);
    assert!(
        encapsulated,
        "NTRU encapsulation: {COIN_DRAW_LIMIT} consecutive coin draws sampled a zero \
         polynomial (r = 0, or m = 0 for ntru-hrss); the random source is broken"
    );
}

/// `Decapsulate` (spec §1.12.3). Both candidate keys are always computed and
/// line 6 selects between them with a mask.
pub(crate) fn decapsulate<P: ParameterSet<N>, const N: usize>(
    packed_private_key: &[u8],
    packed_ciphertext: &[u8],
    shared_key: &mut [u8; SHARED_KEY_BYTES],
) {
    assert_eq!(packed_private_key.len(), kem_private_key_bytes(N, P::LOG_Q));
    // Lines 1–2.
    let (dpke_private_key, prf_key) =
        packed_private_key.split_at(dpke_private_key_bytes(N, P::LOG_Q));
    // Line 3.
    let mut packed_rm = vec![0u8; dpke_plaintext_bytes(N)];
    let fail = dpke_decrypt::<P, N>(dpke_private_key, packed_ciphertext, &mut packed_rm);
    // Line 4.
    let mut accepted = Sha3_256::digest(&packed_rm);
    // Line 5.
    let mut hasher = Sha3_256::new();
    hasher.update(prf_key);
    hasher.update(packed_ciphertext);
    let mut random_key = hasher.finalize();
    // Line 6.
    let fail = fail as u8;
    for ((out, &a), &b) in shared_key.iter_mut().zip(&accepted).zip(&random_key) {
        *out = a ^ ((a ^ b) & fail);
    }
    zeroize_slice(&mut packed_rm);
    zeroize_slice(&mut accepted);
    zeroize_slice(&mut random_key);
}

// ===========================================================================
// Per-set public API
// ===========================================================================

/// Expands, inside a per-set module, to that parameter set's constants, its
/// key, ciphertext and shared-secret newtypes, the zero-sized namespace type
/// with `keygen` / `encaps` / `decaps`, and the per-set tests (including the
/// known-answer tests against `kat_path`).
macro_rules! define_ntru_kem {
    (
        n = $n:literal,
        log_q = $log_q:literal,
        family = $family:ident,
        namespace = $type_name:ident,
        public_key = $pk_ty:ident,
        private_key = $sk_ty:ident,
        ciphertext = $ct_ty:ident,
        shared_secret = $ss_ty:ident,
        kat_path = $kat_path:literal $(,)?
    ) => {
        /// The prime n of this parameter set.
        const N: usize = $n;
        /// logq for this parameter set.
        const LOG_Q: u32 = $log_q;
        /// The family (ntru-hps or ntru-hrss) of this parameter set.
        const FAMILY: $crate::public_key::ntru_pqc_shared::Family =
            $crate::public_key::ntru_pqc_shared::Family::$family;

        // The encoding lengths, used for the array sizes below; the public
        // names are the namespace type's associated constants.
        const PUBLIC_KEY_BYTES: usize =
            $crate::public_key::ntru_pqc_shared::kem_public_key_bytes(N, LOG_Q);
        const PRIVATE_KEY_BYTES: usize =
            $crate::public_key::ntru_pqc_shared::kem_private_key_bytes(N, LOG_Q);
        const CIPHERTEXT_BYTES: usize =
            $crate::public_key::ntru_pqc_shared::kem_ciphertext_bytes(N, LOG_Q);
        const SHARED_SECRET_BYTES: usize =
            $crate::public_key::ntru_pqc_shared::SHARED_KEY_BYTES;

        /// NTRU public key for this parameter set in its specification
        /// encoding, `pack_Rq0(h)` (spec §1.8.3): coefficients 0 … n − 2 of h
        /// at logq bits each, least significant bit first
        /// (`PUBLIC_KEY_BYTES` bytes). The omitted coefficient n − 1 is
        /// recovered on use because h ≡ 0 modulo (q, Φ1).
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk_ty {
            bytes: [u8; PUBLIC_KEY_BYTES],
        }

        /// NTRU private key for this parameter set in its specification
        /// encoding (spec §1.11.1 line 4 and §1.12.1 line 3):
        /// `pack_S3(f) ‖ pack_S3(f_p) ‖ pack_Sq(h_q) ‖ prf_key`, where
        /// f_p = 1/f in S/3 and h_q = 1/h in S/q (`PRIVATE_KEY_BYTES` bytes).
        /// The buffer is zeroized on drop, equality is compared in constant
        /// time, and the `Debug` impl prints `<redacted>` instead of key
        /// material.
        #[derive(Clone)]
        pub struct $sk_ty {
            bytes: [u8; PRIVATE_KEY_BYTES],
        }

        /// NTRU ciphertext for this parameter set, `pack_Rq0(c)` with
        /// c = Rq(r·h + Lift(m)) (spec §1.11.3), `CIPHERTEXT_BYTES` bytes.
        /// Decapsulation treats non-zero padding bits in the final byte as a
        /// failure (spec §1.11.4 note 2) and rejects implicitly.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $ct_ty {
            bytes: [u8; CIPHERTEXT_BYTES],
        }

        /// KEM shared secret for this parameter set: the 32-byte SHA3-256
        /// digest of `pack_S3(r) ‖ pack_S3(m)`, or after a decapsulation
        /// failure the implicit-rejection key SHA3-256(prf_key ‖ ciphertext)
        /// (spec §1.12.3). Zeroized on drop, compared in constant time;
        /// `Debug` prints `<redacted>`. There is deliberately no
        /// `from_wire_bytes`: shared secrets only come out of `encaps` /
        /// `decaps`.
        #[derive(Clone)]
        pub struct $ss_ty {
            bytes: [u8; SHARED_SECRET_BYTES],
        }

        impl ::core::cmp::PartialEq for $sk_ty {
            /// Compares the packed private keys in constant time.
            fn eq(&self, other: &Self) -> bool {
                $crate::ct::constant_time_eq_mask(&self.bytes, &other.bytes) == u8::MAX
            }
        }

        impl ::core::cmp::Eq for $sk_ty {}

        impl ::core::cmp::PartialEq for $ss_ty {
            /// Compares the shared secrets in constant time.
            fn eq(&self, other: &Self) -> bool {
                $crate::ct::constant_time_eq_mask(&self.bytes, &other.bytes) == u8::MAX
            }
        }

        impl ::core::cmp::Eq for $ss_ty {}

        impl Drop for $sk_ty {
            fn drop(&mut self) {
                // The packed private key holds f, 1/f in S/3, 1/h in S/q,
                // and the implicit-rejection PRF key.
                $crate::ct::zeroize_slice(self.bytes.as_mut_slice());
            }
        }

        impl Drop for $ss_ty {
            fn drop(&mut self) {
                $crate::ct::zeroize_slice(self.bytes.as_mut_slice());
            }
        }

        impl $pk_ty {
            /// Parse a public key from its specification encoding. Returns
            /// `None` exactly when `bytes.len() != PUBLIC_KEY_BYTES` (this
            /// parameter set's fixed length); the content is not otherwise
            /// validated, so any correctly-sized byte string is accepted.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PUBLIC_KEY_BYTES {
                    return None;
                }
                let mut out = [0u8; PUBLIC_KEY_BYTES];
                out.copy_from_slice(bytes);
                Some(Self { bytes: out })
            }

            /// Copy of the encoding, `PUBLIC_KEY_BYTES` bytes; round-trips
            /// bit-for-bit through [`Self::from_wire_bytes`].
            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
                self.bytes
            }

            /// Borrow the encoding in place — the same bytes
            /// [`Self::to_wire_bytes`] copies out, without the copy.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
                &self.bytes
            }
        }

        impl $sk_ty {
            /// Parse a private key from its specification encoding (the DPKE
            /// private key followed by the 32-byte implicit-rejection PRF
            /// key). Returns `None` exactly when
            /// `bytes.len() != PRIVATE_KEY_BYTES`; no consistency check is run
            /// on the content.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PRIVATE_KEY_BYTES {
                    return None;
                }
                let mut out = [0u8; PRIVATE_KEY_BYTES];
                out.copy_from_slice(bytes);
                Some(Self { bytes: out })
            }

            /// Copy the packed private key out as a plain array
            /// (`PRIVATE_KEY_BYTES` bytes); round-trips through
            /// [`Self::from_wire_bytes`]. The copy leaves the
            /// `Drop`-zeroizing wrapper — wiping the returned array after use
            /// becomes the caller's responsibility.
            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; PRIVATE_KEY_BYTES] {
                self.bytes
            }

            /// Borrow the packed private key in place, avoiding the
            /// unzeroized copy [`Self::to_wire_bytes`] hands out.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_BYTES] {
                &self.bytes
            }
        }

        impl $ct_ty {
            /// Parse a ciphertext from its specification encoding. Returns
            /// `None` exactly when `bytes.len() != CIPHERTEXT_BYTES`. Padding
            /// bits are not checked here; a malformed or corrupted ciphertext
            /// is instead absorbed by decapsulation's implicit rejection.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != CIPHERTEXT_BYTES {
                    return None;
                }
                let mut out = [0u8; CIPHERTEXT_BYTES];
                out.copy_from_slice(bytes);
                Some(Self { bytes: out })
            }

            /// Copy of the encoding, `CIPHERTEXT_BYTES` bytes; round-trips
            /// bit-for-bit through [`Self::from_wire_bytes`].
            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
                self.bytes
            }

            /// Borrow the encoding in place — the same bytes
            /// [`Self::to_wire_bytes`] copies out, without the copy.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
                &self.bytes
            }
        }

        impl $ss_ty {
            /// Copy the 32-byte shared secret out as a plain array. The copy
            /// leaves the `Drop`-zeroizing wrapper — wiping the returned array
            /// after use becomes the caller's responsibility.
            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; SHARED_SECRET_BYTES] {
                self.bytes
            }

            /// Borrow the 32-byte shared secret in place, avoiding the
            /// unzeroized copy [`Self::to_wire_bytes`] hands out.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
                &self.bytes
            }
        }

        impl ::core::fmt::Debug for $pk_ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($pk_ty)).finish()
            }
        }

        impl ::core::fmt::Debug for $ct_ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($ct_ty)).finish()
            }
        }

        impl ::core::fmt::Debug for $sk_ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($sk_ty), "(<redacted>)"))
            }
        }

        impl ::core::fmt::Debug for $ss_ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($ss_ty), "(<redacted>)"))
            }
        }

        /// Zero-sized namespace for this parameter set's KEM (spec §1.12):
        /// the encoding lengths plus the [`Self::keygen`] /
        /// [`Self::encaps`] / [`Self::decaps`] entry points. Carries no state
        /// of its own — all state travels in the key, ciphertext, and
        /// shared-secret newtypes.
        pub struct $type_name;

        impl $crate::public_key::ntru_pqc_shared::ParameterSet<N> for $type_name {
            const LOG_Q: u32 = LOG_Q;
            const FAMILY: $crate::public_key::ntru_pqc_shared::Family = FAMILY;
        }

        impl $type_name {
            /// Public-key length in bytes (kem_public_key_bytes, spec
            /// §1.5.13).
            pub const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
            /// Private-key length in bytes, including the implicit-rejection
            /// PRF key (kem_private_key_bytes, spec §1.5.14).
            pub const PRIVATE_KEY_BYTES: usize = PRIVATE_KEY_BYTES;
            /// Ciphertext length in bytes (kem_ciphertext_bytes, spec
            /// §1.5.15).
            pub const CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;
            /// Shared-secret length in bytes (kem_shared_key_bits / 8, spec
            /// §1.5.16): 32 for every round-3 set.
            pub const SHARED_SECRET_BYTES: usize = SHARED_SECRET_BYTES;

            /// `Key_Pair` (spec §1.12.1). Draws fg_bits (sample_key_bits / 8
            /// bytes) and then the 32-byte prf_key from `rng` as two
            /// requests, the order and split that the round-3 known-answer
            /// files reproduce, and returns `pack_Rq0(h)` with the private
            /// key `pack_S3(f) ‖ pack_S3(f_p) ‖ pack_Sq(h_q) ‖ prf_key`.
            ///
            /// Key generation never creates a zero polynomial, whose key pair
            /// would be all zero (h = 0, so every ciphertext would be
            /// Lift(m)). The specification's sampler turns uniform coins into
            /// f = 0 (or, for ntru-hrss, g = 0) with probability below
            /// 2^−799; such fg_bits are discarded and a second request is
            /// drawn from `rng` before prf_key.
            ///
            /// # Panics
            ///
            /// Panics if the fg_bits of two consecutive requests both sample
            /// a zero polynomial. A uniform source does that with probability
            /// below 2^−1598; a source that does it is treated as broken, and
            /// this entry point reports that by panicking rather than by an
            /// error value.
            pub fn keygen<R: $crate::Csprng>(rng: &mut R) -> ($pk_ty, $sk_ty) {
                let mut pk = [0u8; PUBLIC_KEY_BYTES];
                let mut sk = [0u8; PRIVATE_KEY_BYTES];
                $crate::public_key::ntru_pqc_shared::key_pair_with_rng::<$type_name, R, N>(
                    rng, &mut sk, &mut pk,
                );
                let private_key = $sk_ty { bytes: sk };
                $crate::ct::zeroize_slice(sk.as_mut_slice());
                ($pk_ty { bytes: pk }, private_key)
            }

            /// `Encapsulate` (spec §1.12.2) against `pk`. Draws the coins
            /// (sample_plaintext_bits / 8 bytes) from `rng` in one request,
            /// samples (r, m), and returns the ciphertext with the shared
            /// secret SHA3-256(`pack_S3(r) ‖ pack_S3(m)`). Decapsulating the
            /// returned ciphertext under the matching private key yields an
            /// equal shared secret.
            ///
            /// Encapsulation never creates a zero polynomial, which
            /// decapsulation rejects. The specification's sampler turns
            /// uniform coins into r = 0 (or, for ntru-hrss, m = 0) with
            /// probability below 2^−799; such coins are discarded and a second
            /// request is drawn from `rng`.
            ///
            /// # Panics
            ///
            /// Panics if the coins of two consecutive requests both sample a
            /// zero polynomial. A uniform source does that with probability
            /// below 2^−1598; a source that does it is treated as broken, and
            /// this entry point reports that by panicking rather than by an
            /// error value.
            pub fn encaps<R: $crate::Csprng>(pk: &$pk_ty, rng: &mut R) -> ($ct_ty, $ss_ty) {
                let mut ct = [0u8; CIPHERTEXT_BYTES];
                let mut ss = [0u8; SHARED_SECRET_BYTES];
                $crate::public_key::ntru_pqc_shared::encapsulate_with_rng::<$type_name, R, N>(
                    &pk.bytes, rng, &mut ss, &mut ct,
                );
                let shared = $ss_ty { bytes: ss };
                $crate::ct::zeroize_slice(ss.as_mut_slice());
                ($ct_ty { bytes: ct }, shared)
            }

            /// `Decapsulate` (spec §1.12.3). Recovers `pack_S3(r) ‖
            /// pack_S3(m)` from `ct` and returns its SHA3-256 digest. It never
            /// fails: when the recovered r or m lies outside its sample space,
            /// or the ciphertext's padding bits are not zero, it returns
            /// SHA3-256(prf_key ‖ ct) instead. Both digests are always
            /// computed and selected with a mask, so acceptance and rejection
            /// share one code path.
            pub fn decaps(sk: &$sk_ty, ct: &$ct_ty) -> $ss_ty {
                let mut ss = [0u8; SHARED_SECRET_BYTES];
                $crate::public_key::ntru_pqc_shared::decapsulate::<$type_name, N>(
                    &sk.bytes, &ct.bytes, &mut ss,
                );
                let shared = $ss_ty { bytes: ss };
                $crate::ct::zeroize_slice(ss.as_mut_slice());
                shared
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::hash::sha3::Sha3_256;
            use $crate::public_key::ntru_pqc_shared::{
                coins_sampling_zero_f, coins_sampling_zero_g, coins_sampling_zero_m,
                coins_sampling_zero_r, sample_plaintext_bytes, Family, ScriptedCoinSource,
                KAT_DEFAULT_COUNTS,
            };
            use $crate::CtrDrbgAes256;

            #[test]
            fn parameter_byte_lengths() {
                assert!(PUBLIC_KEY_BYTES > 0);
                assert!(PRIVATE_KEY_BYTES > 0);
                assert!(CIPHERTEXT_BYTES > 0);
                assert_eq!(SHARED_SECRET_BYTES, 32);
            }

            #[test]
            fn roundtrip_random() {
                let mut drbg = CtrDrbgAes256::new(&[0x42u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let (ct, ss_a) = $type_name::encaps(&pk, &mut drbg);
                let ss_b = $type_name::decaps(&sk, &ct);
                assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
            }

            #[test]
            fn roundtrip_multiple_seeds() {
                for seed in [0x00u8, 0x55, 0xaa, 0xff] {
                    let mut drbg = CtrDrbgAes256::new(&[seed; 48]);
                    let (pk, sk) = $type_name::keygen(&mut drbg);
                    let (ct, ss_a) = $type_name::encaps(&pk, &mut drbg);
                    let ss_b = $type_name::decaps(&sk, &ct);
                    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes(), "seed byte 0x{seed:02x}");
                }
            }

            /// SHA3-256(prf_key ‖ ciphertext), spec §1.12.3 line 5.
            fn rejection_key(sk: &$sk_ty, ct: &[u8]) -> [u8; 32] {
                let mut h = Sha3_256::new();
                h.update(&sk.as_bytes()[PRIVATE_KEY_BYTES - 32..]);
                h.update(ct);
                h.finalize()
            }

            #[test]
            fn implicit_rejection_on_corrupted_ciphertext() {
                let mut drbg = CtrDrbgAes256::new(&[0x99u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let (ct, ss_a) = $type_name::encaps(&pk, &mut drbg);
                let mut bad = ct.to_wire_bytes();
                bad[0] ^= 0x01;
                let bad_ct = $ct_ty::from_wire_bytes(&bad).unwrap();
                let ss_bad = $type_name::decaps(&sk, &bad_ct);
                assert_ne!(ss_bad.as_bytes(), ss_a.as_bytes());
                let ss_bad2 = $type_name::decaps(&sk, &bad_ct);
                assert_eq!(ss_bad.as_bytes(), ss_bad2.as_bytes());
                assert_eq!(ss_bad.as_bytes(), &rejection_key(&sk, &bad));
            }

            /// Spec §1.11.4 note 2: bits of the final ciphertext byte beyond
            /// (n − 1)·logq do not change c, so only the explicit padding
            /// test turns them into a rejection.
            #[test]
            fn nonzero_padding_bits_are_rejected() {
                let used = ((N - 1) * LOG_Q as usize) % 8;
                if used == 0 {
                    return; // this set's encoding has no padding bits
                }
                let mut drbg = CtrDrbgAes256::new(&[0x5au8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let (ct, ss) = $type_name::encaps(&pk, &mut drbg);
                let mut bad = ct.to_wire_bytes();
                bad[CIPHERTEXT_BYTES - 1] |= 0x80;
                let bad_ct = $ct_ty::from_wire_bytes(&bad).unwrap();
                let rejected = $type_name::decaps(&sk, &bad_ct);
                assert_ne!(rejected.as_bytes(), ss.as_bytes());
                assert_eq!(rejected.as_bytes(), &rejection_key(&sk, &bad));
            }

            #[test]
            fn wire_format_roundtrip() {
                let mut drbg = CtrDrbgAes256::new(&[0x21u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let (ct, _) = $type_name::encaps(&pk, &mut drbg);
                let pk_bytes = pk.to_wire_bytes();
                let sk_bytes = sk.to_wire_bytes();
                let ct_bytes = ct.to_wire_bytes();
                assert_eq!(pk_bytes.len(), PUBLIC_KEY_BYTES);
                assert_eq!(sk_bytes.len(), PRIVATE_KEY_BYTES);
                assert_eq!(ct_bytes.len(), CIPHERTEXT_BYTES);
                let pk2 = $pk_ty::from_wire_bytes(&pk_bytes).unwrap();
                let sk2 = $sk_ty::from_wire_bytes(&sk_bytes).unwrap();
                let ct2 = $ct_ty::from_wire_bytes(&ct_bytes).unwrap();
                assert_eq!(pk, pk2);
                assert_eq!(sk, sk2);
                assert_eq!(ct, ct2);
            }

            /// Keys from `CtrDrbgAes256::new(&[0x64; 48])`, as in the
            /// review's reproduction of the zero-polynomial case.
            fn reproduction_keys() -> ($pk_ty, $sk_ty) {
                $type_name::keygen(&mut CtrDrbgAes256::new(&[0x64u8; 48]))
            }

            /// The panic payload of `f` as text.
            fn panic_message(f: impl FnOnce()) -> String {
                let outcome =
                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(f));
                let payload = outcome.expect_err("the operation must refuse loudly");
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|m| m.to_string()))
                    .unwrap_or_default()
            }

            /// Encapsulation from a source that answers every request with
            /// `coins`, which sample a zero polynomial, must panic after
            /// exactly two requests: no endless loop, and no ciphertext built
            /// from refused coins.
            fn assert_encaps_refuses_loudly(pk: &$pk_ty, coins: &[u8]) {
                // The DRBG behind the script is never reached.
                let mut source = ScriptedCoinSource::new(
                    coins.to_vec(),
                    usize::MAX,
                    CtrDrbgAes256::new(&[0u8; 48]),
                );
                let message = panic_message(|| {
                    let _ = $type_name::encaps(pk, &mut source);
                });
                assert!(
                    message.contains("NTRU encapsulation: 2 consecutive coin draws sampled a zero polynomial")
                        && message.ends_with("the random source is broken"),
                    "unexpected panic message: {message}"
                );
                assert_eq!(source.requests(), 2, "requests before giving up");
            }

            /// Key generation from a source that answers every request with
            /// `fg_bits`, which sample a zero polynomial, must panic after
            /// exactly two requests, before prf_key is drawn: no endless
            /// loop, and no key pair built from refused coins.
            fn assert_keygen_refuses_loudly(fg_bits: &[u8]) {
                let mut source = ScriptedCoinSource::new(
                    fg_bits.to_vec(),
                    usize::MAX,
                    CtrDrbgAes256::new(&[0u8; 48]),
                );
                let message = panic_message(|| {
                    let _ = $type_name::keygen(&mut source);
                });
                assert!(
                    message.contains("NTRU key generation: 2 consecutive coin draws sampled a zero polynomial")
                        && message.ends_with("the random source is broken"),
                    "unexpected panic message: {message}"
                );
                assert_eq!(source.requests(), 2, "requests before giving up");
            }

            /// Key generation from a source whose first request is `fg_bits`,
            /// which sample a zero polynomial, and whose later requests are
            /// sound: the refused bits are discarded after exactly one
            /// redraw, the key pair equals the sound source's alone, and it
            /// encapsulates and decapsulates to the same shared secret.
            fn assert_keygen_draws_again(fg_bits: &[u8]) {
                let mut source = ScriptedCoinSource::new(
                    fg_bits.to_vec(),
                    1,
                    CtrDrbgAes256::new(&[0x65u8; 48]),
                );
                let (pk, sk) = $type_name::keygen(&mut source);
                assert_eq!(source.requests(), 3, "fg_bits, fg_bits again, prf_key");
                let (sound_pk, sound_sk) =
                    $type_name::keygen(&mut CtrDrbgAes256::new(&[0x65u8; 48]));
                assert_eq!(pk, sound_pk);
                assert_eq!(sk, sound_sk);
                assert!(pk.as_bytes().iter().any(|&b| b != 0), "h ≠ 0");
                let mut drbg = CtrDrbgAes256::new(&[0x66u8; 48]);
                let (ct, ss) = $type_name::encaps(&pk, &mut drbg);
                assert_eq!($type_name::decaps(&sk, &ct), ss);
            }

            /// f = 0 through the public API. All-zero fg_bits, and fg_bits
            /// whose f block is zero and whose other bytes are 1, are refused
            /// loudly when every request repeats them and replaced when only
            /// the first request does.
            #[test]
            fn keygen_never_uses_zero_f() {
                let all_zero = vec![0u8; coins_sampling_zero_f(N, FAMILY).len()];
                for fg_bits in [all_zero, coins_sampling_zero_f(N, FAMILY)] {
                    assert_keygen_refuses_loudly(&fg_bits);
                    assert_keygen_draws_again(&fg_bits);
                }
            }

            /// A source stuck on fg_bits that sample f = 0 is reported as
            /// broken.
            #[test]
            #[should_panic(expected = "the random source is broken")]
            fn keygen_panics_when_two_draws_sample_zero_f() {
                let mut source = ScriptedCoinSource::new(
                    coins_sampling_zero_f(N, FAMILY),
                    2,
                    CtrDrbgAes256::new(&[0u8; 48]),
                );
                let _ = $type_name::keygen(&mut source);
            }

            /// g = 0 through the public API. For ntru-hrss, where
            /// L_g = Φ1·T+, fg_bits whose g block is zero are refused like
            /// f = 0. For ntru-hps, `Fixed_Type` has weight q/8 − 2 whatever
            /// its input, so the same bits are used at once and the key pair
            /// works.
            #[test]
            fn keygen_never_uses_zero_hrss_g() {
                let fg_bits = coins_sampling_zero_g(N, FAMILY);
                match FAMILY {
                    Family::Hrss => {
                        assert_keygen_refuses_loudly(&fg_bits);
                        assert_keygen_draws_again(&fg_bits);
                    }
                    Family::Hps => {
                        let mut source =
                            ScriptedCoinSource::new(fg_bits, 1, CtrDrbgAes256::new(&[0u8; 48]));
                        let (pk, sk) = $type_name::keygen(&mut source);
                        assert_eq!(source.requests(), 2);
                        let mut drbg = CtrDrbgAes256::new(&[0x67u8; 48]);
                        let (ct, ss) = $type_name::encaps(&pk, &mut drbg);
                        assert_eq!($type_name::decaps(&sk, &ct), ss);
                    }
                }
            }

            /// Encapsulation from a source whose first request is `coins`,
            /// which sample a zero polynomial, and whose later requests are
            /// sound: the refused coins are discarded, the output equals the
            /// sound source's alone, and decapsulation agrees with it.
            fn assert_encaps_draws_again(pk: &$pk_ty, sk: &$sk_ty, coins: &[u8]) {
                let mut source =
                    ScriptedCoinSource::new(coins.to_vec(), 1, CtrDrbgAes256::new(&[0x65u8; 48]));
                let (ct, ss) = $type_name::encaps(pk, &mut source);
                assert_eq!(source.requests(), 2);
                let (sound_ct, sound_ss) =
                    $type_name::encaps(pk, &mut CtrDrbgAes256::new(&[0x65u8; 48]));
                assert_eq!(ct, sound_ct);
                assert_eq!(ss, sound_ss);
                assert_eq!($type_name::decaps(sk, &ct), ss);
            }

            /// r = 0 through the public API; decapsulation rejects it.
            /// All-zero coins, and coins whose r block is zero and whose other
            /// bytes are 1, are refused loudly when every request repeats
            /// them and replaced when only the first request does.
            #[test]
            fn encaps_never_uses_zero_r() {
                let (pk, sk) = reproduction_keys();
                let all_zero = vec![0u8; sample_plaintext_bytes(N, FAMILY)];
                for coins in [all_zero, coins_sampling_zero_r(N, FAMILY)] {
                    assert_encaps_refuses_loudly(&pk, &coins);
                    assert_encaps_draws_again(&pk, &sk, &coins);
                }
            }

            /// m = 0 through the public API. For ntru-hrss, where L_m = T,
            /// coins whose m block is zero are refused like r = 0. For
            /// ntru-hps, `Fixed_Type` has weight q/8 − 2 whatever its input,
            /// so the same coins are used at once and decapsulate correctly.
            #[test]
            fn encaps_never_uses_zero_hrss_m() {
                let (pk, sk) = reproduction_keys();
                let coins = coins_sampling_zero_m(N, FAMILY);
                match FAMILY {
                    Family::Hrss => {
                        assert_encaps_refuses_loudly(&pk, &coins);
                        assert_encaps_draws_again(&pk, &sk, &coins);
                    }
                    Family::Hps => {
                        let mut source =
                            ScriptedCoinSource::new(coins, 1, CtrDrbgAes256::new(&[0u8; 48]));
                        let (ct, ss) = $type_name::encaps(&pk, &mut source);
                        assert_eq!(source.requests(), 1);
                        assert_eq!($type_name::decaps(&sk, &ct), ss);
                    }
                }
            }

            /// The NIST round-3 known-answer file for this parameter set,
            /// at the default counts: eight sampled entries in a debug build,
            /// all 100 in a release build (`KAT_DEFAULT_COUNTS`).
            #[test]
            fn nist_kat() {
                let rsp = include_str!($kat_path);
                for &count in KAT_DEFAULT_COUNTS {
                    run_kat_count(rsp, count);
                }
            }

            /// All 100 entries of the known-answer file in any build.
            #[test]
            #[ignore = "replays all 100 KAT entries, which a debug build takes seconds per set to do; \
                        release builds run them by default in `nist_kat`; \
                        opt in with `cargo test --lib ntru -- --ignored`"]
            fn nist_kat_full() {
                let rsp = include_str!($kat_path);
                for count in 0..100 {
                    run_kat_count(rsp, count);
                }
            }

            fn run_kat_count(rsp: &str, count: usize) {
                let entry = $crate::public_key::ntru_pqc_shared::parse_kat_entry(rsp, count)
                    .unwrap_or_else(|| panic!("KAT count={count} missing"));
                assert_eq!(entry.seed.len(), 48, "seed length");
                let mut seed = [0u8; 48];
                seed.copy_from_slice(&entry.seed);
                let mut drbg = CtrDrbgAes256::new(&seed);

                let (pk, sk) = $type_name::keygen(&mut drbg);
                assert_eq!(
                    pk.to_wire_bytes().as_slice(),
                    entry.pk.as_slice(),
                    "pk @ count={count}"
                );
                assert_eq!(
                    sk.to_wire_bytes().as_slice(),
                    entry.sk.as_slice(),
                    "sk @ count={count}"
                );

                let (ct, ss) = $type_name::encaps(&pk, &mut drbg);
                assert_eq!(
                    ct.to_wire_bytes().as_slice(),
                    entry.ct.as_slice(),
                    "ct @ count={count}"
                );
                assert_eq!(
                    ss.to_wire_bytes().as_slice(),
                    entry.ss.as_slice(),
                    "ss @ count={count}"
                );

                let ss2 = $type_name::decaps(&sk, &ct);
                assert_eq!(ss.as_bytes(), ss2.as_bytes(), "decaps @ count={count}");
            }
        }
    };
}

pub(crate) use define_ntru_kem;

// ===========================================================================
// Known-answer file parsing (tests only)
// ===========================================================================

/// One entry of a NIST PQC `.rsp` KAT file: 48-byte seed plus the
/// reference-implementation outputs.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct KatEntry {
    pub seed: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub ct: Vec<u8>,
    pub ss: Vec<u8>,
}

/// Parse the `count = N` entry out of a NIST PQC `.rsp` KAT file. Returns
/// `None` if the count is absent (e.g. asking for entry 100 from a 100-entry
/// file).
///
/// The parser scans line-by-line for the literal `count = N` header
/// (after `str::trim`), then collects every `key = hex` line that
/// follows until either a blank line, the next `count =` header, or
/// end-of-file. Unrecognised keys are ignored. This means an extra
/// metadata line in a future `.rsp` (e.g. `mlen = 32`) does not
/// silently truncate the entry.
#[cfg(test)]
pub(crate) fn parse_kat_entry(rsp: &str, count: usize) -> Option<KatEntry> {
    let target = format!("count = {count}");
    let mut lines = rsp.lines();
    while let Some(line) = lines.next() {
        if line.trim() == target {
            let mut seed = None;
            let mut pk = None;
            let mut sk = None;
            let mut ct = None;
            let mut ss = None;
            for line in lines.by_ref() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("count = ") {
                    break;
                }
                let Some((key, value)) = trimmed.split_once(" = ") else {
                    continue;
                };
                let bytes = crate::test_utils::decode_hex(value);
                match key.trim() {
                    "seed" => seed = Some(bytes),
                    "pk" => pk = Some(bytes),
                    "sk" => sk = Some(bytes),
                    "ct" => ct = Some(bytes),
                    "ss" => ss = Some(bytes),
                    _ => {}
                }
            }
            return Some(KatEntry {
                seed: seed?,
                pk: pk?,
                sk: sk?,
                ct: ct?,
                ss: ss?,
            });
        }
    }
    None
}

/// The entries of the NIST round-3 KAT files (100 each) that the per-set
/// `nist_kat` test replays by default. A debug build replays eight counts
/// that span the range, chosen to catch first-entry, state-rollover and
/// final-entry faults without the full sweep's cost; a release build, where
/// all four files replay in well under a second, replays every entry. The
/// per-set `nist_kat_full` replays every entry in any build under
/// `--ignored`.
#[cfg(all(test, debug_assertions))]
pub(crate) const KAT_DEFAULT_COUNTS: &[usize] = &[0, 1, 7, 23, 42, 67, 83, 99];

/// See the debug-build definition.
#[cfg(all(test, not(debug_assertions)))]
pub(crate) const KAT_DEFAULT_COUNTS: &[usize] = &{
    let mut counts = [0usize; 100];
    let mut i = 0;
    while i < 100 {
        counts[i] = i;
        i += 1;
    }
    counts
};

/// A random source for the encapsulation tests: it answers its first
/// `scripted_requests` requests with copies of `coins` (whose length must be
/// the request's) and later ones from `inner`, and it counts the requests it
/// answers.
#[cfg(test)]
pub(crate) struct ScriptedCoinSource<R> {
    coins: Vec<u8>,
    scripted_requests: usize,
    requests: usize,
    inner: R,
}

#[cfg(test)]
impl<R: Csprng> ScriptedCoinSource<R> {
    /// `coins` for the first `scripted_requests` requests, then `inner`.
    pub(crate) fn new(coins: Vec<u8>, scripted_requests: usize, inner: R) -> Self {
        Self {
            coins,
            scripted_requests,
            requests: 0,
            inner,
        }
    }

    /// The number of requests answered so far.
    pub(crate) fn requests(&self) -> usize {
        self.requests
    }
}

#[cfg(test)]
impl<R: Csprng> Csprng for ScriptedCoinSource<R> {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        if self.requests < self.scripted_requests {
            out.copy_from_slice(&self.coins);
        } else {
            self.inner.fill_bytes(out);
        }
        self.requests += 1;
    }
}

/// Encapsulation coins (sample_plaintext_bits / 8 bytes) whose r block is
/// zero bytes and whose remaining bytes are 1: r = 0, and m ≠ 0 for either
/// family.
#[cfg(test)]
pub(crate) fn coins_sampling_zero_r(n: usize, family: Family) -> Vec<u8> {
    let mut coins = vec![1u8; sample_plaintext_bytes(n, family)];
    coins[..sample_iid_bytes(n)].fill(0);
    coins
}

/// Encapsulation coins whose r block is bytes 1 and whose m block is zero
/// bytes: r ≠ 0, and m = 0 for ntru-hrss. For ntru-hps `Fixed_Type` returns
/// weight q/8 − 2 from any input, so m ≠ 0 there.
#[cfg(test)]
pub(crate) fn coins_sampling_zero_m(n: usize, family: Family) -> Vec<u8> {
    let mut coins = vec![0u8; sample_plaintext_bytes(n, family)];
    coins[..sample_iid_bytes(n)].fill(1);
    coins
}

/// Key-generation bits (sample_key_bits / 8 bytes) whose f block is zero
/// bytes and whose g block is bytes 1: f = 0, and g ≠ 0 for either family.
/// The blocks are laid out as the encapsulation coins' r and m blocks
/// (§1.10.1 and §1.10.2 split their input at the same offset), so the byte
/// strings coincide with [`coins_sampling_zero_r`].
#[cfg(test)]
pub(crate) fn coins_sampling_zero_f(n: usize, family: Family) -> Vec<u8> {
    let mut coins = vec![1u8; sample_key_bytes(n, family)];
    coins[..sample_iid_bytes(n)].fill(0);
    coins
}

/// Key-generation bits whose f block is bytes 1 and whose g block is zero
/// bytes: f ≠ 0, and g = 0 for ntru-hrss. For ntru-hps `Fixed_Type` returns
/// weight q/8 − 2 from any input, so g ≠ 0 there.
#[cfg(test)]
pub(crate) fn coins_sampling_zero_g(n: usize, family: Family) -> Vec<u8> {
    let mut coins = vec![0u8; sample_key_bytes(n, family)];
    coins[..sample_iid_bytes(n)].fill(1);
    coins
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64* (Marsaglia's xorshift with a multiplicative output
    /// scramble): deterministic test data without the crate's CSPRNG.
    struct TestRng(u64);

    impl TestRng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }

        fn below(&mut self, bound: u32) -> u32 {
            (self.next_u64() % u64::from(bound)) as u32
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| (self.next_u64() >> 56) as u8).collect()
        }

        fn residues<const N: usize>(&mut self, modulus: u32) -> [u16; N] {
            let mut a = [0u16; N];
            for c in &mut a {
                *c = self.below(modulus) as u16;
            }
            a
        }

        fn canonical_s3<const N: usize>(&mut self) -> [u16; N] {
            let mut a: [u16; N] = self.residues(3);
            a[N - 1] = 0;
            a
        }
    }

    const EDGE_U32: [u32; 10] = [
        0,
        1,
        2,
        3,
        0x1234_5678,
        0x7fff_ffff,
        0x8000_0000,
        0x8000_0001,
        0xffff_fffe,
        0xffff_ffff,
    ];

    fn mask(condition: bool) -> u32 {
        if condition {
            u32::MAX
        } else {
            0
        }
    }

    fn one<const N: usize>() -> [u16; N] {
        let mut e = [0u16; N];
        e[0] = 1;
        e
    }

    fn signed(c: u16) -> i64 {
        i64::from(c as i16)
    }

    /// Cyclic product modulo x^n − 1 with coefficients reduced into
    /// [0, modulus), from the definition.
    fn reference_cyclic_product<const N: usize>(
        a: &[i64; N],
        b: &[i64; N],
        modulus: i64,
    ) -> [i64; N] {
        let mut c = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                c[(i + j) % N] = (c[(i + j) % N] + a[i] * b[j]).rem_euclid(modulus);
            }
        }
        c
    }

    /// Product reduced modulo (modulus, Φn) to the representative of degree at
    /// most n − 2, from the definitions.
    fn reference_product_mod_phi<const N: usize>(
        a: &[u16; N],
        b: &[u16; N],
        modulus: i64,
    ) -> [u16; N] {
        let c = reference_cyclic_product(&a.map(i64::from), &b.map(i64::from), modulus);
        let top = c[N - 1];
        c.map(|x| (x - top).rem_euclid(modulus) as u16)
    }

    // ---- constant-time helpers against direct formulas --------------------

    #[test]
    fn ct_mask_nonzero_u32_matches_definition() {
        let mut rng = TestRng(0x0123_4567_89ab_cdef);
        let randoms: Vec<u32> = (0..100_000).map(|_| rng.next_u32()).collect();
        for x in (0..=u32::from(u16::MAX)).chain(EDGE_U32).chain(randoms) {
            assert_eq!(ct_mask_nonzero_u32(x), mask(x != 0), "x = {x:#x}");
        }
    }

    #[test]
    fn ct_mask_lt_u32_matches_definition() {
        for a in EDGE_U32 {
            for b in EDGE_U32 {
                assert_eq!(ct_mask_lt_u32(a, b), mask(a < b), "{a:#x} < {b:#x}");
            }
        }
        for a in 0..300u32 {
            for b in 0..300u32 {
                assert_eq!(ct_mask_lt_u32(a, b), mask(a < b));
            }
        }
        let mut rng = TestRng(2);
        for _ in 0..100_000 {
            let (a, b) = (rng.next_u32(), rng.next_u32());
            assert_eq!(ct_mask_lt_u32(a, b), mask(a < b));
            assert_eq!(ct_mask_lt_u32(a, a), 0);
            let c = a.wrapping_add(1);
            assert_eq!(ct_mask_lt_u32(a, c), mask(a < c));
        }
    }

    #[test]
    fn ct_reduce_once_matches_definition() {
        let reference = |x: u32, m: u32| if x >= m { x - m } else { x };
        for m in [1u32, 3, 243, 2048, 4096, 8192, 65536] {
            for x in 0..2 * m {
                assert_eq!(ct_reduce_once(x, m), reference(x, m), "x = {x}, m = {m}");
            }
        }
        let mut rng = TestRng(3);
        for _ in 0..100_000 {
            let m = rng.below(1 << 31) + 1;
            let x = (u64::from(rng.next_u32()) % (2 * u64::from(m))) as u32;
            assert_eq!(ct_reduce_once(x, m), reference(x, m), "x = {x}, m = {m}");
        }
        for x in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            assert_eq!(ct_reduce_once(x, 1 << 31), reference(x, 1 << 31));
        }
    }

    #[test]
    fn ct_mod3_is_exhaustively_correct() {
        for x in 0..=u16::MAX {
            assert_eq!(ct_mod3(x), x % 3, "x = {x}");
        }
    }

    /// The maxima the `ct_mod3` derivation states, each evaluated over the
    /// range the previous step leaves, with the inputs that attain them.
    #[test]
    fn ct_mod3_step_maxima_match_the_derivation() {
        let step = |y: u32, shift: u32, mask: u32| (y >> shift) + (y & mask);
        let maximum = |bound: u32, shift: u32, mask: u32| {
            let top = (0..=bound).map(|y| step(y, shift, mask)).max().unwrap();
            let at: Vec<u32> = (0..=bound)
                .filter(|&y| step(y, shift, mask) == top)
                .collect();
            (top, at)
        };
        assert_eq!(maximum(65535, 8, 0xff), (510, vec![65535]));
        assert_eq!(maximum(510, 4, 0x0f), (45, vec![495, 510]));
        assert_eq!(maximum(45, 2, 0x03), (13, vec![43]));
        assert_eq!(maximum(13, 2, 0x03), (5, vec![11]));
    }

    #[test]
    fn ct_mod3_signed_is_exhaustively_correct() {
        for c in -(1i32 << 14)..(1i32 << 14) {
            assert_eq!(
                i32::from(ct_mod3_signed(c as u16)),
                c.rem_euclid(3),
                "c = {c}"
            );
        }
    }

    #[test]
    fn centered_mod_q_is_exhaustively_correct() {
        for log_q in [11u32, 12, 13] {
            let q = 1i64 << log_q;
            for x in 0..=u16::MAX {
                let residue = i64::from(x) % q;
                let centered = if residue >= q / 2 {
                    residue - q
                } else {
                    residue
                };
                assert_eq!(
                    signed(centered_mod_q(x, log_q)),
                    centered,
                    "x = {x}, logq = {log_q}"
                );
            }
        }
    }

    #[test]
    fn s3_residue_helpers_match_integer_arithmetic() {
        for a in 0..3u16 {
            let value = signed(s3_residue_to_signed(a));
            assert!((-1..=1).contains(&value));
            assert_eq!(value.rem_euclid(3), i64::from(a));
            assert_eq!(s3_neg(a), (3 - a) % 3);
            for b in 0..3u16 {
                assert_eq!(s3_add(a, b), (a + b) % 3);
                assert_eq!(s3_sub(a, b), (a + 3 - b) % 3);
            }
        }
    }

    #[test]
    fn ct_compare_exchange_orders_every_pair() {
        let mut rng = TestRng(4);
        let mut pairs: Vec<(u32, u32)> = EDGE_U32
            .iter()
            .flat_map(|&a| EDGE_U32.iter().map(move |&b| (a, b)))
            .collect();
        pairs.extend((0..10_000).map(|_| (rng.next_u32(), rng.next_u32())));
        for (a, b) in pairs {
            let (mut lo, mut hi) = (a, b);
            ct_compare_exchange(&mut lo, &mut hi);
            assert_eq!((lo, hi), (a.min(b), a.max(b)));
        }
    }

    #[test]
    fn sort_u32_constant_time_matches_std_sort() {
        let mut rng = TestRng(5);
        for len in (0..=70).chain([127, 128, 129, 508, 676, 820]) {
            let cases: Vec<Vec<u32>> = vec![
                (0..len).map(|_| rng.next_u32()).collect(),
                (0..len).map(|_| rng.below(4)).collect(),
                (0..len as u32).rev().collect(),
                vec![u32::MAX; len],
                (0..len)
                    .map(|i| if i % 2 == 0 { u32::MAX } else { 0 })
                    .collect(),
            ];
            for case in cases {
                let mut got = case.clone();
                sort_u32_constant_time(&mut got);
                let mut want = case;
                want.sort_unstable();
                assert_eq!(got, want, "length {len}");
            }
        }
    }

    #[test]
    fn s3_digits_match_the_base_3_expansion() {
        for byte in 0..=u8::MAX {
            let value = u32::from(byte) % 243;
            for (j, &digit) in s3_digits(byte).iter().enumerate() {
                assert_eq!(
                    u32::from(digit),
                    value / 3u32.pow(j as u32) % 3,
                    "byte {byte}, digit {j}"
                );
            }
        }
    }

    #[test]
    fn membership_masks_match_their_definitions() {
        let mut rng = TestRng(6);
        for log_q in [11u32, 12, 13] {
            let q = 1u16 << log_q;
            let mut zero = [0u16; 13];
            assert_eq!(ct_mask_sq_in_t(&zero, log_q), 0, "zero is not in T");
            for _ in 0..5000 {
                let mut r = [0u16; 13];
                for c in &mut r[..12] {
                    *c = match rng.below(8) {
                        0..=2 => 0,
                        3 => 1,
                        4 => q - 1,
                        5 => 2,
                        6 => q - 2,
                        _ => rng.below(u32::from(q)) as u16,
                    };
                }
                let in_t =
                    r.iter().all(|&c| c == 0 || c == 1 || c == q - 1) && r.iter().any(|&c| c != 0);
                assert_eq!(ct_mask_sq_in_t(&r, log_q), mask(in_t), "{r:?}");
            }
            zero[3] = 2;
            assert_eq!(ct_mask_s3_in_t(&zero), u32::MAX);
            assert_eq!(ct_mask_s3_in_t(&[0u16; 13]), 0);
        }
        for (n_log_q, target) in [(11u32, 127usize), (12, 255)] {
            for (plus, minus) in [
                (target, target),
                (target - 1, target),
                (target, target + 1),
                (0, 0),
            ] {
                let mut m = [0u16; 821];
                for c in &mut m[..plus] {
                    *c = 1;
                }
                for c in &mut m[plus..plus + minus] {
                    *c = 2;
                }
                let want = mask(plus == target && minus == target);
                assert_eq!(
                    ct_mask_s3_in_fixed_type(&m, n_log_q),
                    want,
                    "{plus}/{minus}"
                );
            }
        }
    }

    // ---- parameters ---------------------------------------------------------

    #[test]
    fn derived_constants_match_the_specification_table() {
        // Spec §1.6: n, logq, family, sample_fixed_type_bits, sample_iid_bits,
        // sample_key_bits, packed_s3_bytes, packed_rq0_bytes, packed_sq_bytes,
        // dpke_private_key_bytes, dpke_plaintext_bytes, kem_private_key_bytes.
        let table = [
            (
                509,
                11,
                Family::Hps,
                Some(15240),
                4064,
                19304,
                102,
                699,
                699,
                903,
                204,
                935,
            ),
            (
                677,
                11,
                Family::Hps,
                Some(20280),
                5408,
                25688,
                136,
                930,
                930,
                1202,
                272,
                1234,
            ),
            (
                821,
                12,
                Family::Hps,
                Some(24600),
                6560,
                31160,
                164,
                1230,
                1230,
                1558,
                328,
                1590,
            ),
            (
                701,
                13,
                Family::Hrss,
                None,
                5600,
                11200,
                140,
                1138,
                1138,
                1418,
                280,
                1450,
            ),
        ];
        for (n, log_q, family, fixed_bits, iid_bits, key_bits, s3, rq0, sq, dpke_sk, pt, kem_sk) in
            table
        {
            if let Some(bits) = fixed_bits {
                assert_eq!(bits % 8, 0);
                assert_eq!(8 * sample_fixed_type_bytes(n), bits);
            }
            assert_eq!(8 * sample_iid_bytes(n), iid_bits);
            assert_eq!(8 * sample_key_bytes(n, family), key_bits);
            assert_eq!(8 * sample_plaintext_bytes(n, family), key_bits);
            assert_eq!(packed_s3_bytes(n), s3);
            assert_eq!(packed_rq0_bytes(n, log_q), rq0);
            assert_eq!(packed_sq_bytes(n, log_q), sq);
            assert_eq!(dpke_private_key_bytes(n, log_q), dpke_sk);
            assert_eq!(dpke_plaintext_bytes(n), pt);
            assert_eq!(kem_public_key_bytes(n, log_q), rq0);
            assert_eq!(kem_ciphertext_bytes(n, log_q), rq0);
            assert_eq!(kem_private_key_bytes(n, log_q), kem_sk);
        }
    }

    #[test]
    fn recommended_parameters_satisfy_the_family_conditions() {
        fn order(g: usize, n: usize) -> usize {
            let mut x = g % n;
            let mut k = 1;
            while x != 1 {
                x = x * g % n;
                k += 1;
            }
            k
        }
        for (n, log_q, family) in [
            (509usize, 11u32, Family::Hps),
            (677, 11, Family::Hps),
            (821, 12, Family::Hps),
            (701, 13, Family::Hrss),
        ] {
            assert!(
                (2..n).take_while(|d| d * d <= n).all(|d| n % d != 0),
                "{n} is prime"
            );
            assert_eq!(order(2, n), n - 1, "order of 2 modulo {n}");
            assert_eq!(order(3, n), n - 1, "order of 3 modulo {n}");
            let q = 1usize << log_q;
            match family {
                // §1.3.2: recommended only with q/8 − 2 ≤ 2n/3.
                Family::Hps => assert!(3 * (q / 8 - 2) <= 2 * n),
                // §1.3.3: q = 2^⌈7/2 + log2 n⌉, i.e.
                // 2^(logq − 1) < 2^3.5·n ≤ 2^logq; squared, integers only.
                Family::Hrss => {
                    let scaled = 128 * n * n;
                    assert!(q * q / 4 < scaled && scaled <= q * q);
                }
            }
        }
    }

    // ---- encodings ----------------------------------------------------------

    /// Bit i (0-based) of a byte string, low bit of each byte first
    /// (spec §1.8.1).
    fn bit(bytes: &[u8], i: usize) -> u32 {
        u32::from(bytes[i / 8] >> (i % 8)) & 1
    }

    fn check_encodings<const N: usize>(log_q: u32, seed: u64) {
        let mut rng = TestRng(seed);
        let q = 1u32 << log_q;
        let width = log_q as usize;

        // pack_Rq0 / unpack_Rq0 against the bit-string definition.
        let mut a = [0u16; N];
        for c in &mut a[..N - 1] {
            *c = rng.next_u32() as u16;
        }
        a[N - 1] = a[..N - 1].iter().fold(0u16, |s, &c| s.wrapping_sub(c));
        let mut packed = vec![0u8; packed_rq0_bytes(N, log_q)];
        pack_rq0(&mut packed, &a, log_q);
        for (i, &coefficient) in a.iter().enumerate().take(N - 1) {
            let value: u32 = (0..width).map(|j| bit(&packed, i * width + j) << j).sum();
            assert_eq!(value, u32::from(coefficient) % q, "coefficient {i}");
        }
        for i in (N - 1) * width..packed.len() * 8 {
            assert_eq!(bit(&packed, i), 0, "padding bit {i}");
        }
        let (unpacked, padding) = unpack_rq0::<N>(&packed, log_q);
        assert_eq!(padding, 0);
        for i in 0..N {
            assert_eq!(u32::from(unpacked[i]), u32::from(a[i]) % q);
        }
        if !((N - 1) * width).is_multiple_of(8) {
            let mut bad = packed.clone();
            *bad.last_mut().unwrap() |= 0x80;
            let (same, padding) = unpack_rq0::<N>(&bad, log_q);
            assert_ne!(padding, 0);
            assert_eq!(same, unpacked);
        }

        // pack_Sq encodes Sq(b); unpack_Sq recovers it.
        let mut b = [0u16; N];
        for c in &mut b {
            *c = rng.next_u32() as u16;
        }
        let mut packed = vec![0u8; packed_sq_bytes(N, log_q)];
        pack_sq(&mut packed, &b, log_q);
        let unpacked = unpack_sq::<N>(&packed, log_q);
        for i in 0..N - 1 {
            assert_eq!(
                u32::from(unpacked[i]),
                u32::from(b[i].wrapping_sub(b[N - 1])) % q
            );
        }
        assert_eq!(unpacked[N - 1], 0);

        // pack_S3 against byte = Σ 3^j·v_(5i+j), and the round trip.
        let s: [u16; N] = rng.canonical_s3();
        let mut packed = vec![0u8; packed_s3_bytes(N)];
        pack_s3(&mut packed, &s);
        for (i, &byte) in packed.iter().enumerate() {
            let expected: u32 = (0..5)
                .map(|j| {
                    let index = 5 * i + j;
                    let trit = if index < N { u32::from(s[index]) } else { 0 };
                    trit * 3u32.pow(j as u32)
                })
                .sum();
            assert_eq!(u32::from(byte), expected, "byte {i}");
        }
        assert_eq!(unpack_s3::<N>(&packed), s);

        // pack_S3 reduces modulo Φn first.
        let mut t = s;
        t[N - 1] = 2;
        let reduced = t.map(|c| ((i64::from(c) - 2).rem_euclid(3)) as u16);
        let mut packed_t = vec![0u8; packed_s3_bytes(N)];
        pack_s3(&mut packed_t, &t);
        pack_s3(&mut packed, &reduced);
        assert_eq!(packed_t, packed);

        // unpack_S3 of arbitrary bytes is S3 of the digit polynomial.
        for fill in [None, Some(0xffu8), Some(243)] {
            let bytes = match fill {
                None => rng.bytes(packed_s3_bytes(N)),
                Some(value) => vec![value; packed_s3_bytes(N)],
            };
            let mut v = [0i64; N];
            for (i, &byte) in bytes.iter().enumerate() {
                let mut x = i64::from(byte) % 243;
                for j in 0..5 {
                    v[(5 * i + j) % N] += x % 3;
                    x /= 3;
                }
            }
            let top = v[N - 1];
            let expected = v.map(|c| (c - top).rem_euclid(3) as u16);
            assert_eq!(unpack_s3::<N>(&bytes), expected, "fill {fill:?}");
        }
    }

    #[test]
    fn encodings_match_their_definitions() {
        check_encodings::<509>(11, 11);
        check_encodings::<677>(11, 12);
        check_encodings::<821>(12, 13);
        check_encodings::<701>(13, 14);
    }

    // ---- arithmetic ---------------------------------------------------------

    #[test]
    fn field_inverse_is_exhaustively_correct_for_n_5() {
        // 2 and 3 both have order 4 modulo 5, so S/2 is GF(16) and S/3 is
        // GF(81). Every residue vector of length 5 is tried, including
        // non-canonical ones; those with all coefficients equal are multiples
        // of Φ5 and have no inverse.
        for p in [2usize, 3] {
            for index in 0..p.pow(5) {
                let mut a = [0u16; 5];
                let mut x = index;
                for c in &mut a {
                    *c = (x % p) as u16;
                    x /= p;
                }
                let inverse = field_inverse(&a, p);
                assert_eq!(inverse[4], 0);
                if a.iter().all(|&c| c == a[0]) {
                    assert_eq!(inverse, [0u16; 5], "{a:?} ≡ 0");
                } else {
                    assert_eq!(
                        reference_product_mod_phi(&a, &inverse, p as i64),
                        one::<5>(),
                        "{a:?} mod {p}"
                    );
                }
            }
        }
    }

    fn check_field_inverse<const N: usize>(seed: u64, trials: usize) {
        let mut rng = TestRng(seed);
        for p in [2u32, 3] {
            for _ in 0..trials {
                let a: [u16; N] = rng.residues(p);
                let inverse = field_inverse(&a, p as usize);
                assert_eq!(
                    reference_product_mod_phi(&a, &inverse, i64::from(p)),
                    one::<N>()
                );
            }
        }
    }

    #[test]
    fn field_inverse_is_correct_at_the_recommended_degrees() {
        check_field_inverse::<29>(29, 20);
        check_field_inverse::<509>(509, 2);
        check_field_inverse::<677>(677, 2);
        check_field_inverse::<701>(701, 2);
        check_field_inverse::<821>(821, 2);
    }

    fn check_sq_inverse<const N: usize>(log_q: u32, seed: u64) {
        let mut rng = TestRng(seed);
        let q = 1u32 << log_q;
        for _ in 0..2 {
            let a: [u16; N] = rng.residues(q);
            let b = sq_inverse(&a, log_q);
            assert_eq!(b[N - 1], 0);
            assert!(b.iter().all(|&c| u32::from(c) < q));
            assert_eq!(reference_product_mod_phi(&a, &b, i64::from(q)), one::<N>());
        }
    }

    #[test]
    fn sq_inverse_is_correct_at_the_recommended_parameters() {
        check_sq_inverse::<509>(11, 1);
        check_sq_inverse::<677>(11, 2);
        check_sq_inverse::<821>(12, 3);
        check_sq_inverse::<701>(13, 4);
    }

    fn check_lift<const N: usize>(seed: u64) {
        let mut rng = TestRng(seed);
        for trial in 0..20 {
            let m: [u16; N] = if trial == 0 {
                one()
            } else {
                rng.canonical_s3()
            };
            let hrss = lift(Family::Hrss, &m);
            // Φ1 divides the ntru-hrss Lift: the coefficients sum to zero.
            assert_eq!(hrss.iter().map(|&c| signed(c)).sum::<i64>(), 0);
            assert!(hrss.iter().all(|&c| (-2..=2).contains(&signed(c))));
            // S3(Lift(m)) = m (spec §1.3.1).
            let top = signed(hrss[N - 1]);
            assert_eq!(hrss.map(|c| (signed(c) - top).rem_euclid(3) as u16), m);
            // ntru-hps: Lift(m) = S3(m), also for a non-canonical input.
            assert_eq!(lift(Family::Hps, &m), m.map(s3_residue_to_signed));
            let mut shifted = m.map(|c| (c + 1) % 3);
            shifted[N - 1] = 1;
            assert_eq!(lift(Family::Hps, &shifted), m.map(s3_residue_to_signed));
        }
        // Spec §1.9.3 note 1: S3(1/Φ1) has period-3 coefficients.
        let w = s3_divide_by_phi1(&one::<N>());
        assert_eq!(w[N - 1], 0);
        for (i, &c) in w[..N - 1].iter().enumerate() {
            let expected = if N % 3 == 1 { i as i64 } else { 1 - i as i64 };
            assert_eq!(i64::from(c), expected.rem_euclid(3), "coefficient {i}");
        }
    }

    #[test]
    fn lift_satisfies_its_specification() {
        check_lift::<7>(7); // n ≡ 1 (mod 3)
        check_lift::<13>(13); // n ≡ 1 (mod 3)
        check_lift::<29>(29); // n ≡ 2 (mod 3)
        check_lift::<701>(701);
        check_lift::<509>(509);
    }

    // ---- sampling -----------------------------------------------------------

    fn reference_ternary<const N: usize>(bits: &[u8]) -> [i64; N] {
        let mut v = [0i64; N];
        for (c, &b) in v.iter_mut().zip(bits) {
            *c = match b % 3 {
                0 => 0,
                1 => 1,
                _ => -1,
            };
        }
        v
    }

    fn reference_ternary_plus<const N: usize>(bits: &[u8]) -> [i64; N] {
        let mut v = reference_ternary::<N>(bits);
        let t: i64 = (0..N - 1).map(|i| v[i] * v[i + 1]).sum();
        let s = if t < 0 { -1 } else { 1 };
        for i in (0..N - 1).step_by(2) {
            v[i] *= s;
        }
        v
    }

    #[test]
    fn ternary_and_ternary_plus_match_the_specification() {
        let mut rng = TestRng(8);
        let mut inputs: Vec<Vec<u8>> = (0..20).map(|_| rng.bytes(700)).collect();
        inputs.push((0..700).map(|i| [1u8, 2][i % 2]).collect()); // t = −(n − 2)
        inputs.push((0..700).map(|i| [1u8, 1][i % 2]).collect()); // t = n − 2
        inputs.push(vec![0u8; 700]); // t = 0
        for bits in inputs {
            let residues = |v: [i64; 701]| v.map(|c| c.rem_euclid(3) as u16);
            assert_eq!(ternary::<701>(&bits), residues(reference_ternary(&bits)));
            let plus = reference_ternary_plus::<701>(&bits);
            assert!((0..700).map(|i| plus[i] * plus[i + 1]).sum::<i64>() >= 0);
            assert_eq!(ternary_plus::<701>(&bits), residues(plus));
        }
    }

    fn check_fixed_type<const N: usize>(log_q: u32, seed: u64) {
        let mut rng = TestRng(seed);
        let q = 1usize << log_q;
        for _ in 0..3 {
            let bits = rng.bytes(sample_fixed_type_bytes(N));
            let bit_at = |i: usize| u64::from(bits[i / 8] >> (i % 8)) & 1;
            let mut a: Vec<u64> = (0..N - 1)
                .map(|i| {
                    let label = if i < q / 16 - 1 {
                        1
                    } else if i < q / 8 - 2 {
                        2
                    } else {
                        0
                    };
                    label + (0..30).map(|j| bit_at(30 * i + j) << (2 + j)).sum::<u64>()
                })
                .collect();
            // Known-answer order: the A_i as 32-bit two's complement
            // integers (see `fixed_type`).
            a.sort_unstable_by_key(|&x| x as u32 as i32);
            let mut expected = [0u16; N];
            for (e, &x) in expected.iter_mut().zip(&a) {
                *e = (x % 4) as u16;
            }
            let got = fixed_type::<N>(&bits, log_q);
            assert_eq!(got, expected);
            assert_eq!(got.iter().filter(|&&c| c == 1).count(), q / 16 - 1);
            assert_eq!(got.iter().filter(|&&c| c == 2).count(), q / 16 - 1);
            assert_eq!(got[N - 1], 0);
        }
    }

    #[test]
    fn fixed_type_matches_the_specification() {
        check_fixed_type::<509>(11, 21);
        check_fixed_type::<677>(11, 22);
        check_fixed_type::<821>(12, 23);
    }

    // ---- DPKE ---------------------------------------------------------------

    fn check_public_key_conditions<const N: usize>(log_q: u32, family: Family, seed: u64) {
        let mut rng = TestRng(seed);
        let q = 1i64 << log_q;
        let (f, g) = sample_fg::<N>(family, log_q, &rng.bytes(sample_key_bytes(N, family)))
            .expect("uniform coins lie in L_f × L_g");
        let (h, hq) = dpke_public_key(&f, &g, log_q);
        // Rq(h·f) = 3·g (spec §1.11.2 output).
        let hf = reference_cyclic_product(
            &h.map(i64::from),
            &f.map(|c| signed(s3_residue_to_signed(c))),
            q,
        );
        assert_eq!(hf, g.map(|c| (3 * signed(c)).rem_euclid(q)));
        // Sq(h·hq) = 1.
        let h_mod_q = h.map(|c| (i64::from(c) % q) as u16);
        let hq_mod_q = hq.map(|c| (i64::from(c) % q) as u16);
        assert_eq!(
            reference_product_mod_phi(&h_mod_q, &hq_mod_q, q),
            one::<N>()
        );
        // f·S3_inverse(f) = 1 in S/3.
        assert_eq!(
            reference_product_mod_phi(&f, &s3_inverse(&f), 3),
            one::<N>()
        );
        // g ∈ L_g.
        match family {
            Family::Hps => {
                let weight = (q / 8 - 2) as usize;
                assert_eq!(g.iter().filter(|&&c| signed(c) != 0).count(), weight);
                assert_eq!(g.iter().map(|&c| signed(c)).sum::<i64>(), 0);
            }
            Family::Hrss => assert_eq!(g.iter().map(|&c| signed(c)).sum::<i64>(), 0),
        }
    }

    #[test]
    fn dpke_public_key_meets_its_output_conditions() {
        check_public_key_conditions::<509>(11, Family::Hps, 31);
        check_public_key_conditions::<821>(12, Family::Hps, 32);
        check_public_key_conditions::<701>(13, Family::Hrss, 33);
    }

    struct TestHps509;

    impl ParameterSet<509> for TestHps509 {
        const LOG_Q: u32 = 11;
        const FAMILY: Family = Family::Hps;
    }

    struct TestHps677;

    impl ParameterSet<677> for TestHps677 {
        const LOG_Q: u32 = 11;
        const FAMILY: Family = Family::Hps;
    }

    struct TestHps821;

    impl ParameterSet<821> for TestHps821 {
        const LOG_Q: u32 = 12;
        const FAMILY: Family = Family::Hps;
    }

    struct TestHrss701;

    impl ParameterSet<701> for TestHrss701 {
        const LOG_Q: u32 = 13;
        const FAMILY: Family = Family::Hrss;
    }

    /// A KEM key pair (packed private key, packed public key) from `seed`.
    fn test_key_pair<P: ParameterSet<N>, const N: usize>(seed: u64) -> (Vec<u8>, Vec<u8>) {
        let mut rng = TestRng(seed);
        let key_seed = rng.bytes(sample_key_bytes(N, P::FAMILY) + PRF_KEY_BYTES);
        let mut sk = vec![0u8; kem_private_key_bytes(N, P::LOG_Q)];
        let mut pk = vec![0u8; kem_public_key_bytes(N, P::LOG_Q)];
        key_pair::<P, N>(&key_seed, &mut sk, &mut pk).expect("a uniform seed lies in L_f × L_g");
        (sk, pk)
    }

    /// Runs the explicit-seed [`key_pair`] and reports whether it accepted
    /// `fg_bits`. A refused seed must leave both outputs unwritten; an
    /// accepted one must give a key pair with h ≠ 0 whose encapsulation
    /// decapsulates to the same shared key.
    fn key_generation_accepts<P: ParameterSet<N>, const N: usize>(fg_bits: &[u8]) -> bool {
        let mut seed = fg_bits.to_vec();
        seed.extend_from_slice(&[0x5cu8; PRF_KEY_BYTES]);
        let mut sk = vec![0xa5u8; kem_private_key_bytes(N, P::LOG_Q)];
        let mut pk = vec![0xa5u8; kem_public_key_bytes(N, P::LOG_Q)];
        if key_pair::<P, N>(&seed, &mut sk, &mut pk).is_none() {
            assert!(
                sk.iter().chain(&pk).all(|&b| b == 0xa5),
                "a refused seed wrote an output"
            );
            return false;
        }
        assert!(pk.iter().any(|&b| b != 0), "h = 0");
        let coins = TestRng(0x6667).bytes(sample_plaintext_bytes(N, P::FAMILY));
        assert!(encapsulation_accepts::<P, N>(&sk, &pk, &coins));
        true
    }

    /// f = 0 at the explicit-seed boundary: an f block of zero bytes, or of
    /// multiples of 3 that are not all zero, is refused whatever the g block
    /// holds, and one non-zero f coefficient makes the seed acceptable.
    fn check_explicit_seed_sampling_zero_f<P: ParameterSet<N>, const N: usize>(seed: u64) {
        let iid = sample_iid_bytes(N);
        let mut fg_bits = coins_sampling_zero_f(N, P::FAMILY);
        assert!(!key_generation_accepts::<P, N>(&fg_bits));
        fg_bits[..iid].copy_from_slice(&zero_ternary_coins(iid));
        let g_len = fg_bits.len() - iid;
        fg_bits[iid..].copy_from_slice(&TestRng(!seed).bytes(g_len));
        assert!(!key_generation_accepts::<P, N>(&fg_bits));
        fg_bits[iid / 2] = 1;
        assert!(key_generation_accepts::<P, N>(&fg_bits));
    }

    #[test]
    fn explicit_seeds_sampling_zero_f_are_refused() {
        check_explicit_seed_sampling_zero_f::<TestHps509, 509>(51);
        check_explicit_seed_sampling_zero_f::<TestHps677, 677>(52);
        check_explicit_seed_sampling_zero_f::<TestHps821, 821>(53);
        check_explicit_seed_sampling_zero_f::<TestHrss701, 701>(54);
    }

    /// g bits that give only zero `Ternary_Plus` coefficients at the
    /// explicit-seed boundary: an ntru-hrss g = 0 is refused, and one
    /// non-zero g coefficient makes the seed acceptable. For ntru-hps the same
    /// bits are accepted, because `Fixed_Type` always returns weight q/8 − 2.
    fn check_explicit_seed_sampling_zero_g<P: ParameterSet<N>, const N: usize>() {
        let iid = sample_iid_bytes(N);
        let hps = P::FAMILY == Family::Hps;
        let mut fg_bits = coins_sampling_zero_g(N, P::FAMILY);
        assert_eq!(key_generation_accepts::<P, N>(&fg_bits), hps);
        let g_len = fg_bits.len() - iid;
        fg_bits[iid..].copy_from_slice(&zero_ternary_coins(g_len));
        assert_eq!(key_generation_accepts::<P, N>(&fg_bits), hps);
        let last = fg_bits.len() - 1;
        fg_bits[last] = 5;
        assert!(key_generation_accepts::<P, N>(&fg_bits));
    }

    #[test]
    fn explicit_seeds_sampling_zero_hrss_g_are_refused() {
        check_explicit_seed_sampling_zero_g::<TestHrss701, 701>();
        check_explicit_seed_sampling_zero_g::<TestHps509, 509>();
        check_explicit_seed_sampling_zero_g::<TestHps677, 677>();
        check_explicit_seed_sampling_zero_g::<TestHps821, 821>();
    }

    /// `sample_fg` refuses exactly the seeds whose f, or ntru-hrss g, is
    /// zero: the zero polynomial is what the literal procedure would return.
    #[test]
    fn sample_fg_refuses_exactly_the_zero_polynomials() {
        let fg_bits = coins_sampling_zero_f(701, Family::Hrss);
        assert!(sample_fg::<701>(Family::Hrss, 13, &fg_bits).is_none());
        assert_eq!(ternary_plus::<701>(&fg_bits[..700]), [0u16; 701]);
        let fg_bits = coins_sampling_zero_g(701, Family::Hrss);
        assert!(sample_fg::<701>(Family::Hrss, 13, &fg_bits).is_none());
        assert_eq!(ternary_plus::<701>(&fg_bits[700..]), [0u16; 701]);
        let (f, g) = sample_fg::<509>(Family::Hps, 11, &coins_sampling_zero_g(509, Family::Hps))
            .expect("Fixed_Type never returns 0");
        assert_ne!(f, [0u16; 509]);
        assert_eq!(g.iter().filter(|&&c| c != 0).count(), 2048 / 8 - 2);
    }

    /// Spec §1.2 item 13 defines T as the non-zero ternary polynomials, so a
    /// ciphertext built with r = 0, or with m = 0, decrypts to the right
    /// plaintext but fails line 11 (an ntru-hps m = 0 also has the wrong
    /// weight), and decapsulation returns the rejection key.
    fn check_decryption_rejects_zero_polynomials<P: ParameterSet<N>, const N: usize>(seed: u64) {
        let log_q = P::LOG_Q;
        let (sk, pk) = test_key_pair::<P, N>(seed);
        let coins = TestRng(!seed).bytes(sample_plaintext_bytes(N, P::FAMILY));
        let (r, m) =
            sample_rm::<N>(P::FAMILY, log_q, &coins).expect("uniform coins lie in L_r × L_m");
        let zero = [0u16; N];
        let s3 = packed_s3_bytes(N);
        for (r, m, valid) in [(&r, &m, true), (&zero, &m, false), (&r, &zero, false)] {
            let mut packed_rm = vec![0u8; 2 * s3];
            pack_s3(&mut packed_rm[..s3], r);
            pack_s3(&mut packed_rm[s3..], m);
            let mut ct = vec![0u8; kem_ciphertext_bytes(N, log_q)];
            dpke_encrypt::<P, N>(&pk, &packed_rm, &mut ct);
            let mut recovered = vec![0u8; 2 * s3];
            let fail =
                dpke_decrypt::<P, N>(&sk[..dpke_private_key_bytes(N, log_q)], &ct, &mut recovered);
            assert_eq!(recovered, packed_rm);
            assert_eq!(fail, mask(!valid));

            let mut shared = [0u8; SHARED_KEY_BYTES];
            decapsulate::<P, N>(&sk, &ct, &mut shared);
            let expected = if valid {
                Sha3_256::digest(&packed_rm)
            } else {
                let mut h = Sha3_256::new();
                h.update(&sk[sk.len() - PRF_KEY_BYTES..]);
                h.update(&ct);
                h.finalize()
            };
            assert_eq!(shared, expected);
        }
    }

    #[test]
    fn decryption_treats_zero_polynomials_as_outside_the_sample_spaces() {
        check_decryption_rejects_zero_polynomials::<TestHps509, 509>(2020);
        check_decryption_rejects_zero_polynomials::<TestHps677, 677>(2021);
        check_decryption_rejects_zero_polynomials::<TestHps821, 821>(2022);
        check_decryption_rejects_zero_polynomials::<TestHrss701, 701>(2023);
    }

    /// Runs the explicit-coins [`encapsulate`] and reports whether it accepted
    /// `coins`. Refused coins must leave both outputs unwritten; accepted
    /// coins must give a ciphertext whose decapsulation reproduces the shared
    /// key.
    fn encapsulation_accepts<P: ParameterSet<N>, const N: usize>(
        sk: &[u8],
        pk: &[u8],
        coins: &[u8],
    ) -> bool {
        let mut shared = [0xa5u8; SHARED_KEY_BYTES];
        let mut ct = vec![0xa5u8; kem_ciphertext_bytes(N, P::LOG_Q)];
        if encapsulate::<P, N>(pk, coins, &mut shared, &mut ct).is_none() {
            assert!(
                shared.iter().chain(&ct).all(|&b| b == 0xa5),
                "refused coins wrote an output"
            );
            return false;
        }
        let mut decapsulated = [0u8; SHARED_KEY_BYTES];
        decapsulate::<P, N>(sk, &ct, &mut decapsulated);
        assert_eq!(decapsulated, shared, "decapsulation disagrees");
        true
    }

    /// `len` coin bytes that are multiples of 3 without all being zero, so
    /// every `Ternary` coefficient they give is 0.
    fn zero_ternary_coins(len: usize) -> Vec<u8> {
        (0..len).map(|i| [3u8, 129, 255, 0][i % 4]).collect()
    }

    /// r = 0 at the explicit-coins boundary: an r block of zero bytes, or of
    /// multiples of 3 that are not all zero, is refused whatever the m block
    /// holds, and one non-zero r coefficient makes the coins acceptable.
    fn check_explicit_coins_sampling_zero_r<P: ParameterSet<N>, const N: usize>(seed: u64) {
        let (sk, pk) = test_key_pair::<P, N>(seed);
        let iid = sample_iid_bytes(N);
        let mut coins = coins_sampling_zero_r(N, P::FAMILY);
        assert!(!encapsulation_accepts::<P, N>(&sk, &pk, &coins));
        coins[..iid].copy_from_slice(&zero_ternary_coins(iid));
        let m_len = coins.len() - iid;
        coins[iid..].copy_from_slice(&TestRng(!seed).bytes(m_len));
        assert!(!encapsulation_accepts::<P, N>(&sk, &pk, &coins));
        coins[iid / 2] = 1;
        assert!(encapsulation_accepts::<P, N>(&sk, &pk, &coins));
    }

    #[test]
    fn explicit_coins_sampling_zero_r_are_refused() {
        check_explicit_coins_sampling_zero_r::<TestHps509, 509>(41);
        check_explicit_coins_sampling_zero_r::<TestHps677, 677>(42);
        check_explicit_coins_sampling_zero_r::<TestHps821, 821>(43);
        check_explicit_coins_sampling_zero_r::<TestHrss701, 701>(44);
    }

    /// m bits that give only zero `Ternary` coefficients at the explicit-coins
    /// boundary: an ntru-hrss m = 0 is refused, and one non-zero m coefficient
    /// makes the coins acceptable. For ntru-hps the same bits are accepted,
    /// because `Fixed_Type` always returns weight q/8 − 2.
    fn check_explicit_coins_sampling_zero_m<P: ParameterSet<N>, const N: usize>(seed: u64) {
        let (sk, pk) = test_key_pair::<P, N>(seed);
        let iid = sample_iid_bytes(N);
        let hps = P::FAMILY == Family::Hps;
        let mut coins = coins_sampling_zero_m(N, P::FAMILY);
        assert_eq!(encapsulation_accepts::<P, N>(&sk, &pk, &coins), hps);
        let m_len = coins.len() - iid;
        coins[iid..].copy_from_slice(&zero_ternary_coins(m_len));
        assert_eq!(encapsulation_accepts::<P, N>(&sk, &pk, &coins), hps);
        let last = coins.len() - 1;
        coins[last] = 5;
        assert!(encapsulation_accepts::<P, N>(&sk, &pk, &coins));
    }

    #[test]
    fn explicit_coins_sampling_zero_hrss_m_are_refused() {
        check_explicit_coins_sampling_zero_m::<TestHrss701, 701>(45);
        check_explicit_coins_sampling_zero_m::<TestHps509, 509>(46);
        check_explicit_coins_sampling_zero_m::<TestHps677, 677>(47);
        check_explicit_coins_sampling_zero_m::<TestHps821, 821>(48);
    }
}
