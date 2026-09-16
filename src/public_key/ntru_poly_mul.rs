//! Shared polynomial multiplication for the NTRU KEM modules in
//! $\mathbb{Z}[x] / (x^N - 1)$ over `u16` wrapping arithmetic.
//!
//! The construction is the classical Karatsuba split (Karatsuba and Ofman,
//! "Multiplication of multidigit numbers on automata", Soviet Physics
//! Doklady 7 (1963), 595–596): split each operand at midpoint, do three
//! half-size products instead of four, recombine.
//!
//! Below a small base-case threshold the routine falls back to schoolbook;
//! the recursive overhead otherwise outweighs the asymptotic
//! $O(N^{\log_2 3}) \approx O(N^{1.585})$ gain. Operand sizes used here run
//! up to $N = 1499$ (the largest IEEE 1363.1 EES set). Empirical crossover on
//! Apple silicon and recent x86 lands in the 32–64 coefficient range.
//!
//! All arithmetic is `u16` wrapping (mod 2^16). Karatsuba's algebraic
//! identity holds in any commutative ring, including Z/2^16, so wrapping
//! intermediates produce the same result as wider arithmetic followed by
//! reduction modulo a power-of-two `q ≤ 2^13`. The cyclic reduction folds
//! the linear-convolution result modulo `x^N − 1` by adding the high half
//! back into the low half.
//!
//! # Wiping
//!
//! At least one operand is a secret in every call the KEMs make (a private
//! polynomial, a plaintext, or a blinding value), and the multiplier does not
//! distinguish public operands from secret ones. All of its heap memory — the
//! 2N − 1 linear-convolution buffer and the half sums and partial products of
//! every Karatsuba level — lives in one work buffer that
//! [`poly_mul_cyclic`] allocates, carves into slices, and scrubs with
//! [`crate::ct::zeroize_slice`] before it is freed. The recursion allocates
//! nothing of its own. The output slice `r` and the operands belong to the
//! caller, which wipes them under its own contract.
//!
//! # Side channels
//!
//! The schoolbook base case has no data-dependent branches — every `(i, j)`
//! pair issues exactly one `wrapping_mul` and one `wrapping_add`, independent
//! of operand values. Karatsuba's recursion structure (always the same three
//! sub-multiplies, with data-independent partitioning) lifts that property to
//! the recursive caller. So this multiplier is data-independent in its
//! control flow given fixed input lengths. Caveat: `u16::wrapping_mul` is
//! only constant-time at the hardware level on architectures whose integer
//! multiplier is itself constant-time, which is the case on every CPU this
//! crate targets (modern AArch64 / x86-64 / RISC-V `MUL`).
//!
//! The tests compare every output coefficient with the definition of the
//! cyclic convolution, r_k = Σ_i a_i·b_((k − i) mod N), evaluated directly.

use crate::ct::zeroize_slice;

// Empirically validated on Apple Silicon (2026-06): 32 is measurably slower
// (deeper recursion overhead); 48, 64, and 96 are indistinguishable within
// benchmark noise for the round-3 N values, so the schoolbook crossover
// stays at 48.
const KARA_THRESHOLD: usize = 48;

/// Schoolbook polynomial multiply: `c = a * b` with `|c| = |a| + |b| - 1`.
///
/// `c` is overwritten. Coefficient arithmetic is `u16` wrapping. The
/// inner loop is data-independent: every `(i, j)` pair issues exactly
/// one `wrapping_mul` and one `wrapping_add` regardless of operand
/// values. There is no early-continue on zero coefficients — that
/// would leak the zero pattern of the secret operand through the
/// instruction-count side channel, and modern CPUs make `wrapping_mul`
/// on `u16` fast enough that the early-skip is not a worthwhile
/// trade. The Karatsuba caller below inherits this property because
/// every recursion level reduces to schoolbook at the base.
fn poly_mul_schoolbook(c: &mut [u16], a: &[u16], b: &[u16]) {
    debug_assert_eq!(c.len(), a.len() + b.len() - 1);
    for slot in c.iter_mut() {
        *slot = 0;
    }
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            c[i + j] = c[i + j].wrapping_add(ai.wrapping_mul(bj));
        }
    }
}

/// Words of scratch [`poly_mul_kara`] needs, beyond its output, for operands
/// of length `n`.
///
/// One level with low half m = ⌈n/2⌉ and high half h = n − m holds the two
/// half sums (m each) and the three partial products (2m − 1, 2m − 1 and
/// 2h − 1). Its three sub-multiplications run one after another and share
/// the remainder, so the recursion adds the requirement of the largest of
/// them, m ≥ h. One level costs 4m + 2n − 3 < 4n words, and the levels
/// halve, so the total stays below 8n (the tests check n ≤ 1600).
fn kara_scratch_len(n: usize) -> usize {
    if n <= KARA_THRESHOLD {
        return 0;
    }
    let m = n.div_ceil(2);
    let h = n - m;
    2 * m + (2 * m - 1) + (2 * m - 1) + (2 * h - 1) + kara_scratch_len(m)
}

/// Karatsuba multiply: `c = a * b` with `|c| = 2 * |a| - 1` and `|a| = |b|`.
///
/// Splits `a = a_lo + x^m · a_hi` (and similarly for `b`), computes three
/// half-size products `z0 = a_lo·b_lo`, `z2 = a_hi·b_hi`, and
/// `z1 = (a_lo + a_hi)·(b_lo + b_hi) − z0 − z2`, then assembles
/// `c = z0 + z1·x^m + z2·x^{2m}`. Below the threshold the routine drops to
/// schoolbook so recursion overhead doesn't outweigh the asymptotic win.
///
/// `scratch` holds at least [`kara_scratch_len`]`(a.len())` words; the level
/// takes its half sums and partial products from its front and hands the rest
/// to the sub-multiplications. Every word it uses is written before it is
/// read, so the scratch's prior contents do not matter, and the caller that
/// owns the scratch wipes it.
fn poly_mul_kara(c: &mut [u16], a: &[u16], b: &[u16], scratch: &mut [u16]) {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    debug_assert_eq!(c.len(), 2 * n - 1);

    if n <= KARA_THRESHOLD {
        poly_mul_schoolbook(c, a, b);
        return;
    }

    let m = n.div_ceil(2); // size of low half
    let (a_lo, a_hi) = a.split_at(m);
    let (b_lo, b_hi) = b.split_at(m);
    let h = a_hi.len(); // size of high half: h <= m and h = n - m

    let (a_sum, rest) = scratch.split_at_mut(m);
    let (b_sum, rest) = rest.split_at_mut(m);
    let (z0, rest) = rest.split_at_mut(2 * m - 1);
    let (z1, rest) = rest.split_at_mut(2 * m - 1);
    let (z2, rest) = rest.split_at_mut(2 * h - 1);

    // a_sum = a_lo + a_hi (high padded with zeros, length m)
    a_sum.copy_from_slice(a_lo);
    b_sum.copy_from_slice(b_lo);
    for i in 0..h {
        a_sum[i] = a_sum[i].wrapping_add(a_hi[i]);
        b_sum[i] = b_sum[i].wrapping_add(b_hi[i]);
    }

    poly_mul_kara(z0, a_lo, b_lo, rest);
    poly_mul_kara(z2, a_hi, b_hi, rest);
    poly_mul_kara(z1, a_sum, b_sum, rest);

    // z1 = z1 - z0 - z2 over the overlapping prefix lengths.
    for i in 0..z0.len() {
        z1[i] = z1[i].wrapping_sub(z0[i]);
    }
    for i in 0..z2.len() {
        z1[i] = z1[i].wrapping_sub(z2[i]);
    }

    // c = z0 + z1·x^m + z2·x^{2m}
    for slot in c.iter_mut() {
        *slot = 0;
    }
    for i in 0..z0.len() {
        c[i] = c[i].wrapping_add(z0[i]);
    }
    for i in 0..z1.len() {
        c[i + m] = c[i + m].wrapping_add(z1[i]);
    }
    for i in 0..z2.len() {
        c[i + 2 * m] = c[i + 2 * m].wrapping_add(z2[i]);
    }
}

/// Cyclic convolution `r = a · b` in `Z[x] / (x^N − 1)` over `u16` wrapping.
///
/// All slices must be the same length `N >= 2`. The output overwrites `r`.
/// The one heap buffer this call makes, holding the linear convolution and
/// every level's Karatsuba scratch, is wiped before it is freed (see the
/// module documentation).
pub(crate) fn poly_mul_cyclic(r: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    debug_assert_eq!(r.len(), n);
    debug_assert!(n >= 2);

    let linear_len = 2 * n - 1;
    let mut work = vec![0u16; linear_len + kara_scratch_len(n)];
    let (c, scratch) = work.split_at_mut(linear_len);
    poly_mul_kara(c, a, b, scratch);

    // Reduce mod (x^N − 1): c'[i] = c[i] + c[i + N] for i in 0..N-1,
    // and c'[N-1] = c[N-1] (no fold partner since c has length 2N-1).
    for i in 0..n - 1 {
        r[i] = c[i].wrapping_add(c[i + n]);
    }
    r[n - 1] = c[n - 1];
    zeroize_slice(&mut work);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cyclic convolution straight from its definition: coefficient k of
    /// a·b modulo x^N − 1 collects every product a_i·b_j with
    /// i + j ≡ k (mod N), i.e. j = (k − i) mod N.
    fn convolution_by_definition(a: &[u16], b: &[u16]) -> Vec<u16> {
        let n = a.len();
        (0..n)
            .map(|k| {
                (0..n).fold(0u16, |sum, i| {
                    sum.wrapping_add(a[i].wrapping_mul(b[(k + n - i) % n]))
                })
            })
            .collect()
    }

    fn check(n: usize, seed: u32) {
        // Linear-feedback PRNG so the test is deterministic without pulling
        // in the crate's CSPRNG.
        let mut s: u32 = seed.wrapping_add(0x9E3779B9);
        let mut next = || {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            (s >> 16) as u16
        };
        let a: Vec<u16> = (0..n).map(|_| next()).collect();
        let b: Vec<u16> = (0..n).map(|_| next()).collect();
        let mut got = vec![0u16; n];
        poly_mul_cyclic(&mut got, &a, &b);
        assert_eq!(
            got,
            convolution_by_definition(&a, &b),
            "mismatch at n = {n}"
        );
    }

    #[test]
    fn matches_reference_at_threshold_and_above() {
        // Exercise both base case and several recursion levels, including
        // every round-3 and IEEE 1363.1 operand length.
        for n in [
            2, 7, 32, 47, 48, 49, 64, 96, 97, 100, 401, 443, 449, 509, 541, 677, 701, 821, 1087,
            1171, 1499,
        ] {
            check(n, n as u32);
        }
    }

    #[test]
    fn handles_zero_input() {
        let n = 256;
        let a = vec![0u16; n];
        let b: Vec<u16> = (0..n as u16).collect();
        let mut got = vec![0u16; n];
        poly_mul_cyclic(&mut got, &a, &b);
        assert!(got.iter().all(|&c| c == 0));
    }

    /// Exact accounting of the scratch: the words one level carves off, plus
    /// what the largest sub-multiplication needs, stay below 8n, and the
    /// requirement is monotone in n (the z2 sub-multiplication of size h ≤ m
    /// relies on that when it is handed the scratch sized for m).
    #[test]
    fn scratch_requirement_is_bounded_and_monotone() {
        let mut previous = 0;
        for n in 1..=1600 {
            let need = kara_scratch_len(n);
            assert!(need < 8 * n, "n = {n}: {need}");
            assert!(need >= previous, "n = {n}");
            previous = need;
            if n <= KARA_THRESHOLD {
                assert_eq!(need, 0);
            }
        }
    }

    /// A multiplication whose scratch is smaller than the level needs would
    /// panic in `split_at_mut`; running every level through a buffer of
    /// exactly `kara_scratch_len(n)` words shows the accounting is sufficient.
    #[test]
    fn scratch_requirement_is_sufficient() {
        for n in [49, 96, 97, 193, 509, 701, 821, 1499] {
            let a: Vec<u16> = (0..n as u16).map(|i| i.wrapping_mul(7)).collect();
            let mut c = vec![0u16; 2 * n - 1];
            let mut scratch = vec![0u16; kara_scratch_len(n)];
            poly_mul_kara(&mut c, &a, &a, &mut scratch);
            let mut expected = vec![0u16; 2 * n - 1];
            poly_mul_schoolbook(&mut expected, &a, &a);
            assert_eq!(c, expected, "n = {n}");
        }
    }
}
