//! Shared polynomial multiplication for the NTRU KEM modules in
//! `Z[x] / (x^N - 1)` over `u16` wrapping arithmetic.
//!
//! The construction is the classical Karatsuba split (Karatsuba and Ofman,
//! "Multiplication of multidigit numbers on automata", Soviet Physics
//! Doklady 7 (1963), 595–596): split each operand at midpoint, do three
//! half-size products instead of four, recombine.
//!
//! Below a small base-case threshold the routine falls back to schoolbook;
//! the recursive overhead otherwise outweighs the asymptotic
//! `O(N^{log_2 3}) ≈ O(N^{1.585})` gain for the operand sizes used here
//! (N ≤ 821). Empirical crossover on Apple silicon and recent x86 lands in
//! the 32–64 coefficient range.
//!
//! All arithmetic is `u16` wrapping (mod 2^16). Karatsuba's algebraic
//! identity holds in any commutative ring, including Z/2^16, so wrapping
//! intermediates produce the same result as wider arithmetic followed by
//! reduction modulo a power-of-two `q ≤ 2^13`. The cyclic reduction folds
//! the linear-convolution result modulo `x^N − 1` by adding the high half
//! back into the low half.
//!
//! The shared cyclic-multiply test cross-checks every output coefficient
//! against the textbook double-loop reference at the production `N` values.

const KARA_THRESHOLD: usize = 48;

/// Schoolbook polynomial multiply: `c = a * b` with `|c| = |a| + |b| - 1`.
///
/// `c` is overwritten. Coefficient arithmetic is `u16` wrapping.
fn poly_mul_schoolbook(c: &mut [u16], a: &[u16], b: &[u16]) {
    debug_assert_eq!(c.len(), a.len() + b.len() - 1);
    for slot in c.iter_mut() {
        *slot = 0;
    }
    for (i, &ai) in a.iter().enumerate() {
        if ai == 0 {
            continue;
        }
        for (j, &bj) in b.iter().enumerate() {
            c[i + j] = c[i + j].wrapping_add(ai.wrapping_mul(bj));
        }
    }
}

/// Karatsuba multiply: `c = a * b` with `|c| = 2 * |a| - 1` and `|a| = |b|`.
///
/// Splits `a = a_lo + x^m · a_hi` (and similarly for `b`), computes three
/// half-size products `z0 = a_lo·b_lo`, `z2 = a_hi·b_hi`, and
/// `z1 = (a_lo + a_hi)·(b_lo + b_hi) − z0 − z2`, then assembles
/// `c = z0 + z1·x^m + z2·x^{2m}`. Below the threshold the routine drops to
/// schoolbook so recursion overhead doesn't outweigh the asymptotic win.
fn poly_mul_kara(c: &mut [u16], a: &[u16], b: &[u16]) {
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

    // a_sum = a_lo + a_hi (high padded with zeros, length m)
    let mut a_sum = vec![0u16; m];
    let mut b_sum = vec![0u16; m];
    a_sum.copy_from_slice(a_lo);
    b_sum.copy_from_slice(b_lo);
    for i in 0..h {
        a_sum[i] = a_sum[i].wrapping_add(a_hi[i]);
        b_sum[i] = b_sum[i].wrapping_add(b_hi[i]);
    }

    let mut z0 = vec![0u16; 2 * m - 1];
    let mut z2 = vec![0u16; 2 * h - 1];
    let mut z1 = vec![0u16; 2 * m - 1];

    poly_mul_kara(&mut z0, a_lo, b_lo);
    poly_mul_kara(&mut z2, a_hi, b_hi);
    poly_mul_kara(&mut z1, &a_sum, &b_sum);

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
pub(crate) fn poly_mul_cyclic(r: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    debug_assert_eq!(r.len(), n);
    debug_assert!(n >= 2);

    let mut c = vec![0u16; 2 * n - 1];
    poly_mul_kara(&mut c, a, b);

    // Reduce mod (x^N − 1): c'[i] = c[i] + c[i + N] for i in 0..N-1,
    // and c'[N-1] = c[N-1] (no fold partner since c has length 2N-1).
    for i in 0..n - 1 {
        r[i] = c[i].wrapping_add(c[i + n]);
    }
    r[n - 1] = c[n - 1];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference cyclic multiply, identical to the round-3 C reference.
    fn poly_mul_cyclic_ref(r: &mut [u16], a: &[u16], b: &[u16]) {
        let n = a.len();
        for slot in r.iter_mut() {
            *slot = 0;
        }
        for k in 0..n {
            let mut acc: u16 = 0;
            for i in 1..n - k {
                acc = acc.wrapping_add(a[k + i].wrapping_mul(b[n - i]));
            }
            for i in 0..=k {
                acc = acc.wrapping_add(a[k - i].wrapping_mul(b[i]));
            }
            r[k] = acc;
        }
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
        let mut want = vec![0u16; n];
        poly_mul_cyclic(&mut got, &a, &b);
        poly_mul_cyclic_ref(&mut want, &a, &b);
        assert_eq!(got, want, "mismatch at n = {n}");
    }

    #[test]
    fn matches_reference_at_threshold_and_above() {
        // Exercise both base case and several recursion levels.
        for n in [2, 7, 32, 47, 48, 49, 64, 100, 509, 677, 701, 821] {
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
}
