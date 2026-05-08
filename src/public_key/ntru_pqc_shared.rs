//! Constant-time helpers shared by the NIST PQC NTRU modules
//! ([`crate::public_key::ntru_hps509`], `_hps677`, `_hps821`, `_hrss701`).
//!
//! Everything in this file is data-independent in its control flow: no
//! branches on input, no array indexing by secrets, no early-exit on a
//! sentinel value. The four NTRU sets each used to carry their own copies
//! of these helpers — this module holds the single source of truth.
//!
//! Note that the polynomial multiplication used by all four NTRU sets
//! ([`crate::public_key::ntru_poly_mul`]) is *not* constant-time: its
//! schoolbook base case has a data-dependent early-continue on zero
//! coefficients. The NIST modules are exposed under [`crate::vt`] for that
//! reason.

/// Branch-free conditional move. When `b == 1`, `r` is set to `x`; when
/// `b == 0`, `r` is unchanged. The caller is responsible for keeping `b`
/// in `{0, 1}`.
///
/// Mask trick: $-(b)$ as a `u8` is `0xff` when $b = 1$ and `0x00` when
/// $b = 0$. XOR-blend gives the conditional copy without branching.
pub(crate) fn cmov(r: &mut [u8], x: &[u8], b: u8) {
    debug_assert_eq!(r.len(), x.len());
    debug_assert!(b == 0 || b == 1);
    let mask = (!b).wrapping_add(1);
    for (ri, &xi) in r.iter_mut().zip(x.iter()) {
        *ri ^= mask & (xi ^ *ri);
    }
}

/// Branchless `(a, b) := (min(a, b), max(a, b))` over signed `i32`.
/// Used as the comparator inside [`crypto_sort_int32`].
#[inline(always)]
fn int32_minmax(a: &mut i32, b: &mut i32) {
    let ab = (*b) ^ (*a);
    let mut c = ((*b) as i64).wrapping_sub((*a) as i64) as i32;
    c ^= ab & (c ^ (*b));
    c >>= 31;
    c &= ab;
    *a ^= c;
    *b ^= c;
}

/// Sort `array` ascending using Batcher's merge-exchange network.
///
/// Every comparator is data-independent (only the two slot indices vary),
/// so the resulting sort is constant-time conditional on `array.len()`.
/// Used by the NIST PQC `T_fixed` sampler to permute by 30-bit random
/// tags without revealing the tag values through timing.
///
/// Reference: Batcher, "Sorting networks and their applications" (AFIPS
/// 1968).
pub(crate) fn crypto_sort_int32(array: &mut [i32]) {
    let n = array.len();
    if n < 2 {
        return;
    }
    let mut top: usize = 1;
    while top < n - top {
        top += top;
    }

    let mut p = top;
    while p >= 1 {
        let mut i = 0usize;
        while i + 2 * p <= n {
            for j in i..i + p {
                let (lo, hi) = array.split_at_mut(j + p);
                int32_minmax(&mut lo[j], &mut hi[0]);
            }
            i += 2 * p;
        }
        for j in i..n.saturating_sub(p) {
            let (lo, hi) = array.split_at_mut(j + p);
            int32_minmax(&mut lo[j], &mut hi[0]);
        }

        let mut i = 0usize;
        let mut j = 0usize;
        let mut q = top;
        while q > p {
            'outer: loop {
                if j != i {
                    loop {
                        if j == n - q {
                            break 'outer;
                        }
                        let mut a = array[j + p];
                        let mut r = q;
                        while r > p {
                            // `a` is a register copy of `array[j+p]`; we
                            // only need a mutable reference to
                            // `array[j+r]` here, no split needed.
                            int32_minmax(&mut a, &mut array[j + r]);
                            r >>= 1;
                        }
                        array[j + p] = a;
                        j += 1;
                        if j == i + p {
                            i += 2 * p;
                            break;
                        }
                    }
                }
                while i + p <= n - q {
                    for k in i..i + p {
                        let mut a = array[k + p];
                        let mut r = q;
                        while r > p {
                            int32_minmax(&mut a, &mut array[k + r]);
                            r >>= 1;
                        }
                        array[k + p] = a;
                    }
                    i += 2 * p;
                }
                let mut k = i;
                while k < n.saturating_sub(q) {
                    let mut a = array[k + p];
                    let mut r = q;
                    while r > p {
                        int32_minmax(&mut a, &mut array[k + r]);
                        r >>= 1;
                    }
                    array[k + p] = a;
                    k += 1;
                }
                break;
            }
            q >>= 1;
        }

        p >>= 1;
    }
}

/// Sign-bit AND on signed `i16`: returns `-1` (all-ones in `i16`) when
/// both `x` and `y` are negative, `0` otherwise. Used inside the
/// constant-time Bernstein–Yang inverter loop.
#[inline(always)]
pub(crate) fn both_negative_mask_i16(x: i16, y: i16) -> i16 {
    (x & y) >> 15
}

/// Reduce $a \in [0, 2^{16})$ modulo 3 without branches.
///
/// Folds the input through successive halvings of the modulus
/// (`mod 255 → mod 15 → mod 3 → mod 3`) and then applies a single
/// branchless correction step. Identical reduction is used by all four
/// NIST PQC NTRU parameter sets.
#[inline]
pub(crate) fn mod3(a: u16) -> u16 {
    let mut r = (a >> 8) + (a & 0xff);
    r = (r >> 4) + (r & 0xf);
    r = (r >> 2) + (r & 0x3);
    r = (r >> 2) + (r & 0x3);
    let t = (r as i16) - 3;
    let c = t >> 15;
    (((c as u16) & r) | ((!c as u16) & (t as u16))) & 0xffff
}

// ---- shared NIST PQC KAT parsing (test only) -------------------------------

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

/// Decode an even-length hex string into bytes. Permissive about embedded
/// whitespace so the same routine handles both `.rsp` lines and the legacy
/// per-set `*.hex` fixtures.
#[cfg(test)]
pub(crate) fn hex_to_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0, "hex length must be even");
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Parse the `count = N` entry out of a NIST PQC `.rsp` KAT file. Returns
/// `None` if the count is absent (e.g. asking for entry 100 from a 100-entry
/// file).
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
            for line in lines.by_ref().take(5) {
                let (key, value) = line.split_once(" = ")?;
                let bytes = hex_to_bytes(value.trim());
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

/// Counts that span the full 0..100 range of the NIST round-3 KAT files.
/// Picked to catch first-entry / state-rollover / final-entry bugs without
/// running a full 30+-second 100-entry sweep on every `cargo test`.
#[cfg(test)]
pub(crate) const KAT_SAMPLED_COUNTS: &[usize] = &[0, 1, 7, 23, 42, 67, 83, 99];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmov_copies_when_b_is_one_else_no_change() {
        let mut r = [1u8, 2, 3, 4];
        let x = [9u8, 8, 7, 6];
        cmov(&mut r, &x, 0);
        assert_eq!(r, [1, 2, 3, 4]);
        cmov(&mut r, &x, 1);
        assert_eq!(r, [9, 8, 7, 6]);
    }

    #[test]
    fn crypto_sort_int32_matches_std_sort() {
        let inputs: &[&[i32]] = &[
            &[],
            &[0],
            &[3, 1, 2],
            &[i32::MAX, i32::MIN, 0, -1, 1],
            &[7, 7, 7, 7, 7],
            &[5, -3, 8, 0, -7, 2, 6, -1, 9, 4, -2, 1, -5, 3, -6, 7, -8, -4],
        ];
        for &case in inputs {
            let mut a = case.to_vec();
            let mut b = case.to_vec();
            crypto_sort_int32(&mut a);
            b.sort();
            assert_eq!(a, b, "sort mismatch on {case:?}");
        }
    }

    #[test]
    fn mod3_matches_naive_reduction() {
        for a in 0u16..=u16::MAX {
            assert_eq!(mod3(a), a % 3);
        }
    }
}
