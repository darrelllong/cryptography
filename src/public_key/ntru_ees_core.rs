//! Shared core for the IEEE Std 1363.1-2008 NTRUEncrypt parameter sets in
//! this crate. Each per-set module
//! ([`crate::public_key::ntru_ees401ep1`], etc.) is a thin wrapper that
//! plugs an [`EesParams`] constant and an `N` const generic into the
//! routines defined here.
//!
//! The construction is exactly the one described in the per-set module
//! docstrings; this file just hoists the algorithm out of nine duplicates.
//! Two structural variants are supported:
//!
//! - **Dense trapdoor** (`prod_flag = 0` in the IEEE tables): `t` is a
//!   single trinary polynomial with `df` ones and `df` minus-ones; the
//!   private key encodes `t` as 2-bit signed trinary.
//! - **Product-form trapdoor** (`prod_flag = 1`): `t = f_1 \cdot f_2 + f_3`
//!   with `(df_1, df_2, df_3)` ones-counts; the private key encodes the
//!   three sparse trinary polynomials as 9-bit-per-coefficient index lists.
//!
//! Side channels: variable-time arithmetic. This module is only used from
//! types under [`crate::vt`].
//!
//! Storage strategy: hot polynomial buffers (`Poly<N>::coeffs`) are
//! inline `[u16; N]` arrays via the `const N: usize` parameter, so the
//! Karatsuba multiplier inner loop avoids heap traffic on those.
//! Several other inputs and intermediates remain heap-resident:
//! wire-format byte buffers (`pk`, `sk`, `ct`); the IGF state's `BitStr`
//! `Vec<u8>` and the seed `Vec<u8>` it copies; `mgf`'s working buffer
//! of accepted hash bytes; the trial-and-error trinary samplers in
//! `sample_trinary` / `sample_trapdoor`; and the F_2 extended-Euclidean
//! inverter that backs `poly_inverse_mod_q_cyclic`. None of these is
//! removable without either `generic_const_exprs` (the wire buffers'
//! lengths are derived from `N` and `logq`) or a redesign of the
//! inverter / sampler. The IEEE 1363.1 EES keygen and encrypt paths
//! therefore allocate; this is intentional but worth naming so a
//! profiler reading the heap pattern is not surprised.

use crate::hash::sha1::Sha1;
use crate::hash::sha2::Sha256;
use crate::Csprng;

// ---- parameter definitions --------------------------------------------------

/// Hash function selected by the IEEE 1363.1 OID for a given parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashKind {
    Sha1,
    Sha256,
}

impl HashKind {
    /// Output length in bytes (`hlen` in IEEE 1363.1).
    pub const fn output_len(self) -> usize {
        match self {
            HashKind::Sha1 => 20,
            HashKind::Sha256 => 32,
        }
    }

    fn digest_into(self, input: &[u8], out: &mut [u8]) {
        match self {
            HashKind::Sha1 => out.copy_from_slice(Sha1::digest(input).as_slice()),
            HashKind::Sha256 => out.copy_from_slice(Sha256::digest(input).as_slice()),
        }
    }

    /// Hash the concatenation of `prefix || suffix` into `out` incrementally,
    /// without materialising the joined buffer. Used by IGF / MGF callers
    /// where the prefix is the IGF seed `z` and the suffix is a small
    /// counter encoding.
    fn digest_two_into(self, prefix: &[u8], suffix: &[u8], out: &mut [u8]) {
        match self {
            HashKind::Sha1 => {
                let mut h = Sha1::new();
                h.update(prefix);
                h.update(suffix);
                out.copy_from_slice(h.finalize().as_slice());
            }
            HashKind::Sha256 => {
                let mut h = Sha256::new();
                h.update(prefix);
                h.update(suffix);
                out.copy_from_slice(h.finalize().as_slice());
            }
        }
    }
}

/// Trapdoor structure for the private key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapdoorKind {
    /// `t` is a single trinary polynomial with `df` ones and `df` minus-ones.
    Dense { df: usize },
    /// `t = f_1 \cdot f_2 + f_3`. `df1`, `df2`, `df3` are the per-component
    /// ones-counts.
    ProductForm { df1: usize, df2: usize, df3: usize },
}

/// All scalar parameters for an EES NTRUEncrypt set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EesParams {
    pub n: usize,
    /// `q = 2^logq`. Every IEEE 1363.1 set in this crate uses `logq = 11`.
    pub logq: usize,
    pub trapdoor: TrapdoorKind,
    pub dg: usize,
    pub dm0: usize,
    /// Number of random *bits* prepended to the message.
    pub db_bits: usize,
    /// Bits per IGF rejection sample.
    pub c_bits: usize,
    pub min_calls_r: usize,
    pub min_calls_mask: usize,
    pub pklen_bits: usize,
    pub oid: [u8; 3],
    pub hash: HashKind,
}

impl EesParams {
    pub const fn db_bytes(&self) -> usize {
        self.db_bits / 8
    }
    pub const fn pklen_bytes(&self) -> usize {
        self.pklen_bits.div_ceil(8)
    }
    pub const fn q(&self) -> u32 {
        1u32 << self.logq
    }
    pub const fn q_mask(&self) -> u16 {
        ((1u32 << self.logq) - 1) as u16
    }
    /// Wire length of a public key in bytes: `ceil(N * logq / 8)`.
    pub const fn pk_wire_bytes(&self) -> usize {
        (self.n * self.logq).div_ceil(8)
    }
    /// Trapdoor section of the private key (does not include the embedded
    /// public key bytes).
    pub const fn trapdoor_wire_bytes(&self) -> usize {
        match self.trapdoor {
            TrapdoorKind::Dense { .. } => (self.n * 2).div_ceil(8),
            TrapdoorKind::ProductForm { df1, df2, df3 } => {
                let indices = 2 * (df1 + df2 + df3);
                let bits = indices * Self::index_bits(self.n);
                bits.div_ceil(8)
            }
        }
    }
    /// Number of bits needed per index in the product-form sparse encoding.
    /// Returns `ceil(log2(N))` rounded up to the next bit.
    const fn index_bits(n: usize) -> usize {
        // log2(n) ceiling, computed with const-friendly arithmetic
        let mut bits = 0usize;
        let mut v = n.saturating_sub(1);
        while v > 0 {
            bits += 1;
            v >>= 1;
        }
        bits
    }
    pub const fn ciphertext_wire_bytes(&self) -> usize {
        self.pk_wire_bytes()
    }
    pub const fn max_message_bytes(&self) -> usize {
        self.n / 2 * 3 / 8 - 1 - self.db_bytes()
    }
}

// ---- polynomial type --------------------------------------------------------

/// Polynomial in `Z_q[x] / (x^N - 1)` with `u16` coefficients.
#[derive(Clone, Copy)]
pub struct Poly<const N: usize> {
    pub coeffs: [u16; N],
}

impl<const N: usize> Poly<N> {
    pub fn zero() -> Self {
        Self { coeffs: [0u16; N] }
    }
}

#[inline(always)]
fn modq(x: u16, q_mask: u16) -> u16 {
    x & q_mask
}

pub fn poly_mul<const N: usize>(r: &mut Poly<N>, a: &Poly<N>, b: &Poly<N>) {
    crate::public_key::ntru_poly_mul::poly_mul_cyclic(&mut r.coeffs, &a.coeffs, &b.coeffs);
}

pub fn poly_add<const N: usize>(a: &mut Poly<N>, b: &Poly<N>) {
    for i in 0..N {
        a.coeffs[i] = a.coeffs[i].wrapping_add(b.coeffs[i]);
    }
}

pub fn poly_sub<const N: usize>(a: &mut Poly<N>, b: &Poly<N>) {
    for i in 0..N {
        a.coeffs[i] = a.coeffs[i].wrapping_sub(b.coeffs[i]);
    }
}

/// Reduce coefficients into `{0, 1, 2}` (canonical trinary representation
/// after centred-residue mod `q`).
pub fn poly_mod3<const N: usize>(a: &mut Poly<N>, params: &EesParams) {
    let q = params.q();
    let q_mask = params.q_mask();
    for c in a.coeffs.iter_mut() {
        let m = modq(*c, q_mask);
        let centred = if (m as u32) > q / 2 {
            m as i32 - q as i32
        } else {
            m as i32
        };
        let r = centred.rem_euclid(3);
        *c = r as u16;
    }
}

pub fn poly_scalar_mul<const N: usize>(a: &mut Poly<N>, k: u16, q_mask: u16) {
    for c in a.coeffs.iter_mut() {
        *c = c.wrapping_mul(k) & q_mask;
    }
}

pub fn poly_mod_q<const N: usize>(a: &mut Poly<N>, q_mask: u16) {
    for c in a.coeffs.iter_mut() {
        *c = modq(*c, q_mask);
    }
}

// ---- trinary and product-form polynomial representations -------------------

#[derive(Clone, Eq, PartialEq)]
pub struct TernaryPoly {
    pub ones: Vec<u16>,
    pub neg_ones: Vec<u16>,
}

impl Drop for TernaryPoly {
    fn drop(&mut self) {
        // The non-zero index lists ARE the secret trapdoor `f`; wipe them so a
        // dropped private key (`Trapdoor` -> `ProductPoly`/`TernaryPoly`) does
        // not leave key material in freed memory. Cascades through every owner.
        crate::ct::zeroize_slice(self.ones.as_mut_slice());
        crate::ct::zeroize_slice(self.neg_ones.as_mut_slice());
    }
}

impl TernaryPoly {
    pub fn to_dense<const N: usize>(&self, q_mask: u16) -> Poly<N> {
        let mut p = Poly::<N>::zero();
        for &i in &self.ones {
            p.coeffs[i as usize] = 1;
        }
        for &i in &self.neg_ones {
            p.coeffs[i as usize] = q_mask;
        }
        p
    }

    pub fn mul_dense<const N: usize>(&self, b: &Poly<N>, out: &mut Poly<N>) {
        for c in out.coeffs.iter_mut() {
            *c = 0;
        }
        for &idx in &self.ones {
            let s = idx as usize;
            for j in 0..N {
                let k = if s + j >= N { s + j - N } else { s + j };
                out.coeffs[k] = out.coeffs[k].wrapping_add(b.coeffs[j]);
            }
        }
        for &idx in &self.neg_ones {
            let s = idx as usize;
            for j in 0..N {
                let k = if s + j >= N { s + j - N } else { s + j };
                out.coeffs[k] = out.coeffs[k].wrapping_sub(b.coeffs[j]);
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProductPoly {
    pub f1: TernaryPoly,
    pub f2: TernaryPoly,
    pub f3: TernaryPoly,
}

impl ProductPoly {
    pub fn mul_dense<const N: usize>(&self, a: &Poly<N>, out: &mut Poly<N>) {
        let mut t1 = Poly::<N>::zero();
        self.f1.mul_dense::<N>(a, &mut t1);
        self.f2.mul_dense::<N>(&t1, out);
        let mut t3 = Poly::<N>::zero();
        self.f3.mul_dense::<N>(a, &mut t3);
        poly_add::<N>(out, &t3);
    }

    pub fn to_dense<const N: usize>(&self, q_mask: u16) -> Poly<N> {
        let f2_dense = self.f2.to_dense::<N>(q_mask);
        let mut out = Poly::<N>::zero();
        self.f1.mul_dense::<N>(&f2_dense, &mut out);
        let f3_dense = self.f3.to_dense::<N>(q_mask);
        poly_add::<N>(&mut out, &f3_dense);
        out
    }
}

/// Trapdoor used in the private key.
#[derive(Clone, Eq, PartialEq)]
pub enum Trapdoor {
    Dense(TernaryPoly),
    Product(ProductPoly),
}

impl Trapdoor {
    fn mul_dense<const N: usize>(&self, a: &Poly<N>, out: &mut Poly<N>) {
        match self {
            Trapdoor::Dense(t) => t.mul_dense::<N>(a, out),
            Trapdoor::Product(p) => p.mul_dense::<N>(a, out),
        }
    }

    fn to_dense<const N: usize>(&self, q_mask: u16) -> Poly<N> {
        match self {
            Trapdoor::Dense(t) => t.to_dense::<N>(q_mask),
            Trapdoor::Product(p) => p.to_dense::<N>(q_mask),
        }
    }

    /// Pack the trapdoor into the canonical IEEE 1363.1 wire bytes. The
    /// output length must equal [`EesParams::trapdoor_wire_bytes`].
    pub fn to_wire(&self, params: &EesParams, out: &mut [u8]) {
        debug_assert_eq!(out.len(), params.trapdoor_wire_bytes());
        for b in out.iter_mut() {
            *b = 0;
        }
        match self {
            Trapdoor::Dense(t) => {
                // O(df) write at each non-zero index.
                for &i in &t.ones {
                    let bit_pos = 2 * (i as usize);
                    out[bit_pos / 8] |= 1 << (bit_pos % 8);
                }
                for &i in &t.neg_ones {
                    let bit_pos = 2 * (i as usize);
                    out[bit_pos / 8] |= 3 << (bit_pos % 8);
                }
            }
            Trapdoor::Product(p) => {
                let mut bit_offset = 0usize;
                let index_bits = EesParams::index_bits(params.n);
                for poly in &[&p.f1, &p.f2, &p.f3] {
                    pack_indices(&poly.ones, out, &mut bit_offset, index_bits).expect("ones fit");
                    pack_indices(&poly.neg_ones, out, &mut bit_offset, index_bits)
                        .expect("neg_ones fit");
                }
            }
        }
    }

    /// Inverse of [`Trapdoor::to_wire`]. Validates count and index ranges.
    pub fn from_wire(bytes: &[u8], params: &EesParams) -> Option<Self> {
        if bytes.len() != params.trapdoor_wire_bytes() {
            return None;
        }
        match params.trapdoor {
            TrapdoorKind::Dense { df } => {
                let n = params.n;
                let mut bit_pos = 0usize;
                let mut ones = Vec::new();
                let mut neg_ones = Vec::new();
                for i in 0..n {
                    let code = (bytes[bit_pos / 8] >> (bit_pos % 8)) & 0x3;
                    bit_pos += 2;
                    match code {
                        0 => {}
                        1 => ones.push(i as u16),
                        3 => neg_ones.push(i as u16),
                        _ => return None,
                    }
                }
                if ones.len() != df || neg_ones.len() != df {
                    return None;
                }
                if !padding_bits_clear(bytes, n * 2) {
                    return None;
                }
                Some(Trapdoor::Dense(TernaryPoly { ones, neg_ones }))
            }
            TrapdoorKind::ProductForm { df1, df2, df3 } => {
                let mut bit_offset = 0usize;
                let index_bits = EesParams::index_bits(params.n);
                let n = params.n;
                let f1_ones = unpack_indices(bytes, df1, &mut bit_offset, index_bits, n)?;
                let f1_neg = unpack_indices(bytes, df1, &mut bit_offset, index_bits, n)?;
                let f2_ones = unpack_indices(bytes, df2, &mut bit_offset, index_bits, n)?;
                let f2_neg = unpack_indices(bytes, df2, &mut bit_offset, index_bits, n)?;
                let f3_ones = unpack_indices(bytes, df3, &mut bit_offset, index_bits, n)?;
                let f3_neg = unpack_indices(bytes, df3, &mut bit_offset, index_bits, n)?;
                if !padding_bits_clear(bytes, bit_offset) {
                    return None;
                }
                Some(Trapdoor::Product(ProductPoly {
                    f1: TernaryPoly {
                        ones: f1_ones,
                        neg_ones: f1_neg,
                    },
                    f2: TernaryPoly {
                        ones: f2_ones,
                        neg_ones: f2_neg,
                    },
                    f3: TernaryPoly {
                        ones: f3_ones,
                        neg_ones: f3_neg,
                    },
                }))
            }
        }
    }

    /// Sample a trapdoor at IID-uniform via the rejection sampler in
    /// [`sample_trinary`]; the variant is chosen by `params.trapdoor`.
    /// This is the ordinary-keygen entry point.
    fn sample_iid<R: Csprng>(rng: &mut R, params: &EesParams) -> Self {
        match params.trapdoor {
            TrapdoorKind::Dense { df } => Trapdoor::Dense(sample_trinary(rng, params.n, df, df)),
            TrapdoorKind::ProductForm { df1, df2, df3 } => Trapdoor::Product(ProductPoly {
                f1: sample_trinary(rng, params.n, df1, df1),
                f2: sample_trinary(rng, params.n, df2, df2),
                f3: sample_trinary(rng, params.n, df3, df3),
            }),
        }
    }

    /// Sample a blinding trapdoor via the IGF state, used by SVES-3
    /// encryption. The variant is chosen by the IGF's parameter set.
    fn sample_via_igf(state: &mut IgfState<'_>) -> Self {
        match state.params.trapdoor {
            TrapdoorKind::Dense { df } => Trapdoor::Dense(igf_gen_ternary(state, df)),
            TrapdoorKind::ProductForm { df1, df2, df3 } => Trapdoor::Product(ProductPoly {
                f1: igf_gen_ternary(state, df1),
                f2: igf_gen_ternary(state, df2),
                f3: igf_gen_ternary(state, df3),
            }),
        }
    }
}

// ---- inversion mod 2 in F_2[x] / (x^N - 1) ---------------------------------

fn poly_trim(p: &mut Vec<u8>) {
    while p.len() > 1 && *p.last().unwrap() == 0 {
        p.pop();
    }
}

fn poly_deg(p: &[u8]) -> Option<usize> {
    (0..p.len()).rev().find(|&i| p[i] != 0)
}

fn poly_inverse_mod2_cyclic(a_coeffs: &[u8]) -> Option<Vec<u8>> {
    let n = a_coeffs.len();
    let mut r0 = vec![0u8; n + 1];
    r0[0] = 1;
    r0[n] = 1;
    let mut r1: Vec<u8> = a_coeffs.iter().map(|&c| c & 1).collect();
    poly_trim(&mut r1);
    let mut t0 = vec![0u8; 1];
    let mut t1 = vec![1u8; 1];

    while let Some(d1) = poly_deg(&r1) {
        let d0 = match poly_deg(&r0) {
            Some(d) => d,
            None => {
                std::mem::swap(&mut r0, &mut r1);
                std::mem::swap(&mut t0, &mut t1);
                break;
            }
        };
        if d0 < d1 {
            std::mem::swap(&mut r0, &mut r1);
            std::mem::swap(&mut t0, &mut t1);
            continue;
        }
        let shift = d0 - d1;
        for i in 0..=d1 {
            r0[shift + i] ^= r1[i];
        }
        poly_trim(&mut r0);
        let new_t0_len = t0.len().max(t1.len() + shift);
        if t0.len() < new_t0_len {
            t0.resize(new_t0_len, 0);
        }
        for i in 0..t1.len() {
            t0[shift + i] ^= t1[i];
        }
    }

    if !(r0.len() == 1 && r0[0] == 1) {
        return None;
    }
    let mut out = vec![0u8; n];
    for (i, &c) in t0.iter().enumerate() {
        if c & 1 == 1 {
            out[i % n] ^= 1;
        }
    }
    Some(out)
}

fn poly_inverse_mod_q_cyclic<const N: usize>(a: &Poly<N>, params: &EesParams) -> Option<Poly<N>> {
    let q = params.q();
    let q_mask = params.q_mask();
    let a_mod2: Vec<u8> = a.coeffs.iter().map(|&c| (c & 1) as u8).collect();
    let inv2 = poly_inverse_mod2_cyclic(&a_mod2)?;

    let mut b = Poly::<N>::zero();
    for (bc, &ic) in b.coeffs.iter_mut().zip(inv2.iter()) {
        *bc = ic as u16;
    }

    // Newton-style Hensel lift: each pass squares `precision` (2 → 4
    // → 16 → 256 → 65536). Four iterations suffice for every $q \le
    // 2^{16}$, which covers every IEEE 1363.1 EES parameter set in
    // this crate ($q = 2048$). `saturating_mul` caps the final pass at
    // `u32::MAX` so the loop terminates cleanly even if a future
    // parameter set raised `q` past 2^{16}.
    let mut precision: u32 = 2;
    while precision < q {
        let mut ab = Poly::<N>::zero();
        poly_mul::<N>(&mut ab, a, &b);
        poly_mod_q::<N>(&mut ab, q_mask);
        let mut two_minus_ab = Poly::<N>::zero();
        two_minus_ab.coeffs[0] = 2u16.wrapping_sub(ab.coeffs[0]) & q_mask;
        for i in 1..N {
            two_minus_ab.coeffs[i] = 0u16.wrapping_sub(ab.coeffs[i]) & q_mask;
        }
        let mut new_b = Poly::<N>::zero();
        poly_mul::<N>(&mut new_b, &b, &two_minus_ab);
        poly_mod_q::<N>(&mut new_b, q_mask);
        b = new_b;
        precision = precision.saturating_mul(precision);
    }
    Some(b)
}

// ---- bit-string accumulator (IEEE 1363.1 §9 BPGM3 / IGF helpers) -----------
//
// Bits are packed LSB-first within each byte; byte 0 holds the oldest 8 bits
// (the "bottom") and the partial byte at `buf.len() - 1` holds the newest
// (the "top"). The IGF only ever appends at the top, reads the top `c` bits,
// and (when refilling) saves the unconsumed bottom slice into a fresh
// `BitStr` that gets new hash output appended above. There are exactly four
// supported operations; everything else is a hidden invariant. Track the
// total bit count explicitly and derive the byte index / partial-bit count
// from it on the fly so the invariants are obvious.

#[derive(Clone)]
struct BitStr {
    buf: Vec<u8>,
    bit_len: usize,
}

impl BitStr {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            bit_len: 0,
        }
    }

    /// Append 8 bits at the top of the stack.
    fn append_byte(&mut self, b: u8) {
        let off = self.bit_len % 8;
        if off == 0 {
            self.buf.push(b);
        } else {
            *self.buf.last_mut().expect("non-empty by `bit_len > 0`") |= b << off;
            self.buf.push(b >> (8 - off));
        }
        self.bit_len += 8;
    }

    fn append(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.append_byte(b);
        }
    }

    /// Read the top `num_bits` (most recently appended) as a little-endian
    /// `u32`; `num_bits` must be ≤ 32 and ≤ `bit_len`.
    fn leading(&self, num_bits: u8) -> u32 {
        let n = num_bits as usize;
        debug_assert!(n <= 32 && n <= self.bit_len);
        let start = self.bit_len - n;
        let mut v: u32 = 0;
        for i in 0..n {
            let p = start + i;
            v |= u32::from((self.buf[p / 8] >> (p % 8)) & 1) << i;
        }
        v
    }

    /// Drop the top `num_bits`; trims trailing bytes that are wholly above
    /// the new bit length and clears any stale bits in the new top byte so
    /// later appends OR cleanly into it.
    fn truncate(&mut self, num_bits: u8) {
        let n = num_bits as usize;
        debug_assert!(n <= self.bit_len);
        self.bit_len -= n;
        let needed = self.bit_len.div_ceil(8);
        self.buf.truncate(needed);
        let off = self.bit_len % 8;
        if off != 0 {
            let last = self.buf.last_mut().expect("non-empty by needed > 0");
            *last &= (1u8 << off) - 1;
        }
    }

    /// Take the bottom `num_bits` (oldest, the unconsumed remainder) into
    /// a fresh `BitStr`. Used at IGF refill time to preserve the residual
    /// before stacking new hash output above it.
    fn trailing(&self, num_bits: u32) -> Self {
        let n = num_bits as usize;
        debug_assert!(n <= self.bit_len);
        let needed = n.div_ceil(8);
        let mut buf = self.buf[..needed].to_vec();
        let off = n % 8;
        if off != 0 {
            *buf.last_mut().expect("needed > 0") &= (1u8 << off) - 1;
        }
        Self { buf, bit_len: n }
    }
}

struct IgfState<'a> {
    z: Vec<u8>,
    counter: u16,
    buf: BitStr,
    rem_bits: u32,
    params: &'a EesParams,
}

impl<'a> IgfState<'a> {
    fn new(seed: &[u8], params: &'a EesParams) -> Self {
        // The IGF reads `c_bits` per index sample, accumulating into
        // `BitStr::leading(num_bits: u8)` — so `c_bits` must fit in a
        // u8. Every IEEE 1363.1 EES set this crate ships uses
        // `c_bits ∈ {9, 11, 12, 13}`; the guard catches a future
        // parameter set that violates the assumption.
        debug_assert!(
            params.c_bits <= u8::MAX as usize,
            "IGF c_bits must fit in a u8"
        );
        let hlen = params.hash.output_len();
        let mut s = Self {
            z: seed.to_vec(),
            counter: 0,
            buf: BitStr::new(),
            rem_bits: (params.min_calls_r * 8 * hlen) as u32,
            params,
        };
        while (s.counter as usize) < params.min_calls_r {
            s.absorb_one();
        }
        s
    }
    fn absorb_one(&mut self) {
        let hlen = self.params.hash.output_len();
        let mut out = [0u8; 64];
        self.params
            .hash
            .digest_two_into(&self.z, &self.counter.to_le_bytes(), &mut out[..hlen]);
        self.buf.append(&out[..hlen]);
        self.counter = self.counter.wrapping_add(1);
    }
    fn next_index(&mut self) -> u16 {
        let n = self.params.n as u32;
        let c = self.params.c_bits as u8;
        let hlen = self.params.hash.output_len();
        // Largest multiple of n that fits in c bits. `v < rnd_thresh` ⇒ `v %
        // n` is uniformly distributed; otherwise resample.
        let rnd_thresh: u32 = (1u32 << c) - (1u32 << c) % n;
        loop {
            if self.rem_bits < c as u32 {
                let mut tail = self.buf.trailing(self.rem_bits);
                let need = (c as u32) - self.rem_bits;
                let extra_calls = need.div_ceil((hlen as u32) * 8);
                let mut out = [0u8; 64];
                for _ in 0..extra_calls {
                    self.params.hash.digest_two_into(
                        &self.z,
                        &self.counter.to_le_bytes(),
                        &mut out[..hlen],
                    );
                    tail.append(&out[..hlen]);
                    self.counter = self.counter.wrapping_add(1);
                    self.rem_bits += 8 * hlen as u32;
                }
                self.buf = tail;
            }
            let v = self.buf.leading(c);
            self.buf.truncate(c);
            self.rem_bits -= c as u32;
            if v < rnd_thresh {
                return (v % n) as u16;
            }
        }
    }
}

fn igf_gen_ternary(state: &mut IgfState<'_>, num_each: usize) -> TernaryPoly {
    let n = state.params.n;
    let mut occupied = vec![false; n];
    let mut neg_ones = Vec::with_capacity(num_each);
    let mut ones = Vec::with_capacity(num_each);
    while neg_ones.len() < num_each {
        let idx = state.next_index();
        if !occupied[idx as usize] {
            occupied[idx as usize] = true;
            neg_ones.push(idx);
        }
    }
    while ones.len() < num_each {
        let idx = state.next_index();
        if !occupied[idx as usize] {
            occupied[idx as usize] = true;
            ones.push(idx);
        }
    }
    neg_ones.sort_unstable();
    ones.sort_unstable();
    TernaryPoly { ones, neg_ones }
}

fn igf_gen_blinding(state: &mut IgfState<'_>) -> Trapdoor {
    Trapdoor::sample_via_igf(state)
}

// ---- MGF -------------------------------------------------------------------

/// IEEE 1363.1 §9.2.4 Trit-decomposition table: each in-range byte
/// (0..243 = 3^5) maps to a 5-trit base-3 expansion using {0, 1, -1}. Built at
/// compile time so MGF stays branch-free at the hash-output -> trinary stage.
const MGF_TRIT_TABLE: [[i8; 5]; 243] = {
    let mut t = [[0i8; 5]; 243];
    let map = [0i8, 1, -1];
    let mut byte = 0usize;
    while byte < 243 {
        let mut v = byte;
        let mut slot = 0usize;
        while slot < 5 {
            t[byte][slot] = map[v % 3];
            v /= 3;
            slot += 1;
        }
        byte += 1;
    }
    t
};

fn mgf<const N: usize>(seed: &[u8], params: &EesParams) -> Poly<N> {
    let hlen = params.hash.output_len();
    let q_mask = params.q_mask();
    let mut z = [0u8; 64];
    params.hash.digest_into(seed, &mut z[..hlen]);

    let mut buf: Vec<u8> = Vec::with_capacity(params.min_calls_mask * hlen);
    let mut counter: u16 = 0;
    let mut h = [0u8; 64];
    while (counter as usize) < params.min_calls_mask {
        params
            .hash
            .digest_two_into(&z[..hlen], &counter.to_be_bytes(), &mut h[..hlen]);
        for &b in &h[..hlen] {
            if b < 243 {
                buf.push(b);
            }
        }
        counter = counter.wrapping_add(1);
    }

    let mut out = Poly::<N>::zero();
    let mut cur = 0usize;
    // The IEEE 1363.1 IGF + MGF rejection-samples bytes < 243 at a
    // density of 243/256 ≈ 95%, so the expected number of hash
    // calls is at most $\lceil N / (5 \cdot 0.95 \cdot \text{hlen})
    // \rceil$ — about 4 for $N = 1499, \text{hlen} = 32$. The bound
    // below is a defensive ceiling against a pathological hash
    // distribution; for the round-3-style SHA-1 / SHA-256 hashes
    // shipped in this crate it is never reached.
    let counter_ceiling = (params.min_calls_mask as u16).saturating_add(1024);
    'outer: loop {
        for &b in &buf {
            for &t in &MGF_TRIT_TABLE[b as usize] {
                out.coeffs[cur] = match t {
                    -1 => q_mask,
                    0 => 0,
                    1 => 1,
                    _ => unreachable!(),
                };
                cur += 1;
                if cur >= N {
                    break 'outer;
                }
            }
        }
        assert!(
            counter < counter_ceiling,
            "MGF rejection sampler exceeded counter ceiling — hash output is pathologically biased"
        );
        params
            .hash
            .digest_two_into(&z[..hlen], &counter.to_be_bytes(), &mut h[..hlen]);
        buf.clear();
        for &b in &h[..hlen] {
            if b < 243 {
                buf.push(b);
            }
        }
        counter = counter.wrapping_add(1);
    }
    out
}

// ---- SVES encoding (IEEE 1363.1 §9.2.2 / §9.2.3) ---------------------------

const SVES_C1: [i8; 8] = [0, 0, 0, 1, 1, 1, -1, -1];
const SVES_C2: [i8; 8] = [0, 1, -1, 0, 1, -1, 0, 1];

fn trit_to_u16(t: i8, q_mask: u16) -> u16 {
    match t {
        -1 => q_mask,
        0 => 0,
        1 => 1,
        _ => unreachable!(),
    }
}

fn sves_from_bytes<const N: usize>(m: &[u8], q_mask: u16) -> Poly<N> {
    let mut out = Poly::<N>::zero();
    let mut coeff_idx: usize = 0;
    let mut i = 0usize;
    while i + 3 <= m.len().div_ceil(3) * 3 && coeff_idx < N - 1 {
        let b0 = if i < m.len() { m[i] } else { 0 } as u32;
        let b1 = if i + 1 < m.len() { m[i + 1] } else { 0 } as u32;
        let b2 = if i + 2 < m.len() { m[i + 2] } else { 0 } as u32;
        let mut chunk = (b2 << 16) | (b1 << 8) | b0;
        i += 3;
        for _ in 0..8 {
            if coeff_idx >= N - 1 {
                break;
            }
            let tbl = (chunk & 7) as usize;
            out.coeffs[coeff_idx] = trit_to_u16(SVES_C1[tbl], q_mask);
            out.coeffs[coeff_idx + 1] = trit_to_u16(SVES_C2[tbl], q_mask);
            coeff_idx += 2;
            chunk >>= 3;
        }
    }
    out
}

/// Decode the trit-pair packing back to bytes, returning `(bytes, valid)`.
///
/// The forbidden pair `(2, 2)` (which does not fit the 3-bit packing) is
/// flagged in `valid` rather than short-circuiting with an early return. This
/// keeps decryption on a single code path regardless of *why* a ciphertext is
/// rejected, which is what closes the classic NTRU decryption-failure /
/// reaction oracle: an attacker cannot distinguish a structural-decode failure
/// here from a re-encryption mismatch later. For a well-formed message no
/// `(2, 2)` occurs, so masking `c` to three bits leaves the output identical to
/// a strict decoder.
fn sves_to_bytes<const N: usize>(p: &Poly<N>) -> (Vec<u8>, bool) {
    let num_bits = (N * 3).div_ceil(2);
    let num_bytes = num_bits.div_ceil(8);
    let mut out = vec![0u8; num_bytes + 3];
    let end = N / 2 * 2;
    let mut invalid = 0u32;
    let mut d_idx = 0usize;
    let mut i = 0usize;
    while i < end {
        let mut acc: u32 = 0;
        let mut bits_in_acc: u32 = 0;
        for _ in 0..8 {
            if i >= end {
                break;
            }
            let c1 = u32::from(p.coeffs[i]);
            let c2 = u32::from(p.coeffs[i + 1]);
            i += 2;
            // Flag the forbidden (2,2) pair without leaving the loop.
            invalid |= u32::from(c1 == 2) & u32::from(c2 == 2);
            // Mask to three bits so (2,2) -> 8 cannot corrupt the packing of a
            // rejected ciphertext (its bytes are discarded anyway).
            let c = (c1 * 3 + c2) & 0x7;
            acc |= c << bits_in_acc;
            bits_in_acc += 3;
            while bits_in_acc >= 8 && d_idx < out.len() {
                out[d_idx] = (acc & 0xff) as u8;
                d_idx += 1;
                acc >>= 8;
                bits_in_acc -= 8;
            }
        }
        if bits_in_acc > 0 && d_idx < out.len() {
            out[d_idx] |= acc as u8;
        }
    }
    out.truncate(num_bytes);
    (out, invalid == 0)
}

#[cfg(test)]
mod sves_tests {
    use super::{sves_to_bytes, Poly};

    #[test]
    fn forbidden_pair_is_flagged_not_paniced() {
        // The (2,2) trit pair — previously an early `return None` — must now set
        // the invalid flag while still producing a full-length buffer, with no
        // panic (this is the branch the reaction-oracle fix depends on).
        let mut p = Poly::<8>::zero();
        p.coeffs[2] = 2;
        p.coeffs[3] = 2;
        let (bytes, valid) = sves_to_bytes::<8>(&p);
        assert!(!valid, "(2,2) pair must be flagged invalid");
        assert_eq!(bytes.len(), (8 * 3usize).div_ceil(2).div_ceil(8));
    }

    #[test]
    fn legal_pairs_stay_valid_and_masking_is_a_noop() {
        // Every legal pair has c1*3+c2 in 0..=7, so the `& 0x7` mask is a no-op
        // and the decode is byte-identical to a strict decoder that never sees
        // the forbidden value.
        let mut p = Poly::<8>::zero();
        for (k, &(a, b)) in [(0u16, 0u16), (0, 1), (1, 2), (2, 1)].iter().enumerate() {
            p.coeffs[2 * k] = a;
            p.coeffs[2 * k + 1] = b;
        }
        let (_bytes, valid) = sves_to_bytes::<8>(&p);
        assert!(valid);
    }
}

// ---- byte encodings of polynomials -----------------------------------------

fn poly_to_arr<const N: usize>(p: &Poly<N>, out: &mut [u8], params: &EesParams) {
    let logq = params.logq;
    let q_mask = params.q_mask();
    debug_assert_eq!(out.len(), params.pk_wire_bytes());
    for b in out.iter_mut() {
        *b = 0;
    }
    let mut bit_pos = 0usize;
    for i in 0..N {
        let v = (p.coeffs[i] & q_mask) as u32;
        for b in 0..logq {
            let bit = ((v >> b) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
}

fn poly_from_arr<const N: usize>(input: &[u8], params: &EesParams) -> Poly<N> {
    let logq = params.logq;
    debug_assert!(input.len() >= params.pk_wire_bytes());
    let mut p = Poly::<N>::zero();
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut v: u32 = 0;
        for b in 0..logq {
            let bit = ((input[bit_pos / 8] >> (bit_pos % 8)) & 1) as u32;
            v |= bit << b;
            bit_pos += 1;
        }
        p.coeffs[i] = v as u16;
    }
    p
}

fn poly_to_arr4<const N: usize>(p: &Poly<N>, params: &EesParams) -> Vec<u8> {
    let q = params.q();
    let q_mask = params.q_mask();
    let nbits = N * 2;
    let mut out = vec![0u8; nbits.div_ceil(8)];
    let mut bit_pos = 0usize;
    for i in 0..N {
        let centred = {
            let m = p.coeffs[i] & q_mask;
            let centred = if (m as u32) > q / 2 {
                m as i32 - q as i32
            } else {
                m as i32
            };
            (centred & 3) as u8
        };
        for b in 0..2 {
            let bit = (centred >> b) & 1;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
    out
}

// ---- private-key wire encoding (dense vs product form) ---------------------

fn pack_indices(
    indices: &[u16],
    out: &mut [u8],
    bit_offset: &mut usize,
    index_bits: usize,
) -> Option<()> {
    for &v in indices {
        if (v as usize) >= (1usize << index_bits) {
            return None;
        }
        for i in 0..index_bits {
            let bit = ((v >> i) & 1) as u8;
            out[*bit_offset / 8] |= bit << (*bit_offset % 8);
            *bit_offset += 1;
        }
    }
    Some(())
}

fn unpack_indices(
    bytes: &[u8],
    n: usize,
    bit_offset: &mut usize,
    index_bits: usize,
    n_max: usize,
) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut v: u32 = 0;
        for i in 0..index_bits {
            let bit = ((bytes[*bit_offset / 8] >> (*bit_offset % 8)) & 1) as u32;
            v |= bit << i;
            *bit_offset += 1;
        }
        if (v as usize) >= n_max {
            return None;
        }
        out.push(v as u16);
    }
    Some(out)
}

/// `out`'s trailing bits past `used_bits` must be zero; returns true if so.
/// Used both for trapdoor and pk/ct wire decoding so the malleability check
/// is implemented once. Caller passes the slice and the meaningful bit count.
#[doc(hidden)]
pub fn padding_bits_clear(bytes: &[u8], used_bits: usize) -> bool {
    debug_assert!(used_bits <= bytes.len() * 8);
    let total = bytes.len() * 8;
    if total == used_bits {
        return true;
    }
    let last = *bytes.last().expect("non-empty by construction");
    let used_in_last = used_bits - (bytes.len() - 1) * 8;
    (last >> used_in_last) == 0
}

/// Pack the trapdoor portion of a private key into the `params`-defined
/// trapdoor wire bytes. Thin alias for [`Trapdoor::to_wire`].
pub fn trapdoor_to_wire(t: &Trapdoor, params: &EesParams, out: &mut [u8]) {
    t.to_wire(params, out);
}

/// Inverse of [`trapdoor_to_wire`]. Thin alias for
/// [`Trapdoor::from_wire`].
pub fn trapdoor_from_wire(bytes: &[u8], params: &EesParams) -> Option<Trapdoor> {
    Trapdoor::from_wire(bytes, params)
}

// ---- helpers ---------------------------------------------------------------

fn next_index_below<R: Csprng>(rng: &mut R, modulus: u32) -> u32 {
    let threshold = u32::MAX - (u32::MAX % modulus);
    loop {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v < threshold {
            return v % modulus;
        }
    }
}

fn sample_trinary<R: Csprng>(
    rng: &mut R,
    n: usize,
    num_ones: usize,
    num_neg_ones: usize,
) -> TernaryPoly {
    debug_assert!(num_ones + num_neg_ones <= n);
    let mut idx: Vec<u16> = (0..n as u16).collect();
    let take = num_ones + num_neg_ones;
    for i in 0..take {
        let j = i + next_index_below(rng, (n - i) as u32) as usize;
        idx.swap(i, j);
    }
    let mut ones = idx[..num_ones].to_vec();
    let mut neg_ones = idx[num_ones..take].to_vec();
    ones.sort_unstable();
    neg_ones.sort_unstable();
    TernaryPoly { ones, neg_ones }
}

fn sample_trapdoor<R: Csprng>(rng: &mut R, params: &EesParams) -> Trapdoor {
    Trapdoor::sample_iid(rng, params)
}

fn check_rep_weight<const N: usize>(p: &Poly<N>, params: &EesParams) -> bool {
    let mut w = [0usize; 3];
    for i in 0..N {
        let v = p.coeffs[i] as usize;
        if v < 3 {
            w[v] += 1;
        }
    }
    w[0] >= params.dm0 && w[1] >= params.dm0 && w[2] >= params.dm0
}

// ---- top-level keygen / encrypt / decrypt ---------------------------------

/// Failure modes of the EES encrypt / decrypt routines. Wire-length and
/// padding-bit violations are rejected earlier, by the typed
/// `from_wire_bytes` constructors in the per-set wrappers, so only these
/// two conditions surface as an `Err`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtruEesError {
    /// The plaintext handed to `encrypt` is longer than
    /// [`EesParams::max_message_bytes`] for the parameter set, so the
    /// SVES-3 message block (`db` salt bits, length byte, payload, zero
    /// padding) cannot hold it.
    MessageTooLong,
    /// Decryption rejected the ciphertext: the candidate message failed an
    /// SVES-3 check (per-value trinary weight below `dm0`, non-zero
    /// padding, out-of-range length byte) or the deterministic
    /// re-encryption did not reproduce the ciphertext. The cause is
    /// deliberately not distinguished, and is reported only after every
    /// check has run — see the reaction-oracle notes inside [`decrypt`].
    InvalidCiphertext,
}

/// Generate a fresh key pair. The returned `pk_bytes` has length
/// `params.pk_wire_bytes()`; the trapdoor is returned as a [`Trapdoor`] so
/// the caller can pack it with [`trapdoor_to_wire`].
pub fn keygen<const N: usize, R: Csprng>(params: &EesParams, rng: &mut R) -> (Vec<u8>, Trapdoor) {
    debug_assert_eq!(params.n, N);
    let q_mask = params.q_mask();
    loop {
        let t = sample_trapdoor(rng, params);
        // f = 1 + 3 · t expanded into a dense polynomial.
        let mut f = t.to_dense::<N>(q_mask);
        poly_scalar_mul::<N>(&mut f, 3, q_mask);
        f.coeffs[0] = f.coeffs[0].wrapping_add(1) & q_mask;
        let f_inv = match poly_inverse_mod_q_cyclic::<N>(&f, params) {
            Some(inv) => inv,
            None => continue,
        };

        let g = sample_trinary(rng, params.n, params.dg, params.dg);
        let mut g_dense = g.to_dense::<N>(q_mask);
        poly_mod_q::<N>(&mut g_dense, q_mask);
        let mut h = Poly::<N>::zero();
        poly_mul::<N>(&mut h, &g_dense, &f_inv);
        poly_scalar_mul::<N>(&mut h, 3, q_mask);

        let mut pk_bytes = vec![0u8; params.pk_wire_bytes()];
        poly_to_arr::<N>(&h, &mut pk_bytes, params);
        return (pk_bytes, t);
    }
}

pub fn encrypt<const N: usize, R: Csprng>(
    pk_bytes: &[u8],
    msg: &[u8],
    rng: &mut R,
    params: &EesParams,
) -> Result<Vec<u8>, NtruEesError> {
    debug_assert_eq!(params.n, N);
    if msg.len() > params.max_message_bytes() {
        return Err(NtruEesError::MessageTooLong);
    }
    let q_mask = params.q_mask();
    let mut h = poly_from_arr::<N>(pk_bytes, params);
    poly_mod_q::<N>(&mut h, q_mask);

    let pklen_bytes = params.pklen_bytes();
    let htrunc = &pk_bytes[..pklen_bytes];
    let db_bytes = params.db_bytes();
    let max_msg = params.max_message_bytes();

    loop {
        let mut b = vec![0u8; db_bytes];
        rng.fill_bytes(&mut b);

        let m_len = db_bytes + 1 + max_msg + 1;
        let mut m = vec![0u8; m_len];
        m[..db_bytes].copy_from_slice(&b);
        m[db_bytes] = msg.len() as u8;
        m[db_bytes + 1..db_bytes + 1 + msg.len()].copy_from_slice(msg);

        let mtrin = sves_from_bytes::<N>(&m, q_mask);

        let mut sdata = Vec::with_capacity(params.oid.len() + msg.len() + b.len() + htrunc.len());
        sdata.extend_from_slice(&params.oid);
        sdata.extend_from_slice(msg);
        sdata.extend_from_slice(&b);
        sdata.extend_from_slice(htrunc);

        let mut igf = IgfState::new(&sdata, params);
        let r = igf_gen_blinding(&mut igf);

        let mut bigr = Poly::<N>::zero();
        r.mul_dense::<N>(&h, &mut bigr);
        poly_mod_q::<N>(&mut bigr, q_mask);

        let or4 = poly_to_arr4::<N>(&bigr, params);
        let mask = mgf::<N>(&or4, params);

        let mut mtrin_plus_mask = mtrin;
        poly_add::<N>(&mut mtrin_plus_mask, &mask);
        poly_mod3::<N>(&mut mtrin_plus_mask, params);

        if !check_rep_weight::<N>(&mtrin_plus_mask, params) {
            continue;
        }

        let mut e = bigr;
        for i in 0..N {
            let v = mtrin_plus_mask.coeffs[i];
            let signed: u16 = match v {
                0 => 0,
                1 => 1,
                2 => q_mask,
                _ => unreachable!(),
            };
            e.coeffs[i] = e.coeffs[i].wrapping_add(signed);
        }
        poly_mod_q::<N>(&mut e, q_mask);

        let mut out = vec![0u8; params.ciphertext_wire_bytes()];
        poly_to_arr::<N>(&e, &mut out, params);
        return Ok(out);
    }
}

pub fn decrypt<const N: usize>(
    sk_trapdoor: &Trapdoor,
    pk_bytes: &[u8],
    ct_bytes: &[u8],
    params: &EesParams,
) -> Result<Vec<u8>, NtruEesError> {
    debug_assert_eq!(params.n, N);
    let q_mask = params.q_mask();
    let e = poly_from_arr::<N>(ct_bytes, params);

    let mut te = Poly::<N>::zero();
    sk_trapdoor.mul_dense::<N>(&e, &mut te);
    let mut ci = te;
    poly_scalar_mul::<N>(&mut ci, 3, q_mask);
    poly_add::<N>(&mut ci, &e);
    poly_mod_q::<N>(&mut ci, q_mask);
    poly_mod3::<N>(&mut ci, params);

    let mut retcode_ok = check_rep_weight::<N>(&ci, params);

    let mut c_r = e;
    let mut ci_modq = Poly::<N>::zero();
    for i in 0..N {
        ci_modq.coeffs[i] = match ci.coeffs[i] {
            0 => 0,
            1 => 1,
            2 => q_mask,
            _ => unreachable!(),
        };
    }
    poly_sub::<N>(&mut c_r, &ci_modq);
    poly_mod_q::<N>(&mut c_r, q_mask);

    let or4 = poly_to_arr4::<N>(&c_r, params);
    let mask = mgf::<N>(&or4, params);

    let mut cmtrin = ci;
    poly_sub::<N>(&mut cmtrin, &mask);
    poly_mod3::<N>(&mut cmtrin, params);

    // Decode without an early return; fold a decode failure into `retcode_ok`
    // so structural failures no longer short-circuit *before* the re-encryption
    // check. This removes the classic reaction oracle in which a decode/length
    // failure rejected measurably faster than a re-encryption mismatch.
    //
    // Note: this is not a fully time-invariant decrypt. The recovered length
    // byte `cl` still governs a small amount of tail work (the message copy,
    // the padding scan, and the length of the IGF seed), which is inherent to
    // variable-length SVES messages; the dominant re-encryption cost
    // (`mul_dense` + the coefficient diff) is length-independent. The removed
    // early returns were the exploitable distinguisher.
    let (cm, sves_ok) = sves_to_bytes::<N>(&cmtrin);
    retcode_ok &= sves_ok;

    let db_bytes = params.db_bytes();
    let max_msg = params.max_message_bytes();
    let cb = &cm[..db_bytes];
    let cl_raw = cm[db_bytes] as usize;
    // Fold the length-byte range check into the flag too, and clamp so the
    // message/padding slices below can never go out of bounds on a tampered
    // ciphertext (the clamped bytes are discarded when `retcode_ok` is false).
    retcode_ok &= cl_raw <= max_msg;
    let cl = cl_raw.min(max_msg);
    let msg = cm[db_bytes + 1..db_bytes + 1 + cl].to_vec();

    let pad_start = db_bytes + 1 + cl;
    let pad_end = (params.n * 3).div_ceil(2);
    let pad_end_bytes = pad_end.div_ceil(8);
    for &p in &cm[pad_start..pad_end_bytes.min(cm.len())] {
        if p != 0 {
            retcode_ok = false;
        }
    }

    let pklen_bytes = params.pklen_bytes();
    let htrunc = &pk_bytes[..pklen_bytes];
    let mut sdata = Vec::with_capacity(params.oid.len() + cl + db_bytes + db_bytes);
    sdata.extend_from_slice(&params.oid);
    sdata.extend_from_slice(&msg);
    sdata.extend_from_slice(cb);
    sdata.extend_from_slice(htrunc);
    let mut igf = IgfState::new(&sdata, params);
    let cr_priv = igf_gen_blinding(&mut igf);

    let h = poly_from_arr::<N>(pk_bytes, params);
    let mut bigr_prime = Poly::<N>::zero();
    cr_priv.mul_dense::<N>(&h, &mut bigr_prime);
    poly_mod_q::<N>(&mut bigr_prime, q_mask);

    // Constant-time re-encryption check: accumulate the XOR difference over
    // every coefficient instead of breaking on the first mismatch, so the
    // comparison cost never depends on where a tampered ciphertext diverges.
    let mut diff: u16 = 0;
    for i in 0..N {
        diff |= bigr_prime.coeffs[i] ^ c_r.coeffs[i];
    }
    if diff != 0 {
        retcode_ok = false;
    }

    if !retcode_ok {
        return Err(NtruEesError::InvalidCiphertext);
    }
    Ok(msg)
}

// ---- per-set wrapper macro --------------------------------------------------
//
// Each IEEE 1363.1 parameter set turns into a thin wrapper module: typed
// `*PublicKey`, `*PrivateKey`, `*Ciphertext` newtypes plus a `keygen` /
// `encrypt` / `decrypt` namespace, all delegating to the generic routines
// above. The macro takes the four wrapper type idents explicitly (avoiding a
// paste! dependency) plus the parameter values; each per-set source file is
// then a single macro invocation.

macro_rules! define_ees_set {
    (
        namespace = $type_name:ident,
        public_key = $pk_ty:ident,
        private_key = $sk_ty:ident,
        ciphertext = $ct_ty:ident,
        n = $n:expr,
        trapdoor = $trapdoor:expr,
        dg = $dg:expr,
        dm0 = $dm0:expr,
        db_bits = $db_bits:expr,
        c_bits = $c_bits:expr,
        min_calls_r = $min_calls_r:expr,
        min_calls_mask = $min_calls_mask:expr,
        pklen_bits = $pklen_bits:expr,
        oid = $oid:expr,
        hash = $hash:expr,
        pk_bytes = $pk_bytes:expr,
        sk_packed_bytes = $sk_packed_bytes:expr,
        ct_bytes = $ct_bytes:expr,
        regression_digest = $regression_digest:expr $(,)?
    ) => {
        use $crate::public_key::ntru_ees_core::{
            decrypt as __ees_core_decrypt, encrypt as __ees_core_encrypt,
            keygen as __ees_core_keygen, padding_bits_clear as __ees_padding_bits_clear,
            trapdoor_from_wire as __ees_trapdoor_from_wire,
            trapdoor_to_wire as __ees_trapdoor_to_wire, EesParams, HashKind, NtruEesError,
            Trapdoor, TrapdoorKind,
        };
        use $crate::Csprng;

        const PARAMS: EesParams = EesParams {
            n: $n,
            logq: 11,
            trapdoor: $trapdoor,
            dg: $dg,
            dm0: $dm0,
            db_bits: $db_bits,
            c_bits: $c_bits,
            min_calls_r: $min_calls_r,
            min_calls_mask: $min_calls_mask,
            pklen_bits: $pklen_bits,
            oid: $oid,
            hash: $hash,
        };

        const N: usize = $n;

        pub const PUBLIC_KEY_BYTES: usize = PARAMS.pk_wire_bytes();
        pub const PRIVATE_KEY_BYTES: usize = PARAMS.trapdoor_wire_bytes();
        pub const CIPHERTEXT_BYTES: usize = PARAMS.ciphertext_wire_bytes();
        pub const MAX_MESSAGE_BYTES: usize = PARAMS.max_message_bytes();

        /// Public key for this parameter set: the polynomial
        /// `h = 3 g f^{-1} (mod q)` held in its canonical wire form —
        /// `N` coefficients of `logq = 11` bits each, coefficient 0
        /// first, bits packed least-significant first within each byte,
        /// [`PUBLIC_KEY_BYTES`] (`ceil(N * 11 / 8)`) bytes in all.
        /// Produced by the namespace type's `keygen` or decoded with
        /// [`Self::from_wire_bytes`].
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk_ty {
            bytes: Vec<u8>,
        }

        /// Private key for this parameter set: the sampled trinary
        /// trapdoor `t` (the secret polynomial is `f = 1 + 3t`) together
        /// with an embedded copy of the matching public key, which the
        /// SVES-3 re-encryption check in `decrypt` reads. `Debug` prints
        /// `<redacted>` instead of key material, and the trapdoor's
        /// index lists are zeroised on drop.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $sk_ty {
            t: Trapdoor,
            pk: $pk_ty,
        }

        /// Ciphertext for this parameter set: the ring element
        /// `e = r h + m' (mod q)` in the same 11-bit-per-coefficient,
        /// least-significant-bit-first packing as the public key —
        /// [`CIPHERTEXT_BYTES`] bytes, always equal to
        /// [`PUBLIC_KEY_BYTES`].
        #[derive(Clone, Eq, PartialEq)]
        pub struct $ct_ty {
            bytes: Vec<u8>,
        }

        impl $pk_ty {
            /// Decode a public key from its wire bytes. Returns `None`
            /// unless `bytes` is exactly [`PUBLIC_KEY_BYTES`] long and
            /// the unused bits after the `N * 11` coefficient bits in
            /// the final byte are all zero, so every public key has a
            /// single accepted encoding. Coefficient values are not
            /// otherwise constrained (any residue mod `q` is a valid
            /// coefficient).
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PUBLIC_KEY_BYTES {
                    return None;
                }
                if !__ees_padding_bits_clear(bytes, N * PARAMS.logq) {
                    return None;
                }
                Some(Self {
                    bytes: bytes.to_vec(),
                })
            }

            /// Canonical wire encoding, [`PUBLIC_KEY_BYTES`] long, as an
            /// owned copy. [`Self::from_wire_bytes`] accepts exactly
            /// this output and reproduces an equal key.
            #[must_use]
            pub fn to_wire_bytes(&self) -> Vec<u8> {
                self.bytes.clone()
            }

            /// Borrow the canonical wire encoding without copying: the
            /// same [`PUBLIC_KEY_BYTES`] bytes [`Self::to_wire_bytes`]
            /// would return.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $sk_ty {
            /// Serialise as the packed trapdoor followed by the embedded
            /// public key: [`PRIVATE_KEY_BYTES`] `+` [`PUBLIC_KEY_BYTES`]
            /// bytes total. The trapdoor section uses the IEEE 1363.1
            /// packing for this set's trapdoor structure: 2 bits of
            /// signed trinary per coefficient for a dense set, or
            /// `ceil(log2 N)`-bit index lists for a product-form set.
            /// The output contains the secret key; treat it with
            /// the same care as the key itself.
            #[must_use]
            pub fn to_wire_bytes(&self) -> Vec<u8> {
                let mut out = vec![0u8; PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES];
                __ees_trapdoor_to_wire(&self.t, &PARAMS, &mut out[..PRIVATE_KEY_BYTES]);
                out[PRIVATE_KEY_BYTES..].copy_from_slice(&self.pk.bytes);
                out
            }

            /// Inverse of [`Self::to_wire_bytes`]. Returns `None`
            /// unless the length is exactly [`PRIVATE_KEY_BYTES`] `+`
            /// [`PUBLIC_KEY_BYTES`], the trapdoor section decodes with
            /// precisely the ones / minus-ones counts this set
            /// prescribes (with clear trailing padding bits and, for
            /// product form, every index below `N`), and the trailing
            /// public key passes the public-key type's own decoder.
            /// Consistency between trapdoor and public key is *not*
            /// verified here; a mismatched pair makes every later
            /// `decrypt` fail its re-encryption check.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES {
                    return None;
                }
                let t = __ees_trapdoor_from_wire(&bytes[..PRIVATE_KEY_BYTES], &PARAMS)?;
                let pk = $pk_ty::from_wire_bytes(&bytes[PRIVATE_KEY_BYTES..])?;
                Some(Self { t, pk })
            }

            /// The public key stored alongside the trapdoor at key
            /// generation or deserialisation; returned by reference, no
            /// arithmetic is redone to derive it.
            #[must_use]
            pub fn public_key(&self) -> &$pk_ty {
                &self.pk
            }
        }

        impl $ct_ty {
            /// Decode a ciphertext from wire bytes. Returns `None`
            /// unless `bytes` is exactly [`CIPHERTEXT_BYTES`] long with
            /// the bits past the `N * 11` coefficient bits in the final
            /// byte all zero — the same single-accepted-encoding rule
            /// the public-key decoder enforces. Whether the ciphertext
            /// actually decrypts is decided later, by the namespace
            /// type's `decrypt`.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != CIPHERTEXT_BYTES {
                    return None;
                }
                if !__ees_padding_bits_clear(bytes, N * PARAMS.logq) {
                    return None;
                }
                Some(Self {
                    bytes: bytes.to_vec(),
                })
            }

            /// Canonical wire encoding, [`CIPHERTEXT_BYTES`] long, as an
            /// owned copy. [`Self::from_wire_bytes`] accepts exactly
            /// this output and reproduces an equal ciphertext.
            #[must_use]
            pub fn to_wire_bytes(&self) -> Vec<u8> {
                self.bytes.clone()
            }

            /// Borrow the canonical wire encoding without copying: the
            /// same [`CIPHERTEXT_BYTES`] bytes [`Self::to_wire_bytes`]
            /// would return.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl ::core::fmt::Debug for $sk_ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($sk_ty), "(<redacted>)"))
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

        /// Namespace type for this IEEE 1363.1 parameter set: a unit
        /// struct carrying the wire-size constants and the `keygen` /
        /// `encrypt` / `decrypt` entry points, all of which delegate to
        /// the shared routines in
        /// [`crate::public_key::ntru_ees_core`] with this set's
        /// constants bound. Variable-time arithmetic; see the core
        /// module's side-channel notes.
        pub struct $type_name;

        impl $type_name {
            /// Wire-format public-key length in bytes for this set.
            pub const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
            /// Wire-format private-key length in bytes for this set.
            pub const PRIVATE_KEY_BYTES: usize = PRIVATE_KEY_BYTES;
            /// Wire-format ciphertext length in bytes for this set.
            pub const CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;
            /// Maximum byte length of a message that
            /// [`Self::encrypt`] will accept; longer inputs return
            /// [`NtruEesError::MessageTooLong`].
            pub const MAX_MESSAGE_BYTES: usize = MAX_MESSAGE_BYTES;

            /// Generate a key pair from `rng`: sample this set's
            /// trinary trapdoor `t`, retrying until `f = 1 + 3t` is
            /// invertible mod `q`, then publish `h = 3 g f^{-1} (mod q)`
            /// for a fresh trinary `g` with `dg` ones and `dg`
            /// minus-ones. The private key embeds a copy of the public
            /// key, which [`Self::decrypt`]'s re-encryption check
            /// reads. Draws a variable number of bytes from `rng`
            /// (rejection sampling plus the invertibility retry loop).
            pub fn keygen<R: Csprng>(rng: &mut R) -> ($pk_ty, $sk_ty) {
                let (pk_bytes, t) = __ees_core_keygen::<N, R>(&PARAMS, rng);
                let pk = $pk_ty {
                    bytes: pk_bytes.clone(),
                };
                let sk = $sk_ty { t, pk: pk.clone() };
                (pk, sk)
            }

            /// SVES-3 encryption (IEEE 1363.1). Prepends `db` random
            /// salt bits and a length byte to `msg`, zero-pads, masks
            /// the resulting trinary message with an MGF of `r * h`,
            /// and returns the [`CIPHERTEXT_BYTES`]-byte ciphertext
            /// `e = r h + m' (mod q)`, where the blinding polynomial
            /// `r` is derived deterministically (IGF) from the set OID,
            /// the message, the salt, and the truncated public key.
            /// Errs with [`NtruEesError::MessageTooLong`] when
            /// `msg.len()` exceeds [`MAX_MESSAGE_BYTES`]; salts are
            /// redrawn until the masked message carries at least `dm0`
            /// of each trinary value, so the number of bytes drawn from
            /// `rng` is itself variable.
            pub fn encrypt<R: Csprng>(
                pk: &$pk_ty,
                msg: &[u8],
                rng: &mut R,
            ) -> Result<$ct_ty, NtruEesError> {
                let bytes = __ees_core_encrypt::<N, R>(&pk.bytes, msg, rng, &PARAMS)?;
                Ok($ct_ty { bytes })
            }

            /// SVES-3 decryption. Recovers the candidate message from
            /// `f e (mod q)` centred and reduced mod 3, strips the MGF
            /// mask, then re-derives `r` and re-encrypts; any failure —
            /// trinary weight below `dm0`, non-zero padding, an
            /// out-of-range length byte, or a re-encryption mismatch —
            /// is reported uniformly as
            /// [`NtruEesError::InvalidCiphertext`], and only after
            /// every check has run (reaction-oracle hygiene; see the
            /// core `decrypt`). On success returns the plaintext, at
            /// most [`MAX_MESSAGE_BYTES`] bytes.
            pub fn decrypt(sk: &$sk_ty, ct: &$ct_ty) -> Result<Vec<u8>, NtruEesError> {
                __ees_core_decrypt::<N>(&sk.t, &sk.pk.bytes, &ct.bytes, &PARAMS)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::CtrDrbgAes256;

            #[test]
            fn parameter_byte_lengths() {
                assert_eq!(PUBLIC_KEY_BYTES, $pk_bytes);
                assert_eq!(PRIVATE_KEY_BYTES, $sk_packed_bytes);
                assert_eq!(CIPHERTEXT_BYTES, $ct_bytes);
                assert!(MAX_MESSAGE_BYTES > 0);
            }

            #[test]
            fn round_trip_empty_and_full_messages() {
                let mut drbg = CtrDrbgAes256::new(&[0x42u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                for &len in &[0usize, 1, 16, 32, MAX_MESSAGE_BYTES] {
                    let mut msg = vec![0u8; len];
                    drbg.fill_bytes(&mut msg);
                    let ct = $type_name::encrypt(&pk, &msg, &mut drbg).expect("encrypt");
                    let dec = $type_name::decrypt(&sk, &ct).expect("decrypt");
                    assert_eq!(dec, msg, "round-trip at len={}", len);
                }
            }

            #[test]
            fn rejects_oversize_message() {
                let mut drbg = CtrDrbgAes256::new(&[0x77u8; 48]);
                let (pk, _) = $type_name::keygen(&mut drbg);
                let too_big = vec![0u8; MAX_MESSAGE_BYTES + 1];
                let err = $type_name::encrypt(&pk, &too_big, &mut drbg).unwrap_err();
                assert_eq!(err, NtruEesError::MessageTooLong);
            }

            #[test]
            fn corrupted_ciphertext_rejected() {
                let mut drbg = CtrDrbgAes256::new(&[0x99u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let msg = b"hello ntru";
                let ct = $type_name::encrypt(&pk, msg, &mut drbg).expect("encrypt");
                let mut bad_bytes = ct.to_wire_bytes();
                bad_bytes[10] ^= 0xff;
                let bad_ct = $ct_ty::from_wire_bytes(&bad_bytes).expect("structural decode");
                match $type_name::decrypt(&sk, &bad_ct) {
                    Err(NtruEesError::InvalidCiphertext) => {}
                    other => panic!("expected InvalidCiphertext, got {:?}", other),
                }
            }

            /// Regression vector: locks in the byte-level encoding of pk,
            /// sk, and ct under a fixed DRBG seed and message. Computed
            /// once via `cargo run --bin ees_regression_gen`; a future
            /// refactor that silently changes wire-format byte order or
            /// padding will fail this digest check.
            #[test]
            fn byte_format_regression_digest() {
                use $crate::hash::sha2::Sha256;
                let mut drbg = CtrDrbgAes256::new(&[0xC0u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let ct = $type_name::encrypt(&pk, &[0xA5u8; 8], &mut drbg).expect("encrypt");
                let mut h = Sha256::new();
                h.update(&pk.to_wire_bytes());
                h.update(&sk.to_wire_bytes());
                h.update(&ct.to_wire_bytes());
                let digest = h.finalize();
                let mut hex = String::with_capacity(64);
                for b in digest.iter() {
                    use ::core::fmt::Write;
                    write!(&mut hex, "{:02x}", b).unwrap();
                }
                assert_eq!(hex, $regression_digest, "byte-format regression");
            }

            #[test]
            fn wire_format_roundtrip_keys_and_ct() {
                let mut drbg = CtrDrbgAes256::new(&[0xa0u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let msg = b"wire-format-roundtrip";
                let ct = $type_name::encrypt(&pk, msg, &mut drbg).expect("encrypt");

                let pk_round = $pk_ty::from_wire_bytes(&pk.to_wire_bytes()).expect("pk decode");
                let sk_round = $sk_ty::from_wire_bytes(&sk.to_wire_bytes()).expect("sk decode");
                let ct_round = $ct_ty::from_wire_bytes(&ct.to_wire_bytes()).expect("ct decode");

                assert_eq!(pk_round, pk);
                assert_eq!(sk_round, sk);
                assert_eq!(ct_round, ct);

                let dec = $type_name::decrypt(&sk_round, &ct_round).expect("decrypt");
                assert_eq!(dec, msg);
            }
        }
    };
}

pub(crate) use define_ees_set;
