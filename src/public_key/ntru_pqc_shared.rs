//! Constant-time helpers, the OWCPA + FO-style KEM core, and the
//! `NtruVariant` trait shared by the NIST PQC NTRU modules
//! ([`crate::public_key::ntru_hps509`], `_hps677`, `_hps821`, `_hrss701`).
//!
//! This module hosts the algorithmic core that the four per-set NTRU
//! PQC modules in this crate share. Each per-set file is the
//! parameter constants plus a single `impl NtruVariant<N, LOGQ>` and
//! a `define_pqc_kem!` invocation; everything else lives here.
//!
//! Reference: round-3 NTRU specification (Chen, Chung, Hülsing, Lange,
//! Lyubashevsky, Saito, Schanck, Schwabe, Stehlé, Whyte, Xagawa,
//! Yamakawa, Zhang; NIST PQC, 2020-10-16).
//!
//! Construction (HPS variants `Hps509Variant` / `Hps677Variant` /
//! `Hps821Variant`; HRSS variant `Hrss701Variant`):
//!
//! - Ring $\mathbb{Z}_q[x] / (x^N - 1)$ with operations projected onto
//!   $\mathbb{Z}_q[x] / \Phi_n(x)$ where
//!   $\Phi_n(x) = (x^N - 1) / (x - 1)$ for the `Sq` and `S3` views.
//! - One-way CPA-secure encryption (OWCPA) under the trapdoor
//!   $(f, g)$ with public key $h = g / f$ in $R_q$, encryption
//!   $c = r \cdot h + \text{lift}(m)$, decryption recovering
//!   $(r, m)$. Variant-specific bits ($g$-update, $\text{lift}$,
//!   message validation) come from [`NtruVariant`] methods.
//! - CCA KEM via the SXY/Sch18 Fujisaki–Okamoto-style transform:
//!   shared key $K = \text{SHA3-256}(r \mathbin\| m)$, with
//!   deterministic implicit rejection
//!   $K = \text{SHA3-256}(\text{prf} \mathbin\| c)$ on any
//!   decapsulation failure. SHA3-256 and AES-256 CTR-DRBG come
//!   from this crate's `hash` and `cprng` modules; no C/FFI
//!   backends are used.
//!
//! Implementation notes shared by all four parameter sets:
//!
//! - inversion in $R_2 = \mathbb{F}_2[x] / (x^N - 1)$ and in
//!   $S_3 = \mathbb{F}_3[x] / \Phi_n(x)$ uses the constant-time gcd
//!   recursion of Bernstein and Yang ("Fast constant-time gcd
//!   computation and modular inversion", TCHES 2019).
//! - the fixed-weight `T_fixed` sampler ([`sample_fixed_type`], HPS
//!   only) tags each candidate coefficient with 30 random bits and
//!   a 2-bit trinary intent, then sorts by tag using Batcher's
//!   bitonic sorting network (Batcher, "Sorting networks and their
//!   applications", AFIPS 1968).
//! - polynomial arithmetic and packings are implemented in-tree;
//!   the cyclic multiplier ([`crate::public_key::ntru_poly_mul`])
//!   uses Karatsuba over `u16` wrapping arithmetic.
//!
//! Side-channel inventory (the per-set modules link here instead of
//! repeating it):
//!
//! - **Constant-time** (data-independent control flow): the
//!   Bernstein–Yang $R_2$ and $S_3$ inverters, the four-round
//!   Newton/Hensel lift to $R_q$, the Batcher fixed-weight sort
//!   ([`crypto_sort_int32`], used by HPS only), [`cmov`], `mod3`,
//!   `mod3_u8`, the IID-uniform-mod-3 sampler, the SHA3-256 + AES-256
//!   CTR-DRBG implementations from this crate's `hash` and `cprng`
//!   modules, and the polynomial multiplier in
//!   [`crate::public_key::ntru_poly_mul`] (its schoolbook base case
//!   issues exactly one `wrapping_mul` and one `wrapping_add` per
//!   coefficient pair, with no early-skip on zeros, and Karatsuba
//!   inherits that property recursively).
//!
//! - **Caveats**: `u16::wrapping_mul` is only constant-time at the
//!   hardware level on architectures whose integer multiplier is
//!   itself constant-time, which is the case on every CPU this crate
//!   targets (modern AArch64 / x86-64 / RISC-V `MUL`). The four NIST
//!   PQC NTRU modules remain re-exported under [`crate::vt`] because
//!   that namespace is this crate's convention for "public-key
//!   primitives that have not been independently formally vetted as
//!   constant-time across all relevant micro-architectural channels"
//!   — e.g. cache-timing on the `params` accesses, branch-predictor
//!   training on the FO transform — not because of any specific
//!   data-dependent branch in the source.

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

/// Reduce $a \in [0, 5)$ modulo 3 without branches. Used inside the
/// Bernstein–Yang $\mathbb{F}_3$ inverter to keep intermediate
/// coefficients canonical after each `g[i] += sign * f[i]` step.
#[inline]
pub(crate) fn mod3_u8(a: u8) -> u8 {
    let a = (a >> 2) + (a & 3);
    let t = (a as i16) - 3;
    let c = t >> 5;
    (t ^ (c & ((a as i16) ^ t))) as u8
}

/// Builder-style hash-update helper used by the NIST FO-style KEM
/// transforms: `Sha3_256::new().chain(a).chain(b).finalize()` reads more
/// naturally than a sequence of `update` calls.
pub(crate) trait DigestChain: crate::hash::Digest + Sized {
    fn chain(self, data: &[u8]) -> Self {
        let mut me = self;
        me.update(data);
        me
    }
}

impl<D: crate::hash::Digest> DigestChain for D {}

// ---- shared polynomial inverters (Bernstein–Yang + Hensel) -----------------

/// Constant-time inverse of `a` in $R_2 = \mathbb{F}_2[x] / (x^N - 1)$.
///
/// Bernstein and Yang's swap-and-shift gcd recursion (TCHES 2019, "Fast
/// constant-time gcd computation and modular inversion") with $2(N - 1) - 1$
/// iterations, the worst-case bound from the cited paper. Every comparator,
/// shift, and conditional in the loop is data-independent.
pub(crate) fn poly_r2_inv<const N: usize>(r: &mut [u16; N], a: &[u16; N]) {
    let mut f = [0u16; N];
    let mut g = [0u16; N];
    let mut v = [0u16; N];
    let mut w = [0u16; N];
    w[0] = 1;
    for fi in f.iter_mut() {
        *fi = 1;
    }
    for i in 0..N - 1 {
        g[N - 2 - i] = (a[i] ^ a[N - 1]) & 1;
    }
    g[N - 1] = 0;
    let mut delta: i16 = 1;

    for _ in 0..(2 * (N - 1) - 1) {
        for i in (1..N).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;

        let sign = (g[0] & f[0]) as i16;
        let swap = both_negative_mask_i16(-delta, -(g[0] as i16));
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for i in 0..N {
            let t = (swap as u16) & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            let t = (swap as u16) & (v[i] ^ w[i]);
            v[i] ^= t;
            w[i] ^= t;
        }
        for i in 0..N {
            g[i] ^= (sign as u16) & f[i];
        }
        for i in 0..N {
            w[i] ^= (sign as u16) & v[i];
        }
        for i in 0..N - 1 {
            g[i] = g[i + 1];
        }
        g[N - 1] = 0;
    }

    for i in 0..N - 1 {
        r[i] = v[N - 2 - i];
    }
    r[N - 1] = 0;
}

/// Constant-time inverse of `a` in $S_3 = \mathbb{F}_3[x] / \Phi_n(x)$.
/// Same Bernstein–Yang recursion as [`poly_r2_inv`] but over $\mathbb{F}_3$;
/// `mod3_u8` keeps each step's coefficients canonical in $\{0, 1, 2\}$.
pub(crate) fn poly_s3_inv<const N: usize>(r: &mut [u16; N], a: &[u16; N]) {
    let mut f = [0u16; N];
    let mut g = [0u16; N];
    let mut v = [0u16; N];
    let mut w = [0u16; N];
    w[0] = 1;
    for fi in f.iter_mut() {
        *fi = 1;
    }
    for i in 0..N - 1 {
        g[N - 2 - i] = mod3_u8(((a[i] & 3) + 2 * (a[N - 1] & 3)) as u8) as u16;
    }
    g[N - 1] = 0;
    let mut delta: i16 = 1;

    for _ in 0..(2 * (N - 1) - 1) {
        for i in (1..N).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;

        let sign = mod3_u8((2 * g[0] * f[0]) as u8) as u16;
        let swap = both_negative_mask_i16(-delta, -(g[0] as i16));
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for i in 0..N {
            let t = (swap as u16) & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            let t = (swap as u16) & (v[i] ^ w[i]);
            v[i] ^= t;
            w[i] ^= t;
        }
        for i in 0..N {
            g[i] = mod3_u8((g[i] + sign * f[i]) as u8) as u16;
        }
        for i in 0..N {
            w[i] = mod3_u8((w[i] + sign * v[i]) as u8) as u16;
        }
        for i in 0..N - 1 {
            g[i] = g[i + 1];
        }
        g[N - 1] = 0;
    }

    let sign = f[0] as u16;
    for i in 0..N - 1 {
        r[i] = mod3_u8((sign * v[N - 2 - i]) as u8) as u16;
    }
    r[N - 1] = 0;
}

/// Hensel-lift an inverse of `a` from $R_2$ to $R_q = \mathbb{Z}_q[x] / (x^N - 1)$.
///
/// Newton-style 2-adic lift: given $a \cdot b \equiv 1 \pmod{2^k}$,
/// the update $b \leftarrow b \cdot (2 - a \cdot b)$ doubles the precision
/// to $\pmod{2^{2k}}$. Four iterations carry the precision from $2^1$ to
/// $2^{16}$, which subsumes every $q$ in this NTRU family ($q \le 2^{13}$).
/// All arithmetic is `u16` wrapping; the caller reduces modulo $q$ at use.
pub(crate) fn poly_r2_inv_to_rq_inv<const N: usize>(
    r: &mut [u16; N],
    ai: &[u16; N],
    a: &[u16; N],
) {
    let mut b = [0u16; N];
    for i in 0..N {
        b[i] = 0u16.wrapping_sub(a[i]);
    }
    r.copy_from_slice(ai);

    let mut c = [0u16; N];
    let mut s = [0u16; N];

    use crate::public_key::ntru_poly_mul::poly_mul_cyclic as mul;

    mul(&mut c, r, &b);
    c[0] = c[0].wrapping_add(2);
    mul(&mut s, &c, r);

    mul(&mut c, &s, &b);
    c[0] = c[0].wrapping_add(2);
    mul(r, &c, &s);

    mul(&mut c, r, &b);
    c[0] = c[0].wrapping_add(2);
    mul(&mut s, &c, r);

    mul(&mut c, &s, &b);
    c[0] = c[0].wrapping_add(2);
    mul(r, &c, &s);
}

// ---- per-set wrapper macro --------------------------------------------------
//
// Each NIST PQC NTRU set ships a typed wrapper around the shared
// `kem_keypair_seeded` / `kem_enc_seeded` / `kem_dec` routines and a fixed
// set of byte-length constants (`PUBLIC_KEY_BYTES`, `PRIVATE_KEY_BYTES`,
// `CIPHERTEXT_BYTES`, `SHARED_SECRET_BYTES`). The wrapper, the
// newtype quartet, the `Debug` impls, the `from_wire_bytes` /
// `to_wire_bytes` / `as_bytes` methods, and the standard generic test
// scaffolding (round-trip, implicit rejection, wire-format round-trip,
// sampled NIST KAT, full NIST KAT) are mechanical — this macro emits
// them so each NIST module is just the algebra plus the parameter
// constants.
//
// Caller-scope identifiers the expansion captures (these must exist
// in the calling module's namespace):
//   - `N` (`const usize`): ring degree for this parameter set.
//   - `LOGQ` (`const usize`): $\log_2 q$ for this parameter set.
//   - `PUBLIC_KEY_BYTES`, `PRIVATE_KEY_BYTES`, `CIPHERTEXT_BYTES`,
//     `SHARED_SECRET_BYTES` (`const usize`): wire-format byte sizes
//     used as `[u8; …]` element counts in the newtype storage.
//   - `SAMPLE_FG_BYTES`, `SAMPLE_RM_BYTES`, `OWCPA_MSGBYTES`
//     (`const usize`): scratch-buffer sizes the macro stack-allocates
//     and threads into the shared kem_*_seeded / kem_dec routines.
// Every NIST PQC per-set file in this crate defines these; a future
// module that uses different naming will hit a confusing macro-side
// resolution error, so this list is the contract.

macro_rules! define_pqc_kem {
    (
        namespace = $type_name:ident,
        public_key = $pk_ty:ident,
        private_key = $sk_ty:ident,
        ciphertext = $ct_ty:ident,
        shared_secret = $ss_ty:ident,
        variant = $variant:ident,
        kat_path = $kat_path:literal $(,)?
    ) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk_ty {
            bytes: [u8; PUBLIC_KEY_BYTES],
        }

        #[derive(Clone, Eq, PartialEq)]
        pub struct $sk_ty {
            bytes: [u8; PRIVATE_KEY_BYTES],
        }

        #[derive(Clone, Eq, PartialEq)]
        pub struct $ct_ty {
            bytes: [u8; CIPHERTEXT_BYTES],
        }

        #[derive(Clone, Eq, PartialEq)]
        pub struct $ss_ty {
            bytes: [u8; SHARED_SECRET_BYTES],
        }

        impl $pk_ty {
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PUBLIC_KEY_BYTES { return None; }
                let mut out = [0u8; PUBLIC_KEY_BYTES];
                out.copy_from_slice(bytes);
                Some(Self { bytes: out })
            }

            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] { self.bytes }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] { &self.bytes }
        }

        impl $sk_ty {
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PRIVATE_KEY_BYTES { return None; }
                let mut out = [0u8; PRIVATE_KEY_BYTES];
                out.copy_from_slice(bytes);
                Some(Self { bytes: out })
            }

            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; PRIVATE_KEY_BYTES] { self.bytes }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_BYTES] { &self.bytes }
        }

        impl $ct_ty {
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != CIPHERTEXT_BYTES { return None; }
                let mut out = [0u8; CIPHERTEXT_BYTES];
                out.copy_from_slice(bytes);
                Some(Self { bytes: out })
            }

            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; CIPHERTEXT_BYTES] { self.bytes }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] { &self.bytes }
        }

        impl $ss_ty {
            #[must_use]
            pub fn to_wire_bytes(&self) -> [u8; SHARED_SECRET_BYTES] { self.bytes }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] { &self.bytes }
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

        pub struct $type_name;

        impl $type_name {
            /// Wire-format public-key length in bytes for this set.
            pub const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
            /// Wire-format private-key length in bytes for this set
            /// (includes the implicit-rejection PRF key tail).
            pub const PRIVATE_KEY_BYTES: usize = PRIVATE_KEY_BYTES;
            /// Wire-format ciphertext length in bytes for this set.
            pub const CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;
            /// Shared-secret length in bytes (always 32 for the
            /// round-3 NTRU sets).
            pub const SHARED_SECRET_BYTES: usize = SHARED_SECRET_BYTES;

            pub fn keygen<R: $crate::Csprng>(rng: &mut R) -> ($pk_ty, $sk_ty) {
                let mut pk = [0u8; PUBLIC_KEY_BYTES];
                let mut sk = [0u8; PRIVATE_KEY_BYTES];
                let mut seed_scratch = [0u8; SAMPLE_FG_BYTES];
                $crate::public_key::ntru_pqc_shared::kem_keypair_seeded::<$variant, R, N, LOGQ>(
                    &mut pk,
                    &mut sk,
                    rng,
                    &mut seed_scratch,
                );
                ($pk_ty { bytes: pk }, $sk_ty { bytes: sk })
            }

            pub fn encaps<R: $crate::Csprng>(
                pk: &$pk_ty,
                rng: &mut R,
            ) -> ($ct_ty, $ss_ty) {
                let mut ct = [0u8; CIPHERTEXT_BYTES];
                let mut ss = [0u8; SHARED_SECRET_BYTES];
                let mut rm_seed_scratch = [0u8; SAMPLE_RM_BYTES];
                let mut rm_scratch = [0u8; OWCPA_MSGBYTES];
                $crate::public_key::ntru_pqc_shared::kem_enc_seeded::<$variant, R, N, LOGQ>(
                    &mut ct,
                    &mut ss,
                    &pk.bytes,
                    rng,
                    &mut rm_seed_scratch,
                    &mut rm_scratch,
                );
                ($ct_ty { bytes: ct }, $ss_ty { bytes: ss })
            }

            pub fn decaps(sk: &$sk_ty, ct: &$ct_ty) -> $ss_ty {
                let mut ss = [0u8; SHARED_SECRET_BYTES];
                let mut rm_scratch = [0u8; OWCPA_MSGBYTES];
                $crate::public_key::ntru_pqc_shared::kem_dec::<$variant, N, LOGQ>(
                    &mut ss,
                    &ct.bytes,
                    &sk.bytes,
                    &mut rm_scratch,
                );
                $ss_ty { bytes: ss }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
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
                    assert_eq!(
                        ss_a.as_bytes(),
                        ss_b.as_bytes(),
                        "seed byte 0x{seed:02x}"
                    );
                }
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

            /// Sampled NIST round-3 KAT validation for this parameter set.
            /// See [`nist_kat_full`] for the full 100-vector sweep.
            #[test]
            fn nist_kat_sampled_counts() {
                let rsp = include_str!($kat_path);
                for &count in $crate::public_key::ntru_pqc_shared::KAT_SAMPLED_COUNTS {
                    run_kat_count(rsp, count);
                }
            }

            /// Heavy variant — validates all 100 entries of the .rsp file.
            #[test]
            #[ignore]
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
                assert_eq!(pk.to_wire_bytes().as_slice(), entry.pk.as_slice(), "pk @ count={count}");
                assert_eq!(sk.to_wire_bytes().as_slice(), entry.sk.as_slice(), "sk @ count={count}");

                let (ct, ss) = $type_name::encaps(&pk, &mut drbg);
                assert_eq!(ct.to_wire_bytes().as_slice(), entry.ct.as_slice(), "ct @ count={count}");
                assert_eq!(ss.to_wire_bytes().as_slice(), entry.ss.as_slice(), "ss @ count={count}");

                let ss2 = $type_name::decaps(&sk, &ct);
                assert_eq!(ss.as_bytes(), ss2.as_bytes(), "decaps @ count={count}");
            }
        }
    };
}

pub(crate) use define_pqc_kem;

// ---- shared polynomial helpers (N- and LOGQ-parameterised) -----------------

/// $\Phi_n$-projection of a polynomial coefficient vector treated mod 3.
/// Subtracts the constant term from every coefficient (with the standard
/// "$2 \cdot \text{last}$" identity for mod-3 arithmetic), then reduces.
pub(crate) fn poly_mod_3_phi_n<const N: usize>(r: &mut [u16; N]) {
    let last = r[N - 1];
    for c in r.iter_mut() {
        *c = mod3(*c + 2 * last);
    }
}

/// $\Phi_n$-projection of a polynomial coefficient vector mod $q$. The
/// caller is responsible for masking with `Q_MASK` afterwards if it wants
/// canonical values; the multiplications elsewhere already do so.
pub(crate) fn poly_mod_q_phi_n<const N: usize>(r: &mut [u16; N]) {
    let last = r[N - 1];
    for c in r.iter_mut() {
        *c = c.wrapping_sub(last);
    }
}

/// Embed coefficients in $\{0, 1, 2\}$ into $\mathbb{Z}_q$ as
/// $\{0, 1, q - 1\}$.
pub(crate) fn poly_z3_to_zq<const N: usize>(r: &mut [u16; N], q_mask: u16) {
    for c in r.iter_mut() {
        *c |= (0u16.wrapping_sub(*c >> 1)) & q_mask;
    }
}

/// Project $\mathbb{Z}_q$ coefficients in $\{0, 1, q - 1\}$ back to
/// $\{0, 1, 2\}$.
pub(crate) fn poly_trinary_zq_to_z3<const N: usize, const LOGQ: usize>(r: &mut [u16; N]) {
    let q_mask = ((1u32 << LOGQ) - 1) as u16;
    for c in r.iter_mut() {
        *c = *c & q_mask;
        *c = 3 & (*c ^ (*c >> (LOGQ - 1)));
    }
}

/// Project an arbitrary $R_q$ coefficient vector onto $S_3$ (mod 3,
/// mod $\Phi_n$).
pub(crate) fn poly_rq_to_s3<const N: usize, const LOGQ: usize>(
    r: &mut [u16; N],
    a: &[u16; N],
) {
    let q_mask = ((1u32 << LOGQ) - 1) as u16;
    for i in 0..N {
        let mut c = a[i] & q_mask;
        let flag = c >> (LOGQ - 1);
        c = c.wrapping_add(flag << (1 - (LOGQ & 1)));
        r[i] = c;
    }
    poly_mod_3_phi_n::<N>(r);
}

/// Inverse in $R_q = \mathbb{Z}_q[x] / (x^N - 1)$: F_2 inverse via
/// Bernstein–Yang, then Hensel-lift to mod $q$.
pub(crate) fn poly_rq_inv<const N: usize>(r: &mut [u16; N], a: &[u16; N]) {
    let mut ai2 = [0u16; N];
    poly_r2_inv(&mut ai2, a);
    poly_r2_inv_to_rq_inv(r, &ai2, a);
}

// ---- per-set NTRU variant trait + shared OWCPA core ------------------------
//
// The HPS-509 / HPS-677 / HPS-821 / HRSS-701 modules differ in five
// variant-specific behaviours plus an Sq packer that depends on `LOGQ`:
//
// - the joint $f, g$ sampler (HPS uses iid + fixed-weight; HRSS uses
//   `Sample_iid_plus` for both)
// - the joint $r, m$ sampler (HPS uses iid + fixed-weight; HRSS uses
//   iid for both)
// - the keygen $g$-update step ($g \gets 3g$ for HPS, $g \gets 3(x-1)g$
//   for HRSS)
// - the lift function (trivial $\mathbb{Z}_3 \to \mathbb{Z}_q$ embedding for
//   HPS, $(x-1)$-factor lift for HRSS)
// - the message-space check (weight + balance for HPS; HRSS accepts any
//   $S_3$ element)
// - the `Sq` packer / unpacker (11-bit, 12-bit, 13-bit)
//
// Everything else (Bernstein–Yang inversion, Hensel lift, Sq/S3
// arithmetic, IGF/MGF-style sampling helpers, OWCPA validity checks,
// the FO transform on top of OWCPA) is identical. The `NtruVariant`
// trait names just the variant-specific bits, and the
// [`owcpa_keypair`] / [`owcpa_enc`] / [`owcpa_dec`] free functions
// in this module implement OWCPA on top of it.

/// Per-set NTRU variant: HPS-509 / HPS-677 / HPS-821 / HRSS-701 each
/// implement this trait. The `N` and `LOGQ` const generics carry the
/// ring-degree and log-modulus into associated-constant expressions
/// without `generic_const_exprs`.
///
/// The trait carries the HPS sampler / lift / message-check defaults so
/// HPS-flavoured impls only need to set the parameter consts and the
/// LOGQ-specific Sq packer; HRSS-701 overrides the variant-specific
/// methods.
pub(crate) trait NtruVariant<const N: usize, const LOGQ: usize> {
    const Q_MASK: u16;
    const SAMPLE_FG_BYTES: usize;
    const SAMPLE_RM_BYTES: usize;
    const PACK_TRINARY_BYTES: usize;
    const OWCPA_PUBLICKEYBYTES: usize;
    const OWCPA_SECRETKEYBYTES: usize;
    const OWCPA_BYTES: usize;
    const OWCPA_MSGBYTES: usize;

    /// HPS-only fixed sampling weight. HRSS-701 must set this to 0
    /// explicitly — the trait deliberately declines to provide a
    /// default so that a future variant which forgets to set
    /// `WEIGHT` cannot silently feed 0 into [`owcpa_check_m`] and
    /// accept every message.
    const WEIGHT: usize;

    /// HPS default: $f$ via `sample_iid`, $g$ via `sample_fixed_type`
    /// with `WEIGHT`. HRSS overrides to use `sample_iid_plus` for both.
    fn sample_fg(f: &mut [u16; N], g: &mut [u16; N], seed: &[u8]) {
        debug_assert_eq!(seed.len(), Self::SAMPLE_FG_BYTES);
        let iid_bytes = N - 1;
        sample_iid::<N>(f, &seed[..iid_bytes]);
        let mut scratch = [0i32; N];
        sample_fixed_type::<N>(g, &seed[iid_bytes..], Self::WEIGHT, &mut scratch);
    }

    /// HPS default: $r$ via `sample_iid`, $m$ via `sample_fixed_type`
    /// with `WEIGHT`. HRSS overrides to use `sample_iid` for both.
    fn sample_rm(r: &mut [u16; N], m: &mut [u16; N], seed: &[u8]) {
        debug_assert_eq!(seed.len(), Self::SAMPLE_RM_BYTES);
        let iid_bytes = N - 1;
        sample_iid::<N>(r, &seed[..iid_bytes]);
        let mut scratch = [0i32; N];
        sample_fixed_type::<N>(m, &seed[iid_bytes..], Self::WEIGHT, &mut scratch);
    }

    /// HPS default: $g \gets 3 g$. HRSS overrides to
    /// $g \gets 3 (x - 1) g$.
    fn update_g_after_z3_to_zq(g: &mut [u16; N]) {
        for gi in g.iter_mut() {
            *gi = gi.wrapping_mul(3);
        }
    }

    /// HPS default: trivial $\{0, 1, 2\} \to \{0, 1, q - 1\}$ embedding.
    /// HRSS overrides with the $(x - 1)$-factor lift.
    fn poly_lift(r: &mut [u16; N], a: &[u16; N]) {
        poly_lift_hps::<N>(r, a, Self::Q_MASK);
    }

    /// HPS default: weight + balance check against `WEIGHT`. HRSS
    /// overrides to return 0 (any $S_3$ element is a valid message).
    fn check_m(m: &[u16; N]) -> i32 {
        owcpa_check_m::<N>(m, Self::WEIGHT)
    }

    fn poly_sq_tobytes(r: &mut [u8], a: &[u16; N]);
    fn poly_sq_frombytes(r: &mut [u16; N], a: &[u8]);
}

/// OWCPA key pair generation. Writes the canonical public-key wire
/// bytes to `pk` and the canonical OWCPA secret-key bytes (without the
/// FO implicit-rejection PRF tail) to `sk`. Uses `seed` for the joint
/// $(f, g)$ sample.
pub(crate) fn owcpa_keypair<V, const N: usize, const LOGQ: usize>(
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &[u8],
) where
    V: NtruVariant<N, LOGQ>,
{
    debug_assert_eq!(pk.len(), V::OWCPA_PUBLICKEYBYTES);
    debug_assert_eq!(sk.len(), V::OWCPA_SECRETKEYBYTES);
    debug_assert_eq!(seed.len(), V::SAMPLE_FG_BYTES);

    let mut f = [0u16; N];
    let mut g = [0u16; N];
    V::sample_fg(&mut f, &mut g, seed);

    let mut invf_mod3 = [0u16; N];
    poly_s3_inv::<N>(&mut invf_mod3, &f);
    poly_s3_tobytes::<N>(&mut sk[..V::PACK_TRINARY_BYTES], &f);
    poly_s3_tobytes::<N>(
        &mut sk[V::PACK_TRINARY_BYTES..2 * V::PACK_TRINARY_BYTES],
        &invf_mod3,
    );

    poly_z3_to_zq::<N>(&mut f, V::Q_MASK);
    poly_z3_to_zq::<N>(&mut g, V::Q_MASK);
    V::update_g_after_z3_to_zq(&mut g);

    let mut gf = [0u16; N];
    poly_rq_mul::<N>(&mut gf, &g, &f);

    let mut invgf = [0u16; N];
    poly_rq_inv::<N>(&mut invgf, &gf);

    let mut tmp = [0u16; N];
    let mut invh = [0u16; N];
    poly_rq_mul::<N>(&mut tmp, &invgf, &f);
    poly_sq_mul::<N>(&mut invh, &tmp, &f);
    V::poly_sq_tobytes(&mut sk[2 * V::PACK_TRINARY_BYTES..], &invh);

    let mut h = [0u16; N];
    poly_rq_mul::<N>(&mut tmp, &invgf, &g);
    poly_rq_mul::<N>(&mut h, &tmp, &g);
    V::poly_sq_tobytes(pk, &h);
}

/// OWCPA encryption. Computes $c = r \cdot h + \text{lift}(m)$ in
/// $R_q$, packed via the variant's Sq packer.
pub(crate) fn owcpa_enc<V, const N: usize, const LOGQ: usize>(
    c: &mut [u8],
    r: &[u16; N],
    m: &[u16; N],
    pk: &[u8],
) where
    V: NtruVariant<N, LOGQ>,
{
    debug_assert_eq!(c.len(), V::OWCPA_BYTES);
    debug_assert_eq!(pk.len(), V::OWCPA_PUBLICKEYBYTES);

    let mut h = [0u16; N];
    V::poly_sq_frombytes(&mut h, pk);
    poly_rq_sum_zero_adjust::<N>(&mut h);

    let mut ct = [0u16; N];
    poly_rq_mul::<N>(&mut ct, r, &h);

    let mut liftm = [0u16; N];
    V::poly_lift(&mut liftm, m);
    for i in 0..N {
        ct[i] = ct[i].wrapping_add(liftm[i]);
    }

    V::poly_sq_tobytes(c, &ct);
}

/// OWCPA decryption. Recovers $(r, m)$ from `ciphertext` under the
/// trapdoor encoded in `secretkey`, packs them into `rm`, and returns
/// 0 on success and 1 on any consistency failure (invalid ciphertext
/// padding, $m$ outside the valid set, or recovered $r$ outside
/// $\{0, 1, q - 1\}$).
pub(crate) fn owcpa_dec<V, const N: usize, const LOGQ: usize>(
    rm: &mut [u8],
    ciphertext: &[u8],
    secretkey: &[u8],
) -> i32
where
    V: NtruVariant<N, LOGQ>,
{
    debug_assert_eq!(rm.len(), V::OWCPA_MSGBYTES);
    debug_assert_eq!(ciphertext.len(), V::OWCPA_BYTES);
    debug_assert_eq!(secretkey.len(), V::OWCPA_SECRETKEYBYTES);

    let mut c = [0u16; N];
    V::poly_sq_frombytes(&mut c, ciphertext);
    poly_rq_sum_zero_adjust::<N>(&mut c);

    let mut f = [0u16; N];
    poly_s3_frombytes::<N>(&mut f, &secretkey[..V::PACK_TRINARY_BYTES]);
    poly_z3_to_zq::<N>(&mut f, V::Q_MASK);

    let mut cf = [0u16; N];
    poly_rq_mul::<N>(&mut cf, &c, &f);

    let mut mf = [0u16; N];
    poly_rq_to_s3::<N, LOGQ>(&mut mf, &cf);

    let mut finv3 = [0u16; N];
    poly_s3_frombytes::<N>(
        &mut finv3,
        &secretkey[V::PACK_TRINARY_BYTES..2 * V::PACK_TRINARY_BYTES],
    );

    let mut m = [0u16; N];
    poly_s3_mul::<N>(&mut m, &mf, &finv3);
    poly_s3_tobytes::<N>(&mut rm[V::PACK_TRINARY_BYTES..], &m);

    let mut fail = 0i32;
    fail |= owcpa_check_ciphertext::<N, LOGQ>(ciphertext);
    fail |= V::check_m(&m);

    let mut liftm = [0u16; N];
    V::poly_lift(&mut liftm, &m);
    let mut b = [0u16; N];
    for i in 0..N {
        b[i] = c[i].wrapping_sub(liftm[i]);
    }

    let mut invh = [0u16; N];
    V::poly_sq_frombytes(&mut invh, &secretkey[2 * V::PACK_TRINARY_BYTES..]);
    let mut r = [0u16; N];
    poly_sq_mul::<N>(&mut r, &b, &invh);

    fail |= owcpa_check_r::<N, LOGQ>(&r);

    poly_trinary_zq_to_z3::<N, LOGQ>(&mut r);
    poly_s3_tobytes::<N>(&mut rm[..V::PACK_TRINARY_BYTES], &r);

    fail
}

// ---- OWCPA validity checks -------------------------------------------------

/// Check that the high padding bits of a ciphertext's last byte are zero
/// (a wire-format malleability check). Returns 0 on success, 1 on any
/// non-zero padding bit.
///
/// `bits_used` (= `(LOGQ * (N - 1)) mod 8`) is the number of valid
/// low-order bits in the final byte; the high `8 - bits_used` bits are
/// padding and must be zero. Mask `0xff << bits_used` selects exactly
/// those high padding bits.
pub(crate) fn owcpa_check_ciphertext<const N: usize, const LOGQ: usize>(
    ciphertext: &[u8],
) -> i32 {
    let pack_deg = N - 1;
    let bits_used = (LOGQ * pack_deg) & 7;
    let mask: u8 = if bits_used == 0 { 0 } else { 0xffu8 << bits_used };
    let last = *ciphertext.last().expect("non-empty ciphertext");
    let t = (last & mask) as u16;
    (1 & ((!t).wrapping_add(1) >> 15)) as i32
}

/// Check that a recovered $r \in R_q$ is in the trinary set $\{0, 1, q-1\}$
/// with `r[N - 1] == 0`. Returns 0 on success, 1 on any out-of-range
/// coefficient.
pub(crate) fn owcpa_check_r<const N: usize, const LOGQ: usize>(r: &[u16; N]) -> i32 {
    let q16: u16 = if LOGQ < 16 { 1u16 << LOGQ } else { 0 };
    let mut t: u32 = 0;
    for i in 0..N - 1 {
        let c = r[i];
        t |= ((c.wrapping_add(1)) & q16.wrapping_sub(4)) as u32;
        t |= (c.wrapping_add(2) & 4) as u32;
    }
    t |= r[N - 1] as u32;
    (1 & ((!t).wrapping_add(1) >> 31)) as i32
}

/// Check that `m` is in $S_3$ with the given target weight, balanced
/// $+1$ / $-1$ counts. Returns 0 on success, 1 on weight or balance
/// mismatch. HPS-only — HRSS-701 accepts any $S_3$ message.
pub(crate) fn owcpa_check_m<const N: usize>(m: &[u16; N], weight: usize) -> i32 {
    let mut ps: u16 = 0;
    let mut ms: u16 = 0;
    for i in 0..N {
        ps = ps.wrapping_add(m[i] & 1);
        ms = ms.wrapping_add(m[i] & 2);
    }
    let mut t: u32 = 0;
    t |= (ps ^ (ms >> 1)) as u32;
    t |= (ms ^ (weight as u16)) as u32;
    (1 & ((!t).wrapping_add(1) >> 31)) as i32
}

/// Restore the high coefficient of an $R_q$ polynomial whose $N - 1$
/// low coefficients were just unpacked from an `Sq` byte stream, so the
/// total coefficient sum is zero modulo $q$. The unpacker leaves
/// `r[N - 1] == 0`; this routine sets it to the negated sum of the
/// others.
pub(crate) fn poly_rq_sum_zero_adjust<const N: usize>(r: &mut [u16; N]) {
    r[N - 1] = 0;
    let mut acc: u16 = 0;
    for i in 0..(N - 1) {
        acc = acc.wrapping_sub(r[i]);
    }
    r[N - 1] = acc;
}

// ---- KEM key generation + encapsulation (FO-style transform) --------------

/// CCA KEM key generation: draw an OWCPA seed plus the implicit-rejection
/// PRF key from `rng`, run [`owcpa_keypair`], and pack everything into the
/// caller's wire-format buffers.
///
/// `seed_scratch` must be `V::SAMPLE_FG_BYTES` bytes long; the macro that
/// invokes this function declares it as a stack array of the per-set
/// size so no heap allocation appears on the keygen hot path.
pub(crate) fn kem_keypair_seeded<V, R, const N: usize, const LOGQ: usize>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    seed_scratch: &mut [u8],
) where
    V: NtruVariant<N, LOGQ>,
    R: crate::Csprng,
{
    debug_assert_eq!(seed_scratch.len(), V::SAMPLE_FG_BYTES);
    rng.fill_bytes(seed_scratch);
    owcpa_keypair::<V, N, LOGQ>(pk, &mut sk[..V::OWCPA_SECRETKEYBYTES], seed_scratch);
    rng.fill_bytes(&mut sk[V::OWCPA_SECRETKEYBYTES..]);
}

/// CCA KEM encapsulation: draw fresh randomness for $(r, m)$, hash the
/// resulting message into the shared secret, then OWCPA-encrypt against
/// `pk`.
///
/// `rm_seed_scratch` must be `V::SAMPLE_RM_BYTES` long and `rm_scratch`
/// must be `V::OWCPA_MSGBYTES` long; the macro stack-allocates both.
pub(crate) fn kem_enc_seeded<V, R, const N: usize, const LOGQ: usize>(
    c: &mut [u8],
    k: &mut [u8],
    pk: &[u8],
    rng: &mut R,
    rm_seed_scratch: &mut [u8],
    rm_scratch: &mut [u8],
) where
    V: NtruVariant<N, LOGQ>,
    R: crate::Csprng,
{
    use crate::hash::sha3::Sha3_256;
    debug_assert_eq!(k.len(), 32);
    debug_assert_eq!(rm_seed_scratch.len(), V::SAMPLE_RM_BYTES);
    debug_assert_eq!(rm_scratch.len(), V::OWCPA_MSGBYTES);

    rng.fill_bytes(rm_seed_scratch);

    let mut r = [0u16; N];
    let mut m = [0u16; N];
    V::sample_rm(&mut r, &mut m, rm_seed_scratch);

    poly_s3_tobytes::<N>(&mut rm_scratch[..V::PACK_TRINARY_BYTES], &r);
    poly_s3_tobytes::<N>(&mut rm_scratch[V::PACK_TRINARY_BYTES..], &m);

    let digest = Sha3_256::new().chain(rm_scratch).finalize();
    k.copy_from_slice(&digest);

    poly_z3_to_zq::<N>(&mut r, V::Q_MASK);
    owcpa_enc::<V, N, LOGQ>(c, &r, &m, pk);
}

// ---- KEM decapsulation (FO-style transform) --------------------------------

/// CCA KEM decapsulation: run [`owcpa_dec`], hash $r \| m$ for the
/// session key, hash `prf || c` for the implicit-rejection key, and
/// `cmov` between them on the OWCPA failure flag.
///
/// `rm_scratch` must be `V::OWCPA_MSGBYTES` long; the macro
/// stack-allocates it.
pub(crate) fn kem_dec<V, const N: usize, const LOGQ: usize>(
    k: &mut [u8],
    c: &[u8],
    sk: &[u8],
    rm_scratch: &mut [u8],
) where
    V: NtruVariant<N, LOGQ>,
{
    use crate::hash::sha3::Sha3_256;
    debug_assert_eq!(k.len(), 32);
    debug_assert_eq!(rm_scratch.len(), V::OWCPA_MSGBYTES);
    let fail = owcpa_dec::<V, N, LOGQ>(rm_scratch, c, &sk[..V::OWCPA_SECRETKEYBYTES]);

    let digest = Sha3_256::new().chain(rm_scratch).finalize();
    k.copy_from_slice(&digest);

    let reject = Sha3_256::new()
        .chain(&sk[V::OWCPA_SECRETKEYBYTES..])
        .chain(c)
        .finalize();
    cmov(k, &reject, fail as u8);
}

// ---- IID and fixed-weight samplers -----------------------------------------

/// $\text{Sample\_iid}$ from round-3 NTRU, §3.3.1: each output coefficient
/// is the input byte reduced modulo 3. Output buffer is $N - 1$
/// coefficients (the high coefficient is set to 0); input length must be
/// $N - 1$ bytes.
pub(crate) fn sample_iid<const N: usize>(r: &mut [u16; N], uniform_bytes: &[u8]) {
    debug_assert_eq!(uniform_bytes.len(), N - 1);
    for i in 0..N - 1 {
        r[i] = mod3(uniform_bytes[i] as u16);
    }
    r[N - 1] = 0;
}

/// $\text{Sample\_fixed\_type}$ from round-3 NTRU, §3.3.4: pack 30
/// random bits per word from `u` (4 words per 15 bytes), tag the bottom
/// two bits with the intended trinary value (half $+1$ as `01`, half
/// $-1$ as `10`, rest $0$), sort using the constant-time bitonic
/// network, and read off the bottom-two-bit tag of each sorted slot.
/// Used by HPS keygen for `g` and by HPS encryption for `r`.
pub(crate) fn sample_fixed_type<const N: usize>(
    r: &mut [u16; N],
    u: &[u8],
    weight: usize,
    scratch: &mut [i32; N],
) {
    debug_assert_eq!(u.len(), (30 * (N - 1) + 7) / 8);
    // All NIST round-3 parameter sets have $(N - 1) \equiv 0 \pmod 4$
    // (508, 676, 820), so the input always lands on a block boundary
    // and there is no tail to handle. The assertion below documents the
    // assumption — flip it to a tail branch if a future parameter set
    // breaks the alignment.
    debug_assert_eq!((N - 1) % 4, 0, "sample_fixed_type assumes (N - 1) % 4 == 0");

    // Use the first N - 1 slots of the caller's scratch buffer. Slot
    // `N - 1` exists only because stable Rust can't size an inline
    // array as `[i32; N - 1]` without `generic_const_exprs`.
    let s = &mut scratch[..N - 1];
    for slot in s.iter_mut() {
        *slot = 0;
    }

    let blocks = (N - 1) / 4;
    for i in 0..blocks {
        let base = 15 * i;
        s[4 * i] = ((u[base] as i32) << 2)
            | ((u[base + 1] as i32) << 10)
            | ((u[base + 2] as i32) << 18)
            | ((u[base + 3] as u32 as i32) << 26);
        s[4 * i + 1] = (((u[base + 3] as i32) & 0xc0) >> 4)
            | ((u[base + 4] as i32) << 4)
            | ((u[base + 5] as i32) << 12)
            | ((u[base + 6] as i32) << 20)
            | ((u[base + 7] as u32 as i32) << 28);
        s[4 * i + 2] = (((u[base + 7] as i32) & 0xf0) >> 2)
            | ((u[base + 8] as i32) << 6)
            | ((u[base + 9] as i32) << 14)
            | ((u[base + 10] as i32) << 22)
            | ((u[base + 11] as u32 as i32) << 30);
        s[4 * i + 3] = ((u[base + 11] as i32) & 0xfc)
            | ((u[base + 12] as i32) << 8)
            | ((u[base + 13] as i32) << 16)
            | ((u[base + 14] as u32 as i32) << 24);
    }

    for i in 0..weight / 2 {
        s[i] |= 1;
    }
    for i in weight / 2..weight {
        s[i] |= 2;
    }

    crypto_sort_int32(s);

    for i in 0..N - 1 {
        r[i] = (s[i] & 3) as u16;
    }
    r[N - 1] = 0;
}

// ---- ring multiplication wrappers ------------------------------------------

/// Cyclic multiplication in $R = \mathbb{Z}[x] / (x^N - 1)$ over `u16`
/// wrapping arithmetic. Thin alias for the shared
/// [`crate::public_key::ntru_poly_mul::poly_mul_cyclic`] entry point.
pub(crate) fn poly_rq_mul<const N: usize>(
    r: &mut [u16; N],
    a: &[u16; N],
    b: &[u16; N],
) {
    crate::public_key::ntru_poly_mul::poly_mul_cyclic(r, a, b);
}

/// $R_q$ multiplication followed by mod-$\Phi_n$ projection.
pub(crate) fn poly_sq_mul<const N: usize>(
    r: &mut [u16; N],
    a: &[u16; N],
    b: &[u16; N],
) {
    poly_rq_mul::<N>(r, a, b);
    poly_mod_q_phi_n::<N>(r);
}

/// $R$ multiplication followed by mod-3, mod-$\Phi_n$ projection.
pub(crate) fn poly_s3_mul<const N: usize>(
    r: &mut [u16; N],
    a: &[u16; N],
    b: &[u16; N],
) {
    poly_rq_mul::<N>(r, a, b);
    poly_mod_3_phi_n::<N>(r);
}

// ---- HPS lift: trivial Z_3 -> Z_q embedding --------------------------------

/// HPS lift: copy `a`'s coefficients into `r` and remap $\{0, 1, 2\}$
/// onto $\{0, 1, q - 1\}$. The HRSS variant (with the `(x - 1)` factor)
/// is in `ntru_hrss701` because it has no other call site.
pub(crate) fn poly_lift_hps<const N: usize>(r: &mut [u16; N], a: &[u16; N], q_mask: u16) {
    *r = *a;
    poly_z3_to_zq::<N>(r, q_mask);
}

// ---- S_q packing for q = 2^11 (HPS509, HPS677) -----------------------------

/// Pack `a`'s 11-bit coefficients into bytes: 8 coefficients per 11-byte
/// block. Output buffer must be `((N - 1) * 11 + 7) / 8` bytes.
pub(crate) fn poly_sq_tobytes_logq11<const N: usize>(r: &mut [u8], a: &[u16; N]) {
    const Q_MASK_11: u16 = (1u16 << 11) - 1;
    let pack_deg = N - 1;
    debug_assert_eq!(r.len(), (pack_deg * 11 + 7) / 8);
    let mut t = [0u16; 8];
    let full = pack_deg / 8;
    for i in 0..full {
        for j in 0..8 {
            t[j] = a[8 * i + j] & Q_MASK_11;
        }
        r[11 * i] = (t[0] & 0xff) as u8;
        r[11 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x1f) << 3)) as u8;
        r[11 * i + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6)) as u8;
        r[11 * i + 3] = ((t[2] >> 2) & 0xff) as u8;
        r[11 * i + 4] = ((t[2] >> 10) | ((t[3] & 0x7f) << 1)) as u8;
        r[11 * i + 5] = ((t[3] >> 7) | ((t[4] & 0x0f) << 4)) as u8;
        r[11 * i + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7)) as u8;
        r[11 * i + 7] = ((t[5] >> 1) & 0xff) as u8;
        r[11 * i + 8] = ((t[5] >> 9) | ((t[6] & 0x3f) << 2)) as u8;
        r[11 * i + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5)) as u8;
        r[11 * i + 10] = (t[7] >> 3) as u8;
    }
    let i = full;
    let tail = pack_deg - 8 * i;
    for j in 0..tail {
        t[j] = a[8 * i + j] & Q_MASK_11;
    }
    for j in tail..8 {
        t[j] = 0;
    }
    match pack_deg & 0x07 {
        4 => {
            r[11 * i] = (t[0] & 0xff) as u8;
            r[11 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x1f) << 3)) as u8;
            r[11 * i + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6)) as u8;
            r[11 * i + 3] = ((t[2] >> 2) & 0xff) as u8;
            r[11 * i + 4] = ((t[2] >> 10) | ((t[3] & 0x7f) << 1)) as u8;
            r[11 * i + 5] = ((t[3] >> 7) | ((t[4] & 0x0f) << 4)) as u8;
        }
        2 => {
            r[11 * i] = (t[0] & 0xff) as u8;
            r[11 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x1f) << 3)) as u8;
            r[11 * i + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6)) as u8;
        }
        0 => {}
        _ => unreachable!(),
    }
}

/// Inverse of [`poly_sq_tobytes_logq11`].
pub(crate) fn poly_sq_frombytes_logq11<const N: usize>(r: &mut [u16; N], a: &[u8]) {
    let pack_deg = N - 1;
    debug_assert!(a.len() >= (pack_deg * 11 + 7) / 8);
    let full = pack_deg / 8;
    for i in 0..full {
        r[8 * i] = ((a[11 * i] as u16) >> 0) | (((a[11 * i + 1] as u16) & 0x07) << 8);
        r[8 * i + 1] =
            ((a[11 * i + 1] as u16) >> 3) | (((a[11 * i + 2] as u16) & 0x3f) << 5);
        r[8 * i + 2] = ((a[11 * i + 2] as u16) >> 6)
            | (((a[11 * i + 3] as u16) & 0xff) << 2)
            | (((a[11 * i + 4] as u16) & 0x01) << 10);
        r[8 * i + 3] =
            ((a[11 * i + 4] as u16) >> 1) | (((a[11 * i + 5] as u16) & 0x0f) << 7);
        r[8 * i + 4] =
            ((a[11 * i + 5] as u16) >> 4) | (((a[11 * i + 6] as u16) & 0x7f) << 4);
        r[8 * i + 5] = ((a[11 * i + 6] as u16) >> 7)
            | (((a[11 * i + 7] as u16) & 0xff) << 1)
            | (((a[11 * i + 8] as u16) & 0x03) << 9);
        r[8 * i + 6] =
            ((a[11 * i + 8] as u16) >> 2) | (((a[11 * i + 9] as u16) & 0x1f) << 6);
        r[8 * i + 7] =
            ((a[11 * i + 9] as u16) >> 5) | (((a[11 * i + 10] as u16) & 0xff) << 3);
    }
    let i = full;
    match pack_deg & 0x07 {
        4 => {
            r[8 * i] = ((a[11 * i] as u16) >> 0) | (((a[11 * i + 1] as u16) & 0x07) << 8);
            r[8 * i + 1] =
                ((a[11 * i + 1] as u16) >> 3) | (((a[11 * i + 2] as u16) & 0x3f) << 5);
            r[8 * i + 2] = ((a[11 * i + 2] as u16) >> 6)
                | (((a[11 * i + 3] as u16) & 0xff) << 2)
                | (((a[11 * i + 4] as u16) & 0x01) << 10);
            r[8 * i + 3] =
                ((a[11 * i + 4] as u16) >> 1) | (((a[11 * i + 5] as u16) & 0x0f) << 7);
        }
        2 => {
            r[8 * i] = ((a[11 * i] as u16) >> 0) | (((a[11 * i + 1] as u16) & 0x07) << 8);
            r[8 * i + 1] =
                ((a[11 * i + 1] as u16) >> 3) | (((a[11 * i + 2] as u16) & 0x3f) << 5);
        }
        0 => {}
        _ => unreachable!(),
    }
    r[N - 1] = 0;
}

// ---- S_q packing for q = 2^12 (HPS821) -------------------------------------

/// Pack `a`'s 12-bit coefficients into bytes: 2 coefficients per 3-byte
/// block. Output buffer must be `((N - 1) * 12 + 7) / 8` bytes.
pub(crate) fn poly_sq_tobytes_logq12<const N: usize>(r: &mut [u8], a: &[u16; N]) {
    const Q_MASK_12: u16 = (1u16 << 12) - 1;
    let pack_deg = N - 1;
    debug_assert_eq!(r.len(), (pack_deg * 12 + 7) / 8);
    for i in 0..pack_deg / 2 {
        let c0 = a[2 * i] & Q_MASK_12;
        let c1 = a[2 * i + 1] & Q_MASK_12;
        r[3 * i] = (c0 & 0xff) as u8;
        r[3 * i + 1] = ((c0 >> 8) | ((c1 & 0x0f) << 4)) as u8;
        r[3 * i + 2] = (c1 >> 4) as u8;
    }
}

/// Inverse of [`poly_sq_tobytes_logq12`].
pub(crate) fn poly_sq_frombytes_logq12<const N: usize>(r: &mut [u16; N], a: &[u8]) {
    let pack_deg = N - 1;
    debug_assert!(a.len() >= (pack_deg * 12 + 7) / 8);
    for i in 0..pack_deg / 2 {
        r[2 * i] = (a[3 * i] as u16) | (((a[3 * i + 1] as u16) & 0x0f) << 8);
        r[2 * i + 1] =
            ((a[3 * i + 1] as u16) >> 4) | (((a[3 * i + 2] as u16) & 0xff) << 4);
    }
    r[N - 1] = 0;
}

// ---- S_q packing for q = 2^13 (HRSS701) ------------------------------------

/// Pack `a`'s 13-bit coefficients into bytes: 8 coefficients per 13-byte
/// block. Output buffer must be `((N - 1) * 13 + 7) / 8` bytes.
pub(crate) fn poly_sq_tobytes_logq13<const N: usize>(r: &mut [u8], a: &[u16; N]) {
    const Q_MASK_13: u16 = (1u16 << 13) - 1;
    let pack_deg = N - 1;
    debug_assert_eq!(r.len(), (pack_deg * 13 + 7) / 8);
    let mut t = [0u16; 8];
    let full = pack_deg / 8;
    for i in 0..full {
        for j in 0..8 {
            t[j] = a[8 * i + j] & Q_MASK_13;
        }
        r[13 * i] = (t[0] & 0xff) as u8;
        r[13 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5)) as u8;
        r[13 * i + 2] = ((t[1] >> 3) & 0xff) as u8;
        r[13 * i + 3] = ((t[1] >> 11) | ((t[2] & 0x3f) << 2)) as u8;
        r[13 * i + 4] = ((t[2] >> 6) | ((t[3] & 0x01) << 7)) as u8;
        r[13 * i + 5] = ((t[3] >> 1) & 0xff) as u8;
        r[13 * i + 6] = ((t[3] >> 9) | ((t[4] & 0x0f) << 4)) as u8;
        r[13 * i + 7] = ((t[4] >> 4) & 0xff) as u8;
        r[13 * i + 8] = ((t[4] >> 12) | ((t[5] & 0x7f) << 1)) as u8;
        r[13 * i + 9] = ((t[5] >> 7) | ((t[6] & 0x03) << 6)) as u8;
        r[13 * i + 10] = ((t[6] >> 2) & 0xff) as u8;
        r[13 * i + 11] = ((t[6] >> 10) | ((t[7] & 0x1f) << 3)) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
    let i = full;
    let tail = pack_deg - 8 * i;
    for j in 0..tail {
        t[j] = a[8 * i + j] & Q_MASK_13;
    }
    for j in tail..8 {
        t[j] = 0;
    }
    match pack_deg & 0x07 {
        4 => {
            r[13 * i] = (t[0] & 0xff) as u8;
            r[13 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5)) as u8;
            r[13 * i + 2] = ((t[1] >> 3) & 0xff) as u8;
            r[13 * i + 3] = ((t[1] >> 11) | ((t[2] & 0x3f) << 2)) as u8;
            r[13 * i + 4] = ((t[2] >> 6) | ((t[3] & 0x01) << 7)) as u8;
            r[13 * i + 5] = ((t[3] >> 1) & 0xff) as u8;
            r[13 * i + 6] = ((t[3] >> 9) | ((t[4] & 0x0f) << 4)) as u8;
        }
        2 => {
            r[13 * i] = (t[0] & 0xff) as u8;
            r[13 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5)) as u8;
            r[13 * i + 2] = ((t[1] >> 3) & 0xff) as u8;
            r[13 * i + 3] = ((t[1] >> 11) | ((t[2] & 0x3f) << 2)) as u8;
        }
        0 => {}
        _ => unreachable!(),
    }
}

/// Inverse of [`poly_sq_tobytes_logq13`].
pub(crate) fn poly_sq_frombytes_logq13<const N: usize>(r: &mut [u16; N], a: &[u8]) {
    let pack_deg = N - 1;
    debug_assert!(a.len() >= (pack_deg * 13 + 7) / 8);
    let full = pack_deg / 8;
    for i in 0..full {
        r[8 * i] = (a[13 * i] as u16) | (((a[13 * i + 1] as u16) & 0x1f) << 8);
        r[8 * i + 1] = ((a[13 * i + 1] as u16) >> 5)
            | ((a[13 * i + 2] as u16) << 3)
            | (((a[13 * i + 3] as u16) & 0x03) << 11);
        r[8 * i + 2] =
            ((a[13 * i + 3] as u16) >> 2) | (((a[13 * i + 4] as u16) & 0x7f) << 6);
        r[8 * i + 3] = ((a[13 * i + 4] as u16) >> 7)
            | ((a[13 * i + 5] as u16) << 1)
            | (((a[13 * i + 6] as u16) & 0x0f) << 9);
        r[8 * i + 4] = ((a[13 * i + 6] as u16) >> 4)
            | ((a[13 * i + 7] as u16) << 4)
            | (((a[13 * i + 8] as u16) & 0x01) << 12);
        r[8 * i + 5] =
            ((a[13 * i + 8] as u16) >> 1) | (((a[13 * i + 9] as u16) & 0x3f) << 7);
        r[8 * i + 6] = ((a[13 * i + 9] as u16) >> 6)
            | ((a[13 * i + 10] as u16) << 2)
            | (((a[13 * i + 11] as u16) & 0x07) << 10);
        r[8 * i + 7] =
            ((a[13 * i + 11] as u16) >> 3) | ((a[13 * i + 12] as u16) << 5);
    }
    let i = full;
    match pack_deg & 0x07 {
        4 => {
            r[8 * i] = (a[13 * i] as u16) | (((a[13 * i + 1] as u16) & 0x1f) << 8);
            r[8 * i + 1] = ((a[13 * i + 1] as u16) >> 5)
                | ((a[13 * i + 2] as u16) << 3)
                | (((a[13 * i + 3] as u16) & 0x03) << 11);
            r[8 * i + 2] =
                ((a[13 * i + 3] as u16) >> 2) | (((a[13 * i + 4] as u16) & 0x7f) << 6);
            r[8 * i + 3] = ((a[13 * i + 4] as u16) >> 7)
                | ((a[13 * i + 5] as u16) << 1)
                | (((a[13 * i + 6] as u16) & 0x0f) << 9);
        }
        2 => {
            r[8 * i] = (a[13 * i] as u16) | (((a[13 * i + 1] as u16) & 0x1f) << 8);
            r[8 * i + 1] = ((a[13 * i + 1] as u16) >> 5)
                | ((a[13 * i + 2] as u16) << 3)
                | (((a[13 * i + 3] as u16) & 0x03) << 11);
        }
        0 => {}
        _ => unreachable!(),
    }
    r[N - 1] = 0;
}

// ---- S_3 packing: 5 trits per byte in base 3 -------------------------------

/// Pack `a`'s $N - 1$ trinary coefficients (in $\{0, 1, 2\}$) into bytes
/// using base-3 encoding: each output byte holds 5 trits, with the
/// least-significant trit at the bottom of the byte. The output buffer
/// length must equal `((N - 1) + 4) / 5`.
pub(crate) fn poly_s3_tobytes<const N: usize>(msg: &mut [u8], a: &[u16; N]) {
    let pack_deg = N - 1;
    debug_assert_eq!(msg.len(), (pack_deg + 4) / 5);
    let full = pack_deg / 5;
    for i in 0..full {
        let mut c = (a[5 * i + 4] & 0xff) as u8;
        c = (3u8.wrapping_mul(c)).wrapping_add(a[5 * i + 3] as u8);
        c = (3u8.wrapping_mul(c)).wrapping_add(a[5 * i + 2] as u8);
        c = (3u8.wrapping_mul(c)).wrapping_add(a[5 * i + 1] as u8);
        c = (3u8.wrapping_mul(c)).wrapping_add(a[5 * i] as u8);
        msg[i] = c;
    }
    if pack_deg > full * 5 {
        let mut c: u8 = 0;
        let start = 5 * full;
        let mut j = (pack_deg - start) as isize - 1;
        while j >= 0 {
            c = (3u8.wrapping_mul(c)).wrapping_add(a[start + j as usize] as u8);
            j -= 1;
        }
        msg[full] = c;
    }
}

/// Inverse of [`poly_s3_tobytes`]. Reduces mod 3, mod $\Phi_n$ on the way out.
pub(crate) fn poly_s3_frombytes<const N: usize>(r: &mut [u16; N], msg: &[u8]) {
    let pack_deg = N - 1;
    debug_assert_eq!(msg.len(), (pack_deg + 4) / 5);
    let full = pack_deg / 5;
    for i in 0..full {
        let c = msg[i] as u32;
        r[5 * i] = c as u16;
        r[5 * i + 1] = ((c * 171) >> 9) as u16;
        r[5 * i + 2] = ((c * 57) >> 9) as u16;
        r[5 * i + 3] = ((c * 19) >> 9) as u16;
        r[5 * i + 4] = ((c * 203) >> 14) as u16;
    }
    if pack_deg > full * 5 {
        let mut c = msg[full] as u32;
        let mut j = 0;
        while 5 * full + j < pack_deg {
            r[5 * full + j] = c as u16;
            c = (c * 171) >> 9;
            j += 1;
        }
    }
    r[N - 1] = 0;
    poly_mod_3_phi_n::<N>(r);
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
/// whitespace so the same routine handles `.rsp`-line hex fields, which
/// don't always end at a fixed column.
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
