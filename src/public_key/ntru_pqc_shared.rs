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

// ---- per-set wrapper macro --------------------------------------------------
//
// Each NIST PQC NTRU set ships a typed wrapper around its internal
// `kem_keypair_seeded` / `kem_enc_seeded` / `kem_dec` routines and a fixed
// set of byte-length constants (`PUBLIC_KEY_BYTES`, `PRIVATE_KEY_BYTES`,
// `CIPHERTEXT_BYTES`, `SHARED_SECRET_BYTES`). The wrapper, the
// newtype quartet, the `Debug` impls, the `from_wire_bytes` /
// `to_wire_bytes` / `as_bytes` methods, and the standard generic test
// scaffolding (round-trip, implicit rejection, wire-format round-trip,
// sampled NIST KAT, full NIST KAT) are mechanical — this macro emits
// them so each NIST module is just the algebra plus the parameter
// constants.

#[macro_export]
#[doc(hidden)]
macro_rules! __define_pqc_kem {
    (
        namespace = $type_name:ident,
        public_key = $pk_ty:ident,
        private_key = $sk_ty:ident,
        ciphertext = $ct_ty:ident,
        shared_secret = $ss_ty:ident,
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
            pub fn keygen<R: $crate::Csprng>(rng: &mut R) -> ($pk_ty, $sk_ty) {
                let mut pk = [0u8; PUBLIC_KEY_BYTES];
                let mut sk = [0u8; PRIVATE_KEY_BYTES];
                kem_keypair_seeded(&mut pk, &mut sk, rng);
                ($pk_ty { bytes: pk }, $sk_ty { bytes: sk })
            }

            pub fn encaps<R: $crate::Csprng>(
                pk: &$pk_ty,
                rng: &mut R,
            ) -> ($ct_ty, $ss_ty) {
                let mut ct = [0u8; CIPHERTEXT_BYTES];
                let mut ss = [0u8; SHARED_SECRET_BYTES];
                kem_enc_seeded(&mut ct, &mut ss, &pk.bytes, rng);
                ($ct_ty { bytes: ct }, $ss_ty { bytes: ss })
            }

            pub fn decaps(sk: &$sk_ty, ct: &$ct_ty) -> $ss_ty {
                let mut ss = [0u8; SHARED_SECRET_BYTES];
                kem_dec(&mut ss, &ct.bytes, &sk.bytes);
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

#[doc(hidden)]
pub use crate::__define_pqc_kem as define_pqc_kem;

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
