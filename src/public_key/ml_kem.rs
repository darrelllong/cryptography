//! ML-KEM (Kyber) implemented in safe, idiomatic Rust from FIPS 203.
//!
//! This module provides:
//! - ML-KEM-512/768/1024 parameter sets
//! - key generation
//! - encapsulation and decapsulation
//! - strict wire/key-blob framing
//!
//! Implementation notes:
//! - arithmetic and packing are implemented in-tree
//! - SHA3/SHAKE primitives come from this crate's hash module
//! - no C/FFI backends are used

use core::fmt;

use crate::hash::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use crate::hash::Xof;
use crate::Csprng;

const N: usize = 256;
const MAX_K: usize = 4;
const Q: i16 = 3329;
const Q_I32: i32 = 3329;
const SYM_BYTES: usize = 32;
const SS_BYTES: usize = 32;
const POLY_BYTES: usize = 384;

// q^-1 mod 2^16 = -3327
const QINV: i16 = -3327;
const INV_NTT_FACTOR: i16 = 1441; // mont^2 / 128
const TO_MONT_FACTOR: i16 = 1353; // 2^32 mod q

const SHAKE128_BLOCK_BYTES: usize = 168;

const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

type Poly = [i16; N];

#[derive(Clone, Debug, Eq, PartialEq)]
struct PolyVec {
    polys: [Poly; MAX_K],
    k: usize,
}

impl PolyVec {
    fn zero(k: usize) -> Self {
        debug_assert!(k <= MAX_K);
        Self {
            polys: [[0i16; N]; MAX_K],
            k,
        }
    }

    fn k(&self) -> usize {
        self.k
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Profile {
    k: usize,
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
}

/// ML-KEM parameter sets from FIPS 203.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemParameterSet {
    #[must_use]
    const fn profile(self) -> Profile {
        match self {
            Self::MlKem512 => Profile {
                k: 2,
                eta1: 3,
                eta2: 2,
                du: 10,
                dv: 4,
            },
            Self::MlKem768 => Profile {
                k: 3,
                eta1: 2,
                eta2: 2,
                du: 10,
                dv: 4,
            },
            Self::MlKem1024 => Profile {
                k: 4,
                eta1: 2,
                eta2: 2,
                du: 11,
                dv: 5,
            },
        }
    }

    /// Lattice rank parameter.
    #[must_use]
    pub const fn k(self) -> usize {
        self.profile().k
    }

    /// Public-key byte length.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        POLY_BYTES * self.k() + SYM_BYTES
    }

    /// Secret-key byte length.
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        2 * POLY_BYTES * self.k() + 3 * SYM_BYTES
    }

    /// Ciphertext byte length.
    #[must_use]
    pub const fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Shared-secret length in bytes.
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        let _ = self;
        SS_BYTES
    }

    #[must_use]
    const fn id(self) -> u8 {
        match self {
            Self::MlKem512 => 0x02,
            Self::MlKem768 => 0x03,
            Self::MlKem1024 => 0x04,
        }
    }

    #[must_use]
    const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x02 => Some(Self::MlKem512),
            0x03 => Some(Self::MlKem768),
            0x04 => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

/// ML-KEM public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemPublicKey {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM private key.
#[derive(Clone, Eq, PartialEq)]
pub struct MlKemPrivateKey {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemCiphertext {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM shared secret (32 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemSharedSecret {
    bytes: [u8; SS_BYTES],
}

/// Namespace for ML-KEM operations.
pub struct MlKem;

impl MlKemPublicKey {
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.public_key_len() {
            return None;
        }
        let p = params.profile();
        let (pkpv, rho) = unpack_public_key(p, bytes)?;
        // Re-encode and compare to reject non-canonical NTT coefficients.
        // poly_from_bytes accepts any 12-bit value [0, 4095]; values in
        // [3329, 4095] are not valid mod-Q representatives and would silently
        // produce wrong encapsulation results.  poly_to_bytes normalises to
        // [0, Q), so a round-trip mismatch indicates a non-canonical input.
        // The private key import already does this; public key import must too.
        let mut reencoded = polyvec_to_bytes(&pkpv);
        reencoded.extend_from_slice(&rho);
        if reencoded != bytes {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }

    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlKemParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }
}

impl MlKemPrivateKey {
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.private_key_len() {
            return None;
        }
        let p = params.profile();
        let sk_pke_len = p.k * POLY_BYTES;
        let pk_len = p.k * POLY_BYTES + SYM_BYTES;
        let (sk_pke, rest) = bytes.split_at(sk_pke_len);
        let (pk, trailer) = rest.split_at(pk_len);
        let (h_pk, z) = trailer.split_at(SYM_BYTES);
        // Structural checks.
        let skpv = polyvec_from_bytes(p.k, sk_pke)?;
        let (pkpv, rho) = unpack_public_key(p, pk)?;
        let mut pk_reencoded = polyvec_to_bytes(&pkpv);
        pk_reencoded.extend_from_slice(&rho);
        if pk_reencoded != pk {
            return None;
        }
        let h_expected = hash_h(pk);
        if h_expected.as_slice() != h_pk {
            return None;
        }
        // Also ensure secret key polyvec bytes are canonical.
        if polyvec_to_bytes(&skpv) != sk_pke {
            return None;
        }
        if z.len() != SYM_BYTES {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }

    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlKemParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }
}

impl MlKemCiphertext {
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.ciphertext_len() {
            return None;
        }
        unpack_ciphertext(params.profile(), bytes)?;
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }
}

impl MlKemSharedSecret {
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; SS_BYTES] {
        self.bytes
    }

    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SS_BYTES {
            return None;
        }
        let mut out = [0u8; SS_BYTES];
        out.copy_from_slice(bytes);
        Some(Self { bytes: out })
    }
}

impl MlKem {
    /// Deterministic keygen for vectors/KATs.
    ///
    /// `seed` is `d || z` (64 bytes) as in FIPS 203.
    #[must_use]
    pub fn keygen_from_seed(
        params: MlKemParameterSet,
        seed: &[u8; 2 * SYM_BYTES],
    ) -> Option<(MlKemPublicKey, MlKemPrivateKey)> {
        let p = params.profile();
        let mut d = [0u8; SYM_BYTES];
        let mut z = [0u8; SYM_BYTES];
        d.copy_from_slice(&seed[..SYM_BYTES]);
        z.copy_from_slice(&seed[SYM_BYTES..]);

        // WHAT: build CPA keypair from deterministic seed material and cache H(pk), z.
        // WHY: decapsulation needs H(pk) and z for the implicit-rejection path from FIPS 203.
        let (pk_bytes, sk_pke) = indcpa_keypair(p, &d)?;
        let h_pk = hash_h(&pk_bytes);

        let mut sk_bytes = Vec::with_capacity(params.private_key_len());
        sk_bytes.extend_from_slice(&sk_pke);
        sk_bytes.extend_from_slice(&pk_bytes);
        sk_bytes.extend_from_slice(&h_pk);
        sk_bytes.extend_from_slice(&z);

        let pk = MlKemPublicKey {
            params,
            bytes: pk_bytes,
        };
        let sk = MlKemPrivateKey {
            params,
            bytes: sk_bytes,
        };
        Some((pk, sk))
    }

    /// Generate an ML-KEM keypair from caller RNG.
    #[must_use]
    pub fn keygen<R: Csprng>(
        params: MlKemParameterSet,
        rng: &mut R,
    ) -> Option<(MlKemPublicKey, MlKemPrivateKey)> {
        let mut seed = [0u8; 2 * SYM_BYTES];
        rng.fill_bytes(&mut seed);
        Self::keygen_from_seed(params, &seed)
    }

    /// Deterministic encapsulation using explicit 32-byte randomness (`m`).
    ///
    /// This is the KAT/oracle-testing entry point.
    #[must_use]
    pub fn encaps_with_randomness(
        public_key: &MlKemPublicKey,
        randomness: &[u8; SYM_BYTES],
    ) -> Option<(MlKemCiphertext, MlKemSharedSecret)> {
        let p = public_key.params.profile();
        let h_pk = hash_h(&public_key.bytes);

        let mut buf = [0u8; 2 * SYM_BYTES];
        buf[..SYM_BYTES].copy_from_slice(randomness);
        buf[SYM_BYTES..].copy_from_slice(&h_pk);

        // WHAT: derive (shared-secret || encryption coins) from randomness and H(pk).
        // WHY: this ties encapsulation coins to the target public key and avoids reuse hazards.
        let kr = hash_g(&buf);
        let mut coins = [0u8; SYM_BYTES];
        coins.copy_from_slice(&kr[SYM_BYTES..]);

        let ct_bytes = indcpa_encrypt(p, randomness, &public_key.bytes, &coins)?;
        let mut ss = [0u8; SS_BYTES];
        ss.copy_from_slice(&kr[..SS_BYTES]);
        Some((
            MlKemCiphertext {
                params: public_key.params,
                bytes: ct_bytes,
            },
            MlKemSharedSecret { bytes: ss },
        ))
    }

    /// Encapsulate to a recipient public key.
    #[must_use]
    pub fn encaps<R: Csprng>(
        public_key: &MlKemPublicKey,
        rng: &mut R,
    ) -> Option<(MlKemCiphertext, MlKemSharedSecret)> {
        let mut m = [0u8; SYM_BYTES];
        rng.fill_bytes(&mut m);
        Self::encaps_with_randomness(public_key, &m)
    }

    /// Decapsulate a ciphertext with a private key.
    #[must_use]
    pub fn decaps(
        private_key: &MlKemPrivateKey,
        ciphertext: &MlKemCiphertext,
    ) -> Option<MlKemSharedSecret> {
        if private_key.params != ciphertext.params {
            return None;
        }
        let p = private_key.params.profile();
        let sk_pke_len = p.k * POLY_BYTES;
        let pk_len = p.k * POLY_BYTES + SYM_BYTES;
        let h_offset = sk_pke_len + pk_len;
        let z_offset = h_offset + SYM_BYTES;

        let sk_bytes = &private_key.bytes;
        if sk_bytes.len() != private_key.params.private_key_len() {
            return None;
        }

        let sk_pke = &sk_bytes[..sk_pke_len];
        let pk = &sk_bytes[sk_pke_len..(sk_pke_len + pk_len)];
        let h_pk = &sk_bytes[h_offset..z_offset];
        let z = &sk_bytes[z_offset..];

        let m_prime = indcpa_decrypt(p, &ciphertext.bytes, sk_pke)?;
        let mut g_in = [0u8; 2 * SYM_BYTES];
        g_in[..SYM_BYTES].copy_from_slice(&m_prime);
        g_in[SYM_BYTES..].copy_from_slice(h_pk);
        let kr = hash_g(&g_in);
        let mut coins = [0u8; SYM_BYTES];
        coins.copy_from_slice(&kr[SYM_BYTES..]);

        let cmp = indcpa_encrypt(p, &m_prime, pk, &coins)?;

        let mut rk_in = Vec::with_capacity(SYM_BYTES + ciphertext.bytes.len());
        rk_in.extend_from_slice(z);
        rk_in.extend_from_slice(&ciphertext.bytes);
        let rk = hash_j(&rk_in);

        // WHAT: select derived K on re-encryption match, else select fallback rk.
        // WHY: implicit rejection must stay branchless so malformed ciphertexts do not leak via timing.
        let mask = crate::ct::constant_time_eq_mask(&cmp, &ciphertext.bytes);
        let mut ss = [0u8; SS_BYTES];
        let inv = !mask;
        for i in 0..SS_BYTES {
            ss[i] = (kr[i] & mask) | (rk[i] & inv);
        }
        Some(MlKemSharedSecret { bytes: ss })
    }
}

impl fmt::Debug for MlKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKemPrivateKey(<redacted>)")
    }
}

impl Drop for MlKemPrivateKey {
    fn drop(&mut self) {
        // WHAT: wipe the packed secret-key buffer on drop.
        // WHY: ML-KEM private keys are stored as raw bytes and should not stay
        // resident after the owner goes out of scope.
        crate::ct::zeroize_slice(self.bytes.as_mut_slice());
    }
}

fn hash_h(data: &[u8]) -> [u8; SYM_BYTES] {
    Sha3_256::digest(data)
}

fn hash_g(data: &[u8]) -> [u8; 2 * SYM_BYTES] {
    Sha3_512::digest(data)
}

fn hash_j(data: &[u8]) -> [u8; SS_BYTES] {
    let mut xof = Shake256::new();
    xof.update(data);
    let mut out = [0u8; SS_BYTES];
    xof.squeeze(&mut out);
    out
}

#[inline(always)]
fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV) as i32;
    ((a - t * Q_I32) >> 16) as i16
}

#[inline(always)]
fn barrett_reduce(a: i16) -> i16 {
    let v: i16 = (((1i32 << 26) + Q_I32 / 2) / Q_I32) as i16;
    let t = (((v as i32) * (a as i32) + (1i32 << 25)) >> 26) as i16;
    a - t * Q
}

#[inline(always)]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

fn poly_reduce(poly: &mut Poly) {
    for c in poly.iter_mut() {
        *c = barrett_reduce(*c);
    }
}

#[inline(always)]
fn poly_add_assign(dst: &mut Poly, rhs: &Poly) {
    for i in 0..N {
        dst[i] = dst[i].wrapping_add(rhs[i]);
    }
}

#[inline(always)]
fn poly_sub_assign(dst: &mut Poly, rhs: &Poly) {
    for i in 0..N {
        dst[i] = dst[i].wrapping_sub(rhs[i]);
    }
}

fn ntt(poly: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = fqmul(zeta, poly[j + len]);
                poly[j + len] = poly[j].wrapping_sub(t);
                poly[j] = poly[j].wrapping_add(t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn invntt(poly: &mut Poly) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..(start + len) {
                let t = poly[j];
                poly[j] = barrett_reduce(t.wrapping_add(poly[j + len]));
                let diff = poly[j + len].wrapping_sub(t);
                poly[j + len] = fqmul(zeta, diff);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in poly.iter_mut() {
        *c = fqmul(*c, INV_NTT_FACTOR);
    }
}

#[inline(always)]
fn basemul_pair(a: &[i16], b: &[i16], zeta: i16) -> (i16, i16) {
    let mut r0 = fqmul(a[1], b[1]);
    r0 = fqmul(r0, zeta);
    r0 = r0.wrapping_add(fqmul(a[0], b[0]));
    let r1 = fqmul(a[0], b[1]).wrapping_add(fqmul(a[1], b[0]));
    (r0, r1)
}

fn poly_basemul_montgomery_add_assign(dst: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..(N / 4) {
        let zeta = ZETAS[64 + i];
        let ai = 4 * i;
        let (r0, r1) = basemul_pair(&a[ai..ai + 2], &b[ai..ai + 2], zeta);
        dst[ai] = dst[ai].wrapping_add(r0);
        dst[ai + 1] = dst[ai + 1].wrapping_add(r1);
        let (s0, s1) = basemul_pair(&a[ai + 2..ai + 4], &b[ai + 2..ai + 4], -zeta);
        dst[ai + 2] = dst[ai + 2].wrapping_add(s0);
        dst[ai + 3] = dst[ai + 3].wrapping_add(s1);
    }
}

fn poly_tomont(poly: &mut Poly) {
    for c in poly.iter_mut() {
        *c = montgomery_reduce((*c as i32) * (TO_MONT_FACTOR as i32));
    }
}

fn polyvec_ntt(v: &mut PolyVec) {
    let k = v.k();
    for poly in v.polys[..k].iter_mut() {
        ntt(poly);
        poly_reduce(poly);
    }
}

fn polyvec_invntt(v: &mut PolyVec) {
    let k = v.k();
    for poly in v.polys[..k].iter_mut() {
        invntt(poly);
    }
}

fn polyvec_reduce(v: &mut PolyVec) {
    let k = v.k();
    for poly in v.polys[..k].iter_mut() {
        poly_reduce(poly);
    }
}

fn polyvec_add_assign(dst: &mut PolyVec, rhs: &PolyVec) {
    debug_assert_eq!(dst.k(), rhs.k());
    let k = dst.k();
    for (a, b) in dst.polys[..k].iter_mut().zip(rhs.polys[..k].iter()) {
        poly_add_assign(a, b);
    }
}

fn polyvec_basemul_acc_montgomery(a: &PolyVec, b: &PolyVec) -> Poly {
    debug_assert_eq!(a.k(), b.k());
    let mut out = [0i16; N];
    for i in 0..a.k() {
        poly_basemul_montgomery_add_assign(&mut out, &a.polys[i], &b.polys[i]);
    }
    poly_reduce(&mut out);
    out
}

fn map_coeff_to_nonnegative(mut x: i16) -> u16 {
    x = barrett_reduce(x);
    if x < 0 {
        (x as i32 + Q_I32) as u16
    } else {
        x as u16
    }
}

fn compress_coeff(x: i16, d: usize) -> u16 {
    let v = map_coeff_to_nonnegative(x) as i32;
    let scale = 1i32 << d;
    (((v * scale + (Q_I32 / 2)) / Q_I32) & (scale - 1)) as u16
}

fn decompress_coeff(x: u16, d: usize) -> i16 {
    let rounding = 1i32 << (d - 1);
    (((x as i32) * Q_I32 + rounding) >> d) as i16
}

fn poly_to_bytes(poly: &Poly) -> [u8; POLY_BYTES] {
    let mut out = [0u8; POLY_BYTES];
    for i in 0..(N / 2) {
        let t0 = map_coeff_to_nonnegative(poly[2 * i]);
        let t1 = map_coeff_to_nonnegative(poly[2 * i + 1]);
        out[3 * i] = (t0 & 0xFF) as u8;
        out[3 * i + 1] = ((t0 >> 8) as u8) | (((t1 & 0x0F) as u8) << 4);
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
    out
}

fn poly_from_bytes(bytes: &[u8]) -> Option<Poly> {
    if bytes.len() != POLY_BYTES {
        return None;
    }
    let mut out = [0i16; N];
    for i in 0..(N / 2) {
        let d0 = (u16::from(bytes[3 * i])) | (u16::from(bytes[3 * i + 1]) << 8);
        let d1 = (u16::from(bytes[3 * i + 1]) >> 4) | (u16::from(bytes[3 * i + 2]) << 4);
        out[2 * i] = (d0 & 0x0FFF) as i16;
        out[2 * i + 1] = (d1 & 0x0FFF) as i16;
    }
    Some(out)
}

fn poly_compress(poly: &Poly, d: usize) -> Vec<u8> {
    match d {
        4 => {
            let mut out = vec![0u8; N / 2];
            for i in 0..(N / 8) {
                let mut t = [0u8; 8];
                for j in 0..8 {
                    t[j] = compress_coeff(poly[8 * i + j], 4) as u8;
                }
                out[4 * i] = t[0] | (t[1] << 4);
                out[4 * i + 1] = t[2] | (t[3] << 4);
                out[4 * i + 2] = t[4] | (t[5] << 4);
                out[4 * i + 3] = t[6] | (t[7] << 4);
            }
            out
        }
        5 => {
            let mut out = vec![0u8; 5 * N / 8];
            for i in 0..(N / 8) {
                let mut t = [0u8; 8];
                for j in 0..8 {
                    t[j] = compress_coeff(poly[8 * i + j], 5) as u8;
                }
                out[5 * i] = t[0] | (t[1] << 5);
                out[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                out[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
                out[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                out[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
            }
            out
        }
        _ => Vec::new(),
    }
}

fn poly_decompress(bytes: &[u8], d: usize) -> Option<Poly> {
    let mut out = [0i16; N];
    match d {
        4 => {
            if bytes.len() != N / 2 {
                return None;
            }
            for i in 0..(N / 2) {
                out[2 * i] = decompress_coeff((bytes[i] & 0x0F) as u16, 4);
                out[2 * i + 1] = decompress_coeff((bytes[i] >> 4) as u16, 4);
            }
        }
        5 => {
            if bytes.len() != 5 * N / 8 {
                return None;
            }
            for i in 0..(N / 8) {
                let b0 = u16::from(bytes[5 * i]);
                let b1 = u16::from(bytes[5 * i + 1]);
                let b2 = u16::from(bytes[5 * i + 2]);
                let b3 = u16::from(bytes[5 * i + 3]);
                let b4 = u16::from(bytes[5 * i + 4]);
                let t0 = b0 & 0x1F;
                let t1 = ((b0 >> 5) | (b1 << 3)) & 0x1F;
                let t2 = (b1 >> 2) & 0x1F;
                let t3 = ((b1 >> 7) | (b2 << 1)) & 0x1F;
                let t4 = ((b2 >> 4) | (b3 << 4)) & 0x1F;
                let t5 = (b3 >> 1) & 0x1F;
                let t6 = ((b3 >> 6) | (b4 << 2)) & 0x1F;
                let t7 = (b4 >> 3) & 0x1F;
                out[8 * i] = decompress_coeff(t0, 5);
                out[8 * i + 1] = decompress_coeff(t1, 5);
                out[8 * i + 2] = decompress_coeff(t2, 5);
                out[8 * i + 3] = decompress_coeff(t3, 5);
                out[8 * i + 4] = decompress_coeff(t4, 5);
                out[8 * i + 5] = decompress_coeff(t5, 5);
                out[8 * i + 6] = decompress_coeff(t6, 5);
                out[8 * i + 7] = decompress_coeff(t7, 5);
            }
        }
        _ => return None,
    }
    Some(out)
}

fn polyvec_to_bytes(v: &PolyVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.k() * POLY_BYTES);
    for poly in &v.polys[..v.k()] {
        out.extend_from_slice(&poly_to_bytes(poly));
    }
    out
}

fn polyvec_from_bytes(k: usize, bytes: &[u8]) -> Option<PolyVec> {
    if k > MAX_K {
        return None;
    }
    if bytes.len() != k * POLY_BYTES {
        return None;
    }
    let mut polys = [[0i16; N]; MAX_K];
    for (i, poly) in polys.iter_mut().enumerate().take(k) {
        let start = i * POLY_BYTES;
        let end = start + POLY_BYTES;
        *poly = poly_from_bytes(&bytes[start..end])?;
    }
    Some(PolyVec { polys, k })
}

fn polyvec_compress(v: &PolyVec, d: usize) -> Vec<u8> {
    let k = v.k();
    match d {
        10 => {
            let mut out = vec![0u8; k * 320];
            for i in 0..k {
                for j in 0..(N / 4) {
                    let t0 = compress_coeff(v.polys[i][4 * j], 10);
                    let t1 = compress_coeff(v.polys[i][4 * j + 1], 10);
                    let t2 = compress_coeff(v.polys[i][4 * j + 2], 10);
                    let t3 = compress_coeff(v.polys[i][4 * j + 3], 10);
                    let off = i * 320 + 5 * j;
                    out[off] = t0 as u8;
                    out[off + 1] = (t0 >> 8) as u8 | ((t1 << 2) as u8);
                    out[off + 2] = (t1 >> 6) as u8 | ((t2 << 4) as u8);
                    out[off + 3] = (t2 >> 4) as u8 | ((t3 << 6) as u8);
                    out[off + 4] = (t3 >> 2) as u8;
                }
            }
            out
        }
        11 => {
            let mut out = vec![0u8; k * 352];
            for i in 0..k {
                for j in 0..(N / 8) {
                    let t0 = compress_coeff(v.polys[i][8 * j], 11);
                    let t1 = compress_coeff(v.polys[i][8 * j + 1], 11);
                    let t2 = compress_coeff(v.polys[i][8 * j + 2], 11);
                    let t3 = compress_coeff(v.polys[i][8 * j + 3], 11);
                    let t4 = compress_coeff(v.polys[i][8 * j + 4], 11);
                    let t5 = compress_coeff(v.polys[i][8 * j + 5], 11);
                    let t6 = compress_coeff(v.polys[i][8 * j + 6], 11);
                    let t7 = compress_coeff(v.polys[i][8 * j + 7], 11);
                    let off = i * 352 + 11 * j;
                    out[off] = t0 as u8;
                    out[off + 1] = (t0 >> 8) as u8 | ((t1 << 3) as u8);
                    out[off + 2] = (t1 >> 5) as u8 | ((t2 << 6) as u8);
                    out[off + 3] = (t2 >> 2) as u8;
                    out[off + 4] = (t2 >> 10) as u8 | ((t3 << 1) as u8);
                    out[off + 5] = (t3 >> 7) as u8 | ((t4 << 4) as u8);
                    out[off + 6] = (t4 >> 4) as u8 | ((t5 << 7) as u8);
                    out[off + 7] = (t5 >> 1) as u8;
                    out[off + 8] = (t5 >> 9) as u8 | ((t6 << 2) as u8);
                    out[off + 9] = (t6 >> 6) as u8 | ((t7 << 5) as u8);
                    out[off + 10] = (t7 >> 3) as u8;
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

fn polyvec_decompress(k: usize, bytes: &[u8], d: usize) -> Option<PolyVec> {
    if k > MAX_K {
        return None;
    }
    let mut polys = [[0i16; N]; MAX_K];
    match d {
        10 => {
            if bytes.len() != k * 320 {
                return None;
            }
            for (i, poly) in polys.iter_mut().enumerate().take(k) {
                for j in 0..(N / 4) {
                    let off = i * 320 + 5 * j;
                    let b0 = u16::from(bytes[off]);
                    let b1 = u16::from(bytes[off + 1]);
                    let b2 = u16::from(bytes[off + 2]);
                    let b3 = u16::from(bytes[off + 3]);
                    let b4 = u16::from(bytes[off + 4]);
                    let t0 = (b0 | (b1 << 8)) & 0x03FF;
                    let t1 = ((b1 >> 2) | (b2 << 6)) & 0x03FF;
                    let t2 = ((b2 >> 4) | (b3 << 4)) & 0x03FF;
                    let t3 = ((b3 >> 6) | (b4 << 2)) & 0x03FF;
                    poly[4 * j] = decompress_coeff(t0, 10);
                    poly[4 * j + 1] = decompress_coeff(t1, 10);
                    poly[4 * j + 2] = decompress_coeff(t2, 10);
                    poly[4 * j + 3] = decompress_coeff(t3, 10);
                }
            }
        }
        11 => {
            if bytes.len() != k * 352 {
                return None;
            }
            for (i, poly) in polys.iter_mut().enumerate().take(k) {
                for j in 0..(N / 8) {
                    let off = i * 352 + 11 * j;
                    let b0 = u16::from(bytes[off]);
                    let b1 = u16::from(bytes[off + 1]);
                    let b2 = u16::from(bytes[off + 2]);
                    let b3 = u16::from(bytes[off + 3]);
                    let b4 = u16::from(bytes[off + 4]);
                    let b5 = u16::from(bytes[off + 5]);
                    let b6 = u16::from(bytes[off + 6]);
                    let b7 = u16::from(bytes[off + 7]);
                    let b8 = u16::from(bytes[off + 8]);
                    let b9 = u16::from(bytes[off + 9]);
                    let b10 = u16::from(bytes[off + 10]);
                    let t0 = (b0 | (b1 << 8)) & 0x07FF;
                    let t1 = ((b1 >> 3) | (b2 << 5)) & 0x07FF;
                    let t2 = ((b2 >> 6) | (b3 << 2) | (b4 << 10)) & 0x07FF;
                    let t3 = ((b4 >> 1) | (b5 << 7)) & 0x07FF;
                    let t4 = ((b5 >> 4) | (b6 << 4)) & 0x07FF;
                    let t5 = ((b6 >> 7) | (b7 << 1) | (b8 << 9)) & 0x07FF;
                    let t6 = ((b8 >> 2) | (b9 << 6)) & 0x07FF;
                    let t7 = ((b9 >> 5) | (b10 << 3)) & 0x07FF;
                    poly[8 * j] = decompress_coeff(t0, 11);
                    poly[8 * j + 1] = decompress_coeff(t1, 11);
                    poly[8 * j + 2] = decompress_coeff(t2, 11);
                    poly[8 * j + 3] = decompress_coeff(t3, 11);
                    poly[8 * j + 4] = decompress_coeff(t4, 11);
                    poly[8 * j + 5] = decompress_coeff(t5, 11);
                    poly[8 * j + 6] = decompress_coeff(t6, 11);
                    poly[8 * j + 7] = decompress_coeff(t7, 11);
                }
            }
        }
        _ => return None,
    }
    Some(PolyVec { polys, k })
}

fn poly_from_message(msg: &[u8; SYM_BYTES]) -> Poly {
    let mut out = [0i16; N];
    for i in 0..SYM_BYTES {
        for j in 0..8 {
            let bit = (msg[i] >> j) & 1;
            if bit == 1 {
                out[8 * i + j] = ((Q as i32 + 1) / 2) as i16;
            }
        }
    }
    out
}

fn poly_to_message(poly: &Poly) -> [u8; SYM_BYTES] {
    let mut msg = [0u8; SYM_BYTES];
    for i in 0..SYM_BYTES {
        let mut byte = 0u8;
        for j in 0..8 {
            let mut t = i32::from(barrett_reduce(poly[8 * i + j]));
            if t < 0 {
                t += Q_I32;
            }
            let bit = (((t << 1) + Q_I32 / 2) / Q_I32) & 1;
            byte |= (bit as u8) << j;
        }
        msg[i] = byte;
    }
    msg
}

fn sample_uniform_ntt(seed: &[u8; SYM_BYTES], x: u8, y: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(seed);
    xof.update(&[x, y]);

    let mut out = [0i16; N];
    let mut ctr = 0usize;
    let mut buf = [0u8; SHAKE128_BLOCK_BYTES];
    while ctr < N {
        xof.squeeze(&mut buf);
        let mut pos = 0usize;
        while ctr < N && pos + 3 <= buf.len() {
            // WHAT: unpack two 12-bit candidates from each 3-byte chunk.
            // WHY: rejection sampling here preserves a uniform distribution over [0, q).
            let val0 = ((u16::from(buf[pos])) | (u16::from(buf[pos + 1]) << 8)) & 0x0FFF;
            let val1 = ((u16::from(buf[pos + 1]) >> 4) | (u16::from(buf[pos + 2]) << 4)) & 0x0FFF;
            pos += 3;
            if val0 < Q as u16 {
                out[ctr] = val0 as i16;
                ctr += 1;
            }
            if ctr < N && val1 < Q as u16 {
                out[ctr] = val1 as i16;
                ctr += 1;
            }
        }
    }
    out
}

fn sample_noise_poly(seed: &[u8; SYM_BYTES], nonce: u8, eta: usize) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&[nonce]);
    let out_len = eta * N / 4; // max is 192 (eta=3)
    let mut buf = [0u8; 3 * N / 4];
    xof.squeeze(&mut buf[..out_len]);
    match eta {
        2 => cbd2(&buf[..out_len]),
        3 => cbd3(&buf[..out_len]),
        _ => [0i16; N],
    }
}

fn load32_le(x: &[u8]) -> u32 {
    u32::from(x[0]) | (u32::from(x[1]) << 8) | (u32::from(x[2]) << 16) | (u32::from(x[3]) << 24)
}

fn load24_le(x: &[u8]) -> u32 {
    u32::from(x[0]) | (u32::from(x[1]) << 8) | (u32::from(x[2]) << 16)
}

fn cbd2(buf: &[u8]) -> Poly {
    let mut out = [0i16; N];
    for i in 0..(N / 8) {
        let t = load32_le(&buf[4 * i..4 * i + 4]);
        let mut d = t & 0x5555_5555;
        d = d.wrapping_add((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            out[8 * i + j] = a - b;
        }
    }
    out
}

fn cbd3(buf: &[u8]) -> Poly {
    let mut out = [0i16; N];
    for i in 0..(N / 4) {
        let t = load24_le(&buf[3 * i..3 * i + 3]);
        let mut d = t & 0x0024_9249;
        d = d.wrapping_add((t >> 1) & 0x0024_9249);
        d = d.wrapping_add((t >> 2) & 0x0024_9249);
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            out[4 * i + j] = a - b;
        }
    }
    out
}

fn gen_matrix(p: Profile, seed: &[u8; SYM_BYTES], transposed: bool) -> [PolyVec; MAX_K] {
    let mut rows = core::array::from_fn(|_| PolyVec::zero(p.k));
    for (i, row_slot) in rows.iter_mut().enumerate().take(p.k) {
        let mut row_value = PolyVec::zero(p.k);
        for j in 0..p.k {
            // WHAT: swap matrix coordinates when `transposed` is requested.
            // WHY: keygen needs A while encapsulation needs A^T; one sampler serves both.
            let (x, y) = if transposed {
                (i as u8, j as u8)
            } else {
                (j as u8, i as u8)
            };
            row_value.polys[j] = sample_uniform_ntt(seed, x, y);
        }
        *row_slot = row_value;
    }
    rows
}

fn pack_public_key(t_hat: &PolyVec, rho: &[u8; SYM_BYTES]) -> Vec<u8> {
    let mut out = polyvec_to_bytes(t_hat);
    out.extend_from_slice(rho);
    out
}

fn unpack_public_key(p: Profile, pk: &[u8]) -> Option<(PolyVec, [u8; SYM_BYTES])> {
    if pk.len() != p.k * POLY_BYTES + SYM_BYTES {
        return None;
    }
    let (poly_bytes, rho_bytes) = pk.split_at(p.k * POLY_BYTES);
    let t_hat = polyvec_from_bytes(p.k, poly_bytes)?;
    let mut rho = [0u8; SYM_BYTES];
    rho.copy_from_slice(rho_bytes);
    Some((t_hat, rho))
}

fn pack_ciphertext(p: Profile, b: &PolyVec, v: &Poly) -> Vec<u8> {
    let mut out = polyvec_compress(b, p.du);
    out.extend_from_slice(&poly_compress(v, p.dv));
    out
}

fn unpack_ciphertext(p: Profile, ct: &[u8]) -> Option<(PolyVec, Poly)> {
    if ct.len() != (N * p.k * p.du).div_ceil(8) + (N * p.dv).div_ceil(8) {
        return None;
    }
    let b_len = (N * p.k * p.du).div_ceil(8);
    let (b_bytes, v_bytes) = ct.split_at(b_len);
    let b = polyvec_decompress(p.k, b_bytes, p.du)?;
    let v = poly_decompress(v_bytes, p.dv)?;
    Some((b, v))
}

fn indcpa_keypair(p: Profile, d: &[u8; SYM_BYTES]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut g_in = [0u8; SYM_BYTES + 1];
    g_in[..SYM_BYTES].copy_from_slice(d);
    g_in[SYM_BYTES] = p.k as u8;
    let g_out = hash_g(&g_in);

    let mut rho = [0u8; SYM_BYTES];
    rho.copy_from_slice(&g_out[..SYM_BYTES]);
    let mut sigma = [0u8; SYM_BYTES];
    sigma.copy_from_slice(&g_out[SYM_BYTES..]);

    let a_hat = gen_matrix(p, &rho, false);

    let mut s_hat = PolyVec::zero(p.k);
    let mut e_hat = PolyVec::zero(p.k);
    let mut nonce = 0u8;
    for i in 0..p.k {
        s_hat.polys[i] = sample_noise_poly(&sigma, nonce, p.eta1);
        nonce = nonce.wrapping_add(1);
    }
    for i in 0..p.k {
        e_hat.polys[i] = sample_noise_poly(&sigma, nonce, p.eta1);
        nonce = nonce.wrapping_add(1);
    }

    polyvec_ntt(&mut s_hat);
    polyvec_ntt(&mut e_hat);

    let mut t_hat = PolyVec::zero(p.k);
    for (i, row) in a_hat.iter().enumerate().take(p.k) {
        let mut t = polyvec_basemul_acc_montgomery(row, &s_hat);
        poly_tomont(&mut t);
        poly_add_assign(&mut t, &e_hat.polys[i]);
        poly_reduce(&mut t);
        t_hat.polys[i] = t;
    }

    // WHAT: keep the secret vector serialized as s-hat (NTT domain).
    // WHY: decapsulation consumes s-hat directly in NTT space and avoids an extra transform.
    let sk_pke = polyvec_to_bytes(&s_hat);
    let pk = pack_public_key(&t_hat, &rho);
    Some((pk, sk_pke))
}

fn indcpa_encrypt(
    p: Profile,
    msg: &[u8; SYM_BYTES],
    pk_bytes: &[u8],
    coins: &[u8; SYM_BYTES],
) -> Option<Vec<u8>> {
    let (t_hat, rho) = unpack_public_key(p, pk_bytes)?;
    // WHAT: expand the transposed public matrix from `rho`.
    // WHY: Kyber encapsulation multiplies by A^T as specified.
    let at = gen_matrix(p, &rho, true);
    let m_poly = poly_from_message(msg);

    let mut sp = PolyVec::zero(p.k);
    let mut ep = PolyVec::zero(p.k);
    let mut nonce = 0u8;
    for i in 0..p.k {
        sp.polys[i] = sample_noise_poly(coins, nonce, p.eta1);
        nonce = nonce.wrapping_add(1);
    }
    for i in 0..p.k {
        ep.polys[i] = sample_noise_poly(coins, nonce, p.eta2);
        nonce = nonce.wrapping_add(1);
    }
    let epp = sample_noise_poly(coins, nonce, p.eta2);

    polyvec_ntt(&mut sp);

    let mut b_hat = PolyVec::zero(p.k);
    for (i, row) in at.iter().enumerate().take(p.k) {
        b_hat.polys[i] = polyvec_basemul_acc_montgomery(row, &sp);
    }
    let mut v_hat = polyvec_basemul_acc_montgomery(&t_hat, &sp);

    polyvec_invntt(&mut b_hat);
    invntt(&mut v_hat);

    polyvec_add_assign(&mut b_hat, &ep);
    poly_add_assign(&mut v_hat, &epp);
    poly_add_assign(&mut v_hat, &m_poly);
    polyvec_reduce(&mut b_hat);
    poly_reduce(&mut v_hat);

    Some(pack_ciphertext(p, &b_hat, &v_hat))
}

fn indcpa_decrypt(p: Profile, ct: &[u8], sk_pke: &[u8]) -> Option<[u8; SYM_BYTES]> {
    let (mut b, mut v) = unpack_ciphertext(p, ct)?;
    let s_hat = polyvec_from_bytes(p.k, sk_pke)?;

    polyvec_ntt(&mut b);
    let mut mp = polyvec_basemul_acc_montgomery(&s_hat, &b);
    invntt(&mut mp);

    poly_sub_assign(&mut v, &mp);
    poly_reduce(&mut v);
    Some(poly_to_message(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    fn decode_hex(hex: &str) -> Option<Vec<u8>> {
        let bytes = hex.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for i in (0..bytes.len()).step_by(2) {
            let hi = hex_nibble(bytes[i])?;
            let lo = hex_nibble(bytes[i + 1])?;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }

    fn decode_hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
        let bytes = decode_hex(hex)?;
        bytes.try_into().ok()
    }

    fn parse_vector_map(contents: &'static str) -> HashMap<&'static str, &'static str> {
        let mut out = HashMap::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line.split_once('=').expect("vector format key=value");
            out.insert(name.trim(), value.trim());
        }
        out
    }

    fn parse_i16_vector(contents: &str) -> Vec<i16> {
        contents
            .split_whitespace()
            .filter(|tok| !tok.starts_with('#'))
            .filter_map(|tok| tok.parse::<i16>().ok())
            .collect()
    }

    #[test]
    fn ml_kem_parameter_lengths_match_profiles() {
        assert_eq!(MlKemParameterSet::MlKem512.public_key_len(), 800);
        assert_eq!(MlKemParameterSet::MlKem512.private_key_len(), 1632);
        assert_eq!(MlKemParameterSet::MlKem512.ciphertext_len(), 768);

        assert_eq!(MlKemParameterSet::MlKem768.public_key_len(), 1184);
        assert_eq!(MlKemParameterSet::MlKem768.private_key_len(), 2400);
        assert_eq!(MlKemParameterSet::MlKem768.ciphertext_len(), 1088);

        assert_eq!(MlKemParameterSet::MlKem1024.public_key_len(), 1568);
        assert_eq!(MlKemParameterSet::MlKem1024.private_key_len(), 3168);
        assert_eq!(MlKemParameterSet::MlKem1024.ciphertext_len(), 1568);
    }

    #[test]
    fn ml_kem_zetas_match_reference_ntt_table() {
        // Reference: pq-crystals/kyber ref/ntt.c zetas table.
        let expected = parse_i16_vector(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_kem_ref_zetas.txt"
        )));
        let expected: [i16; 128] = expected.try_into().expect("expected 128 ML-KEM zetas");
        assert_eq!(ZETAS, expected);
    }

    #[test]
    fn wire_and_blob_roundtrips() {
        let params = MlKemParameterSet::MlKem768;
        let seed = [0x42u8; 64];
        let (pk, sk) = MlKem::keygen_from_seed(params, &seed).expect("keygen");
        let mut m = [0u8; 32];
        m.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (i as u8).wrapping_mul(17));
        let (ct, ss) = MlKem::encaps_with_randomness(&pk, &m).expect("encaps");
        let ss2 = MlKem::decaps(&sk, &ct).expect("decaps");
        assert_eq!(ss, ss2);

        let pk_blob = pk.to_key_blob();
        let sk_blob = sk.to_key_blob();
        let ct_wire = ct.to_wire_bytes();

        assert_eq!(MlKemPublicKey::from_key_blob(&pk_blob).expect("pk"), pk);
        assert_eq!(MlKemPrivateKey::from_key_blob(&sk_blob).expect("sk"), sk);
        assert_eq!(
            MlKemCiphertext::from_wire_bytes(params, &ct_wire).expect("ct"),
            ct
        );
    }

    #[test]
    fn deterministic_encapsulation_matches_decapsulation() {
        for &(params, seed_byte, msg_byte) in &[
            (MlKemParameterSet::MlKem512, 0x11u8, 0x22u8),
            (MlKemParameterSet::MlKem768, 0x33u8, 0x44u8),
            (MlKemParameterSet::MlKem1024, 0x55u8, 0x66u8),
        ] {
            let seed = [seed_byte; 64];
            let (pk, sk) = MlKem::keygen_from_seed(params, &seed).expect("keygen");
            let msg = [msg_byte; 32];
            let (ct, ss) = MlKem::encaps_with_randomness(&pk, &msg).expect("encaps");
            let ss_recv = MlKem::decaps(&sk, &ct).expect("decaps");
            assert_eq!(ss, ss_recv, "{params:?}");
        }
    }

    #[test]
    fn ml_kem_512_matches_acvp_fips203_subset() {
        // Source: NIST ACVP server vectors, ML-KEM keyGen/encapDecap FIPS203,
        // tgId 1 tcId 1 (keyGen + encapsulation) and tgId 4 tcId 1 (decapsulation).
        let vectors = parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_kem_fips203_subset.txt"
        )));

        let d: [u8; 32] = decode_hex_array(vectors["KEYGEN_D"]).expect("d");
        let z: [u8; 32] = decode_hex_array(vectors["KEYGEN_Z"]).expect("z");
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);

        let (pk, _sk) =
            MlKem::keygen_from_seed(MlKemParameterSet::MlKem512, &seed).expect("keygen");
        assert_eq!(
            pk.to_wire_bytes(),
            decode_hex(vectors["KEYGEN_EK"]).expect("expected ek")
        );

        let encap_pk = MlKemPublicKey::from_wire_bytes(
            MlKemParameterSet::MlKem512,
            &decode_hex(vectors["ENCAP_EK"]).expect("encap ek"),
        )
        .expect("encap pk");
        let m: [u8; 32] = decode_hex_array(vectors["ENCAP_M"]).expect("encap m");
        let (ct, ss) = MlKem::encaps_with_randomness(&encap_pk, &m).expect("encaps");
        assert_eq!(
            ct.to_wire_bytes(),
            decode_hex(vectors["ENCAP_C"]).expect("expected c")
        );
        assert_eq!(
            ss.to_wire_bytes(),
            decode_hex_array::<SS_BYTES>(vectors["ENCAP_K"]).expect("expected k")
        );

        let decap_sk = MlKemPrivateKey::from_wire_bytes(
            MlKemParameterSet::MlKem512,
            &decode_hex(vectors["DECAP_DK"]).expect("decap dk"),
        )
        .expect("decap sk");
        let decap_ct = MlKemCiphertext::from_wire_bytes(
            MlKemParameterSet::MlKem512,
            &decode_hex(vectors["DECAP_C"]).expect("decap c"),
        )
        .expect("decap ct");
        let decap_ss = MlKem::decaps(&decap_sk, &decap_ct).expect("decaps");
        assert_eq!(
            decap_ss.to_wire_bytes(),
            decode_hex_array::<SS_BYTES>(vectors["DECAP_K"]).expect("decap k")
        );
    }
}
