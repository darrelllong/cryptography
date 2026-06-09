//! ML-DSA (Dilithium) implemented in safe, idiomatic Rust from FIPS 204.
//!
//! This module provides:
//! - ML-DSA-44/65/87 parameter sets
//! - key generation
//! - signing and verification
//! - strict wire/key-blob framing
//!
//! Implementation notes:
//! - arithmetic and packing are implemented in-tree
//! - SHAKE primitives come from this crate's hash module
//! - no C/FFI backends are used in production code paths

use core::fmt;
use std::sync::OnceLock;

use crate::hash::sha3::{Shake128, Shake256};
use crate::hash::Xof;
use crate::Csprng;

const N: usize = 256;
const MAX_K: usize = 8;
const MAX_L: usize = 7;
const MAX_CONTEXT_BYTES: usize = u8::MAX as usize;
const MAX_PRE_BYTES: usize = 2 + MAX_CONTEXT_BYTES;
const MAX_CTILDE_BYTES: usize = 64;
const MAX_POLYW1_PACKED_BYTES: usize = 192;
const MAX_W1_PACKED_BYTES: usize = MAX_K * MAX_POLYW1_PACKED_BYTES;

const SEED_BYTES: usize = 32;
const CRH_BYTES: usize = 64;
const TR_BYTES: usize = 64;
const RND_BYTES: usize = 32;

const Q: i32 = 8_380_417;
const D: i32 = 13;

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

const QINV: i32 = 58_728_449; // q^(-1) mod 2^32
const INV_NTT_FACTOR: i32 = 41_978; // mont^2 / 256

const ZETAS: [i32; N] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

type Poly = [i32; N];
type UnpackedSecretKey = (
    [u8; SEED_BYTES],
    [u8; TR_BYTES],
    [u8; SEED_BYTES],
    Polyveck,
    Polyvecl,
    Polyveck,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Profile {
    k: usize,
    l: usize,
    eta: i32,
    tau: usize,
    beta: i32,
    gamma1: i32,
    gamma2: i32,
    omega: usize,
    ctilde_bytes: usize,
    polyeta_packed_bytes: usize,
    polyz_packed_bytes: usize,
    polyw1_packed_bytes: usize,
}

impl Profile {
    const POLYT1_PACKED_BYTES: usize = 320;
    const POLYT0_PACKED_BYTES: usize = 416;

    fn public_key_len(self) -> usize {
        SEED_BYTES + self.k * Self::POLYT1_PACKED_BYTES
    }

    fn private_key_len(self) -> usize {
        2 * SEED_BYTES
            + TR_BYTES
            + self.l * self.polyeta_packed_bytes
            + self.k * self.polyeta_packed_bytes
            + self.k * Self::POLYT0_PACKED_BYTES
    }

    fn signature_len(self) -> usize {
        self.ctilde_bytes + self.l * self.polyz_packed_bytes + self.omega + self.k
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Polyvecl {
    vec: [Poly; MAX_L],
    l: usize,
}

impl Polyvecl {
    fn zero(l: usize) -> Self {
        debug_assert!(l <= MAX_L);
        Self {
            vec: [[0i32; N]; MAX_L],
            l,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Polyveck {
    vec: [Poly; MAX_K],
    k: usize,
}

impl Polyveck {
    fn zero(k: usize) -> Self {
        debug_assert!(k <= MAX_K);
        Self {
            vec: [[0i32; N]; MAX_K],
            k,
        }
    }
}

/// ML-DSA parameter sets from FIPS 204.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaParameterSet {
    #[must_use]
    const fn profile(self) -> Profile {
        match self {
            Self::MlDsa44 => Profile {
                k: 4,
                l: 4,
                eta: 2,
                tau: 39,
                beta: 78,
                gamma1: 1 << 17,
                gamma2: (Q - 1) / 88,
                omega: 80,
                ctilde_bytes: 32,
                polyeta_packed_bytes: 96,
                polyz_packed_bytes: 576,
                polyw1_packed_bytes: 192,
            },
            Self::MlDsa65 => Profile {
                k: 6,
                l: 5,
                eta: 4,
                tau: 49,
                beta: 196,
                gamma1: 1 << 19,
                gamma2: (Q - 1) / 32,
                omega: 55,
                ctilde_bytes: 48,
                polyeta_packed_bytes: 128,
                polyz_packed_bytes: 640,
                polyw1_packed_bytes: 128,
            },
            Self::MlDsa87 => Profile {
                k: 8,
                l: 7,
                eta: 2,
                tau: 60,
                beta: 120,
                gamma1: 1 << 19,
                gamma2: (Q - 1) / 32,
                omega: 75,
                ctilde_bytes: 64,
                polyeta_packed_bytes: 96,
                polyz_packed_bytes: 640,
                polyw1_packed_bytes: 128,
            },
        }
    }

    #[must_use]
    const fn id(self) -> u8 {
        match self {
            Self::MlDsa44 => 0x44,
            Self::MlDsa65 => 0x65,
            Self::MlDsa87 => 0x87,
        }
    }

    #[must_use]
    const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x44 => Some(Self::MlDsa44),
            0x65 => Some(Self::MlDsa65),
            0x87 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Public-key byte length.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Secret-key byte length.
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Signature byte length.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// ML-DSA public key.
pub struct MlDsaPublicKey {
    params: MlDsaParameterSet,
    bytes: Vec<u8>,
    expanded: OnceLock<Option<CachedPublicKey>>,
}

/// ML-DSA private key.
pub struct MlDsaPrivateKey {
    params: MlDsaParameterSet,
    bytes: Vec<u8>,
    expanded: OnceLock<Option<CachedPrivateKey>>,
}

/// ML-DSA signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlDsaSignature {
    params: MlDsaParameterSet,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct CachedPublicKey {
    tr: [u8; TR_BYTES],
    t1_shift_ntt: Polyveck,
    mat: [Polyvecl; MAX_K],
}

#[derive(Clone)]
struct CachedPrivateKey {
    tr: [u8; TR_BYTES],
    key: [u8; SEED_BYTES],
    t0_ntt: Polyveck,
    s1_ntt: Polyvecl,
    s2_ntt: Polyveck,
    mat: [Polyvecl; MAX_K],
}

fn zeroize_poly(poly: &mut Poly) {
    crate::ct::zeroize_slice(poly.as_mut_slice());
}

fn zeroize_polyvecl(polyvec: &mut Polyvecl) {
    for poly in polyvec.vec.iter_mut() {
        zeroize_poly(poly);
    }
    polyvec.l = 0;
}

fn zeroize_polyveck(polyvec: &mut Polyveck) {
    for poly in polyvec.vec.iter_mut() {
        zeroize_poly(poly);
    }
    polyvec.k = 0;
}

fn zeroize_cached_private_key(cache: &mut CachedPrivateKey) {
    crate::ct::zeroize_slice(cache.tr.as_mut_slice());
    crate::ct::zeroize_slice(cache.key.as_mut_slice());
    zeroize_polyveck(&mut cache.t0_ntt);
    zeroize_polyvecl(&mut cache.s1_ntt);
    zeroize_polyveck(&mut cache.s2_ntt);
    for mat_row in cache.mat.iter_mut() {
        zeroize_polyvecl(mat_row);
    }
}

/// Namespace wrapper for ML-DSA operations.
pub struct MlDsa;

impl Clone for MlDsaPublicKey {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
            bytes: self.bytes.clone(),
            expanded: OnceLock::new(),
        }
    }
}

impl PartialEq for MlDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params && self.bytes == other.bytes
    }
}

impl Eq for MlDsaPublicKey {}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPublicKey")
            .field("params", &self.params)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl Clone for MlDsaPrivateKey {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
            bytes: self.bytes.clone(),
            expanded: OnceLock::new(),
        }
    }
}

impl PartialEq for MlDsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params && self.bytes == other.bytes
    }
}

impl Eq for MlDsaPrivateKey {}

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        // WHAT: wipe the serialized secret key bytes.
        // WHY: this buffer is the canonical ML-DSA private key material.
        crate::ct::zeroize_slice(self.bytes.as_mut_slice());

        // WHAT: wipe expanded signing cache if it has been initialized.
        // WHY: the cache contains derived secret polynomials and seeds.
        if let Some(cache_opt) = self.expanded.get_mut() {
            if let Some(cache) = cache_opt.as_mut() {
                zeroize_cached_private_key(cache);
            }
            *cache_opt = None;
        }
    }
}

impl MlDsaPublicKey {
    fn expanded(&self) -> Option<&CachedPublicKey> {
        // WHAT: lazily cache parsed/expanded public-key state (rho, tr, A-matrix, shifted+NTT t1).
        // WHY: verify() is often called many times per key; redoing unpack/expand every call is avoidable work.
        self.expanded
            .get_or_init(|| {
                let p = self.params.profile();
                let (rho, mut t1) = unpack_pk(p, &self.bytes)?;
                let mut tr = [0u8; TR_BYTES];
                shake256_absorb_squeeze(&[&self.bytes], &mut tr);
                polyveck_shiftl(&mut t1);
                polyveck_ntt(&mut t1);
                let mat = polyvec_matrix_expand(p, &rho);
                Some(CachedPublicKey {
                    tr,
                    t1_shift_ntt: t1,
                    mat,
                })
            })
            .as_ref()
    }

    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlDsaParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.public_key_len() {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
            expanded: OnceLock::new(),
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
        let params = MlDsaParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }
}

impl MlDsaPrivateKey {
    fn expanded(&self) -> Option<&CachedPrivateKey> {
        // WHAT: lazily cache parsed/expanded private-key state (A-matrix and NTT-domain secret vectors).
        // WHY: repeated signing with the same key should reuse deterministic precomputation safely.
        self.expanded
            .get_or_init(|| {
                let p = self.params.profile();
                let (rho, tr, key, mut t0, mut s1, mut s2) = unpack_sk(p, &self.bytes)?;
                let mat = polyvec_matrix_expand(p, &rho);
                polyvecl_ntt(&mut s1);
                polyveck_ntt(&mut s2);
                polyveck_ntt(&mut t0);
                Some(CachedPrivateKey {
                    tr,
                    key,
                    t0_ntt: t0,
                    s1_ntt: s1,
                    s2_ntt: s2,
                    mat,
                })
            })
            .as_ref()
    }

    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlDsaParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.private_key_len() {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
            expanded: OnceLock::new(),
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
        let params = MlDsaParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }
}

impl MlDsaSignature {
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlDsaParameterSet, bytes: &[u8]) -> Option<Self> {
        let p = params.profile();
        if bytes.len() != params.signature_len() {
            return None;
        }
        unpack_sig(p, bytes).map(|_| Self {
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
        let params = MlDsaParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }
}

impl MlDsa {
    /// Deterministic key generation from a caller-provided seed.
    #[must_use]
    pub fn keygen_from_seed(
        params: MlDsaParameterSet,
        seed: &[u8; SEED_BYTES],
    ) -> Option<(MlDsaPublicKey, MlDsaPrivateKey)> {
        let p = params.profile();
        let mut inbuf = [0u8; SEED_BYTES + 2];
        inbuf[..SEED_BYTES].copy_from_slice(seed);
        inbuf[SEED_BYTES] = p.k as u8;
        inbuf[SEED_BYTES + 1] = p.l as u8;

        let mut seedbuf = [0u8; 2 * SEED_BYTES + CRH_BYTES];
        shake256_absorb_squeeze(&[&inbuf], &mut seedbuf);
        let mut rho = [0u8; SEED_BYTES];
        rho.copy_from_slice(&seedbuf[..SEED_BYTES]);
        let mut rhoprime = [0u8; CRH_BYTES];
        rhoprime.copy_from_slice(&seedbuf[SEED_BYTES..SEED_BYTES + CRH_BYTES]);
        let mut key = [0u8; SEED_BYTES];
        key.copy_from_slice(&seedbuf[SEED_BYTES + CRH_BYTES..]);

        let mat = polyvec_matrix_expand(p, &rho);
        let s1 = polyvecl_uniform_eta(p, &rhoprime, 0);
        let s2 = polyveck_uniform_eta(p, &rhoprime, p.l as u16);

        let mut s1hat = s1.clone();
        polyvecl_ntt(&mut s1hat);
        let mut t1 = polyvec_matrix_pointwise_montgomery(p, &mat, &s1hat);
        polyveck_reduce(&mut t1);
        polyveck_invntt_tomont(&mut t1);
        polyveck_add_assign(&mut t1, &s2);
        polyveck_caddq(&mut t1);

        let (t1_hi, t0) = polyveck_power2round(p, &t1);
        let pk_bytes = pack_pk(p, &rho, &t1_hi);

        let mut tr = [0u8; TR_BYTES];
        shake256_absorb_squeeze(&[&pk_bytes], &mut tr);
        let sk_bytes = pack_sk(p, &rho, &tr, &key, &t0, &s1, &s2);

        Some((
            MlDsaPublicKey {
                params,
                bytes: pk_bytes,
                expanded: OnceLock::new(),
            },
            MlDsaPrivateKey {
                params,
                bytes: sk_bytes,
                expanded: OnceLock::new(),
            },
        ))
    }

    /// Randomized key generation.
    #[must_use]
    pub fn keygen<R: Csprng>(
        params: MlDsaParameterSet,
        rng: &mut R,
    ) -> Option<(MlDsaPublicKey, MlDsaPrivateKey)> {
        let mut seed = [0u8; SEED_BYTES];
        rng.fill_bytes(&mut seed);
        Self::keygen_from_seed(params, &seed)
    }

    /// Sign using caller-provided randomness and explicit context.
    ///
    /// Context length must be <= 255 bytes.
    #[must_use]
    pub fn sign_with_randomness_and_context(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        randomness: &[u8; RND_BYTES],
        context: &[u8],
    ) -> Option<MlDsaSignature> {
        let p = private_key.params.profile();
        let mut pre_buf = [0u8; MAX_PRE_BYTES];
        let pre = build_pre_into(context, &mut pre_buf)?;
        let expanded = private_key.expanded()?;

        let mut mu = [0u8; CRH_BYTES];
        shake256_absorb_squeeze(&[&expanded.tr, pre, message], &mut mu);

        let mut rhoprime = [0u8; CRH_BYTES];
        shake256_absorb_squeeze(&[&expanded.key, randomness, &mu], &mut rhoprime);

        let mut nonce = 0u16;
        let mut w1_packed = [0u8; MAX_W1_PACKED_BYTES];
        let mut c = [0u8; MAX_CTILDE_BYTES];
        loop {
            // WHAT: sample candidate y and attempt one Fiat-Shamir signature round.
            // WHY: Dilithium signing is rejection-based; out-of-bound intermediates must be retried.
            let y = polyvecl_uniform_gamma1(p, &rhoprime, nonce);
            nonce = nonce.wrapping_add(1);

            let mut z = y.clone();
            polyvecl_ntt(&mut z);
            let mut w1 = polyvec_matrix_pointwise_montgomery(p, &expanded.mat, &z);
            polyveck_reduce(&mut w1);
            polyveck_invntt_tomont(&mut w1);

            polyveck_caddq(&mut w1);
            let (w1_hi, mut w0) = polyveck_decompose(p, &w1);
            let w1_packed_len = p.k * p.polyw1_packed_bytes;
            let w1_packed = &mut w1_packed[..w1_packed_len];
            polyveck_pack_w1_into(p, &w1_hi, w1_packed);

            let c = &mut c[..p.ctilde_bytes];
            shake256_absorb_squeeze(&[&mu, w1_packed], c);
            let mut cp = poly_challenge(p, c);
            poly_ntt(&mut cp);

            let mut z = polyvecl_pointwise_poly_montgomery(p, &cp, &expanded.s1_ntt);
            polyvecl_invntt_tomont(&mut z);
            polyvecl_add_assign(&mut z, &y);
            polyvecl_reduce(&mut z);
            if polyvecl_chknorm(&z, p.gamma1 - p.beta) {
                continue;
            }

            let mut h = polyveck_pointwise_poly_montgomery(p, &cp, &expanded.s2_ntt);
            polyveck_invntt_tomont(&mut h);
            polyveck_sub_assign(&mut w0, &h);
            polyveck_reduce(&mut w0);
            if polyveck_chknorm(&w0, p.gamma2 - p.beta) {
                continue;
            }

            let mut h = polyveck_pointwise_poly_montgomery(p, &cp, &expanded.t0_ntt);
            polyveck_invntt_tomont(&mut h);
            polyveck_reduce(&mut h);
            if polyveck_chknorm(&h, p.gamma2) {
                continue;
            }

            polyveck_add_assign(&mut w0, &h);
            let (hint, n) = polyveck_make_hint(p, &w0, &w1_hi);
            // WHAT: reject signatures whose hint weight exceeds omega.
            // WHY: omega is part of the wire-format validity contract and verifier cost bound.
            if n > p.omega {
                continue;
            }

            let sig_bytes = pack_sig(p, c, &z, &hint);
            return Some(MlDsaSignature {
                params: private_key.params,
                bytes: sig_bytes,
            });
        }
    }

    /// Deterministic signing with caller-provided randomness and empty context.
    #[must_use]
    pub fn sign_with_randomness(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        randomness: &[u8; RND_BYTES],
    ) -> Option<MlDsaSignature> {
        Self::sign_with_randomness_and_context(private_key, message, randomness, b"")
    }

    /// Randomized signing with empty context.
    #[must_use]
    pub fn sign<R: Csprng>(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Option<MlDsaSignature> {
        let mut randomness = [0u8; RND_BYTES];
        rng.fill_bytes(&mut randomness);
        Self::sign_with_randomness(private_key, message, &randomness)
    }

    /// Verify with explicit context.
    #[must_use]
    pub fn verify_with_context(
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
        context: &[u8],
    ) -> bool {
        if public_key.params != signature.params {
            return false;
        }
        let p = public_key.params.profile();
        let mut pre_buf = [0u8; MAX_PRE_BYTES];
        let pre = match build_pre_into(context, &mut pre_buf) {
            Some(pre) => pre,
            None => return false,
        };
        let expanded = match public_key.expanded() {
            Some(v) => v,
            None => return false,
        };
        let (c, mut z, h) = match unpack_sig(p, &signature.bytes) {
            Some(v) => v,
            None => return false,
        };
        if polyvecl_chknorm(&z, p.gamma1 - p.beta) {
            return false;
        }

        let mut mu = [0u8; CRH_BYTES];
        shake256_absorb_squeeze(&[&expanded.tr, pre, message], &mut mu);

        let mut cp = poly_challenge(p, &c);

        polyvecl_ntt(&mut z);
        let mut w1 = polyvec_matrix_pointwise_montgomery(p, &expanded.mat, &z);

        poly_ntt(&mut cp);
        let t1_cp = polyveck_pointwise_poly_montgomery(p, &cp, &expanded.t1_shift_ntt);

        polyveck_sub_assign(&mut w1, &t1_cp);
        polyveck_reduce(&mut w1);
        polyveck_invntt_tomont(&mut w1);

        polyveck_caddq(&mut w1);
        let w1 = polyveck_use_hint(p, &w1, &h);
        let mut packed_w1 = [0u8; MAX_W1_PACKED_BYTES];
        let packed_w1 = &mut packed_w1[..p.k * p.polyw1_packed_bytes];
        polyveck_pack_w1_into(p, &w1, packed_w1);

        let mut c2 = [0u8; MAX_CTILDE_BYTES];
        let c2 = &mut c2[..p.ctilde_bytes];
        shake256_absorb_squeeze(&[&mu, packed_w1], c2);
        // WHAT: recompute challenge from reconstructed w1 and compare to signature c.
        // WHY: this is the core FS consistency check that binds (z, h) to the message and public key.
        // The comparison is constant-time as side-channel hygiene, even though
        // verification inputs are public.
        crate::ct::constant_time_eq_mask(c.as_slice(), c2) == u8::MAX
    }

    /// Verify with empty context.
    #[must_use]
    pub fn verify(public_key: &MlDsaPublicKey, message: &[u8], signature: &MlDsaSignature) -> bool {
        Self::verify_with_context(public_key, message, signature, b"")
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaPrivateKey(<redacted>)")
    }
}

fn build_pre_into<'a>(context: &[u8], out: &'a mut [u8; MAX_PRE_BYTES]) -> Option<&'a [u8]> {
    if context.len() > MAX_CONTEXT_BYTES {
        return None;
    }
    // WHAT: encode context as [0x00 || len || context].
    // WHY: FIPS 204 signs a framed context string, not raw context bytes.
    out[0] = 0;
    out[1] = context.len() as u8;
    out[2..2 + context.len()].copy_from_slice(context);
    Some(&out[..2 + context.len()])
}

fn shake256_absorb_squeeze(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = Shake256::new();
    for part in parts {
        xof.update(part);
    }
    xof.squeeze(out);
}

#[inline(always)]
fn montgomery_reduce(a: i64) -> i32 {
    let t = ((a as i32 as i64) * (QINV as i64)) as i32;
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

#[inline(always)]
fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

#[inline(always)]
fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

fn power2round(a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    let a0 = a - (a1 << D);
    (a1, a0)
}

fn decompose(p: Profile, a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;
    if p.gamma2 == (Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        a1 = (a1 * 11_275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    let mut a0 = a - a1 * 2 * p.gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

fn make_hint(p: Profile, a0: i32, a1: i32) -> i32 {
    if a0 > p.gamma2 || a0 < -p.gamma2 || (a0 == -p.gamma2 && a1 != 0) {
        1
    } else {
        0
    }
}

fn use_hint(p: Profile, a: i32, hint: i32) -> i32 {
    let (a1, a0) = decompose(p, a);
    if hint == 0 {
        return a1;
    }
    if p.gamma2 == (Q - 1) / 32 {
        if a0 > 0 {
            (a1 + 1) & 15
        } else {
            (a1 - 1) & 15
        }
    } else if a0 > 0 {
        if a1 == 43 {
            0
        } else {
            a1 + 1
        }
    } else if a1 == 0 {
        43
    } else {
        a1 - 1
    }
}

fn poly_reduce(poly: &mut Poly) {
    for c in poly.iter_mut() {
        *c = reduce32(*c);
    }
}

fn poly_caddq(poly: &mut Poly) {
    for c in poly.iter_mut() {
        *c = caddq(*c);
    }
}

#[inline(always)]
fn poly_add_assign(dst: &mut Poly, rhs: &Poly) {
    for i in 0..N {
        dst[i] += rhs[i];
    }
}

#[inline(always)]
fn poly_sub_assign(dst: &mut Poly, rhs: &Poly) {
    for i in 0..N {
        dst[i] -= rhs[i];
    }
}

fn poly_shiftl(poly: &mut Poly) {
    for c in poly.iter_mut() {
        *c <<= D;
    }
}

fn poly_ntt(poly: &mut Poly) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len > 0 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            for j in start..(start + len) {
                let t = montgomery_reduce((zeta as i64) * (poly[j + len] as i64));
                poly[j + len] = poly[j] - t;
                poly[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn poly_invntt_tomont(poly: &mut Poly) {
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            for j in start..(start + len) {
                let t = poly[j];
                poly[j] = t + poly[j + len];
                poly[j + len] = t - poly[j + len];
                poly[j + len] = montgomery_reduce((zeta as i64) * (poly[j + len] as i64));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in poly.iter_mut() {
        *c = montgomery_reduce((INV_NTT_FACTOR as i64) * (*c as i64));
    }
}

#[inline(always)]
fn poly_pointwise_montgomery(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i32; N];
    for i in 0..N {
        out[i] = montgomery_reduce((a[i] as i64) * (b[i] as i64));
    }
    out
}

fn poly_power2round(poly: &Poly) -> (Poly, Poly) {
    let mut hi = [0i32; N];
    let mut lo = [0i32; N];
    for i in 0..N {
        let (a1, a0) = power2round(poly[i]);
        hi[i] = a1;
        lo[i] = a0;
    }
    (hi, lo)
}

fn poly_decompose(p: Profile, poly: &Poly) -> (Poly, Poly) {
    let mut hi = [0i32; N];
    let mut lo = [0i32; N];
    for i in 0..N {
        let (a1, a0) = decompose(p, poly[i]);
        hi[i] = a1;
        lo[i] = a0;
    }
    (hi, lo)
}

fn poly_make_hint(p: Profile, a0: &Poly, a1: &Poly) -> (Poly, usize) {
    let mut h = [0i32; N];
    let mut s = 0usize;
    for i in 0..N {
        h[i] = make_hint(p, a0[i], a1[i]);
        s += h[i] as usize;
    }
    (h, s)
}

fn poly_use_hint(p: Profile, a: &Poly, h: &Poly) -> Poly {
    let mut out = [0i32; N];
    for i in 0..N {
        out[i] = use_hint(p, a[i], h[i]);
    }
    out
}

fn poly_chknorm(poly: &Poly, bound: i32) -> bool {
    if bound > (Q - 1) / 8 {
        return true;
    }
    for c in poly {
        let t = c - ((c >> 31) & (2 * c));
        if t >= bound {
            return true;
        }
    }
    false
}

fn rej_uniform(dst: &mut [i32], len: usize, buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos + 3 <= buf.len() {
        let mut t = u32::from(buf[pos]);
        pos += 1;
        t |= u32::from(buf[pos]) << 8;
        pos += 1;
        t |= u32::from(buf[pos]) << 16;
        pos += 1;
        t &= 0x7F_FFFF;
        if t < Q as u32 {
            dst[ctr] = t as i32;
            ctr += 1;
        }
    }
    ctr
}

fn poly_uniform(seed: &[u8; SEED_BYTES], nonce: u16) -> Poly {
    const POLY_UNIFORM_NBLOCKS: usize = 768_usize.div_ceil(SHAKE128_RATE);
    let mut xof = Shake128::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());

    let mut buf = [0u8; POLY_UNIFORM_NBLOCKS * SHAKE128_RATE + 2];
    let mut buflen = POLY_UNIFORM_NBLOCKS * SHAKE128_RATE;
    xof.squeeze(&mut buf[..buflen]);

    let mut out = [0i32; N];
    let mut ctr = rej_uniform(&mut out, N, &buf[..buflen]);
    while ctr < N {
        let off = buflen % 3;
        for i in 0..off {
            buf[i] = buf[buflen - off + i];
        }
        xof.squeeze(&mut buf[off..off + SHAKE128_RATE]);
        buflen = SHAKE128_RATE + off;
        ctr += rej_uniform(&mut out[ctr..], N - ctr, &buf[..buflen]);
    }
    out
}

fn rej_eta(dst: &mut [i32], len: usize, buf: &[u8], eta: i32) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos < buf.len() {
        let mut t0 = i32::from(buf[pos] & 0x0F);
        let mut t1 = i32::from(buf[pos] >> 4);
        pos += 1;

        if eta == 2 {
            if t0 < 15 {
                t0 = t0 - ((205 * t0) >> 10) * 5;
                dst[ctr] = 2 - t0;
                ctr += 1;
            }
            if t1 < 15 && ctr < len {
                t1 = t1 - ((205 * t1) >> 10) * 5;
                dst[ctr] = 2 - t1;
                ctr += 1;
            }
        } else {
            if t0 < 9 {
                dst[ctr] = 4 - t0;
                ctr += 1;
            }
            if t1 < 9 && ctr < len {
                dst[ctr] = 4 - t1;
                ctr += 1;
            }
        }
    }
    ctr
}

fn poly_uniform_eta(p: Profile, seed: &[u8; CRH_BYTES], nonce: u16) -> Poly {
    let req: usize = if p.eta == 2 { 136 } else { 227 };
    let nblocks = req.div_ceil(SHAKE256_RATE);
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());

    let mut buf = [0u8; 2 * SHAKE256_RATE];
    let buflen = nblocks * SHAKE256_RATE;
    xof.squeeze(&mut buf[..buflen]);

    let mut out = [0i32; N];
    let mut ctr = rej_eta(&mut out, N, &buf[..buflen], p.eta);
    while ctr < N {
        xof.squeeze(&mut buf[..SHAKE256_RATE]);
        ctr += rej_eta(&mut out[ctr..], N - ctr, &buf[..SHAKE256_RATE], p.eta);
    }
    out
}

fn poly_uniform_gamma1(p: Profile, seed: &[u8; CRH_BYTES], nonce: u16) -> Poly {
    let nblocks = p.polyz_packed_bytes.div_ceil(SHAKE256_RATE);
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut buf = [0u8; 5 * SHAKE256_RATE];
    xof.squeeze(&mut buf[..nblocks * SHAKE256_RATE]);
    polyz_unpack(p, &buf[..p.polyz_packed_bytes]).expect("polyz unpack in gamma1 sampler")
}

fn poly_challenge(p: Profile, seed: &[u8]) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    let mut buf = [0u8; SHAKE256_RATE];
    xof.squeeze(&mut buf);

    let mut signs = 0u64;
    for (i, b) in buf.iter().enumerate().take(8) {
        signs |= u64::from(*b) << (8 * i);
    }
    let mut pos = 8usize;
    let mut out = [0i32; N];
    for i in (N - p.tau)..N {
        let b = loop {
            if pos >= SHAKE256_RATE {
                xof.squeeze(&mut buf);
                pos = 0;
            }
            let b = usize::from(buf[pos]);
            pos += 1;
            if b <= i {
                break b;
            }
        };
        out[i] = out[b];
        out[b] = 1 - 2 * (signs as i32 & 1);
        signs >>= 1;
    }
    out
}

fn polyeta_pack(p: Profile, poly: &Poly, out: &mut [u8]) {
    if p.eta == 2 {
        for i in 0..(N / 8) {
            let t0 = (p.eta - poly[8 * i]) as u8;
            let t1 = (p.eta - poly[8 * i + 1]) as u8;
            let t2 = (p.eta - poly[8 * i + 2]) as u8;
            let t3 = (p.eta - poly[8 * i + 3]) as u8;
            let t4 = (p.eta - poly[8 * i + 4]) as u8;
            let t5 = (p.eta - poly[8 * i + 5]) as u8;
            let t6 = (p.eta - poly[8 * i + 6]) as u8;
            let t7 = (p.eta - poly[8 * i + 7]) as u8;
            out[3 * i] = t0 | (t1 << 3) | (t2 << 6);
            out[3 * i + 1] = (t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7);
            out[3 * i + 2] = (t5 >> 1) | (t6 << 2) | (t7 << 5);
        }
    } else {
        for i in 0..(N / 2) {
            let t0 = (p.eta - poly[2 * i]) as u8;
            let t1 = (p.eta - poly[2 * i + 1]) as u8;
            out[i] = t0 | (t1 << 4);
        }
    }
}

fn polyeta_unpack(p: Profile, input: &[u8]) -> Option<Poly> {
    if input.len() != p.polyeta_packed_bytes {
        return None;
    }
    let mut out = [0i32; N];
    if p.eta == 2 {
        for i in 0..(N / 8) {
            out[8 * i] = i32::from(input[3 * i] & 7);
            out[8 * i + 1] = i32::from((input[3 * i] >> 3) & 7);
            out[8 * i + 2] = i32::from(((input[3 * i] >> 6) | (input[3 * i + 1] << 2)) & 7);
            out[8 * i + 3] = i32::from((input[3 * i + 1] >> 1) & 7);
            out[8 * i + 4] = i32::from((input[3 * i + 1] >> 4) & 7);
            out[8 * i + 5] = i32::from(((input[3 * i + 1] >> 7) | (input[3 * i + 2] << 1)) & 7);
            out[8 * i + 6] = i32::from((input[3 * i + 2] >> 2) & 7);
            out[8 * i + 7] = i32::from((input[3 * i + 2] >> 5) & 7);
            for j in 0..8 {
                out[8 * i + j] = p.eta - out[8 * i + j];
            }
        }
    } else {
        for i in 0..(N / 2) {
            out[2 * i] = i32::from(input[i] & 0x0F);
            out[2 * i + 1] = i32::from(input[i] >> 4);
            out[2 * i] = p.eta - out[2 * i];
            out[2 * i + 1] = p.eta - out[2 * i + 1];
        }
    }
    Some(out)
}

fn polyt1_pack(poly: &Poly, out: &mut [u8]) {
    for i in 0..(N / 4) {
        out[5 * i] = poly[4 * i] as u8;
        out[5 * i + 1] = ((poly[4 * i] >> 8) | (poly[4 * i + 1] << 2)) as u8;
        out[5 * i + 2] = ((poly[4 * i + 1] >> 6) | (poly[4 * i + 2] << 4)) as u8;
        out[5 * i + 3] = ((poly[4 * i + 2] >> 4) | (poly[4 * i + 3] << 6)) as u8;
        out[5 * i + 4] = (poly[4 * i + 3] >> 2) as u8;
    }
}

fn polyt1_unpack(input: &[u8]) -> Option<Poly> {
    if input.len() != Profile::POLYT1_PACKED_BYTES {
        return None;
    }
    let mut out = [0i32; N];
    for i in 0..(N / 4) {
        out[4 * i] =
            ((u32::from(input[5 * i]) | (u32::from(input[5 * i + 1]) << 8)) as i32) & 0x3FF;
        out[4 * i + 1] = (((u32::from(input[5 * i + 1])) >> 2)
            | ((u32::from(input[5 * i + 2])) << 6)) as i32
            & 0x3FF;
        out[4 * i + 2] = (((u32::from(input[5 * i + 2])) >> 4)
            | ((u32::from(input[5 * i + 3])) << 4)) as i32
            & 0x3FF;
        out[4 * i + 3] = (((u32::from(input[5 * i + 3])) >> 6)
            | ((u32::from(input[5 * i + 4])) << 2)) as i32
            & 0x3FF;
    }
    Some(out)
}

fn polyt0_pack(poly: &Poly, out: &mut [u8]) {
    for i in 0..(N / 8) {
        let mut t = [0u32; 8];
        for j in 0..8 {
            t[j] = ((1 << (D - 1)) - poly[8 * i + j]) as u32;
        }

        out[13 * i] = t[0] as u8;
        out[13 * i + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
        out[13 * i + 2] = (t[1] >> 3) as u8;
        out[13 * i + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
        out[13 * i + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
        out[13 * i + 5] = (t[3] >> 1) as u8;
        out[13 * i + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
        out[13 * i + 7] = (t[4] >> 4) as u8;
        out[13 * i + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
        out[13 * i + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
        out[13 * i + 10] = (t[6] >> 2) as u8;
        out[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
        out[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

fn polyt0_unpack(input: &[u8]) -> Option<Poly> {
    if input.len() != Profile::POLYT0_PACKED_BYTES {
        return None;
    }
    let mut out = [0i32; N];
    for i in 0..(N / 8) {
        out[8 * i] =
            (u32::from(input[13 * i]) | (u32::from(input[13 * i + 1]) << 8)) as i32 & 0x1FFF;
        out[8 * i + 1] = ((u32::from(input[13 * i + 1]) >> 5)
            | (u32::from(input[13 * i + 2]) << 3)
            | (u32::from(input[13 * i + 3]) << 11)) as i32
            & 0x1FFF;
        out[8 * i + 2] = ((u32::from(input[13 * i + 3]) >> 2) | (u32::from(input[13 * i + 4]) << 6))
            as i32
            & 0x1FFF;
        out[8 * i + 3] = ((u32::from(input[13 * i + 4]) >> 7)
            | (u32::from(input[13 * i + 5]) << 1)
            | (u32::from(input[13 * i + 6]) << 9)) as i32
            & 0x1FFF;
        out[8 * i + 4] = ((u32::from(input[13 * i + 6]) >> 4)
            | (u32::from(input[13 * i + 7]) << 4)
            | (u32::from(input[13 * i + 8]) << 12)) as i32
            & 0x1FFF;
        out[8 * i + 5] = ((u32::from(input[13 * i + 8]) >> 1) | (u32::from(input[13 * i + 9]) << 7))
            as i32
            & 0x1FFF;
        out[8 * i + 6] = ((u32::from(input[13 * i + 9]) >> 6)
            | (u32::from(input[13 * i + 10]) << 2)
            | (u32::from(input[13 * i + 11]) << 10)) as i32
            & 0x1FFF;
        out[8 * i + 7] = ((u32::from(input[13 * i + 11]) >> 3)
            | (u32::from(input[13 * i + 12]) << 5)) as i32
            & 0x1FFF;
        for j in 0..8 {
            out[8 * i + j] = (1 << (D - 1)) - out[8 * i + j];
        }
    }
    Some(out)
}

fn polyz_pack(p: Profile, poly: &Poly, out: &mut [u8]) {
    if p.gamma1 == (1 << 17) {
        for i in 0..(N / 4) {
            let t0 = (p.gamma1 - poly[4 * i]) as u32;
            let t1 = (p.gamma1 - poly[4 * i + 1]) as u32;
            let t2 = (p.gamma1 - poly[4 * i + 2]) as u32;
            let t3 = (p.gamma1 - poly[4 * i + 3]) as u32;
            out[9 * i] = t0 as u8;
            out[9 * i + 1] = (t0 >> 8) as u8;
            out[9 * i + 2] = ((t0 >> 16) | (t1 << 2)) as u8;
            out[9 * i + 3] = (t1 >> 6) as u8;
            out[9 * i + 4] = ((t1 >> 14) | (t2 << 4)) as u8;
            out[9 * i + 5] = (t2 >> 4) as u8;
            out[9 * i + 6] = ((t2 >> 12) | (t3 << 6)) as u8;
            out[9 * i + 7] = (t3 >> 2) as u8;
            out[9 * i + 8] = (t3 >> 10) as u8;
        }
    } else {
        for i in 0..(N / 2) {
            let t0 = (p.gamma1 - poly[2 * i]) as u32;
            let t1 = (p.gamma1 - poly[2 * i + 1]) as u32;
            out[5 * i] = t0 as u8;
            out[5 * i + 1] = (t0 >> 8) as u8;
            out[5 * i + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
            out[5 * i + 3] = (t1 >> 4) as u8;
            out[5 * i + 4] = (t1 >> 12) as u8;
        }
    }
}

fn polyz_unpack(p: Profile, input: &[u8]) -> Option<Poly> {
    if input.len() != p.polyz_packed_bytes {
        return None;
    }
    let mut out = [0i32; N];
    if p.gamma1 == (1 << 17) {
        for i in 0..(N / 4) {
            out[4 * i] = (u32::from(input[9 * i])
                | (u32::from(input[9 * i + 1]) << 8)
                | (u32::from(input[9 * i + 2]) << 16)) as i32
                & 0x3FFFF;
            out[4 * i + 1] = ((u32::from(input[9 * i + 2]) >> 2)
                | (u32::from(input[9 * i + 3]) << 6)
                | (u32::from(input[9 * i + 4]) << 14)) as i32
                & 0x3FFFF;
            out[4 * i + 2] = ((u32::from(input[9 * i + 4]) >> 4)
                | (u32::from(input[9 * i + 5]) << 4)
                | (u32::from(input[9 * i + 6]) << 12)) as i32
                & 0x3FFFF;
            out[4 * i + 3] = ((u32::from(input[9 * i + 6]) >> 6)
                | (u32::from(input[9 * i + 7]) << 2)
                | (u32::from(input[9 * i + 8]) << 10)) as i32
                & 0x3FFFF;
            out[4 * i] = p.gamma1 - out[4 * i];
            out[4 * i + 1] = p.gamma1 - out[4 * i + 1];
            out[4 * i + 2] = p.gamma1 - out[4 * i + 2];
            out[4 * i + 3] = p.gamma1 - out[4 * i + 3];
        }
    } else {
        for i in 0..(N / 2) {
            out[2 * i] = (u32::from(input[5 * i])
                | (u32::from(input[5 * i + 1]) << 8)
                | (u32::from(input[5 * i + 2]) << 16)) as i32
                & 0xFFFFF;
            out[2 * i + 1] = ((u32::from(input[5 * i + 2]) >> 4)
                | (u32::from(input[5 * i + 3]) << 4)
                | (u32::from(input[5 * i + 4]) << 12)) as i32;
            out[2 * i] = p.gamma1 - out[2 * i];
            out[2 * i + 1] = p.gamma1 - out[2 * i + 1];
        }
    }
    Some(out)
}

fn polyw1_pack(p: Profile, poly: &Poly, out: &mut [u8]) {
    if p.gamma2 == (Q - 1) / 88 {
        for i in 0..(N / 4) {
            out[3 * i] = (poly[4 * i] | (poly[4 * i + 1] << 6)) as u8;
            out[3 * i + 1] = ((poly[4 * i + 1] >> 2) | (poly[4 * i + 2] << 4)) as u8;
            out[3 * i + 2] = ((poly[4 * i + 2] >> 4) | (poly[4 * i + 3] << 2)) as u8;
        }
    } else {
        for i in 0..(N / 2) {
            out[i] = (poly[2 * i] | (poly[2 * i + 1] << 4)) as u8;
        }
    }
}

fn polyvecl_uniform_eta(p: Profile, seed: &[u8; CRH_BYTES], mut nonce: u16) -> Polyvecl {
    let mut out = Polyvecl::zero(p.l);
    for i in 0..p.l {
        out.vec[i] = poly_uniform_eta(p, seed, nonce);
        nonce = nonce.wrapping_add(1);
    }
    out
}

fn polyvecl_uniform_gamma1(p: Profile, seed: &[u8; CRH_BYTES], nonce: u16) -> Polyvecl {
    let mut out = Polyvecl::zero(p.l);
    for i in 0..p.l {
        let poly_nonce = (p.l as u32 * nonce as u32 + i as u32) as u16;
        out.vec[i] = poly_uniform_gamma1(p, seed, poly_nonce);
    }
    out
}

fn polyvecl_ntt(v: &mut Polyvecl) {
    for i in 0..v.l {
        poly_ntt(&mut v.vec[i]);
    }
}

fn polyvecl_invntt_tomont(v: &mut Polyvecl) {
    for i in 0..v.l {
        poly_invntt_tomont(&mut v.vec[i]);
    }
}

fn polyvecl_reduce(v: &mut Polyvecl) {
    for i in 0..v.l {
        poly_reduce(&mut v.vec[i]);
    }
}

fn polyvecl_add_assign(dst: &mut Polyvecl, rhs: &Polyvecl) {
    debug_assert_eq!(dst.l, rhs.l);
    for i in 0..dst.l {
        poly_add_assign(&mut dst.vec[i], &rhs.vec[i]);
    }
}

fn polyvecl_pointwise_poly_montgomery(p: Profile, a: &Poly, v: &Polyvecl) -> Polyvecl {
    let mut out = Polyvecl::zero(p.l);
    for i in 0..p.l {
        out.vec[i] = poly_pointwise_montgomery(a, &v.vec[i]);
    }
    out
}

fn polyvecl_pointwise_acc_montgomery(p: Profile, u: &Polyvecl, v: &Polyvecl) -> Poly {
    debug_assert_eq!(u.l, p.l);
    debug_assert_eq!(v.l, p.l);
    let mut w = [0i32; N];
    for (j, wj) in w.iter_mut().enumerate() {
        *wj = montgomery_reduce((u.vec[0][j] as i64) * (v.vec[0][j] as i64));
    }
    for i in 1..p.l {
        for (j, wj) in w.iter_mut().enumerate() {
            let t = montgomery_reduce((u.vec[i][j] as i64) * (v.vec[i][j] as i64));
            *wj = wj.wrapping_add(t);
        }
    }
    w
}

fn polyvecl_chknorm(v: &Polyvecl, bound: i32) -> bool {
    for i in 0..v.l {
        if poly_chknorm(&v.vec[i], bound) {
            return true;
        }
    }
    false
}

fn polyveck_uniform_eta(p: Profile, seed: &[u8; CRH_BYTES], mut nonce: u16) -> Polyveck {
    let mut out = Polyveck::zero(p.k);
    for i in 0..p.k {
        out.vec[i] = poly_uniform_eta(p, seed, nonce);
        nonce = nonce.wrapping_add(1);
    }
    out
}

fn polyveck_reduce(v: &mut Polyveck) {
    for i in 0..v.k {
        poly_reduce(&mut v.vec[i]);
    }
}

fn polyveck_caddq(v: &mut Polyveck) {
    for i in 0..v.k {
        poly_caddq(&mut v.vec[i]);
    }
}

fn polyveck_add_assign(dst: &mut Polyveck, rhs: &Polyveck) {
    debug_assert_eq!(dst.k, rhs.k);
    for i in 0..dst.k {
        poly_add_assign(&mut dst.vec[i], &rhs.vec[i]);
    }
}

fn polyveck_sub_assign(dst: &mut Polyveck, rhs: &Polyveck) {
    debug_assert_eq!(dst.k, rhs.k);
    for i in 0..dst.k {
        poly_sub_assign(&mut dst.vec[i], &rhs.vec[i]);
    }
}

fn polyveck_shiftl(v: &mut Polyveck) {
    for i in 0..v.k {
        poly_shiftl(&mut v.vec[i]);
    }
}

fn polyveck_ntt(v: &mut Polyveck) {
    for i in 0..v.k {
        poly_ntt(&mut v.vec[i]);
    }
}

fn polyveck_invntt_tomont(v: &mut Polyveck) {
    for i in 0..v.k {
        poly_invntt_tomont(&mut v.vec[i]);
    }
}

fn polyveck_pointwise_poly_montgomery(p: Profile, a: &Poly, v: &Polyveck) -> Polyveck {
    let mut out = Polyveck::zero(p.k);
    for i in 0..p.k {
        out.vec[i] = poly_pointwise_montgomery(a, &v.vec[i]);
    }
    out
}

fn polyveck_chknorm(v: &Polyveck, bound: i32) -> bool {
    for i in 0..v.k {
        if poly_chknorm(&v.vec[i], bound) {
            return true;
        }
    }
    false
}

fn polyveck_power2round(p: Profile, v: &Polyveck) -> (Polyveck, Polyveck) {
    let mut v1 = Polyveck::zero(p.k);
    let mut v0 = Polyveck::zero(p.k);
    for i in 0..p.k {
        let (hi, lo) = poly_power2round(&v.vec[i]);
        v1.vec[i] = hi;
        v0.vec[i] = lo;
    }
    (v1, v0)
}

fn polyveck_decompose(p: Profile, v: &Polyveck) -> (Polyveck, Polyveck) {
    let mut v1 = Polyveck::zero(p.k);
    let mut v0 = Polyveck::zero(p.k);
    for i in 0..p.k {
        let (hi, lo) = poly_decompose(p, &v.vec[i]);
        v1.vec[i] = hi;
        v0.vec[i] = lo;
    }
    (v1, v0)
}

fn polyveck_make_hint(p: Profile, v0: &Polyveck, v1: &Polyveck) -> (Polyveck, usize) {
    let mut h = Polyveck::zero(p.k);
    let mut s = 0usize;
    for i in 0..p.k {
        let (hp, n) = poly_make_hint(p, &v0.vec[i], &v1.vec[i]);
        h.vec[i] = hp;
        s += n;
    }
    (h, s)
}

fn polyveck_use_hint(p: Profile, u: &Polyveck, h: &Polyveck) -> Polyveck {
    let mut w = Polyveck::zero(p.k);
    for i in 0..p.k {
        w.vec[i] = poly_use_hint(p, &u.vec[i], &h.vec[i]);
    }
    w
}

fn polyveck_pack_w1_into(p: Profile, w1: &Polyveck, out: &mut [u8]) {
    debug_assert_eq!(out.len(), p.k * p.polyw1_packed_bytes);
    for i in 0..p.k {
        polyw1_pack(
            p,
            &w1.vec[i],
            &mut out[i * p.polyw1_packed_bytes..(i + 1) * p.polyw1_packed_bytes],
        );
    }
}

fn polyvec_matrix_expand(p: Profile, rho: &[u8; SEED_BYTES]) -> [Polyvecl; MAX_K] {
    let mut mat = core::array::from_fn(|_| Polyvecl::zero(p.l));
    for (i, row) in mat.iter_mut().enumerate().take(p.k) {
        for j in 0..p.l {
            // WHAT: derive A[i][j] from rho and a unique 16-bit nonce.
            // WHY: deterministic expansion keeps key material compact while preserving domain separation.
            row.vec[j] = poly_uniform(rho, ((i << 8) + j) as u16);
        }
    }
    mat
}

fn polyvec_matrix_pointwise_montgomery(
    p: Profile,
    mat: &[Polyvecl; MAX_K],
    v: &Polyvecl,
) -> Polyveck {
    let mut out = Polyveck::zero(p.k);
    for (i, row) in mat.iter().enumerate().take(p.k) {
        out.vec[i] = polyvecl_pointwise_acc_montgomery(p, row, v);
    }
    out
}

fn pack_pk(p: Profile, rho: &[u8; SEED_BYTES], t1: &Polyveck) -> Vec<u8> {
    let mut out = vec![0u8; p.public_key_len()];
    out[..SEED_BYTES].copy_from_slice(rho);
    let mut pos = SEED_BYTES;
    for i in 0..p.k {
        polyt1_pack(
            &t1.vec[i],
            &mut out[pos..pos + Profile::POLYT1_PACKED_BYTES],
        );
        pos += Profile::POLYT1_PACKED_BYTES;
    }
    out
}

fn unpack_pk(p: Profile, pk: &[u8]) -> Option<([u8; SEED_BYTES], Polyveck)> {
    if pk.len() != p.public_key_len() {
        return None;
    }
    let mut rho = [0u8; SEED_BYTES];
    rho.copy_from_slice(&pk[..SEED_BYTES]);
    let mut t1 = Polyveck::zero(p.k);
    let mut pos = SEED_BYTES;
    for i in 0..p.k {
        t1.vec[i] = polyt1_unpack(&pk[pos..pos + Profile::POLYT1_PACKED_BYTES])?;
        pos += Profile::POLYT1_PACKED_BYTES;
    }
    Some((rho, t1))
}

fn pack_sk(
    p: Profile,
    rho: &[u8; SEED_BYTES],
    tr: &[u8; TR_BYTES],
    key: &[u8; SEED_BYTES],
    t0: &Polyveck,
    s1: &Polyvecl,
    s2: &Polyveck,
) -> Vec<u8> {
    let mut out = vec![0u8; p.private_key_len()];
    let mut pos = 0usize;
    out[pos..pos + SEED_BYTES].copy_from_slice(rho);
    pos += SEED_BYTES;
    out[pos..pos + SEED_BYTES].copy_from_slice(key);
    pos += SEED_BYTES;
    out[pos..pos + TR_BYTES].copy_from_slice(tr);
    pos += TR_BYTES;

    for i in 0..p.l {
        polyeta_pack(p, &s1.vec[i], &mut out[pos..pos + p.polyeta_packed_bytes]);
        pos += p.polyeta_packed_bytes;
    }
    for i in 0..p.k {
        polyeta_pack(p, &s2.vec[i], &mut out[pos..pos + p.polyeta_packed_bytes]);
        pos += p.polyeta_packed_bytes;
    }
    for i in 0..p.k {
        polyt0_pack(
            &t0.vec[i],
            &mut out[pos..pos + Profile::POLYT0_PACKED_BYTES],
        );
        pos += Profile::POLYT0_PACKED_BYTES;
    }
    out
}

fn unpack_sk(p: Profile, sk: &[u8]) -> Option<UnpackedSecretKey> {
    if sk.len() != p.private_key_len() {
        return None;
    }
    let mut pos = 0usize;
    let mut rho = [0u8; SEED_BYTES];
    rho.copy_from_slice(&sk[pos..pos + SEED_BYTES]);
    pos += SEED_BYTES;
    let mut key = [0u8; SEED_BYTES];
    key.copy_from_slice(&sk[pos..pos + SEED_BYTES]);
    pos += SEED_BYTES;
    let mut tr = [0u8; TR_BYTES];
    tr.copy_from_slice(&sk[pos..pos + TR_BYTES]);
    pos += TR_BYTES;

    let mut s1 = Polyvecl::zero(p.l);
    for i in 0..p.l {
        s1.vec[i] = polyeta_unpack(p, &sk[pos..pos + p.polyeta_packed_bytes])?;
        pos += p.polyeta_packed_bytes;
    }
    let mut s2 = Polyveck::zero(p.k);
    for i in 0..p.k {
        s2.vec[i] = polyeta_unpack(p, &sk[pos..pos + p.polyeta_packed_bytes])?;
        pos += p.polyeta_packed_bytes;
    }
    let mut t0 = Polyveck::zero(p.k);
    for i in 0..p.k {
        t0.vec[i] = polyt0_unpack(&sk[pos..pos + Profile::POLYT0_PACKED_BYTES])?;
        pos += Profile::POLYT0_PACKED_BYTES;
    }
    Some((rho, tr, key, t0, s1, s2))
}

fn pack_sig(p: Profile, c: &[u8], z: &Polyvecl, h: &Polyveck) -> Vec<u8> {
    debug_assert_eq!(c.len(), p.ctilde_bytes);
    let mut out = vec![0u8; p.signature_len()];
    let mut pos = 0usize;
    out[pos..pos + p.ctilde_bytes].copy_from_slice(c);
    pos += p.ctilde_bytes;
    for i in 0..p.l {
        polyz_pack(p, &z.vec[i], &mut out[pos..pos + p.polyz_packed_bytes]);
        pos += p.polyz_packed_bytes;
    }

    let hint_pos = pos;
    let mut k = 0usize;
    for i in 0..p.k {
        for j in 0..N {
            if h.vec[i][j] != 0 {
                // WHAT: store set-bit positions of each hint polynomial in ascending order.
                // WHY: sparse index encoding keeps signatures compact and canonically ordered.
                out[hint_pos + k] = j as u8;
                k += 1;
            }
        }
        out[hint_pos + p.omega + i] = k as u8;
    }
    out
}

fn unpack_sig(p: Profile, sig: &[u8]) -> Option<(Vec<u8>, Polyvecl, Polyveck)> {
    if sig.len() != p.signature_len() {
        return None;
    }
    let mut pos = 0usize;
    let c = sig[pos..pos + p.ctilde_bytes].to_vec();
    pos += p.ctilde_bytes;

    let mut z = Polyvecl::zero(p.l);
    for i in 0..p.l {
        z.vec[i] = polyz_unpack(p, &sig[pos..pos + p.polyz_packed_bytes])?;
        pos += p.polyz_packed_bytes;
    }

    let hint = &sig[pos..];
    if hint.len() != p.omega + p.k {
        return None;
    }
    let mut h = Polyveck::zero(p.k);
    let mut k = 0usize;
    for i in 0..p.k {
        let end = usize::from(hint[p.omega + i]);
        if end < k || end > p.omega {
            return None;
        }
        for j in k..end {
            let idx = usize::from(hint[j]);
            // WHAT: enforce strictly increasing indices within each hint polynomial.
            // WHY: rejecting non-canonical duplicates/orderings closes alternate encodings of the same hint set.
            if j > k && idx <= usize::from(hint[j - 1]) {
                return None;
            }
            if idx >= N {
                return None;
            }
            h.vec[i][idx] = 1;
        }
        k = end;
    }
    for b in hint.iter().take(p.omega).skip(k) {
        if *b != 0 {
            return None;
        }
    }

    Some((c, z, h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parameter_lengths_match_known_profiles() {
        assert_eq!(MlDsaParameterSet::MlDsa44.public_key_len(), 1312);
        assert_eq!(MlDsaParameterSet::MlDsa44.private_key_len(), 2560);
        assert_eq!(MlDsaParameterSet::MlDsa44.signature_len(), 2420);

        assert_eq!(MlDsaParameterSet::MlDsa65.public_key_len(), 1952);
        assert_eq!(MlDsaParameterSet::MlDsa65.private_key_len(), 4032);
        assert_eq!(MlDsaParameterSet::MlDsa65.signature_len(), 3309);

        assert_eq!(MlDsaParameterSet::MlDsa87.public_key_len(), 2592);
        assert_eq!(MlDsaParameterSet::MlDsa87.private_key_len(), 4896);
        assert_eq!(MlDsaParameterSet::MlDsa87.signature_len(), 4627);
    }

    #[test]
    fn wire_and_key_blob_roundtrip_shapes() {
        for params in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let pk_bytes = vec![0x11u8; params.public_key_len()];
            let sk_bytes = vec![0x22u8; params.private_key_len()];
            let sig_bytes = vec![0x00u8; params.signature_len()];

            let pk = MlDsaPublicKey::from_wire_bytes(params, &pk_bytes).expect("pk");
            let sk = MlDsaPrivateKey::from_wire_bytes(params, &sk_bytes).expect("sk");
            assert_eq!(MlDsaPublicKey::from_key_blob(&pk.to_key_blob()), Some(pk));
            assert_eq!(MlDsaPrivateKey::from_key_blob(&sk.to_key_blob()), Some(sk));

            // Random bytes are not guaranteed to decode to canonical signatures.
            let _ = MlDsaSignature::from_wire_bytes(params, &sig_bytes);
        }
    }

    #[test]
    fn sign_verify_roundtrip_each_parameter() {
        for params in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let seed = [0x42u8; 32];
            let (pk, sk) = MlDsa::keygen_from_seed(params, &seed).expect("keygen");
            let message = b"ml-dsa-roundtrip";
            let randomness = [0u8; 32];
            let sig = MlDsa::sign_with_randomness(&sk, message, &randomness).expect("sign");
            assert!(MlDsa::verify(&pk, message, &sig), "{params:?}");
            assert!(!MlDsa::verify(&pk, b"wrong", &sig), "{params:?}");
        }
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let seed = [0x24u8; 32];
        let (pk, sk) = MlDsa::keygen_from_seed(MlDsaParameterSet::MlDsa44, &seed).expect("keygen");
        let mut sig = MlDsa::sign_with_randomness(&sk, b"tamper", &[0u8; 32])
            .expect("sign")
            .to_wire_bytes();
        sig[10] ^= 0x01;
        let sig =
            MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa44, &sig).expect("signature");
        assert!(!MlDsa::verify(&pk, b"tamper", &sig));
    }

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

    fn parse_i32_vector(contents: &str) -> Vec<i32> {
        contents
            .split_whitespace()
            .filter(|tok| !tok.starts_with('#'))
            .filter_map(|tok| tok.parse::<i32>().ok())
            .collect()
    }

    #[test]
    fn ml_dsa_44_keygen_matches_acvp_fips204_vector() {
        // Source: NIST ACVP server vectors, ML-DSA keyGen FIPS204, tgId=1 tcId=1.
        let vectors = parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_dsa_fips204_subset.txt"
        )));
        let seed: [u8; 32] = decode_hex_array(vectors["KEYGEN_SEED"]).expect("seed");
        let expected_pk = decode_hex(vectors["KEYGEN_PK"]).expect("pk");
        let (pk, _sk) = MlDsa::keygen_from_seed(MlDsaParameterSet::MlDsa44, &seed).expect("keygen");
        assert_eq!(pk.to_wire_bytes(), expected_pk);
    }

    #[test]
    fn ml_dsa_zetas_match_reference_ntt_table() {
        // Reference: pq-crystals/dilithium ref/ntt.c zetas table.
        let expected = parse_i32_vector(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_dsa_ref_zetas.txt"
        )));
        let expected: [i32; N] = expected.try_into().expect("expected 256 ML-DSA zetas");
        assert_eq!(ZETAS, expected);
    }

    #[test]
    fn ml_dsa_65_verify_matches_acvp_fips204_vector() {
        // Source: NIST ACVP server vectors, ML-DSA sigVer FIPS204, tgId=3 tcId=36 (testPassed=true).
        let vectors = parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_dsa_fips204_subset.txt"
        )));
        let pk = MlDsaPublicKey::from_wire_bytes(
            MlDsaParameterSet::MlDsa65,
            &decode_hex(vectors["VERIFY_PK"]).expect("pk"),
        )
        .expect("verify pk");
        let sig = MlDsaSignature::from_wire_bytes(
            MlDsaParameterSet::MlDsa65,
            &decode_hex(vectors["VERIFY_SIG"]).expect("signature"),
        )
        .expect("verify sig");
        let msg = decode_hex(vectors["VERIFY_MESSAGE"]).expect("message");
        let ctx = decode_hex(vectors["VERIFY_CONTEXT"]).expect("context");
        assert!(MlDsa::verify_with_context(&pk, &msg, &sig, &ctx));
    }
}
