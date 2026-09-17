//! ML-KEM, the module-lattice key-encapsulation mechanism of FIPS 203,
//! implemented in safe Rust from the standard itself.
//!
//! This module provides:
//! - ML-KEM-512/768/1024 parameter sets
//! - key generation
//! - encapsulation and decapsulation
//! - strict wire/key-blob framing
//!
//! # Provenance
//!
//! Every algorithm here was written from the pseudocode and definitions of
//! FIPS 203 (August 2024) and keeps its structure and names. The NTT
//! constants are computed at compile time from ζ = 17 and checked against
//! Appendix A; modular reduction follows Barrett (CRYPTO '86), and the
//! division-free Compress_d follows Granlund and Montgomery (PLDI '94).
//!
//! | FIPS 203 | Function |
//! |---|---|
//! | Algorithms 3–4, BitsToBytes and BytesToBits | folded into `byte_encode` and `byte_decode` |
//! | Algorithm 5, ByteEncode_d | `byte_encode` |
//! | Algorithm 6, ByteDecode_d | `byte_decode` |
//! | (4.7) Compress_d and (4.8) Decompress_d | `compress` (through `compress_rounding`) and `decompress` |
//! | (4.2)–(4.5) PRF, H, J, G | `prf`, `hash_h`, `hash_j`, `hash_g` |
//! | Algorithm 7, SampleNTT | `sample_ntt`; the matrix Â is `sample_a_hat` |
//! | Algorithm 8, SamplePolyCBD_η | `sample_poly_cbd` |
//! | Algorithm 9, NTT | `ntt` |
//! | Algorithm 10, NTT⁻¹ | `ntt_inverse` |
//! | Algorithm 11, MultiplyNTTs | `multiply_ntts` |
//! | Algorithm 12, BaseCaseMultiply | `base_case_multiply` |
//! | Algorithm 13, K-PKE.KeyGen | `k_pke_keygen` |
//! | Algorithm 14, K-PKE.Encrypt | `k_pke_encrypt` |
//! | Algorithm 15, K-PKE.Decrypt | `k_pke_decrypt` |
//! | Algorithm 16, ML-KEM.KeyGen_internal | `ml_kem_keygen_internal`, behind [`MlKem::keygen_from_seed`] |
//! | Algorithm 17, ML-KEM.Encaps_internal | `ml_kem_encaps_internal`, behind [`MlKem::encaps_with_randomness`] |
//! | Algorithm 18, ML-KEM.Decaps_internal | `ml_kem_decaps_internal`, behind [`MlKem::decaps`] |
//! | Algorithms 19–21, ML-KEM.KeyGen, Encaps, Decaps | [`MlKem::keygen`], [`MlKem::encaps`], [`MlKem::decaps`] |
//! | §7.2 encapsulation-key modulus check | `modulus_check`, in [`MlKemPublicKey::from_wire_bytes`] |
//! | §7.3 decapsulation-key hash check | [`MlKemPrivateKey::from_wire_bytes`] |
//! | §7.1 key pair check, step 4 (pair-wise consistency) | `pair_wise_consistency`: on `dk` and the `ek` inside it in [`MlKemPrivateKey::from_wire_bytes`]; on the returned pair, as the FIPS 140-3 IG 10.3.A test of a new key pair, in [`MlKem::keygen`] |
//!
//! Implementation notes:
//! - coefficients are canonical integers in [0, q), and every step on secret
//!   values avoids data-dependent branches, table indices, and division (see
//!   the comment that opens the arithmetic core)
//! - SHA3/SHAKE primitives come from this crate's hash module
//! - no C/FFI backends are used
//!
//! # Standard key encodings
//!
//! RFC 9935 carries the keys in X.509's containers, beside the crate's own
//! `to_wire_bytes` and `to_key_blob` forms:
//!
//! - [`MlKemPublicKey::to_spki_der`] and its siblings: a
//!   `SubjectPublicKeyInfo` (§4) under `id-alg-ml-kem-512`, `-768` or `-1024`
//!   (§3) with the parameters absent, and the encapsulation key `ek` as the
//!   `subjectPublicKey`.
//! - [`MlKemPrivateKey::to_pkcs8_der`] and its siblings: a PKCS #8
//!   `OneAsymmetricKey` whose `privateKey` is the §6 `CHOICE` of `seed`
//!   (`d ‖ z`, 64 bytes), `expandedKey` (`dk`), or `both`.
//!
//! On output a key writes its 64-byte seed when it has one, the form §6
//! recommends and §7 asks implementations to retain and export. Keys from
//! [`MlKem::keygen`] and [`MlKem::keygen_from_seed`], and keys read from a
//! `seed` or `both`, keep their seed. A key built from an expanded key alone
//! ([`MlKemPrivateKey::from_wire_bytes`], a key blob, or an `expandedKey`)
//! cannot recover one, since key generation is one-way (§7), and writes
//! `expandedKey`. `both` is never written: the seed determines the rest.
//!
//! On input all three alternatives are accepted, told apart by tag as §6
//! directs. A `seed` is expanded by ML-KEM.KeyGen_internal (Algorithm 16). A
//! `both` must pass the §8 seed consistency check: its expanded key must be
//! the one its seed generates. An `expandedKey` is checked as the next section
//! describes. A version 2 `publicKey` must equal the encapsulation key inside
//! `dk`.
//!
//! # Decapsulation keys read without their seed
//!
//! [`MlKemPrivateKey::from_wire_bytes`], [`MlKemPrivateKey::from_key_blob`],
//! and an `expandedKey` read by [`MlKemPrivateKey::from_pkcs8_der`] or
//! [`MlKemPrivateKey::from_pkcs8_pem`] take `dk` without the seed that
//! generated it. Such a key gets the FIPS 203 §7.1 key pair check, for a key
//! pair its owner did not generate, on `dk` and the `ek` inside it: the §7.2
//! type and modulus checks on `ek`, the §7.3 type and hash checks on `dk` (the
//! hash check is the one RFC 9935 §8 requires), and the step 4 pair-wise
//! consistency test. Step 1, seed consistency, needs the seed. The crate also
//! refuses a non-canonically packed `ŝ`.
//!
//! The pair-wise consistency test encapsulates to `ek` with
//! ML-KEM.Encaps_internal under a message `m` of 32 random bytes, and refuses
//! the key unless ML-KEM.Decaps_internal on `dk` returns the same shared key.
//! Step 4.i draws `m` in the notation §3.3 defines as a fresh string of random
//! bytes from an approved RBG, so a fixed or derived message would not be the
//! test. These importers therefore take a random source, as [`MlKem::keygen`]
//! and [`MlKem::encaps`] do, and draw 32 bytes from it for each key that
//! reaches the test. The test is what finds the second example of RFC 9935
//! Appendix C.4.1, an `ŝ` altered under an intact `H(ek)`. A `seed` or `both`
//! draws nothing: its seed proves that `dk` is key generation's output. As
//! §7.1 warns, passing does not show that a key pair was properly generated:
//! an expanded key whose `z` alone was altered, like the fourth example's,
//! passes.

use core::fmt;
use std::sync::OnceLock;

use crate::hash::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use crate::hash::Xof;
use crate::public_key::ml_pkix::{self, PrivateKeyChoice};
use crate::public_key::pkix::{
    pem_decode, pem_encode, AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey,
    SubjectPublicKeyInfo, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL,
};
use crate::Csprng;

const N: usize = 256;
/// The largest rank k of any parameter set; the stack-held vectors of the
/// arithmetic core are sized to it.
const MAX_K: usize = 4;
/// q = 3329 (FIPS 203 §2.3).
const Q: u32 = 3329;
const SYM_BYTES: usize = 32;
const SS_BYTES: usize = 32;
const POLY_BYTES: usize = 384;
/// Bits per coefficient in a full-precision encoding: `⌈log₂ q⌉ = 12`
/// (FIPS 203 §2, ByteEncode₁₂).
const COEFF_BITS: usize = 12;
/// `PRF_η` output is `64·η` bytes (FIPS 203 §4.1), and η is at most 3.
const PRF_BYTES_PER_ETA: usize = 64;
const MAX_ETA: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Profile {
    k: usize,
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
}

/// `id-alg-ml-kem-512`, 2.16.840.1.101.3.4.4.1 (RFC 9935 §3).
const ID_ALG_ML_KEM_512: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 1]);

/// `id-alg-ml-kem-768`, 2.16.840.1.101.3.4.4.2 (RFC 9935 §3).
const ID_ALG_ML_KEM_768: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 2]);

/// `id-alg-ml-kem-1024`, 2.16.840.1.101.3.4.4.3 (RFC 9935 §3).
const ID_ALG_ML_KEM_1024: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 3]);

/// ML-KEM parameter sets from FIPS 203.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemParameterSet {
    /// ML-KEM-512 (security category 1): rank k = 2; 800-byte public key,
    /// 1632-byte private key, 768-byte ciphertext, 32-byte shared secret.
    MlKem512,
    /// ML-KEM-768 (security category 3): rank k = 3; 1184-byte public key,
    /// 2400-byte private key, 1088-byte ciphertext, 32-byte shared secret.
    MlKem768,
    /// ML-KEM-1024 (security category 5): rank k = 4; 1568-byte public key,
    /// 3168-byte private key, 1568-byte ciphertext, 32-byte shared secret.
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

    /// The RFC 9935 §3 identifier of this parameter set.
    const fn algorithm(self) -> &'static ObjectIdentifier {
        match self {
            Self::MlKem512 => &ID_ALG_ML_KEM_512,
            Self::MlKem768 => &ID_ALG_ML_KEM_768,
            Self::MlKem1024 => &ID_ALG_ML_KEM_1024,
        }
    }

    /// The parameter set `algorithm` names, whose parameters RFC 9935 §3
    /// requires to be absent.
    fn from_algorithm(algorithm: &AlgorithmIdentifier<'_>) -> Option<Self> {
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
            .into_iter()
            .find(|params| algorithm.matches(params.algorithm(), None))
    }
}

/// ML-KEM public key.
pub struct MlKemPublicKey {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
    // Lazily-expanded matrix Â (FIPS 203 Algorithm 14, lines 3–8), a function
    // of the public seed ρ alone. §3.3 permits storing it, so repeated
    // encapsulations to this key do not re-run SampleNTT. Ignored by Clone/Eq
    // (it is derived state).
    a_hat: OnceLock<ZqMatrix>,
}

impl Clone for MlKemPublicKey {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
            bytes: self.bytes.clone(),
            a_hat: OnceLock::new(),
        }
    }
}

impl PartialEq for MlKemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params && self.bytes == other.bytes
    }
}

impl Eq for MlKemPublicKey {}

impl fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKemPublicKey")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

/// ML-KEM private key.
pub struct MlKemPrivateKey {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
    // The seed d ‖ z that generated `bytes`, when known: RFC 9935 §7 asks
    // implementations to retain it. Eq compares the key material in `bytes`;
    // whether the seed is still known changes only the PKCS #8 output form.
    // It is boxed so that moving the key moves a pointer, not a copy of the
    // seed that Drop could not reach.
    seed: Option<Box<[u8; 2 * SYM_BYTES]>>,
    // Cached Â for the embedded encapsulation key, used by the decapsulation
    // re-encryption. Ignored by Clone/Eq. See `MlKemPublicKey::a_hat`.
    a_hat: OnceLock<ZqMatrix>,
}

impl Clone for MlKemPrivateKey {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
            bytes: self.bytes.clone(),
            seed: self.seed.as_deref().map(boxed_seed),
            a_hat: OnceLock::new(),
        }
    }
}

impl PartialEq for MlKemPrivateKey {
    /// Compares the parameter sets, then the decapsulation keys in constant
    /// time. A retained seed is not compared: the seed determines the key.
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params
            && crate::ct::constant_time_eq_mask(&self.bytes, &other.bytes) == u8::MAX
    }
}

impl Eq for MlKemPrivateKey {}

/// ML-KEM ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemCiphertext {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM shared secret (32 bytes).
#[derive(Clone)]
pub struct MlKemSharedSecret {
    bytes: [u8; SS_BYTES],
}

impl PartialEq for MlKemSharedSecret {
    /// Compares the two secrets in constant time: no early exit on the first
    /// differing byte.
    fn eq(&self, other: &Self) -> bool {
        crate::ct::constant_time_eq_mask(&self.bytes, &other.bytes) == u8::MAX
    }
}

impl Eq for MlKemSharedSecret {}

impl fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKemSharedSecret(<redacted>)")
    }
}

impl Drop for MlKemSharedSecret {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.bytes.as_mut_slice());
    }
}

/// Namespace for ML-KEM operations.
pub struct MlKem;

impl MlKemPublicKey {
    /// The FIPS 203 parameter set this key belongs to. Encapsulation output
    /// sizes and blob framing are fixed by this value.
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    /// Expand (once) and return the cached matrix Â. Its seed ρ is the
    /// trailing `SYM_BYTES` of the encapsulation key.
    fn a_hat(&self) -> &ZqMatrix {
        self.a_hat.get_or_init(|| {
            let k = self.params.k();
            let mut rho = [0u8; SYM_BYTES];
            rho.copy_from_slice(&self.bytes[POLY_BYTES * k..]);
            sample_a_hat(k, &rho)
        })
    }

    /// Serialize to the FIPS 203 encapsulation-key encoding `t || rho`
    /// (`public_key_len()` bytes: 800/1184/1568 for ML-KEM-512/768/1024).
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Parse a FIPS 203 encapsulation key. Returns `None` if the length is
    /// not exactly `params.public_key_len()` or if any packed 12-bit NTT
    /// coefficient is non-canonical (>= q = 3329), enforced by a re-encode
    /// round-trip as the "modulus check" of FIPS 203 §7.2 requires.
    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.public_key_len() {
            return None;
        }
        // FIPS 203 §7.2 modulus check. ByteDecode_12 reduces each 12-bit field
        // modulo q, so a field in [3329, 4095] does not survive the round
        // trip; accepting it would silently stand for a different key.
        if !modulus_check(params.k(), bytes) {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
            a_hat: OnceLock::new(),
        })
    }

    /// Serialize to this crate's self-describing framing: a one-byte
    /// parameter-set tag followed by the FIPS 203 wire encoding. Unlike
    /// [`Self::to_wire_bytes`], the result can be parsed without knowing
    /// the parameter set out of band.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse a blob produced by [`Self::to_key_blob`]. Returns `None` on an
    /// empty input, an unknown parameter-set tag, or a body rejected by
    /// [`Self::from_wire_bytes`] (wrong length or non-canonical encoding).
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlKemParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }

    /// Encode as the RFC 9935 §4 `SubjectPublicKeyInfo` in DER: the parameter
    /// set's `id-alg-ml-kem-*` identifier with the parameters absent (§3), and
    /// the FIPS 203 encapsulation key as the `subjectPublicKey`.
    #[must_use]
    pub fn to_spki_der(&self) -> Vec<u8> {
        let algorithm = AlgorithmIdentifier::new(self.params.algorithm(), None);
        SubjectPublicKeyInfo::new(algorithm, &self.bytes).to_der()
    }

    /// Encode as RFC 7468 `PUBLIC KEY` text (§13) around [`Self::to_spki_der`].
    #[must_use]
    pub fn to_spki_pem(&self) -> String {
        pem_encode(PUBLIC_KEY_LABEL, self.to_spki_der())
    }

    /// Decode an RFC 9935 §4 `SubjectPublicKeyInfo` from strict DER with no
    /// trailing bytes. The identifier names the parameter set and carries no
    /// parameters (§3), and the key must pass [`Self::from_wire_bytes`] for
    /// that parameter set: the FIPS 203 §7.2 type and modulus checks.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let spki = SubjectPublicKeyInfo::from_der(der)?;
        let params = MlKemParameterSet::from_algorithm(spki.algorithm())?;
        Self::from_wire_bytes(params, spki.subject_public_key())
    }

    /// Decode RFC 7468 `PUBLIC KEY` text (§13) with [`Self::from_spki_der`].
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        pem_decode(PUBLIC_KEY_LABEL, pem, Self::from_spki_der)
    }
}

impl MlKemPrivateKey {
    /// Expand (once) and return the cached Â for the embedded encapsulation
    /// key, used by the decapsulation re-encryption.
    fn a_hat(&self) -> &ZqMatrix {
        self.a_hat.get_or_init(|| {
            let k = self.params.k();
            // dk = dk_PKE ‖ ek ‖ H(ek) ‖ z, and ρ closes ek: it follows the
            // 384k bytes of dk_PKE and the 384k bytes encoding ek's t̂.
            let rho_start = 2 * POLY_BYTES * k;
            let mut rho = [0u8; SYM_BYTES];
            rho.copy_from_slice(&self.bytes[rho_start..rho_start + SYM_BYTES]);
            sample_a_hat(k, &rho)
        })
    }

    /// The FIPS 203 parameter set this key belongs to. It fixes which
    /// ciphertext length [`MlKem::decaps`] accepts and the blob framing.
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    /// Serialize to the FIPS 203 decapsulation-key encoding
    /// `dk_PKE || ek || H(ek) || z` (`private_key_len()` bytes:
    /// 1632/2400/3168 for ML-KEM-512/768/1024). This is raw secret key
    /// material; handle the returned buffer accordingly.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Parse a FIPS 203 decapsulation key and check it, with the
    /// encapsulation key inside it, as a key pair. Returns `None` if the
    /// length is not exactly `params.private_key_len()`, if either the secret
    /// or the embedded public polynomial vector is non-canonically packed
    /// (checked by re-encode round-trips), if the stored `H(ek)` does not
    /// match the hash of the embedded encapsulation key (the §7.3 hash check),
    /// or if the key fails the pair-wise consistency test of FIPS 203 §7.1.
    /// That test draws its 32-byte message from `rng`, which §3.3 asks to be
    /// an approved RBG; the module documentation says why it runs here.
    #[must_use]
    pub fn from_wire_bytes<R: Csprng>(
        params: MlKemParameterSet,
        bytes: &[u8],
        rng: &mut R,
    ) -> Option<Self> {
        if bytes.len() != params.private_key_len() {
            return None;
        }
        let k = params.k();
        let (dk_pke, rest) = bytes.split_at(POLY_BYTES * k);
        let (ek, trailer) = rest.split_at(POLY_BYTES * k + SYM_BYTES);
        let h_ek = &trailer[..SYM_BYTES];
        // The embedded encapsulation key must pass the §7.2 modulus check,
        // and the §7.3 hash check requires H(ek) to equal the stored hash.
        if !modulus_check(k, ek) || hash_h(ek).as_slice() != h_ek {
            return None;
        }
        // dk_PKE must be canonically packed too (compared in constant time,
        // since it encodes the secret ŝ).
        if !dk_pke_is_canonical(dk_pke) {
            return None;
        }
        let key = Self {
            params,
            bytes: bytes.to_vec(),
            seed: None,
            a_hat: OnceLock::new(),
        };
        // A refused key is dropped here, which wipes its copy of dk.
        key.pair_wise_consistency(rng).then_some(key)
    }

    /// Serialize to this crate's self-describing framing: a one-byte
    /// parameter-set tag followed by the FIPS 203 wire encoding. The result
    /// contains raw secret key material; handle it accordingly.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse a blob produced by [`Self::to_key_blob`]. Returns `None` on an
    /// empty input, an unknown parameter-set tag, or a body rejected by
    /// [`Self::from_wire_bytes`] (wrong length, non-canonical encoding, an
    /// inconsistent embedded `H(ek)`, or a failed pair-wise consistency test,
    /// whose 32-byte message is drawn from `rng`).
    #[must_use]
    pub fn from_key_blob<R: Csprng>(blob: &[u8], rng: &mut R) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlKemParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest, rng)
    }

    /// Encode as the RFC 9935 §6 `OneAsymmetricKey` (PKCS #8) in DER: version
    /// 1, the parameter set's identifier with the parameters absent (§3), and
    /// no public key. The `privateKey` is the 64-byte `seed` when this key
    /// retains one, the form §6 recommends, and the `expandedKey` otherwise;
    /// the module documentation says which keys retain their seed. The result
    /// holds secret key material.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        let private_key = match &self.seed {
            Some(seed) => PrivateKeyChoice::Seed(seed.as_slice()),
            None => PrivateKeyChoice::ExpandedKey(&self.bytes),
        };
        ml_pkix::private_key_to_pkcs8(self.params.algorithm(), private_key)
    }

    /// Encode as RFC 7468 `PRIVATE KEY` text (§10) around
    /// [`Self::to_pkcs8_der`].
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode(PRIVATE_KEY_LABEL, self.to_pkcs8_der())
    }

    /// Decode an RFC 9935 `OneAsymmetricKey` in any X.690 BER encoding, DER
    /// included: RFC 5958 §2 says "receivers MUST support BER". The private-key
    /// `CHOICE` inside must still be DER (RFC 9935 §6), and the key is then
    /// checked as [`Self::from_pkcs8_der`] checks it, drawing from `rng` only for
    /// an `expandedKey`.
    #[must_use]
    pub fn from_pkcs8_ber<R: Csprng>(ber: &[u8], rng: &mut R) -> Option<Self> {
        crate::public_key::pkix::pkcs8_ber(ber, |der| Self::from_pkcs8_der(der, rng))
    }

    /// Decode an RFC 9935 §6 `OneAsymmetricKey` from strict DER with no
    /// trailing bytes. The identifier names the parameter set and carries no
    /// parameters (§3). The `privateKey` may be any alternative of the §6
    /// `CHOICE`, told apart by tag:
    ///
    /// - `seed`: 64 bytes, expanded by ML-KEM.KeyGen_internal(d, z);
    /// - `expandedKey`: accepted as [`Self::from_wire_bytes`] accepts it, with
    ///   the FIPS 203 §7.3 hash check that §8 requires and the §7.1 pair-wise
    ///   consistency test, whose 32-byte message is drawn from `rng`;
    /// - `both`: its expanded key must be exactly the one its seed generates,
    ///   the §8 seed consistency check.
    ///
    /// Only an `expandedKey` draws from `rng`. A version 2 `publicKey` must
    /// equal the encapsulation key inside the private key. Attributes are
    /// ignored.
    #[must_use]
    pub fn from_pkcs8_der<R: Csprng>(der: &[u8], rng: &mut R) -> Option<Self> {
        let package = OneAsymmetricKey::from_der(der)?;
        let params = MlKemParameterSet::from_algorithm(package.algorithm())?;
        let choice = PrivateKeyChoice::from_der(
            package.private_key(),
            2 * SYM_BYTES,
            params.private_key_len(),
        )?;
        let key = match choice {
            PrivateKeyChoice::Seed(seed) => Self::from_seed(params, seed)?,
            PrivateKeyChoice::ExpandedKey(expanded_key) => {
                Self::from_wire_bytes(params, expanded_key, rng)?
            }
            PrivateKeyChoice::Both { seed, expanded_key } => {
                let key = Self::from_seed(params, seed)?;
                // Compared without an early exit: both hold the secret key.
                if crate::ct::constant_time_eq_mask(&key.bytes, expanded_key) != u8::MAX {
                    return None;
                }
                key
            }
        };
        match package.public_key() {
            Some(public_key) if public_key != key.encapsulation_key() => None,
            _ => Some(key),
        }
    }

    /// Decode RFC 7468 `PRIVATE KEY` text (§10) with [`Self::from_pkcs8_der`],
    /// which draws from `rng` only for an `expandedKey`.
    #[must_use]
    pub fn from_pkcs8_pem<R: Csprng>(pem: &str, rng: &mut R) -> Option<Self> {
        pem_decode(PRIVATE_KEY_LABEL, pem, |der| Self::from_pkcs8_der(der, rng))
    }

    /// The private key ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16)
    /// generates from the 64-byte seed `d ‖ z`; `None` for another length.
    fn from_seed(params: MlKemParameterSet, seed: &[u8]) -> Option<Self> {
        if seed.len() != 2 * SYM_BYTES {
            return None;
        }
        // Filled in place, so no by-value copy of the seed is left behind.
        let mut d_z = [0u8; 2 * SYM_BYTES];
        d_z.copy_from_slice(seed);
        let (_, private_key) = MlKem::keygen_from_seed(params, &d_z);
        crate::ct::zeroize_slice(&mut d_z);
        Some(private_key)
    }

    /// The encapsulation key inside `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`.
    fn encapsulation_key(&self) -> &[u8] {
        let k = self.params.k();
        &self.bytes[POLY_BYTES * k..2 * POLY_BYTES * k + SYM_BYTES]
    }

    /// The pair-wise consistency test of FIPS 203 §7.1, step 4, on this key's
    /// `dk` and the `ek` inside it, with a 32-byte message drawn from `rng`:
    /// the form the test takes for a decapsulation key imported without its
    /// seed, whose encapsulation key is the one it carries. Both halves use
    /// this key's cached Â, since they share ρ.
    fn pair_wise_consistency<R: Csprng>(&self, rng: &mut R) -> bool {
        let a_hat = self.a_hat();
        pair_wise_consistency(
            self.params.profile(),
            self.encapsulation_key(),
            a_hat,
            &self.bytes,
            a_hat,
            rng,
        )
    }
}

/// The pair-wise consistency test of FIPS 203 §7.1, step 4, on the
/// encapsulation key `ek` and decapsulation key `dk` of the parameter set `p`:
/// whether ML-KEM.Decaps_internal(dk, c) returns the shared key K that
/// ML-KEM.Encaps_internal(ek, m) produced with c, for a message m of 32 bytes
/// drawn from `rng`. `ek_a_hat` is Â for `ek`, used by the encapsulation, and
/// `dk_a_hat` is Â for the encapsulation key inside `dk`, used by the
/// decapsulation's re-encryption; each key computes with its own matrix, so
/// the test asks exactly whether the two keys agree. K and K′ are compared
/// without an early exit, and every intermediate value is wiped before the
/// verdict is returned.
fn pair_wise_consistency<R: Csprng>(
    p: Profile,
    ek: &[u8],
    ek_a_hat: &ZqMatrix,
    dk: &[u8],
    dk_a_hat: &ZqMatrix,
    rng: &mut R,
) -> bool {
    // Step 4.i: m ←$ 𝔹³², a fresh random string (§3.3).
    let mut m = [0u8; SYM_BYTES];
    rng.fill_bytes(&mut m);
    // Step 4.ii: (K, c) ← ML-KEM.Encaps_internal(ek, m).
    let mut shared_key = [0u8; SS_BYTES];
    let mut c = ml_kem_encaps_internal(p, ek, &m, ek_a_hat, &mut shared_key);
    crate::ct::zeroize_slice(&mut m);
    // Step 4.iii: K′ ← ML-KEM.Decaps_internal(dk, c).
    let mut decapsulated = [0u8; SS_BYTES];
    ml_kem_decaps_internal(p, dk, &c, dk_a_hat, &mut decapsulated);
    // Step 4.iv: reject unless K = K′.
    let mut equal = crate::ct::constant_time_eq_mask(&shared_key, &decapsulated);
    let consistent = equal == u8::MAX;
    crate::ct::zeroize_slice(core::slice::from_mut(&mut equal));
    crate::ct::zeroize_slice(&mut shared_key);
    crate::ct::zeroize_slice(&mut decapsulated);
    crate::ct::zeroize_slice(c.as_mut_slice());
    consistent
}

impl MlKemCiphertext {
    /// The FIPS 203 parameter set this ciphertext was produced under.
    /// [`MlKem::decaps`] refuses a ciphertext whose parameter set differs
    /// from the private key's.
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    /// Serialize to the FIPS 203 ciphertext encoding `c1 || c2`
    /// (`ciphertext_len()` bytes: 768/1088/1568 for ML-KEM-512/768/1024).
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Parse a FIPS 203 ciphertext. Returns `None` if the length is not
    /// exactly `params.ciphertext_len()` (the ciphertext type check of
    /// FIPS 203 §7.3). Every byte string of that length is well formed:
    /// `32·d` bytes hold exactly 256 `d`-bit fields, all of which
    /// ByteDecode_d accepts. Acceptance here does not imply the
    /// ciphertext is genuine: decapsulating a forged or corrupted
    /// ciphertext still succeeds and yields the implicit-rejection secret.
    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.ciphertext_len() {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }
}

impl MlKemSharedSecret {
    /// Return the 32-byte shared secret. This is keying material — feed it
    /// to a KDF or cipher and avoid persisting it; the containing struct
    /// zeroizes itself on drop, but the returned copy is the caller's to
    /// scrub.
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; SS_BYTES] {
        self.bytes
    }

    /// Reconstruct a shared secret from bytes (e.g. from a KAT vector).
    /// Returns `None` unless `bytes` is exactly 32 bytes; any 32-byte
    /// value is accepted, as every value is a valid shared secret.
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SS_BYTES {
            return None;
        }
        // Filled in place: the secret is copied into the value that will
        // wipe it, not into a local first.
        let mut secret = Self {
            bytes: [0u8; SS_BYTES],
        };
        secret.bytes.copy_from_slice(bytes);
        Some(secret)
    }
}

impl MlKem {
    /// Deterministic key generation for vectors and KATs:
    /// ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16) on `seed = d ‖ z`
    /// (64 bytes). Every seed generates a key pair, so nothing can fail.
    ///
    /// This entry point takes no random source, so it runs no pair-wise
    /// consistency test: §7.1 step 4.i wants a fresh random message, and a
    /// message derived from the seed would not be that test. [`MlKem::keygen`]
    /// is the generator that tests what it returns.
    #[must_use]
    pub fn keygen_from_seed(
        params: MlKemParameterSet,
        seed: &[u8; 2 * SYM_BYTES],
    ) -> (MlKemPublicKey, MlKemPrivateKey) {
        let mut d = [0u8; SYM_BYTES];
        let mut z = [0u8; SYM_BYTES];
        d.copy_from_slice(&seed[..SYM_BYTES]);
        z.copy_from_slice(&seed[SYM_BYTES..]);
        let (ek, dk) = ml_kem_keygen_internal(params.profile(), &d, &z);
        crate::ct::zeroize_slice(&mut d);
        crate::ct::zeroize_slice(&mut z);

        let pk = MlKemPublicKey {
            params,
            bytes: ek,
            a_hat: OnceLock::new(),
        };
        let sk = MlKemPrivateKey {
            params,
            bytes: dk,
            seed: Some(boxed_seed(seed)),
            a_hat: OnceLock::new(),
        };
        (pk, sk)
    }

    /// ML-KEM.KeyGen (FIPS 203 Algorithm 19): `d` and `z` are 32 bytes each
    /// from `rng`, and the pair is ML-KEM.KeyGen_internal(d, z).
    ///
    /// Before it is returned, the pair takes the pair-wise consistency test
    /// FIPS 140-3 IG 10.3.A asks of a freshly generated key pair, in the form
    /// FIPS 203 §7.1 step 4 gives it and on the two values this function
    /// returns: encapsulate to the public key under a 32-byte message from
    /// `rng`, decapsulate with the private key, and compare the two shared
    /// keys. `rng` therefore supplies 96
    /// bytes per call. `None` means the generated pair failed that test,
    /// which a correct implementation on working hardware never produces; a
    /// caller that sees it should treat the module as faulty rather than
    /// retry.
    #[must_use]
    pub fn keygen<R: Csprng>(
        params: MlKemParameterSet,
        rng: &mut R,
    ) -> Option<(MlKemPublicKey, MlKemPrivateKey)> {
        let mut seed = [0u8; 2 * SYM_BYTES];
        rng.fill_bytes(&mut seed);
        let (pk, sk) = Self::keygen_from_seed(params, &seed);
        // The private key keeps its own copy of the seed.
        crate::ct::zeroize_slice(&mut seed);
        Self::pair_wise_consistency(&pk, &sk, rng).then_some((pk, sk))
    }

    /// The pair-wise consistency test of FIPS 203 §7.1, step 4, on a public
    /// key and a private key held separately: encapsulate to `public_key`
    /// under a 32-byte message drawn from `rng`, decapsulate with
    /// `private_key`, and compare the shared keys. Each key computes with its
    /// own cached Â. `false` when the parameter sets differ, in which case
    /// nothing is drawn. [`MlKem::keygen`] runs this on the pair it returns.
    fn pair_wise_consistency<R: Csprng>(
        public_key: &MlKemPublicKey,
        private_key: &MlKemPrivateKey,
        rng: &mut R,
    ) -> bool {
        public_key.params == private_key.params
            && pair_wise_consistency(
                public_key.params.profile(),
                &public_key.bytes,
                public_key.a_hat(),
                &private_key.bytes,
                private_key.a_hat(),
                rng,
            )
    }

    /// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17) with the 32-byte
    /// message `randomness` as `m`: the KAT and oracle-testing entry point.
    /// Every message yields a ciphertext and shared key, so nothing can fail.
    ///
    /// The public key already passed the §7.2 checks when it was built. The
    /// shared key is written straight into the returned
    /// [`MlKemSharedSecret`], which wipes it on drop.
    #[must_use]
    pub fn encaps_with_randomness(
        public_key: &MlKemPublicKey,
        randomness: &[u8; SYM_BYTES],
    ) -> (MlKemCiphertext, MlKemSharedSecret) {
        let mut shared_secret = MlKemSharedSecret {
            bytes: [0u8; SS_BYTES],
        };
        let c = ml_kem_encaps_internal(
            public_key.params.profile(),
            &public_key.bytes,
            randomness,
            public_key.a_hat(),
            &mut shared_secret.bytes,
        );
        (
            MlKemCiphertext {
                params: public_key.params,
                bytes: c,
            },
            shared_secret,
        )
    }

    /// ML-KEM.Encaps (FIPS 203 Algorithm 20): the message `m` is 32 bytes
    /// from `rng`, and the result is ML-KEM.Encaps_internal(ek, m).
    ///
    /// FIPS 203 §3.3 requires `rng` to be an approved RBG whose security
    /// strength is at least that of the parameter set: 128 bits for
    /// ML-KEM-512, 192 bits for ML-KEM-768, and 256 bits for ML-KEM-1024. The
    /// shared key is only as unpredictable as `m`.
    #[must_use]
    pub fn encaps<R: Csprng>(
        public_key: &MlKemPublicKey,
        rng: &mut R,
    ) -> (MlKemCiphertext, MlKemSharedSecret) {
        let mut m = [0u8; SYM_BYTES];
        rng.fill_bytes(&mut m);
        let result = Self::encaps_with_randomness(public_key, &m);
        crate::ct::zeroize_slice(&mut m);
        result
    }

    /// ML-KEM.Decaps (FIPS 203 Algorithm 21): the shared key for `ciphertext`
    /// under `private_key`.
    ///
    /// `None` means only that the two arguments belong to different parameter
    /// sets. Within one parameter set decapsulation never fails, and `Some`
    /// is not authentication: for a forged or corrupted ciphertext it holds
    /// the implicit-rejection value K̄ = J(z ‖ c) of Algorithm 18, a
    /// pseudorandom key that neither the sender nor anyone else can compute
    /// without `z`, so the two sides simply disagree on the shared key. The
    /// choice between K′ and K̄ is made without a branch, and no indication of
    /// it leaves this function (§6.3).
    ///
    /// The §7.3 ciphertext type check, that `c` has exactly the parameter
    /// set's ciphertext length, is enforced structurally: every
    /// [`MlKemCiphertext`] comes from [`MlKemCiphertext::from_wire_bytes`] or
    /// from encapsulation, and the decapsulation-key type and hash checks
    /// likewise belong to [`MlKemPrivateKey`]'s constructors.
    #[must_use]
    pub fn decaps(
        private_key: &MlKemPrivateKey,
        ciphertext: &MlKemCiphertext,
    ) -> Option<MlKemSharedSecret> {
        if private_key.params != ciphertext.params {
            return None;
        }
        let mut shared_secret = MlKemSharedSecret {
            bytes: [0u8; SS_BYTES],
        };
        ml_kem_decaps_internal(
            private_key.params.profile(),
            &private_key.bytes,
            &ciphertext.bytes,
            private_key.a_hat(),
            &mut shared_secret.bytes,
        );
        Some(shared_secret)
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
        if let Some(seed) = self.seed.as_mut() {
            crate::ct::zeroize_slice(seed.as_mut_slice());
        }
    }
}

/// A heap copy of `seed`, allocated zeroed and filled in place, so that no
/// by-value copy of the secret is made on the way.
fn boxed_seed(seed: &[u8; 2 * SYM_BYTES]) -> Box<[u8; 2 * SYM_BYTES]> {
    let mut boxed = Box::new([0u8; 2 * SYM_BYTES]);
    boxed.copy_from_slice(seed);
    boxed
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

// ===========================================================================
// FIPS 203 arithmetic core
// ===========================================================================
//
// Representation. Every element of Z_q is held as its canonical representative
// in [0, q) in a `u16`, and an array in Z_q^256 (the coefficients of a
// polynomial in R_q, or of an NTT representation in T_q, §2.4.4) is a
// `[u16; 256]`. Arithmetic widens to `u32`/`u64`, reduces, and narrows back, so
// every value a function returns is canonical again. The integers stored are
// the integers the pseudocode manipulates: there is no signed, Montgomery, or
// otherwise scaled form anywhere.
//
// Sums and differences. For a, b in [0, q), both a + b and a + q − b lie in
// [0, 2q), and `reduce_once` maps [0, 2q) onto [0, q) by a masked subtraction.
//
// Products. Barrett's method (P. Barrett, "Implementing the Rivest Shamir and
// Adleman public key encryption algorithm on a standard digital signal
// processor", CRYPTO '86, LNCS 263, pp. 311–323) replaces the division in
// x mod q by a multiplication and a shift. Derivation and bound:
//
//   Let s = 25 and m = ⌊2^s / q⌋ = 10079, so 2^s = m·q + ε with
//   ε = 2^s mod q = 1441 and 0 ≤ ε < q. Take an integer 0 ≤ x < 2^s and write
//   x = Q·q + ρ with 0 ≤ ρ < q. Then
//
//       x·m / 2^s = x·(2^s − ε) / (q·2^s) = x/q − x·ε / (q·2^s),
//
//   and 0 ≤ x·ε / (q·2^s) < 2^s·q / (q·2^s) = 1 because x < 2^s and ε < q.
//   Hence Q − 1 ≤ x/q − 1 < x·m / 2^s ≤ x/q < Q + 1, so the quotient estimate
//   Q̃ = ⌊x·m / 2^s⌋ is Q − 1 or Q, and r = x − Q̃·q is ρ + q or ρ. Either way
//   r ≡ x (mod q) and 0 ≤ r < 2q, so one `reduce_once` completes x mod q.
//
//   Word sizes: x·m < 2^25 · 2^14 = 2^39 fits a u64; Q̃·q ≤ x < 2^25 fits a
//   u32, and the subtraction cannot underflow.
//
//   Why s = 25: it is the least power of two above the largest value any
//   caller reduces, 2(q − 1)^2 = 22 151 168 — BaseCaseMultiply's
//   a0·b0 + (a1·b1 mod q)·γ and a0·b1 + a1·b0 with every operand in [0, q).
//   Debug builds assert the precondition at every call (so every KAT exercises
//   it), and `barrett_reduction_is_exact_on_its_whole_domain` checks both
//   conclusions, 0 ≤ r < 2q and r ≡ x (mod q), for all 2^25 inputs.
//
// Constant time. The coefficients of s, e, y, e1, e2, the message polynomial,
// and everything computed from them are secret. On such values release builds
// perform only +, −, ×, shifts and masks: no data-dependent branch, no
// data-dependent table index, and no `/` or `%`, whose latency can depend on
// the operands (KyberSlash, CVE-2024-37880). Outside the tests, `/` and `%`
// occur only in constant evaluation (`BARRETT_MULTIPLIER`, `pow_mod_q` for the
// tables, ⌊q/2⌋ in `compress_rounding`) and in the NTT's `len /= 2` on its
// public loop bound. Every branch is on public data (lengths, the parameter
// d, SampleNTT's candidates derived from ρ, the §7.2 modulus check on ek) or
// decides whether an imported key is accepted. Debug assertions, which release
// builds omit, are the one place secret values are tested.

/// ζ = 17, the primitive 256th root of unity modulo q that fixes the NTT
/// (FIPS 203 §2.3, §4.3).
const ZETA: u32 = 17;

/// Barrett shift s (derivation above).
const BARRETT_SHIFT: u32 = 25;

/// Barrett multiplier m = ⌊2^s / q⌋ (= 10079), computed rather than transcribed.
const BARRETT_MULTIPLIER: u64 = (1u64 << BARRETT_SHIFT) / Q as u64;

/// An array in Z_q^256 (FIPS 203 §2.4.4): the coefficients of a polynomial in
/// R_q or of an NTT representation in T_q, each canonical in [0, q).
type ZqArray = [u16; N];

/// A length-k vector of arrays (FIPS 203 §2.4.6), held on the stack at the
/// largest rank; entries from index k on are unused and stay zero.
type ZqVector = [ZqArray; MAX_K];

/// A k × k matrix of arrays (FIPS 203 §2.4.6): the public matrix Â, which a
/// key caches. Its k² entries are held on the heap in row-major order, so the
/// cache is the size the parameter set needs and a key stays small by value.
struct ZqMatrix {
    k: usize,
    entries: Box<[ZqArray]>,
}

impl ZqMatrix {
    /// The entry Â[i][j] of row i, column j.
    fn entry(&self, i: usize, j: usize) -> &ZqArray {
        &self.entries[i * self.k + j]
    }

    /// The k rows, each of k entries.
    fn rows(&self) -> impl Iterator<Item = &[ZqArray]> {
        self.entries.chunks_exact(self.k)
    }
}

/// r mod q for 0 ≤ r < 2q, without a branch.
///
/// t = r − q (wrapping) is below q < 2^31 when r ≥ q, and is r − q + 2^32 ≥
/// 2^32 − q > 2^31 when r < q, so bit 31 of t is set exactly when r < q. The
/// mask −(t >> 31) is then all ones, and t + (q & mask) is r; otherwise it is
/// t = r − q.
#[inline]
fn reduce_once(r: u32) -> u32 {
    debug_assert!(r < 2 * Q);
    let t = r.wrapping_sub(Q);
    let mask = 0u32.wrapping_sub(t >> 31);
    t.wrapping_add(Q & mask)
}

/// Barrett reduction without its final correction: for 0 ≤ x < 2^25, returns
/// r ≡ x (mod q) with 0 ≤ r < 2q (derivation at the head of this section).
#[inline]
fn barrett_almost_reduce(x: u32) -> u32 {
    debug_assert!(x < 1 << BARRETT_SHIFT);
    let quotient = ((u64::from(x) * BARRETT_MULTIPLIER) >> BARRETT_SHIFT) as u32;
    x - quotient * Q
}

/// x mod q for 0 ≤ x < 2^25: Barrett reduction, then one `reduce_once`.
#[inline]
fn barrett_mod_q(x: u32) -> u16 {
    reduce_once(barrett_almost_reduce(x)) as u16
}

/// a + b mod q for canonical a, b (the sum lies in [0, 2q)).
#[inline]
fn add_mod_q(a: u16, b: u16) -> u16 {
    reduce_once(u32::from(a) + u32::from(b)) as u16
}

/// a − b mod q for canonical a, b, as a + q − b ∈ (0, 2q).
#[inline]
fn sub_mod_q(a: u16, b: u16) -> u16 {
    reduce_once(u32::from(a) + Q - u32::from(b)) as u16
}

/// a·b mod q for canonical a, b; the product is at most (q − 1)^2 < 2^25.
#[inline]
fn mul_mod_q(a: u16, b: u16) -> u16 {
    barrett_mod_q(u32::from(a) * u32::from(b))
}

/// BitRev7(r) (FIPS 203 §2.3): the integer whose seven-bit binary expansion is
/// that of r read backwards.
const fn bit_rev7(r: usize) -> usize {
    let mut reversed = 0;
    let mut bit = 0;
    while bit < 7 {
        reversed |= ((r >> bit) & 1) << (6 - bit);
        bit += 1;
    }
    reversed
}

/// base^exponent mod q by square-and-multiply. Used only to build constants
/// and tables at compile time from public values, hence the plain `%`.
const fn pow_mod_q(base: u32, mut exponent: u32) -> u32 {
    let mut result = 1;
    let mut square = base % Q;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * square % Q;
        }
        square = square * square % Q;
        exponent >>= 1;
    }
    result
}

/// The table ζ^(scale·BitRev7(i) + offset) mod q for i = 0, …, 127.
const fn zeta_power_table(scale: u32, offset: u32) -> [u16; N / 2] {
    let mut table = [0u16; N / 2];
    let mut i = 0;
    while i < N / 2 {
        table[i] = pow_mod_q(ZETA, scale * bit_rev7(i) as u32 + offset) as u16;
        i += 1;
    }
    table
}

/// ζ^BitRev7(i) mod q for i = 0, …, 127, the constants of line 5 of
/// Algorithms 9 and 10 (FIPS 203 §4.3). Generated from ζ at compile time;
/// `ml_kem_ntt_tables_match_fips203_appendix_a` compares it with Appendix A.
const NTT_ZETAS: [u16; N / 2] = zeta_power_table(1, 0);

/// ζ^(2·BitRev7(i)+1) mod q for i = 0, …, 127: the γ with X^2 − γ the i-th
/// quadratic factor of X^256 + 1 (FIPS 203 (4.10)), as Algorithm 11 uses it.
const MULTIPLY_GAMMAS: [u16; N / 2] = zeta_power_table(2, 1);

/// 128^(−1) mod q = 3303, the final scale of NTT⁻¹ (Algorithm 10, line 14),
/// computed as 128^(q−2) mod q (Fermat's little theorem, q prime).
const NTT_INVERSE_SCALE: u16 = pow_mod_q(128, Q - 2) as u16;

/// ByteEncode_d (FIPS 203 Algorithm 5), with its closing BitsToBytes
/// (Algorithm 3): writes the 32·d-byte encoding of `f` into `out`.
///
/// Algorithm 5 puts bit j of F[i] at position i·d + j of a bit array b, and
/// Algorithm 3 adds b[t]·2^(t mod 8) to byte ⌊t/8⌋; the result is the
/// little-endian concatenation of the d-bit entries. Instead of materializing
/// b, each entry is appended to a bit accumulator above the bits still
/// pending, and each completed byte is emitted. Fewer than 8 bits are pending
/// when an entry arrives, so the accumulator never holds more than 7 + 12 = 19
/// bits. The control flow depends on d alone.
///
/// Every entry must lie below m, where m = 2^d for d < 12 and m = q for d = 12.
fn byte_encode(d: usize, f: &ZqArray, out: &mut [u8]) {
    debug_assert!((1..=12).contains(&d));
    debug_assert_eq!(out.len(), 32 * d);
    let mut pending: u32 = 0;
    let mut pending_bits = 0usize;
    let mut next = 0usize;
    for &entry in f {
        debug_assert!(u32::from(entry) < if d == COEFF_BITS { Q } else { 1 << d });
        pending |= u32::from(entry) << pending_bits;
        pending_bits += d;
        while pending_bits >= 8 {
            out[next] = pending as u8;
            next += 1;
            pending >>= 8;
            pending_bits -= 8;
        }
    }
    debug_assert!(pending_bits == 0 && next == out.len());
}

/// ByteDecode_d (FIPS 203 Algorithm 6), with its opening BytesToBits
/// (Algorithm 4): decodes 32·d bytes into an array.
///
/// BytesToBits lists the bits of each byte least significant first, and line
/// 3 of Algorithm 6 reassembles bits i·d, …, i·d + d − 1 into F[i], so F[i] is
/// the i-th little-endian d-bit field of the input. Bytes enter an accumulator
/// until at least d bits are pending (at most 11 + 8 = 19) and the low d bits
/// are taken. For d = 12 the field, in [0, 4096), is then reduced modulo
/// m = q as line 3 requires; 4096 < 2q, so one `reduce_once` does it. For
/// d < 12 the field already is an element of Z_(2^d).
fn byte_decode(d: usize, bytes: &[u8]) -> ZqArray {
    debug_assert!((1..=12).contains(&d));
    debug_assert_eq!(bytes.len(), 32 * d);
    let field_mask = (1u32 << d) - 1;
    let mut f = [0u16; N];
    let mut pending: u32 = 0;
    let mut pending_bits = 0usize;
    let mut next = 0usize;
    for entry in &mut f {
        while pending_bits < d {
            pending |= u32::from(bytes[next]) << pending_bits;
            next += 1;
            pending_bits += 8;
        }
        let field = pending & field_mask;
        pending >>= d;
        pending_bits -= d;
        let value = if d == COEFF_BITS {
            reduce_once(field)
        } else {
            field
        };
        *entry = value as u16;
    }
    f
}

/// FIPS 203 §4.2.1 `Compress_d(v) = ⌈(2^d / q) · v⌋ mod 2^d` for
/// `v ∈ [0, q)`, evaluated as the integer division
/// `⌊(2^d · v + ⌊q/2⌋) / q⌋ mod 2^d` but without dividing by `q`.
///
/// Compression runs on the decrypted message and on the re-encryption of it
/// inside decapsulation, so a division whose latency depends on the operand
/// (KyberSlash, CVE-2024-37880) would leak the secret. The division by the
/// invariant `q` is replaced by a multiply-and-shift (Granlund & Montgomery,
/// "Division by Invariant Integers using Multiplication", PLDI 1994): with
/// `m = ⌈2^s / q⌉`, `⌊x · m / 2^s⌋ = ⌊x / q⌋` for every `x` below a bound that
/// grows with `s`. The largest dividend here is `(q − 1)·2^11 + 1664 =
/// 6 817 408`; `s = 33` is the smallest shift whose `m = 2 580 335` is exact
/// for every integer `x < 13 788 717`, which covers all `d` at once, and the
/// product stays below 2^44. Both facts were established by exhaustive
/// search, and `compress_rounding_matches_division_for_every_input` re-checks
/// the pair against the rounding division for every `v` and every `d`.
fn compress_rounding(v: u32, d: usize) -> u32 {
    const DIV_Q_MUL: u64 = 2_580_335;
    const DIV_Q_SHIFT: u32 = 33;
    const HALF_Q: u64 = (Q / 2) as u64;
    debug_assert!(
        matches!(d, 1 | 4 | 5 | 10 | 11),
        "ML-KEM compresses to 1, 4, 5, 10, or 11 bits"
    );
    let x = (u64::from(v) << d) + HALF_Q;
    (((x * DIV_Q_MUL) >> DIV_Q_SHIFT) as u32) & ((1u32 << d) - 1)
}

/// Compress_d (FIPS 203 (4.7)) applied to every entry of an array (§2.4.8),
/// through the division-free `compress_rounding`.
fn compress(d: usize, f: &ZqArray) -> ZqArray {
    let mut out = [0u16; N];
    for (y, &x) in out.iter_mut().zip(f) {
        *y = compress_rounding(u32::from(x), d) as u16;
    }
    out
}

/// Decompress_d (FIPS 203 (4.8)) applied to every entry of an array (§2.4.8).
///
/// Decompress_d(y) = ⌈(q / 2^d)·y⌋, where ⌈·⌋ rounds halves up (§2.3), so it
/// equals ⌊(q·y + 2^(d−1)) / 2^d⌋ and the division is a shift by d. For
/// y ≤ 2^d − 1 the rational value is at most q − q/2^d + 1/2 < q (as
/// 2^d < 2q), so the result is canonical, and q·y + 2^(d−1) < 2^23 fits a u32.
fn decompress(d: usize, f: &ZqArray) -> ZqArray {
    debug_assert!((1..12).contains(&d));
    let half = 1u32 << (d - 1);
    let mut out = [0u16; N];
    for (x, &y) in out.iter_mut().zip(f) {
        debug_assert!(u32::from(y) < 1 << d);
        *x = ((Q * u32::from(y) + half) >> d) as u16;
    }
    out
}

/// PRF_η(s, b) = SHAKE256(s ‖ b, 8·64·η) (FIPS 203 (4.2)–(4.3)), written to
/// `out`, which must hold exactly 64·η bytes.
fn prf(eta: usize, s: &[u8; SYM_BYTES], b: u8, out: &mut [u8]) {
    debug_assert_eq!(out.len(), PRF_BYTES_PER_ETA * eta);
    let mut xof = Shake256::new();
    xof.update(s);
    xof.update(&[b]);
    xof.squeeze(out);
}

/// SampleNTT (FIPS 203 Algorithm 7): rejection-samples an element of T_q from
/// SHAKE128 absorbing B = ρ ‖ j ‖ i.
///
/// Every pass squeezes three fresh bytes (line 5) and forms two 12-bit
/// candidates (lines 6–7); each is kept if below q. The input is public, so
/// branching on the candidates reveals nothing secret. The loop is unbounded,
/// as Appendix B recommends.
fn sample_ntt(b: &[u8; SYM_BYTES + 2]) -> ZqArray {
    let mut xof = Shake128::new();
    xof.update(b);
    let mut a_hat = [0u16; N];
    let mut c = [0u8; 3];
    let mut j = 0;
    while j < N {
        xof.squeeze(&mut c);
        // d1 = C[0] + 256·(C[1] mod 16) and d2 = ⌊C[1]/16⌋ + 16·C[2].
        let d1 = u16::from(c[0]) + 256 * u16::from(c[1] & 0x0f);
        let d2 = u16::from(c[1] >> 4) + 16 * u16::from(c[2]);
        if u32::from(d1) < Q {
            a_hat[j] = d1;
            j += 1;
        }
        if u32::from(d2) < Q && j < N {
            a_hat[j] = d2;
            j += 1;
        }
    }
    a_hat
}

/// SamplePolyCBD_η (FIPS 203 Algorithm 8) on B of 64·η bytes.
///
/// Bit t of BytesToBits(B) (Algorithm 4) is bit t mod 8 of byte ⌊t/8⌋. For
/// each i, x sums the η bits from position 2iη (line 3), y the next η bits
/// (line 4), and f[i] = x − y mod q (line 5). The bits are secret: they are
/// only extracted at public positions and added, and x − y mod q is
/// `reduce_once(x + q − y)`, valid since x + q − y ∈ [q − η, q + η] ⊂ [0, 2q).
fn sample_poly_cbd(eta: usize, b: &[u8]) -> ZqArray {
    debug_assert!(eta == 2 || eta == 3);
    debug_assert_eq!(b.len(), 64 * eta);
    let bit = |t: usize| u32::from((b[t >> 3] >> (t & 7)) & 1);
    let mut f = [0u16; N];
    for (i, entry) in f.iter_mut().enumerate() {
        let first = 2 * i * eta;
        let x: u32 = (first..first + eta).map(bit).sum();
        let y: u32 = (first + eta..first + 2 * eta).map(bit).sum();
        *entry = reduce_once(x + Q - y) as u16;
    }
    f
}

/// SamplePolyCBD_η(PRF_η(seed, nonce)), the noise draw of Algorithm 13 (lines
/// 9, 13) and Algorithm 14 (lines 10, 14, 17). The PRF output is wiped.
fn sample_poly_cbd_prf(eta: usize, seed: &[u8; SYM_BYTES], nonce: u8) -> ZqArray {
    let mut buf = [0u8; PRF_BYTES_PER_ETA * MAX_ETA];
    let bytes = &mut buf[..PRF_BYTES_PER_ETA * eta];
    prf(eta, seed, nonce, bytes);
    let f = sample_poly_cbd(eta, bytes);
    crate::ct::zeroize_slice(&mut buf);
    f
}

/// NTT (FIPS 203 Algorithm 9), in place: the coefficients of f ∈ R_q become
/// those of f̂ ∈ T_q.
///
/// Lines 8–10 on canonical values: t = zeta·f̂[j + len] by Barrett reduction
/// (the product is at most (q − 1)^2), then f̂[j + len] = f̂[j] − t and
/// f̂[j] = f̂[j] + t by `sub_mod_q` and `add_mod_q`.
fn ntt(f: &mut ZqArray) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let zeta = NTT_ZETAS[i];
            i += 1;
            let (low, high) = f[start..start + 2 * len].split_at_mut(len);
            for (f_j, f_j_len) in low.iter_mut().zip(high.iter_mut()) {
                let t = mul_mod_q(zeta, *f_j_len);
                *f_j_len = sub_mod_q(*f_j, t);
                *f_j = add_mod_q(*f_j, t);
            }
        }
        len /= 2;
    }
}

/// NTT⁻¹ (FIPS 203 Algorithm 10), in place: the coefficients of f̂ ∈ T_q
/// become those of f ∈ R_q.
///
/// Lines 8–10 on canonical values: f[j] = t + f[j + len] by `add_mod_q`, and
/// f[j + len] = zeta·(f[j + len] − t) by `sub_mod_q` then Barrett reduction.
/// Line 14 scales every entry by 3303 = 128^(−1) mod q.
fn ntt_inverse(f: &mut ZqArray) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        for start in (0..N).step_by(2 * len) {
            let zeta = NTT_ZETAS[i];
            i -= 1;
            let (low, high) = f[start..start + 2 * len].split_at_mut(len);
            for (f_j, f_j_len) in low.iter_mut().zip(high.iter_mut()) {
                let t = *f_j;
                *f_j = add_mod_q(t, *f_j_len);
                *f_j_len = mul_mod_q(zeta, sub_mod_q(*f_j_len, t));
            }
        }
        len *= 2;
    }
    for entry in f.iter_mut() {
        *entry = mul_mod_q(*entry, NTT_INVERSE_SCALE);
    }
}

/// MultiplyNTTs (FIPS 203 Algorithm 11): the product f̂ ×_Tq ĝ, one quadratic
/// factor Z_q[X]/(X^2 − ζ^(2·BitRev7(i)+1)) at a time.
fn multiply_ntts(f: &ZqArray, g: &ZqArray) -> ZqArray {
    let mut h = [0u16; N];
    for (i, &gamma) in MULTIPLY_GAMMAS.iter().enumerate() {
        let (c0, c1) = base_case_multiply(f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], gamma);
        h[2 * i] = c0;
        h[2 * i + 1] = c1;
    }
    h
}

/// BaseCaseMultiply (FIPS 203 Algorithm 12): (a0 + a1·X)(b0 + b1·X) modulo
/// X^2 − γ, i.e. c0 = a0·b0 + a1·b1·γ and c1 = a0·b1 + a1·b0.
///
/// With canonical inputs, a0·b0 + (a1·b1 mod q)·γ and a0·b1 + a1·b0 are each
/// at most 2(q − 1)^2 < 2^25, so one Barrett reduction apiece suffices.
fn base_case_multiply(a0: u16, a1: u16, b0: u16, b1: u16, gamma: u16) -> (u16, u16) {
    let a1_b1 = u32::from(mul_mod_q(a1, b1));
    let (a0, a1, b0, b1) = (u32::from(a0), u32::from(a1), u32::from(b0), u32::from(b1));
    let c0 = barrett_mod_q(a0 * b0 + a1_b1 * u32::from(gamma));
    let c1 = barrett_mod_q(a0 * b1 + a1 * b0);
    (c0, c1)
}

/// f ← f + g coordinate-wise (FIPS 203 §2.4.5).
fn array_add_assign(f: &mut ZqArray, g: &ZqArray) {
    for (x, &y) in f.iter_mut().zip(g) {
        *x = add_mod_q(*x, y);
    }
}

/// f ← f − g coordinate-wise (FIPS 203 §2.4.5).
fn array_sub_assign(f: &mut ZqArray, g: &ZqArray) {
    for (x, &y) in f.iter_mut().zip(g) {
        *x = sub_mod_q(*x, y);
    }
}

/// Â ∘ û (FIPS 203 (2.12)): entry i is Σ_j Â[i][j] ×_Tq û[j].
fn matrix_mul_vector(k: usize, a_hat: &ZqMatrix, u_hat: &ZqVector) -> ZqVector {
    debug_assert_eq!(a_hat.k, k);
    let mut w_hat = [[0u16; N]; MAX_K];
    for (w_i, a_row) in w_hat.iter_mut().zip(a_hat.rows()) {
        for (a_ij, u_j) in a_row.iter().zip(u_hat) {
            let mut product = multiply_ntts(a_ij, u_j);
            array_add_assign(w_i, &product);
            crate::ct::zeroize_slice(&mut product);
        }
    }
    w_hat
}

/// Â^T ∘ û (FIPS 203 (2.13)): entry i is Σ_j Â[j][i] ×_Tq û[j].
fn matrix_transpose_mul_vector(k: usize, a_hat: &ZqMatrix, u_hat: &ZqVector) -> ZqVector {
    debug_assert_eq!(a_hat.k, k);
    let mut y_hat = [[0u16; N]; MAX_K];
    for (i, y_i) in y_hat.iter_mut().enumerate().take(k) {
        for (j, u_j) in u_hat.iter().enumerate().take(k) {
            let mut product = multiply_ntts(a_hat.entry(j, i), u_j);
            array_add_assign(y_i, &product);
            crate::ct::zeroize_slice(&mut product);
        }
    }
    y_hat
}

/// û^T ∘ v̂ (FIPS 203 (2.14)): Σ_j û[j] ×_Tq v̂[j].
fn dot_product(k: usize, u_hat: &ZqVector, v_hat: &ZqVector) -> ZqArray {
    let mut z_hat = [0u16; N];
    for (u_j, v_j) in u_hat.iter().zip(v_hat).take(k) {
        let mut product = multiply_ntts(u_j, v_j);
        array_add_assign(&mut z_hat, &product);
        crate::ct::zeroize_slice(&mut product);
    }
    z_hat
}

/// Overwrite every entry of a vector with zeros.
fn zeroize_vector(v: &mut ZqVector) {
    for f in v.iter_mut() {
        crate::ct::zeroize_slice(f);
    }
}

/// The matrix Â with Â[i][j] = SampleNTT(ρ ‖ j ‖ i) (FIPS 203 Algorithm 13,
/// lines 3–7; Algorithm 14, lines 4–8): j and i are bytes 33 and 34 of the
/// SampleNTT input.
fn sample_a_hat(k: usize, rho: &[u8; SYM_BYTES]) -> ZqMatrix {
    let mut entries = vec![[0u16; N]; k * k].into_boxed_slice();
    let mut b = [0u8; SYM_BYTES + 2];
    b[..SYM_BYTES].copy_from_slice(rho);
    for (i, row) in entries.chunks_exact_mut(k).enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            b[SYM_BYTES] = j as u8;
            b[SYM_BYTES + 1] = i as u8;
            *entry = sample_ntt(&b);
        }
    }
    ZqMatrix { k, entries }
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13): the encryption key ek_PKE (384k + 32
/// bytes) and decryption key dk_PKE (384k bytes) for the 32-byte seed d.
fn k_pke_keygen(p: Profile, d: &[u8; SYM_BYTES]) -> (Vec<u8>, Vec<u8>) {
    let k = p.k;

    // Line 1: (ρ, σ) ← G(d ‖ k).
    let mut g_input = [0u8; SYM_BYTES + 1];
    g_input[..SYM_BYTES].copy_from_slice(d);
    g_input[SYM_BYTES] = k as u8;
    let mut g_output = hash_g(&g_input);
    let mut rho = [0u8; SYM_BYTES];
    let mut sigma = [0u8; SYM_BYTES];
    rho.copy_from_slice(&g_output[..SYM_BYTES]);
    sigma.copy_from_slice(&g_output[SYM_BYTES..]);
    crate::ct::zeroize_slice(&mut g_input);
    crate::ct::zeroize_slice(&mut g_output);

    // Lines 3–7.
    let a_hat = sample_a_hat(k, &rho);

    // Lines 2 and 8–15: s[i] uses PRF nonce N = i, e[i] uses N = k + i.
    let mut s = [[0u16; N]; MAX_K];
    for (i, s_i) in s.iter_mut().enumerate().take(k) {
        *s_i = sample_poly_cbd_prf(p.eta1, &sigma, i as u8);
    }
    let mut e = [[0u16; N]; MAX_K];
    for (i, e_i) in e.iter_mut().enumerate().take(k) {
        *e_i = sample_poly_cbd_prf(p.eta1, &sigma, (k + i) as u8);
    }
    crate::ct::zeroize_slice(&mut sigma);

    // Lines 16–17, in place: s and e now hold ŝ and ê.
    for (s_i, e_i) in s.iter_mut().zip(e.iter_mut()).take(k) {
        ntt(s_i);
        ntt(e_i);
    }

    // Line 18: t̂ ← Â ∘ ŝ + ê.
    let mut t_hat = matrix_mul_vector(k, &a_hat, &s);
    for (t_i, e_i) in t_hat.iter_mut().zip(&e).take(k) {
        array_add_assign(t_i, e_i);
    }

    // Lines 19–20: ek_PKE ← ByteEncode_12(t̂) ‖ ρ and dk_PKE ← ByteEncode_12(ŝ).
    let mut ek_pke = vec![0u8; POLY_BYTES * k + SYM_BYTES];
    let (encoded_t, seed) = ek_pke.split_at_mut(POLY_BYTES * k);
    for (chunk, t_i) in encoded_t.chunks_exact_mut(POLY_BYTES).zip(&t_hat) {
        byte_encode(12, t_i, chunk);
    }
    seed.copy_from_slice(&rho);
    let mut dk_pke = vec![0u8; POLY_BYTES * k];
    for (chunk, s_i) in dk_pke.chunks_exact_mut(POLY_BYTES).zip(&s) {
        byte_encode(12, s_i, chunk);
    }

    zeroize_vector(&mut s);
    zeroize_vector(&mut e);
    (ek_pke, dk_pke)
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14): encrypts the 32-byte message m
/// under ek_PKE with the 32-byte randomness r.
///
/// `a_hat` must be the matrix of lines 4–8, expanded from the seed ρ =
/// ek_PKE[384k : 384k + 32] (line 3); §3.3 allows it to be stored with the key,
/// which is how the callers supply it.
fn k_pke_encrypt(
    p: Profile,
    ek_pke: &[u8],
    m: &[u8; SYM_BYTES],
    r: &[u8; SYM_BYTES],
    a_hat: &ZqMatrix,
) -> Vec<u8> {
    let k = p.k;
    debug_assert_eq!(ek_pke.len(), POLY_BYTES * k + SYM_BYTES);

    // Line 2: t̂ ← ByteDecode_12(ek_PKE[0 : 384k]).
    let mut t_hat = [[0u16; N]; MAX_K];
    for (t_i, chunk) in t_hat
        .iter_mut()
        .zip(ek_pke.chunks_exact(POLY_BYTES))
        .take(k)
    {
        *t_i = byte_decode(12, chunk);
    }

    // Lines 1 and 9–17: y[i] uses PRF nonce N = i, e1[i] uses N = k + i, and
    // e2 uses N = 2k.
    let mut y = [[0u16; N]; MAX_K];
    for (i, y_i) in y.iter_mut().enumerate().take(k) {
        *y_i = sample_poly_cbd_prf(p.eta1, r, i as u8);
    }
    let mut e1 = [[0u16; N]; MAX_K];
    for (i, e1_i) in e1.iter_mut().enumerate().take(k) {
        *e1_i = sample_poly_cbd_prf(p.eta2, r, (k + i) as u8);
    }
    let mut e2 = sample_poly_cbd_prf(p.eta2, r, (2 * k) as u8);

    // Line 18, in place: y now holds ŷ.
    for y_i in y.iter_mut().take(k) {
        ntt(y_i);
    }

    // Line 19: u ← NTT⁻¹(Â^T ∘ ŷ) + e1.
    let mut u = matrix_transpose_mul_vector(k, a_hat, &y);
    for (u_i, e1_i) in u.iter_mut().zip(&e1).take(k) {
        ntt_inverse(u_i);
        array_add_assign(u_i, e1_i);
    }

    // Line 20: μ ← Decompress_1(ByteDecode_1(m)).
    let mut message_bits = byte_decode(1, m);
    let mut mu = decompress(1, &message_bits);

    // Line 21: v ← NTT⁻¹(t̂^T ∘ ŷ) + e2 + μ.
    let mut v = dot_product(k, &t_hat, &y);
    ntt_inverse(&mut v);
    array_add_assign(&mut v, &e2);
    array_add_assign(&mut v, &mu);

    // Lines 22–24: c ← ByteEncode_du(Compress_du(u)) ‖ ByteEncode_dv(Compress_dv(v)).
    let c1_len = 32 * p.du * k;
    let mut c = vec![0u8; c1_len + 32 * p.dv];
    let (c1, c2) = c.split_at_mut(c1_len);
    for (chunk, u_i) in c1.chunks_exact_mut(32 * p.du).zip(&u) {
        let mut compressed = compress(p.du, u_i);
        byte_encode(p.du, &compressed, chunk);
        crate::ct::zeroize_slice(&mut compressed);
    }
    let mut compressed = compress(p.dv, &v);
    byte_encode(p.dv, &compressed, c2);

    crate::ct::zeroize_slice(&mut compressed);
    zeroize_vector(&mut y);
    zeroize_vector(&mut e1);
    zeroize_vector(&mut u);
    crate::ct::zeroize_slice(&mut e2);
    crate::ct::zeroize_slice(&mut message_bits);
    crate::ct::zeroize_slice(&mut mu);
    crate::ct::zeroize_slice(&mut v);
    c
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15): recovers the 32-byte message from
/// the ciphertext c with dk_PKE.
fn k_pke_decrypt(p: Profile, dk_pke: &[u8], c: &[u8]) -> [u8; SYM_BYTES] {
    let k = p.k;
    debug_assert_eq!(dk_pke.len(), POLY_BYTES * k);
    debug_assert_eq!(c.len(), 32 * (p.du * k + p.dv));

    // Lines 1–2.
    let (c1, c2) = c.split_at(32 * p.du * k);

    // Lines 3–4: u′ ← Decompress_du(ByteDecode_du(c1)), v′ likewise with dv.
    let mut u_prime = [[0u16; N]; MAX_K];
    for (u_i, chunk) in u_prime.iter_mut().zip(c1.chunks_exact(32 * p.du)) {
        *u_i = decompress(p.du, &byte_decode(p.du, chunk));
    }
    let v_prime = decompress(p.dv, &byte_decode(p.dv, c2));

    // Line 5: ŝ ← ByteDecode_12(dk_PKE).
    let mut s_hat = [[0u16; N]; MAX_K];
    for (s_i, chunk) in s_hat.iter_mut().zip(dk_pke.chunks_exact(POLY_BYTES)) {
        *s_i = byte_decode(12, chunk);
    }

    // Line 6: w ← v′ − NTT⁻¹(ŝ^T ∘ NTT(u′)).
    for u_i in u_prime.iter_mut().take(k) {
        ntt(u_i);
    }
    let mut s_dot_u = dot_product(k, &s_hat, &u_prime);
    ntt_inverse(&mut s_dot_u);
    let mut w = v_prime;
    array_sub_assign(&mut w, &s_dot_u);

    // Line 7: m ← ByteEncode_1(Compress_1(w)).
    let mut compressed = compress(1, &w);
    let mut m = [0u8; SYM_BYTES];
    byte_encode(1, &compressed, &mut m);

    zeroize_vector(&mut s_hat);
    crate::ct::zeroize_slice(&mut s_dot_u);
    crate::ct::zeroize_slice(&mut w);
    crate::ct::zeroize_slice(&mut compressed);
    m
}

/// ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16): ek = ek_PKE and
/// dk = dk_PKE ‖ ek ‖ H(ek) ‖ z.
fn ml_kem_keygen_internal(
    p: Profile,
    d: &[u8; SYM_BYTES],
    z: &[u8; SYM_BYTES],
) -> (Vec<u8>, Vec<u8>) {
    let (ek, mut dk_pke) = k_pke_keygen(p, d);
    let mut dk = Vec::with_capacity(2 * POLY_BYTES * p.k + 3 * SYM_BYTES);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&hash_h(&ek));
    dk.extend_from_slice(z);
    crate::ct::zeroize_slice(&mut dk_pke);
    (ek, dk)
}

/// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17): returns the ciphertext c
/// for ek and the 32-byte randomness m, and writes the shared key K into
/// `shared_key`, the caller's own storage, so no copy of K is left on this
/// function's stack. `a_hat` is ek's matrix Â.
fn ml_kem_encaps_internal(
    p: Profile,
    ek: &[u8],
    m: &[u8; SYM_BYTES],
    a_hat: &ZqMatrix,
    shared_key: &mut [u8; SS_BYTES],
) -> Vec<u8> {
    // Line 1: (K, r) ← G(m ‖ H(ek)).
    let mut g_input = [0u8; 2 * SYM_BYTES];
    g_input[..SYM_BYTES].copy_from_slice(m);
    g_input[SYM_BYTES..].copy_from_slice(&hash_h(ek));
    let mut g_output = hash_g(&g_input);
    let mut r = [0u8; SYM_BYTES];
    shared_key.copy_from_slice(&g_output[..SS_BYTES]);
    r.copy_from_slice(&g_output[SS_BYTES..SS_BYTES + SYM_BYTES]);
    crate::ct::zeroize_slice(&mut g_input);
    crate::ct::zeroize_slice(&mut g_output);

    // Line 2: c ← K-PKE.Encrypt(ek, m, r).
    let c = k_pke_encrypt(p, ek, m, &r, a_hat);
    crate::ct::zeroize_slice(&mut r);
    c
}

/// ML-KEM.Decaps_internal (FIPS 203 Algorithm 18): writes the shared key for
/// the ciphertext c under dk into `shared_key`, the caller's own storage, so
/// no copy of it is left on this function's stack. `a_hat` is Â for the
/// encapsulation key inside dk.
///
/// The comparison of c with the re-encryption c′ (line 9) and the choice
/// between K′ and K̄ (line 10) are branch-free, so the implicit-rejection flag
/// never steers control flow; as §6.3 requires, it is not returned in any form
/// and is wiped before the function returns.
fn ml_kem_decaps_internal(
    p: Profile,
    dk: &[u8],
    c: &[u8],
    a_hat: &ZqMatrix,
    shared_key: &mut [u8; SS_BYTES],
) {
    let k = p.k;
    debug_assert_eq!(dk.len(), 2 * POLY_BYTES * k + 3 * SYM_BYTES);

    // Lines 1–4.
    let (dk_pke, rest) = dk.split_at(POLY_BYTES * k);
    let (ek_pke, rest) = rest.split_at(POLY_BYTES * k + SYM_BYTES);
    let (h, z) = rest.split_at(SYM_BYTES);

    // Line 5: m′ ← K-PKE.Decrypt(dk_PKE, c).
    let mut m_prime = k_pke_decrypt(p, dk_pke, c);

    // Line 6: (K′, r′) ← G(m′ ‖ h).
    let mut g_input = [0u8; 2 * SYM_BYTES];
    g_input[..SYM_BYTES].copy_from_slice(&m_prime);
    g_input[SYM_BYTES..].copy_from_slice(h);
    let mut g_output = hash_g(&g_input);
    let mut k_prime = [0u8; SS_BYTES];
    let mut r_prime = [0u8; SYM_BYTES];
    k_prime.copy_from_slice(&g_output[..SS_BYTES]);
    r_prime.copy_from_slice(&g_output[SS_BYTES..SS_BYTES + SYM_BYTES]);
    crate::ct::zeroize_slice(&mut g_input);
    crate::ct::zeroize_slice(&mut g_output);

    // Line 7: K̄ ← J(z ‖ c).
    let mut j_input = Vec::with_capacity(SYM_BYTES + c.len());
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(c);
    let mut k_bar = hash_j(&j_input);
    crate::ct::zeroize_slice(j_input.as_mut_slice());

    // Line 8: c′ ← K-PKE.Encrypt(ek_PKE, m′, r′).
    let mut c_prime = k_pke_encrypt(p, ek_pke, &m_prime, &r_prime, a_hat);
    crate::ct::zeroize_slice(&mut m_prime);
    crate::ct::zeroize_slice(&mut r_prime);

    // Lines 9–11: K′ if c = c′, else K̄, selected by mask.
    let mut equal = crate::ct::constant_time_eq_mask(c, &c_prime);
    for ((out, &good), &reject) in shared_key.iter_mut().zip(&k_prime).zip(&k_bar) {
        *out = (good & equal) | (reject & !equal);
    }
    crate::ct::zeroize_slice(core::slice::from_mut(&mut equal));
    crate::ct::zeroize_slice(c_prime.as_mut_slice());
    crate::ct::zeroize_slice(&mut k_prime);
    crate::ct::zeroize_slice(&mut k_bar);
}

/// The encapsulation-key modulus check of FIPS 203 §7.2, (7.1): each 384-byte
/// block of ek[0 : 384k] must equal ByteEncode_12(ByteDecode_12(block)), which
/// holds exactly when every 12-bit field already lies in [0, q − 1].
fn modulus_check(k: usize, ek: &[u8]) -> bool {
    let mut test = [0u8; POLY_BYTES];
    ek[..POLY_BYTES * k].chunks_exact(POLY_BYTES).all(|block| {
        byte_encode(12, &byte_decode(12, block), &mut test);
        test[..] == *block
    })
}

/// Whether dk_PKE (384k bytes) consists of canonical ByteEncode_12 blocks, by
/// the same round trip as `modulus_check` but compared without early exit,
/// because dk_PKE encodes the secret ŝ. FIPS 203 §7.3 does not require this;
/// the crate checks it on import.
fn dk_pke_is_canonical(dk_pke: &[u8]) -> bool {
    let mut all_equal = 0xffu8;
    let mut test = [0u8; POLY_BYTES];
    for block in dk_pke.chunks_exact(POLY_BYTES) {
        let mut decoded = byte_decode(12, block);
        byte_encode(12, &decoded, &mut test);
        all_equal &= crate::ct::constant_time_eq_mask(&test, block);
        crate::ct::zeroize_slice(&mut decoded);
    }
    crate::ct::zeroize_slice(&mut test);
    all_equal == 0xff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key::io::der_octet_string;
    use crate::public_key::pkix::NULL_PARAMETERS;
    use crate::test_utils::{
        decode_hex, decode_hex_array, openssl3, parse_vector_map, ScratchFile,
    };
    use std::collections::HashMap;

    /// q as an i32, for the signed representatives FIPS 203 Appendix A prints.
    const Q_I32: i32 = Q as i32;

    /// The multiply-and-shift constants in `compress_rounding` must equal
    /// the rounding division `⌊(2^d·v + q/2) / q⌋ mod 2^d` for every field
    /// element and every compression width the scheme uses.
    #[test]
    fn compress_rounding_matches_division_for_every_input() {
        let q = Q;
        for d in [1usize, 4, 5, 10, 11] {
            for v in 0..q {
                let reference = (((v << d) + q / 2) / q) & ((1u32 << d) - 1);
                assert_eq!(
                    super::compress_rounding(v, d),
                    reference,
                    "d = {d}, v = {v}"
                );
            }
        }
    }

    const ALL_PARAMS: [MlKemParameterSet; 3] = [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ];

    #[test]
    fn ml_kem_parameter_lengths_match_profiles() {
        // The ciphertext literal must agree with the FIPS 203 formula
        // 32·(d_u·k + d_v) evaluated on the profile.
        for params in ALL_PARAMS {
            let p = params.profile();
            assert_eq!(
                params.ciphertext_len(),
                32 * (p.du * p.k + p.dv),
                "{params:?}"
            );
        }

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
    fn wire_and_blob_roundtrips() {
        let params = MlKemParameterSet::MlKem768;
        let seed = [0x42u8; 64];
        let (pk, sk) = MlKem::keygen_from_seed(params, &seed);
        let mut m = [0u8; 32];
        m.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (i as u8).wrapping_mul(17));
        let (ct, ss) = MlKem::encaps_with_randomness(&pk, &m);
        let ss2 = MlKem::decaps(&sk, &ct).expect("decaps");
        assert_eq!(ss, ss2);

        let pk_blob = pk.to_key_blob();
        let sk_blob = sk.to_key_blob();
        let ct_wire = ct.to_wire_bytes();

        assert_eq!(MlKemPublicKey::from_key_blob(&pk_blob).expect("pk"), pk);
        assert_eq!(
            MlKemPrivateKey::from_key_blob(&sk_blob, &mut test_rng()).expect("sk"),
            sk
        );
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
            let (pk, sk) = MlKem::keygen_from_seed(params, &seed);
            let msg = [msg_byte; 32];
            let (ct, ss) = MlKem::encaps_with_randomness(&pk, &msg);
            let ss_recv = MlKem::decaps(&sk, &ct).expect("decaps");
            assert_eq!(ss, ss_recv, "{params:?}");
        }
    }

    #[test]
    fn implicit_rejection_is_deterministic_and_distinct() {
        // FIPS 203 decapsulation never fails on a well-formed-length ciphertext:
        // a tampered ciphertext yields the deterministic implicit-rejection key
        // K̄ = J(z || c), not the true shared secret and not an error.
        let params = MlKemParameterSet::MlKem768;
        let seed = [0x42u8; 64];
        let (pk, sk) = MlKem::keygen_from_seed(params, &seed);
        let msg = [0x24u8; 32];
        let (ct, ss) = MlKem::encaps_with_randomness(&pk, &msg);

        // Flip a bit; length stays valid so this exercises implicit rejection,
        // not the length check.
        let mut bad = ct.to_wire_bytes();
        bad[0] ^= 1;
        let bad_ct = MlKemCiphertext::from_wire_bytes(params, &bad).expect("valid length");

        let rej1 = MlKem::decaps(&sk, &bad_ct).expect("decaps returns a key, never None");
        let rej2 = MlKem::decaps(&sk, &bad_ct).expect("decaps");

        assert_eq!(rej1, rej2, "rejection key must be deterministic in (z, c)");
        assert_ne!(
            rej1, ss,
            "rejection key must differ from the true shared secret"
        );
    }

    #[test]
    fn ml_kem_512_acvp_keygen_encaps_and_implicit_rejection_decaps() {
        // Source: NIST ACVP-Server ML-KEM keyGen and encapDecap FIPS203 files
        // at RELEASE/v1.1.0.40: keyGen tgId 1 tcId 1, encapsulation tgId 1
        // tcId 1, and decapsulation tgId 4 tcId 76 (the file header gives the
        // commit).
        //
        // What this pins: ML-KEM-512 keyGen (ek only), one honest
        // encapsulation (c and K), and one decapsulation whose ciphertext does
        // NOT re-encrypt to itself, so the expected K is the implicit-rejection
        // value J(z || c) — asserted below. The successful-decapsulation path
        // and the other parameter sets are pinned by the reference KATs in
        // `ml_kem_*_matches_reference_kat_for_every_parameter_set` and by the
        // current ACVP release in `ml_kem_*_nist_acvp_*`.
        let vectors = parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_kem_fips203_subset.txt"
        )));

        let d: [u8; 32] = decode_hex_array(vectors["KEYGEN_D"]);
        let z: [u8; 32] = decode_hex_array(vectors["KEYGEN_Z"]);
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);

        let (pk, _sk) = MlKem::keygen_from_seed(MlKemParameterSet::MlKem512, &seed);
        assert_eq!(pk.to_wire_bytes(), decode_hex(vectors["KEYGEN_EK"]));

        let encap_pk = MlKemPublicKey::from_wire_bytes(
            MlKemParameterSet::MlKem512,
            &decode_hex(vectors["ENCAP_EK"]),
        )
        .expect("encap pk");
        let m: [u8; 32] = decode_hex_array(vectors["ENCAP_M"]);
        let (ct, ss) = MlKem::encaps_with_randomness(&encap_pk, &m);
        assert_eq!(ct.to_wire_bytes(), decode_hex(vectors["ENCAP_C"]));
        assert_eq!(
            ss.to_wire_bytes(),
            decode_hex_array::<SS_BYTES>(vectors["ENCAP_K"])
        );

        let decap_sk = MlKemPrivateKey::from_wire_bytes(
            MlKemParameterSet::MlKem512,
            &decode_hex(vectors["DECAP_DK"]),
            &mut test_rng(),
        )
        .expect("decap sk");
        let decap_ct = MlKemCiphertext::from_wire_bytes(
            MlKemParameterSet::MlKem512,
            &decode_hex(vectors["DECAP_C"]),
        )
        .expect("decap ct");
        let decap_ss = MlKem::decaps(&decap_sk, &decap_ct).expect("decaps");
        let expected_k = decode_hex_array::<SS_BYTES>(vectors["DECAP_K"]);
        assert_eq!(decap_ss.to_wire_bytes(), expected_k);

        // This ACVP case is an implicit rejection: K = J(z || c), z being the
        // last 32 bytes of dk.
        let dk = decode_hex(vectors["DECAP_DK"]);
        let mut z_c = dk[dk.len() - SYM_BYTES..].to_vec();
        z_c.extend_from_slice(&decap_ct.to_wire_bytes());
        assert_eq!(
            hash_j(&z_c),
            expected_k,
            "ACVP tgId 4 tcId 76 is a rejection case"
        );
    }

    // ---- Reference-implementation known answers (all parameter sets) ----
    //
    // tests/vectors/ml_kem_ref_kat.txt is produced by running the
    // pq-crystals/kyber reference as an oracle (scripts/gen_pq_ref_vectors.sh).

    const REF_KAT_SETS: [(MlKemParameterSet, &str); 3] = [
        (MlKemParameterSet::MlKem512, "MLKEM512"),
        (MlKemParameterSet::MlKem768, "MLKEM768"),
        (MlKemParameterSet::MlKem1024, "MLKEM1024"),
    ];

    fn ref_kat_vectors() -> HashMap<&'static str, &'static str> {
        parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_kem_ref_kat.txt"
        )))
    }

    fn ref_kat(vectors: &HashMap<&str, &str>, prefix: &str, name: &str) -> Vec<u8> {
        let key = format!("{prefix}_{name}");
        decode_hex(vectors[key.as_str()])
    }

    fn ref_kat_seed(vectors: &HashMap<&str, &str>, prefix: &str) -> [u8; 2 * SYM_BYTES] {
        let mut seed = [0u8; 2 * SYM_BYTES];
        seed[..SYM_BYTES].copy_from_slice(&ref_kat(vectors, prefix, "D"));
        seed[SYM_BYTES..].copy_from_slice(&ref_kat(vectors, prefix, "Z"));
        seed
    }

    #[test]
    fn ml_kem_keygen_matches_reference_kat_for_every_parameter_set() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let seed = ref_kat_seed(&vectors, prefix);
            let (pk, sk) = MlKem::keygen_from_seed(params, &seed);
            // Both keys byte-for-byte: this pins the decapsulation-key layout
            // dk_PKE || ek || H(ek) || z, not just its length.
            assert_eq!(
                pk.to_wire_bytes(),
                ref_kat(&vectors, prefix, "PK"),
                "{params:?} ek"
            );
            assert_eq!(
                sk.to_wire_bytes(),
                ref_kat(&vectors, prefix, "SK"),
                "{params:?} dk"
            );
        }
    }

    #[test]
    fn ml_kem_encaps_and_decaps_match_reference_kat_for_every_parameter_set() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let expected_ct = ref_kat(&vectors, prefix, "CT");
            let expected_ss: [u8; SS_BYTES] = ref_kat(&vectors, prefix, "SS")
                .try_into()
                .expect("32-byte shared secret");
            let m: [u8; SYM_BYTES] = ref_kat(&vectors, prefix, "M")
                .try_into()
                .expect("32-byte m");

            // Encapsulate to the imported ek.
            let pk = MlKemPublicKey::from_wire_bytes(params, &ref_kat(&vectors, prefix, "PK"))
                .expect("ek");
            let (ct, ss) = MlKem::encaps_with_randomness(&pk, &m);
            assert_eq!(ct.to_wire_bytes(), expected_ct, "{params:?} c");
            assert_eq!(ss.to_wire_bytes(), expected_ss, "{params:?} K");

            // Successful decapsulation, with both an imported dk and one this
            // crate generated from the same seed.
            let imported = MlKemPrivateKey::from_wire_bytes(
                params,
                &ref_kat(&vectors, prefix, "SK"),
                &mut test_rng(),
            )
            .expect("dk");
            let ct = MlKemCiphertext::from_wire_bytes(params, &expected_ct).expect("c");
            assert_eq!(
                MlKem::decaps(&imported, &ct)
                    .expect("decaps")
                    .to_wire_bytes(),
                expected_ss,
                "{params:?} decaps with imported dk"
            );
            let (_, generated) = MlKem::keygen_from_seed(params, &ref_kat_seed(&vectors, prefix));
            assert_eq!(
                MlKem::decaps(&generated, &ct)
                    .expect("decaps")
                    .to_wire_bytes(),
                expected_ss,
                "{params:?} decaps with generated dk"
            );
        }
    }

    #[test]
    fn ml_kem_implicit_rejection_matches_reference_kat_for_every_parameter_set() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let sk = MlKemPrivateKey::from_wire_bytes(
                params,
                &ref_kat(&vectors, prefix, "SK"),
                &mut test_rng(),
            )
            .expect("dk");
            let index = usize::from(ref_kat(&vectors, prefix, "CTBAD_INDEX")[0]);
            let mask = ref_kat(&vectors, prefix, "CTBAD_XOR")[0];
            let expected_bad: [u8; SS_BYTES] = ref_kat(&vectors, prefix, "SSBAD")
                .try_into()
                .expect("32-byte rejection secret");

            let mut bad = ref_kat(&vectors, prefix, "CT");
            bad[index] ^= mask;
            let bad_ct = MlKemCiphertext::from_wire_bytes(params, &bad).expect("c'");
            let ss_bad = MlKem::decaps(&sk, &bad_ct).expect("decaps never fails on a well-sized c");
            assert_eq!(ss_bad.to_wire_bytes(), expected_bad, "{params:?} K-bar");
            assert_ne!(
                ss_bad.to_wire_bytes().as_slice(),
                ref_kat(&vectors, prefix, "SS").as_slice()
            );

            // FIPS 203 Algorithm 18 fixes the rejection value as J(z || c').
            let mut z_c = ref_kat(&vectors, prefix, "Z");
            z_c.extend_from_slice(&bad);
            assert_eq!(hash_j(&z_c), expected_bad, "{params:?} K-bar = J(z || c')");
        }
    }

    // ---- FIPS 203 arithmetic core ----

    #[test]
    fn ml_kem_ntt_tables_match_fips203_appendix_a() {
        // FIPS 203 Appendix A, first table: ζ^BitRev7(i) mod q for
        // i = 0, …, 127, transcribed from the standard.
        const APPENDIX_A_ZETAS: [u16; 128] = [
            1, 1729, 2580, 3289, 2642, 630, 1897, 848, //
            1062, 1919, 193, 797, 2786, 3260, 569, 1746, //
            296, 2447, 1339, 1476, 3046, 56, 2240, 1333, //
            1426, 2094, 535, 2882, 2393, 2879, 1974, 821, //
            289, 331, 3253, 1756, 1197, 2304, 2277, 2055, //
            650, 1977, 2513, 632, 2865, 33, 1320, 1915, //
            2319, 1435, 807, 452, 1438, 2868, 1534, 2402, //
            2647, 2617, 1481, 648, 2474, 3110, 1227, 910, //
            17, 2761, 583, 2649, 1637, 723, 2288, 1100, //
            1409, 2662, 3281, 233, 756, 2156, 3015, 3050, //
            1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, //
            939, 2308, 2437, 2388, 733, 2337, 268, 641, //
            1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, //
            1063, 319, 2773, 757, 2099, 561, 2466, 2594, //
            2804, 1092, 403, 1026, 1143, 2150, 2775, 886, //
            1722, 1212, 1874, 1029, 2110, 2935, 885, 2154, //
        ];
        // FIPS 203 Appendix A, second table: ζ^(2·BitRev7(i)+1) mod q for
        // i = 0, …, 127, which the standard prints as signed representatives.
        const APPENDIX_A_GAMMAS: [i16; 128] = [
            17, -17, 2761, -2761, 583, -583, 2649, -2649, //
            1637, -1637, 723, -723, 2288, -2288, 1100, -1100, //
            1409, -1409, 2662, -2662, 3281, -3281, 233, -233, //
            756, -756, 2156, -2156, 3015, -3015, 3050, -3050, //
            1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, //
            1847, -1847, 952, -952, 1461, -1461, 2687, -2687, //
            939, -939, 2308, -2308, 2437, -2437, 2388, -2388, //
            733, -733, 2337, -2337, 268, -268, 641, -641, //
            1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220, //
            375, -375, 2549, -2549, 2090, -2090, 1645, -1645, //
            1063, -1063, 319, -319, 2773, -2773, 757, -757, //
            2099, -2099, 561, -561, 2466, -2466, 2594, -2594, //
            2804, -2804, 1092, -1092, 403, -403, 1026, -1026, //
            1143, -1143, 2150, -2150, 2775, -2775, 886, -886, //
            1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029, //
            2110, -2110, 2935, -2935, 885, -885, 2154, -2154, //
        ];

        assert_eq!(NTT_ZETAS, APPENDIX_A_ZETAS);
        for (i, (&computed, &printed)) in MULTIPLY_GAMMAS
            .iter()
            .zip(APPENDIX_A_GAMMAS.iter())
            .enumerate()
        {
            assert_eq!(
                i32::from(computed),
                i32::from(printed).rem_euclid(Q_I32),
                "gamma[{i}]"
            );
        }
        // §4.3: ζ = 17 is a primitive 256th root of unity (ζ^128 = −1, so its
        // order divides 256 but not 128), and Algorithm 10 scales by
        // 3303 = 128^(−1) mod q.
        assert_eq!(pow_mod_q(ZETA, 128), Q - 1);
        assert_eq!(NTT_INVERSE_SCALE, 3303);
        assert_eq!(u32::from(NTT_INVERSE_SCALE) * 128 % Q, 1);
    }

    /// Exhaustive check of the Barrett bound derived in the arithmetic-core
    /// comment: for every x in the domain [0, 2^25), the uncorrected result r
    /// satisfies 0 ≤ r < 2q and r ≡ x (mod q); `reduce_once` is exact on
    /// [0, 2q); and the domain covers the largest input the callers form.
    #[test]
    fn barrett_reduction_is_exact_on_its_whole_domain() {
        let q = Q;
        assert_eq!(BARRETT_MULTIPLIER, 10_079);
        for x in 0..1u32 << BARRETT_SHIFT {
            let r = barrett_almost_reduce(x);
            assert!(r < 2 * q && r % q == x % q, "x = {x}, r = {r}");
        }
        for r in 0..2 * q {
            assert_eq!(reduce_once(r), r % q, "r = {r}");
        }
        // 2(q − 1)^2 is BaseCaseMultiply's largest pre-reduction value, and
        // s = 25 is the least shift whose domain contains it.
        let largest_input = 2 * (q - 1) * (q - 1);
        assert!(largest_input < 1 << BARRETT_SHIFT);
        assert!(largest_input >= 1 << (BARRETT_SHIFT - 1));
    }

    /// Marsaglia's xorshift64, a deterministic source of test inputs.
    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn random_array(state: &mut u64, modulus: u32) -> ZqArray {
        let mut f = [0u16; N];
        for entry in &mut f {
            *entry = (xorshift64(state) % u64::from(modulus)) as u16;
        }
        f
    }

    #[test]
    fn ntt_inverse_undoes_ntt_on_random_polynomials() {
        let mut state = 0x9e37_79b9_7f4a_7c15;
        let mut inputs: Vec<ZqArray> = (0..500).map(|_| random_array(&mut state, Q)).collect();
        inputs.push([0; N]);
        inputs.push([1; N]);
        inputs.push([(Q - 1) as u16; N]);
        for f in inputs {
            let mut forward_then_back = f;
            ntt(&mut forward_then_back);
            ntt_inverse(&mut forward_then_back);
            assert_eq!(forward_then_back, f);

            let mut back_then_forward = f;
            ntt_inverse(&mut back_then_forward);
            ntt(&mut back_then_forward);
            assert_eq!(back_then_forward, f);
        }
    }

    /// Multiplication in R_q = Z_q[X]/(X^256 + 1) by the schoolbook method,
    /// with plain `%` (test-only, no secrets).
    fn schoolbook_multiply(f: &ZqArray, g: &ZqArray) -> ZqArray {
        let q = u64::from(Q);
        let mut wide = [0u64; 2 * N];
        for (i, &f_i) in f.iter().enumerate() {
            for (j, &g_j) in g.iter().enumerate() {
                wide[i + j] += u64::from(f_i) * u64::from(g_j);
            }
        }
        let (low, high) = wide.split_at(N);
        let mut h = [0u16; N];
        for ((h_i, &lo), &hi) in h.iter_mut().zip(low).zip(high) {
            // X^256 = −1.
            *h_i = ((lo % q + q - hi % q) % q) as u16;
        }
        h
    }

    #[test]
    fn multiply_ntts_is_multiplication_in_r_q() {
        // FIPS 203 (4.9): f ×_Rq g = NTT⁻¹(NTT(f) ×_Tq NTT(g)).
        let mut state = 0x0123_4567_89ab_cdef;
        let mut x = [0u16; N];
        x[1] = 1;
        let mut x_255 = [0u16; N];
        x_255[255] = 1;
        let mut pairs = vec![(x, x_255)];
        for _ in 0..25 {
            pairs.push((random_array(&mut state, Q), random_array(&mut state, Q)));
        }
        for (f, g) in pairs {
            let (mut f_hat, mut g_hat) = (f, g);
            ntt(&mut f_hat);
            ntt(&mut g_hat);
            let mut h = multiply_ntts(&f_hat, &g_hat);
            ntt_inverse(&mut h);
            assert_eq!(h, schoolbook_multiply(&f, &g));
        }
    }

    #[test]
    fn byte_codec_and_compression_follow_fips203_section_4_2_1() {
        let mut state = 0xfeed_face_cafe_beef;
        for d in 1..=12usize {
            let modulus = if d == 12 { Q } else { 1 << d };
            for _ in 0..20 {
                let f = random_array(&mut state, modulus);
                let mut bytes = vec![0u8; 32 * d];
                byte_encode(d, &f, &mut bytes);
                assert_eq!(byte_decode(d, &bytes), f, "d = {d}");
            }
        }

        // Bits are little-endian within bytes and entries (Algorithms 3 and
        // 5): with d = 1, entry 9 is bit 1 of byte 1; with d = 12, entry 1
        // starts at bit 4 of byte 1.
        let mut f = [0u16; N];
        f[9] = 1;
        let mut bytes = [0u8; 32];
        byte_encode(1, &f, &mut bytes);
        assert_eq!(bytes[..3], [0, 0b10, 0]);
        let mut f = [0u16; N];
        f[1] = 0xabc;
        let mut bytes = [0u8; POLY_BYTES];
        byte_encode(12, &f, &mut bytes);
        assert_eq!(bytes[..4], [0x00, 0xc0, 0xab, 0x00]);

        // ByteDecode_12 reduces each field modulo q: 4095 decodes to 766.
        assert!(byte_decode(12, &[0xff; POLY_BYTES])
            .iter()
            .all(|&entry| u32::from(entry) == 4095 - Q));

        // §4.2.1: Compress_d(Decompress_d(y)) = y for every y and every d used.
        for d in [1usize, 4, 5, 10, 11] {
            let values: Vec<u16> = (0..1u16 << d).collect();
            for chunk in values.chunks(N) {
                let mut y = [0u16; N];
                y[..chunk.len()].copy_from_slice(chunk);
                assert_eq!(compress(d, &decompress(d, &y)), y, "d = {d}");
            }
        }
    }

    #[test]
    fn encapsulation_key_modulus_check_rejects_unreduced_fields() {
        let params = MlKemParameterSet::MlKem768;
        let (pk, _) = MlKem::keygen_from_seed(params, &[7u8; 64]);
        let mut ek = pk.to_wire_bytes();
        // The first 12-bit field is byte 0 plus the low nibble of byte 1.
        ek[0] = 0x00;
        ek[1] = (ek[1] & 0xf0) | 0x0d;
        assert!(
            MlKemPublicKey::from_wire_bytes(params, &ek).is_some(),
            "0xd00 = q − 1 is canonical"
        );
        ek[0] = 0x01;
        assert!(
            MlKemPublicKey::from_wire_bytes(params, &ek).is_none(),
            "0xd01 = q must fail the FIPS 203 §7.2 modulus check"
        );
    }

    /// Each parameter set with its RFC 9935 name and its Appendix C.1
    /// subsection number.
    const NAMED_PARAMS: [(MlKemParameterSet, &str, usize); 3] = [
        (MlKemParameterSet::MlKem512, "ML-KEM-512", 1),
        (MlKemParameterSet::MlKem768, "ML-KEM-768", 2),
        (MlKemParameterSet::MlKem1024, "ML-KEM-1024", 3),
    ];

    /// The identifier octet of the private-key `CHOICE` alternative inside the
    /// DER `OneAsymmetricKey` `der`: 0x80 seed, 0x04 expandedKey, 0x30 both.
    fn private_key_alternative(der: &[u8]) -> u8 {
        OneAsymmetricKey::from_der(der)
            .expect("OneAsymmetricKey")
            .private_key()[0]
    }

    /// The keys of RFC 9935 Appendix C, under the provenance note in the file.
    const RFC9935_APPENDIX_C: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/rfc9935_appendix_c.txt"
    ));

    /// The textual encoding printed under `heading` in the extract.
    fn rfc9935_example(heading: &str) -> &'static str {
        let marker = format!("\n{heading}\n");
        let start = RFC9935_APPENDIX_C
            .find(&marker)
            .unwrap_or_else(|| panic!("no {heading:?} in the RFC 9935 extract"))
            + marker.len();
        let text = &RFC9935_APPENDIX_C[start..];
        let boundary = text
            .find("-----END ")
            .expect("a post-encapsulation boundary");
        let end = boundary + text[boundary..].find('\n').expect("a line end") + 1;
        &text[..end]
    }

    /// The random source the importers' pair-wise consistency test draws from.
    fn test_rng() -> crate::CtrDrbgAes256 {
        crate::CtrDrbgAes256::new(&[0x5c; 48])
    }

    /// A random source that counts the bytes drawn from it.
    struct CountingRng {
        inner: crate::CtrDrbgAes256,
        drawn: usize,
    }

    impl Csprng for CountingRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.drawn += out.len();
            self.inner.fill_bytes(out);
        }
    }

    /// What `import` returns, and how many bytes it drew from `rng`.
    fn drawn_by<T>(
        rng: &mut CountingRng,
        import: impl FnOnce(&mut CountingRng) -> T,
    ) -> (T, usize) {
        let before = rng.drawn;
        let imported = import(rng);
        (imported, rng.drawn - before)
    }

    /// `dk` as a private key, with none of the import checks applied.
    fn unchecked_private_key(params: MlKemParameterSet, dk: &[u8]) -> MlKemPrivateKey {
        MlKemPrivateKey {
            params,
            bytes: dk.to_vec(),
            seed: None,
            a_hat: OnceLock::new(),
        }
    }

    /// `dk` read through each import path that takes a decapsulation key
    /// without its seed: the path, what it returned, and the bytes it drew.
    fn import_expanded(
        params: MlKemParameterSet,
        dk: &[u8],
        rng: &mut CountingRng,
    ) -> [(&'static str, (Option<MlKemPrivateKey>, usize)); 4] {
        let unchecked = unchecked_private_key(params, dk);
        let blob = unchecked.to_key_blob();
        let der = unchecked.to_pkcs8_der();
        let pem = unchecked.to_pkcs8_pem();
        [
            (
                "from_wire_bytes",
                drawn_by(rng, |rng| MlKemPrivateKey::from_wire_bytes(params, dk, rng)),
            ),
            (
                "from_key_blob",
                drawn_by(rng, |rng| MlKemPrivateKey::from_key_blob(&blob, rng)),
            ),
            (
                "from_pkcs8_der",
                drawn_by(rng, |rng| MlKemPrivateKey::from_pkcs8_der(&der, rng)),
            ),
            (
                "from_pkcs8_pem",
                drawn_by(rng, |rng| MlKemPrivateKey::from_pkcs8_pem(&pem, rng)),
            ),
        ]
    }

    /// The `expandedKey` inside the PKCS #8 text `pem`, alone or within `both`.
    fn expanded_key_in(pem: &str) -> Vec<u8> {
        pem_decode(PRIVATE_KEY_LABEL, pem, |der| {
            let package = OneAsymmetricKey::from_der(der)?;
            let params = MlKemParameterSet::from_algorithm(package.algorithm())?;
            match PrivateKeyChoice::from_der(
                package.private_key(),
                2 * SYM_BYTES,
                params.private_key_len(),
            )? {
                PrivateKeyChoice::ExpandedKey(expanded_key)
                | PrivateKeyChoice::Both { expanded_key, .. } => Some(expanded_key.to_vec()),
                PrivateKeyChoice::Seed(_) => None,
            }
        })
        .expect("an expanded key")
    }

    #[test]
    fn rfc9935_appendix_c1_private_keys_decode_in_every_form() {
        // "all derived from the same seed 000102...1e1f", continued to 64 bytes.
        let seed: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).expect("below 64"));
        let mut rng = test_rng();
        for (params, name, subsection) in NAMED_PARAMS {
            let (public, generated) = MlKem::keygen_from_seed(params, &seed);
            let seed_pem = rfc9935_example(&format!("C.1.{subsection}.1 {name} seed"));
            let expanded_pem = rfc9935_example(&format!("C.1.{subsection}.2 {name} expandedKey"));
            let both_pem = rfc9935_example(&format!("C.1.{subsection}.3 {name} both"));
            let from_seed = MlKemPrivateKey::from_pkcs8_pem(seed_pem, &mut rng).expect("seed form");
            let from_expanded =
                MlKemPrivateKey::from_pkcs8_pem(expanded_pem, &mut rng).expect("expanded form");
            let from_both = MlKemPrivateKey::from_pkcs8_pem(both_pem, &mut rng).expect("both form");
            assert_eq!(from_seed, generated, "{name}");
            assert_eq!(from_expanded, generated, "{name}");
            assert_eq!(from_both, generated, "{name}");
            // A key with its seed writes the seed form and one without writes
            // the expanded form, each exactly as the RFC prints it.
            assert_eq!(generated.to_pkcs8_pem(), seed_pem, "{name}");
            assert_eq!(from_seed.to_pkcs8_pem(), seed_pem, "{name}");
            assert_eq!(from_both.to_pkcs8_pem(), seed_pem, "{name}");
            assert_eq!(from_expanded.to_pkcs8_pem(), expanded_pem, "{name}");

            // Appendix C.2 prints the public key these private keys hold.
            let public_pem = rfc9935_example(&format!("C.2 {name} public key"));
            assert_eq!(
                MlKemPublicKey::from_spki_pem(public_pem).as_ref(),
                Some(&public),
                "{name}"
            );
            assert_eq!(public.to_spki_pem(), public_pem, "{name}");
            assert_eq!(from_expanded.encapsulation_key(), public.to_wire_bytes());
        }
    }

    #[test]
    fn rfc9935_appendix_c4_inconsistent_private_keys() {
        // The first and fourth examples are `both` whose seed and expanded key
        // disagree (the fourth only in z): the §8 seed consistency check
        // refuses them. The third alters H(ek): the FIPS 203 §7.3 hash check
        // refuses it. The second alters ŝ under an intact H(ek): the FIPS 203
        // §7.1 pair-wise consistency test refuses it.
        let params = MlKemParameterSet::MlKem512;
        let mut rng = test_rng();
        for example in 1..=4 {
            let pem = rfc9935_example(&format!("C.4.1 example {example}"));
            assert!(
                MlKemPrivateKey::from_pkcs8_pem(pem, &mut rng).is_none(),
                "example {example}"
            );
        }

        // The second example's key passes the §7.2 and §7.3 checks and is
        // canonically packed, so the pair-wise test alone refuses it, on every
        // path that reads a decapsulation key without its seed.
        let second = expanded_key_in(rfc9935_example("C.4.1 example 2"));
        let k = params.k();
        let (dk_pke, rest) = second.split_at(POLY_BYTES * k);
        let (ek, trailer) = rest.split_at(POLY_BYTES * k + SYM_BYTES);
        assert!(modulus_check(k, ek) && dk_pke_is_canonical(dk_pke));
        assert_eq!(hash_h(ek).as_slice(), &trailer[..SYM_BYTES]);
        let mut counting = CountingRng {
            inner: test_rng(),
            drawn: 0,
        };
        for (path, (imported, drawn)) in import_expanded(params, &second, &mut counting) {
            assert!(imported.is_none(), "{path}");
            assert_eq!(drawn, SYM_BYTES, "{path} ran the pair-wise test");
        }

        // What the appendix says the pair-wise test finds: the second and
        // third examples fail it, whatever message is drawn, and the fourth,
        // whose vectors are intact, passes it.
        let passes = |example: u32, rng: &mut crate::CtrDrbgAes256| {
            let dk = expanded_key_in(rfc9935_example(&format!("C.4.1 example {example}")));
            unchecked_private_key(params, &dk).pair_wise_consistency(rng)
        };
        for _ in 0..8 {
            assert!(!passes(2, &mut rng));
            assert!(!passes(3, &mut rng));
            assert!(passes(4, &mut rng));
        }
        // So the fourth example's expanded key alone is accepted: without its
        // seed nothing shows that z was altered, as FIPS 203 §7.1 cautions.
        let fourth = expanded_key_in(rfc9935_example("C.4.1 example 4"));
        assert!(MlKemPrivateKey::from_wire_bytes(params, &fourth, &mut rng).is_some());
    }

    /// `MlKem::keygen` draws d and z (64 bytes) and then the 32-byte message
    /// of the FIPS 140-3 IG 10.3.A pair-wise consistency test, and returns
    /// exactly the pair KeyGen_internal(d, z) makes. The pair also agrees
    /// with itself under a fresh encapsulation.
    #[test]
    fn keygen_runs_the_pair_wise_consistency_test_on_the_new_pair() {
        for params in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let mut rng = CountingRng {
                inner: crate::CtrDrbgAes256::new(&[0x2e; 48]),
                drawn: 0,
            };
            let mut replay = crate::CtrDrbgAes256::new(&[0x2e; 48]);
            let mut seed = [0u8; 2 * SYM_BYTES];
            replay.fill_bytes(&mut seed);
            let (expected_pk, expected_sk) = MlKem::keygen_from_seed(params, &seed);

            let ((pk, sk), drawn) = drawn_by(&mut rng, |rng| {
                MlKem::keygen(params, rng).expect("a generated pair passes its own test")
            });
            assert_eq!(
                drawn,
                3 * SYM_BYTES,
                "{params:?}: d, z and the test message"
            );
            assert_eq!(pk.to_wire_bytes(), expected_pk.to_wire_bytes());
            assert_eq!(sk.to_wire_bytes(), expected_sk.to_wire_bytes());
            // The test encapsulated to the returned public key and
            // decapsulated with the returned private key: both caches of Â
            // are filled, where KeyGen_internal alone fills neither.
            assert!(pk.a_hat.get().is_some() && sk.a_hat.get().is_some());
            assert!(expected_pk.a_hat.get().is_none() && expected_sk.a_hat.get().is_none());

            let (ct, shared) = MlKem::encaps(&pk, &mut rng);
            assert_eq!(MlKem::decaps(&sk, &ct), Some(shared));
        }
    }

    #[test]
    fn expanded_keys_get_the_pair_wise_consistency_test_on_every_import_path() {
        let mut keygen_rng = crate::CtrDrbgAes256::new(&[0x71; 48]);
        let mut rng = CountingRng {
            inner: test_rng(),
            drawn: 0,
        };
        for (params, name, _) in NAMED_PARAMS {
            let (_, generated) = MlKem::keygen(params, &mut keygen_rng).expect("keygen");
            let dk = generated.to_wire_bytes();

            // Key generation's own key is accepted on each path that reads dk
            // without its seed, and each draws one 32-byte message for the test.
            for (path, (imported, drawn)) in import_expanded(params, &dk, &mut rng) {
                assert_eq!(imported.as_ref(), Some(&generated), "{name} {path}");
                assert_eq!(drawn, SYM_BYTES, "{name} {path}");
            }
            // A seed proves dk: the seed and both forms draw nothing.
            let seed = generated.seed.as_deref().expect("keygen keeps its seed");
            let both = ml_pkix::private_key_to_pkcs8(
                params.algorithm(),
                PrivateKeyChoice::Both {
                    seed: seed.as_slice(),
                    expanded_key: &dk,
                },
            );
            for (form, der) in [("seed", generated.to_pkcs8_der()), ("both", both)] {
                let (imported, drawn) =
                    drawn_by(&mut rng, |rng| MlKemPrivateKey::from_pkcs8_der(&der, rng));
                assert_eq!(imported.as_ref(), Some(&generated), "{name} {form}");
                assert_eq!(drawn, 0, "{name} {form}");
            }

            // ŝ with its first coefficient moved by one: still canonically
            // packed, under the same ek and H(ek), so only the pair-wise test
            // can refuse it, and on every path it does.
            let mut altered = dk.clone();
            let mut s_hat_0 = byte_decode(12, &altered[..POLY_BYTES]);
            s_hat_0[0] = add_mod_q(s_hat_0[0], 1);
            byte_encode(12, &s_hat_0, &mut altered[..POLY_BYTES]);
            for (path, (imported, drawn)) in import_expanded(params, &altered, &mut rng) {
                assert!(imported.is_none(), "{name} {path}");
                assert_eq!(drawn, SYM_BYTES, "{name} {path}");
            }
        }
    }

    #[test]
    fn pkcs8_ber_accepts_an_indefinite_length_container() {
        let params = MlKemParameterSet::MlKem768;
        let mut rng = test_rng();
        let (_, generated) = MlKem::keygen_from_seed(params, &[0x33; 64]);
        let der = generated.to_pkcs8_der();
        let ber = crate::test_utils::der_to_indefinite_length(&der);
        assert!(MlKemPrivateKey::from_pkcs8_der(&ber, &mut rng).is_none());
        let from_ber = MlKemPrivateKey::from_pkcs8_ber(&ber, &mut rng).expect("BER");
        assert_eq!(from_ber.to_pkcs8_der(), der);
        let from_der = MlKemPrivateKey::from_pkcs8_ber(&der, &mut rng).expect("DER is BER");
        assert_eq!(from_der.to_pkcs8_der(), der);
    }

    #[test]
    fn pkcs8_writes_the_seed_when_retained_and_the_expanded_key_otherwise() {
        let params = MlKemParameterSet::MlKem768;
        let mut rng = test_rng();
        let (_, generated) = MlKem::keygen_from_seed(params, &[0x33; 64]);
        let expanded_only =
            MlKemPrivateKey::from_wire_bytes(params, &generated.to_wire_bytes(), &mut rng)
                .expect("dk");
        assert_eq!(private_key_alternative(&generated.to_pkcs8_der()), 0x80);
        assert_eq!(private_key_alternative(&expanded_only.to_pkcs8_der()), 0x04);

        // Either form reads back as the same key, and an expanded key does not
        // gain a seed on the way.
        let reread =
            MlKemPrivateKey::from_pkcs8_der(&expanded_only.to_pkcs8_der(), &mut rng).expect("dk");
        assert_eq!(reread, generated);
        assert_eq!(private_key_alternative(&reread.to_pkcs8_der()), 0x04);
        assert_eq!(
            MlKemPrivateKey::from_pkcs8_der(&generated.to_pkcs8_der(), &mut rng).as_ref(),
            Some(&generated)
        );

        // Random key generation keeps the seed too; the crate's own forms are
        // unchanged by it.
        let (_, random) =
            MlKem::keygen(params, &mut crate::CtrDrbgAes256::new(&[0x44; 48])).expect("keygen");
        assert_eq!(private_key_alternative(&random.to_pkcs8_der()), 0x80);
        assert_eq!(random.to_key_blob()[1..], random.to_wire_bytes());
        assert_eq!(
            MlKemPrivateKey::from_key_blob(&random.to_key_blob(), &mut rng).as_ref(),
            Some(&random)
        );
    }

    #[test]
    fn spki_and_pkcs8_refuse_what_rfc9935_does_not_allow() {
        let params = MlKemParameterSet::MlKem512;
        let seed = [0x21u8; 64];
        let (public, private) = MlKem::keygen_from_seed(params, &seed);
        let mut rng = test_rng();
        let absent = AlgorithmIdentifier::new(params.algorithm(), None);
        let null = AlgorithmIdentifier::new(params.algorithm(), Some(NULL_PARAMETERS));
        let other_set = AlgorithmIdentifier::new(MlKemParameterSet::MlKem768.algorithm(), None);
        let ek = public.to_wire_bytes();
        let dk = private.to_wire_bytes();

        assert_eq!(
            MlKemPublicKey::from_spki_der(&public.to_spki_der()).as_ref(),
            Some(&public)
        );
        let spki = |algorithm: AlgorithmIdentifier<'static>, key: &[u8]| {
            SubjectPublicKeyInfo::new(algorithm, key).to_der()
        };
        // The first 12-bit field set to 4095, beyond q (the §7.2 modulus check).
        let mut unreduced = ek.clone();
        unreduced[0] = 0xff;
        unreduced[1] |= 0x0f;
        let mut trailing = public.to_spki_der();
        trailing.push(0);
        for (der, why) in [
            (spki(null, &ek), "NULL parameters"),
            (spki(other_set, &ek), "another parameter set's identifier"),
            (spki(absent, &ek[..ek.len() - 1]), "a truncated key"),
            (spki(absent, &unreduced), "an unreduced coefficient"),
            (trailing, "bytes after the SEQUENCE"),
        ] {
            assert!(MlKemPublicKey::from_spki_der(&der).is_none(), "{why}");
        }

        let package = |algorithm: AlgorithmIdentifier<'static>,
                       private_key: &[u8],
                       public_key: Option<&[u8]>| {
            OneAsymmetricKey::new(algorithm, private_key, public_key).to_der()
        };
        let seed_form = PrivateKeyChoice::Seed(&seed).to_der();
        let expanded_form = PrivateKeyChoice::ExpandedKey(&dk).to_der();
        let both_form = PrivateKeyChoice::Both {
            seed: &seed,
            expanded_key: &dk,
        }
        .to_der();
        // Every alternative is accepted, with or without the matching public key.
        for form in [&seed_form, &expanded_form, &both_form] {
            for public_key in [None, Some(&ek[..])] {
                assert_eq!(
                    MlKemPrivateKey::from_pkcs8_der(&package(absent, form, public_key), &mut rng)
                        .as_ref(),
                    Some(&private)
                );
            }
        }

        let (other_public, _) = MlKem::keygen_from_seed(params, &[0x22; 64]);
        let mut other_z = dk.clone();
        *other_z.last_mut().expect("non-empty") ^= 0x01;
        let mut other_hash = dk.clone();
        other_hash[dk.len() - 2 * SYM_BYTES - 1] ^= 0x01;
        let mut trailing = package(absent, &seed_form, None);
        trailing.push(0);
        let refused = [
            (package(null, &seed_form, None), "NULL parameters"),
            (
                package(other_set, &expanded_form, None),
                "an ML-KEM-768 identifier on an ML-KEM-512 key",
            ),
            (
                package(absent, &PrivateKeyChoice::Seed(&seed[..63]).to_der(), None),
                "a short seed",
            ),
            (
                package(
                    absent,
                    &PrivateKeyChoice::ExpandedKey(&other_hash).to_der(),
                    None,
                ),
                "an expanded key failing the hash check",
            ),
            (
                package(
                    absent,
                    &PrivateKeyChoice::Both {
                        seed: &seed,
                        expanded_key: &other_z,
                    }
                    .to_der(),
                    None,
                ),
                "both, disagreeing in z",
            ),
            (
                package(
                    absent,
                    &PrivateKeyChoice::Both {
                        seed: &[0x22; 64],
                        expanded_key: &dk,
                    }
                    .to_der(),
                    None,
                ),
                "both, with another seed",
            ),
            (package(absent, &seed, None), "a bare seed"),
            (
                package(absent, &der_octet_string(&seed_form), None),
                "a seed wrapped twice",
            ),
            (
                package(absent, &seed_form, Some(&other_public.to_wire_bytes())),
                "another key's public key",
            ),
            (
                package(absent, &expanded_form, Some(&ek[..ek.len() - 1])),
                "a truncated public key",
            ),
            (trailing, "bytes after the SEQUENCE"),
        ];
        for (der, why) in refused {
            assert!(
                MlKemPrivateKey::from_pkcs8_der(&der, &mut rng).is_none(),
                "{why}"
            );
        }
    }

    /// For every parameter set the installed OpenSSL lists: the crate reads
    /// OpenSSL's key in each of its private-key output forms and decapsulates
    /// what OpenSSL encapsulated; OpenSSL reads the crate's key in the seed and
    /// the expanded form, derives the same public key, and decapsulates what
    /// the crate encapsulated.
    #[test]
    fn openssl_ml_kem_keys_interoperate() {
        const TEST: &str = "openssl_ml_kem_keys_interoperate";
        let Some(listing) = openssl3(&["list", "-kem-algorithms"], b"").or_skip(TEST) else {
            return;
        };
        let listing = String::from_utf8_lossy(&listing).into_owned();
        let mut rng = test_rng();
        let run = |args: &[&str], stdin: &[u8]| {
            openssl3(args, stdin)
                .or_skip(TEST)
                .expect("openssl ran once already")
        };
        for (params, name, _) in NAMED_PARAMS {
            if !listing.contains(name) {
                eprintln!("skipping {TEST} for {name}: the installed openssl does not list it");
                continue;
            }
            let theirs_pem = run(&["genpkey", "-algorithm", name], b"");
            let theirs = MlKemPrivateKey::from_pkcs8_pem(
                std::str::from_utf8(&theirs_pem).expect("PEM is ASCII"),
                &mut rng,
            )
            .expect("OpenSSL's PKCS #8 key");
            assert_eq!(theirs.parameter_set(), params);
            let theirs_spki = run(&["pkey", "-pubout", "-outform", "DER"], &theirs_pem);
            let theirs_public = MlKemPublicKey::from_spki_der(&theirs_spki)
                .expect("OpenSSL's SubjectPublicKeyInfo");
            assert_eq!(theirs.encapsulation_key(), theirs_public.to_wire_bytes());
            assert_eq!(theirs_public.to_spki_der(), theirs_spki);
            // The same key in each of OpenSSL's private-key output forms: the
            // alternative OpenSSL wrote is checked, and so is whether the key
            // read from it keeps its seed.
            for (form, alternative, keeps_seed) in [
                ("seed-only", 0x80, true),
                ("priv-only", 0x04, false),
                ("seed-priv", 0x30, true),
            ] {
                let provparam = format!("ml-kem.output_formats={form}");
                let Some(der) = openssl3(
                    &["pkey", "-provparam", &provparam, "-outform", "DER"],
                    &theirs_pem,
                )
                .or_skip(&format!("{TEST} ({name}, {form})")) else {
                    continue;
                };
                assert_eq!(private_key_alternative(&der), alternative, "{name} {form}");
                let read = MlKemPrivateKey::from_pkcs8_der(&der, &mut rng).expect("OpenSSL's key");
                assert_eq!(read, theirs, "{name} {form}");
                assert_eq!(read.seed.is_some(), keeps_seed, "{name} {form}");
            }
            let public_file = ScratchFile::new(
                TEST,
                &format!("{name}-theirs.pem"),
                theirs_public.to_spki_pem().as_bytes(),
            );
            let ciphertext_file = ScratchFile::new(TEST, &format!("{name}-theirs.ct"), b"");
            let secret_file = ScratchFile::new(TEST, &format!("{name}-theirs.ss"), b"");
            run(
                &[
                    "pkeyutl",
                    "-encap",
                    "-pubin",
                    "-inkey",
                    public_file.arg(),
                    "-out",
                    ciphertext_file.arg(),
                    "-secret",
                    secret_file.arg(),
                ],
                b"",
            );
            let ciphertext = MlKemCiphertext::from_wire_bytes(params, &ciphertext_file.read())
                .expect("OpenSSL's ciphertext");
            let shared = MlKem::decaps(&theirs, &ciphertext).expect("decaps");
            assert_eq!(secret_file.read(), shared.to_wire_bytes(), "{name}");

            let (public, ours) = MlKem::keygen_from_seed(params, &[0x6b; 64]);
            let expanded_only =
                MlKemPrivateKey::from_wire_bytes(params, &ours.to_wire_bytes(), &mut rng)
                    .expect("dk");
            assert_eq!(
                run(
                    &["pkey", "-pubin", "-outform", "DER"],
                    public.to_spki_pem().as_bytes()
                ),
                public.to_spki_der()
            );
            let (ciphertext, shared) = MlKem::encaps_with_randomness(&public, &[0x6c; 32]);
            for key in [&ours, &expanded_only] {
                let pem = key.to_pkcs8_pem();
                assert_eq!(
                    run(&["pkey", "-pubout", "-outform", "DER"], pem.as_bytes()),
                    public.to_spki_der(),
                    "{name}"
                );
                let reemitted = run(&["pkey", "-outform", "DER"], pem.as_bytes());
                let reread =
                    MlKemPrivateKey::from_pkcs8_der(&reemitted, &mut rng).expect("re-emitted key");
                assert_eq!(reread, ours, "{name}");
                // OpenSSL writes a seed back exactly when it was given one.
                assert_eq!(reread.seed.is_some(), key.seed.is_some(), "{name}");
                let text = run(&["pkey", "-text", "-noout"], pem.as_bytes());
                assert!(String::from_utf8_lossy(&text).contains(&format!("{name} Private-Key")));
                let key_file = ScratchFile::new(TEST, &format!("{name}-ours.pem"), pem.as_bytes());
                let ciphertext_file = ScratchFile::new(
                    TEST,
                    &format!("{name}-ours.ct"),
                    &ciphertext.to_wire_bytes(),
                );
                let secret_file = ScratchFile::new(TEST, &format!("{name}-ours.ss"), b"");
                run(
                    &[
                        "pkeyutl",
                        "-decap",
                        "-inkey",
                        key_file.arg(),
                        "-in",
                        ciphertext_file.arg(),
                        "-secret",
                        secret_file.arg(),
                    ],
                    b"",
                );
                assert_eq!(secret_file.read(), shared.to_wire_bytes(), "{name}");
            }
        }
    }

    /// `MlKem::pair_wise_consistency` asks whether a public key and a private
    /// key held separately agree: a matched pair passes, a public key paired
    /// with another seed's private key fails whatever message is drawn, and
    /// keys of different parameter sets fail before anything is drawn.
    #[test]
    fn pair_wise_consistency_tells_a_matched_pair_from_a_mismatched_one() {
        let mut rng = CountingRng {
            inner: test_rng(),
            drawn: 0,
        };
        for params in ALL_PARAMS {
            let (pk_a, sk_a) = MlKem::keygen_from_seed(params, &[0xa1; 64]);
            let (pk_b, sk_b) = MlKem::keygen_from_seed(params, &[0xb2; 64]);
            for _ in 0..4 {
                let (consistent, drawn) = drawn_by(&mut rng, |rng| {
                    MlKem::pair_wise_consistency(&pk_a, &sk_a, rng)
                });
                assert!(consistent, "{params:?}: a matched pair");
                assert_eq!(drawn, SYM_BYTES, "{params:?}: one message");
                let (consistent, drawn) = drawn_by(&mut rng, |rng| {
                    MlKem::pair_wise_consistency(&pk_a, &sk_b, rng)
                });
                assert!(!consistent, "{params:?}: pk from seed A, sk from seed B");
                assert_eq!(drawn, SYM_BYTES, "{params:?}: one message");
                let (consistent, _) = drawn_by(&mut rng, |rng| {
                    MlKem::pair_wise_consistency(&pk_b, &sk_a, rng)
                });
                assert!(!consistent, "{params:?}: pk from seed B, sk from seed A");
            }
        }
        let (pk_512, _) = MlKem::keygen_from_seed(MlKemParameterSet::MlKem512, &[0xc3; 64]);
        let (_, sk_768) = MlKem::keygen_from_seed(MlKemParameterSet::MlKem768, &[0xc3; 64]);
        let (consistent, drawn) = drawn_by(&mut rng, |rng| {
            MlKem::pair_wise_consistency(&pk_512, &sk_768, rng)
        });
        assert!(!consistent, "different parameter sets");
        assert_eq!(drawn, 0, "refused before a message is drawn");
    }

    /// Every wire constructor accepts exactly its parameter set's length: one
    /// byte more, one byte fewer, and nothing at all are refused, and the
    /// private-key constructor refuses them before drawing its test message.
    #[test]
    fn wire_constructors_refuse_every_wrong_length() {
        let mut rng = CountingRng {
            inner: test_rng(),
            drawn: 0,
        };
        for params in ALL_PARAMS {
            let (pk, sk) = MlKem::keygen_from_seed(params, &[0x5a; 64]);
            let (ct, ss) = MlKem::encaps_with_randomness(&pk, &[0x3c; 32]);
            let (ek, dk, c, k) = (
                pk.to_wire_bytes(),
                sk.to_wire_bytes(),
                ct.to_wire_bytes(),
                ss.to_wire_bytes().to_vec(),
            );
            // The exact lengths are accepted (the control).
            assert_eq!(ek.len(), params.public_key_len());
            assert_eq!(dk.len(), params.private_key_len());
            assert_eq!(c.len(), params.ciphertext_len());
            assert!(MlKemPublicKey::from_wire_bytes(params, &ek).is_some());
            assert!(MlKemCiphertext::from_wire_bytes(params, &c).is_some());
            assert!(MlKemSharedSecret::from_wire_bytes(&k).is_some());
            let (imported, drawn) = drawn_by(&mut rng, |rng| {
                MlKemPrivateKey::from_wire_bytes(params, &dk, rng)
            });
            assert!(imported.is_some() && drawn == SYM_BYTES, "{params:?}");

            let wrong_lengths = |bytes: &[u8]| {
                let mut longer = bytes.to_vec();
                longer.push(0);
                [
                    ("one byte more", longer),
                    ("one byte fewer", bytes[..bytes.len() - 1].to_vec()),
                    ("nothing", Vec::new()),
                ]
            };
            for (why, bytes) in wrong_lengths(&ek) {
                assert!(
                    MlKemPublicKey::from_wire_bytes(params, &bytes).is_none(),
                    "{params:?} ek, {why}"
                );
            }
            for (why, bytes) in wrong_lengths(&dk) {
                let (imported, drawn) = drawn_by(&mut rng, |rng| {
                    MlKemPrivateKey::from_wire_bytes(params, &bytes, rng)
                });
                assert!(imported.is_none(), "{params:?} dk, {why}");
                assert_eq!(drawn, 0, "{params:?} dk, {why}: refused before the test");
            }
            for (why, bytes) in wrong_lengths(&c) {
                assert!(
                    MlKemCiphertext::from_wire_bytes(params, &bytes).is_none(),
                    "{params:?} c, {why}"
                );
            }
            for (why, bytes) in wrong_lengths(&k) {
                assert!(
                    MlKemSharedSecret::from_wire_bytes(&bytes).is_none(),
                    "{params:?} K, {why}"
                );
            }
        }
    }

    /// `MlKem::decaps` answers `None` for exactly one reason: the private key
    /// and the ciphertext belong to different parameter sets.
    #[test]
    fn decaps_refuses_a_ciphertext_of_another_parameter_set() {
        let pairs: Vec<_> = ALL_PARAMS
            .into_iter()
            .map(|params| {
                let (pk, sk) = MlKem::keygen_from_seed(params, &[0x77; 64]);
                let (ct, _) = MlKem::encaps_with_randomness(&pk, &[0x66; 32]);
                (params, sk, ct)
            })
            .collect();
        for (key_params, sk, _) in &pairs {
            for (ct_params, _, ct) in &pairs {
                assert_eq!(
                    MlKem::decaps(sk, ct).is_some(),
                    key_params == ct_params,
                    "dk {key_params:?}, c {ct_params:?}"
                );
            }
        }
    }

    /// A key blob is a parameter-set tag and the wire encoding: an empty blob,
    /// an unknown tag, and a known tag over another set's body are refused,
    /// and the private-key reader draws nothing for any of them.
    #[test]
    fn key_blobs_refuse_an_empty_blob_and_an_unknown_tag() {
        let params = MlKemParameterSet::MlKem512;
        let (pk, sk) = MlKem::keygen_from_seed(params, &[0x1d; 64]);
        let (ek, dk) = (pk.to_wire_bytes(), sk.to_wire_bytes());
        let mut rng = CountingRng {
            inner: test_rng(),
            drawn: 0,
        };
        assert!(MlKemPublicKey::from_key_blob(&[]).is_none());
        let (imported, drawn) = drawn_by(&mut rng, |rng| MlKemPrivateKey::from_key_blob(&[], rng));
        assert!(imported.is_none() && drawn == 0);
        assert!(MlKemPublicKey::from_key_blob(&[params.id()]).is_none());
        let (imported, drawn) = drawn_by(&mut rng, |rng| {
            MlKemPrivateKey::from_key_blob(&[params.id()], rng)
        });
        assert!(imported.is_none() && drawn == 0);

        let tagged = |tag: u8, body: &[u8]| {
            let mut blob = vec![tag];
            blob.extend_from_slice(body);
            blob
        };
        // 0x02, 0x03 and 0x04 are the three tags; every other byte is unknown,
        // and the two other known tags name bodies of other lengths.
        for tag in (0x00..=0xff).filter(|tag| *tag != params.id()) {
            assert!(
                MlKemPublicKey::from_key_blob(&tagged(tag, &ek)).is_none(),
                "tag {tag:#04x}"
            );
            let (imported, drawn) = drawn_by(&mut rng, |rng| {
                MlKemPrivateKey::from_key_blob(&tagged(tag, &dk), rng)
            });
            assert!(imported.is_none() && drawn == 0, "tag {tag:#04x}");
        }
        assert_eq!(
            MlKemPublicKey::from_key_blob(&tagged(params.id(), &ek)),
            Some(pk)
        );
        let (imported, drawn) = drawn_by(&mut rng, |rng| {
            MlKemPrivateKey::from_key_blob(&tagged(params.id(), &dk), rng)
        });
        assert!(imported == Some(sk) && drawn == SYM_BYTES);
    }

    // ---- NIST ACVP known answers (all parameter sets) ----
    //
    // tests/vectors/ml_kem_acvp_fips203.txt holds cases copied from NIST's
    // ACVP-Server repository; its header names the files, commit and each
    // case's tgId and tcId.

    const ACVP_SETS: [(MlKemParameterSet, &str); 3] = [
        (MlKemParameterSet::MlKem512, "MLKEM512"),
        (MlKemParameterSet::MlKem768, "MLKEM768"),
        (MlKemParameterSet::MlKem1024, "MLKEM1024"),
    ];

    fn acvp_vectors() -> HashMap<&'static str, &'static str> {
        parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_kem_acvp_fips203.txt"
        )))
    }

    fn acvp(vectors: &HashMap<&str, &str>, prefix: &str, name: &str) -> Vec<u8> {
        let key = format!("{prefix}_{name}");
        decode_hex(vectors[key.as_str()])
    }

    fn acvp_secret(vectors: &HashMap<&str, &str>, prefix: &str, name: &str) -> [u8; SS_BYTES] {
        acvp(vectors, prefix, name)
            .try_into()
            .expect("a 32-byte shared key")
    }

    #[test]
    fn ml_kem_keygen_matches_nist_acvp_for_every_parameter_set() {
        let vectors = acvp_vectors();
        for (params, prefix) in ACVP_SETS {
            let mut seed = [0u8; 2 * SYM_BYTES];
            seed[..SYM_BYTES].copy_from_slice(&acvp(&vectors, prefix, "KEYGEN_D"));
            seed[SYM_BYTES..].copy_from_slice(&acvp(&vectors, prefix, "KEYGEN_Z"));
            let (pk, sk) = MlKem::keygen_from_seed(params, &seed);
            let (ek, dk) = (
                acvp(&vectors, prefix, "KEYGEN_EK"),
                acvp(&vectors, prefix, "KEYGEN_DK"),
            );
            assert_eq!(pk.to_wire_bytes(), ek, "{params:?} ek");
            assert_eq!(sk.to_wire_bytes(), dk, "{params:?} dk");
            // NIST's keys pass the §7 checks the public constructors apply.
            assert_eq!(MlKemPublicKey::from_wire_bytes(params, &ek), Some(pk));
            assert_eq!(
                MlKemPrivateKey::from_wire_bytes(params, &dk, &mut test_rng()).as_ref(),
                Some(&sk)
            );
        }
    }

    #[test]
    fn ml_kem_encapsulation_matches_nist_acvp_for_every_parameter_set() {
        let vectors = acvp_vectors();
        for (params, prefix) in ACVP_SETS {
            let pk = MlKemPublicKey::from_wire_bytes(params, &acvp(&vectors, prefix, "ENCAP_EK"))
                .expect("NIST's ek passes the §7.2 checks");
            let m: [u8; SYM_BYTES] = acvp(&vectors, prefix, "ENCAP_M")
                .try_into()
                .expect("a 32-byte m");
            let (ct, ss) = MlKem::encaps_with_randomness(&pk, &m);
            assert_eq!(
                ct.to_wire_bytes(),
                acvp(&vectors, prefix, "ENCAP_C"),
                "{params:?} c"
            );
            assert_eq!(
                ss.to_wire_bytes(),
                acvp_secret(&vectors, prefix, "ENCAP_K"),
                "{params:?} K"
            );
        }
    }

    /// NIST's decapsulation cases of both kinds: a valid ciphertext, whose K
    /// is the encapsulated key and not J(z ‖ c), and a modified one, whose K
    /// is exactly the implicit-rejection value J(z ‖ c) of Algorithm 18.
    #[test]
    fn ml_kem_decapsulation_matches_nist_acvp_for_every_parameter_set() {
        let vectors = acvp_vectors();
        for (params, prefix) in ACVP_SETS {
            for (case, rejects) in [("DECAP_VALID", false), ("DECAP_MODIFIED", true)] {
                let dk = acvp(&vectors, prefix, &format!("{case}_DK"));
                let c = acvp(&vectors, prefix, &format!("{case}_C"));
                let expected = acvp_secret(&vectors, prefix, &format!("{case}_K"));
                let sk = MlKemPrivateKey::from_wire_bytes(params, &dk, &mut test_rng())
                    .expect("NIST's dk passes the §7 checks");
                let ct = MlKemCiphertext::from_wire_bytes(params, &c).expect("c");
                assert_eq!(
                    MlKem::decaps(&sk, &ct).expect("one parameter set"),
                    MlKemSharedSecret::from_wire_bytes(&expected).expect("K"),
                    "{params:?} {case}"
                );
                let mut z_c = dk[dk.len() - SYM_BYTES..].to_vec();
                z_c.extend_from_slice(&c);
                assert_eq!(
                    hash_j(&z_c) == expected,
                    rejects,
                    "{params:?} {case}: K is J(z || c) exactly for the modified ciphertext"
                );
            }
        }
    }

    /// NIST's key-check cases: a decapsulation key whose H(ek) was modified
    /// fails the §7.3 hash check, and an encapsulation key with a coefficient
    /// at or above q fails the §7.2 modulus check, on every public path in.
    #[test]
    fn ml_kem_key_checks_refuse_nist_acvp_invalid_keys() {
        let vectors = acvp_vectors();
        let mut rng = CountingRng {
            inner: test_rng(),
            drawn: 0,
        };
        for (params, prefix) in ACVP_SETS {
            let k = params.k();
            let dk = acvp(&vectors, prefix, "DKCHECK_MODIFIED_H_DK");
            assert_eq!(dk.len(), params.private_key_len());
            let (dk_pke, rest) = dk.split_at(POLY_BYTES * k);
            let (ek, trailer) = rest.split_at(POLY_BYTES * k + SYM_BYTES);
            // Only the hash is wrong: the vectors themselves are canonical.
            assert!(modulus_check(k, ek) && dk_pke_is_canonical(dk_pke));
            assert_ne!(hash_h(ek).as_slice(), &trailer[..SYM_BYTES], "{params:?}");
            for (path, (imported, drawn)) in import_expanded(params, &dk, &mut rng) {
                assert!(imported.is_none(), "{params:?} {path}");
                assert_eq!(
                    drawn, 0,
                    "{params:?} {path}: refused before the pair-wise test"
                );
            }

            let ek = acvp(&vectors, prefix, "EKCHECK_TOO_LARGE_EK");
            assert_eq!(ek.len(), params.public_key_len());
            assert!(!modulus_check(k, &ek), "{params:?}");
            assert!(MlKemPublicKey::from_wire_bytes(params, &ek).is_none());
            let mut blob = vec![params.id()];
            blob.extend_from_slice(&ek);
            assert!(MlKemPublicKey::from_key_blob(&blob).is_none());
            let spki =
                SubjectPublicKeyInfo::new(AlgorithmIdentifier::new(params.algorithm(), None), &ek)
                    .to_der();
            assert!(MlKemPublicKey::from_spki_der(&spki).is_none());
        }
    }
}
