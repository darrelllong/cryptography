//! ML-DSA, the Module-Lattice-Based Digital Signature Algorithm, implemented
//! in safe Rust from FIPS 204.
//!
//! This module provides:
//! - ML-DSA-44/65/87 parameter sets
//! - key generation
//! - signing (hedged or deterministic, with a context string) and verification
//! - strict wire/key-blob framing
//!
//! SHAKE128 and SHAKE256 come from this crate's hash module; no C or FFI code
//! is involved.
//!
//! # Correspondence with FIPS 204
//!
//! Each algorithm of the standard is implemented by a private item named
//! after it, whose documentation cites the algorithm by number.
//!
//! | FIPS 204 | Algorithm | Implementation |
//! |---|---|---|
//! | 1 | ML-DSA.KeyGen | `MlDsa::keygen` |
//! | 2 | ML-DSA.Sign | `MlDsa::sign_with_randomness_and_context`, and the `sign*` wrappers over it |
//! | 3 | ML-DSA.Verify | `MlDsa::verify_with_context` and `MlDsa::verify`, over `verify_framed` |
//! | 4, 5 | HashML-DSA.Sign, HashML-DSA.Verify | not provided |
//! | 6 | ML-DSA.KeyGen_internal | `keygen_internal` |
//! | 7 | ML-DSA.Sign_internal | `sign_internal`; lines 11–30 in `sign_attempt`, with the tests of lines 23 and 28 in `rejection_mask`; lines 1–5 cached by `MlDsaPrivateKey::expanded` |
//! | 8 | ML-DSA.Verify_internal | `verify_internal`; line 13's norm test in `response_within_bound`; lines 1, 5 and 6 cached by `MlDsaPublicKey::expanded`; lines 2–4 in `MlDsaSignature::from_wire_bytes` |
//! | 9 | IntegerToBits | `BitStringWriter::integer_to_bits` |
//! | 10 | BitsToInteger | `BitStringReader::bits_to_integer` |
//! | 11 | IntegerToBytes | `integer_to_bytes` |
//! | 12 | BitsToBytes | `BitStringWriter` |
//! | 13 | BytesToBits | `BitStringReader` |
//! | 14 | CoeffFromThreeBytes | `coeff_from_three_bytes` |
//! | 15 | CoeffFromHalfByte | `coeff_from_half_byte` |
//! | 16 | SimpleBitPack | `simple_bit_pack` |
//! | 17 | BitPack | `bit_pack` |
//! | 18 | SimpleBitUnpack | `simple_bit_unpack` |
//! | 19 | BitUnpack | `bit_unpack` |
//! | 20 | HintBitPack | `hint_bit_pack` |
//! | 21 | HintBitUnpack | `hint_bit_unpack` |
//! | 22 | pkEncode | `pk_encode` |
//! | 23 | pkDecode | `pk_decode` |
//! | 24 | skEncode | `sk_encode` |
//! | 25 | skDecode | `sk_decode` |
//! | 26 | sigEncode | `sig_encode` |
//! | 27 | sigDecode | `sig_decode` |
//! | 28 | w1Encode | `w1_encode` |
//! | 29 | SampleInBall | `sample_in_ball` |
//! | 30 | RejNTTPoly | `rej_ntt_poly` |
//! | 31 | RejBoundedPoly | `rej_bounded_poly` |
//! | 32 | ExpandA | `expand_a` |
//! | 33 | ExpandS | `expand_s` |
//! | 34 | ExpandMask | `expand_mask` |
//! | 35 | Power2Round | `power2_round` |
//! | 36 | Decompose | `decompose` |
//! | 37 | HighBits | `high_bits` |
//! | 38 | LowBits | `low_bits` |
//! | 39 | MakeHint | `make_hint` |
//! | 40 | UseHint | `use_hint` |
//! | 41 | NTT | `ntt`, applied to vectors by `ntt_vector` |
//! | 42 | NTT⁻¹ | `ntt_inverse`, applied to vectors by `ntt_inverse_vector` |
//! | 43 | BitRev8 | `bit_rev8` |
//! | 44 | AddNTT | folded into `matrix_vector_ntt` (one reduction per sum); the test module's `add_ntt` checks the fold |
//! | 45 | MultiplyNTT | `multiply_ntt` |
//! | 46 | AddVectorNTT | not called: Algorithms 6–8 add vectors only in R_q, and Algorithm 8's subtraction in T_q (line 9) is done coefficientwise in `verify_internal` |
//! | 47 | ScalarVectorNTT | `scalar_vector_ntt` |
//! | 48 | MatrixVectorNTT | `matrix_vector_ntt` |
//! | 49 | MontgomeryReduce | not used (see Arithmetic) |
//! | Appendix B | zetas | `ZETAS`, computed at compile time from ζ = 1753 |
//!
//! # Arithmetic
//!
//! Elements of R_q and T_q are held with coefficients in the range 0 to q − 1.
//! Products are reduced with Barrett's method and the 64-bit reciprocal
//! ⌊2^64/q⌋, so the zetas stay in the plain form Appendix B prints and
//! Appendix A's Montgomery form is never needed.
//!
//! # Side channels
//!
//! The arithmetic on secret values (s1, s2, t0, K, ρ′, ρ″, y, w, and the
//! challenge and response of a rejected attempt) is data-independent:
//! reductions, rounding (`power2_round`, `decompose`, `make_hint`), the
//! rejection tests and the hint count use masks and multiply-and-shift
//! quotients in place of branches and divisions; `sample_in_ball` places the
//! challenge's nonzero entries by masked scans instead of indexing memory by
//! a secret position; private keys compare in constant time; and every
//! signing attempt does the same work whichever rejection test fails, so
//! timing shows that an attempt was rejected but not by which test.
//!
//! What does vary is the rejection sampling that FIPS 204 itself specifies
//! with data-dependent loops (Appendix C). `rej_bounded_poly` (Algorithm 31,
//! on ρ′ during key generation) branches on whether each nibble of the XOF
//! output is one of the values Algorithm 15 discards, and stores an accepted
//! coefficient at a position that counts the acceptances before it;
//! `sample_in_ball` (Algorithm 29, on c̃ while signing) discards bytes above
//! its current index; and the signing loop runs until an attempt passes. The
//! XOF bytes consumed, the store positions and the attempt count therefore
//! depend on which candidates were discarded. A discarded nibble or byte is
//! not part of any secret, and an accepted value is used only through the
//! data-independent arithmetic above; the attempt count is a function of
//! rnd, K and the message. In the deterministic variant that count is fixed
//! by the key and message, the leak §3.6.1 footnote 3 describes; see
//! [`MlDsa::sign_deterministic`].
//!
//! # Standard key encodings
//!
//! RFC 9881 carries the keys in X.509's containers, beside the crate's own
//! `to_wire_bytes` and `to_key_blob` forms:
//!
//! - [`MlDsaPublicKey::to_spki_der`] and its siblings: a
//!   `SubjectPublicKeyInfo` (§4) under `id-ml-dsa-44`, `-65` or `-87` (§2)
//!   with the parameters absent, and the FIPS 204 public key as the
//!   `subjectPublicKey`.
//! - [`MlDsaPrivateKey::to_pkcs8_der`] and its siblings: a PKCS #8
//!   `OneAsymmetricKey` whose `privateKey` is the §6 `CHOICE` of `seed` (ξ,
//!   32 bytes), `expandedKey` (the FIPS 204 private key), or `both`.
//!
//! On output a key writes its seed ξ when it has one, the form §6 and §8.1
//! recommend. Keys from [`MlDsa::keygen`] and [`MlDsa::keygen_from_seed`],
//! and keys read from a `seed` or `both`, keep their seed. A key built from an
//! expanded key alone ([`MlDsaPrivateKey::from_wire_bytes`], a key blob, or an
//! `expandedKey`) cannot recover ξ, since key generation is one-way (§8.1),
//! and writes `expandedKey`. `both` is never written: ξ determines the rest.
//!
//! On input all three alternatives are accepted, told apart by tag as §6
//! directs. A `seed` is expanded by ML-DSA.KeyGen_internal (Algorithm 6). A
//! `both` must pass the §8.2 seed consistency check: its expanded key must be
//! the one ξ generates. An `expandedKey` is checked by regenerating its public
//! key: s1 and s2 must lie in [−η, η] (the malformed input Algorithm 25 warns
//! of), and the t0 and tr it carries must be the ones ρ, s1 and s2 produce,
//! which refuses the inconsistent expanded keys of Appendix C.4. Without ξ
//! nothing can show that K, s1 and s2 came from key generation; these are the
//! consistency checks the key's own contents allow. A version 2 `publicKey`
//! must equal the public key the private key yields.

use core::fmt;
use std::sync::OnceLock;

use crate::hash::sha3::{Shake128, Shake256};
use crate::hash::Xof;
use crate::public_key::ml_pkix::{self, PrivateKeyChoice};
use crate::public_key::pkix::{
    pem_decode, pem_encode, AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey,
    SubjectPublicKeyInfo, PRIVATE_KEY_LABEL, PUBLIC_KEY_LABEL,
};
use crate::Csprng;

/// n = 256, the number of coefficients of a polynomial in R and R_q (§2.3).
/// Bits in a byte, the width every packing here fills.
const BYTE_BITS: u32 = 8;

/// CoeffFromHalfByte (FIPS 204 Algorithm 15) rejects a half-byte at or above
/// `5⌈(2η + 1)/5⌉` for η = 2, and at or above `2η + 1` for η = 4.
const ETA2_REJECT_BOUND: i32 = 15;
const ETA4_REJECT_BOUND: i32 = 9;

const N: usize = 256;
/// Algorithms 2 and 3 refuse context strings longer than 255 bytes.
const MAX_CONTEXT_BYTES: usize = u8::MAX as usize;
/// IntegerToBytes(0, 1) ‖ IntegerToBytes(|ctx|, 1) ‖ ctx, at its longest.
const MAX_PRE_BYTES: usize = 2 + MAX_CONTEXT_BYTES;

/// Length of ξ, ρ, K and rnd.
const SEED_BYTES: usize = 32;
/// Length of ρ′, ρ″ and μ.
const CRH_BYTES: usize = 64;
/// Length of tr = H(pk, 64).
const TR_BYTES: usize = 64;
/// Length of the signing randomness rnd.
const RND_BYTES: usize = 32;
/// Largest λ/4 of Table 1.
const MAX_CTILDE_BYTES: usize = 64;

/// The modulus q = 2^23 − 2^13 + 1 (Table 1).
const Q: i32 = 8_380_417;
/// ζ = 1753, a primitive 512th root of unity modulo q (Table 1, §7.5).
const ZETA: i32 = 1753;
/// d, the number of low-order bits Power2Round drops from t (Table 1).
const D: u32 = 13;

/// bitlen a (§2.3): the number of binary digits of a positive integer a.
const fn bitlen(a: u32) -> u32 {
    u32::BITS - a.leading_zeros()
}

/// Width of a t1 coefficient, bitlen(q − 1) − d (Algorithms 22 and 23).
const T1_BITS: u32 = bitlen((Q - 1) as u32) - D;
/// The bound b = 2^(bitlen(q − 1) − d) − 1 that pkEncode passes to SimpleBitPack.
const T1_MAX: u32 = (1 << T1_BITS) - 1;
/// One SimpleBitPack'd t1 polynomial: 32·(bitlen(q − 1) − d) bytes.
const T1_PACKED_BYTES: usize = 32 * T1_BITS as usize;
/// The bounds (a, b) = (2^(d−1) − 1, 2^(d−1)) that skEncode passes to BitPack for t0.
const T0_A: u32 = (1 << (D - 1)) - 1;
const T0_B: u32 = 1 << (D - 1);
/// One BitPack'd t0 polynomial: 32·bitlen(a + b) = 32·d bytes.
const T0_PACKED_BYTES: usize = 32 * bitlen(T0_A + T0_B) as usize;
/// Longest BitPack'd z polynomial, 32·(1 + bitlen(γ1 − 1)), over Table 1.
const MAX_Z_PACKED_BYTES: usize = 32 * 20;
/// Longest w1Encode output, 32·k·bitlen((q − 1)/(2γ2) − 1), over Table 1:
/// ML-DSA-87's 32·8·bitlen(15) = 1024 bytes (ML-DSA-44 and -65 both encode
/// to 768). `Profile::from_table_1` checks that no parameter set exceeds it.
const MAX_W1_ENCODED_BYTES: usize = 1024;

/// Coefficients of one polynomial. Elements of R_q and T_q are kept in the
/// canonical range [0, q); short elements of R (s1, s2, t0, y, z, c and the
/// outputs of the rounding algorithms) are kept as signed integers.
type Poly = [i32; N];

/// A vector of polynomials: an element of R^ℓ or R^k, or of the corresponding
/// R_q or T_q module (§2.3), sized to the parameter set at construction.
///
/// The coefficients live on the heap, so a vector moves as a pointer and a
/// length: the 1 KiB-per-polynomial payload is never copied onto the stack by
/// a move, and the whole module's stack demand stays at a few KiB. A vector
/// scrubs its coefficients when dropped, and the secret-carrying ones are
/// scrubbed explicitly as soon as they are no longer needed (§3.6.3), which
/// is earlier than their scope ends.
#[derive(Clone)]
struct PolyVec {
    polys: Box<[Poly]>,
}

impl PolyVec {
    /// The zero vector of `len` polynomials, allocated zeroed on the heap.
    fn zero(len: usize) -> Self {
        Self {
            polys: vec![[0; N]; len].into_boxed_slice(),
        }
    }

    /// The number of coordinates: ℓ or k.
    fn len(&self) -> usize {
        self.polys.len()
    }

    fn polys(&self) -> &[Poly] {
        &self.polys
    }

    fn polys_mut(&mut self) -> &mut [Poly] {
        &mut self.polys
    }

    /// Scrubs every coefficient.
    fn wipe(&mut self) {
        crate::ct::zeroize_slice(self.polys.as_flattened_mut());
    }
}

impl Drop for PolyVec {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// A matrix Â ∈ T_q^(k×ℓ) as ExpandA (Algorithm 32) produces it, stored row
/// by row on the heap: row r holds the entries Â(r, 0), …, Â(r, ℓ − 1). Â is
/// a function of the public ρ and needs no scrubbing (§3.6.3, case 2).
struct MatrixNtt {
    entries: Box<[Poly]>,
    k: usize,
    l: usize,
}

impl MatrixNtt {
    /// The k×ℓ zero matrix of the parameter set.
    fn zero(p: Profile) -> Self {
        Self {
            entries: vec![[0; N]; p.k * p.l].into_boxed_slice(),
            k: p.k,
            l: p.l,
        }
    }

    /// The rows Â(0, ·), …, Â(k − 1, ·), each of ℓ entries.
    fn rows(&self) -> impl Iterator<Item = &[Poly]> {
        self.entries.chunks_exact(self.l)
    }

    fn rows_mut(&mut self) -> impl Iterator<Item = &mut [Poly]> {
        self.entries.chunks_exact_mut(self.l)
    }
}

/// One parameter-set column of FIPS 204 Table 1.
struct Table1 {
    k: usize,
    l: usize,
    eta: i32,
    tau: usize,
    lambda: usize,
    gamma1: i32,
    gamma2: i32,
    omega: usize,
}

/// A parameter set: the Table 1 values together with the quantities FIPS 204
/// derives from them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Profile {
    k: usize,
    l: usize,
    eta: i32,
    tau: usize,
    /// β = τ·η.
    beta: i32,
    gamma1: i32,
    gamma2: i32,
    omega: usize,
    /// λ/4, the byte length of the commitment hash c̃.
    ctilde_bytes: usize,
    /// One BitPack'd s1 or s2 polynomial: 32·bitlen(2η) bytes.
    s_packed_bytes: usize,
    /// One BitPack'd z polynomial: 32·(1 + bitlen(γ1 − 1)) bytes.
    polyz_packed_bytes: usize,
    /// One SimpleBitPack'd w1 polynomial: 32·bitlen((q − 1)/(2γ2) − 1) bytes.
    w1_packed_bytes: usize,
    /// m = (q − 1)/(2γ2): the modulus of UseHint, one more than the largest
    /// HighBits value.
    high_bits_modulus: i32,
    /// Division by 2γ2 over the dividends Decompose forms (see `decompose`).
    decompose_division: FloorDivision,
}

impl Profile {
    const fn from_table_1(t: Table1) -> Self {
        let profile = Self {
            k: t.k,
            l: t.l,
            eta: t.eta,
            tau: t.tau,
            beta: t.tau as i32 * t.eta,
            gamma1: t.gamma1,
            gamma2: t.gamma2,
            omega: t.omega,
            ctilde_bytes: t.lambda / 4,
            s_packed_bytes: 32 * bitlen(2 * t.eta as u32) as usize,
            polyz_packed_bytes: 32 * (1 + bitlen((t.gamma1 - 1) as u32)) as usize,
            w1_packed_bytes: 32 * bitlen(((Q - 1) / (2 * t.gamma2) - 1) as u32) as usize,
            high_bits_modulus: (Q - 1) / (2 * t.gamma2),
            // Decompose divides r + γ2 − 1, for r ∈ [0, q − 1], by 2γ2.
            decompose_division: FloorDivision::derive(
                (2 * t.gamma2) as u64,
                (Q + t.gamma2 - 2) as u64,
            ),
        };
        assert!(profile.ctilde_bytes <= MAX_CTILDE_BYTES);
        assert!(profile.polyz_packed_bytes <= MAX_Z_PACKED_BYTES);
        assert!(profile.k * profile.w1_packed_bytes <= MAX_W1_ENCODED_BYTES);
        profile
    }

    /// pk ∈ B^(32 + 32k(bitlen(q − 1) − d)) (Algorithm 22).
    const fn public_key_len(self) -> usize {
        SEED_BYTES + self.k * T1_PACKED_BYTES
    }

    /// sk ∈ B^(32 + 32 + 64 + 32((ℓ + k)·bitlen(2η) + dk)) (Algorithm 24).
    const fn private_key_len(self) -> usize {
        2 * SEED_BYTES
            + TR_BYTES
            + (self.l + self.k) * self.s_packed_bytes
            + self.k * T0_PACKED_BYTES
    }

    /// σ ∈ B^(λ/4 + ℓ·32(1 + bitlen(γ1 − 1)) + ω + k) (Algorithm 26).
    const fn signature_len(self) -> usize {
        self.ctilde_bytes + self.l * self.polyz_packed_bytes + self.omega + self.k
    }

    /// Length of w1Encode(w1) (Algorithm 28).
    const fn w1_encoded_len(self) -> usize {
        self.k * self.w1_packed_bytes
    }
}

/// ML-DSA-44, Table 1.
const ML_DSA_44: Profile = Profile::from_table_1(Table1 {
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    lambda: 128,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    omega: 80,
});

/// ML-DSA-65, Table 1.
const ML_DSA_65: Profile = Profile::from_table_1(Table1 {
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    lambda: 192,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 55,
});

/// ML-DSA-87, Table 1.
const ML_DSA_87: Profile = Profile::from_table_1(Table1 {
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    lambda: 256,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 75,
});

/// `id-ml-dsa-44`, 2.16.840.1.101.3.4.3.17 (RFC 9881 §2).
const ID_ML_DSA_44: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 17]);

/// `id-ml-dsa-65`, 2.16.840.1.101.3.4.3.18 (RFC 9881 §2).
const ID_ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 18]);

/// `id-ml-dsa-87`, 2.16.840.1.101.3.4.3.19 (RFC 9881 §2).
const ID_ML_DSA_87: ObjectIdentifier =
    ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 3, 19]);

/// ML-DSA parameter sets from FIPS 204.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (security category 2): matrix dimensions (k, l) = (4, 4);
    /// 1312-byte public key, 2560-byte private key, 2420-byte signature.
    MlDsa44,
    /// ML-DSA-65 (security category 3): matrix dimensions (k, l) = (6, 5);
    /// 1952-byte public key, 4032-byte private key, 3309-byte signature.
    MlDsa65,
    /// ML-DSA-87 (security category 5): matrix dimensions (k, l) = (8, 7);
    /// 2592-byte public key, 4896-byte private key, 4627-byte signature.
    MlDsa87,
}

impl MlDsaParameterSet {
    #[must_use]
    const fn profile(self) -> Profile {
        match self {
            Self::MlDsa44 => ML_DSA_44,
            Self::MlDsa65 => ML_DSA_65,
            Self::MlDsa87 => ML_DSA_87,
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

    /// The RFC 9881 §2 identifier of this parameter set.
    const fn algorithm(self) -> &'static ObjectIdentifier {
        match self {
            Self::MlDsa44 => &ID_ML_DSA_44,
            Self::MlDsa65 => &ID_ML_DSA_65,
            Self::MlDsa87 => &ID_ML_DSA_87,
        }
    }

    /// The parameter set `algorithm` names, whose parameters RFC 9881 §2
    /// requires to be absent.
    fn from_algorithm(algorithm: &AlgorithmIdentifier<'_>) -> Option<Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|params| algorithm.matches(params.algorithm(), None))
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
    expanded: OnceLock<CachedPublicKey>,
}

/// ML-DSA private key.
pub struct MlDsaPrivateKey {
    params: MlDsaParameterSet,
    bytes: Vec<u8>,
    /// The seed ξ that generated `bytes`, when known: RFC 9881 §8.1 asks
    /// implementations to retain it. Eq compares the key material in `bytes`;
    /// whether the seed is still known changes only the PKCS #8 output form.
    /// It is boxed so that moving the key moves a pointer, not a copy of the
    /// seed that Drop could not reach.
    seed: Option<Box<[u8; SEED_BYTES]>>,
    expanded: OnceLock<Option<Box<CachedPrivateKey>>>,
}

/// ML-DSA signature.
///
/// Holds both the FIPS 204 wire encoding and its decoded form `(c~, z, h)`.
/// The decode happens exactly once, when the signature is produced or
/// parsed, so verification never re-parses the bytes.
pub struct MlDsaSignature {
    params: MlDsaParameterSet,
    bytes: Vec<u8>,
    decoded: DecodedSignature,
}

/// The three components of a signature as FIPS 204 `sigEncode`/`sigDecode`
/// (Algorithms 26 and 27) see them: the commitment hash `c~`, the response
/// vector `z`, and the hint vector `h`.
#[derive(Clone)]
struct DecodedSignature {
    /// c̃, λ/4 bytes.
    c: Vec<u8>,
    /// z mod± q, with coefficients in [−γ1 + 1, γ1].
    z: PolyVec,
    /// h, with coefficients in {0, 1}.
    h: PolyVec,
}

/// Verification state that depends only on the public key: pkDecode, ExpandA
/// and tr (Algorithm 8, lines 1, 5 and 6), and NTT(t1·2^d) from line 9.
struct CachedPublicKey {
    tr: [u8; TR_BYTES],
    t1_shifted_hat: PolyVec,
    a_hat: MatrixNtt,
}

/// Signing state that depends only on the private key (Algorithm 7, lines 1-5).
struct CachedPrivateKey {
    tr: [u8; TR_BYTES],
    key: [u8; SEED_BYTES],
    s1_hat: PolyVec,
    s2_hat: PolyVec,
    t0_hat: PolyVec,
    a_hat: MatrixNtt,
}

impl CachedPrivateKey {
    fn zeroed(p: Profile) -> Self {
        Self {
            tr: [0; TR_BYTES],
            key: [0; SEED_BYTES],
            s1_hat: PolyVec::zero(p.l),
            s2_hat: PolyVec::zero(p.k),
            t0_hat: PolyVec::zero(p.k),
            a_hat: MatrixNtt::zero(p),
        }
    }
}

fn zeroize_cached_private_key(cache: &mut CachedPrivateKey) {
    crate::ct::zeroize_slice(cache.tr.as_mut_slice());
    crate::ct::zeroize_slice(cache.key.as_mut_slice());
    cache.s1_hat.wipe();
    cache.s2_hat.wipe();
    cache.t0_hat.wipe();
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
            seed: self.seed.as_deref().map(boxed_seed),
            expanded: OnceLock::new(),
        }
    }
}

impl PartialEq for MlDsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // The encodings carry K, s1, s2 and t0: compare them without an early exit.
        self.params == other.params
            && crate::ct::constant_time_eq_mask(&self.bytes, &other.bytes) == u8::MAX
    }
}

impl Eq for MlDsaPrivateKey {}

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        // The encoding carries K, s1, s2 and t0, and the seed ξ regenerates
        // all of them (§3.6.3, case 1: ξ is treated as the private key is).
        crate::ct::zeroize_slice(self.bytes.as_mut_slice());
        if let Some(seed) = self.seed.as_mut() {
            crate::ct::zeroize_slice(seed.as_mut_slice());
        }

        // The cache, once built, holds K, tr and the NTTs of s1, s2 and t0.
        if let Some(cache_opt) = self.expanded.get_mut() {
            if let Some(cache) = cache_opt.as_mut() {
                zeroize_cached_private_key(cache);
            }
            *cache_opt = None;
        }
    }
}

impl Clone for MlDsaSignature {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
            bytes: self.bytes.clone(),
            decoded: self.decoded.clone(),
        }
    }
}

impl PartialEq for MlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        // The decoded form is a function of the bytes, so the bytes decide.
        self.params == other.params && self.bytes == other.bytes
    }
}

impl Eq for MlDsaSignature {}

impl fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSignature")
            .field("params", &self.params)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl MlDsaPublicKey {
    /// The verification state of Algorithm 8, lines 1, 5 and 6, built on the
    /// first call and kept for every later verification under this key:
    /// §3.6.3 (case 2) allows Â to be stored, and the rest is a function of
    /// the public key alone.
    fn expanded(&self) -> &CachedPublicKey {
        self.expanded.get_or_init(|| {
            let p = self.params.profile();
            let (rho, mut t1_shifted_hat) = pk_decode(p, &self.bytes);
            let mut tr = [0u8; TR_BYTES];
            hash_h(&[&self.bytes], &mut tr);
            // t1 < 2^10, so t1·2^d ≤ (2^10 − 1)·2^13 = q − 1 is already reduced.
            for coefficient in t1_shifted_hat.polys_mut().as_flattened_mut() {
                *coefficient <<= D;
            }
            ntt_vector(&mut t1_shifted_hat);
            CachedPublicKey {
                tr,
                t1_shifted_hat,
                a_hat: expand_a(p, &rho),
            }
        })
    }

    /// The FIPS 204 parameter set this key belongs to. Verification refuses
    /// a signature whose parameter set differs from the key's.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.params
    }

    /// Serialize to the FIPS 204 public-key encoding `rho || t1`
    /// (`public_key_len()` bytes: 1312/1952/2592 for ML-DSA-44/65/87).
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Parse a FIPS 204 public key. Only the length is checked here
    /// (`None` unless exactly `params.public_key_len()` bytes): every byte
    /// string of that length is a valid pkDecode input, whose t1 is always in
    /// range. The key is unpacked and the A-matrix expanded lazily, on first
    /// verification.
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

    /// Serialize to this crate's self-describing framing: a one-byte
    /// parameter-set tag followed by the FIPS 204 wire encoding. Unlike
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
    /// empty input, an unknown parameter-set tag, or a body whose length
    /// does not match the tagged parameter set.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlDsaParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }

    /// Encode as the RFC 9881 §4 `SubjectPublicKeyInfo` in DER: the parameter
    /// set's `id-ml-dsa-*` identifier with the parameters absent (§2), and the
    /// FIPS 204 public key as the `subjectPublicKey`.
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

    /// Decode an RFC 9881 §4 `SubjectPublicKeyInfo` from strict DER with no
    /// trailing bytes. The identifier names the parameter set and carries no
    /// parameters (§2), and the key must pass [`Self::from_wire_bytes`] for
    /// that parameter set.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let spki = SubjectPublicKeyInfo::from_der(der)?;
        let params = MlDsaParameterSet::from_algorithm(spki.algorithm())?;
        Self::from_wire_bytes(params, spki.subject_public_key())
    }

    /// Decode RFC 7468 `PUBLIC KEY` text (§13) with [`Self::from_spki_der`].
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        pem_decode(PUBLIC_KEY_LABEL, pem, Self::from_spki_der)
    }
}

impl MlDsaPrivateKey {
    /// Algorithm 7, lines 1-5 (skDecode, the NTTs of s1, s2 and t0, and
    /// ExpandA), built on the first call and kept for every later signature
    /// under this key; the values are deterministic in the key, and Â may be
    /// stored (§3.6.3, case 2). `None` for a key with s1 or s2 outside
    /// [−η, η], which every public constructor has already refused.
    fn expanded(&self) -> Option<&CachedPrivateKey> {
        self.expanded
            .get_or_init(|| {
                let p = self.params.profile();
                // The cache is allocated zeroed on the heap and filled in place,
                // so the decoded secrets are never moved through temporaries the
                // wipe cannot reach.
                let mut cache = Box::new(CachedPrivateKey::zeroed(p));
                let c = &mut *cache;
                let rho = sk_decode(
                    p,
                    &self.bytes,
                    &mut c.key,
                    &mut c.tr,
                    &mut c.s1_hat,
                    &mut c.s2_hat,
                    &mut c.t0_hat,
                );
                // Until the NTTs below, the three vectors hold s1, s2 and t0.
                // skDecode leaves s1 and s2 unchecked (Algorithm 25, lines 3
                // and 6). A key with a coefficient outside [−η, η] is malformed
                // and refused, after a pass over every coefficient, so the
                // refusal does not reveal where the fault lies.
                if outside_eta_mask(p, &c.s1_hat) | outside_eta_mask(p, &c.s2_hat) != 0 {
                    zeroize_cached_private_key(c);
                    return None;
                }
                for v in [&mut c.s1_hat, &mut c.s2_hat, &mut c.t0_hat] {
                    for coefficient in v.polys_mut().as_flattened_mut() {
                        *coefficient = to_mod_q(*coefficient);
                    }
                    ntt_vector(v);
                }
                c.a_hat = expand_a(p, &rho);
                Some(cache)
            })
            .as_deref()
    }

    /// The FIPS 204 parameter set this key belongs to. It fixes the
    /// signature length produced by signing and the blob framing.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.params
    }

    /// Serialize to the FIPS 204 private-key encoding
    /// `rho || K || tr || s1 || s2 || t0` (`private_key_len()` bytes:
    /// 2560/4032/4896 for ML-DSA-44/65/87). This is raw secret key
    /// material; handle the returned buffer accordingly.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Parse a FIPS 204 private key `rho || K || tr || s1 || s2 || t0` of
    /// exactly `params.private_key_len()` bytes, and check it as a key whose
    /// generation this module did not see: `s1` and `s2` must lie in
    /// [−η, η], and `t0` and `tr` must be the values Algorithm 6 derives from
    /// ρ, `s1` and `s2` (the two inconsistencies of RFC 9881 Appendix C.4).
    /// `None` for another length or a key that fails those checks. The check
    /// expands the key (skDecode, the NTTs and ExpandA), and signing reuses
    /// that expansion.
    #[must_use]
    pub fn from_wire_bytes(params: MlDsaParameterSet, bytes: &[u8]) -> Option<Self> {
        Self::from_expanded_key(params, bytes).map(|(key, _)| key)
    }

    /// The key `bytes` encodes together with the public key it regenerates,
    /// or `None` when [`Self::from_wire_bytes`] would refuse it.
    fn from_expanded_key(
        params: MlDsaParameterSet,
        bytes: &[u8],
    ) -> Option<(Self, MlDsaPublicKey)> {
        if bytes.len() != params.private_key_len() {
            return None;
        }
        let key = Self {
            params,
            bytes: bytes.to_vec(),
            seed: None,
            expanded: OnceLock::new(),
        };
        let public_key = key.regenerate_public_key()?;
        Some((key, public_key))
    }

    /// Serialize to this crate's self-describing framing: a one-byte
    /// parameter-set tag followed by the FIPS 204 wire encoding. The
    /// result contains raw secret key material; handle it accordingly.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse a blob produced by [`Self::to_key_blob`]. Returns `None` on an
    /// empty input, an unknown parameter-set tag, or a body that
    /// [`Self::from_wire_bytes`] refuses for the tagged parameter set.
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlDsaParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }

    /// Encode as the RFC 9881 §6 `OneAsymmetricKey` (PKCS #8) in DER: version
    /// 1, the parameter set's identifier with the parameters absent (§2), and
    /// no public key. The `privateKey` is the 32-byte `seed` ξ when this key
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

    /// Decode an RFC 9881 `OneAsymmetricKey` in any X.690 BER encoding, DER
    /// included: RFC 5958 §2 says "receivers MUST support BER". The private-key
    /// `CHOICE` inside must still be DER (RFC 9881 §6), and the key is then
    /// checked as [`Self::from_pkcs8_der`] checks it.
    #[must_use]
    pub fn from_pkcs8_ber(ber: &[u8]) -> Option<Self> {
        crate::public_key::pkix::pkcs8_ber(ber, Self::from_pkcs8_der)
    }

    /// Decode an RFC 9881 §6 `OneAsymmetricKey` from strict DER with no
    /// trailing bytes. The identifier names the parameter set and carries no
    /// parameters (§2). The `privateKey` may be any alternative of the §6
    /// `CHOICE`, told apart by tag:
    ///
    /// - `seed`: 32 bytes, expanded by ML-DSA.KeyGen_internal(ξ);
    /// - `expandedKey`: the FIPS 204 private key, validated by regenerating
    ///   its public key, which requires s1 and s2 in range and the t0 and tr
    ///   it carries to be the ones they produce;
    /// - `both`: its expanded key must be exactly the one ξ generates, the
    ///   §8.2 seed consistency check.
    ///
    /// A version 2 `publicKey` must equal the public key the private key
    /// yields. Attributes are ignored.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let package = OneAsymmetricKey::from_der(der)?;
        let params = MlDsaParameterSet::from_algorithm(package.algorithm())?;
        let choice = PrivateKeyChoice::from_der(
            package.private_key(),
            SEED_BYTES,
            params.private_key_len(),
        )?;
        let (key, public_key) = match choice {
            PrivateKeyChoice::Seed(seed) => Self::keys_from_seed(params, seed)?,
            PrivateKeyChoice::ExpandedKey(expanded_key) => {
                Self::from_expanded_key(params, expanded_key)?
            }
            PrivateKeyChoice::Both { seed, expanded_key } => {
                let (key, public_key) = Self::keys_from_seed(params, seed)?;
                // Compared without an early exit: both hold the secret key.
                if crate::ct::constant_time_eq_mask(&key.bytes, expanded_key) != u8::MAX {
                    return None;
                }
                (key, public_key)
            }
        };
        match package.public_key() {
            Some(encoded) if encoded != public_key.bytes => None,
            _ => Some(key),
        }
    }

    /// Decode RFC 7468 `PRIVATE KEY` text (§10) with [`Self::from_pkcs8_der`].
    #[must_use]
    pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        pem_decode(PRIVATE_KEY_LABEL, pem, Self::from_pkcs8_der)
    }

    /// The private key and public key ML-DSA.KeyGen_internal (Algorithm 6)
    /// generates from the 32-byte seed ξ; `None` for another length.
    fn keys_from_seed(params: MlDsaParameterSet, seed: &[u8]) -> Option<(Self, MlDsaPublicKey)> {
        if seed.len() != SEED_BYTES {
            return None;
        }
        // Filled in place, so no by-value copy of ξ is left behind.
        let mut xi = [0u8; SEED_BYTES];
        xi.copy_from_slice(seed);
        let (public_key, private_key) = MlDsa::keygen_from_seed(params, &xi);
        crate::ct::zeroize_slice(&mut xi);
        Some((private_key, public_key))
    }

    /// The public key this private key implies: Algorithm 6, lines 5, 6 and 8,
    /// rerun on the key's ρ, s1 and s2. `None` when the key is malformed: s1
    /// or s2 outside [−η, η] (refused by `expanded`), or a t0 or tr other than
    /// the ones the recomputed t yields, the two inconsistencies of RFC 9881
    /// Appendix C.4.
    fn regenerate_public_key(&self) -> Option<MlDsaPublicKey> {
        let p = self.params.profile();
        let cache = self.expanded()?;
        // Line 5: t ← NTT⁻¹(Â ∘ NTT(s1)) + s2, from the cached NTT(s1), NTT(s2)
        // and Â. The cache also holds NTT(t0 mod q), which gives back the t0
        // the key carries.
        let mut t = PolyVec::zero(p.k);
        matrix_vector_ntt(&cache.a_hat, &cache.s1_hat, &mut t);
        ntt_inverse_vector(&mut t);
        // Copied into zeroed vectors in place, never through a by-value clone.
        let mut s2 = PolyVec::zero(p.k);
        s2.polys_mut().copy_from_slice(cache.s2_hat.polys());
        ntt_inverse_vector(&mut s2);
        let mut carried_t0 = PolyVec::zero(p.k);
        carried_t0.polys_mut().copy_from_slice(cache.t0_hat.polys());
        ntt_inverse_vector(&mut carried_t0);
        // Line 6: (t1, t0) ← Power2Round(t), each recomputed t0 coefficient
        // compared with the carried one without an early exit. Both lie in
        // (−2^(d−1), 2^(d−1)], so they agree exactly when they agree mod q.
        let mut t1 = PolyVec::zero(p.k);
        let mut differs = 0;
        for (((t_j, &s2_j), &carried_j), t1_j) in t
            .polys_mut()
            .as_flattened_mut()
            .iter_mut()
            .zip(s2.polys().as_flattened())
            .zip(carried_t0.polys().as_flattened())
            .zip(t1.polys_mut().as_flattened_mut())
        {
            *t_j = add_mod_q(*t_j, s2_j);
            let (high, low) = power2_round(*t_j);
            *t1_j = high;
            differs |= to_mod_q(low) ^ carried_j;
        }
        t.wipe();
        s2.wipe();
        carried_t0.wipe();
        // Line 8, and the tr = H(pk, 64) of line 9.
        let mut rho = [0u8; SEED_BYTES];
        rho.copy_from_slice(&self.bytes[..SEED_BYTES]);
        let pk = pk_encode(p, &rho, &t1);
        let mut tr = [0u8; TR_BYTES];
        hash_h(&[&pk], &mut tr);
        if differs != 0 || tr != cache.tr {
            return None;
        }
        Some(MlDsaPublicKey {
            params: self.params,
            bytes: pk,
            expanded: OnceLock::new(),
        })
    }
}

impl MlDsaSignature {
    /// The FIPS 204 parameter set this signature was produced under.
    /// Verification refuses a signature whose parameter set differs from
    /// the public key's.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.params
    }

    /// Serialize to the FIPS 204 signature encoding `c~ || z || h`
    /// (`signature_len()` bytes: 2420/3309/4627 for ML-DSA-44/65/87).
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Parse a FIPS 204 signature. Returns `None` if the length is not
    /// exactly `params.signature_len()` or if the structural decode fails
    /// (malformed hint encoding: indices out of order or a weight above
    /// omega). Acceptance here says nothing about validity for any
    /// message; that is decided by verification.
    #[must_use]
    pub fn from_wire_bytes(params: MlDsaParameterSet, bytes: &[u8]) -> Option<Self> {
        let p = params.profile();
        if bytes.len() != params.signature_len() {
            return None;
        }
        let decoded = sig_decode(p, bytes)?;
        Some(Self {
            params,
            bytes: bytes.to_vec(),
            decoded,
        })
    }

    /// Serialize to this crate's self-describing framing: a one-byte
    /// parameter-set tag followed by the FIPS 204 wire encoding, mirroring
    /// the key-blob format used by the key types.
    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse a blob produced by [`Self::to_key_blob`]. Returns `None` on an
    /// empty input, an unknown parameter-set tag, or a body rejected by
    /// [`Self::from_wire_bytes`] (wrong length or malformed hint encoding).
    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, rest) = blob.split_first()?;
        let params = MlDsaParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, rest)
    }
}

impl MlDsa {
    /// ML-DSA.KeyGen_internal (Algorithm 6) on the caller's 32-byte seed ξ,
    /// which the private key retains (see the module documentation). Every
    /// seed yields a key pair: the standard's ⊥ in Algorithm 1 is for a
    /// failed random bit generator, which a supplied seed has no part in.
    #[must_use]
    pub fn keygen_from_seed(
        params: MlDsaParameterSet,
        seed: &[u8; SEED_BYTES],
    ) -> (MlDsaPublicKey, MlDsaPrivateKey) {
        let (pk, sk) = keygen_internal(params.profile(), seed);
        (
            MlDsaPublicKey {
                params,
                bytes: pk,
                expanded: OnceLock::new(),
            },
            MlDsaPrivateKey {
                params,
                bytes: sk,
                seed: Some(boxed_seed(seed)),
                expanded: OnceLock::new(),
            },
        )
    }

    /// ML-DSA.KeyGen (Algorithm 1): ξ drawn from `rng`, then
    /// [`Self::keygen_from_seed`]. The `Csprng` contract has no failure
    /// return, so neither has this.
    #[must_use]
    pub fn keygen<R: Csprng>(
        params: MlDsaParameterSet,
        rng: &mut R,
    ) -> (MlDsaPublicKey, MlDsaPrivateKey) {
        // Algorithm 1, line 1: ξ ← B^32.
        let mut xi = [0u8; SEED_BYTES];
        rng.fill_bytes(&mut xi);
        let keys = Self::keygen_from_seed(params, &xi);
        crate::ct::zeroize_slice(&mut xi);
        keys
    }

    /// ML-DSA.Sign (Algorithm 2) with the caller's 32-byte `randomness` in
    /// place of line 5's rnd, and an explicit context string.
    ///
    /// `None` is the algorithm's ⊥:
    ///
    /// - `context` is longer than 255 bytes (lines 1–3);
    /// - ML-DSA.Sign_internal rejected 814 attempts in a row, the Appendix C
    ///   cap this crate applies, which a correct implementation reaches with
    ///   probability at most 2^−256.
    ///
    /// A private key whose s1 or s2 lies outside [−η, η] would also give
    /// `None`, but every constructor of [`MlDsaPrivateKey`] refuses such a
    /// key, so no key this function can be handed is one.
    #[must_use]
    pub fn sign_with_randomness_and_context(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        randomness: &[u8; RND_BYTES],
        context: &[u8],
    ) -> Option<MlDsaSignature> {
        // Algorithm 2, lines 1-3.
        if context.len() > MAX_CONTEXT_BYTES {
            return None;
        }
        // Line 10: the prefix of M′.
        let mut pre_bytes = [0u8; MAX_PRE_BYTES];
        let pre = build_pre_into(context, &mut pre_bytes);
        let p = private_key.params.profile();
        let key = private_key.expanded()?;
        // Line 11.
        let (bytes, decoded) =
            sign_internal(p, key, [pre, message], randomness, SIGN_ATTEMPT_LIMIT)?;
        Some(MlDsaSignature {
            params: private_key.params,
            bytes,
            decoded,
        })
    }

    /// Sign with caller-provided 32-byte randomness `rnd` and empty context.
    ///
    /// This is the hedged signing of FIPS 204 (Algorithm 2) with `rnd`
    /// supplied by the caller instead of drawn from an RNG: the output is a
    /// deterministic function of `(private_key, message, rnd)`, which is what
    /// known-answer tests need, but it is the standard's *deterministic
    /// variant* only when `rnd` is all zeros — see [`Self::sign_deterministic`].
    #[must_use]
    pub fn sign_with_randomness(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        randomness: &[u8; RND_BYTES],
    ) -> Option<MlDsaSignature> {
        Self::sign_with_randomness_and_context(private_key, message, randomness, &[])
    }

    /// Deterministic signing (the FIPS 204 Algorithm 2 variant with
    /// `rnd = 0^32`) with empty context: the signature is a function of the
    /// key and message alone. Prefer [`Self::sign`] unless reproducibility is
    /// required. §3.4 allows this variant only where side-channel and fault
    /// attacks are not a concern or are mitigated by other means, and §3.6.1
    /// footnote 3 names a leak particular to it: with rnd fixed, the number
    /// of rejected attempts, and so the signing time, is a function of the
    /// key and the message, and reveals information about the message
    /// (though not the private key); a signer who wants the message kept
    /// confidential should hedge instead. `None` in the cases
    /// [`Self::sign_with_randomness_and_context`] lists.
    #[must_use]
    pub fn sign_deterministic(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
    ) -> Option<MlDsaSignature> {
        // Algorithm 2, line 5, deterministic variant: rnd ← {0}^32.
        Self::sign_with_randomness(private_key, message, &[0u8; RND_BYTES])
    }

    /// Randomized signing with empty context.
    #[must_use]
    pub fn sign<R: Csprng>(
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Option<MlDsaSignature> {
        // Algorithm 2, line 5: rnd ← B^32.
        let mut rnd = [0u8; RND_BYTES];
        rng.fill_bytes(&mut rnd);
        let signature = Self::sign_with_randomness(private_key, message, &rnd);
        crate::ct::zeroize_slice(&mut rnd);
        signature
    }

    /// ML-DSA.Verify (Algorithm 3) with an explicit context string.
    ///
    /// `None` is the algorithm's ⊥ (lines 1–3): `context` is longer than 255
    /// bytes, and nothing was verified. Otherwise `Some(true)` exactly when
    /// `signature` is valid for `message` under `public_key` and `context`,
    /// and `Some(false)` when it is not, a signature of another parameter
    /// set than the key's included.
    #[must_use]
    pub fn verify_with_context(
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
        context: &[u8],
    ) -> Option<bool> {
        // Algorithm 3, lines 1-3.
        if context.len() > MAX_CONTEXT_BYTES {
            return None;
        }
        Some(Self::verify_framed(public_key, message, signature, context))
    }

    /// ML-DSA.Verify (Algorithm 3) with the empty context string, which
    /// cannot be too long: `true` exactly when `signature` is valid for
    /// `message` under `public_key`.
    #[must_use]
    pub fn verify(public_key: &MlDsaPublicKey, message: &[u8], signature: &MlDsaSignature) -> bool {
        Self::verify_framed(public_key, message, signature, &[])
    }

    /// Algorithm 3, lines 5 and 6, for a `context` of at most 255 bytes. A
    /// signature of another parameter set is not a signature under this key.
    fn verify_framed(
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
        context: &[u8],
    ) -> bool {
        if signature.params != public_key.params {
            return false;
        }
        // Line 5: the prefix of M′.
        let mut pre_bytes = [0u8; MAX_PRE_BYTES];
        let pre = build_pre_into(context, &mut pre_bytes);
        // Line 6.
        verify_internal(
            public_key.params.profile(),
            public_key.expanded(),
            [pre, message],
            &signature.decoded,
        )
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaPrivateKey(<redacted>)")
    }
}

// ===========================================================================
// Internal key generation, signing and verification (FIPS 204 §6)
// ===========================================================================

/// A heap copy of `seed`, allocated zeroed and filled in place, so that no
/// by-value copy of the secret is made on the way.
fn boxed_seed(seed: &[u8; SEED_BYTES]) -> Box<[u8; SEED_BYTES]> {
    let mut boxed = Box::new([0u8; SEED_BYTES]);
    boxed.copy_from_slice(seed);
    boxed
}

/// ML-DSA.KeyGen_internal (Algorithm 6): (pk, sk) from the seed ξ.
fn keygen_internal(p: Profile, xi: &[u8; SEED_BYTES]) -> (Vec<u8>, Vec<u8>) {
    // Line 1: (ρ, ρ′, K) ← H(ξ ‖ IntegerToBytes(k, 1) ‖ IntegerToBytes(ℓ, 1), 128).
    let mut seeds = [0u8; SEED_BYTES + CRH_BYTES + SEED_BYTES];
    hash_h(
        &[xi, &integer_to_bytes::<1>(p.k), &integer_to_bytes::<1>(p.l)],
        &mut seeds,
    );
    let mut rho = [0u8; SEED_BYTES];
    let mut rho_prime = [0u8; CRH_BYTES];
    let mut key = [0u8; SEED_BYTES];
    rho.copy_from_slice(&seeds[..SEED_BYTES]);
    rho_prime.copy_from_slice(&seeds[SEED_BYTES..SEED_BYTES + CRH_BYTES]);
    key.copy_from_slice(&seeds[SEED_BYTES + CRH_BYTES..]);
    crate::ct::zeroize_slice(&mut seeds);

    // Line 3.
    let a_hat = expand_a(p, &rho);
    // Line 4.
    let mut s1 = PolyVec::zero(p.l);
    let mut s2 = PolyVec::zero(p.k);
    expand_s(p, &rho_prime, &mut s1, &mut s2);
    crate::ct::zeroize_slice(&mut rho_prime);

    // Line 5: t ← NTT⁻¹(Â ∘ NTT(s1)) + s2.
    let mut s1_hat = PolyVec::zero(p.l);
    vector_to_mod_q(&s1, &mut s1_hat);
    ntt_vector(&mut s1_hat);
    let mut t = PolyVec::zero(p.k);
    matrix_vector_ntt(&a_hat, &s1_hat, &mut t);
    ntt_inverse_vector(&mut t);
    for (t_j, &s2_j) in t
        .polys_mut()
        .as_flattened_mut()
        .iter_mut()
        .zip(s2.polys().as_flattened())
    {
        *t_j = add_mod_q(*t_j, to_mod_q(s2_j));
    }

    // Line 6: (t1, t0) ← Power2Round(t), coefficientwise.
    let mut t1 = PolyVec::zero(p.k);
    let mut t0 = PolyVec::zero(p.k);
    for ((&t_j, t1_j), t0_j) in t
        .polys()
        .as_flattened()
        .iter()
        .zip(t1.polys_mut().as_flattened_mut())
        .zip(t0.polys_mut().as_flattened_mut())
    {
        (*t1_j, *t0_j) = power2_round(t_j);
    }

    // Lines 8-10.
    let pk = pk_encode(p, &rho, &t1);
    let mut tr = [0u8; TR_BYTES];
    hash_h(&[&pk], &mut tr);
    let sk = sk_encode(p, &rho, &key, &tr, &s1, &s2, &t0);

    crate::ct::zeroize_slice(&mut key);
    s1.wipe();
    s2.wipe();
    s1_hat.wipe();
    t.wipe();
    t0.wipe();
    (pk, sk)
}

/// All ones if some coefficient of `s` lies outside [−η, η], zero otherwise.
/// Every coefficient is examined whatever the answer.
fn outside_eta_mask(p: Profile, s: &PolyVec) -> i32 {
    s.polys().as_flattened().iter().fold(0, |outside, &s_j| {
        outside | at_least_mask(abs_ct(s_j), p.eta + 1)
    })
}

/// Writes f of each coefficient of `input` into `output`, a vector of the
/// same length.
fn map_coefficients(input: &PolyVec, output: &mut PolyVec, f: impl Fn(i32) -> i32) {
    debug_assert_eq!(output.len(), input.len());
    for (out_j, &in_j) in output
        .polys_mut()
        .as_flattened_mut()
        .iter_mut()
        .zip(input.polys().as_flattened())
    {
        *out_j = f(in_j);
    }
}

/// Appendix C, Table 3: ML-DSA.Sign_internal may cap its rejection loop, at no
/// fewer than 814 iterations, a count a correct implementation exceeds with
/// probability at most 2^−256.
const SIGN_ATTEMPT_LIMIT: usize = 814;

/// ML-DSA.Sign_internal (Algorithm 7) on M′ = `m_prime[0]` ‖ `m_prime[1]`,
/// returning σ together with its decoded components, or ⊥ once
/// `attempt_limit` attempts have all been rejected. Lines 1-5 arrive
/// precomputed in `key`.
fn sign_internal(
    p: Profile,
    key: &CachedPrivateKey,
    m_prime: [&[u8]; 2],
    rnd: &[u8; RND_BYTES],
    attempt_limit: usize,
) -> Option<(Vec<u8>, DecodedSignature)> {
    // Line 6: μ ← H(BytesToBits(tr) ‖ M′, 64).
    let mut mu = [0u8; CRH_BYTES];
    hash_h(&[&key.tr, m_prime[0], m_prime[1]], &mut mu);
    // Line 7: ρ″ ← H(K ‖ rnd ‖ μ, 64).
    let mut rho_double_prime = [0u8; CRH_BYTES];
    hash_h(&[&key.key, rnd, &mu], &mut rho_double_prime);

    // Lines 8-32, with κ = attempt·ℓ (line 31). Each attempt wipes its
    // scratch on exit, whether it was accepted or rejected.
    let mut scratch = SigningScratch::new(p);
    let decoded = (0..attempt_limit).find_map(|attempt| {
        sign_attempt(p, key, &mu, &rho_double_prime, attempt * p.l, &mut scratch)
    });
    // μ and ρ″ have served their last attempt (§3.6.3). Should the limit have
    // been reached, the result is ⊥ and these were the last intermediates
    // still held (Appendix C).
    crate::ct::zeroize_slice(&mut mu);
    crate::ct::zeroize_slice(&mut rho_double_prime);

    // Line 33.
    decoded.map(|decoded| (sig_encode(p, &decoded), decoded))
}

/// Working storage for one iteration of Algorithm 7's rejection loop. While an
/// iteration runs, every field holds values derived from the private key.
struct SigningScratch {
    y: PolyVec,
    y_hat: PolyVec,
    w: PolyVec,
    w1: PolyVec,
    /// ⟨⟨cs1⟩⟩ (line 18), then z = y + ⟨⟨cs1⟩⟩ in place (line 20).
    z: PolyVec,
    /// ⟨⟨cs2⟩⟩ (line 19), then w − ⟨⟨cs2⟩⟩ in place (line 21).
    w_minus_cs2: PolyVec,
    ct0: PolyVec,
    h: PolyVec,
    c: Poly,
    c_hat: Poly,
    c_tilde: [u8; MAX_CTILDE_BYTES],
    w1_tilde: [u8; MAX_W1_ENCODED_BYTES],
}

impl SigningScratch {
    fn new(p: Profile) -> Self {
        Self {
            y: PolyVec::zero(p.l),
            y_hat: PolyVec::zero(p.l),
            w: PolyVec::zero(p.k),
            w1: PolyVec::zero(p.k),
            z: PolyVec::zero(p.l),
            w_minus_cs2: PolyVec::zero(p.k),
            ct0: PolyVec::zero(p.k),
            h: PolyVec::zero(p.k),
            c: [0; N],
            c_hat: [0; N],
            c_tilde: [0; MAX_CTILDE_BYTES],
            w1_tilde: [0; MAX_W1_ENCODED_BYTES],
        }
    }

    fn wipe(&mut self) {
        self.y.wipe();
        self.y_hat.wipe();
        self.w.wipe();
        self.w1.wipe();
        self.z.wipe();
        self.w_minus_cs2.wipe();
        self.ct0.wipe();
        self.h.wipe();
        crate::ct::zeroize_slice(&mut self.c);
        crate::ct::zeroize_slice(&mut self.c_hat);
        crate::ct::zeroize_slice(&mut self.c_tilde);
        crate::ct::zeroize_slice(&mut self.w1_tilde);
    }
}

/// Wipes a `SigningScratch` when dropped, however the iteration using it ends.
struct WipeOnDrop<'a>(&'a mut SigningScratch);

impl Drop for WipeOnDrop<'_> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

/// One round of the FIPS 204 signing rejection loop (Algorithm 7, lines
/// 11-30) for counter κ: computes the commitment, challenge, response `z`, and
/// hint, and returns the decoded signature if every bound holds. Returns
/// `None` if the candidate must be rejected. Secret-derived intermediates
/// (`y`, `NTT(y)`, `w`, `w1`, `c~`, `c`, `c·s1`, `z`, `w − c·s2`, `c·t0`, `h`)
/// live in `scratch`, which is wiped on every exit.
fn sign_attempt(
    p: Profile,
    key: &CachedPrivateKey,
    mu: &[u8; CRH_BYTES],
    rho_double_prime: &[u8; CRH_BYTES],
    kappa: usize,
    scratch: &mut SigningScratch,
) -> Option<DecodedSignature> {
    let guard = WipeOnDrop(scratch);
    let s = &mut *guard.0;

    // Line 11: y ← ExpandMask(ρ″, κ).
    expand_mask(p, rho_double_prime, kappa, &mut s.y);
    // Line 12: w ← NTT⁻¹(Â ∘ NTT(y)).
    vector_to_mod_q(&s.y, &mut s.y_hat);
    ntt_vector(&mut s.y_hat);
    matrix_vector_ntt(&key.a_hat, &s.y_hat, &mut s.w);
    ntt_inverse_vector(&mut s.w);
    // Line 13: w1 ← HighBits(w).
    map_coefficients(&s.w, &mut s.w1, |w_j| high_bits(p, w_j));
    // Line 15: c̃ ← H(μ ‖ w1Encode(w1), λ/4).
    let w1_tilde = &mut s.w1_tilde[..p.w1_encoded_len()];
    w1_encode(p, &s.w1, w1_tilde);
    hash_h(&[mu, w1_tilde], &mut s.c_tilde[..p.ctilde_bytes]);
    // Lines 16-17: c ← SampleInBall(c̃), ĉ ← NTT(c).
    sample_in_ball(p, &s.c_tilde[..p.ctilde_bytes], &mut s.c);
    for (c_hat_j, &c_j) in s.c_hat.iter_mut().zip(s.c.iter()) {
        *c_hat_j = to_mod_q(c_j);
    }
    ntt(&mut s.c_hat);
    // Lines 18 and 20: z ← y + NTT⁻¹(ĉ ∘ ŝ1).
    scalar_vector_ntt(&s.c_hat, &key.s1_hat, &mut s.z);
    ntt_inverse_vector(&mut s.z);
    for (z_j, &y_j) in
        s.z.polys_mut()
            .as_flattened_mut()
            .iter_mut()
            .zip(s.y.polys().as_flattened())
    {
        *z_j = add_mod_q(*z_j, to_mod_q(y_j));
    }
    // Lines 19 and 21: w − ⟨⟨cs2⟩⟩, whose LowBits is r0.
    scalar_vector_ntt(&s.c_hat, &key.s2_hat, &mut s.w_minus_cs2);
    ntt_inverse_vector(&mut s.w_minus_cs2);
    for (d_j, &w_j) in s
        .w_minus_cs2
        .polys_mut()
        .as_flattened_mut()
        .iter_mut()
        .zip(s.w.polys().as_flattened())
    {
        *d_j = sub_mod_q(w_j, *d_j);
    }
    // Line 25: ⟨⟨ct0⟩⟩ ← NTT⁻¹(ĉ ∘ t̂0).
    scalar_vector_ntt(&s.c_hat, &key.t0_hat, &mut s.ct0);
    ntt_inverse_vector(&mut s.ct0);
    // Line 26: h ← MakeHint(−⟨⟨ct0⟩⟩, w − ⟨⟨cs2⟩⟩ + ⟨⟨ct0⟩⟩).
    for ((h_j, &ct0_j), &d_j) in
        s.h.polys_mut()
            .as_flattened_mut()
            .iter_mut()
            .zip(s.ct0.polys().as_flattened())
            .zip(s.w_minus_cs2.polys().as_flattened())
    {
        *h_j = make_hint(p, sub_mod_q(0, ct0_j), add_mod_q(d_j, ct0_j));
    }

    // Lines 23 and 28. Algorithm 7 skips lines 25-28 once line 23 rejects;
    // computing them regardless reaches the same verdict, and every attempt
    // then does the same work, so timing shows that an attempt was rejected
    // but not which test rejected it.
    if rejection_mask(p, &s.z, &s.w_minus_cs2, &s.ct0, &s.h) != 0 {
        return None;
    }

    // Accepted: c̃, z mod± q (line 33) and h become the public signature.
    let mut z = PolyVec::zero(p.l);
    map_coefficients(&s.z, &mut z, centered_mod_q);
    Some(DecodedSignature {
        c: s.c_tilde[..p.ctilde_bytes].to_vec(),
        z,
        h: s.h.clone(),
    })
}

/// The rejection tests of Algorithm 7 as one mask: all ones if ‖z‖∞ ≥ γ1 − β
/// or ‖LowBits(w − ⟨⟨cs2⟩⟩)‖∞ ≥ γ2 − β (line 23), or if ‖⟨⟨ct0⟩⟩‖∞ ≥ γ2 or h
/// holds more than ω ones (line 28); zero otherwise. z, w − ⟨⟨cs2⟩⟩ and
/// ⟨⟨ct0⟩⟩ have coefficients in [0, q) and h in {0, 1}. Every coefficient is
/// examined, and the mask helpers' ranges hold: the absolute values are at
/// most (q − 1)/2 and the hint weight at most k·256.
fn rejection_mask(
    p: Profile,
    z: &PolyVec,
    w_minus_cs2: &PolyVec,
    ct0: &PolyVec,
    h: &PolyVec,
) -> i32 {
    let mut reject = 0;
    for &z_j in z.polys().as_flattened() {
        reject |= at_least_mask(abs_ct(centered_mod_q(z_j)), p.gamma1 - p.beta);
    }
    for &d_j in w_minus_cs2.polys().as_flattened() {
        reject |= at_least_mask(abs_ct(low_bits(p, d_j)), p.gamma2 - p.beta);
    }
    for &ct0_j in ct0.polys().as_flattened() {
        reject |= at_least_mask(abs_ct(centered_mod_q(ct0_j)), p.gamma2);
    }
    let weight: i32 = h.polys().as_flattened().iter().sum();
    reject | at_least_mask(weight, p.omega as i32 + 1)
}

/// The first conjunct of Algorithm 8, line 13: [[‖z‖∞ < γ1 − β]] for z mod± q.
/// Verification holds only public values, so this stops at the first
/// coefficient out of bounds.
fn response_within_bound(p: Profile, z: &PolyVec) -> bool {
    let bound = p.gamma1 - p.beta;
    z.polys()
        .as_flattened()
        .iter()
        .all(|&z_j| z_j.abs() < bound)
}

/// ML-DSA.Verify_internal (Algorithm 8) on M′ = `m_prime[0]` ‖ `m_prime[1]`.
/// Lines 1, 5 and 6 arrive precomputed in `key`; lines 2-4 ran when the
/// signature was parsed. The intermediates are functions of the message,
/// signature and public key, which some applications keep confidential, and
/// §3.6.3 has each destroyed as soon as it is no longer needed.
fn verify_internal(
    p: Profile,
    key: &CachedPublicKey,
    m_prime: [&[u8]; 2],
    sig: &DecodedSignature,
) -> bool {
    // Line 13's first conjunct. Deciding it first changes only how much work
    // a bad signature costs.
    if !response_within_bound(p, &sig.z) {
        return false;
    }
    // Line 7: μ ← H(BytesToBits(tr) ‖ M′, 64).
    let mut mu = [0u8; CRH_BYTES];
    hash_h(&[&key.tr, m_prime[0], m_prime[1]], &mut mu);
    // Line 8: c ← SampleInBall(c̃).
    let mut c = [0i32; N];
    sample_in_ball(p, &sig.c, &mut c);
    let mut c_hat = [0i32; N];
    for (c_hat_j, &c_j) in c_hat.iter_mut().zip(c.iter()) {
        *c_hat_j = to_mod_q(c_j);
    }
    ntt(&mut c_hat);
    // Line 9: w′Approx ← NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t1·2^d)).
    let mut z_hat = PolyVec::zero(p.l);
    vector_to_mod_q(&sig.z, &mut z_hat);
    ntt_vector(&mut z_hat);
    let mut w_approx = PolyVec::zero(p.k);
    matrix_vector_ntt(&key.a_hat, &z_hat, &mut w_approx);
    z_hat.wipe();
    let mut ct1_hat = PolyVec::zero(p.k);
    scalar_vector_ntt(&c_hat, &key.t1_shifted_hat, &mut ct1_hat);
    crate::ct::zeroize_slice(&mut c);
    crate::ct::zeroize_slice(&mut c_hat);
    for (w_j, &ct1_j) in w_approx
        .polys_mut()
        .as_flattened_mut()
        .iter_mut()
        .zip(ct1_hat.polys().as_flattened())
    {
        *w_j = sub_mod_q(*w_j, ct1_j);
    }
    ct1_hat.wipe();
    ntt_inverse_vector(&mut w_approx);
    // Line 10: w′1 ← UseHint(h, w′Approx).
    let mut w1 = PolyVec::zero(p.k);
    for ((w1_j, &h_j), &r_j) in w1
        .polys_mut()
        .as_flattened_mut()
        .iter_mut()
        .zip(sig.h.polys().as_flattened())
        .zip(w_approx.polys().as_flattened())
    {
        *w1_j = use_hint(p, h_j, r_j);
    }
    w_approx.wipe();
    // Line 12: c̃′ ← H(μ ‖ w1Encode(w′1), λ/4).
    let mut w1_tilde = [0u8; MAX_W1_ENCODED_BYTES];
    w1_encode(p, &w1, &mut w1_tilde[..p.w1_encoded_len()]);
    w1.wipe();
    let mut c_tilde_prime = [0u8; MAX_CTILDE_BYTES];
    hash_h(
        &[&mu, &w1_tilde[..p.w1_encoded_len()]],
        &mut c_tilde_prime[..p.ctilde_bytes],
    );
    crate::ct::zeroize_slice(&mut mu);
    crate::ct::zeroize_slice(&mut w1_tilde);
    // Line 13's second conjunct.
    let verdict =
        crate::ct::constant_time_eq_mask(&sig.c, &c_tilde_prime[..p.ctilde_bytes]) == u8::MAX;
    crate::ct::zeroize_slice(&mut c_tilde_prime);
    verdict
}

/// The byte prefix of M′ that ML-DSA.Sign and ML-DSA.Verify form at lines 10
/// and 5 of Algorithms 2 and 3: IntegerToBytes(0, 1) ‖ IntegerToBytes(|ctx|, 1)
/// ‖ ctx, written into `out` and returned as a slice of it. The leading 0 is
/// the domain separator that tells ML-DSA from HashML-DSA, whose Algorithms 4
/// and 5 write 1 there; |ctx| fits its one byte because both callers refused
/// longer contexts at lines 1–3. M′ is a bit string in the standard, and for
/// a message of whole bytes it is BytesToBits of this prefix followed by the
/// message, which is how H absorbs it (§3.7).
fn build_pre_into<'a>(context: &[u8], out: &'a mut [u8; MAX_PRE_BYTES]) -> &'a [u8] {
    debug_assert!(context.len() <= MAX_CONTEXT_BYTES);
    out[0] = 0;
    out[1] = context.len() as u8;
    out[2..2 + context.len()].copy_from_slice(context);
    &out[..2 + context.len()]
}

// ===========================================================================
// Arithmetic modulo q
// ===========================================================================
//
// Every routine here is branch-free and touches memory independently of the
// values it computes on, because the same code carries s1, s2, t0, y and w.

/// ⌊2^64 / q⌋, the Barrett reciprocal of q for a 64-bit word.
const BARRETT_RECIPROCAL: u64 = ((1u128 << 64) / Q as u128) as u64;

/// x mod q for any x ∈ [0, 2^64), in constant time.
///
/// Barrett reduction (P. Barrett, "Implementing the Rivest Shamir and Adleman
/// public key encryption algorithm on a standard digital signal processor",
/// CRYPTO '86). With m = ⌊2^64/q⌋ the quotient estimate q̂ = ⌊x·m/2^64⌋ is
/// within one of ⌊x/q⌋. From m ≤ 2^64/q, x·m/2^64 ≤ x/q, so q̂ ≤ ⌊x/q⌋. From
/// m > 2^64/q − 1, x·m/2^64 > x/q − x/2^64 > x/q − 1, so q̂ ≥ ⌊x/q⌋ − 1. Hence
/// x − q̂·q ∈ [0, 2q), and one masked subtraction of q completes the reduction.
#[inline(always)]
fn reduce(x: u64) -> i32 {
    let estimate = ((u128::from(x) * u128::from(BARRETT_RECIPROCAL)) >> 64) as u64;
    subtract_q_if_at_least_q((x - estimate * Q as u64) as u32)
}

/// r mod q for r ∈ [0, 2q), with a mask in place of a branch. When r ≥ q,
/// r − q lies in [0, q) and has bit 31 clear; when r < q it wraps to
/// [2^32 − q, 2^32), where bit 31 is set because q < 2^31.
#[inline(always)]
const fn subtract_q_if_at_least_q(r: u32) -> i32 {
    let difference = r.wrapping_sub(Q as u32);
    let borrowed = 0u32.wrapping_sub(difference >> 31);
    difference.wrapping_add(Q as u32 & borrowed) as i32
}

/// (a + b) mod q for a, b ∈ [0, q); the sum lies in [0, 2q).
#[inline(always)]
const fn add_mod_q(a: i32, b: i32) -> i32 {
    subtract_q_if_at_least_q((a + b) as u32)
}

/// (a − b) mod q for a, b ∈ [0, q); a − b + q lies in [1, 2q).
#[inline(always)]
const fn sub_mod_q(a: i32, b: i32) -> i32 {
    subtract_q_if_at_least_q((a - b + Q) as u32)
}

/// (a·b) mod q for a, b ∈ [0, q); the product is below q² < 2^46.
#[inline(always)]
fn mul_mod_q(a: i32, b: i32) -> i32 {
    reduce(a as u64 * b as u64)
}

/// x mod q for a signed x ∈ (−q, q): q is added exactly when the sign bit is set.
#[inline(always)]
const fn to_mod_q(x: i32) -> i32 {
    x + (Q & (x >> 31))
}

/// x mod± q (§2.3) for x ∈ [0, q). As q is odd, −⌈q/2⌉ < m′ ≤ ⌊q/2⌋ is the
/// range [−(q − 1)/2, (q − 1)/2], and q is subtracted exactly when
/// x > (q − 1)/2, which the sign of (q − 1)/2 − x reports.
#[inline(always)]
const fn centered_mod_q(x: i32) -> i32 {
    x - (Q & (((Q - 1) / 2 - x) >> 31))
}

/// |x| without a branch, for |x| < 2^31.
#[inline(always)]
const fn abs_ct(x: i32) -> i32 {
    let sign = x >> 31;
    (x ^ sign) - sign
}

/// All ones when value ≥ bound and zero otherwise, for value, bound ∈ [0, 2^30].
#[inline(always)]
const fn at_least_mask(value: i32, bound: i32) -> i32 {
    (bound - 1 - value) >> 31
}

/// Multiply-and-shift form of ⌊n/d⌋ for every n in a known range [0, U]
/// (T. Granlund and P. L. Montgomery, "Division by invariant integers using
/// multiplication", PLDI 1994).
///
/// For a shift s let M = ⌈2^s/d⌉ and e = M·d − 2^s ∈ [0, d). Writing
/// n = a·d + b with 0 ≤ b < d gives n·M/2^s = n/d + n·e/(d·2^s) =
/// a + (b + n·e/2^s)/d. When e·U < 2^s, n·e/2^s < 1, so
/// 0 ≤ b + n·e/2^s < d and ⌊n·M/2^s⌋ = a exactly. `derive` takes the least
/// such s and insists that U·M fits in 64 bits, so `quotient` cannot overflow
/// for a dividend in range, which it checks in debug builds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FloorDivision {
    multiplier: u64,
    shift: u32,
    max_dividend: u64,
}

impl FloorDivision {
    const fn derive(divisor: u64, max_dividend: u64) -> Self {
        let mut shift = 0;
        loop {
            assert!(
                shift < 64,
                "no 64-bit multiplier for this divisor and range"
            );
            let power = 1u128 << shift;
            let multiplier = power.div_ceil(divisor as u128);
            let excess = multiplier * divisor as u128 - power;
            if excess * (max_dividend as u128) < power {
                assert!((max_dividend as u128) * multiplier <= u64::MAX as u128);
                return Self {
                    multiplier: multiplier as u64,
                    shift,
                    max_dividend,
                };
            }
            shift += 1;
        }
    }

    /// ⌊n/d⌋ for n ∈ [0, U], with no division instruction.
    #[inline(always)]
    const fn quotient(self, n: u64) -> u64 {
        debug_assert!(n <= self.max_dividend);
        (n * self.multiplier) >> self.shift
    }
}

// ===========================================================================
// NTT and arithmetic in T_q (FIPS 204 §7.5, §7.6)
// ===========================================================================

/// base^exponent mod q by square-and-multiply. Used only to build constants
/// at compile time from public values.
const fn pow_mod_q(base: i32, mut exponent: u32) -> i32 {
    let q = Q as u64;
    let mut power = base as u64 % q;
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * power % q;
        }
        power = power * power % q;
        exponent >>= 1;
    }
    result as i32
}

/// BitRev8 (Algorithm 43): bit i of m becomes bit 7 − i of the result.
const fn bit_rev8(m: u8) -> u8 {
    let mut reversed = 0u8;
    let mut i = 0;
    while i < BYTE_BITS as u8 {
        reversed |= ((m >> i) & 1) << (BYTE_BITS as u8 - 1 - i);
        i += 1;
    }
    reversed
}

/// zetas(k) = ζ^BitRev8(k) mod q (§7.5), computed at compile time from ζ = 1753.
///
/// Algorithms 41 and 42 read only k ∈ [1, 255]. At k = 0 the formula gives
/// ζ^0 = 1, where the printed table of Appendix B shows an unused 0.
const ZETAS: [i32; N] = {
    let mut table = [0i32; N];
    let mut k = 0;
    while k < N {
        table[k] = pow_mod_q(ZETA, bit_rev8(k as u8) as u32);
        k += 1;
    }
    table
};

/// f = 256^(−1) mod q (Algorithm 42, line 21), by Fermat's little theorem.
const NTT_INVERSE_SCALE: i32 = pow_mod_q(N as i32, (Q - 2) as u32);

/// NTT (Algorithm 41), in place on coefficients in [0, q).
fn ntt(w: &mut Poly) {
    let mut m = 0;
    let mut len = N / 2;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            let z = ZETAS[m];
            let (low, high) = w[start..start + 2 * len].split_at_mut(len);
            for (w_j, w_j_len) in low.iter_mut().zip(high.iter_mut()) {
                let t = mul_mod_q(z, *w_j_len);
                *w_j_len = sub_mod_q(*w_j, t);
                *w_j = add_mod_q(*w_j, t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// NTT⁻¹ (Algorithm 42), in place on coefficients in [0, q).
fn ntt_inverse(w: &mut Poly) {
    let mut m = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            // −zetas(m) mod q; zetas(m) is a power of ζ, never 0, so this is in [1, q).
            let z = Q - ZETAS[m];
            let (low, high) = w[start..start + 2 * len].split_at_mut(len);
            for (w_j, w_j_len) in low.iter_mut().zip(high.iter_mut()) {
                let t = *w_j;
                *w_j = add_mod_q(t, *w_j_len);
                *w_j_len = mul_mod_q(z, sub_mod_q(t, *w_j_len));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for w_j in w.iter_mut() {
        *w_j = mul_mod_q(NTT_INVERSE_SCALE, *w_j);
    }
}

/// NTT applied to each coordinate of a vector (§2.5).
fn ntt_vector(v: &mut PolyVec) {
    v.polys_mut().iter_mut().for_each(ntt);
}

/// NTT⁻¹ applied to each coordinate of a vector (§2.5).
fn ntt_inverse_vector(v: &mut PolyVec) {
    v.polys_mut().iter_mut().for_each(ntt_inverse);
}

/// Writes `short` mod q into `canonical`, a vector of the same length,
/// coordinate by coordinate, for signed coefficients in (−q, q).
fn vector_to_mod_q(short: &PolyVec, canonical: &mut PolyVec) {
    debug_assert_eq!(canonical.len(), short.len());
    for (dst, src) in canonical.polys_mut().iter_mut().zip(short.polys()) {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d = to_mod_q(s);
        }
    }
}

/// MultiplyNTT (Algorithm 45): c_hat = a_hat ∘ b_hat.
fn multiply_ntt(a_hat: &Poly, b_hat: &Poly, c_hat: &mut Poly) {
    for ((c, &a), &b) in c_hat.iter_mut().zip(a_hat.iter()).zip(b_hat.iter()) {
        *c = mul_mod_q(a, b);
    }
}

/// ScalarVectorNTT (Algorithm 47): w_hat = c_hat ∘ v_hat, into a vector of
/// the same length.
fn scalar_vector_ntt(c_hat: &Poly, v_hat: &PolyVec, w_hat: &mut PolyVec) {
    debug_assert_eq!(w_hat.len(), v_hat.len());
    for (w_i, v_i) in w_hat.polys_mut().iter_mut().zip(v_hat.polys()) {
        multiply_ntt(c_hat, v_i, w_i);
    }
}

/// MatrixVectorNTT (Algorithm 48): w_hat = M_hat ∘ v_hat.
///
/// Line 4 accumulates with AddNTT (Algorithm 44) over MultiplyNTT (Algorithm
/// 45). The same residue is obtained by summing the ℓ integer products first
/// and reducing once: each product is below q² < 2^46 and ℓ ≤ 7 of them sum
/// below 2^49, well inside the 64-bit range `reduce` accepts.
fn matrix_vector_ntt(m_hat: &MatrixNtt, v_hat: &PolyVec, w_hat: &mut PolyVec) {
    debug_assert_eq!((m_hat.l, m_hat.k), (v_hat.len(), w_hat.len()));
    let mut sums = [0u64; N];
    for (row, w_i) in m_hat.rows().zip(w_hat.polys_mut()) {
        sums.fill(0);
        for (m_ij, v_j) in row.iter().zip(v_hat.polys()) {
            for ((sum, &m), &v) in sums.iter_mut().zip(m_ij.iter()).zip(v_j.iter()) {
                *sum += m as u64 * v as u64;
            }
        }
        for (w, &sum) in w_i.iter_mut().zip(sums.iter()) {
            *w = reduce(sum);
        }
    }
    crate::ct::zeroize_slice(&mut sums);
}

// ===========================================================================
// Conversion between data types (FIPS 204 §7.1)
// ===========================================================================

/// IntegerToBytes (Algorithm 11): x mod 256^α as α = `A` bytes, least
/// significant first. Only public counters and dimensions reach it.
fn integer_to_bytes<const A: usize>(x: usize) -> [u8; A] {
    let mut y = [0u8; A];
    let mut rest = x;
    for y_i in y.iter_mut() {
        *y_i = (rest % 256) as u8;
        rest /= 256;
    }
    y
}

/// A bit string written directly into its BitsToBytes (Algorithm 12) image:
/// bit i of the string is bit (i mod 8) of byte ⌊i/8⌋, so the string itself
/// is never materialized. Writes depend only on the widths, never on values.
struct BitStringWriter<'a> {
    bytes: &'a mut [u8],
    next_byte: usize,
    pending: u64,
    pending_bits: u32,
}

impl<'a> BitStringWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes,
            next_byte: 0,
            pending: 0,
            pending_bits: 0,
        }
    }

    /// Appends IntegerToBits(x, α) (Algorithm 9), the α ≤ 32 low-order bits
    /// of x, least significant first.
    #[inline(always)]
    fn integer_to_bits(&mut self, x: u32, alpha: u32) {
        self.pending |= (u64::from(x) & ((1u64 << alpha) - 1)) << self.pending_bits;
        self.pending_bits += alpha;
        while self.pending_bits >= BYTE_BITS {
            self.bytes[self.next_byte] = self.pending as u8;
            self.next_byte += 1;
            self.pending >>= BYTE_BITS;
            self.pending_bits -= BYTE_BITS;
        }
    }

    /// Every packing in FIPS 204 writes a whole number of bytes.
    fn finish(self) {
        debug_assert!(self.pending_bits == 0 && self.next_byte == self.bytes.len());
    }
}

/// A byte string read as its BytesToBits (Algorithm 13) bit string, bit i
/// being bit (i mod 8) of byte ⌊i/8⌋, and consumed a group at a time.
struct BitStringReader<'a> {
    bytes: &'a [u8],
    next_byte: usize,
    pending: u64,
    pending_bits: u32,
}

impl<'a> BitStringReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            next_byte: 0,
            pending: 0,
            pending_bits: 0,
        }
    }

    /// BitsToInteger (Algorithm 10) of the next α ≤ 32 bits y: Σ y(i)·2^i.
    #[inline(always)]
    fn bits_to_integer(&mut self, alpha: u32) -> u32 {
        while self.pending_bits < alpha {
            self.pending |= u64::from(self.bytes[self.next_byte]) << self.pending_bits;
            self.next_byte += 1;
            self.pending_bits += 8;
        }
        let x = (self.pending & ((1u64 << alpha) - 1)) as u32;
        self.pending >>= alpha;
        self.pending_bits -= alpha;
        x
    }
}

/// CoeffFromThreeBytes (Algorithm 14). Only the public seed ρ reaches it.
#[inline(always)]
fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<i32> {
    // Lines 1-4 clear the top bit of b2; line 5 forms 2^16·b2′ + 2^8·b1 + b0.
    let z = (i32::from(b2 & 0x7f) << 16) | (i32::from(b1) << 8) | i32::from(b0);
    (z < Q).then_some(z)
}

/// ⌊b/5⌋ for b ∈ [0, 15]; `FloorDivision::derive` settles on M = 13, s = 6
/// (e = 13·5 − 64 = 1, and 1·15 < 64).
const DIVIDE_HALF_BYTE_BY_5: FloorDivision = FloorDivision::derive(5, 15);

/// CoeffFromHalfByte (Algorithm 15).
///
/// The nibble comes from ρ′ and is secret. The choice between a coefficient
/// and ⊥ may branch: it reveals only whether this nibble was one of the
/// discarded values, never which coefficient an accepted nibble yields. That
/// coefficient is computed without `%`, a table or a branch, as
/// 2 − (b − 5·⌊b/5⌋) with the quotient taken by multiply-and-shift.
#[inline(always)]
fn coeff_from_half_byte(eta: i32, b: u8) -> Option<i32> {
    let b = i32::from(b);
    if eta == 2 && b < ETA2_REJECT_BOUND {
        let quotient = DIVIDE_HALF_BYTE_BY_5.quotient(b as u64) as i32;
        Some(2 - (b - 5 * quotient))
    } else if eta == 4 && b < ETA4_REJECT_BOUND {
        Some(4 - b)
    } else {
        None
    }
}

/// SimpleBitPack (Algorithm 16): w with coefficients in [0, b] into
/// 32·bitlen b bytes.
fn simple_bit_pack(w: &Poly, b: u32, out: &mut [u8]) {
    let width = bitlen(b);
    debug_assert_eq!(out.len(), 32 * width as usize);
    let mut z = BitStringWriter::new(out);
    for &w_i in w {
        z.integer_to_bits(w_i as u32, width);
    }
    z.finish();
}

/// BitPack (Algorithm 17): w with coefficients in [−a, b] into
/// 32·bitlen(a + b) bytes, by packing b − w_i.
fn bit_pack(w: &Poly, a: u32, b: u32, out: &mut [u8]) {
    let width = bitlen(a + b);
    debug_assert_eq!(out.len(), 32 * width as usize);
    let mut z = BitStringWriter::new(out);
    for &w_i in w {
        z.integer_to_bits((b as i32 - w_i) as u32, width);
    }
    z.finish();
}

/// SimpleBitUnpack (Algorithm 18): coefficients in [0, 2^c − 1], c = bitlen b.
fn simple_bit_unpack(v: &[u8], b: u32, w: &mut Poly) {
    let c = bitlen(b);
    debug_assert_eq!(v.len(), 32 * c as usize);
    let mut z = BitStringReader::new(v);
    for w_i in w.iter_mut() {
        *w_i = z.bits_to_integer(c) as i32;
    }
}

/// BitUnpack (Algorithm 19): coefficients in [b − 2^c + 1, b],
/// c = bitlen(a + b).
fn bit_unpack(v: &[u8], a: u32, b: u32, w: &mut Poly) {
    let c = bitlen(a + b);
    debug_assert_eq!(v.len(), 32 * c as usize);
    let mut z = BitStringReader::new(v);
    for w_i in w.iter_mut() {
        *w_i = b as i32 - z.bits_to_integer(c) as i32;
    }
}

/// HintBitPack (Algorithm 20). Runs only on an accepted signature's hint,
/// which is public, so it branches on the hint bits as the algorithm does.
fn hint_bit_pack(p: Profile, h: &PolyVec, y: &mut [u8]) {
    debug_assert_eq!(y.len(), p.omega + p.k);
    y.fill(0);
    let mut index = 0;
    for (i, h_i) in h.polys().iter().enumerate() {
        for (j, &h_ij) in h_i.iter().enumerate() {
            if h_ij != 0 {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[p.omega + i] = index as u8;
    }
}

/// HintBitUnpack (Algorithm 21); `None` is ⊥ (malformed input).
fn hint_bit_unpack(p: Profile, y: &[u8]) -> Option<PolyVec> {
    debug_assert_eq!(y.len(), p.omega + p.k);
    let mut h = PolyVec::zero(p.k);
    let mut index = 0;
    for (i, h_i) in h.polys_mut().iter_mut().enumerate() {
        let end = usize::from(y[p.omega + i]);
        if end < index || end > p.omega {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return None;
            }
            h_i[usize::from(y[index])] = 1;
            index += 1;
        }
    }
    if y[index..p.omega].iter().any(|&leftover| leftover != 0) {
        return None;
    }
    Some(h)
}

// ===========================================================================
// Encodings of keys and signatures (FIPS 204 §7.2)
// ===========================================================================

/// pkEncode (Algorithm 22).
fn pk_encode(p: Profile, rho: &[u8; SEED_BYTES], t1: &PolyVec) -> Vec<u8> {
    let mut pk = vec![0u8; p.public_key_len()];
    let (rho_bytes, packed) = pk.split_at_mut(SEED_BYTES);
    rho_bytes.copy_from_slice(rho);
    for (z_i, t1_i) in packed.chunks_exact_mut(T1_PACKED_BYTES).zip(t1.polys()) {
        simple_bit_pack(t1_i, T1_MAX, z_i);
    }
    pk
}

/// pkDecode (Algorithm 23) of a key of exactly `p.public_key_len()` bytes.
fn pk_decode(p: Profile, pk: &[u8]) -> ([u8; SEED_BYTES], PolyVec) {
    debug_assert_eq!(pk.len(), p.public_key_len());
    let (rho_bytes, packed) = pk.split_at(SEED_BYTES);
    let mut rho = [0u8; SEED_BYTES];
    rho.copy_from_slice(rho_bytes);
    let mut t1 = PolyVec::zero(p.k);
    for (t1_i, z_i) in t1
        .polys_mut()
        .iter_mut()
        .zip(packed.chunks_exact(T1_PACKED_BYTES))
    {
        simple_bit_unpack(z_i, T1_MAX, t1_i);
    }
    (rho, t1)
}

/// skEncode (Algorithm 24).
fn sk_encode(
    p: Profile,
    rho: &[u8; SEED_BYTES],
    key: &[u8; SEED_BYTES],
    tr: &[u8; TR_BYTES],
    s1: &PolyVec,
    s2: &PolyVec,
    t0: &PolyVec,
) -> Vec<u8> {
    let mut sk = vec![0u8; p.private_key_len()];
    let (seeds, packed) = sk.split_at_mut(2 * SEED_BYTES + TR_BYTES);
    seeds[..SEED_BYTES].copy_from_slice(rho);
    seeds[SEED_BYTES..2 * SEED_BYTES].copy_from_slice(key);
    seeds[2 * SEED_BYTES..].copy_from_slice(tr);
    let (s_bytes, t0_bytes) = packed.split_at_mut((p.l + p.k) * p.s_packed_bytes);
    let eta = p.eta as u32;
    let s_polys = s1.polys().iter().chain(s2.polys());
    for (chunk, s_i) in s_bytes.chunks_exact_mut(p.s_packed_bytes).zip(s_polys) {
        bit_pack(s_i, eta, eta, chunk);
    }
    for (chunk, t0_i) in t0_bytes.chunks_exact_mut(T0_PACKED_BYTES).zip(t0.polys()) {
        bit_pack(t0_i, T0_A, T0_B, chunk);
    }
    sk
}

/// skDecode (Algorithm 25) of a key of exactly `p.private_key_len()` bytes:
/// returns ρ and writes K, tr, s1, s2 and t0 into the caller's storage, so the
/// secrets are never moved. As the standard notes, s1 and s2 fall outside
/// [−η, η] when the input is malformed; `MlDsaPrivateKey::expanded` refuses
/// such keys.
fn sk_decode(
    p: Profile,
    sk: &[u8],
    key: &mut [u8; SEED_BYTES],
    tr: &mut [u8; TR_BYTES],
    s1: &mut PolyVec,
    s2: &mut PolyVec,
    t0: &mut PolyVec,
) -> [u8; SEED_BYTES] {
    debug_assert_eq!(sk.len(), p.private_key_len());
    let (seeds, packed) = sk.split_at(2 * SEED_BYTES + TR_BYTES);
    let mut rho = [0u8; SEED_BYTES];
    rho.copy_from_slice(&seeds[..SEED_BYTES]);
    key.copy_from_slice(&seeds[SEED_BYTES..2 * SEED_BYTES]);
    tr.copy_from_slice(&seeds[2 * SEED_BYTES..]);
    let (s_bytes, t0_bytes) = packed.split_at((p.l + p.k) * p.s_packed_bytes);
    let (s1_bytes, s2_bytes) = s_bytes.split_at(p.l * p.s_packed_bytes);
    let eta = p.eta as u32;
    debug_assert_eq!((s1.len(), s2.len(), t0.len()), (p.l, p.k, p.k));
    for (s1_i, y_i) in s1
        .polys_mut()
        .iter_mut()
        .zip(s1_bytes.chunks_exact(p.s_packed_bytes))
    {
        bit_unpack(y_i, eta, eta, s1_i);
    }
    for (s2_i, z_i) in s2
        .polys_mut()
        .iter_mut()
        .zip(s2_bytes.chunks_exact(p.s_packed_bytes))
    {
        bit_unpack(z_i, eta, eta, s2_i);
    }
    for (t0_i, w_i) in t0
        .polys_mut()
        .iter_mut()
        .zip(t0_bytes.chunks_exact(T0_PACKED_BYTES))
    {
        bit_unpack(w_i, T0_A, T0_B, t0_i);
    }
    rho
}

/// sigEncode (Algorithm 26). `sig.z` must already be z mod± q.
fn sig_encode(p: Profile, sig: &DecodedSignature) -> Vec<u8> {
    let mut sigma = vec![0u8; p.signature_len()];
    let (c_bytes, rest) = sigma.split_at_mut(p.ctilde_bytes);
    c_bytes.copy_from_slice(&sig.c);
    let (z_bytes, h_bytes) = rest.split_at_mut(p.l * p.polyz_packed_bytes);
    let gamma1 = p.gamma1 as u32;
    for (chunk, z_i) in z_bytes
        .chunks_exact_mut(p.polyz_packed_bytes)
        .zip(sig.z.polys())
    {
        bit_pack(z_i, gamma1 - 1, gamma1, chunk);
    }
    hint_bit_pack(p, &sig.h, h_bytes);
    sigma
}

/// sigDecode (Algorithm 27) of a signature of exactly `p.signature_len()`
/// bytes; `None` is the ⊥ that HintBitUnpack reports.
fn sig_decode(p: Profile, sigma: &[u8]) -> Option<DecodedSignature> {
    debug_assert_eq!(sigma.len(), p.signature_len());
    let (c_tilde, rest) = sigma.split_at(p.ctilde_bytes);
    let (x, y) = rest.split_at(p.l * p.polyz_packed_bytes);
    let gamma1 = p.gamma1 as u32;
    let mut z = PolyVec::zero(p.l);
    for (z_i, x_i) in z
        .polys_mut()
        .iter_mut()
        .zip(x.chunks_exact(p.polyz_packed_bytes))
    {
        bit_unpack(x_i, gamma1 - 1, gamma1, z_i);
    }
    let h = hint_bit_unpack(p, y)?;
    Some(DecodedSignature {
        c: c_tilde.to_vec(),
        z,
        h,
    })
}

/// w1Encode (Algorithm 28) into `w1_tilde`, of `p.w1_encoded_len()` bytes.
fn w1_encode(p: Profile, w1: &PolyVec, w1_tilde: &mut [u8]) {
    debug_assert_eq!(w1_tilde.len(), p.w1_encoded_len());
    let b = (p.high_bits_modulus - 1) as u32;
    for (chunk, w1_i) in w1_tilde.chunks_exact_mut(p.w1_packed_bytes).zip(w1.polys()) {
        simple_bit_pack(w1_i, b, chunk);
    }
}

// ===========================================================================
// Pseudorandom sampling (FIPS 204 §3.7, §7.3)
// ===========================================================================

/// H(str, ℓ) = SHAKE256(str, 8ℓ) (§3.7) on the concatenation of `parts`,
/// with ℓ = `out.len()`.
fn hash_h(parts: &[&[u8]], out: &mut [u8]) {
    let mut ctx = Shake256::new();
    for part in parts {
        ctx.update(part);
    }
    ctx.squeeze(out);
}

/// The output of one XOF, read a byte at a time.
///
/// §3.7 guarantees that any sequence of Squeeze calls yields the bytes of one
/// long squeeze, so the stream refills a whole sponge block whenever the
/// previous block is used up; how often that happens depends only on how many
/// bytes the sampler has consumed. The buffered block is wiped on drop.
struct XofBytes<X: Xof, const BLOCK: usize> {
    xof: X,
    block: [u8; BLOCK],
    next: usize,
}

impl<X: Xof, const BLOCK: usize> XofBytes<X, BLOCK> {
    /// Begins squeezing an XOF that has absorbed its whole input.
    fn new(xof: X) -> Self {
        Self {
            xof,
            block: [0; BLOCK],
            next: BLOCK,
        }
    }

    #[inline(always)]
    fn next_byte(&mut self) -> u8 {
        if self.next == BLOCK {
            self.xof.squeeze(&mut self.block);
            self.next = 0;
        }
        let byte = self.block[self.next];
        self.next += 1;
        byte
    }
}

impl<X: Xof, const BLOCK: usize> Drop for XofBytes<X, BLOCK> {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(&mut self.block);
    }
}

/// H.Init then H.Absorb(ctx, ρ), ready for H.Squeeze (Algorithms 29 and 31).
fn h_stream(rho: &[u8]) -> XofBytes<Shake256, { Shake256::BLOCK_LEN }> {
    let mut ctx = Shake256::new();
    ctx.update(rho);
    XofBytes::new(ctx)
}

/// G.Init then G.Absorb(ctx, ρ), ready for G.Squeeze (Algorithm 30).
fn g_stream(rho: &[u8]) -> XofBytes<Shake128, { Shake128::BLOCK_LEN }> {
    let mut ctx = Shake128::new();
    ctx.update(rho);
    XofBytes::new(ctx)
}

/// SampleInBall (Algorithm 29): c ∈ B_τ from the seed ρ = c̃.
///
/// While signing, c̃ is derived from the secret w, and the challenge of a
/// rejected iteration must stay hidden. Lines 11-12 therefore never index
/// memory by j: every position below i is visited and updated through a mask.
/// The loop of lines 8-10 does branch, but only to discard bytes above i,
/// which carries no information about the j finally accepted.
fn sample_in_ball(p: Profile, rho: &[u8], c: &mut Poly) {
    c.fill(0);
    let mut stream = h_stream(rho);
    // Lines 4-5: s is the first eight bytes; bit i of h = BytesToBits(s) is
    // bit i of s read as a little-endian integer.
    let mut s = [0u8; 8];
    for s_i in s.iter_mut() {
        *s_i = stream.next_byte();
    }
    let mut h = u64::from_le_bytes(s);
    for i in N - p.tau..N {
        let j = loop {
            let candidate = usize::from(stream.next_byte());
            if candidate <= i {
                break candidate;
            }
        };
        // (−1)^h(i + τ − 256) as ±1.
        let sign = 1 - 2 * ((h >> (i + p.tau - N)) & 1) as i32;
        // Line 11, c_i ← c_j, then line 12, c_j ← sign. Earlier steps wrote
        // only positions up to their own i, so c_i is still 0 here. The scan
        // hands the old c_j to `old_c_j` and stores the sign at j; both
        // position indices are below 256, so their XOR is zero exactly at j.
        let mut old_c_j = 0;
        for (position, c_position) in c[..i].iter_mut().enumerate() {
            let is_j = ((position ^ j) as i32 - 1) >> 31;
            old_c_j |= *c_position & is_j;
            *c_position = (*c_position & !is_j) | (sign & is_j);
        }
        // Position i takes the old c_j, or the sign itself when j = i.
        let i_is_j = ((i ^ j) as i32 - 1) >> 31;
        c[i] = (old_c_j & !i_is_j) | (sign & i_is_j);
    }
    crate::ct::zeroize_slice(&mut s);
    crate::ct::zeroize_slice(core::slice::from_mut(&mut h));
}

/// RejNTTPoly (Algorithm 30): â ∈ T_q from the public seed ρ′ ∈ B^34.
fn rej_ntt_poly(rho: &[u8; SEED_BYTES + 2], a_hat: &mut Poly) {
    let mut stream = g_stream(rho);
    let mut j = 0;
    while j < N {
        // Line 5: s ← G.Squeeze(ctx, 3), read in order.
        let (b0, b1, b2) = (stream.next_byte(), stream.next_byte(), stream.next_byte());
        if let Some(coefficient) = coeff_from_three_bytes(b0, b1, b2) {
            a_hat[j] = coefficient;
            j += 1;
        }
    }
}

/// RejBoundedPoly (Algorithm 31): a ∈ R with coefficients in [−η, η] from the
/// secret seed ρ ∈ B^66. See `coeff_from_half_byte` for why the acceptance
/// branches are safe.
fn rej_bounded_poly(p: Profile, rho: &[u8; CRH_BYTES + 2], a: &mut Poly) {
    let mut stream = h_stream(rho);
    let mut j = 0;
    while j < N {
        let z = stream.next_byte();
        let z0 = coeff_from_half_byte(p.eta, z & 0x0f);
        let z1 = coeff_from_half_byte(p.eta, z >> 4);
        if let Some(value) = z0 {
            a[j] = value;
            j += 1;
        }
        if let (Some(value), true) = (z1, j < N) {
            a[j] = value;
            j += 1;
        }
    }
}

/// ExpandA (Algorithm 32).
fn expand_a(p: Profile, rho: &[u8; SEED_BYTES]) -> MatrixNtt {
    let mut a_hat = MatrixNtt::zero(p);
    let mut rho_prime = [0u8; SEED_BYTES + 2];
    rho_prime[..SEED_BYTES].copy_from_slice(rho);
    for (r, row) in a_hat.rows_mut().enumerate() {
        for (s, entry) in row.iter_mut().enumerate() {
            // ρ′ ← ρ ‖ IntegerToBytes(s, 1) ‖ IntegerToBytes(r, 1)
            rho_prime[SEED_BYTES..SEED_BYTES + 1].copy_from_slice(&integer_to_bytes::<1>(s));
            rho_prime[SEED_BYTES + 1..].copy_from_slice(&integer_to_bytes::<1>(r));
            rej_ntt_poly(&rho_prime, entry);
        }
    }
    a_hat
}

/// ExpandS (Algorithm 33), into s1 ∈ R^ℓ and s2 ∈ R^k.
fn expand_s(p: Profile, rho: &[u8; CRH_BYTES], s1: &mut PolyVec, s2: &mut PolyVec) {
    debug_assert_eq!((s1.len(), s2.len()), (p.l, p.k));
    let mut seed = [0u8; CRH_BYTES + 2];
    seed[..CRH_BYTES].copy_from_slice(rho);
    for (r, s1_r) in s1.polys_mut().iter_mut().enumerate() {
        seed[CRH_BYTES..].copy_from_slice(&integer_to_bytes::<2>(r));
        rej_bounded_poly(p, &seed, s1_r);
    }
    for (r, s2_r) in s2.polys_mut().iter_mut().enumerate() {
        seed[CRH_BYTES..].copy_from_slice(&integer_to_bytes::<2>(r + p.l));
        rej_bounded_poly(p, &seed, s2_r);
    }
    crate::ct::zeroize_slice(&mut seed);
}

/// ExpandMask (Algorithm 34): y ∈ R^ℓ with coefficients in [−γ1 + 1, γ1].
/// The integer input that the standard names μ is the signing counter κ.
fn expand_mask(p: Profile, rho: &[u8; CRH_BYTES], mu: usize, y: &mut PolyVec) {
    let c = 1 + bitlen((p.gamma1 - 1) as u32);
    let v_len = 32 * c as usize;
    let gamma1 = p.gamma1 as u32;
    let mut rho_prime = [0u8; CRH_BYTES + 2];
    rho_prime[..CRH_BYTES].copy_from_slice(rho);
    let mut v = [0u8; MAX_Z_PACKED_BYTES];
    debug_assert_eq!(y.len(), p.l);
    for (r, y_r) in y.polys_mut().iter_mut().enumerate() {
        rho_prime[CRH_BYTES..].copy_from_slice(&integer_to_bytes::<2>(mu + r));
        hash_h(&[&rho_prime], &mut v[..v_len]);
        bit_unpack(&v[..v_len], gamma1 - 1, gamma1, y_r);
    }
    crate::ct::zeroize_slice(&mut rho_prime);
    crate::ct::zeroize_slice(&mut v);
}

// ===========================================================================
// High-order and low-order bits and hints (FIPS 204 §7.4)
// ===========================================================================

/// Power2Round (Algorithm 35) for r ∈ [0, q), without branches (t0 is secret).
///
/// r0 = r mod± 2^d is the low d bits of r, less 2^d when they exceed
/// 2^(d−1), which places r0 in (−2^(d−1), 2^(d−1)]; the sign of
/// 2^(d−1) − low makes that choice as a mask. r − r0 is then a nonnegative
/// multiple of 2^d, and the shift divides it exactly.
#[inline(always)]
const fn power2_round(r: i32) -> (i32, i32) {
    let low = r & ((1 << D) - 1);
    let r0 = low - ((1 << D) & (((1 << (D - 1)) - low) >> 31));
    ((r - r0) >> D, r0)
}

/// Decompose (Algorithm 36) for r ∈ [0, q), with no branch, `/` or `%`
/// (it runs on the secret w while signing).
///
/// Let α = 2γ2. Line 2's r0 = r mod± α lies in (−γ2, γ2], so r1′ = (r − r0)/α
/// is the only integer in [(r − γ2)/α, (r + γ2 − 1)/α], an interval shorter
/// than 1. That integer is ⌊(r + γ2 − 1)/α⌋: the floor is at least
/// (r + γ2 − 1 − (α − 1))/α = (r − γ2)/α. The dividend is at most
/// U = q + γ2 − 2, and the profile's `FloorDivision` for (α, U) takes the
/// floor exactly: M = 2886403, s = 39 for γ2 = (q − 1)/88, and M = 16793617,
/// s = 43 for γ2 = (q − 1)/32.
///
/// Line 3's test r+ − r0 = q − 1 reads r1′·α = q − 1, that is r1′ = m with
/// m = (q − 1)/α. As 0 ≤ r1′ ≤ m ≤ 44 < 64, r1′ XOR m lies in [0, 63] and is
/// zero exactly then, so subtracting one and shifting out the sign gives an
/// all-ones mask exactly then. The mask clears r1 (line 4) and subtracts one
/// from r0 (line 5).
#[inline(always)]
fn decompose(p: Profile, r: i32) -> (i32, i32) {
    let r1 = p.decompose_division.quotient((r + p.gamma2 - 1) as u64) as i32;
    let r0 = r - r1 * (2 * p.gamma2);
    let wraps = ((r1 ^ p.high_bits_modulus) - 1) >> 31;
    (r1 & !wraps, r0 + wraps)
}

/// HighBits (Algorithm 37).
#[inline(always)]
fn high_bits(p: Profile, r: i32) -> i32 {
    decompose(p, r).0
}

/// LowBits (Algorithm 38).
#[inline(always)]
fn low_bits(p: Profile, r: i32) -> i32 {
    decompose(p, r).1
}

/// MakeHint (Algorithm 39) for z, r ∈ [0, q): 1 if HighBits(r) differs from
/// HighBits(r + z), else 0, without a branch. Both high parts lie in [0, 43],
/// so their XOR is in [0, 63] and is zero exactly when they agree.
#[inline(always)]
fn make_hint(p: Profile, z: i32, r: i32) -> i32 {
    let r1 = high_bits(p, r);
    let v1 = high_bits(p, add_mod_q(r, z));
    (((r1 ^ v1) - 1) >> 31) + 1
}

/// UseHint (Algorithm 40) for h ∈ {0, 1} and r ∈ [0, q). Verification is its
/// only caller and holds only public values, so it branches as written.
fn use_hint(p: Profile, h: i32, r: i32) -> i32 {
    let m = p.high_bits_modulus;
    let (r1, r0) = decompose(p, r);
    if h == 1 && r0 > 0 {
        return (r1 + 1).rem_euclid(m);
    }
    if h == 1 && r0 <= 0 {
        return (r1 - 1).rem_euclid(m);
    }
    r1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key::io::der_octet_string;
    use crate::public_key::pkix::NULL_PARAMETERS;
    use crate::test_utils::{decode_hex, openssl3, parse_vector_map, ScratchFile};
    use std::collections::HashMap;

    const ALL_PARAMS: [MlDsaParameterSet; 3] = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];

    #[test]
    fn parameter_lengths_match_known_profiles() {
        // The public `*_len` literals and the `Profile` arithmetic are two
        // statements of the same FIPS 204 Table 2 sizes; they must agree.
        for params in ALL_PARAMS {
            let p = params.profile();
            assert_eq!(params.public_key_len(), p.public_key_len(), "{params:?}");
            assert_eq!(params.private_key_len(), p.private_key_len(), "{params:?}");
            assert_eq!(params.signature_len(), p.signature_len(), "{params:?}");
        }

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
            let (_, generated) = MlDsa::keygen_from_seed(params, &[0x22; 32]);
            let sk_bytes = generated.to_wire_bytes();
            let sig_bytes = vec![0x00u8; params.signature_len()];

            let pk = MlDsaPublicKey::from_wire_bytes(params, &pk_bytes).expect("pk");
            let sk = MlDsaPrivateKey::from_wire_bytes(params, &sk_bytes).expect("sk");
            assert_eq!(
                MlDsaPublicKey::from_key_blob(&pk.to_key_blob()).as_ref(),
                Some(&pk)
            );
            assert_eq!(MlDsaPrivateKey::from_key_blob(&sk.to_key_blob()), Some(sk));

            // An all-zero signature is well formed: its hint section is the
            // canonical encoding of no hints, so it parses. Its z decodes to
            // γ1 in every coefficient (BitUnpack gives b − 0 = γ1), which
            // fails Algorithm 8's norm test, so it verifies under no key.
            let zero_sig = MlDsaSignature::from_wire_bytes(params, &sig_bytes).expect("parses");
            let gamma1 = params.profile().gamma1;
            assert!(zero_sig
                .decoded
                .z
                .polys()
                .as_flattened()
                .iter()
                .all(|&z_j| z_j == gamma1));
            assert!(!MlDsa::verify(&pk, b"", &zero_sig), "{params:?}");
            assert_eq!(
                MlDsaSignature::from_key_blob(&zero_sig.to_key_blob()),
                Some(zero_sig)
            );
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
            let (pk, sk) = MlDsa::keygen_from_seed(params, &seed);
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
        let (pk, sk) = MlDsa::keygen_from_seed(MlDsaParameterSet::MlDsa44, &seed);
        let mut sig = MlDsa::sign_with_randomness(&sk, b"tamper", &[0u8; 32])
            .expect("sign")
            .to_wire_bytes();
        sig[10] ^= 0x01;
        let sig =
            MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa44, &sig).expect("signature");
        assert!(!MlDsa::verify(&pk, b"tamper", &sig));
    }

    // ---- NIST ACVP known answers (all parameter sets) ----
    //
    // tests/vectors/ml_dsa_fips204_subset.txt holds cases from the ACVP
    // server's ML-DSA keyGen, sigGen and sigVer FIPS204 files; its header
    // names the repository commit, retrieval date and each case's tgId/tcId.

    const ACVP_SETS: [(MlDsaParameterSet, &str); 3] = [
        (MlDsaParameterSet::MlDsa44, "44"),
        (MlDsaParameterSet::MlDsa65, "65"),
        (MlDsaParameterSet::MlDsa87, "87"),
    ];

    fn acvp_vectors() -> HashMap<&'static str, &'static str> {
        parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_dsa_fips204_subset.txt"
        )))
    }

    /// The case numbers present under `prefix` (say `KEYGEN_44`), at least two.
    fn acvp_cases(vectors: &HashMap<&str, &str>, prefix: &str) -> Vec<usize> {
        let cases: Vec<usize> = (1..)
            .take_while(|i| vectors.contains_key(format!("{prefix}_{i}_TCID").as_str()))
            .collect();
        assert!(cases.len() >= 2, "{prefix}: too few cases in the file");
        cases
    }

    fn acvp(vectors: &HashMap<&str, &str>, prefix: &str, case: usize, name: &str) -> Vec<u8> {
        let key = format!("{prefix}_{case}_{name}");
        decode_hex(vectors[key.as_str()])
    }

    #[test]
    fn acvp_keygen_vectors_match_for_every_parameter_set() {
        let vectors = acvp_vectors();
        for (params, set) in ACVP_SETS {
            let prefix = format!("KEYGEN_{set}");
            for case in acvp_cases(&vectors, &prefix) {
                let xi: [u8; SEED_BYTES] = acvp(&vectors, &prefix, case, "SEED")
                    .try_into()
                    .expect("32-byte seed");
                let (pk, sk) = MlDsa::keygen_from_seed(params, &xi);
                // Both keys byte for byte: the private key pins ρ, K, tr and
                // the packed s1, s2 and t0, not only the public t1.
                assert_eq!(
                    pk.to_wire_bytes(),
                    acvp(&vectors, &prefix, case, "PK"),
                    "{prefix} case {case} pk"
                );
                assert_eq!(
                    sk.to_wire_bytes(),
                    acvp(&vectors, &prefix, case, "SK"),
                    "{prefix} case {case} sk"
                );
            }
        }
    }

    #[test]
    fn acvp_siggen_vectors_match_for_every_parameter_set_and_both_variants() {
        let vectors = acvp_vectors();
        for (params, set) in ACVP_SETS {
            for (variant, deterministic) in [("DET", true), ("HEDGED", false)] {
                let prefix = format!("SIGGEN_{variant}_{set}");
                for case in acvp_cases(&vectors, &prefix) {
                    let sk = MlDsaPrivateKey::from_wire_bytes(
                        params,
                        &acvp(&vectors, &prefix, case, "SK"),
                    )
                    .expect("NIST's private key passes the import checks");
                    let pk = MlDsaPublicKey::from_wire_bytes(
                        params,
                        &acvp(&vectors, &prefix, case, "PK"),
                    )
                    .expect("pk");
                    let msg = acvp(&vectors, &prefix, case, "MSG");
                    let ctx = acvp(&vectors, &prefix, case, "CTX");
                    let expected = acvp(&vectors, &prefix, case, "SIG");
                    let rnd: [u8; RND_BYTES] = if deterministic {
                        [0; RND_BYTES]
                    } else {
                        acvp(&vectors, &prefix, case, "RND")
                            .try_into()
                            .expect("32-byte rnd")
                    };
                    let sig = MlDsa::sign_with_randomness_and_context(&sk, &msg, &rnd, &ctx)
                        .expect("sign");
                    assert_eq!(sig.to_wire_bytes(), expected, "{prefix} case {case}");
                    assert_eq!(
                        MlDsa::verify_with_context(&pk, &msg, &sig, &ctx),
                        Some(true),
                        "{prefix} case {case}"
                    );
                    // The imported private key implies NIST's public key.
                    assert_eq!(sk.regenerate_public_key().as_ref(), Some(&pk));
                }
            }
        }
    }

    #[test]
    fn acvp_sigver_vectors_get_nists_verdict_for_every_parameter_set() {
        let vectors = acvp_vectors();
        for (params, set) in ACVP_SETS {
            let prefix = format!("SIGVER_{set}");
            let (mut accepted, mut refused) = (0, 0);
            for case in acvp_cases(&vectors, &prefix) {
                let pk =
                    MlDsaPublicKey::from_wire_bytes(params, &acvp(&vectors, &prefix, case, "PK"))
                        .expect("pk");
                let msg = acvp(&vectors, &prefix, case, "MSG");
                let ctx = acvp(&vectors, &prefix, case, "CTX");
                let sigma = acvp(&vectors, &prefix, case, "SIG");
                let passed = match vectors[format!("{prefix}_{case}_PASSED").as_str()] {
                    "true" => true,
                    "false" => false,
                    other => panic!("{prefix} case {case}: PASSED={other:?}"),
                };
                let reason = vectors[format!("{prefix}_{case}_REASON").as_str()];
                // A modified hint may already be sigDecode's ⊥ (Algorithm 8,
                // lines 2-4), which the parser reports; that is a refusal too.
                let verdict = MlDsaSignature::from_wire_bytes(params, &sigma).is_some_and(|sig| {
                    MlDsa::verify_with_context(&pk, &msg, &sig, &ctx) == Some(true)
                });
                assert_eq!(verdict, passed, "{prefix} case {case}: {reason}");
                if passed {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
            assert!(
                accepted >= 1 && refused >= 1,
                "{prefix}: both verdicts are exercised"
            );
        }
    }

    // ---- Reference-implementation known answers (all parameter sets) ----
    //
    // tests/vectors/ml_dsa_ref_kat.txt is produced by running the
    // pq-crystals/dilithium reference as an oracle (scripts/gen_pq_ref_vectors.sh).

    const REF_KAT_SETS: [(MlDsaParameterSet, &str); 3] = [
        (MlDsaParameterSet::MlDsa44, "MLDSA44"),
        (MlDsaParameterSet::MlDsa65, "MLDSA65"),
        (MlDsaParameterSet::MlDsa87, "MLDSA87"),
    ];
    const REF_KAT_MESSAGES: usize = 3;

    fn ref_kat_vectors() -> HashMap<&'static str, &'static str> {
        parse_vector_map(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/ml_dsa_ref_kat.txt"
        )))
    }

    fn ref_kat(vectors: &HashMap<&str, &str>, prefix: &str, name: &str) -> Vec<u8> {
        let key = format!("{prefix}_{name}");
        decode_hex(vectors[key.as_str()])
    }

    #[test]
    fn keygen_matches_reference_kat_for_every_parameter_set() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let xi: [u8; SEED_BYTES] = ref_kat(&vectors, prefix, "XI")
                .try_into()
                .expect("32-byte xi");
            let (pk, sk) = MlDsa::keygen_from_seed(params, &xi);
            // Both halves byte-for-byte: this pins the secret-key wire layout
            // (rho || K || tr || s1 || s2 || t0), not just its length.
            assert_eq!(
                pk.to_wire_bytes(),
                ref_kat(&vectors, prefix, "PK"),
                "{params:?} pk"
            );
            assert_eq!(
                sk.to_wire_bytes(),
                ref_kat(&vectors, prefix, "SK"),
                "{params:?} sk"
            );
        }
    }

    #[test]
    fn deterministic_signing_matches_reference_kat_for_every_parameter_set() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            // Import both keys from the reference's bytes so the unpack path
            // is exercised, not only the keys this crate just generated.
            let pk = MlDsaPublicKey::from_wire_bytes(params, &ref_kat(&vectors, prefix, "PK"))
                .expect("pk");
            let sk = MlDsaPrivateKey::from_wire_bytes(params, &ref_kat(&vectors, prefix, "SK"))
                .expect("sk");
            for i in 0..REF_KAT_MESSAGES {
                let msg = ref_kat(&vectors, prefix, &format!("MSG{i}"));
                let expected = ref_kat(&vectors, prefix, &format!("SIG{i}"));

                let sig = MlDsa::sign_with_randomness(&sk, &msg, &[0u8; RND_BYTES]).expect("sign");
                assert_eq!(sig.to_wire_bytes(), expected, "{params:?} message {i}");
                assert_eq!(
                    MlDsa::sign_deterministic(&sk, &msg).expect("sign"),
                    sig,
                    "{params:?} sign_deterministic is rnd = 0^32"
                );

                let parsed = MlDsaSignature::from_wire_bytes(params, &expected).expect("parse");
                assert_eq!(parsed, sig);
                assert!(MlDsa::verify(&pk, &msg, &parsed), "{params:?} message {i}");
                assert_eq!(
                    MlDsa::verify_with_context(&pk, &msg, &parsed, b""),
                    Some(true)
                );
                assert_eq!(
                    MlDsa::verify_with_context(&pk, &msg, &parsed, b"x"),
                    Some(false)
                );
                assert!(!MlDsa::verify(&pk, b"not the message", &parsed));
            }
        }
    }

    #[test]
    fn verify_refuses_reference_signature_with_one_flipped_bit_at_every_offset() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let p = params.profile();
            let pk = MlDsaPublicKey::from_wire_bytes(params, &ref_kat(&vectors, prefix, "PK"))
                .expect("pk");
            let hint_pos = p.ctilde_bytes + p.l * p.polyz_packed_bytes;
            for i in 0..REF_KAT_MESSAGES {
                let msg = ref_kat(&vectors, prefix, &format!("MSG{i}"));
                let good = ref_kat(&vectors, prefix, &format!("SIG{i}"));
                assert_eq!(good.len(), hint_pos + p.omega + p.k);
                // The edges of every component of σ = c̃ ‖ z ‖ h, the
                // boundaries inside z and h, and a stride across the whole.
                let mut offsets = vec![
                    0,
                    p.ctilde_bytes - 1,
                    p.ctilde_bytes,
                    p.ctilde_bytes + p.polyz_packed_bytes - 1,
                    p.ctilde_bytes + p.polyz_packed_bytes,
                    hint_pos - 1,
                    hint_pos,
                    hint_pos + 1,
                    hint_pos + p.omega - 1,
                    hint_pos + p.omega,
                    good.len() - 1,
                ];
                offsets.extend((0..good.len()).step_by(251));
                for offset in offsets {
                    for bit in [0x01u8, 0x80] {
                        let mut bad = good.clone();
                        bad[offset] ^= bit;
                        // A flip that breaks the hint encoding is refused by
                        // the parser (Algorithm 8, lines 2-4); every other one
                        // must be refused by verification.
                        let refused = match MlDsaSignature::from_wire_bytes(params, &bad) {
                            None => true,
                            Some(sig) => !MlDsa::verify(&pk, &msg, &sig),
                        };
                        assert!(
                            refused,
                            "{params:?} message {i} byte {offset} bit {bit:#04x}"
                        );
                    }
                }
            }
        }
    }

    /// Build a signature from a valid one with the hint section replaced by
    /// `indices` for the first polynomial and every cumulative count set to
    /// `indices.len()` (so all other polynomials carry no hints).
    fn with_hint_section(params: MlDsaParameterSet, valid: &[u8], indices: &[u8]) -> Vec<u8> {
        let p = params.profile();
        let hint_pos = p.ctilde_bytes + p.l * p.polyz_packed_bytes;
        let mut sig = valid.to_vec();
        for b in &mut sig[hint_pos..] {
            *b = 0;
        }
        sig[hint_pos..hint_pos + indices.len()].copy_from_slice(indices);
        for i in 0..p.k {
            sig[hint_pos + p.omega + i] = indices.len() as u8;
        }
        sig
    }

    #[test]
    fn non_canonical_hint_encodings_are_rejected_at_parse() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let p = params.profile();
            let pk = MlDsaPublicKey::from_wire_bytes(params, &ref_kat(&vectors, prefix, "PK"))
                .expect("pk");
            let msg = ref_kat(&vectors, prefix, "MSG0");
            let valid = ref_kat(&vectors, prefix, "SIG0");
            let hint_pos = p.ctilde_bytes + p.l * p.polyz_packed_bytes;
            let parses = |sigma: &[u8]| MlDsaSignature::from_wire_bytes(params, sigma).is_some();

            // The same hint set, canonically encoded, parses (and then simply
            // fails verification because it is not the signer's hint).
            let canonical = with_hint_section(params, &valid, &[3, 7]);
            let sig =
                MlDsaSignature::from_wire_bytes(params, &canonical).expect("canonical parses");
            assert!(!MlDsa::verify(&pk, &msg, &sig), "{params:?}");

            // Unsorted indices: Algorithm 21 requires strictly increasing.
            assert!(
                !parses(&with_hint_section(params, &valid, &[7, 3])),
                "{params:?} unsorted"
            );
            // Duplicated index.
            assert!(
                !parses(&with_hint_section(params, &valid, &[5, 5])),
                "{params:?} duplicate"
            );

            // Cumulative counts must be non-decreasing and at most ω.
            let mut decreasing = canonical.clone();
            decreasing[hint_pos + p.omega + 1] = 1;
            assert!(!parses(&decreasing), "{params:?} decreasing count");
            let mut over = canonical.clone();
            over[hint_pos + p.omega + p.k - 1] = (p.omega + 1) as u8;
            assert!(!parses(&over), "{params:?} count above ω");

            // Unused index slots must be zero.
            let mut padded = canonical;
            padded[hint_pos + p.omega - 1] = 9;
            assert!(!parses(&padded), "{params:?} nonzero padding");
        }
    }

    #[test]
    fn context_longer_than_255_bytes_is_rejected() {
        let vectors = ref_kat_vectors();
        let params = MlDsaParameterSet::MlDsa44;
        let pk = MlDsaPublicKey::from_wire_bytes(params, &ref_kat(&vectors, "MLDSA44", "PK"))
            .expect("pk");
        let sk = MlDsaPrivateKey::from_wire_bytes(params, &ref_kat(&vectors, "MLDSA44", "SK"))
            .expect("sk");
        let msg = b"context length boundary";
        let rnd = [0u8; RND_BYTES];

        let longest = [0x5Au8; MAX_CONTEXT_BYTES];
        let sig = MlDsa::sign_with_randomness_and_context(&sk, msg, &rnd, &longest)
            .expect("255-byte context is allowed");
        assert_eq!(
            MlDsa::verify_with_context(&pk, msg, &sig, &longest),
            Some(true)
        );
        assert_eq!(
            MlDsa::verify_with_context(&pk, msg, &sig, &longest[..254]),
            Some(false)
        );

        // One byte longer is Algorithm 2's and Algorithm 3's ⊥, distinct from
        // a signature that was checked and found invalid.
        let too_long = [0x5Au8; MAX_CONTEXT_BYTES + 1];
        assert!(MlDsa::sign_with_randomness_and_context(&sk, msg, &rnd, &too_long).is_none());
        assert_eq!(MlDsa::verify_with_context(&pk, msg, &sig, &too_long), None);
        assert_eq!(
            MlDsa::verify_with_context(&pk, msg, &sig, &[0u8; 1000]),
            None
        );
    }

    #[test]
    fn verify_refuses_a_signature_of_another_parameter_set() {
        let vectors = ref_kat_vectors();
        for (key_params, key_prefix) in REF_KAT_SETS {
            let pk =
                MlDsaPublicKey::from_wire_bytes(key_params, &ref_kat(&vectors, key_prefix, "PK"))
                    .expect("pk");
            for (sig_params, sig_prefix) in REF_KAT_SETS {
                let msg = ref_kat(&vectors, sig_prefix, "MSG1");
                let sig = MlDsaSignature::from_wire_bytes(
                    sig_params,
                    &ref_kat(&vectors, sig_prefix, "SIG1"),
                )
                .expect("sig");
                // Only the signature made under this key's own parameter set
                // verifies; the others are refused before any arithmetic, as
                // a verdict, not as ⊥.
                let same = key_params == sig_params;
                assert_eq!(
                    MlDsa::verify(&pk, &msg, &sig),
                    same,
                    "{key_params:?} {sig_params:?}"
                );
                assert_eq!(
                    MlDsa::verify_with_context(&pk, &msg, &sig, b""),
                    Some(same),
                    "{key_params:?} {sig_params:?}"
                );
            }
        }
    }

    /// FIPS 204 Appendix B, zetas[0..255], transcribed from the published PDF.
    const FIPS_204_APPENDIX_B_ZETAS: [i32; N] = [
        0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485,
        2682288, 2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802,
        4855975, 7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319,
        2815639, 2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
        394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347,
        7562881, 4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317,
        2917338, 1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610,
        5258977, 8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
        1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034,
        1987814, 5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690,
        3482206, 4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756,
        2925816, 3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
        348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997,
        5720892, 6924527, 2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111,
        4423672, 6084020, 5095502, 4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822,
        4423473, 4620952, 6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
        4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099,
        1239911, 4541938, 3195676, 2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018,
        7025525, 613238, 7070156, 6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539,
        7561656, 6201452, 6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
        6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997,
        2647994, 3009748, 5767564, 4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229,
        1665318, 2028038, 1163598, 5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880,
        545376, 7609976, 3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
        6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710, 8077412, 3531229,
        4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
    ];

    // ---- FIPS 204 constants ----

    #[test]
    fn ml_dsa_zetas_match_fips204_appendix_b() {
        // Appendix B prints 0 in the slot Algorithms 41 and 42 never read;
        // the formula ζ^BitRev8(0) gives 1 there.
        assert_eq!(FIPS_204_APPENDIX_B_ZETAS[0], 0);
        assert_eq!(ZETAS[0], 1);
        assert_eq!(ZETAS[1..], FIPS_204_APPENDIX_B_ZETAS[1..]);
        // BitRev8(128) = 1, and ζ is a primitive 512th root of unity.
        assert_eq!(ZETAS[128], ZETA);
        assert_eq!(pow_mod_q(ZETA, 256), Q - 1);
        // Algorithm 42, line 21.
        assert_eq!(NTT_INVERSE_SCALE, 8_347_681);
        assert_eq!(mul_mod_q(NTT_INVERSE_SCALE, 256), 1);
    }

    #[test]
    fn ml_dsa_table_1_values_and_derived_sizes() {
        let expected = [
            // (profile, β, λ/4, 32·bitlen(2η), 32·(1 + bitlen(γ1 − 1)), 32·bitlen((q − 1)/(2γ2) − 1))
            (ML_DSA_44, 78, 32, 96, 576, 192),
            (ML_DSA_65, 196, 48, 128, 640, 128),
            (ML_DSA_87, 120, 64, 96, 640, 128),
        ];
        for (p, beta, ctilde, s, z, w1) in expected {
            assert_eq!(
                (
                    p.beta,
                    p.ctilde_bytes,
                    p.s_packed_bytes,
                    p.polyz_packed_bytes,
                    p.w1_packed_bytes
                ),
                (beta, ctilde, s, z, w1)
            );
        }
        assert_eq!((T1_BITS, T1_PACKED_BYTES, T0_PACKED_BYTES), (10, 320, 416));
        assert_eq!(ML_DSA_44.high_bits_modulus, 44);
        assert_eq!(ML_DSA_65.high_bits_modulus, 16);
        // The scratch bounds are the largest of the three sets' sizes exactly.
        assert_eq!(
            (
                ML_DSA_44.w1_encoded_len(),
                ML_DSA_65.w1_encoded_len(),
                ML_DSA_87.w1_encoded_len()
            ),
            (768, 768, 1024)
        );
        assert_eq!(MAX_W1_ENCODED_BYTES, ML_DSA_87.w1_encoded_len());
        assert_eq!(MAX_Z_PACKED_BYTES, ML_DSA_87.polyz_packed_bytes);
        assert_eq!(MAX_CTILDE_BYTES, ML_DSA_87.ctilde_bytes);
    }

    #[test]
    fn ml_dsa_bit_rev8_and_integer_to_bytes() {
        for m in 0..=u8::MAX {
            let bits: Vec<u8> = spec_integer_to_bits(u32::from(m), 8);
            let reversed: Vec<u8> = bits.iter().rev().copied().collect();
            assert_eq!(
                u32::from(bit_rev8(m)),
                spec_bits_to_integer(&reversed),
                "m = {m}"
            );
        }
        assert_eq!(integer_to_bytes::<2>(0x1234), [0x34, 0x12]);
        assert_eq!(integer_to_bytes::<1>(300), [44]);
        assert_eq!(integer_to_bytes::<2>(65_537), [1, 0]);
    }

    // ---- Test oracles: FIPS 204 algorithms transcribed as written ----

    /// Deterministic test data: SHAKE256 of a label.
    fn test_bytes(label: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        hash_h(&[label], &mut out);
        out
    }

    fn test_poly(label: &[u8]) -> Poly {
        let bytes = test_bytes(label, 4 * N);
        let mut poly = [0; N];
        for (coefficient, chunk) in poly.iter_mut().zip(bytes.chunks_exact(4)) {
            let value = u32::from_le_bytes(chunk.try_into().expect("four bytes"));
            *coefficient = (value % Q as u32) as i32;
        }
        poly
    }

    /// Algorithm 9.
    fn spec_integer_to_bits(x: u32, alpha: u32) -> Vec<u8> {
        let mut x_prime = x;
        let mut y = Vec::new();
        for _ in 0..alpha {
            y.push((x_prime % 2) as u8);
            x_prime /= 2;
        }
        y
    }

    /// Algorithm 10.
    fn spec_bits_to_integer(y: &[u8]) -> u32 {
        let alpha = y.len();
        let mut x = 0u32;
        for i in 1..=alpha {
            x = x.wrapping_mul(2).wrapping_add(u32::from(y[alpha - i]));
        }
        x
    }

    /// Algorithm 12.
    fn spec_bits_to_bytes(y: &[u8]) -> Vec<u8> {
        let mut z = vec![0u8; y.len().div_ceil(8)];
        for (i, &bit) in y.iter().enumerate() {
            z[i / 8] += bit << (i % 8);
        }
        z
    }

    /// Algorithm 13.
    fn spec_bytes_to_bits(z: &[u8]) -> Vec<u8> {
        let mut y = vec![0u8; 8 * z.len()];
        for (i, &byte) in z.iter().enumerate() {
            let mut z_prime = byte;
            for j in 0..8 {
                y[8 * i + j] = z_prime % 2;
                z_prime /= 2;
            }
        }
        y
    }

    /// m mod± α (§2.3): the representative in (−⌈α/2⌉, ⌊α/2⌋].
    fn spec_mod_pm(m: i64, alpha: i64) -> i64 {
        let r = m.rem_euclid(alpha);
        if r > alpha / 2 {
            r - alpha
        } else {
            r
        }
    }

    /// Algorithm 35.
    fn spec_power2_round(r: i32) -> (i32, i32) {
        let r_plus = i64::from(r).rem_euclid(i64::from(Q));
        let r0 = spec_mod_pm(r_plus, 1 << D);
        (((r_plus - r0) / (1 << D)) as i32, r0 as i32)
    }

    /// Algorithm 36.
    fn spec_decompose(gamma2: i32, r: i32) -> (i32, i32) {
        let q = i64::from(Q);
        let alpha = 2 * i64::from(gamma2);
        let r_plus = i64::from(r).rem_euclid(q);
        let mut r0 = spec_mod_pm(r_plus, alpha);
        let r1;
        if r_plus - r0 == q - 1 {
            r1 = 0;
            r0 -= 1;
        } else {
            r1 = (r_plus - r0) / alpha;
        }
        (r1 as i32, r0 as i32)
    }

    /// Algorithm 15.
    fn spec_coeff_from_half_byte(eta: i32, b: u8) -> Option<i32> {
        let b = i32::from(b);
        if eta == 2 && b < 15 {
            Some(2 - (b % 5))
        } else if eta == 4 && b < 9 {
            Some(4 - b)
        } else {
            None
        }
    }

    /// Algorithm 29, one byte per H.Squeeze.
    fn spec_sample_in_ball(tau: usize, rho: &[u8]) -> Poly {
        let mut c = [0i32; N];
        let mut ctx = Shake256::new();
        ctx.update(rho);
        let mut s = [0u8; 8];
        ctx.squeeze(&mut s);
        let h = spec_bytes_to_bits(&s);
        for i in N - tau..N {
            let mut j = [0u8; 1];
            ctx.squeeze(&mut j);
            while usize::from(j[0]) > i {
                ctx.squeeze(&mut j);
            }
            let j = usize::from(j[0]);
            c[i] = c[j];
            c[j] = if h[i + tau - N] == 1 { -1 } else { 1 };
        }
        c
    }

    /// Algorithm 30, three bytes per G.Squeeze.
    fn spec_rej_ntt_poly(rho: &[u8]) -> Poly {
        let mut a_hat = [0i32; N];
        let mut ctx = Shake128::new();
        ctx.update(rho);
        let mut j = 0;
        while j < N {
            let mut s = [0u8; 3];
            ctx.squeeze(&mut s);
            let b2_prime = if s[2] > 127 { s[2] - 128 } else { s[2] };
            let z = 65_536 * i32::from(b2_prime) + 256 * i32::from(s[1]) + i32::from(s[0]);
            if z < Q {
                a_hat[j] = z;
                j += 1;
            }
        }
        a_hat
    }

    /// Algorithm 31, one byte per H.Squeeze.
    fn spec_rej_bounded_poly(eta: i32, rho: &[u8]) -> Poly {
        let mut a = [0i32; N];
        let mut ctx = Shake256::new();
        ctx.update(rho);
        let mut j = 0;
        while j < N {
            let mut z = [0u8; 1];
            ctx.squeeze(&mut z);
            let z0 = spec_coeff_from_half_byte(eta, z[0] % 16);
            let z1 = spec_coeff_from_half_byte(eta, z[0] / 16);
            if let Some(value) = z0 {
                a[j] = value;
                j += 1;
            }
            if let (Some(value), true) = (z1, j < N) {
                a[j] = value;
                j += 1;
            }
        }
        a
    }

    /// AddNTT (Algorithm 44), as written.
    fn add_ntt(a_hat: &Poly, b_hat: &Poly) -> Poly {
        let mut c_hat = [0; N];
        for ((c, &a), &b) in c_hat.iter_mut().zip(a_hat.iter()).zip(b_hat.iter()) {
            *c = add_mod_q(a, b);
        }
        c_hat
    }

    // ---- Arithmetic ----

    #[test]
    fn ml_dsa_barrett_reduction_agrees_with_remainder() {
        assert_eq!(BARRETT_RECIPROCAL, 2_201_172_575_745);
        let q = Q as u64;
        let mut samples = vec![0, 1, q - 1, q, q + 1, 2 * q - 1, 2 * q, (q - 1) * (q - 1)];
        samples.extend([u64::MAX, u64::MAX - 1, 7 * (q - 1) * (q - 1)]);
        for shift in 0..64 {
            samples.push(1u64 << shift);
            samples.push((1u64 << shift).wrapping_sub(1));
        }
        for chunk in test_bytes(b"barrett", 8 * 50_000).chunks_exact(8) {
            let x = u64::from_le_bytes(chunk.try_into().expect("eight bytes"));
            samples.push(x);
            // Multiples of q are where a quotient estimate is off by one.
            let multiple = (x >> 23) * q;
            samples.extend([multiple, multiple.wrapping_sub(1), multiple + 1]);
            samples.push(x >> 18);
        }
        for x in samples {
            assert_eq!(reduce(x) as u64, x % q, "x = {x}");
        }
    }

    #[test]
    fn ml_dsa_residue_helpers_match_their_definitions() {
        // The one-argument helpers are checked on every value in [0, q).
        for x in 0..Q {
            assert_eq!(
                i64::from(centered_mod_q(x)),
                spec_mod_pm(i64::from(x), i64::from(Q))
            );
            assert_eq!(to_mod_q(x), x);
            assert_eq!(to_mod_q(-x), (-x).rem_euclid(Q));
            assert_eq!(subtract_q_if_at_least_q(x as u32), x);
            assert_eq!(subtract_q_if_at_least_q((x + Q) as u32), x);
        }
        // The two-argument ones on every pair drawn from edge values and 256
        // pseudorandom residues.
        let mut values = vec![0, 1, 2, Q / 2, Q / 2 + 1, Q - 2, Q - 1];
        values.extend(test_poly(b"residue pairs"));
        for &a in &values {
            for &b in &values {
                assert_eq!(add_mod_q(a, b), (a + b) % Q);
                assert_eq!(sub_mod_q(a, b), (a - b).rem_euclid(Q));
                assert_eq!(
                    i64::from(mul_mod_q(a, b)),
                    i64::from(a) * i64::from(b) % i64::from(Q)
                );
            }
        }
    }

    #[test]
    fn ml_dsa_floor_division_constants_are_the_derived_ones() {
        let constants = |d: FloorDivision| (d.multiplier, d.shift, d.max_dividend);
        assert_eq!(constants(DIVIDE_HALF_BYTE_BY_5), (13, 6, 15));
        assert_eq!(
            constants(ML_DSA_44.decompose_division),
            (2_886_403, 39, (Q + ML_DSA_44.gamma2 - 2) as u64)
        );
        assert_eq!(
            constants(ML_DSA_65.decompose_division),
            (16_793_617, 43, (Q + ML_DSA_65.gamma2 - 2) as u64)
        );
        assert_eq!(ML_DSA_87.decompose_division, ML_DSA_65.decompose_division);
    }

    #[test]
    fn ml_dsa_coeff_from_half_byte_matches_algorithm_15_for_every_nibble() {
        for b in 0..16u8 {
            assert_eq!(
                DIVIDE_HALF_BYTE_BY_5.quotient(u64::from(b)),
                u64::from(b) / 5
            );
            for eta in [2, 4] {
                assert_eq!(
                    coeff_from_half_byte(eta, b),
                    spec_coeff_from_half_byte(eta, b),
                    "η = {eta}, b = {b}"
                );
            }
        }
    }

    #[test]
    fn ml_dsa_power2_round_matches_algorithm_35_for_every_residue() {
        for r in 0..Q {
            assert_eq!(power2_round(r), spec_power2_round(r), "r = {r}");
        }
    }

    #[test]
    fn ml_dsa_decompose_matches_algorithm_36_for_every_residue_and_both_gamma2() {
        for p in [ML_DSA_44, ML_DSA_65] {
            for r in 0..Q {
                assert_eq!(
                    decompose(p, r),
                    spec_decompose(p.gamma2, r),
                    "γ2 = {}, r = {r}",
                    p.gamma2
                );
            }
        }
    }

    #[test]
    fn ml_dsa_make_hint_and_use_hint_agree_with_algorithms_39_and_40() {
        for p in [ML_DSA_44, ML_DSA_65] {
            let g = p.gamma2;
            let mut rs = vec![0, 1, g - 1, g, g + 1, 2 * g - 1, 2 * g, 2 * g + 1];
            rs.extend([Q - g - 2, Q - g - 1, Q - g, Q - g + 1, Q - 2, Q - 1]);
            let mut zs = vec![0, 1, Q - 1, g - 1, g, Q - g, Q - g + 1];
            let bytes = test_bytes(b"hints", 8 * 4000);
            for chunk in bytes.chunks_exact(8) {
                let a = u32::from_le_bytes(chunk[..4].try_into().expect("four bytes"));
                let b = u32::from_le_bytes(chunk[4..].try_into().expect("four bytes"));
                rs.push((a % Q as u32) as i32);
                zs.push((b % (2 * g as u32 + 1)) as i32 - g);
                zs.push((b % Q as u32) as i32);
            }
            for &r in &rs {
                for &z in &zs {
                    let z = z.rem_euclid(Q);
                    let r1 = spec_decompose(g, r).0;
                    let v1 = spec_decompose(g, (r + z) % Q).0;
                    let hint = make_hint(p, z, r);
                    assert_eq!(hint, i32::from(r1 != v1), "γ2 = {g}, z = {z}, r = {r}");
                    // With ‖z‖∞ ≤ γ2 the hint recovers HighBits(r + z) from r.
                    if abs_ct(centered_mod_q(z)) <= g {
                        assert_eq!(use_hint(p, hint, r), v1, "γ2 = {g}, z = {z}, r = {r}");
                    }
                }
            }
        }
    }

    // ---- NTT ----

    #[test]
    fn ml_dsa_ntt_inverse_undoes_ntt_and_ntt_undoes_inverse() {
        let mut samples = vec![[0; N], [1; N], [Q - 1; N]];
        for i in [0, 1, 127, 128, 254, 255] {
            let mut basis = [0; N];
            basis[i] = 1;
            samples.push(basis);
        }
        for label in 0..16u8 {
            samples.push(test_poly(&[b'n', label]));
        }
        for original in samples {
            let mut w = original;
            ntt(&mut w);
            assert!(w.iter().all(|&c| (0..Q).contains(&c)));
            ntt_inverse(&mut w);
            assert_eq!(w, original);
            ntt_inverse(&mut w);
            assert!(w.iter().all(|&c| (0..Q).contains(&c)));
            ntt(&mut w);
            assert_eq!(w, original);
        }
    }

    #[test]
    fn ml_dsa_ntt_evaluates_at_odd_powers_of_zeta() {
        // Equation (7.1): NTT(w) = (w(ζ^(2·BitRev8(i) + 1)))_i.
        let w = test_poly(b"evaluation");
        let mut w_hat = w;
        ntt(&mut w_hat);
        for (i, &w_hat_i) in w_hat.iter().enumerate() {
            let x = pow_mod_q(ZETA, 2 * u32::from(bit_rev8(i as u8)) + 1);
            let value = w
                .iter()
                .rev()
                .fold(0, |acc, &c| add_mod_q(mul_mod_q(acc, x), c));
            assert_eq!(w_hat_i, value, "i = {i}");
        }
    }

    #[test]
    fn ml_dsa_multiply_ntt_is_multiplication_in_r_q() {
        let a = test_poly(b"factor a");
        let b = test_poly(b"factor b");
        let mut product = [0; N];
        for (i, &a_i) in a.iter().enumerate() {
            for (j, &b_j) in b.iter().enumerate() {
                let term = mul_mod_q(a_i, b_j);
                // X^256 = −1 in R_q.
                if i + j < N {
                    product[i + j] = add_mod_q(product[i + j], term);
                } else {
                    product[i + j - N] = sub_mod_q(product[i + j - N], term);
                }
            }
        }
        let (mut a_hat, mut b_hat, mut c_hat) = (a, b, [0; N]);
        ntt(&mut a_hat);
        ntt(&mut b_hat);
        multiply_ntt(&a_hat, &b_hat, &mut c_hat);
        ntt_inverse(&mut c_hat);
        assert_eq!(c_hat, product);
    }

    #[test]
    fn ml_dsa_matrix_vector_ntt_equals_algorithm_48_as_written() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            let random = expand_a(p, &[7u8; SEED_BYTES]);
            let mut largest = MatrixNtt::zero(p);
            largest.entries.fill([Q - 1; N]);
            let mut random_v = PolyVec::zero(p.l);
            for (j, v_j) in random_v.polys_mut().iter_mut().enumerate() {
                *v_j = test_poly(&[b'v', j as u8]);
            }
            let mut largest_v = PolyVec::zero(p.l);
            for v_j in largest_v.polys_mut() {
                *v_j = [Q - 1; N];
            }
            for (m_hat, v_hat) in [(&random, &random_v), (&largest, &largest_v)] {
                let mut folded = PolyVec::zero(p.k);
                matrix_vector_ntt(m_hat, v_hat, &mut folded);
                for (i, (folded_i, row)) in folded.polys().iter().zip(m_hat.rows()).enumerate() {
                    let mut w_i = [0; N];
                    for (m_ij, v_j) in row.iter().zip(v_hat.polys()) {
                        let mut product = [0; N];
                        multiply_ntt(m_ij, v_j, &mut product);
                        w_i = add_ntt(&w_i, &product);
                    }
                    assert_eq!(*folded_i, w_i, "{p:?} row {i}");
                }
            }
        }
    }

    // ---- Encoding and sampling ----

    #[test]
    fn ml_dsa_bit_string_codec_matches_algorithms_9_to_13() {
        let values: Vec<u32> = test_bytes(b"bit strings", 4 * N)
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes")))
            .collect();
        for width in 1..=32u32 {
            let mut bits = Vec::new();
            for &x in &values {
                bits.extend(spec_integer_to_bits(x, width));
            }
            let expected = spec_bits_to_bytes(&bits);
            let mut packed = vec![0u8; 32 * width as usize];
            let mut writer = BitStringWriter::new(&mut packed);
            for &x in &values {
                writer.integer_to_bits(x, width);
            }
            writer.finish();
            assert_eq!(packed, expected, "width {width}");

            let unpacked_bits = spec_bytes_to_bits(&packed);
            let mut reader = BitStringReader::new(&packed);
            let w = width as usize;
            for (i, &x) in values.iter().enumerate() {
                let spec = spec_bits_to_integer(&unpacked_bits[i * w..(i + 1) * w]);
                assert_eq!(u64::from(spec), u64::from(x) & ((1u64 << width) - 1));
                assert_eq!(
                    reader.bits_to_integer(width),
                    spec,
                    "width {width}, index {i}"
                );
            }
        }
    }

    #[test]
    fn ml_dsa_samplers_match_algorithms_29_to_31_as_written() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            for label in 0..32u8 {
                let rho = test_bytes(&[b'c', label], p.ctilde_bytes);
                let mut c = [0; N];
                sample_in_ball(p, &rho, &mut c);
                assert_eq!(c, spec_sample_in_ball(p.tau, &rho), "{p:?} seed {label}");
                assert_eq!(c.iter().filter(|&&c_j| c_j != 0).count(), p.tau);

                let seed: [u8; CRH_BYTES + 2] = test_bytes(&[b's', label], CRH_BYTES + 2)
                    .try_into()
                    .expect("66 bytes");
                let mut a = [0; N];
                rej_bounded_poly(p, &seed, &mut a);
                assert_eq!(a, spec_rej_bounded_poly(p.eta, &seed), "{p:?} seed {label}");
            }
        }
        for label in 0..8u8 {
            let seed: [u8; SEED_BYTES + 2] = test_bytes(&[b'a', label], SEED_BYTES + 2)
                .try_into()
                .expect("34 bytes");
            let mut a_hat = [0; N];
            rej_ntt_poly(&seed, &mut a_hat);
            assert_eq!(a_hat, spec_rej_ntt_poly(&seed), "seed {label}");
        }
    }

    #[test]
    fn private_key_with_out_of_range_secret_coefficient_is_refused() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in [
            (MlDsaParameterSet::MlDsa44, "MLDSA44"),
            (MlDsaParameterSet::MlDsa65, "MLDSA65"),
        ] {
            let p = params.profile();
            let valid = ref_kat(&vectors, prefix, "SK");
            let s1_start = 2 * SEED_BYTES + TR_BYTES;
            let s2_start = s1_start + p.l * p.s_packed_bytes;
            // Each field holds η − s in bitlen(2η) bits, the first field in the
            // low bits of its first byte: 2η encodes s = −η, the last value in
            // range, and 2η + 1 the first one outside it.
            let field_mask = (1u8 << bitlen(2 * p.eta as u32)) - 1;
            let first_out_of_range = 2 * p.eta as u8 + 1;
            assert!(MlDsaPrivateKey::from_wire_bytes(params, &valid).is_some());
            for start in [s1_start, s2_start] {
                let mut sk_bytes = valid.clone();
                sk_bytes[start] = (sk_bytes[start] & !field_mask) | first_out_of_range;
                let mut blob = vec![params.id()];
                blob.extend_from_slice(&sk_bytes);
                assert!(
                    MlDsaPrivateKey::from_wire_bytes(params, &sk_bytes).is_none(),
                    "{params:?}, byte {start}"
                );
                assert!(
                    MlDsaPrivateKey::from_key_blob(&blob).is_none(),
                    "{params:?}, byte {start}, blob"
                );
            }
        }
    }

    #[test]
    fn expanded_keys_with_an_inconsistent_tr_or_t0_are_refused() {
        let vectors = ref_kat_vectors();
        for (params, prefix) in REF_KAT_SETS {
            let p = params.profile();
            let valid = ref_kat(&vectors, prefix, "SK");
            assert!(MlDsaPrivateKey::from_wire_bytes(params, &valid).is_some());
            let tr_start = 2 * SEED_BYTES;
            let t0_start = tr_start + TR_BYTES + (p.l + p.k) * p.s_packed_bytes;
            assert_eq!(t0_start + p.k * T0_PACKED_BYTES, valid.len());
            // Every 13-bit t0 field value is in BitUnpack's range, so a flip
            // there decodes to another t0, and only the Algorithm 6 recomputation
            // can tell it from the carried one; a flipped tr is caught by the
            // recomputed H(pk, 64). s1 and s2 stay in range throughout.
            for (offset, bit, what) in [
                (tr_start, 0x01, "first byte of tr"),
                (tr_start + TR_BYTES - 1, 0x80, "last byte of tr"),
                (t0_start, 0x01, "first byte of t0"),
                (t0_start + T0_PACKED_BYTES / 2, 0x10, "a middle byte of t0"),
                (valid.len() - 1, 0x80, "last byte of t0"),
            ] {
                let mut sk = valid.clone();
                sk[offset] ^= bit;
                assert!(
                    MlDsaPrivateKey::from_wire_bytes(params, &sk).is_none(),
                    "{params:?}: {what}"
                );
                let mut blob = vec![params.id()];
                blob.extend_from_slice(&sk);
                assert!(
                    MlDsaPrivateKey::from_key_blob(&blob).is_none(),
                    "{params:?}: {what}, blob"
                );
            }
        }
    }

    #[test]
    fn hint_encoding_with_exactly_omega_ones_parses_and_round_trips() {
        for params in ALL_PARAMS {
            let p = params.profile();
            let hint_pos = p.ctilde_bytes + p.l * p.polyz_packed_bytes;
            let mut sig = vec![0u8; params.signature_len()];
            // ω strictly increasing indices, all in the first polynomial.
            for (slot, index) in sig[hint_pos..hint_pos + p.omega].iter_mut().zip(0u8..) {
                *slot = index;
            }
            for count in &mut sig[hint_pos + p.omega..] {
                *count = p.omega as u8;
            }
            let parsed = MlDsaSignature::from_wire_bytes(params, &sig).expect("weight ω parses");
            let weight: i32 = parsed.decoded.h.polys().as_flattened().iter().sum();
            assert_eq!(weight, p.omega as i32, "{params:?}");
            assert_eq!(sig_encode(p, &parsed.decoded), sig, "{params:?}");
        }
    }

    #[test]
    fn ml_dsa_rejection_tests_sit_exactly_on_their_bounds() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            let zero_l = PolyVec::zero(p.l);
            let zero_k = PolyVec::zero(p.k);
            let rejects = |z: &PolyVec, d: &PolyVec, ct0: &PolyVec, h: &PolyVec| {
                rejection_mask(p, z, d, ct0, h) != 0
            };
            assert!(!rejects(&zero_l, &zero_k, &zero_k, &zero_k));
            // Line 23, ‖z‖∞ ≥ γ1 − β, on either sign.
            let bound = p.gamma1 - p.beta;
            for (value, rejected) in [
                (bound - 1, false),
                (bound, true),
                (Q - bound + 1, false),
                (Q - bound, true),
            ] {
                let mut z = zero_l.clone();
                z.polys_mut()[p.l - 1][N - 1] = value;
                assert_eq!(
                    rejects(&z, &zero_k, &zero_k, &zero_k),
                    rejected,
                    "{p:?} z {value}"
                );
            }
            // Line 23, ‖LowBits(w − cs2)‖∞ ≥ γ2 − β: below γ2 a residue is its own
            // low part, and q − x (x < γ2) has low part −x.
            let bound = p.gamma2 - p.beta;
            for (value, rejected) in [
                (bound - 1, false),
                (bound, true),
                (Q - bound + 1, false),
                (Q - bound, true),
            ] {
                let mut d = zero_k.clone();
                d.polys_mut()[0][0] = value;
                assert_eq!(
                    rejects(&zero_l, &d, &zero_k, &zero_k),
                    rejected,
                    "{p:?} r {value}"
                );
            }
            // Line 28, ‖ct0‖∞ ≥ γ2.
            for (value, rejected) in [
                (p.gamma2 - 1, false),
                (p.gamma2, true),
                (Q - p.gamma2 + 1, false),
                (Q - p.gamma2, true),
            ] {
                let mut ct0 = zero_k.clone();
                ct0.polys_mut()[p.k - 1][N / 2] = value;
                assert_eq!(
                    rejects(&zero_l, &zero_k, &ct0, &zero_k),
                    rejected,
                    "{p:?} ct0 {value}"
                );
            }
            // Line 28, more than ω ones in h.
            for (weight, rejected) in [(p.omega, false), (p.omega + 1, true)] {
                let mut h = zero_k.clone();
                for slot in h.polys_mut().as_flattened_mut().iter_mut().take(weight) {
                    *slot = 1;
                }
                assert_eq!(
                    rejects(&zero_l, &zero_k, &zero_k, &h),
                    rejected,
                    "{p:?} weight {weight}"
                );
            }
        }
    }

    #[test]
    fn ml_dsa_verification_norm_test_sits_exactly_on_its_bound() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            let bound = p.gamma1 - p.beta;
            for (value, within) in [
                (0, true),
                (bound - 1, true),
                (bound, false),
                (1 - bound, true),
                (-bound, false),
            ] {
                let mut z = PolyVec::zero(p.l);
                z.polys_mut()[p.l - 1][N - 1] = value;
                assert_eq!(response_within_bound(p, &z), within, "{p:?} z {value}");
            }
        }
    }

    #[test]
    fn signing_returns_nothing_once_the_attempt_limit_is_spent() {
        let vectors = ref_kat_vectors();
        let params = MlDsaParameterSet::MlDsa44;
        let p = params.profile();
        let sk = MlDsaPrivateKey::from_wire_bytes(params, &ref_kat(&vectors, "MLDSA44", "SK"))
            .expect("sk");
        let key = sk.expanded().expect("well-formed key");
        let rnd = [0u8; RND_BYTES];
        for i in 0..REF_KAT_MESSAGES {
            let msg = ref_kat(&vectors, "MLDSA44", &format!("MSG{i}"));
            let m_prime: [&[u8]; 2] = [&[0, 0], msg.as_slice()];
            let needed = (1..=SIGN_ATTEMPT_LIMIT)
                .find(|&limit| sign_internal(p, key, m_prime, &rnd, limit).is_some())
                .expect("signs within the Appendix C limit");
            let (bytes, _) = sign_internal(p, key, m_prime, &rnd, needed).expect("signs");
            assert_eq!(bytes, ref_kat(&vectors, "MLDSA44", &format!("SIG{i}")));
            assert!(sign_internal(p, key, m_prime, &rnd, needed - 1).is_none());
        }
    }

    #[test]
    fn ml_dsa_xof_byte_stream_equals_one_long_squeeze() {
        // The stream behind SampleInBall, RejNTTPoly and RejBoundedPoly, read
        // across several block refills.
        let mut long = [0u8; 3 * Shake256::BLOCK_LEN + 5];
        hash_h(&[b"stream"], &mut long);
        let mut stream = h_stream(b"stream");
        for (i, &expected) in long.iter().enumerate() {
            assert_eq!(stream.next_byte(), expected, "byte {i}");
        }
        let mut long = [0u8; 2 * Shake128::BLOCK_LEN + 1];
        let mut ctx = Shake128::new();
        ctx.update(b"stream");
        ctx.squeeze(&mut long);
        let mut stream = g_stream(b"stream");
        for (i, &expected) in long.iter().enumerate() {
            assert_eq!(stream.next_byte(), expected, "byte {i}");
        }
    }

    /// Each parameter set with its RFC 9881 name and its Appendix C.1
    /// subsection number.
    const NAMED_PARAMS: [(MlDsaParameterSet, &str, usize); 3] = [
        (MlDsaParameterSet::MlDsa44, "ML-DSA-44", 1),
        (MlDsaParameterSet::MlDsa65, "ML-DSA-65", 2),
        (MlDsaParameterSet::MlDsa87, "ML-DSA-87", 3),
    ];

    /// The identifier octet of the private-key `CHOICE` alternative inside the
    /// DER `OneAsymmetricKey` `der`: 0x80 seed, 0x04 expandedKey, 0x30 both.
    fn private_key_alternative(der: &[u8]) -> u8 {
        OneAsymmetricKey::from_der(der)
            .expect("OneAsymmetricKey")
            .private_key()[0]
    }

    #[test]
    fn an_expanded_key_with_s1_out_of_range_is_refused_when_t0_and_tr_agree() {
        let params = MlDsaParameterSet::MlDsa44;
        let p = params.profile();
        let (_, private) = MlDsa::keygen_from_seed(params, &[0x37; 32]);
        // The key re-encoded, with its first s1 coefficient set to −η − 1 when
        // `alter` is set, and t0 and tr recomputed by Algorithm 6 lines 3 to 9,
        // so that only the [−η, η] range check can tell the two apart.
        let reencode = |alter: bool| {
            let mut key = [0u8; SEED_BYTES];
            let mut tr = [0u8; TR_BYTES];
            let mut s1 = PolyVec::zero(p.l);
            let mut s2 = PolyVec::zero(p.k);
            let mut t0 = PolyVec::zero(p.k);
            let sk = private.to_wire_bytes();
            let rho = sk_decode(p, &sk, &mut key, &mut tr, &mut s1, &mut s2, &mut t0);
            if alter {
                s1.polys_mut()[0][0] = -(p.eta + 1);
            }
            let mut s1_hat = PolyVec::zero(p.l);
            vector_to_mod_q(&s1, &mut s1_hat);
            ntt_vector(&mut s1_hat);
            let mut t = PolyVec::zero(p.k);
            matrix_vector_ntt(&expand_a(p, &rho), &s1_hat, &mut t);
            ntt_inverse_vector(&mut t);
            let mut t1 = PolyVec::zero(p.k);
            for (((&t_j, &s2_j), t1_j), t0_j) in t
                .polys()
                .as_flattened()
                .iter()
                .zip(s2.polys().as_flattened())
                .zip(t1.polys_mut().as_flattened_mut())
                .zip(t0.polys_mut().as_flattened_mut())
            {
                (*t1_j, *t0_j) = power2_round(add_mod_q(t_j, to_mod_q(s2_j)));
            }
            let pk = pk_encode(p, &rho, &t1);
            hash_h(&[&pk], &mut tr);
            let sk = sk_encode(p, &rho, &key, &tr, &s1, &s2, &t0);
            OneAsymmetricKey::new(
                AlgorithmIdentifier::new(params.algorithm(), None),
                &PrivateKeyChoice::ExpandedKey(&sk).to_der(),
                None,
            )
            .to_der()
        };
        // Unaltered, the construction reproduces the generated key, accepted.
        let unaltered = reencode(false);
        assert_eq!(
            MlDsaPrivateKey::from_pkcs8_der(&unaltered).as_ref(),
            Some(&private)
        );
        assert_eq!(
            private_key_alternative(&unaltered),
            0x04,
            "the expanded form"
        );
        // Altered, t0 and tr still agree with s1 and s2, so the range check is
        // what refuses it.
        assert!(MlDsaPrivateKey::from_pkcs8_der(&reencode(true)).is_none());
    }

    /// The keys of RFC 9881 Appendix C, under the provenance note in the file.
    const RFC9881_APPENDIX_C: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/rfc9881_appendix_c.txt"
    ));

    /// The textual encoding printed under `heading` in the extract.
    fn rfc9881_example(heading: &str) -> &'static str {
        let marker = format!("\n{heading}\n");
        let start = RFC9881_APPENDIX_C
            .find(&marker)
            .unwrap_or_else(|| panic!("no {heading:?} in the RFC 9881 extract"))
            + marker.len();
        let text = &RFC9881_APPENDIX_C[start..];
        let boundary = text
            .find("-----END ")
            .expect("a post-encapsulation boundary");
        let end = boundary + text[boundary..].find('\n').expect("a line end") + 1;
        &text[..end]
    }

    #[test]
    fn rfc9881_appendix_c1_private_keys_decode_in_every_form() {
        // "all derived from the same seed 000102...1e1f".
        let seed: [u8; SEED_BYTES] = core::array::from_fn(|i| u8::try_from(i).expect("below 32"));
        for (params, name, subsection) in NAMED_PARAMS {
            let (public, generated) = MlDsa::keygen_from_seed(params, &seed);
            let seed_pem = rfc9881_example(&format!("C.1.{subsection}.1 {name} seed"));
            let expanded_pem = rfc9881_example(&format!("C.1.{subsection}.2 {name} expandedKey"));
            let both_pem = rfc9881_example(&format!("C.1.{subsection}.3 {name} both"));
            let from_seed = MlDsaPrivateKey::from_pkcs8_pem(seed_pem).expect("seed form");
            let from_expanded =
                MlDsaPrivateKey::from_pkcs8_pem(expanded_pem).expect("expanded form");
            let from_both = MlDsaPrivateKey::from_pkcs8_pem(both_pem).expect("both form");
            assert_eq!(from_seed, generated, "{name}");
            assert_eq!(from_expanded, generated, "{name}");
            assert_eq!(from_both, generated, "{name}");
            // A key with its seed writes the seed form and one without writes
            // the expanded form, each exactly as the RFC prints it.
            assert_eq!(generated.to_pkcs8_pem(), seed_pem, "{name}");
            assert_eq!(from_seed.to_pkcs8_pem(), seed_pem, "{name}");
            assert_eq!(from_both.to_pkcs8_pem(), seed_pem, "{name}");
            assert_eq!(from_expanded.to_pkcs8_pem(), expanded_pem, "{name}");

            // Appendix C.2 prints the public key, which the expanded key alone
            // regenerates.
            let public_pem = rfc9881_example(&format!("C.2 {name} public key"));
            assert_eq!(
                MlDsaPublicKey::from_spki_pem(public_pem).as_ref(),
                Some(&public),
                "{name}"
            );
            assert_eq!(public.to_spki_pem(), public_pem, "{name}");
            assert_eq!(
                from_expanded.regenerate_public_key().as_ref(),
                Some(&public),
                "{name}"
            );
        }
    }

    #[test]
    fn rfc9881_appendix_c4_inconsistent_private_keys_are_refused() {
        // The first is `both` with a seed and expanded key that disagree (the
        // §8.2 seed consistency check). The second is an expanded key whose tr
        // is not the hash of the public key its s1 and s2 imply, and the third
        // one whose t0 is not the low part of the t they imply: both are found
        // by regenerating the public key.
        for example in 1..=3 {
            let pem = rfc9881_example(&format!("C.4 example {example}"));
            assert!(
                MlDsaPrivateKey::from_pkcs8_pem(pem).is_none(),
                "example {example}"
            );
        }
    }

    #[test]
    fn pkcs8_ber_accepts_an_indefinite_length_container() {
        let params = MlDsaParameterSet::MlDsa65;
        let (_, generated) = MlDsa::keygen_from_seed(params, &[0x33; 32]);
        let der = generated.to_pkcs8_der();
        let ber = crate::test_utils::der_to_indefinite_length(&der);
        assert!(MlDsaPrivateKey::from_pkcs8_der(&ber).is_none());
        let from_ber = MlDsaPrivateKey::from_pkcs8_ber(&ber).expect("BER");
        assert_eq!(from_ber.to_pkcs8_der(), der);
        let from_der = MlDsaPrivateKey::from_pkcs8_ber(&der).expect("DER is BER");
        assert_eq!(from_der.to_pkcs8_der(), der);
    }

    #[test]
    fn pkcs8_writes_the_seed_when_retained_and_the_expanded_key_otherwise() {
        let params = MlDsaParameterSet::MlDsa65;
        let (_, generated) = MlDsa::keygen_from_seed(params, &[0x33; 32]);
        let expanded_only =
            MlDsaPrivateKey::from_wire_bytes(params, &generated.to_wire_bytes()).expect("sk");
        // The first octet of the privateKey contents names the alternative.
        let alternative = |der: &[u8]| {
            OneAsymmetricKey::from_der(der)
                .expect("OneAsymmetricKey")
                .private_key()[0]
        };
        assert_eq!(alternative(&generated.to_pkcs8_der()), 0x80);
        assert_eq!(alternative(&expanded_only.to_pkcs8_der()), 0x04);

        // Either form reads back as the same key, and an expanded key does not
        // gain a seed on the way.
        let reread = MlDsaPrivateKey::from_pkcs8_der(&expanded_only.to_pkcs8_der()).expect("sk");
        assert_eq!(reread, generated);
        assert_eq!(alternative(&reread.to_pkcs8_der()), 0x04);
        assert_eq!(
            MlDsaPrivateKey::from_pkcs8_der(&generated.to_pkcs8_der()).as_ref(),
            Some(&generated)
        );

        // Random key generation keeps the seed too; the crate's own forms are
        // unchanged by it.
        let (_, random) = MlDsa::keygen(params, &mut crate::CtrDrbgAes256::new(&[0x44; 48]));
        assert_eq!(alternative(&random.to_pkcs8_der()), 0x80);
        assert_eq!(random.to_key_blob()[1..], random.to_wire_bytes());
        assert_eq!(
            MlDsaPrivateKey::from_key_blob(&random.to_key_blob()).as_ref(),
            Some(&random)
        );
    }

    #[test]
    fn spki_and_pkcs8_refuse_what_rfc9881_does_not_allow() {
        let params = MlDsaParameterSet::MlDsa44;
        let p = params.profile();
        let seed = [0x21u8; SEED_BYTES];
        let (public, private) = MlDsa::keygen_from_seed(params, &seed);
        let absent = AlgorithmIdentifier::new(params.algorithm(), None);
        let null = AlgorithmIdentifier::new(params.algorithm(), Some(NULL_PARAMETERS));
        let other_set = AlgorithmIdentifier::new(MlDsaParameterSet::MlDsa65.algorithm(), None);
        let pk = public.to_wire_bytes();
        let sk = private.to_wire_bytes();

        assert_eq!(
            MlDsaPublicKey::from_spki_der(&public.to_spki_der()).as_ref(),
            Some(&public)
        );
        let spki = |algorithm: AlgorithmIdentifier<'static>, key: &[u8]| {
            SubjectPublicKeyInfo::new(algorithm, key).to_der()
        };
        let mut trailing = public.to_spki_der();
        trailing.push(0);
        for (der, why) in [
            (spki(null, &pk), "NULL parameters"),
            (spki(other_set, &pk), "another parameter set's identifier"),
            (spki(absent, &pk[..pk.len() - 1]), "a truncated key"),
            (trailing, "bytes after the SEQUENCE"),
        ] {
            assert!(MlDsaPublicKey::from_spki_der(&der).is_none(), "{why}");
        }

        let package = |algorithm: AlgorithmIdentifier<'static>,
                       private_key: &[u8],
                       public_key: Option<&[u8]>| {
            OneAsymmetricKey::new(algorithm, private_key, public_key).to_der()
        };
        let seed_form = PrivateKeyChoice::Seed(&seed).to_der();
        let expanded_form = PrivateKeyChoice::ExpandedKey(&sk).to_der();
        let both_form = PrivateKeyChoice::Both {
            seed: &seed,
            expanded_key: &sk,
        }
        .to_der();
        // Every alternative is accepted, with or without the matching public key.
        for form in [&seed_form, &expanded_form, &both_form] {
            for public_key in [None, Some(&pk[..])] {
                assert_eq!(
                    MlDsaPrivateKey::from_pkcs8_der(&package(absent, form, public_key)).as_ref(),
                    Some(&private)
                );
            }
        }

        // Expanded keys that skDecode reads but key generation cannot produce:
        // the first s1 field one past −η, a flipped bit of tr, and a flipped
        // bit of the last t0 coefficient.
        let expanded = |sk: &[u8]| PrivateKeyChoice::ExpandedKey(sk).to_der();
        let s1_start = 2 * SEED_BYTES + TR_BYTES;
        let field_mask = (1u8 << bitlen(2 * p.eta as u32)) - 1;
        let mut out_of_range = sk.clone();
        out_of_range[s1_start] = (out_of_range[s1_start] & !field_mask) | (2 * p.eta as u8 + 1);
        let mut other_tr = sk.clone();
        other_tr[2 * SEED_BYTES] ^= 0x01;
        let mut other_t0 = sk.clone();
        *other_t0.last_mut().expect("non-empty") ^= 0x80;
        let (other_public, _) = MlDsa::keygen_from_seed(params, &[0x22; 32]);
        let mut trailing = package(absent, &seed_form, None);
        trailing.push(0);
        let refused = [
            (package(null, &seed_form, None), "NULL parameters"),
            (
                package(other_set, &expanded_form, None),
                "an ML-DSA-65 identifier on an ML-DSA-44 key",
            ),
            (
                package(absent, &PrivateKeyChoice::Seed(&seed[..31]).to_der(), None),
                "a short seed",
            ),
            (
                package(absent, &expanded(&out_of_range), None),
                "s1 out of range",
            ),
            (
                package(absent, &expanded(&other_tr), None),
                "an inconsistent tr",
            ),
            (
                package(absent, &expanded(&other_t0), None),
                "an inconsistent t0",
            ),
            (
                package(
                    absent,
                    &PrivateKeyChoice::Both {
                        seed: &[0x22; 32],
                        expanded_key: &sk,
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
                "another key's public key with a seed",
            ),
            (
                package(absent, &expanded_form, Some(&other_public.to_wire_bytes())),
                "another key's public key with an expanded key",
            ),
            (
                package(absent, &both_form, Some(&pk[..pk.len() - 1])),
                "a truncated public key",
            ),
            (trailing, "bytes after the SEQUENCE"),
        ];
        for (der, why) in refused {
            assert!(MlDsaPrivateKey::from_pkcs8_der(&der).is_none(), "{why}");
        }
    }

    /// For every parameter set: the crate reads OpenSSL's key in each of its
    /// private-key output forms and verifies OpenSSL's signature; OpenSSL
    /// reads the crate's key in the seed and the expanded form, derives the
    /// same public key, signs deterministically exactly as the crate does, and
    /// verifies the crate's hedged signature under the crate's
    /// `SubjectPublicKeyInfo`.
    #[test]
    fn openssl_ml_dsa_keys_and_signatures_interoperate() {
        const TEST: &str = "openssl_ml_dsa_keys_and_signatures_interoperate";
        let Some(listing) = openssl3(&["list", "-signature-algorithms"], b"").or_skip(TEST) else {
            return;
        };
        let listing = String::from_utf8_lossy(&listing).into_owned();
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
            let theirs = MlDsaPrivateKey::from_pkcs8_pem(
                std::str::from_utf8(&theirs_pem).expect("PEM is ASCII"),
            )
            .expect("OpenSSL's PKCS #8 key");
            assert_eq!(theirs.parameter_set(), params);
            let theirs_spki = run(&["pkey", "-pubout", "-outform", "DER"], &theirs_pem);
            let theirs_public = MlDsaPublicKey::from_spki_der(&theirs_spki)
                .expect("OpenSSL's SubjectPublicKeyInfo");
            assert_eq!(
                theirs.regenerate_public_key().as_ref(),
                Some(&theirs_public)
            );
            assert_eq!(theirs_public.to_spki_der(), theirs_spki);
            // The same key in each of OpenSSL's private-key output forms: the
            // alternative OpenSSL wrote is checked, and so is whether the key
            // read from it keeps its seed.
            for (form, alternative, keeps_seed) in [
                ("seed-only", 0x80, true),
                ("priv-only", 0x04, false),
                ("seed-priv", 0x30, true),
            ] {
                let provparam = format!("ml-dsa.output_formats={form}");
                let Some(der) = openssl3(
                    &["pkey", "-provparam", &provparam, "-outform", "DER"],
                    &theirs_pem,
                )
                .or_skip(&format!("{TEST} ({name}, {form})")) else {
                    continue;
                };
                assert_eq!(private_key_alternative(&der), alternative, "{name} {form}");
                let read = MlDsaPrivateKey::from_pkcs8_der(&der).expect("OpenSSL's key");
                assert_eq!(read, theirs, "{name} {form}");
                assert_eq!(read.seed.is_some(), keeps_seed, "{name} {form}");
            }
            let message = format!("RFC 9881 keys carrying FIPS 204 signatures, {name}");
            let message_file =
                ScratchFile::new(TEST, &format!("{name}-message.bin"), message.as_bytes());
            let their_key_file = ScratchFile::new(TEST, &format!("{name}-theirs.pem"), &theirs_pem);
            let their_signature = run(
                &[
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    their_key_file.arg(),
                    "-in",
                    message_file.arg(),
                ],
                b"",
            );
            let their_signature = MlDsaSignature::from_wire_bytes(params, &their_signature)
                .expect("OpenSSL's signature");
            assert!(MlDsa::verify(
                &theirs_public,
                message.as_bytes(),
                &their_signature
            ));

            let (public, ours) = MlDsa::keygen_from_seed(params, &[0x4d; 32]);
            let expanded_only =
                MlDsaPrivateKey::from_wire_bytes(params, &ours.to_wire_bytes()).expect("sk");
            assert_eq!(
                run(
                    &["pkey", "-pubin", "-outform", "DER"],
                    public.to_spki_pem().as_bytes()
                ),
                public.to_spki_der()
            );
            let hedged = MlDsa::sign(
                &ours,
                message.as_bytes(),
                &mut crate::CtrDrbgAes256::new(&[0x4e; 48]),
            )
            .expect("sign");
            let public_file = ScratchFile::new(
                TEST,
                &format!("{name}-public.pem"),
                public.to_spki_pem().as_bytes(),
            );
            let signature_file = ScratchFile::new(
                TEST,
                &format!("{name}-signature.bin"),
                &hedged.to_wire_bytes(),
            );
            let verdict = run(
                &[
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-rawin",
                    "-inkey",
                    public_file.arg(),
                    "-in",
                    message_file.arg(),
                    "-sigfile",
                    signature_file.arg(),
                ],
                b"",
            );
            assert!(String::from_utf8_lossy(&verdict).contains("Signature Verified Successfully"));
            let deterministic = MlDsa::sign_deterministic(&ours, message.as_bytes()).expect("sign");
            for key in [&ours, &expanded_only] {
                let pem = key.to_pkcs8_pem();
                assert_eq!(
                    run(&["pkey", "-pubout", "-outform", "DER"], pem.as_bytes()),
                    public.to_spki_der(),
                    "{name}"
                );
                let reemitted = run(&["pkey", "-outform", "DER"], pem.as_bytes());
                let reread = MlDsaPrivateKey::from_pkcs8_der(&reemitted).expect("re-emitted key");
                assert_eq!(reread, ours, "{name}");
                // OpenSSL writes a seed back exactly when it was given one.
                assert_eq!(reread.seed.is_some(), key.seed.is_some(), "{name}");
                let text = run(&["pkey", "-text", "-noout"], pem.as_bytes());
                assert!(String::from_utf8_lossy(&text).contains(&format!("{name} Private-Key")));
                let key_file = ScratchFile::new(TEST, &format!("{name}-ours.pem"), pem.as_bytes());
                let signature = run(
                    &[
                        "pkeyutl",
                        "-sign",
                        "-rawin",
                        "-inkey",
                        key_file.arg(),
                        "-in",
                        message_file.arg(),
                        "-pkeyopt",
                        "deterministic:1",
                    ],
                    b"",
                );
                assert_eq!(signature, deterministic.to_wire_bytes(), "{name}");
            }
        }
    }

    #[test]
    fn ml_dsa_87_runs_on_a_256_kib_stack() {
        // Every polynomial vector and matrix lives on the heap, so the largest
        // parameter set's key generation, signing and verification fit in a
        // thread stack far smaller than a main thread's, on their first use of
        // each key (when the caches are built) and again afterwards.
        let worker = std::thread::Builder::new()
            .name("ml-dsa-87 on 256 KiB".into())
            .stack_size(256 * 1024)
            .spawn(|| {
                let params = MlDsaParameterSet::MlDsa87;
                let (pk, sk) = MlDsa::keygen_from_seed(params, &[0x87; SEED_BYTES]);
                let message = b"a 256 KiB stack is enough";
                for round in 0..2 {
                    let sig = MlDsa::sign_with_randomness(&sk, message, &[round; RND_BYTES])
                        .expect("sign");
                    assert!(MlDsa::verify(&pk, message, &sig));
                }
                let reread =
                    MlDsaPrivateKey::from_wire_bytes(params, &sk.to_wire_bytes()).expect("sk");
                assert_eq!(reread, sk);
            })
            .expect("spawn");
        worker
            .join()
            .expect("ML-DSA-87 completed on a 256 KiB stack");
    }
}
