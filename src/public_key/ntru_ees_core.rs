//! NTRUEncrypt SVES-3 as standardised in IEEE Std 1363.1-2008 and ANSI
//! X9.98, shared by the nine parameter-set modules
//! ([`crate::public_key::ntru_ees401ep1`] and its siblings). Each of those
//! is one `define_ees_set!` invocation binding an [`EesParams`] constant and
//! the ring degree `N`.
//!
//! # Sources
//!
//! The IEEE and ANSI texts are not freely available. The algorithms are
//! written from **EESS #1 v3.1**: Consortium for Efficient Embedded Security,
//! *Efficient Embedded Security Standard (EESS) #1, Version 3.1*, September
//! 2015, the public edition of the same specification. It was distributed as
//! `doc/EESS1-v3.1.pdf` in `NTRUOpenSourceProject/ntru-crypto` and is
//! archived by Software Heritage (SHA-256 `e429bde23ba0a01d…ab3f3245`). The
//! section numbers below are from it; the 2003 edition, EESS #1 v2
//! (`pubs/eess1v2.pdf`), defines the same conversion primitives under older
//! names and numbers.
//!
//! EESS #1 v3.1 tabulates only product-form parameter sets (`ees443ep1` is
//! its Table 5). The eight dense sets are the IEEE Std 1363.1-2008 sets,
//! whose tables were not available here; their values rest on the paper that
//! derived them and on measurement:
//! - `N` and `dF` are Table 1, "Standardized NTRU Parameters (conservative)",
//!   of Hirschhorn, Hoffstein, Howgrave-Graham and Whyte, *Choosing
//!   NTRUEncrypt Parameters in Light of Combined Lattice Reduction and MITM
//!   Approaches*, ACNS 2009, LNCS 5536, pp. 437–455
//!   (`pubs/hirschhorn-hoffstein-howgrave-graham-whyte-2009-…pdf`, below
//!   "HHHW"): (401, 113), (541, 49), (449, 134), (677, 157), (1087, 63),
//!   (1087, 120), (1171, 106) and (1499, 79).
//! - `dr = dF` and `dg = ⌊N/3⌋` are HHHW §1.1 ("p = 3, dr = df, dg =
//!   ⌊N/3⌋"; "the thickness of g does not affect efficiency"). One
//!   [`TrapdoorKind`] therefore shapes both `F` and `r`, as EESS #1 v3.1's
//!   own tables do for `ees443ep1` (`dr1, dr2, dr3` equal to `df1, df2,
//!   df3`). `dg` is also confirmed by key pair validation of the reference
//!   implementation's private keys, whose `g` has exactly `dg + 1` ones.
//! - `dm0 = dF` is HHHW §6, Assumption 7: "An encrypter that re-encrypts
//!   whenever the number of 1s or −1s in m′ falls below df does not make
//!   message recovery fall below the required security level"; §10.2.2
//!   step p applies the bound to the 0s as well. It was then measured for
//!   every set (see "Step p refusals" below).
//! - `db`, `c`, pkLen, the OID, the hash and maxMsgLenBytes are pinned by
//!   the interoperability vectors: `bLen` is the length of each recorded
//!   `b`, maxMsgLenBytes is the recorded `MAX_MSG`, and the recorded
//!   ciphertext reproduces only under the right IGF-2 width, hash, `hTrunc`
//!   length and OID.
//! - minCallsR and minCallsMask set how many hash blocks are computed up
//!   front (convention 3) and change no output, so the vectors cannot tell
//!   them apart; no available publication tabulates them for the dense
//!   sets, and their values here are unconfirmed.
//!
//! Where the text is silent or contradicts itself (noted below), the
//! reading was settled by running the standard authors' reference
//! implementation as a black-box oracle: only its inputs and outputs were
//! used. The interoperability vectors in
//! `tests/vectors/ntru_ees_sves3_reference.txt` (`scripts/ees_ref_vectors/`)
//! pin the result, and every parameter-set test module checks them.
//!
//! # Step p refusals
//!
//! Encryption redraws `b` when the masked message representative has fewer
//! than `dm0` of some trit value (EESS #1 v3.1 §10.2.2 step p). The mask is
//! hash output, so the three counts are those of `N` uniform trits and the
//! probability that an attempt is refused is exactly `1 − P(every count ≥
//! dm0)` under the multinomial with probabilities 1/3:
//!
//! | set | N | dm0 | P(refuse) per attempt |
//! |---|---|---|---|
//! | ees401ep1 | 401 | 113 | 3.49 × 10⁻² (2^−4.8) |
//! | ees443ep1 | 443 | 115 | 9.74 × 10⁻⁴ (2^−10.0) |
//! | ees449ep1 | 449 | 134 | 1.55 × 10⁻¹ (2^−2.7) |
//! | ees541ep1 | 541 | 49 | 1.05 × 10⁻⁴⁰ (2^−132.8) |
//! | ees677ep1 | 677 | 157 | 9.13 × 10⁻⁹ (2^−26.7) |
//! | ees1087ep1 | 1087 | 63 | 2.73 × 10⁻¹⁰⁸ (2^−357.3) |
//! | ees1087ep2 | 1087 | 120 | 1.04 × 10⁻⁶⁵ (2^−215.9) |
//! | ees1171ep1 | 1171 | 106 | 6.88 × 10⁻⁸⁶ (2^−282.9) |
//! | ees1499ep1 | 1499 | 79 | 7.24 × 10⁻¹⁵⁶ (2^−515.4) |
//!
//! The test `step_p_refusal_rates_by_parameter_set` measures this module's
//! rates against the table. The oracle's `dm0` was measured two ways. Over
//! 5000 encryptions per set it redrew `b` for 3.87% of `ees401ep1`
//! attempts, 15.5% of `ees449ep1` attempts and 0.06% of `ees443ep1`
//! attempts, and never for the other six, as the table predicts. Then,
//! under a public key `h = 0`, `r × h` vanishes and the mask is fixed, so
//! `b` and `m` can be chosen to give the representative any trit counts: for
//! all nine sets the oracle redrew `b` at a minimum count of `dm0 − 1` and
//! accepted at `dm0`.
//!
//! # Conventions
//!
//! 1. **Octets and bits** (§8.1–§8.4). I2OSP writes an integer big-endian,
//!    I2BSP most-significant bit first. BS2ROSP packs a bit string into
//!    octets first-bit-high and appends "(8 × oLen – bLen) zero bits"; the
//!    inverse, ROS2BSP, rejects "non-zero bits found after end of bit
//!    string". Its step d names that range as "the bits b_{bLen−1} …
//!    b_{8×oLen−1}", which would include the string's own last bit; this
//!    module reads it as the `8 × oLen − bLen` bits after the string, the
//!    zeros BS2ROSP appended. The oracle reads it the same way: its keys set
//!    the last coefficient bit about half the time (16 of the 27 public
//!    keys in the vectors) and never a padding bit.
//! 2. **Ring elements** (§8.5.1, §8.6.1). RE2BSP applies I2BSP at
//!    ⌈log₂ q⌉ bits to each coefficient in increasing degree, and RE2OSP
//!    follows it with BS2ROSP. Public keys and ciphertexts use RE2OSP at 11
//!    bits per coefficient (the `PackedModQVector` of §11.1.1), the mask
//!    seed at `q = 4`, private-key index lists at ⌈log₂ N⌉ bits.
//! 3. **Hash streams** (§9.4.1.1 steps c–g and j; §9.4.2.1 step a). Blocks
//!    `Hash(Z ‖ C)` for counter = 0, 1, …, converting "counter to an octet
//!    string C of length 4 octets using I2OSP", with `Z = Hash(seed)`
//!    (`hashSeed` = "yes": the parameter tables do not name `hashSeed`, and
//!    the oracle hashes the seed). `minCallsMask` / `minCallsR` blocks are
//!    computed up front; they change timing, not output.
//! 4. **MGF-TP-1** (§9.4.1.1 step i). Each octet `O < 243` yields, in
//!    increasing degree, `O mod 3` and then `O := (O − O mod 3) / 3`, five
//!    times; octets `≥ 243` are discarded; generation stops at `N`. A
//!    coefficient 2 is −1.
//! 5. **IGF-2** (§9.4.2.1 steps e–k). The blocks form one bit string; each
//!    call takes "the leading c bits", converts them to an integer `i`,
//!    starts again "If i ≥ 2^c − (2^c mod N)", and outputs `i mod N`.
//! 6. **Trinary polynomials** (§7.3.1.1). IGF indices are drawn until `df`
//!    distinct coefficients are `+1`, then until `df` more are `−1`, skipping
//!    any index already set. The blinding polynomial method (§9.3.2.2) does
//!    this once for `r`, or for `r₁`, `r₂`, `r₃` in turn on one continuing IGF
//!    state with `r = r₁ × r₂ + r₃`.
//! 7. **Key generation** (§10.2.1). `f = 1 + p × F` must be invertible mod
//!    `q`; `g` has `dg + 1` coefficients `+1` and `dg` coefficients `−1` and
//!    must be invertible mod `q`; `h = f⁻¹ × g × p`. Step g reads "Set
//!    g = g+1"; the key pair validation of §10.2.4.1 step e fixes the
//!    intended result, "exactly (dg +1) 1s and dg -1s". The generator may be
//!    any approved random source; this module samples directly.
//! 8. **Message encoding** (§10.2.2 steps d–h). `M = b ‖ octL ‖ m ‖ p0`, with
//!    `p0` "the 0 byte repeated (maxMsgLenBytes + 1 - l) times", is read as a
//!    bit string, zero-extended to a multiple of three bits. Each three-bit
//!    quantity `v` becomes the pair `(⌊v/3⌋, v mod 3)`, which is the table of
//!    step h (`{1, 1, 0} -> {-1, 0}`, …), and the first `N` trits are used.
//!    Step e also calls `M` `bufferLenBits/8` octets long, one octet shorter
//!    than that concatenation. The octet in question is the final zero of
//!    `p0` and yields only zero trits, so both readings encode identically.
//! 9. **Seed and mask** (§10.2.2 steps i–q). `sData = OID ‖ m ‖ b ‖ hTrunc`,
//!    where `hTrunc` is the first `pkLen` bits of RE2BSP(`h`) as octets.
//!    `r` comes from `sData` and `R = r × h mod q`. The mask is MGF-TP-1 of
//!    RE2OSP(`R mod 4`) "using q=4", and `m' = Mtrin + mask mod 3`, redrawn
//!    while any trit value occurs fewer than `dm0` times. Then
//!    `e = R + m' mod q`.
//! 10. **Decryption** (§10.2.3). `ci = e × f mod q`, reduced mod 3. The text
//!     lists a "lower bound A" used "to reduce into correct interval" but
//!     gives no value; this module reduces into `[−q/2, q/2)`. Then
//!     `cR = e − ci`, and the mask comes from RE2OSP(`cR mod 4`). Pairs of
//!     `ci − mask` become three bits by the inverse table, where "{-1, -1} ->
//!     set 'fail' to 1 and set bit string to {1, 1, 1}"; for odd `N` the
//!     last coefficient `t` is read as the pair `(t, 0)`. The rules "If cl >
//!     maxMsgLenBytes, set fail = 1 and set cl = maxL." and "the remaining
//!     octets should be 0" follow, where `maxL` is the `maxLen = nLen − 1 −
//!     lLen − bLen` of step a with `nLen = ⌈N/8⌉`
//!     ([`EesParams::decryption_max_len`]; 35 octets for `ees401ep1`, below
//!     maxMsgLenBytes for every set), so an over-long candidate is checked
//!     and re-encrypted at that length. The zero check covers the
//!     `maxMsgLenBytes + 1 − cl` octets of `p0` (convention 8), including
//!     the final partial octet that step i's truncation would drop when `N` is
//!     401, 449, 541 or 1171; the oracle checks the same octets. Step o
//!     re-derives `r` ("If cR' != cR, set fail = 1") and step c checks
//!     weights.
//!
//!     The last trit pair can also write bits past `p0`, the end of `M`: one
//!     for `N` = 677, two for `N` = 443 and 1499, none for the other sets.
//!     Step i drops them, no rule checks them, and neither does the oracle.
//!     For 677 the same pair writes the last bit of `p0`, so the zero check
//!     already rejects any change. For 443 and 1499 nothing does: as
//!     specified, adding 1 to coefficient `N − 1` of a ciphertext leaves the
//!     decrypted message unchanged whenever the mask's coefficient there is 0
//!     or −1, about two times in three, and subtracting 2 does so in the
//!     remaining third, so those two sets are malleable. This module
//!     therefore goes beyond the letter of §10.2.3, as the owner decided on
//!     2026-09-11: decryption also fails unless every decoded bit past `p0`
//!     is zero. No honest ciphertext fails this check. Those bits are the
//!     zeros that §10.2.2 step g appends; the final three-bit quantity lies
//!     wholly within `p0` and those zeros, so its trits are `(0, 0)`; and
//!     when the primitive recovers the encryptor's `m'`, every pair decodes
//!     back to the bits it was made from. The check does reject ciphertexts
//!     the oracle accepts, but only ones no honest encryptor produces. Every
//!     check runs, the flags are folded, and the result is selected once.
//! 11. **Key pair validation** (§10.2.4.1, kpv3), applied when a private key
//!     is imported. `F` must be ternary with exactly the prescribed `±1`
//!     counts, and `g` must be "ternary with exactly (dg +1) 1s and dg -1s".
//!     Step c5 sets "g = f × h mod q", but for the `h = f⁻¹ × g × p` of
//!     §10.2.1 step i that product is `p × g`, which is never ternary. The
//!     check is therefore applied to `(f × h mod q) / p`: its coefficients
//!     must be `p` exactly `dg + 1` times, `−p` exactly `dg` times, and 0
//!     otherwise.
//! 12. **Key blobs.** "This standard does not specify the output format for
//!     the key as long as it is unambiguous" (§10.2.1), and §11's ASN.1
//!     covers private keys in product form only. For interoperability this
//!     module uses the reference implementation's framing,
//!     `tag ‖ 0x03 ‖ OID ‖ RE2OSP(h)`, with tag `0x01` for a public key and
//!     `0x02` for a private key. A private key appends `F` in whichever
//!     packing is shorter, always index lists in product form. One packing is
//!     five base-3 digits per octet, least significant first as in MGF-TP-1.
//!     The other is the `+1` and then the `−1` index lists of each polynomial
//!     through RE2OSP.
//! 13. **Public-key plausibility** (§10.2.5.2.2 step a), applied when a
//!     public or private key is imported: "Check that h(1) = g(1)/(1 +
//!     pF(1)) mod q". With the `h = f⁻¹ × g × p` of §10.2.1 step i, `F(1) =
//!     0` and `g(1) = 1`, so the sum of the coefficients of `h` must be `p =
//!     3` mod `q` (the clause's parenthetical "h(1) = 1" describes a key
//!     without the factor `p`). Every key in the vectors satisfies it, an
//!     all-zero `h`, under which encryption would publish the plaintext,
//!     fails it, and so does any single altered coefficient. The centred-norm
//!     test of steps b–f, offered as an example, is not applied.
//!
//! # Side channels
//!
//! Types built on this module live under [`crate::vt`]: variable time.
//! Decryption folds every SVES-3 check, and the one convention 10 adds, into
//! flags selected on once, so a rejected ciphertext runs the same stages as an
//! accepted one.
//! Data-dependent timing remains in these places:
//! - `sData` holds `cl` message octets, so `Hash(sData)` runs one extra
//!   compression per 64 octets of recovered length.
//! - MGF-TP-1 and IGF-2 precompute `minCallsMask` / `minCallsR` hash
//!   blocks, but the loops that read them skip discarded octets, rejected
//!   candidates and repeated indices, so iteration counts follow the hash
//!   output. A further hash call is needed only when the precomputed blocks
//!   run out. For IGF-2 that probability is about 3.7 × 10⁻⁵ per blinding
//!   polynomial for `ees449ep1` (31 SHA-1 blocks give 551 candidates for
//!   268 distinct indices) and below 10⁻¹² for the other sets; for MGF-TP-1
//!   it is below 10⁻⁴⁸.
//! - Sparse convolutions by `F` and by the recovered `r`, and IGF-2's table
//!   of already-drawn indices, touch memory at offsets set by secret indices.
//! - Key-blob parsing and validation, key generation (rejection sampling,
//!   inversion) and the final accept/reject branch are not constant time.
//!
//! # Storage
//!
//! Polynomials are inline `[u16; N]` arrays; wire buffers, sparse index
//! lists and hash pools are heap-allocated. Buffers holding secret-derived
//! data are cleared with [`crate::zeroize_slice`] (volatile writes) before
//! release, and the dense forms of `F`, `f⁻¹` and `g` are built in
//! caller-owned buffers so no copy of them escapes. Wiping is still best
//! effort. Values moved or returned by value can leave copies this module
//! does not reach: the mask and message trit arrays, the hashers' internal
//! state, and the shared multiplier's scratch buffers.

use crate::hash::sha1::Sha1;
use crate::hash::sha2::Sha256;
use crate::Csprng;

// ---- parameter definitions --------------------------------------------------

/// Octets in the encoded message length `octL` (`lLen`, EESS #1 v3.1 §10.2.2).
const LENGTH_OCTETS: usize = 1;

/// Largest hash output this module handles (SHA-256).
const MAX_HASH_OCTETS: usize = 32;

/// Octets before the packed ring element in a key blob: tag, OID length and
/// the three OID octets (convention 12).
pub const KEY_BLOB_HEADER_BYTES: usize = 5;

/// Key-blob tag of a public key (convention 12).
const PUBLIC_KEY_TAG: u8 = 0x01;

/// Key-blob tag of a private key (convention 12).
const PRIVATE_KEY_TAG: u8 = 0x02;

/// Hash function named by a parameter set (EESS #1 v3.1 §9.2); it
/// instantiates both MGF-TP-1 and IGF-2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashKind {
    /// SHA-1, 20-octet output.
    Sha1,
    /// SHA-256, 32-octet output.
    Sha256,
}

impl HashKind {
    /// Output length in octets (`hLen`).
    pub const fn output_len(self) -> usize {
        match self {
            HashKind::Sha1 => 20,
            HashKind::Sha256 => 32,
        }
    }

    /// `Hash(parts[0] ‖ parts[1] ‖ …)` into `out`, which must be exactly
    /// [`Self::output_len`] octets.
    fn digest(self, parts: &[&[u8]], out: &mut [u8]) {
        match self {
            HashKind::Sha1 => {
                let mut h = Sha1::new();
                for &part in parts {
                    h.update(part);
                }
                let mut digest = h.finalize();
                out.copy_from_slice(&digest);
                crate::zeroize_slice(&mut digest);
            }
            HashKind::Sha256 => {
                let mut h = Sha256::new();
                for &part in parts {
                    h.update(part);
                }
                let mut digest = h.finalize();
                out.copy_from_slice(&digest);
                crate::zeroize_slice(&mut digest);
            }
        }
    }
}

/// Shape of the sparse trinary polynomials of a parameter set: the private
/// key component `F` and the blinding value `r` share it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapdoorKind {
    /// One polynomial in `T(df, df)`: `df` coefficients `+1`, `df` `−1`.
    Dense {
        /// Number of `+1` (and of `−1`) coefficients.
        df: usize,
    },
    /// `F₁·F₂ + F₃` with `Fᵢ ∈ T(dfᵢ, dfᵢ)`.
    ProductForm {
        /// Weight parameter of `F₁`.
        df1: usize,
        /// Weight parameter of `F₂`.
        df2: usize,
        /// Weight parameter of `F₃`.
        df3: usize,
    },
}

/// How a private-key blob stores `F` (convention 12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPacking {
    /// Five trits per octet, `N` trits.
    Trits,
    /// The nonzero indices, ⌈log₂ N⌉ bits each.
    Indices,
}

/// Scalar parameters of one SVES-3 parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EesParams {
    /// Ring degree `N`.
    pub n: usize,
    /// `log₂ q`; `q = 2048` for every set here.
    pub logq: usize,
    /// Shape of `F` and of the blinding value `r`.
    pub trapdoor: TrapdoorKind,
    /// `g ∈ T(dg + 1, dg)`.
    pub dg: usize,
    /// Minimum count of each trit value in the message representative.
    pub dm0: usize,
    /// Bits of the random component `b` (a multiple of 8).
    pub db_bits: usize,
    /// IGF-2 candidate width `c`.
    pub c_bits: usize,
    /// Hash blocks IGF-2 computes up front.
    pub min_calls_r: usize,
    /// Hash blocks MGF-TP-1 computes up front.
    pub min_calls_mask: usize,
    /// Bits of the packed public key placed in `sData` (a multiple of 8).
    pub pklen_bits: usize,
    /// The three-octet parameter-set OID that starts `sData`.
    pub oid: [u8; 3],
    /// Hash for MGF-TP-1 and IGF-2.
    pub hash: HashKind,
}

impl EesParams {
    /// Octets of the random component `b` (`bLen`).
    pub const fn b_len(&self) -> usize {
        self.db_bits / 8
    }

    /// Octets of `hTrunc`.
    pub const fn htrunc_len(&self) -> usize {
        self.pklen_bits / 8
    }

    /// The big modulus `q`.
    pub const fn q(&self) -> u32 {
        1u32 << self.logq
    }

    /// `q − 1`, a mask for reduction mod `q`.
    pub const fn q_mask(&self) -> u16 {
        ((1u32 << self.logq) - 1) as u16
    }

    /// Octets of a packed ring element: `⌈N·log₂ q / 8⌉`.
    pub const fn packed_ring_bytes(&self) -> usize {
        (self.n * self.logq).div_ceil(8)
    }

    /// `maxMsgLenBytes`: `⌊⌊N/2⌋·3/8⌋ − lLen − bLen`, which reproduces the
    /// parameter tables (each set module pins its table value).
    pub const fn max_message_bytes(&self) -> usize {
        (self.n / 2) * 3 / 8 - LENGTH_OCTETS - self.b_len()
    }

    /// `maxLen` of decryption (EESS #1 v3.1 §10.2.3 step a): `nLen − 1 −
    /// lLen − bLen` with `nLen = ⌈N/8⌉`. Step k2 clamps a recovered length
    /// above `maxMsgLenBytes` to it (convention 10). It is below
    /// `maxMsgLenBytes` for every set here.
    pub const fn decryption_max_len(&self) -> usize {
        self.n.div_ceil(8) - 1 - LENGTH_OCTETS - self.b_len()
    }

    /// Octets of `M = b ‖ octL ‖ m ‖ p0`.
    const fn padded_message_bytes(&self) -> usize {
        self.b_len() + LENGTH_OCTETS + self.max_message_bytes() + 1
    }

    /// Octets recovered from `N` trits: `⌈3·⌈N/2⌉ / 8⌉`.
    const fn decoded_message_bytes(&self) -> usize {
        (3 * self.n.div_ceil(2)).div_ceil(8)
    }

    /// IGF-2 acceptance bound `2^c − (2^c mod N)`.
    const fn index_limit(&self) -> u32 {
        let span = 1u32 << self.c_bits;
        span - span % (self.n as u32)
    }

    /// Bits per packed index: the bit length of `N − 1`.
    const fn index_bits(&self) -> usize {
        (usize::BITS - (self.n - 1).leading_zeros()) as usize
    }

    /// Total nonzero indices stored for `F`.
    const fn nonzero_indices(&self) -> usize {
        match self.trapdoor {
            TrapdoorKind::Dense { df } => 2 * df,
            TrapdoorKind::ProductForm { df1, df2, df3 } => 2 * (df1 + df2 + df3),
        }
    }

    /// Packing of `F` in a private-key blob (convention 12).
    pub const fn private_key_packing(&self) -> KeyPacking {
        match self.trapdoor {
            TrapdoorKind::ProductForm { .. } => KeyPacking::Indices,
            TrapdoorKind::Dense { .. } => {
                if (self.nonzero_indices() * self.index_bits()).div_ceil(8) <= self.n.div_ceil(5) {
                    KeyPacking::Indices
                } else {
                    KeyPacking::Trits
                }
            }
        }
    }

    /// Octets of the packed `F`.
    pub const fn packed_private_bytes(&self) -> usize {
        match self.private_key_packing() {
            KeyPacking::Trits => self.n.div_ceil(5),
            KeyPacking::Indices => (self.nonzero_indices() * self.index_bits()).div_ceil(8),
        }
    }

    /// Octets of a public-key blob.
    pub const fn public_key_bytes(&self) -> usize {
        KEY_BLOB_HEADER_BYTES + self.packed_ring_bytes()
    }

    /// Octets of a private-key blob: the public-key body plus packed `F`.
    pub const fn private_key_bytes(&self) -> usize {
        self.public_key_bytes() + self.packed_private_bytes()
    }

    /// Octets of a ciphertext.
    pub const fn ciphertext_bytes(&self) -> usize {
        self.packed_ring_bytes()
    }
}

// ---- dense polynomials -------------------------------------------------------

/// Element of `Z_q[x] / (x^N − 1)` with `u16` coefficients.
#[derive(Clone, Copy)]
pub struct Poly<const N: usize> {
    /// Coefficients in increasing degree.
    pub coeffs: [u16; N],
}

impl<const N: usize> Poly<N> {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: [0u16; N] }
    }

    fn wipe(&mut self) {
        crate::zeroize_slice(&mut self.coeffs);
    }
}

fn poly_mul<const N: usize>(r: &mut Poly<N>, a: &Poly<N>, b: &Poly<N>) {
    crate::public_key::ntru_poly_mul::poly_mul_cyclic(&mut r.coeffs, &a.coeffs, &b.coeffs);
}

fn poly_mod_q<const N: usize>(a: &mut Poly<N>, q_mask: u16) {
    for c in a.coeffs.iter_mut() {
        *c &= q_mask;
    }
}

fn poly_scale<const N: usize>(a: &mut Poly<N>, k: u16, q_mask: u16) {
    for c in a.coeffs.iter_mut() {
        *c = c.wrapping_mul(k) & q_mask;
    }
}

// ---- branch-free helpers -----------------------------------------------------

/// 1 when `a == b`, else 0; both operands below 2³¹.
#[inline]
fn ct_eq(a: u32, b: u32) -> u32 {
    ((a ^ b).wrapping_sub(1) >> 31) & 1
}

/// 1 when `a >= b`, else 0; both operands below 2³¹.
#[inline]
fn ct_ge(a: u32, b: u32) -> u32 {
    1 ^ ((a.wrapping_sub(b) >> 31) & 1)
}

/// `if_one` when `bit == 1`, `if_zero` when `bit == 0`.
#[inline]
fn ct_select(bit: u32, if_one: u32, if_zero: u32) -> u32 {
    let mask = bit.wrapping_neg();
    (if_one & mask) | (if_zero & !mask)
}

/// Lift `a ∈ [0, q)` into `[−q/2, q/2)` and reduce mod 3 into `{0, 1, 2}`
/// (convention 10). `a − q ≡ a + 2q (mod 3)` keeps the arithmetic unsigned.
#[inline]
fn centred_mod3(a: u16, q: u32) -> u8 {
    let a = u32::from(a);
    let upper = ct_ge(a, q / 2);
    ((a + 2 * q * upper) % 3) as u8
}

/// Trit `{0, 1, 2}` as the ring value `{0, 1, q − 1}`.
#[inline]
fn lift_trit(t: u8, q_mask: u16) -> u16 {
    let minus = ct_eq(u32::from(t), 2) as u16;
    u16::from(t).wrapping_sub(3 * minus) & q_mask
}

/// 1 when each trit value occurs at least `dm0` times, else 0.
fn weight_ok(trits: &[u8], dm0: usize) -> u32 {
    let (mut zeros, mut ones, mut minus) = (0u32, 0u32, 0u32);
    for &t in trits {
        let t = u32::from(t);
        zeros += ct_eq(t, 0);
        ones += ct_eq(t, 1);
        minus += ct_eq(t, 2);
    }
    let floor = dm0 as u32;
    ct_ge(zeros, floor) & ct_ge(ones, floor) & ct_ge(minus, floor)
}

// ---- sparse trinary polynomials ---------------------------------------------

/// Sparse element of `T(d₊, d₋)`: the degrees of its `+1` and `−1`
/// coefficients, in the order they were drawn or stored.
#[derive(Clone, Eq, PartialEq)]
pub struct TernaryPoly {
    /// Degrees of the `+1` coefficients.
    pub ones: Vec<u16>,
    /// Degrees of the `−1` coefficients.
    pub neg_ones: Vec<u16>,
}

impl Drop for TernaryPoly {
    fn drop(&mut self) {
        // The index lists are the private key `F` or the blinding value `r`.
        crate::zeroize_slice(self.ones.as_mut_slice());
        crate::zeroize_slice(self.neg_ones.as_mut_slice());
    }
}

impl TernaryPoly {
    fn with_capacity(plus: usize, minus: usize) -> Self {
        Self {
            ones: Vec::with_capacity(plus),
            neg_ones: Vec::with_capacity(minus),
        }
    }

    /// Write `self` as a dense polynomial mod `q` into `out`.
    fn dense_into<const N: usize>(&self, q_mask: u16, out: &mut Poly<N>) {
        out.coeffs.fill(0);
        for &i in &self.ones {
            out.coeffs[usize::from(i)] = 1;
        }
        for &i in &self.neg_ones {
            out.coeffs[usize::from(i)] = q_mask;
        }
    }

    /// `out = self · b` in `Z_{2^16}[x] / (x^N − 1)`.
    fn mul_dense<const N: usize>(&self, b: &Poly<N>, out: &mut Poly<N>) {
        out.coeffs.fill(0);
        for (indices, negate) in [(&self.ones, false), (&self.neg_ones, true)] {
            for &index in indices {
                // x^s · b: coefficient k takes b[(k − s) mod N].
                let s = usize::from(index);
                let (head, tail) = b.coeffs.split_at(N - s);
                let (low, high) = out.coeffs.split_at_mut(s);
                for (o, &v) in high.iter_mut().zip(head).chain(low.iter_mut().zip(tail)) {
                    *o = if negate {
                        o.wrapping_sub(v)
                    } else {
                        o.wrapping_add(v)
                    };
                }
            }
        }
    }
}

/// Product-form element `f₁·f₂ + f₃`.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductPoly {
    /// First factor.
    pub f1: TernaryPoly,
    /// Second factor.
    pub f2: TernaryPoly,
    /// Additive term.
    pub f3: TernaryPoly,
}

impl ProductPoly {
    fn mul_dense<const N: usize>(&self, a: &Poly<N>, out: &mut Poly<N>) {
        let mut t1 = Poly::<N>::zero();
        self.f1.mul_dense(a, &mut t1);
        self.f2.mul_dense(&t1, out);
        let mut t3 = Poly::<N>::zero();
        self.f3.mul_dense(a, &mut t3);
        for (o, &v) in out.coeffs.iter_mut().zip(t3.coeffs.iter()) {
            *o = o.wrapping_add(v);
        }
        t1.wipe();
        t3.wipe();
    }

    fn dense_into<const N: usize>(&self, q_mask: u16, out: &mut Poly<N>) {
        let mut f2 = Poly::<N>::zero();
        self.f2.dense_into(q_mask, &mut f2);
        self.f1.mul_dense(&f2, out);
        let mut f3 = Poly::<N>::zero();
        self.f3.dense_into(q_mask, &mut f3);
        for (o, &v) in out.coeffs.iter_mut().zip(f3.coeffs.iter()) {
            *o = o.wrapping_add(v) & q_mask;
        }
        f2.wipe();
        f3.wipe();
    }
}

/// A sparse trinary element with the shape of a parameter set's
/// [`TrapdoorKind`]: the private key component `F` or a blinding value `r`.
#[derive(Clone, Eq, PartialEq)]
pub enum Trapdoor {
    /// One element of `T(df, df)`.
    Dense(TernaryPoly),
    /// `f₁·f₂ + f₃`.
    Product(ProductPoly),
}

impl Trapdoor {
    fn mul_dense<const N: usize>(&self, a: &Poly<N>, out: &mut Poly<N>) {
        match self {
            Trapdoor::Dense(t) => t.mul_dense(a, out),
            Trapdoor::Product(p) => p.mul_dense(a, out),
        }
    }

    fn dense_into<const N: usize>(&self, q_mask: u16, out: &mut Poly<N>) {
        match self {
            Trapdoor::Dense(t) => t.dense_into(q_mask, out),
            Trapdoor::Product(p) => p.dense_into(q_mask, out),
        }
    }

    fn components(&self) -> Vec<&TernaryPoly> {
        match self {
            Trapdoor::Dense(t) => vec![t],
            Trapdoor::Product(p) => vec![&p.f1, &p.f2, &p.f3],
        }
    }

    /// Pack `F` for a private-key blob (convention 12).
    fn write_packed(&self, params: &EesParams, out: &mut [u8]) {
        debug_assert_eq!(out.len(), params.packed_private_bytes());
        match (params.private_key_packing(), self) {
            (KeyPacking::Trits, Trapdoor::Dense(t)) => {
                let mut digits = vec![0u8; params.n.div_ceil(5) * 5];
                for &i in &t.ones {
                    digits[usize::from(i)] = 1;
                }
                for &i in &t.neg_ones {
                    digits[usize::from(i)] = 2;
                }
                for (octet, group) in out.iter_mut().zip(digits.chunks_exact(5)) {
                    *octet = group.iter().rev().fold(0u8, |acc, &d| acc * 3 + d);
                }
                crate::zeroize_slice(&mut digits);
            }
            (KeyPacking::Indices, _) => {
                let bits = params.index_bits() as u32;
                let mut writer = BitWriter::new(out);
                for poly in self.components() {
                    for &i in poly.ones.iter().chain(&poly.neg_ones) {
                        writer.push(u32::from(i), bits);
                    }
                }
                writer.finish();
            }
            (KeyPacking::Trits, Trapdoor::Product(_)) => {
                unreachable!("product-form keys are always index-packed")
            }
        }
    }

    /// Inverse of [`Self::write_packed`]. Rejects a wrong length, a trit
    /// octet `≥ 243`, a nonzero trit past `N − 1`, the wrong number of `±1`
    /// coefficients, an index `≥ N`, an index repeated within a
    /// polynomial's lists or present in both, and set padding bits.
    fn read_packed(bytes: &[u8], params: &EesParams) -> Option<Self> {
        if bytes.len() != params.packed_private_bytes() {
            return None;
        }
        match (params.private_key_packing(), params.trapdoor) {
            (KeyPacking::Trits, TrapdoorKind::Dense { df }) => {
                read_trits(bytes, params.n, df).map(Trapdoor::Dense)
            }
            (KeyPacking::Indices, TrapdoorKind::Dense { df }) => {
                let mut reader = BitReader::new(bytes);
                let t = read_index_lists(&mut reader, params, df)?;
                let used = params.nonzero_indices() * params.index_bits();
                padding_bits_clear(bytes, used).then_some(Trapdoor::Dense(t))
            }
            (KeyPacking::Indices, TrapdoorKind::ProductForm { df1, df2, df3 }) => {
                let mut reader = BitReader::new(bytes);
                let f1 = read_index_lists(&mut reader, params, df1)?;
                let f2 = read_index_lists(&mut reader, params, df2)?;
                let f3 = read_index_lists(&mut reader, params, df3)?;
                let used = params.nonzero_indices() * params.index_bits();
                padding_bits_clear(bytes, used).then_some(Trapdoor::Product(ProductPoly {
                    f1,
                    f2,
                    f3,
                }))
            }
            (KeyPacking::Trits, TrapdoorKind::ProductForm { .. }) => None,
        }
    }
}

/// Trit-packed `F ∈ T(df, df)`: five base-3 digits per octet, least
/// significant first, digit 2 read as −1.
fn read_trits(bytes: &[u8], n: usize, df: usize) -> Option<TernaryPoly> {
    let mut poly = TernaryPoly::with_capacity(df, df);
    for (group, &octet) in bytes.iter().enumerate() {
        if octet >= 243 {
            return None;
        }
        let mut rest = octet;
        for position in group * 5..group * 5 + 5 {
            let digit = rest % 3;
            rest /= 3;
            if digit == 0 {
                continue;
            }
            let list = if digit == 1 {
                &mut poly.ones
            } else {
                &mut poly.neg_ones
            };
            if position >= n || list.len() == df {
                return None;
            }
            list.push(position as u16);
        }
    }
    (poly.ones.len() == df && poly.neg_ones.len() == df).then_some(poly)
}

/// One element of `T(d, d)` from its `+1` list followed by its `−1` list.
fn read_index_lists(
    reader: &mut BitReader<'_>,
    params: &EesParams,
    d: usize,
) -> Option<TernaryPoly> {
    let bits = params.index_bits() as u32;
    let mut poly = TernaryPoly::with_capacity(d, d);
    let mut taken = vec![false; params.n];
    let mut fresh = true;
    for k in 0..2 * d {
        let index = reader.pull(bits) as usize;
        if index >= params.n || taken[index] {
            fresh = false;
            break;
        }
        taken[index] = true;
        let list = if k < d {
            &mut poly.ones
        } else {
            &mut poly.neg_ones
        };
        list.push(index as u16);
    }
    crate::zeroize_slice(&mut taken);
    fresh.then_some(poly)
}

// ---- bit strings (EESS #1 v3.1 §8.1–§8.6) ------------------------------------

/// Appends values most-significant bit first and packs the bits into octets
/// first-bit-high (I2BSP per value, then BS2ROSP).
struct BitWriter<'a> {
    out: &'a mut [u8],
    len: usize,
    acc: u32,
    pending: u32,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        out.fill(0);
        Self {
            out,
            len: 0,
            acc: 0,
            pending: 0,
        }
    }

    fn push(&mut self, value: u32, width: u32) {
        debug_assert!(width <= 16 && value >> width == 0);
        self.acc = (self.acc << width) | value;
        self.pending += width;
        while self.pending >= 8 {
            self.pending -= 8;
            self.out[self.len] = (self.acc >> self.pending) as u8;
            self.len += 1;
            self.acc &= (1 << self.pending) - 1;
        }
    }

    /// Emit a partial final octet with its low-order bits zero.
    fn finish(self) {
        if self.pending > 0 {
            self.out[self.len] = (self.acc << (8 - self.pending)) as u8;
        }
    }
}

impl Drop for BitWriter<'_> {
    fn drop(&mut self) {
        crate::zeroize_slice(core::slice::from_mut(&mut self.acc));
    }
}

/// Reads `width`-bit values most-significant bit first from octets whose
/// first bit is the high-order bit (ROS2BSP, then BS2IP per value). Bits past
/// the end of the input read as zero (convention 8).
struct BitReader<'a> {
    input: &'a [u8],
    next: usize,
    acc: u32,
    avail: u32,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            next: 0,
            acc: 0,
            avail: 0,
        }
    }

    fn pull(&mut self, width: u32) -> u32 {
        debug_assert!(width <= 16);
        while self.avail < width {
            let octet = self.input.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            self.acc = (self.acc << 8) | u32::from(octet);
            self.avail += 8;
        }
        self.avail -= width;
        let value = self.acc >> self.avail;
        self.acc &= (1 << self.avail) - 1;
        value
    }
}

impl Drop for BitReader<'_> {
    fn drop(&mut self) {
        crate::zeroize_slice(core::slice::from_mut(&mut self.acc));
    }
}

/// True when the bits of `bytes` past the first `used_bits` are zero; the
/// caller has already checked `bytes.len() == ⌈used_bits / 8⌉` (ROS2BSP).
fn padding_bits_clear(bytes: &[u8], used_bits: usize) -> bool {
    debug_assert_eq!(bytes.len(), used_bits.div_ceil(8));
    let unused = bytes.len() * 8 - used_bits;
    unused == 0
        || bytes
            .last()
            .is_some_and(|&b| b & ((1u8 << unused) - 1) == 0)
}

/// RE2BSP then BS2ROSP over `values` at `width` bits each (convention 2).
fn pack_values(values: &[u16], width: u32, out: &mut [u8]) {
    let mut writer = BitWriter::new(out);
    for &v in values {
        writer.push(u32::from(v), width);
    }
    writer.finish();
}

/// RE2OSP (EESS #1 v3.1 §8.6.1) of a ring element reduced mod `q`.
fn pack_ring<const N: usize>(p: &Poly<N>, params: &EesParams, out: &mut [u8]) {
    debug_assert_eq!(out.len(), params.packed_ring_bytes());
    debug_assert!(p.coeffs.iter().all(|&c| c <= params.q_mask()));
    pack_values(&p.coeffs, params.logq as u32, out);
}

/// OS2REP (EESS #1 v3.1 §8.6.2); the caller has validated length and padding.
fn unpack_ring<const N: usize>(packed: &[u8], params: &EesParams) -> Poly<N> {
    debug_assert_eq!(packed.len(), params.packed_ring_bytes());
    let mut reader = BitReader::new(packed);
    let mut p = Poly::<N>::zero();
    for c in p.coeffs.iter_mut() {
        *c = reader.pull(params.logq as u32) as u16;
    }
    p
}

/// The mask seed: RE2OSP of `R mod 4` "using q=4" (convention 9).
fn pack_mod4<const N: usize>(p: &Poly<N>) -> Vec<u8> {
    let mut out = vec![0u8; (2 * N).div_ceil(8)];
    let mut writer = BitWriter::new(&mut out);
    for &c in &p.coeffs {
        writer.push(u32::from(c & 3), 2);
    }
    writer.finish();
    out
}

/// `M` as `N` trits, three bits to two trits (convention 8).
fn octets_to_trits<const N: usize>(m: &[u8]) -> [u8; N] {
    let mut reader = BitReader::new(m);
    let mut out = [0u8; N];
    for pair in out.chunks_mut(2) {
        let v = reader.pull(3) as u8;
        pair[0] = v / 3;
        if let Some(second) = pair.get_mut(1) {
            *second = v % 3;
        }
    }
    out
}

/// Inverse of [`octets_to_trits`] into `out` (`⌈3·⌈N/2⌉ / 8⌉` octets).
/// Returns 1 when no pair is `(−1, −1)`, else 0; that pair writes `111`
/// (EESS #1 v3.1 §10.2.3 step h). A lone final trit `t` decodes as the pair
/// `(t, 0)`.
fn trits_to_octets(trits: &[u8], out: &mut [u8]) -> u32 {
    debug_assert_eq!(out.len(), (3 * trits.len().div_ceil(2)).div_ceil(8));
    let mut writer = BitWriter::new(out);
    let mut bad = 0u32;
    for pair in trits.chunks(2) {
        let v = 3 * u32::from(pair[0]) + pair.get(1).map_or(0, |&t| u32::from(t));
        let unused = ct_eq(v, 8);
        bad |= unused;
        writer.push(v - unused, 3);
    }
    writer.finish();
    1 ^ bad
}

// ---- hash-based generators -----------------------------------------------------

/// The octet stream `Hash(Z ‖ I2OSP(0, 4)) ‖ Hash(Z ‖ I2OSP(1, 4)) ‖ …` with
/// `Z = Hash(seed)` (convention 3). `min_calls` blocks are computed up
/// front; later blocks replace the exhausted pool in place.
struct HashStream {
    hash: HashKind,
    z: [u8; MAX_HASH_OCTETS],
    counter: u32,
    pool: Vec<u8>,
    next: usize,
}

impl HashStream {
    fn new(hash: HashKind, seed: &[u8], min_calls: usize) -> Self {
        let hlen = hash.output_len();
        let mut z = [0u8; MAX_HASH_OCTETS];
        hash.digest(&[seed], &mut z[..hlen]);
        let mut stream = Self {
            hash,
            z,
            counter: 0,
            pool: Vec::with_capacity(min_calls.max(1) * hlen),
            next: 0,
        };
        for _ in 0..min_calls {
            stream.append_block();
        }
        stream
    }

    fn append_block(&mut self) {
        let hlen = self.hash.output_len();
        let mut block = [0u8; MAX_HASH_OCTETS];
        self.hash.digest(
            &[&self.z[..hlen], &self.counter.to_be_bytes()],
            &mut block[..hlen],
        );
        self.pool.extend_from_slice(&block[..hlen]);
        crate::zeroize_slice(&mut block);
        self.counter += 1;
    }

    fn next_octet(&mut self) -> u8 {
        if self.next == self.pool.len() {
            crate::zeroize_slice(self.pool.as_mut_slice());
            self.pool.clear();
            self.next = 0;
            self.append_block();
        }
        let octet = self.pool[self.next];
        self.next += 1;
        octet
    }
}

impl Drop for HashStream {
    fn drop(&mut self) {
        crate::zeroize_slice(&mut self.z);
        crate::zeroize_slice(self.pool.as_mut_slice());
    }
}

/// MGF-TP-1 (convention 4): `N` trits in `{0, 1, 2}` from `seed`.
fn mgf_tp1<const N: usize>(seed: &[u8], params: &EesParams) -> [u8; N] {
    let mut stream = HashStream::new(params.hash, seed, params.min_calls_mask);
    let mut out = [0u8; N];
    let mut filled = 0;
    while filled < N {
        let octet = stream.next_octet();
        if octet >= 243 {
            continue;
        }
        let mut rest = octet;
        for slot in out[filled..].iter_mut().take(5) {
            *slot = rest % 3;
            rest /= 3;
            filled += 1;
        }
    }
    out
}

/// IGF-2 (convention 5).
struct IndexGenerator {
    stream: HashStream,
    n: u32,
    c: u32,
    limit: u32,
    reservoir: u32,
    reservoir_bits: u32,
}

impl IndexGenerator {
    fn new(seed: &[u8], params: &EesParams) -> Self {
        Self {
            stream: HashStream::new(params.hash, seed, params.min_calls_r),
            n: params.n as u32,
            c: params.c_bits as u32,
            limit: params.index_limit(),
            reservoir: 0,
            reservoir_bits: 0,
        }
    }

    fn next_index(&mut self) -> u16 {
        loop {
            while self.reservoir_bits < self.c {
                self.reservoir = (self.reservoir << 8) | u32::from(self.stream.next_octet());
                self.reservoir_bits += 8;
            }
            self.reservoir_bits -= self.c;
            let candidate = self.reservoir >> self.reservoir_bits;
            self.reservoir &= (1 << self.reservoir_bits) - 1;
            if candidate < self.limit {
                return (candidate % self.n) as u16;
            }
        }
    }

    /// An element of `T(plus, minus)`: first the `+1` indices, then the
    /// `−1` indices, skipping repeats (EESS #1 v3.1 §7.3.1.1).
    fn ternary(&mut self, plus: usize, minus: usize) -> TernaryPoly {
        let mut poly = TernaryPoly::with_capacity(plus, minus);
        let mut taken = vec![false; self.n as usize];
        for (list, count) in [(&mut poly.ones, plus), (&mut poly.neg_ones, minus)] {
            while list.len() < count {
                let index = self.next_index();
                if !taken[usize::from(index)] {
                    taken[usize::from(index)] = true;
                    list.push(index);
                }
            }
        }
        crate::zeroize_slice(&mut taken);
        poly
    }
}

impl Drop for IndexGenerator {
    fn drop(&mut self) {
        crate::zeroize_slice(core::slice::from_mut(&mut self.reservoir));
    }
}

/// The blinding polynomial for `sData` (EESS #1 v3.1 §9.3.2.2).
fn blinding_value(sdata: &[u8], params: &EesParams) -> Trapdoor {
    let mut igf = IndexGenerator::new(sdata, params);
    match params.trapdoor {
        TrapdoorKind::Dense { df } => Trapdoor::Dense(igf.ternary(df, df)),
        TrapdoorKind::ProductForm { df1, df2, df3 } => Trapdoor::Product(ProductPoly {
            f1: igf.ternary(df1, df1),
            f2: igf.ternary(df2, df2),
            f3: igf.ternary(df3, df3),
        }),
    }
}

// ---- inversion in (Z/qZ)[x] / (x^N − 1) -----------------------------------------

fn poly_trim(p: &mut Vec<u8>) {
    while p.len() > 1 && p.last() == Some(&0) {
        p.pop();
    }
}

fn poly_deg(p: &[u8]) -> Option<usize> {
    p.iter().rposition(|&c| c != 0)
}

/// Inverse in `F₂[x] / (x^N − 1)` by the extended Euclidean algorithm
/// (EESS #1 v3.1 §7.3.4.2–§7.3.4.3).
fn poly_inverse_mod2_cyclic(a_coeffs: &[u8]) -> Option<Vec<u8>> {
    let n = a_coeffs.len();
    // Capacity for the largest Bézout coefficient, so no buffer holding
    // key-derived bits is ever reallocated and left unwiped.
    let capacity = 2 * n + 2;
    let mut r0 = Vec::with_capacity(capacity);
    r0.resize(n + 1, 0u8);
    r0[0] = 1;
    r0[n] = 1;
    let mut r1 = Vec::with_capacity(capacity);
    r1.extend(a_coeffs.iter().map(|&c| c & 1));
    poly_trim(&mut r1);
    let mut t0 = Vec::with_capacity(capacity);
    t0.push(0u8);
    let mut t1 = Vec::with_capacity(capacity);
    t1.push(1u8);

    while let Some(d1) = poly_deg(&r1) {
        let Some(d0) = poly_deg(&r0) else {
            std::mem::swap(&mut r0, &mut r1);
            std::mem::swap(&mut t0, &mut t1);
            break;
        };
        if d0 < d1 {
            std::mem::swap(&mut r0, &mut r1);
            std::mem::swap(&mut t0, &mut t1);
            continue;
        }
        let shift = d0 - d1;
        for (dst, &src) in r0[shift..=shift + d1].iter_mut().zip(&r1[..=d1]) {
            *dst ^= src;
        }
        poly_trim(&mut r0);
        let needed = t0.len().max(t1.len() + shift);
        if t0.len() < needed {
            t0.resize(needed, 0);
        }
        for (dst, &src) in t0[shift..].iter_mut().zip(&t1) {
            *dst ^= src;
        }
    }

    let result = (r0.len() == 1 && r0[0] == 1).then(|| {
        let mut out = vec![0u8; n];
        for (i, &c) in t0.iter().enumerate() {
            out[i % n] ^= c & 1;
        }
        out
    });
    for buffer in [&mut r0, &mut r1, &mut t0, &mut t1] {
        crate::zeroize_slice(buffer.as_mut_slice());
    }
    result
}

/// Inverse mod `q = 2^logq` (EESS #1 v3.1 §7.3.4), written into `b`: invert
/// mod 2, then Newton-lift `b ← b·(2 − a·b)`, doubling the 2-adic precision
/// each pass. Returns false, leaving `b` zero, when `a` has no inverse.
fn poly_inverse_mod_q_cyclic<const N: usize>(
    a: &Poly<N>,
    params: &EesParams,
    b: &mut Poly<N>,
) -> bool {
    let q_mask = params.q_mask();
    b.coeffs.fill(0);
    let mut a_mod2: Vec<u8> = a.coeffs.iter().map(|&c| (c & 1) as u8).collect();
    let inverse_mod2 = poly_inverse_mod2_cyclic(&a_mod2);
    crate::zeroize_slice(&mut a_mod2);
    let Some(mut inverse_mod2) = inverse_mod2 else {
        return false;
    };
    for (bc, &ic) in b.coeffs.iter_mut().zip(inverse_mod2.iter()) {
        *bc = u16::from(ic);
    }
    crate::zeroize_slice(&mut inverse_mod2);

    let mut ab = Poly::<N>::zero();
    let mut correction = Poly::<N>::zero();
    let mut next = Poly::<N>::zero();
    let mut precision: u32 = 2;
    while precision < params.q() {
        poly_mul(&mut ab, a, b);
        for (c, &v) in correction.coeffs.iter_mut().zip(ab.coeffs.iter()) {
            *c = 0u16.wrapping_sub(v) & q_mask;
        }
        correction.coeffs[0] = correction.coeffs[0].wrapping_add(2) & q_mask;
        poly_mul(&mut next, b, &correction);
        poly_mod_q(&mut next, q_mask);
        b.coeffs.copy_from_slice(&next.coeffs);
        precision = precision.saturating_mul(precision);
    }
    ab.wipe();
    correction.wipe();
    next.wipe();
    true
}

fn invertible_mod_q<const N: usize>(p: &Poly<N>) -> bool {
    // q is a power of two, so p is invertible mod q exactly when it is
    // invertible mod 2.
    let mut bits: Vec<u8> = p.coeffs.iter().map(|&c| (c & 1) as u8).collect();
    let inverse = poly_inverse_mod2_cyclic(&bits);
    crate::zeroize_slice(&mut bits);
    match inverse {
        Some(mut inverse) => {
            crate::zeroize_slice(&mut inverse);
            true
        }
        None => false,
    }
}

// ---- key blobs and ciphertexts (convention 12) ----------------------------------

fn blob_body<'a>(blob: &'a [u8], tag: u8, params: &EesParams) -> Option<&'a [u8]> {
    if blob.len() < KEY_BLOB_HEADER_BYTES {
        return None;
    }
    let (header, body) = blob.split_at(KEY_BLOB_HEADER_BYTES);
    let expected = [tag, 3, params.oid[0], params.oid[1], params.oid[2]];
    (header == expected).then_some(body)
}

fn packed_ring_canonical(packed: &[u8], params: &EesParams) -> bool {
    packed.len() == params.packed_ring_bytes() && padding_bits_clear(packed, params.n * params.logq)
}

/// The plausibility test of EESS #1 v3.1 §10.2.5.2.2 step a (convention 13):
/// `h(1)`, the sum of the packed coefficients, must be `p = 3` mod `q`.
fn public_key_plausible(packed_h: &[u8], params: &EesParams) -> bool {
    let mut reader = BitReader::new(packed_h);
    let h_at_one = (0..params.n).fold(0u32, |sum, _| sum + reader.pull(params.logq as u32));
    h_at_one % params.q() == 3
}

/// Validate a public-key blob (framing, canonical packing and the
/// plausibility test of convention 13) and return its packed `h`.
pub fn public_key_from_blob<'a>(blob: &'a [u8], params: &EesParams) -> Option<&'a [u8]> {
    let packed = blob_body(blob, PUBLIC_KEY_TAG, params)?;
    (packed_ring_canonical(packed, params) && public_key_plausible(packed, params))
        .then_some(packed)
}

/// The public-key blob for a packed `h`.
pub fn public_key_blob(packed_h: &[u8], params: &EesParams) -> Vec<u8> {
    debug_assert_eq!(packed_h.len(), params.packed_ring_bytes());
    let mut blob = Vec::with_capacity(params.public_key_bytes());
    blob.extend_from_slice(&[PUBLIC_KEY_TAG, 3]);
    blob.extend_from_slice(&params.oid);
    blob.extend_from_slice(packed_h);
    blob
}

/// Validate a private-key blob, including the plausibility test of
/// convention 13 and key pair validation kpv3 (convention 11); return `F`
/// and the packed `h` it carries.
pub fn private_key_from_blob<'a, const N: usize>(
    blob: &'a [u8],
    params: &EesParams,
) -> Option<(Trapdoor, &'a [u8])> {
    if blob.len() != params.private_key_bytes() {
        return None;
    }
    let body = blob_body(blob, PRIVATE_KEY_TAG, params)?;
    let (packed_h, packed_f) = body.split_at(params.packed_ring_bytes());
    if !packed_ring_canonical(packed_h, params) || !public_key_plausible(packed_h, params) {
        return None;
    }
    let trapdoor = Trapdoor::read_packed(packed_f, params)?;
    key_pair_valid::<N>(&trapdoor, packed_h, params).then_some((trapdoor, packed_h))
}

/// kpv3 (EESS #1 v3.1 §10.2.4.1 steps c–e, convention 11): with
/// `f = 1 + 3F`, `f × h mod q` must be `3g` for a `g` with exactly `dg + 1`
/// coefficients `+1`, `dg` coefficients `−1` and no others. `F`'s own
/// weights were checked when it was unpacked.
fn key_pair_valid<const N: usize>(
    trapdoor: &Trapdoor,
    packed_h: &[u8],
    params: &EesParams,
) -> bool {
    debug_assert_eq!(params.n, N);
    let q_mask = params.q_mask();
    let h = unpack_ring::<N>(packed_h, params);
    let mut fh = Poly::<N>::zero();
    trapdoor.mul_dense(&h, &mut fh);
    let (mut ones, mut minus, mut other) = (0usize, 0usize, 0usize);
    for (&hc, &fc) in h.coeffs.iter().zip(fh.coeffs.iter()) {
        let three_g = hc.wrapping_add(fc.wrapping_mul(3)) & q_mask;
        if three_g == 3 {
            ones += 1;
        } else if three_g == q_mask - 2 {
            minus += 1;
        } else if three_g != 0 {
            other += 1;
        }
    }
    fh.wipe();
    other == 0 && ones == params.dg + 1 && minus == params.dg
}

/// The private-key blob for `F` and packed `h`.
pub fn private_key_blob(trapdoor: &Trapdoor, packed_h: &[u8], params: &EesParams) -> Vec<u8> {
    debug_assert_eq!(packed_h.len(), params.packed_ring_bytes());
    let mut blob = vec![0u8; params.private_key_bytes()];
    blob[..2].copy_from_slice(&[PRIVATE_KEY_TAG, 3]);
    blob[2..KEY_BLOB_HEADER_BYTES].copy_from_slice(&params.oid);
    let (public, private) = blob[KEY_BLOB_HEADER_BYTES..].split_at_mut(params.packed_ring_bytes());
    public.copy_from_slice(packed_h);
    trapdoor.write_packed(params, private);
    blob
}

/// True when `bytes` is a canonically packed ciphertext ring element.
pub fn ciphertext_is_canonical(bytes: &[u8], params: &EesParams) -> bool {
    packed_ring_canonical(bytes, params)
}

// ---- key generation ----------------------------------------------------------

/// Consecutive rejected 32-bit draws after which the index sampler declares
/// the random source broken. A draw is rejected with probability
/// `(2^32 mod bound) / 2^32`, at most `bound / 2^32 < 2^-21` for every ring
/// degree here, so a working source comes nowhere near this.
const INDEX_DRAW_LIMIT: usize = 256;

/// Consecutive refused candidates after which key generation declares the
/// random source broken. Modulo 2, `f = 1 + 3F` and `g ∈ T(dg + 1, dg)` both
/// take the value 1 at `x = 1`, so a candidate is refused only when it shares
/// a factor with `Φ_N(x)` over GF(2). `Φ_N` splits into `(N − 1) / ord_N(2)`
/// irreducibles of degree `ord_N(2)`, and a candidate is divisible by one of
/// them with probability at most their number times `2^-ord_N(2)`. For the
/// degrees shipped, `ord_N(2)` is 200, 442, 224, 540, 676, 543, 1170 and 1498
/// for `N` = 401, 443, 449, 541, 677, 1087, 1171 and 1499 (the test
/// `phi_n_splits_over_gf2_as_tabulated` checks each), so the worst case is
/// `N = 401`, two factors of degree 200: a candidate is refused with
/// probability below `2·2^-200 = 2^-199`, and eight refusals in a row do
/// not happen to a working source. The tests
/// `key_generation_panics_after_eight_non_invertible_f` and `…_g` reach the
/// limit with a scripted source.
const KEYGEN_DRAW_LIMIT: usize = 8;

/// Consecutive random components `b` after which encryption declares the
/// random source broken. An attempt is refused when the masked message
/// representative has fewer than `dm0` of some trit value; the exact
/// probability per set is in the module documentation ("Step p refusals")
/// and is highest for `ees449ep1`, 0.155 per attempt. Sixty-four refusals in
/// a row then have probability `0.155^64 < 2^-172`.
const ENCRYPT_ATTEMPT_LIMIT: usize = 64;

/// A uniform integer in `[0, bound)` by rejection sampling on 32-bit draws:
/// a draw `v` is accepted when `v < 2^32 − (2^32 mod bound)`.
///
/// # Panics
///
/// Panics after [`INDEX_DRAW_LIMIT`] consecutive rejections, which only a
/// broken random source produces.
fn random_below<R: Csprng>(rng: &mut R, bound: u32) -> u32 {
    let threshold = u32::MAX - (u32::MAX % bound);
    for _ in 0..INDEX_DRAW_LIMIT {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        crate::zeroize_slice(&mut buf);
        if v < threshold {
            return v % bound;
        }
    }
    panic!(
        "NTRUEncrypt sampling: {INDEX_DRAW_LIMIT} consecutive 32-bit draws were all rejected \
         (a working source has fewer than one in 2^21 rejected); the random source is broken"
    );
}

/// The permutation buffer of [`random_ternary`]. Its leading entries are the
/// drawn indices, so it is wiped however the sampler exits, a panic of
/// [`random_below`] included.
struct Permutation(Vec<u16>);

impl Drop for Permutation {
    fn drop(&mut self) {
        crate::zeroize_slice(self.0.as_mut_slice());
    }
}

/// A uniformly random element of `T(plus, minus)` (partial Fisher–Yates):
/// entry `i` of the identity permutation is swapped with entry `i + u` for
/// `u` uniform in `[0, n − i)`, for `i` below `plus + minus`; the first
/// `plus` entries are then the `+1` degrees and the next `minus` the `−1`
/// degrees.
fn random_ternary<R: Csprng>(rng: &mut R, n: usize, plus: usize, minus: usize) -> TernaryPoly {
    debug_assert!(plus + minus <= n);
    let mut order = Permutation((0..n as u16).collect());
    for i in 0..plus + minus {
        let j = i + random_below(rng, (n - i) as u32) as usize;
        order.0.swap(i, j);
    }
    let mut poly = TernaryPoly::with_capacity(plus, minus);
    poly.ones.extend_from_slice(&order.0[..plus]);
    poly.neg_ones
        .extend_from_slice(&order.0[plus..plus + minus]);
    drop(order);
    poly.ones.sort_unstable();
    poly.neg_ones.sort_unstable();
    poly
}

fn random_trapdoor<R: Csprng>(rng: &mut R, params: &EesParams) -> Trapdoor {
    let n = params.n;
    match params.trapdoor {
        TrapdoorKind::Dense { df } => Trapdoor::Dense(random_ternary(rng, n, df, df)),
        TrapdoorKind::ProductForm { df1, df2, df3 } => Trapdoor::Product(ProductPoly {
            f1: random_ternary(rng, n, df1, df1),
            f2: random_ternary(rng, n, df2, df2),
            f3: random_ternary(rng, n, df3, df3),
        }),
    }
}

/// Failure modes of the EES encrypt / decrypt routines. Wire-length and
/// padding-bit violations are rejected earlier, by the typed
/// `from_wire_bytes` constructors in the per-set wrappers, so only these
/// two conditions surface as an `Err`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtruEesError {
    /// The plaintext handed to `encrypt` is longer than the parameter set's
    /// `maxMsgLenBytes` (EESS #1 v3.1 §10.2.2 step b, "message too long").
    MessageTooLong,
    /// Decryption output "fail" (EESS #1 v3.1 §10.2.3 step p): the recovered
    /// message representative had fewer than `dm0` of some trit value, held
    /// the unused trit pair, carried a length above `maxMsgLenBytes`, nonzero
    /// padding or nonzero bits past the padding, or did not re-encrypt to the
    /// ciphertext. The check on the bits past the padding goes beyond §10.2.3:
    /// it closes a malleability of `ees443ep1` and `ees1499ep1`, and no honest
    /// ciphertext fails it. The cause is deliberately not distinguished, and
    /// is reported only after every check has run.
    InvalidCiphertext,
}

/// Key generation (convention 7). Returns the packed `h` and `F`.
///
/// # Panics
///
/// Panics when [`KEYGEN_DRAW_LIMIT`] consecutive candidates for `F` or for
/// `g` are all non-invertible, which only a broken random source produces.
pub fn keygen<const N: usize, R: Csprng>(params: &EesParams, rng: &mut R) -> (Vec<u8>, Trapdoor) {
    debug_assert_eq!(params.n, N);
    let q_mask = params.q_mask();

    // Steps a–e: F at random, f = 1 + 3F, until f⁻¹ mod q exists.
    let mut f_inv = Poly::<N>::zero();
    let big_f = 'draw: {
        for _ in 0..KEYGEN_DRAW_LIMIT {
            let big_f = random_trapdoor(rng, params);
            let mut f = Poly::<N>::zero();
            big_f.dense_into(q_mask, &mut f);
            poly_scale(&mut f, 3, q_mask);
            f.coeffs[0] = f.coeffs[0].wrapping_add(1) & q_mask;
            let invertible = poly_inverse_mod_q_cyclic(&f, params, &mut f_inv);
            f.wipe();
            if invertible {
                break 'draw big_f;
            }
        }
        f_inv.wipe();
        panic!(
            "NTRUEncrypt key generation: {KEYGEN_DRAW_LIMIT} consecutive candidates for F gave \
             a non-invertible f = 1 + 3F; the random source is broken"
        );
    };

    // Steps f–i: g ∈ T(dg + 1, dg) until invertible, h = 3·f⁻¹·g mod q.
    let mut h = 'draw: {
        for _ in 0..KEYGEN_DRAW_LIMIT {
            let g = random_ternary(rng, N, params.dg + 1, params.dg);
            let mut g_dense = Poly::<N>::zero();
            g.dense_into(q_mask, &mut g_dense);
            let invertible = invertible_mod_q(&g_dense);
            let mut h = Poly::<N>::zero();
            if invertible {
                poly_mul(&mut h, &g_dense, &f_inv);
            }
            g_dense.wipe();
            if invertible {
                break 'draw h;
            }
        }
        f_inv.wipe();
        panic!(
            "NTRUEncrypt key generation: {KEYGEN_DRAW_LIMIT} consecutive candidates for g were \
             non-invertible; the random source is broken"
        );
    };
    f_inv.wipe();
    poly_scale(&mut h, 3, q_mask);

    let mut packed_h = vec![0u8; params.packed_ring_bytes()];
    pack_ring(&h, params, &mut packed_h);
    (packed_h, big_f)
}

/// SVES-3 encryption (EESS #1 v3.1 §10.2.2; conventions 3–6, 8 and 9). `packed_h` is
/// the packed public key; one random component `b` of `bLen` octets is drawn
/// from `rng` per attempt.
///
/// # Panics
///
/// Panics when [`ENCRYPT_ATTEMPT_LIMIT`] consecutive attempts all fail the
/// step p weight check, which only a broken random source produces.
pub fn encrypt<const N: usize, R: Csprng>(
    packed_h: &[u8],
    msg: &[u8],
    rng: &mut R,
    params: &EesParams,
) -> Result<Vec<u8>, NtruEesError> {
    debug_assert_eq!(params.n, N);
    let max_len = params.max_message_bytes();
    // Steps a–b.
    if msg.len() > max_len {
        return Err(NtruEesError::MessageTooLong);
    }
    let q_mask = params.q_mask();
    let b_len = params.b_len();
    let h = unpack_ring::<N>(packed_h, params);
    let h_trunc = &packed_h[..params.htrunc_len()];

    let mut b = vec![0u8; b_len];
    let mut padded = vec![0u8; params.padded_message_bytes()];
    let mut sdata = Vec::with_capacity(params.oid.len() + msg.len() + b_len + h_trunc.len());
    let mut ciphertext = None;
    for _ in 0..ENCRYPT_ATTEMPT_LIMIT {
        // Step c.
        rng.fill_bytes(&mut b);
        // Steps d–e: M = b ‖ octL ‖ m ‖ p0.
        let (head, rest) = padded.split_at_mut(b_len);
        head.copy_from_slice(&b);
        rest[0] = msg.len() as u8;
        rest[LENGTH_OCTETS..LENGTH_OCTETS + msg.len()].copy_from_slice(msg);
        rest[LENGTH_OCTETS + msg.len()..].fill(0);
        // Step i: sData = OID ‖ m ‖ b ‖ hTrunc.
        sdata.clear();
        sdata.extend_from_slice(&params.oid);
        sdata.extend_from_slice(msg);
        sdata.extend_from_slice(&b);
        sdata.extend_from_slice(h_trunc);
        // Steps j–k: r from sData, R = r·h mod q.
        let r = blinding_value(&sdata, params);
        let mut big_r = Poly::<N>::zero();
        r.mul_dense(&h, &mut big_r);
        poly_mod_q(&mut big_r, q_mask);
        // Steps f–h and l–o: m' = trits(M) + MGF-TP-1(RE2OSP(R mod 4)) mod 3.
        let mut seed = pack_mod4(&big_r);
        let mut mask = mgf_tp1::<N>(&seed, params);
        let mut representative = octets_to_trits::<N>(&padded);
        for (t, &m) in representative.iter_mut().zip(mask.iter()) {
            *t = (*t + m) % 3;
        }
        crate::zeroize_slice(&mut seed);
        crate::zeroize_slice(&mut mask);
        // Step p: minimum-weight check; on failure draw a new b.
        if weight_ok(&representative, params.dm0) == 0 {
            crate::zeroize_slice(&mut representative);
            big_r.wipe();
            continue;
        }
        // Step q: e = R + m' mod q.
        let mut e = big_r;
        for (c, &t) in e.coeffs.iter_mut().zip(representative.iter()) {
            *c = c.wrapping_add(lift_trit(t, q_mask)) & q_mask;
        }
        let mut out = vec![0u8; params.ciphertext_bytes()];
        pack_ring(&e, params, &mut out);
        crate::zeroize_slice(&mut representative);
        big_r.wipe();
        e.wipe();
        ciphertext = Some(out);
        break;
    }
    crate::zeroize_slice(&mut b);
    crate::zeroize_slice(&mut padded);
    crate::zeroize_slice(sdata.as_mut_slice());
    let ciphertext = ciphertext.unwrap_or_else(|| {
        panic!(
            "NTRUEncrypt encryption: {ENCRYPT_ATTEMPT_LIMIT} consecutive random components b \
             gave a message representative below the dm0 weight; the random source is broken"
        )
    });
    Ok(ciphertext)
}

/// SVES-3 decryption (EESS #1 v3.1 §10.2.3; conventions 3–6, 8 and 10).
/// `trapdoor` is `F`, `packed_h` the packed public key and `ct` a
/// canonically packed ciphertext.
pub fn decrypt<const N: usize>(
    trapdoor: &Trapdoor,
    packed_h: &[u8],
    ct: &[u8],
    params: &EesParams,
) -> Result<Vec<u8>, NtruEesError> {
    recover::<N>(trapdoor, packed_h, ct, params).select()
}

/// SVES-3 decryption's state at its accept/reject selection.
struct Recovered {
    /// `maxMsgLenBytes` octets: the candidate message `cm` in the first `cl`,
    /// zeros after.
    message: Vec<u8>,
    /// The candidate length `cl`; when it exceeded `maxMsgLenBytes` it was
    /// clamped to the `maxLen` of §10.2.3 step a
    /// ([`EesParams::decryption_max_len`]).
    cl: usize,
    /// 1 when every check of EESS #1 v3.1 §10.2.3 passes (steps c, h, k and
    /// o), else 0.
    listed_checks: u32,
    /// 1 when every decoded bit past `M` is zero, else 0: the check this
    /// module adds beyond §10.2.3 (convention 10).
    past_message_zero: u32,
}

impl Recovered {
    /// Step p, with the check of convention 10 folded in: the single
    /// selection.
    fn select(self) -> Result<Vec<u8>, NtruEesError> {
        let Recovered {
            mut message,
            cl,
            listed_checks,
            past_message_zero,
        } = self;
        if listed_checks & past_message_zero == 1 {
            message.truncate(cl);
            Ok(message)
        } else {
            crate::zeroize_slice(&mut message);
            Err(NtruEesError::InvalidCiphertext)
        }
    }
}

/// Steps b–o of SVES-3 decryption and the check of convention 10. Every
/// check runs whatever the ciphertext and folds into its flag without a
/// branch; `Recovered::select` then makes the one selection.
fn recover<const N: usize>(
    trapdoor: &Trapdoor,
    packed_h: &[u8],
    ct: &[u8],
    params: &EesParams,
) -> Recovered {
    debug_assert_eq!(params.n, N);
    // The decoded buffer is indexed up to the end of M below.
    assert!(
        params.decoded_message_bytes() >= params.padded_message_bytes(),
        "N trits decode to at least the octets of M"
    );
    let q_mask = params.q_mask();
    let b_len = params.b_len();
    let max_len = params.max_message_bytes();
    // Step a: maxLen = nLen − 1 − lLen − bLen with nLen = ⌈N/8⌉.
    let clamp_len = params.decryption_max_len();
    let e = unpack_ring::<N>(ct, params);

    // Steps b–c: ci = (e + 3·F·e mod q) lifted and reduced mod 3; weights.
    let mut fe = Poly::<N>::zero();
    trapdoor.mul_dense(&e, &mut fe);
    let mut ci = [0u8; N];
    for ((t, &ec), &fc) in ci.iter_mut().zip(e.coeffs.iter()).zip(fe.coeffs.iter()) {
        let a = ec.wrapping_add(fc.wrapping_mul(3)) & q_mask;
        *t = centred_mod3(a, params.q());
    }
    fe.wipe();
    let mut ok = weight_ok(&ci, params.dm0);

    // Steps d, e and s: cR = e − ci mod q, seed = RE2OSP(cR mod 4).
    let mut c_r = e;
    for (c, &t) in c_r.coeffs.iter_mut().zip(ci.iter()) {
        *c = c.wrapping_sub(lift_trit(t, q_mask)) & q_mask;
    }
    let mut seed = pack_mod4(&c_r);

    // Steps f–j: cM = trits⁻¹(ci − MGF-TP-1(seed) mod 3).
    let mut mask = mgf_tp1::<N>(&seed, params);
    let mut representative = ci;
    for (t, &m) in representative.iter_mut().zip(mask.iter()) {
        *t = (*t + 3 - m) % 3;
    }
    let mut padded = vec![0u8; params.decoded_message_bytes()];
    ok &= trits_to_octets(&representative, &mut padded);

    // Step k: cb, cl (above maxMsgLenBytes: fail, and clamped to step a's
    // maxLen) and the zero padding, every octet position visited whatever
    // cl is.
    let cl_raw = u32::from(padded[b_len]);
    let too_long = 1 ^ ct_ge(max_len as u32, cl_raw);
    ok &= 1 ^ too_long;
    let cl = ct_select(too_long, clamp_len as u32, cl_raw) as usize;
    let body = b_len + LENGTH_OCTETS;
    let mut message = vec![0u8; max_len];
    let mut stray = 0u32;
    for j in 0..=max_len {
        let octet = u32::from(padded[body + j]);
        let in_padding = ct_ge(j as u32, cl as u32);
        stray |= octet & in_padding.wrapping_neg();
        if let Some(slot) = message.get_mut(j) {
            *slot = (octet & (1 ^ in_padding).wrapping_neg()) as u8;
        }
    }
    ok &= ct_eq(stray, 0);

    // Beyond §10.2.3 (convention 10): the decoded bits past M, which honest
    // encoding fills with the zeros of §10.2.2 step g. `trits_to_octets`
    // leaves the other bits of those octets zero, so whole octets are tested.
    let mut past = 0u32;
    for &octet in &padded[params.padded_message_bytes()..] {
        past |= u32::from(octet);
    }
    let past_message_zero = ct_eq(past, 0);

    // Steps l–n: sData = OID ‖ cm ‖ cb ‖ hTrunc, cr, cR' = h·cr mod q.
    let h_trunc = &packed_h[..params.htrunc_len()];
    let mut sdata = Vec::with_capacity(params.oid.len() + max_len + b_len + h_trunc.len());
    sdata.extend_from_slice(&params.oid);
    sdata.extend_from_slice(&message[..cl]);
    sdata.extend_from_slice(&padded[..b_len]);
    sdata.extend_from_slice(h_trunc);
    let cr = blinding_value(&sdata, params);
    let h = unpack_ring::<N>(packed_h, params);
    let mut c_r_prime = Poly::<N>::zero();
    cr.mul_dense(&h, &mut c_r_prime);
    poly_mod_q(&mut c_r_prime, q_mask);

    // Step o: compare every coefficient.
    let mut diff = 0u16;
    for (&x, &y) in c_r_prime.coeffs.iter().zip(c_r.coeffs.iter()) {
        diff |= x ^ y;
    }
    ok &= ct_eq(u32::from(diff), 0);

    crate::zeroize_slice(&mut ci);
    crate::zeroize_slice(&mut representative);
    crate::zeroize_slice(&mut mask);
    crate::zeroize_slice(&mut seed);
    crate::zeroize_slice(&mut padded);
    crate::zeroize_slice(sdata.as_mut_slice());
    c_r.wipe();
    c_r_prime.wipe();

    Recovered {
        message,
        cl,
        listed_checks: ok,
        past_message_zero,
    }
}

// ---- per-set wrapper macro --------------------------------------------------
//
// Each parameter set is one invocation: typed public-key, private-key and
// ciphertext wrappers plus a namespace type with `keygen` / `encrypt` /
// `decrypt`, all delegating to the generic routines above.

macro_rules! define_ees_set {
    (
        namespace = $type_name:ident,
        public_key = $pk_ty:ident,
        private_key = $sk_ty:ident,
        ciphertext = $ct_ty:ident,
        name = $name:literal,
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
        public_key_bytes = $pk_bytes:expr,
        private_key_bytes = $sk_bytes:expr,
        ciphertext_bytes = $ct_bytes:expr,
        max_message_bytes = $max_msg:expr $(,)?
    ) => {
        use $crate::public_key::ntru_ees_core::{
            ciphertext_is_canonical as __ees_ciphertext_is_canonical, decrypt as __ees_decrypt,
            encrypt as __ees_encrypt, keygen as __ees_keygen,
            private_key_blob as __ees_private_key_blob,
            private_key_from_blob as __ees_private_key_from_blob,
            public_key_blob as __ees_public_key_blob,
            public_key_from_blob as __ees_public_key_from_blob, EesParams, HashKind, NtruEesError,
            Trapdoor, TrapdoorKind, KEY_BLOB_HEADER_BYTES,
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

        /// Octets of a public-key blob.
        pub const PUBLIC_KEY_BYTES: usize = PARAMS.public_key_bytes();
        /// Octets of a private-key blob.
        pub const PRIVATE_KEY_BYTES: usize = PARAMS.private_key_bytes();
        /// Octets of a ciphertext.
        pub const CIPHERTEXT_BYTES: usize = PARAMS.ciphertext_bytes();
        /// Longest plaintext `encrypt` accepts (`maxMsgLenBytes`).
        pub const MAX_MESSAGE_BYTES: usize = PARAMS.max_message_bytes();

        /// Public key for this parameter set: `h = 3·f⁻¹·g (mod q)` in its
        /// wire form, `PUBLIC_KEY_BYTES` octets. That is the tag `0x01`, the
        /// OID length `0x03` and the three-octet parameter-set OID, followed
        /// by `h` packed with RE2OSP (EESS #1 v3.1 §8.6.1): the `N`
        /// coefficients in increasing degree, 11 bits each, most significant
        /// bit first, final unused bits zero. This is the framing of the
        /// standard authors' reference implementation.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk_ty {
            blob: Vec<u8>,
        }

        /// Private key for this parameter set: `F` (the secret polynomial
        /// is `f = 1 + 3F`) together with the matching public key, which the
        /// SVES-3 re-encryption check reads. `Debug` prints `<redacted>`,
        /// and the index lists of `F` are wiped on drop.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $sk_ty {
            trapdoor: Trapdoor,
            public: $pk_ty,
        }

        /// Ciphertext for this parameter set: the ring element
        /// `e = R + m' (mod q)` packed exactly like the public key's `h`
        /// (11 bits per coefficient, most significant bit first),
        /// `CIPHERTEXT_BYTES` octets with no header.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $ct_ty {
            bytes: Vec<u8>,
        }

        impl $pk_ty {
            /// Decode a public-key blob. Returns `None` unless `bytes` is
            /// exactly `PUBLIC_KEY_BYTES` long, starts with tag `0x01`, OID
            /// length 3 and this set's OID, leaves the bits after the
            /// `N · 11` coefficient bits zero, so each key has one accepted
            /// encoding, and passes the plausibility test of EESS #1 v3.1
            /// §10.2.5.2.2 step a: the coefficients of `h` sum to `3` mod
            /// `q`, as `h = 3·f⁻¹·g` with `f(1) = g(1) = 1` requires. An
            /// all-zero `h`, under which encryption would publish the
            /// plaintext, is refused.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != PUBLIC_KEY_BYTES {
                    return None;
                }
                __ees_public_key_from_blob(bytes, &PARAMS)?;
                Some(Self {
                    blob: bytes.to_vec(),
                })
            }

            /// The public-key blob, `PUBLIC_KEY_BYTES` octets, as an owned
            /// copy. [`Self::from_wire_bytes`] accepts exactly this output.
            #[must_use]
            pub fn to_wire_bytes(&self) -> Vec<u8> {
                self.blob.clone()
            }

            /// Borrow the public-key blob without copying: the same octets
            /// [`Self::to_wire_bytes`] returns.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.blob
            }

            fn packed_h(&self) -> &[u8] {
                &self.blob[KEY_BLOB_HEADER_BYTES..]
            }
        }

        impl $sk_ty {
            /// The private-key blob, `PRIVATE_KEY_BYTES` octets: tag
            /// `0x02`, OID length `0x03`, the OID, the packed `h`, then `F`,
            /// either trit-packed (five trits per octet) or as its index
            /// lists, whichever is shorter for this set (always index lists
            /// in product form). The output contains the secret key; treat
            /// it with the same care as the key itself.
            #[must_use]
            pub fn to_wire_bytes(&self) -> Vec<u8> {
                __ees_private_key_blob(&self.trapdoor, self.public.packed_h(), &PARAMS)
            }

            /// Inverse of [`Self::to_wire_bytes`]. Returns `None` unless the
            /// length, tag, OID and public-key padding are right, `h` passes
            /// the plausibility test (`h(1) ≡ 3 mod q`) and `F`
            /// decodes with exactly this set's `±1` counts. Every trit
            /// octet must be below 243 with no nonzero trit past degree
            /// `N − 1`. Every index must be below `N`, none may repeat
            /// within a polynomial's `+1` or `−1` list or appear in both,
            /// and the padding bits must be clear. The pair must also pass
            /// key pair validation kpv3 (EESS #1 v3.1 §10.2.4.1):
            /// `(1 + 3F)·h mod q` must be `3g` for a `g` with exactly
            /// `dg + 1` coefficients `+1` and `dg` coefficients `−1`.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                let (trapdoor, packed_h) = __ees_private_key_from_blob::<N>(bytes, &PARAMS)?;
                let public = $pk_ty {
                    blob: __ees_public_key_blob(packed_h, &PARAMS),
                };
                Some(Self { trapdoor, public })
            }

            /// The public key stored with the private key; returned by
            /// reference, nothing is recomputed.
            #[must_use]
            pub fn public_key(&self) -> &$pk_ty {
                &self.public
            }
        }

        impl $ct_ty {
            /// Decode a ciphertext. Returns `None` unless `bytes` is exactly
            /// `CIPHERTEXT_BYTES` long with the bits after the `N · 11`
            /// coefficient bits zero. Whether it decrypts is decided later,
            /// by the namespace type's `decrypt`.
            #[must_use]
            pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
                if !__ees_ciphertext_is_canonical(bytes, &PARAMS) {
                    return None;
                }
                Some(Self {
                    bytes: bytes.to_vec(),
                })
            }

            /// The ciphertext octets, `CIPHERTEXT_BYTES` long, as an owned
            /// copy. [`Self::from_wire_bytes`] accepts exactly this output.
            #[must_use]
            pub fn to_wire_bytes(&self) -> Vec<u8> {
                self.bytes.clone()
            }

            /// Borrow the ciphertext octets without copying: the same
            /// octets [`Self::to_wire_bytes`] returns.
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

        /// Namespace type for this NTRUEncrypt SVES-3 parameter set: a
        /// unit struct carrying the wire-size constants and the `keygen` /
        /// `encrypt` / `decrypt` entry points, which delegate to the shared
        /// routines in `ntru_ees_core` with this set's constants bound.
        /// Variable-time arithmetic; see the core module's side-channel
        /// notes.
        pub struct $type_name;

        impl $type_name {
            /// Octets of a public-key blob.
            pub const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
            /// Octets of a private-key blob.
            pub const PRIVATE_KEY_BYTES: usize = PRIVATE_KEY_BYTES;
            /// Octets of a ciphertext.
            pub const CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;
            /// Maximum byte length of a message that [`Self::encrypt`]
            /// accepts; longer inputs return
            /// [`NtruEesError::MessageTooLong`].
            pub const MAX_MESSAGE_BYTES: usize = MAX_MESSAGE_BYTES;

            /// Generate a key pair from `rng` (EESS #1 v3.1 §10.2.1). Draws `F`
            /// with this set's shape until `f = 1 + 3F` is invertible mod
            /// `q`, then `g` with `dg + 1` coefficients `+1` and `dg`
            /// coefficients `−1` until `g` is invertible, and publishes
            /// `h = 3·f⁻¹·g (mod q)`. Draws a variable number of bytes from
            /// `rng` (rejection sampling and both retry loops).
            ///
            /// # Panics
            ///
            /// Panics when eight consecutive candidates for `F` or for `g`
            /// are all non-invertible, or 256 consecutive index draws are
            /// all rejected: each is the mark of a broken random source (a
            /// working one refuses a candidate with probability below
            /// `2^-199`, the `N = 401` worst case where `Φ_N` has two
            /// factors of degree 200 over GF(2), and an index draw with
            /// probability below `2^-21`).
            pub fn keygen<R: Csprng>(rng: &mut R) -> ($pk_ty, $sk_ty) {
                let (packed_h, trapdoor) = __ees_keygen::<N, R>(&PARAMS, rng);
                let public = $pk_ty {
                    blob: __ees_public_key_blob(&packed_h, &PARAMS),
                };
                let private = $sk_ty {
                    trapdoor,
                    public: public.clone(),
                };
                (public, private)
            }

            /// SVES-3 encryption (EESS #1 v3.1 §10.2.2). Draws a random component
            /// `b` of `db / 8` octets from `rng` and forms
            /// `M = b ‖ len ‖ msg ‖ zeros`. The blinding value `r` comes from
            /// IGF-2 over `OID ‖ msg ‖ b ‖ hTrunc`. `M` is encoded as trits
            /// and masked with MGF-TP-1 of `r·h mod 4`, and the result is the
            /// `CIPHERTEXT_BYTES`-octet ciphertext `e = r·h + m' (mod q)`.
            /// A fresh `b` is drawn whenever the masked message has fewer
            /// than `dm0` of some trit value, so `rng` supplies `db / 8`
            /// octets per attempt. Errs with
            /// [`NtruEesError::MessageTooLong`] when `msg.len()` exceeds
            /// `MAX_MESSAGE_BYTES`.
            ///
            /// # Panics
            ///
            /// Panics when 64 consecutive attempts all fail the weight
            /// check, the mark of a broken random source: a working one
            /// fails an attempt with probability at most 0.155 (the
            /// `ees449ep1` row of the core module's "Step p refusals"
            /// table; 0.035 for `ees401ep1`, below `10^-8` for the six
            /// largest sets), so 64 in a row has probability below
            /// `2^-172`.
            pub fn encrypt<R: Csprng>(
                pk: &$pk_ty,
                msg: &[u8],
                rng: &mut R,
            ) -> Result<$ct_ty, NtruEesError> {
                let bytes = __ees_encrypt::<N, R>(pk.packed_h(), msg, rng, &PARAMS)?;
                Ok($ct_ty { bytes })
            }

            /// SVES-3 decryption (EESS #1 v3.1 §10.2.3). Recovers the masked
            /// message from `f·e (mod q)` lifted and reduced mod 3, strips
            /// the mask, re-derives `r` and re-encrypts. Any failure is
            /// reported uniformly as [`NtruEesError::InvalidCiphertext`],
            /// only after every check has run: a trit weight below `dm0`, an
            /// invalid trit pair, a length above `MAX_MESSAGE_BYTES`,
            /// nonzero padding, nonzero bits past the padding (a check beyond
            /// EESS #1 v3.1 that no honest ciphertext fails), or a
            /// re-encryption mismatch. On success returns the plaintext.
            pub fn decrypt(sk: &$sk_ty, ct: &$ct_ty) -> Result<Vec<u8>, NtruEesError> {
                __ees_decrypt::<N>(&sk.trapdoor, sk.public.packed_h(), &ct.bytes, &PARAMS)
            }
        }

        /// Print this set's crate-produced blocks of the interoperability
        /// vector file (see `ntru_ees_core::test_vectors`).
        #[cfg(test)]
        pub(crate) fn emit_crate_vector_blocks(out: &mut String) {
            use $crate::public_key::ntru_ees_core::test_vectors::{self, Origin, RecordingRng};
            use $crate::CtrDrbgAes256;

            let blocks = test_vectors::blocks_for($name);
            let reference = blocks
                .iter()
                .find(|b| b.origin == Origin::Reference)
                .expect("reference block present");
            let pk = $pk_ty::from_wire_bytes(&reference.pk).expect("reference public key");
            let sk = $sk_ty::from_wire_bytes(&reference.sk).expect("reference private key");

            test_vectors::begin_block(
                out,
                $name,
                Origin::CrateEncrypt,
                None,
                &reference.pk,
                &reference.sk,
            );
            for (k, record) in reference.messages.iter().enumerate() {
                let seed = test_vectors::drbg_seed($name, Origin::CrateEncrypt, k);
                let mut rng = RecordingRng::new(CtrDrbgAes256::new(&seed));
                let ct = $type_name::encrypt(&pk, &record.msg, &mut rng).expect("encrypt");
                assert_eq!($type_name::decrypt(&sk, &ct).expect("decrypt"), record.msg);
                test_vectors::push_message(out, &record.msg, rng.recorded(), ct.as_bytes());
            }

            let seed = test_vectors::drbg_seed($name, Origin::CrateKeygen, 0);
            let (gpk, gsk) = $type_name::keygen(&mut CtrDrbgAes256::new(&seed));
            test_vectors::begin_block(
                out,
                $name,
                Origin::CrateKeygen,
                Some(&seed),
                gpk.as_bytes(),
                &gsk.to_wire_bytes(),
            );
            for (k, record) in reference.messages.iter().enumerate() {
                let seed = test_vectors::drbg_seed($name, Origin::CrateKeygen, k + 1);
                let mut rng = RecordingRng::new(CtrDrbgAes256::new(&seed));
                let ct = $type_name::encrypt(&gpk, &record.msg, &mut rng).expect("encrypt");
                assert_eq!($type_name::decrypt(&gsk, &ct).expect("decrypt"), record.msg);
                test_vectors::push_message(out, &record.msg, rng.recorded(), ct.as_bytes());
            }
        }

        /// This set's survey of tampering at the last decoded octet
        /// (`ntru_ees_core::tamper::survey`) over `trials` honest ciphertexts.
        #[cfg(test)]
        pub(crate) fn tamper_survey(
            trials: usize,
        ) -> $crate::public_key::ntru_ees_core::tamper::Survey {
            $crate::public_key::ntru_ees_core::tamper::survey::<N>(&PARAMS, trials)
        }

        /// Step p attempts over `trials` honest encryptions of this set
        /// (`ntru_ees_core::refusals::attempts`).
        #[cfg(test)]
        pub(crate) fn encryption_attempts(trials: usize) -> usize {
            $crate::public_key::ntru_ees_core::refusals::attempts::<N>(&PARAMS, trials)
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::public_key::ntru_ees_core::test_vectors::{self, Origin, ReplayRng};
            use $crate::CtrDrbgAes256;

            #[test]
            fn sizes_match_the_parameter_set() {
                assert_eq!(PUBLIC_KEY_BYTES, $pk_bytes);
                assert_eq!(PRIVATE_KEY_BYTES, $sk_bytes);
                assert_eq!(CIPHERTEXT_BYTES, $ct_bytes);
                assert_eq!(MAX_MESSAGE_BYTES, $max_msg);
                // Step a's maxLen, the clamp of §10.2.3 step k2, lies below
                // maxMsgLenBytes, so a clamped candidate stays in bounds.
                assert_eq!(
                    PARAMS.decryption_max_len(),
                    N.div_ceil(8) - 2 - PARAMS.b_len()
                );
                assert!(PARAMS.decryption_max_len() < MAX_MESSAGE_BYTES);
            }

            /// The plausibility test of EESS #1 v3.1 §10.2.5.2.2 step a,
            /// `h(1) ≡ 3 (mod q)`: keygen output and the reference key pass
            /// it; an all-zero `h` and a single changed coefficient fail it.
            #[test]
            fn public_key_plausibility_test() {
                let mut drbg = CtrDrbgAes256::new(&[0x2bu8; 48]);
                let (pk, _) = $type_name::keygen(&mut drbg);
                let blob = pk.to_wire_bytes();
                assert!($pk_ty::from_wire_bytes(&blob).is_some());
                let reference = test_vectors::blocks_for($name)
                    .into_iter()
                    .find(|b| b.origin == Origin::Reference)
                    .expect("reference block");
                assert!($pk_ty::from_wire_bytes(&reference.pk).is_some());
                let mut zero = blob.clone();
                zero[KEY_BLOB_HEADER_BYTES..].fill(0);
                assert!($pk_ty::from_wire_bytes(&zero).is_none(), "h = 0 accepted");
                let mut bumped = blob.clone();
                bumped[KEY_BLOB_HEADER_BYTES] ^= 0x80;
                assert!(
                    $pk_ty::from_wire_bytes(&bumped).is_none(),
                    "h(1) = 3 + 1024 accepted"
                );
            }

            #[test]
            fn round_trip_empty_and_full_messages() {
                let mut drbg = CtrDrbgAes256::new(&[0x42u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                for &len in &[0usize, 1, 16, MAX_MESSAGE_BYTES - 1, MAX_MESSAGE_BYTES] {
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
                let ct = $type_name::encrypt(&pk, b"hello ntru", &mut drbg).expect("encrypt");
                let mut bad_bytes = ct.to_wire_bytes();
                bad_bytes[10] ^= 0xff;
                let bad_ct = $ct_ty::from_wire_bytes(&bad_bytes).expect("structural decode");
                assert_eq!(
                    $type_name::decrypt(&sk, &bad_ct),
                    Err(NtruEesError::InvalidCiphertext)
                );
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
                assert_eq!(sk.to_wire_bytes().len(), PRIVATE_KEY_BYTES);
                assert_eq!(
                    $type_name::decrypt(&sk_round, &ct_round).expect("decrypt"),
                    msg
                );
            }

            #[test]
            fn malformed_public_key_blobs_are_rejected() {
                let mut drbg = CtrDrbgAes256::new(&[0x13u8; 48]);
                let (pk, sk) = $type_name::keygen(&mut drbg);
                let blob = pk.to_wire_bytes();
                assert!($pk_ty::from_wire_bytes(&blob).is_some());
                for (what, bad) in test_vectors::public_blob_mutations(&blob, &PARAMS) {
                    assert!($pk_ty::from_wire_bytes(&bad).is_none(), "accepted {what}");
                }
                assert!($pk_ty::from_wire_bytes(&sk.to_wire_bytes()).is_none());
                assert!($sk_ty::from_wire_bytes(&blob).is_none());
            }

            #[test]
            fn malformed_private_key_blobs_are_rejected() {
                let mut drbg = CtrDrbgAes256::new(&[0x31u8; 48]);
                let (_, sk) = $type_name::keygen(&mut drbg);
                let blob = sk.to_wire_bytes();
                assert!($sk_ty::from_wire_bytes(&blob).is_some());
                for (what, bad) in test_vectors::private_blob_mutations(&blob, &PARAMS) {
                    assert!($sk_ty::from_wire_bytes(&bad).is_none(), "accepted {what}");
                }
            }

            fn check_block(block: &test_vectors::Block) {
                let pk = $pk_ty::from_wire_bytes(&block.pk).expect("public-key blob parses");
                assert_eq!(
                    pk.to_wire_bytes(),
                    block.pk,
                    "public key re-encodes identically"
                );
                let sk = $sk_ty::from_wire_bytes(&block.sk).expect("private-key blob parses");
                assert_eq!(
                    sk.to_wire_bytes(),
                    block.sk,
                    "private key re-encodes identically"
                );
                assert_eq!(sk.public_key(), &pk);
                assert_eq!(block.messages.len(), 4);
                for record in &block.messages {
                    let ct = $ct_ty::from_wire_bytes(&record.ct).expect("ciphertext parses");
                    assert_eq!(
                        $type_name::decrypt(&sk, &ct).expect("decrypts"),
                        record.msg,
                        "decrypt at len={}",
                        record.msg.len()
                    );
                    let mut replay = ReplayRng::new(&record.enc_rng);
                    let ours =
                        $type_name::encrypt(&pk, &record.msg, &mut replay).expect("encrypts");
                    assert!(
                        replay.is_exhausted(),
                        "encrypt drew exactly the recorded b values"
                    );
                    assert_eq!(
                        ours.as_bytes(),
                        &record.ct[..],
                        "the recorded b gives the recorded ciphertext at len={}",
                        record.msg.len()
                    );
                }
            }

            #[test]
            fn reference_implementation_vectors() {
                let blocks = test_vectors::blocks_for($name);
                let reference: Vec<_> = blocks
                    .iter()
                    .filter(|b| b.origin == Origin::Reference)
                    .collect();
                assert_eq!(reference.len(), 1, "one reference block for {}", $name);
                assert_eq!(reference[0].max_message_bytes, Some(MAX_MESSAGE_BYTES));
                check_block(reference[0]);
            }

            /// The crate-produced blocks of the vector file are reproduced:
            /// this set's encryption under each recorded `b` gives the
            /// recorded ciphertext, and keygen from `KEYGEN_SEED` gives the
            /// recorded key pair. The oracle's verdict on these blocks is
            /// the digest recorded in the vector file header, not re-run
            /// here.
            #[test]
            fn crate_vector_blocks_are_reproduced() {
                let blocks = test_vectors::blocks_for($name);
                let encrypt: Vec<_> = blocks
                    .iter()
                    .filter(|b| b.origin == Origin::CrateEncrypt)
                    .collect();
                let keygen: Vec<_> = blocks
                    .iter()
                    .filter(|b| b.origin == Origin::CrateKeygen)
                    .collect();
                assert_eq!(
                    (encrypt.len(), keygen.len()),
                    (1, 1),
                    "crate blocks for {}",
                    $name
                );
                check_block(encrypt[0]);
                let seed: [u8; 48] = keygen[0]
                    .keygen_seed
                    .as_deref()
                    .and_then(|s| s.try_into().ok())
                    .expect("48-byte keygen seed");
                let (pk, sk) = $type_name::keygen(&mut CtrDrbgAes256::new(&seed));
                assert_eq!(
                    pk.as_bytes(),
                    &keygen[0].pk[..],
                    "keygen reproduces the public key"
                );
                assert_eq!(
                    sk.to_wire_bytes(),
                    keygen[0].sk,
                    "keygen reproduces the private key"
                );
                check_block(keygen[0]);
            }
        }
    };
}

pub(crate) use define_ees_set;

// ---- interoperability vectors (tests only) ----------------------------------

/// Reader and writer for `tests/vectors/ntru_ees_sves3_reference.txt`.
///
/// The file is a sequence of blocks. Each opens with `SET=<name>` and
/// `ORIGIN=<origin>` and carries `PK` and `SK` key blobs, then four
/// `MSG` / `ENC_RNG` / `CT` records, where `ENC_RNG` holds every random
/// octet the encryptor drew. The origins are:
/// - `reference`: produced by the standard authors' implementation;
/// - `crate-encrypt`: this crate's ciphertexts under the reference key;
/// - `crate-keygen`: a key pair from this crate's `keygen` seeded with
///   `KEYGEN_SEED`, with this crate's ciphertexts under it.
///
/// The crate blocks were decrypted and their keys used by the reference
/// implementation (`scripts/ees_ref_vectors/`; the file header records the
/// digest of its verdict), so they pin the other direction of
/// interoperability.
#[cfg(test)]
pub(crate) mod test_vectors {
    use super::{BitReader, BitWriter, EesParams, KeyPacking, TrapdoorKind, KEY_BLOB_HEADER_BYTES};
    use crate::test_utils::{decode_hex, encode_hex, vector_fields};
    use crate::Csprng;
    use std::fmt::Write as _;

    const FILE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/ntru_ees_sves3_reference.txt"
    ));

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Origin {
        Reference,
        CrateEncrypt,
        CrateKeygen,
    }

    impl Origin {
        const fn label(self) -> &'static str {
            match self {
                Origin::Reference => "reference",
                Origin::CrateEncrypt => "crate-encrypt",
                Origin::CrateKeygen => "crate-keygen",
            }
        }

        fn parse(label: &str) -> Self {
            [Origin::Reference, Origin::CrateEncrypt, Origin::CrateKeygen]
                .into_iter()
                .find(|o| o.label() == label)
                .unwrap_or_else(|| panic!("unknown ORIGIN {label}"))
        }
    }

    pub(crate) struct MessageRecord {
        pub(crate) msg: Vec<u8>,
        pub(crate) enc_rng: Vec<u8>,
        pub(crate) ct: Vec<u8>,
    }

    pub(crate) struct Block {
        pub(crate) set: String,
        pub(crate) origin: Origin,
        pub(crate) keygen_seed: Option<Vec<u8>>,
        pub(crate) max_message_bytes: Option<usize>,
        pub(crate) pk: Vec<u8>,
        pub(crate) sk: Vec<u8>,
        pub(crate) messages: Vec<MessageRecord>,
    }

    fn parse(text: &str) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        for (key, value) in vector_fields(text) {
            if key == "SET" {
                blocks.push(Block {
                    set: value.to_string(),
                    origin: Origin::Reference,
                    keygen_seed: None,
                    max_message_bytes: None,
                    pk: Vec::new(),
                    sk: Vec::new(),
                    messages: Vec::new(),
                });
                continue;
            }
            let block = blocks.last_mut().expect("record inside a SET block");
            match key {
                "ORIGIN" => block.origin = Origin::parse(value),
                "KEYGEN_SEED" => block.keygen_seed = Some(decode_hex(value)),
                "MAX_MSG" => block.max_message_bytes = Some(value.parse().expect("MAX_MSG")),
                "PK" => block.pk = decode_hex(value),
                "SK" => block.sk = decode_hex(value),
                "MSG" => block.messages.push(MessageRecord {
                    msg: decode_hex(value),
                    enc_rng: Vec::new(),
                    ct: Vec::new(),
                }),
                "ENC_RNG" => {
                    block.messages.last_mut().expect("MSG first").enc_rng = decode_hex(value)
                }
                "CT" => block.messages.last_mut().expect("MSG first").ct = decode_hex(value),
                other => panic!("unknown key {other}"),
            }
        }
        blocks
    }

    /// Every block of the vector file for parameter set `set`.
    pub(crate) fn blocks_for(set: &str) -> Vec<Block> {
        parse(FILE).into_iter().filter(|b| b.set == set).collect()
    }

    /// Replays recorded random octets; panics if asked for more.
    pub(crate) struct ReplayRng<'a> {
        bytes: &'a [u8],
        used: usize,
    }

    impl<'a> ReplayRng<'a> {
        pub(crate) fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, used: 0 }
        }

        pub(crate) fn is_exhausted(&self) -> bool {
            self.used == self.bytes.len()
        }
    }

    impl Csprng for ReplayRng<'_> {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            let end = self.used + out.len();
            assert!(
                end <= self.bytes.len(),
                "asked for more randomness than was recorded"
            );
            out.copy_from_slice(&self.bytes[self.used..end]);
            self.used = end;
        }
    }

    /// Records every octet drawn from the wrapped generator.
    pub(crate) struct RecordingRng<R> {
        inner: R,
        log: Vec<u8>,
    }

    impl<R: Csprng> RecordingRng<R> {
        pub(crate) fn new(inner: R) -> Self {
            Self {
                inner,
                log: Vec::new(),
            }
        }

        pub(crate) fn recorded(&self) -> &[u8] {
            &self.log
        }
    }

    impl<R: Csprng> Csprng for RecordingRng<R> {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.inner.fill_bytes(out);
            self.log.extend_from_slice(out);
        }
    }

    /// Seed for the crate-produced blocks: the set name, then the origin
    /// and a counter in the last two octets.
    pub(crate) fn drbg_seed(set: &str, origin: Origin, k: usize) -> [u8; 48] {
        let mut seed = [0u8; 48];
        seed[..set.len()].copy_from_slice(set.as_bytes());
        seed[46] = origin as u8;
        seed[47] = k as u8;
        seed
    }

    pub(crate) fn begin_block(
        out: &mut String,
        set: &str,
        origin: Origin,
        keygen_seed: Option<&[u8]>,
        pk: &[u8],
        sk: &[u8],
    ) {
        writeln!(out, "\nSET={set}\nORIGIN={}", origin.label()).expect("write");
        if let Some(seed) = keygen_seed {
            writeln!(out, "KEYGEN_SEED={}", encode_hex(seed).to_ascii_uppercase()).expect("write");
        }
        writeln!(
            out,
            "PK={}\nSK={}",
            encode_hex(pk).to_ascii_uppercase(),
            encode_hex(sk).to_ascii_uppercase()
        )
        .expect("write");
    }

    pub(crate) fn push_message(out: &mut String, msg: &[u8], enc_rng: &[u8], ct: &[u8]) {
        writeln!(
            out,
            "MSG={}\nENC_RNG={}\nCT={}",
            encode_hex(msg).to_ascii_uppercase(),
            encode_hex(enc_rng).to_ascii_uppercase(),
            encode_hex(ct).to_ascii_uppercase()
        )
        .expect("write");
    }

    /// Public-key blobs that must be rejected, derived from a valid one.
    pub(crate) fn public_blob_mutations(
        blob: &[u8],
        params: &EesParams,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let mut cases = Vec::new();
        let mut tag = blob.to_vec();
        tag[0] ^= 0x03;
        cases.push(("a private-key tag", tag));
        let mut oid_len = blob.to_vec();
        oid_len[1] = 4;
        cases.push(("a wrong OID length", oid_len));
        let mut oid = blob.to_vec();
        oid[4] ^= 0x01;
        cases.push(("another set's OID", oid));
        cases.push(("a truncated blob", blob[..blob.len() - 1].to_vec()));
        let mut long = blob.to_vec();
        long.push(0);
        cases.push(("a trailing octet", long));
        if !(params.n * params.logq).is_multiple_of(8) {
            let mut padding = blob.to_vec();
            *padding.last_mut().expect("non-empty") |= 1;
            cases.push(("a set padding bit", padding));
        }
        // Convention 13: h(1) must be 3 mod q.
        let mut zero = blob.to_vec();
        zero[KEY_BLOB_HEADER_BYTES..].fill(0);
        cases.push(("an all-zero h", zero));
        let mut bumped = blob.to_vec();
        bumped[KEY_BLOB_HEADER_BYTES] ^= 0x80;
        cases.push(("h with coefficient 0 changed by 1024", bumped));
        cases
    }

    /// Private-key blobs that must be rejected, derived from a valid one.
    pub(crate) fn private_blob_mutations(
        blob: &[u8],
        params: &EesParams,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let start = KEY_BLOB_HEADER_BYTES + params.packed_ring_bytes();
        let mut cases = Vec::new();
        let mut tag = blob.to_vec();
        tag[0] = 0x01;
        cases.push(("a public-key tag", tag));
        let mut oid = blob.to_vec();
        oid[3] ^= 0x01;
        cases.push(("another set's OID", oid));
        cases.push(("a truncated blob", blob[..blob.len() - 1].to_vec()));
        let mut mismatched = blob.to_vec();
        mismatched[KEY_BLOB_HEADER_BYTES] ^= 0x80;
        cases.push((
            "a public key with one coefficient changed (implausible, and mismatching F)",
            mismatched,
        ));
        let mut zero_h = blob.to_vec();
        zero_h[KEY_BLOB_HEADER_BYTES..start].fill(0);
        cases.push(("an all-zero h", zero_h));
        if !(params.n * params.logq).is_multiple_of(8) {
            let mut padding = blob.to_vec();
            padding[start - 1] |= 1;
            cases.push(("a set public-key padding bit", padding));
        }
        match params.private_key_packing() {
            KeyPacking::Indices => {
                let bits = params.index_bits() as u32;
                let count = params.nonzero_indices();
                let first_d = match params.trapdoor {
                    TrapdoorKind::Dense { df } => df,
                    TrapdoorKind::ProductForm { df1, .. } => df1,
                };
                let mut reader = BitReader::new(&blob[start..]);
                let original: Vec<u32> = (0..count).map(|_| reader.pull(bits)).collect();
                let rewrite = |indices: &[u32]| {
                    let mut out = blob.to_vec();
                    let mut writer = BitWriter::new(&mut out[start..]);
                    for &i in indices {
                        writer.push(i, bits);
                    }
                    writer.finish();
                    out
                };
                let mut repeated = original.clone();
                repeated[1] = repeated[0];
                cases.push(("an index repeated in the +1 list", rewrite(&repeated)));
                let mut repeated_minus = original.clone();
                repeated_minus[first_d + 1] = repeated_minus[first_d];
                cases.push(("an index repeated in the -1 list", rewrite(&repeated_minus)));
                let mut overlap = original.clone();
                overlap[first_d] = overlap[0];
                cases.push(("an index in both lists", rewrite(&overlap)));
                let mut too_big = original.clone();
                too_big[0] = params.n as u32;
                cases.push(("an index equal to N", rewrite(&too_big)));
                if !(count * bits as usize).is_multiple_of(8) {
                    let mut padding = blob.to_vec();
                    *padding.last_mut().expect("non-empty") |= 1;
                    cases.push(("a set index padding bit", padding));
                }
            }
            KeyPacking::Trits => {
                // An octet o ≤ 12 and o + 243 carry the same five digits, so
                // only the range check can reject the second.
                let small = blob[start..]
                    .iter()
                    .position(|&o| o <= 12)
                    .expect("a trit octet no larger than 12");
                let mut big_octet = blob.to_vec();
                big_octet[start + small] += 243;
                cases.push(("a trit octet above 242 with valid digits", big_octet));
                // Turn the first zero coefficient into +1: one too many.
                let mut heavier = blob.to_vec();
                'search: for position in 0..params.n {
                    let octet = heavier[start + position / 5];
                    let place = 3u8.pow((position % 5) as u32);
                    if (octet / place).is_multiple_of(3) {
                        heavier[start + position / 5] = octet + place;
                        break 'search;
                    }
                }
                cases.push(("an extra +1 coefficient", heavier));
                if !params.n.is_multiple_of(5) {
                    let mut beyond = blob.to_vec();
                    *beyond.last_mut().expect("non-empty") += 3u8.pow((params.n % 5) as u32);
                    cases.push(("a nonzero trit past degree N-1", beyond));
                }
            }
        }
        cases
    }
}

// ---- step p refusals of honest encryption (tests only) ---------------------------

/// Measurement of step p's refusals (module documentation, "Step p
/// refusals").
#[cfg(test)]
pub(crate) mod refusals {
    use super::{encrypt, keygen, EesParams};
    use crate::public_key::ntru_ees_core::test_vectors::RecordingRng;
    use crate::{Csprng, CtrDrbgAes256};

    /// Step p attempts over `trials` encryptions, under one key, of random
    /// messages whose lengths cycle from 0 to `maxMsgLenBytes`: the random
    /// octets encryption drew, divided by `bLen`. Every refusal draws one
    /// more `b`.
    pub(crate) fn attempts<const N: usize>(params: &EesParams, trials: usize) -> usize {
        let mut drbg = CtrDrbgAes256::new(&[0x11u8; 48]);
        let (packed_h, _) = keygen::<N, _>(params, &mut drbg);
        let mut messages = CtrDrbgAes256::new(&[0x22u8; 48]);
        let mut rng = RecordingRng::new(drbg);
        let mut drawn = 0usize;
        for trial in 0..trials {
            let mut msg = vec![0u8; trial % (params.max_message_bytes() + 1)];
            messages.fill_bytes(&mut msg);
            let before = rng.recorded().len();
            encrypt::<N, _>(&packed_h, &msg, &mut rng, params).expect("encrypt");
            let used = rng.recorded().len() - before;
            assert_eq!(used % params.b_len(), 0, "encryption draws whole b values");
            drawn += used;
        }
        drawn / params.b_len()
    }
}

// ---- tampering at the last decoded octet (tests only) ---------------------------

/// Single-coefficient tampering of honest ciphertexts at the coefficients
/// whose trits reach the final octet of the decoded buffer: the bits past
/// `M` (convention 10), the bits §10.2.3 step i truncates, or, when there
/// are neither, the last octet of `p0`. [`decrypt`] is `recover` followed by
/// `Recovered::select`; each tampered ciphertext runs `recover` once. Its
/// §10.2.3 flag is the verdict decryption reached before convention 10's
/// check, and `select` gives the verdict now.
#[cfg(test)]
pub(crate) mod tamper {
    use super::{
        decrypt, encrypt, keygen, pack_ring, recover, trits_to_octets, unpack_ring, EesParams,
    };
    use crate::{Csprng, CtrDrbgAes256};

    /// Values added, mod `q`, to the tampered coefficient.
    const DELTAS: [i16; 4] = [1, -1, 2, -2];

    /// One tampering, counted over every honest ciphertext of a survey.
    pub(crate) struct Outcome {
        /// The ciphertext coefficient changed.
        pub(crate) position: usize,
        /// The value added to it, mod `q`.
        pub(crate) delta: i16,
        /// Tampered ciphertexts the §10.2.3 checks accepted; each decrypted
        /// to the original message.
        pub(crate) before: usize,
        /// Tampered ciphertexts [`decrypt`] accepted.
        pub(crate) after: usize,
    }

    /// Result of [`survey`] for one parameter set.
    pub(crate) struct Survey {
        /// Decoded bits past `M`: `3·⌈N/2⌉ − 8·|M|` when that is positive,
        /// else 0.
        pub(crate) bits_past_message: usize,
        /// Bits §10.2.3 step i removes, `3·⌈N/2⌉ mod 8`; the bits past `M`
        /// are among them.
        pub(crate) truncated_bits: usize,
        /// Coefficients whose trit, alone nonzero, decodes to a nonzero bit
        /// in the final octet of the decoded buffer.
        pub(crate) positions: Vec<usize>,
        /// Every position with every value in `DELTAS`.
        pub(crate) outcomes: Vec<Outcome>,
    }

    /// Under one key, encrypt `trials` random messages whose lengths cycle
    /// from 0 to `maxMsgLenBytes`, assert that each decrypts, and tamper each
    /// ciphertext at every position of [`Survey::positions`] with every
    /// value in `DELTAS`.
    pub(crate) fn survey<const N: usize>(params: &EesParams, trials: usize) -> Survey {
        let message_octets = params.padded_message_bytes();
        let decoded_bits = 3 * N.div_ceil(2);
        let bits_past_message = decoded_bits.saturating_sub(8 * message_octets);
        let truncated_bits = decoded_bits % 8;
        let mut decoded = vec![0u8; params.decoded_message_bytes()];
        let last_octet = decoded.len() - 1;
        let positions: Vec<usize> = (0..N)
            .filter(|&position| {
                (1..=2u8).any(|trit| {
                    let mut trits = [0u8; N];
                    trits[position] = trit;
                    trits_to_octets(&trits, &mut decoded);
                    decoded[last_octet] != 0
                })
            })
            .collect();
        assert!(!positions.is_empty(), "some trit reaches the last octet");
        let mut outcomes: Vec<Outcome> = positions
            .iter()
            .flat_map(|&position| {
                DELTAS.map(|delta| Outcome {
                    position,
                    delta,
                    before: 0,
                    after: 0,
                })
            })
            .collect();

        let mut drbg = CtrDrbgAes256::new(&[0x3cu8; 48]);
        let (packed_h, trapdoor) = keygen::<N, _>(params, &mut drbg);
        let q_mask = params.q_mask();
        let mut tampered_ct = vec![0u8; params.ciphertext_bytes()];
        for trial in 0..trials {
            let mut msg = vec![0u8; trial % (params.max_message_bytes() + 1)];
            drbg.fill_bytes(&mut msg);
            let ct = encrypt::<N, _>(&packed_h, &msg, &mut drbg, params).expect("encrypt");
            assert_eq!(
                decrypt::<N>(&trapdoor, &packed_h, &ct, params),
                Ok(msg.clone()),
                "honest ciphertext {trial} decrypts"
            );
            let e = unpack_ring::<N>(&ct, params);
            for outcome in &mut outcomes {
                let mut tampered = e;
                let c = &mut tampered.coeffs[outcome.position];
                *c = c.wrapping_add(outcome.delta as u16) & q_mask;
                pack_ring(&tampered, params, &mut tampered_ct);
                let recovered = recover::<N>(&trapdoor, &packed_h, &tampered_ct, params);
                if recovered.listed_checks == 1 {
                    assert_eq!(
                        &recovered.message[..recovered.cl],
                        &msg[..],
                        "tampering kept the plaintext"
                    );
                    outcome.before += 1;
                }
                if recovered.select().is_ok() {
                    outcome.after += 1;
                }
            }
        }
        Survey {
            bits_past_message,
            truncated_bits,
            positions,
            outcomes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key::ntru_ees401ep1::{NtruEes401Ep1, NtruEes401Ep1PublicKey};

    /// Octets of `b` in `ees401ep1`: `db = 112` bits.
    const EES401EP1_B_LEN: usize = 112 / 8;

    /// A random source that repeats one byte value.
    struct RepeatingRng(u8);

    impl Csprng for RepeatingRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.fill(self.0);
        }
    }

    /// A random source that records every byte it hands out.
    struct RecordingRng {
        inner: crate::CtrDrbgAes256,
        log: Vec<u8>,
    }

    impl Csprng for RecordingRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.inner.fill_bytes(out);
            self.log.extend_from_slice(out);
        }
    }

    /// A random source that hands out one fixed byte string, over and over.
    struct StuckRng(Vec<u8>);

    impl Csprng for StuckRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for (o, &b) in out.iter_mut().zip(self.0.iter().cycle()) {
                *o = b;
            }
        }
    }

    /// `ees401ep1` public key and, per encryption of a 16-octet message, the
    /// random components `b` it drew: the first `b_len` octets of each entry
    /// are the attempt step p refused when there is more than one.
    fn ees401ep1_encryption_draws(count: usize) -> (NtruEes401Ep1PublicKey, Vec<Vec<u8>>) {
        let mut rng = RecordingRng {
            inner: crate::CtrDrbgAes256::new(&[0x11; 48]),
            log: Vec::new(),
        };
        let (pk, _) = NtruEes401Ep1::keygen(&mut rng);
        let draws = (0..count)
            .map(|i| {
                rng.log.clear();
                NtruEes401Ep1::encrypt(&pk, &[i as u8; 16], &mut rng).expect("encrypt");
                rng.log.clone()
            })
            .collect();
        (pk, draws)
    }

    /// Step p's refusal rate per set against the exact probabilities of the
    /// module table ("Step p refusals"), measured under fixed seeds as the
    /// extra `b` draws. This debug-speed form is a consistency check: the
    /// three sets that refuse at all run enough trials to expect at least 25
    /// refusals, and the count must lie within four standard deviations of
    /// the expectation; the six sets whose probability is below `10^-8` must
    /// show none. Its samples are too small to tell `dm0` from `dm0 ± 1`
    /// (the adjacent rates differ by about 1.3× while the band is ±4σ); that
    /// separation is the release-only
    /// [`step_p_refusal_rates_separate_dm0_from_its_neighbours`], and the
    /// oracle measurement in the module documentation pins `dm0` directly.
    /// `ENCRYPT_ATTEMPT_LIMIT` is sized against the worst row, `ees449ep1`.
    #[test]
    fn step_p_refusal_rates_by_parameter_set() {
        use crate::public_key::{
            ntru_ees1087ep1, ntru_ees1087ep2, ntru_ees1171ep1, ntru_ees1499ep1, ntru_ees401ep1,
            ntru_ees443ep1, ntru_ees449ep1, ntru_ees541ep1, ntru_ees677ep1,
        };
        /// (set, attempts over trials, trials, exact refusal probability)
        type Row = (&'static str, fn(usize) -> usize, usize, f64);
        let rows: [Row; 9] = [
            (
                "ees401ep1",
                ntru_ees401ep1::encryption_attempts,
                1000,
                3.49e-2,
            ),
            (
                "ees443ep1",
                ntru_ees443ep1::encryption_attempts,
                30_000,
                9.74e-4,
            ),
            (
                "ees449ep1",
                ntru_ees449ep1::encryption_attempts,
                300,
                1.55e-1,
            ),
            (
                "ees541ep1",
                ntru_ees541ep1::encryption_attempts,
                100,
                1.05e-40,
            ),
            (
                "ees677ep1",
                ntru_ees677ep1::encryption_attempts,
                100,
                9.13e-9,
            ),
            (
                "ees1087ep1",
                ntru_ees1087ep1::encryption_attempts,
                100,
                2.73e-108,
            ),
            (
                "ees1087ep2",
                ntru_ees1087ep2::encryption_attempts,
                100,
                1.04e-65,
            ),
            (
                "ees1171ep1",
                ntru_ees1171ep1::encryption_attempts,
                100,
                6.88e-86,
            ),
            (
                "ees1499ep1",
                ntru_ees1499ep1::encryption_attempts,
                100,
                7.24e-156,
            ),
        ];
        for (name, attempts_over, trials, p) in rows {
            let attempts = attempts_over(trials);
            let refused = attempts - trials;
            let expected = p * attempts as f64;
            let sigma = (expected * (1.0 - p)).sqrt();
            eprintln!(
                "{name}: {refused} of {attempts} attempts refused, rate {:.4}, exact {p:.3e}",
                refused as f64 / attempts as f64
            );
            if expected >= 25.0 {
                assert!(
                    (refused as f64 - expected).abs() <= 4.0 * sigma,
                    "{name}: {refused} refusals against {expected:.1} ± 4·{sigma:.1}"
                );
            } else {
                assert_eq!(refused, 0, "{name}: a refusal at probability {p:.1e}");
            }
        }
    }

    /// The refusal counts decide between the table's `dm0` and its two
    /// neighbours by likelihood, with samples large enough that the
    /// neighbours' expectations lie at least ten standard deviations from
    /// the table's: 100,000 trials of `ees401ep1` (3.49% against 2.61% and
    /// 4.62%), a million of `ees443ep1` (9.74 × 10⁻⁴ against 6.58 × 10⁻⁴ and
    /// 1.43 × 10⁻³) and 30,000 of `ees449ep1` (0.155 against 0.125 and
    /// 0.190). The binomial log-likelihood of the observed count must be
    /// highest under the table's probability, and the count within four
    /// standard deviations of it. Run with `cargo test --release -- --ignored`
    /// (about 25 s); the debug build takes minutes.
    #[test]
    #[ignore = "a million ees443ep1 encryptions; run with `cargo test --release -- --ignored`"]
    fn step_p_refusal_rates_separate_dm0_from_its_neighbours() {
        use crate::public_key::{ntru_ees401ep1, ntru_ees443ep1, ntru_ees449ep1};
        // (set, attempts over trials, trials, exact probability at dm0 − 1, dm0, dm0 + 1)
        type Row = (&'static str, fn(usize) -> usize, usize, [f64; 3]);
        let rows: [Row; 3] = [
            (
                "ees401ep1",
                ntru_ees401ep1::encryption_attempts,
                100_000,
                [2.609e-2, 3.490e-2, 4.617e-2],
            ),
            (
                "ees443ep1",
                ntru_ees443ep1::encryption_attempts,
                1_000_000,
                [6.578e-4, 9.742e-4, 1.4267e-3],
            ),
            (
                "ees449ep1",
                ntru_ees449ep1::encryption_attempts,
                30_000,
                [1.252e-1, 1.549e-1, 1.899e-1],
            ),
        ];
        for (name, attempts_over, trials, probabilities) in rows {
            let attempts = attempts_over(trials);
            let refused = (attempts - trials) as f64;
            let n = attempts as f64;
            let log_likelihood = |p: f64| refused * p.ln() + (n - refused) * (1.0 - p).ln();
            let [below, table, above] = probabilities.map(log_likelihood);
            let expected = probabilities[1] * n;
            let sigma = (expected * (1.0 - probabilities[1])).sqrt();
            eprintln!(
                "{name}: {refused} of {attempts} refused; z = {:+.2}; log-likelihood ratios \
                 dm0 against dm0 − 1: {:.1}, against dm0 + 1: {:.1}",
                (refused - expected) / sigma,
                table - below,
                table - above
            );
            assert!(
                table > below && table > above,
                "{name}: a neighbouring dm0 fits better"
            );
            assert!(
                (refused - expected).abs() <= 4.0 * sigma,
                "{name}: {refused} refusals against {expected:.1} ± 4·{sigma:.1}"
            );
        }
    }

    /// `Φ_N` splits over GF(2) into `(N − 1) / ord_N(2)` irreducibles of
    /// degree `ord_N(2)`, one per cyclotomic coset of 2 modulo `N`.
    /// `KEYGEN_DRAW_LIMIT` is justified from the smallest degree, 200 at
    /// `N = 401`, where there are two factors.
    #[test]
    fn phi_n_splits_over_gf2_as_tabulated() {
        let order_of_two = |n: u32| {
            let (mut k, mut v) = (1u32, 2 % n);
            while v != 1 {
                v = v * 2 % n;
                k += 1;
            }
            k
        };
        // (N, ord_N(2), factors of Φ_N)
        let table = [
            (401, 200, 2),
            (443, 442, 1),
            (449, 224, 2),
            (541, 540, 1),
            (677, 676, 1),
            (1087, 543, 2),
            (1171, 1170, 1),
            (1499, 1498, 1),
        ];
        for (n, degree, factors) in table {
            let ord = order_of_two(n);
            assert_eq!(ord, degree, "ord_{n}(2)");
            assert_eq!((n - 1) % ord, 0, "{n}: cosets partition Z_N*");
            assert_eq!((n - 1) / ord, factors, "factors of Φ_{n} over GF(2)");
        }
    }

    /// A random source that hands out a fixed sequence of 32-bit draws.
    struct ScriptedRng {
        draws: Vec<u32>,
        next: usize,
    }

    impl Csprng for ScriptedRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            assert_eq!(out.len(), 4, "scripted draws are 32-bit");
            let v = *self.draws.get(self.next).expect("script exhausted");
            self.next += 1;
            out.copy_from_slice(&v.to_le_bytes());
        }
    }

    /// The 32-bit draws that make `random_ternary` over `n` output the
    /// distinct degrees `targets` in order. Step `i` of its partial
    /// Fisher–Yates swaps entry `i` with entry `i + u`, `u` being the draw
    /// reduced modulo `n − i`; the target's current position `pos ≥ i` is
    /// found and the draw `pos − i`, below the modulus and the rejection
    /// threshold, swaps it into place.
    fn draws_for(n: usize, targets: &[u16]) -> Vec<u32> {
        let mut order: Vec<u16> = (0..n as u16).collect();
        targets
            .iter()
            .enumerate()
            .map(|(i, &t)| {
                let pos = i + order[i..]
                    .iter()
                    .position(|&x| x == t)
                    .expect("distinct target");
                order.swap(i, pos);
                (pos - i) as u32
            })
            .collect()
    }

    /// GF(2)[x] element from a big-endian hex integer, coefficient of `x^i`
    /// at index `i`, `len` coefficients.
    fn gf2_from_hex(hex: &str, len: usize) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::with_capacity(4 * hex.len());
        for c in hex.bytes().rev() {
            let d = (c as char).to_digit(16).expect("hex digit");
            bits.extend((0..4).map(|b| (d >> b & 1) as u8));
        }
        assert!(bits[len..].iter().all(|&b| b == 0), "value fits {len} bits");
        bits.truncate(len);
        bits
    }

    /// Remainder of `a` modulo `m` in GF(2)[x].
    fn gf2_rem(a: &[u8], m: &[u8]) -> Vec<u8> {
        let dm = poly_deg(m).expect("nonzero modulus");
        let mut r = a.to_vec();
        while let Some(da) = poly_deg(&r) {
            if da < dm {
                break;
            }
            for k in 0..=dm {
                r[da - dm + k] ^= m[k];
            }
        }
        r
    }

    /// One of the two irreducible factors of degree 200 of `Φ_401` over
    /// GF(2), found by equal-degree splitting: the gcd of `Φ_401` with the
    /// trace `Σ_{i<200} r^(2^i)` of a random residue `r`. The test
    /// `multiples_of_a_factor_of_phi_401_are_not_invertible` checks that it
    /// divides `Φ_401`.
    const PHI_401_FACTOR: &str = "1da4854fbfe4c3b29f4ba864b93a4c2ba5f29b864ffbe5424b7";

    /// The multiples of [`PHI_401_FACTOR`] of degree below 401 form a
    /// [401, 201] cyclic code that contains the all-ones word `Φ_401`;
    /// message `m` (201 bits) encodes systematically as
    /// `x^200·m + (x^200·m mod P1)`. Returns that codeword's complement
    /// (its sum with `Φ_401`), still a multiple of `P1`.
    fn complemented_multiple_of_p1(m_hex: &str) -> Vec<u8> {
        let p1 = gf2_from_hex(PHI_401_FACTOR, 201);
        let m = gf2_from_hex(m_hex, 201);
        let mut u = vec![0u8; 401];
        u[200..].copy_from_slice(&m);
        let rem = gf2_rem(&u, &p1);
        for ((c, r), one) in u.iter_mut().zip(rem).zip(std::iter::repeat(1u8)) {
            *c ^= r ^ one;
        }
        assert_eq!(gf2_rem(&u, &p1), vec![0u8; 401], "a multiple of P1");
        u
    }

    /// `F ∈ T(113, 113)` with `f = 1 + 3F` non-invertible mod 2 for
    /// `N = 401`. `f ≡ 1 + F (mod 2)`, so it suffices that `1 + F mod 2` is
    /// a multiple `u` of `P1` with constant term 1 and weight `2·113 + 1`;
    /// `F`'s nonzero degrees are the other 226 ones of `u`, and its signs
    /// are free (the first 113 degrees are `+1`). The message below, of
    /// weight 74, was the 49th random message whose complemented codeword
    /// had weight 227 and constant term 1.
    fn non_invertible_f_401() -> TernaryPoly {
        let u = complemented_multiple_of_p1("1adb0a0514a64a88820c244840c0166a0ad63c9b60832064b9a");
        assert_eq!(u[0], 1);
        let degrees: Vec<u16> = (1..401u16).filter(|&i| u[usize::from(i)] == 1).collect();
        assert_eq!(degrees.len(), 226);
        TernaryPoly {
            ones: degrees[..113].to_vec(),
            neg_ones: degrees[113..].to_vec(),
        }
    }

    /// `g ∈ T(134, 133)` non-invertible mod 2 for `N = 401`: `g mod 2` is a
    /// multiple of `P1` of weight `2·133 + 1`, from a message of weight 34
    /// (the 17th tried).
    fn non_invertible_g_401() -> TernaryPoly {
        let u = complemented_multiple_of_p1("02000000930e200025110200060227488010010121002840400");
        let degrees: Vec<u16> = (0..401u16).filter(|&i| u[usize::from(i)] == 1).collect();
        assert_eq!(degrees.len(), 267);
        TernaryPoly {
            ones: degrees[..134].to_vec(),
            neg_ones: degrees[134..].to_vec(),
        }
    }

    fn dense_401(t: &TernaryPoly) -> Poly<401> {
        let mut p = Poly::<401>::zero();
        t.dense_into(EES401.q_mask(), &mut p);
        p
    }

    #[test]
    fn scripted_draws_drive_random_ternary_to_a_chosen_polynomial() {
        let target = non_invertible_f_401();
        let mut script = target.ones.clone();
        script.extend_from_slice(&target.neg_ones);
        let mut rng = ScriptedRng {
            draws: draws_for(401, &script),
            next: 0,
        };
        let drawn = random_ternary(&mut rng, 401, 113, 113);
        let sorted = |v: &[u16]| {
            let mut v = v.to_vec();
            v.sort_unstable();
            v
        };
        assert_eq!(sorted(&drawn.ones), sorted(&target.ones), "+1 degrees");
        assert_eq!(
            sorted(&drawn.neg_ones),
            sorted(&target.neg_ones),
            "−1 degrees"
        );
        assert_eq!(rng.next, rng.draws.len(), "every draw was used");
    }

    #[test]
    fn multiples_of_a_factor_of_phi_401_are_not_invertible() {
        let p1 = gf2_from_hex(PHI_401_FACTOR, 201);
        assert_eq!(poly_deg(&p1), Some(200));
        assert_eq!(
            gf2_rem(&[1u8; 401], &p1),
            vec![0u8; 401],
            "P1 divides Φ_401"
        );
        let big_f = non_invertible_f_401();
        let mut f = dense_401(&big_f);
        poly_scale(&mut f, 3, EES401.q_mask());
        f.coeffs[0] = f.coeffs[0].wrapping_add(1) & EES401.q_mask();
        let mut inverse = Poly::<401>::zero();
        assert!(!poly_inverse_mod_q_cyclic(&f, &EES401, &mut inverse));
        assert!(inverse.coeffs.iter().all(|&c| c == 0));
        assert!(!invertible_mod_q(&dense_401(&non_invertible_g_401())));
        // The ordinary case, for contrast.
        let good = random_ternary(&mut crate::CtrDrbgAes256::new(&[0x5au8; 48]), 401, 113, 113);
        let mut f = dense_401(&good);
        poly_scale(&mut f, 3, EES401.q_mask());
        f.coeffs[0] = f.coeffs[0].wrapping_add(1) & EES401.q_mask();
        assert!(poly_inverse_mod_q_cyclic(&f, &EES401, &mut inverse));
    }

    /// Eight scripted draws of the same non-invertible `F` reach
    /// `KEYGEN_DRAW_LIMIT`.
    #[test]
    #[should_panic(expected = "consecutive candidates for F")]
    fn key_generation_panics_after_eight_non_invertible_f() {
        let target = non_invertible_f_401();
        let mut script = target.ones.clone();
        script.extend_from_slice(&target.neg_ones);
        let per_candidate = draws_for(401, &script);
        let mut rng = ScriptedRng {
            draws: per_candidate.repeat(KEYGEN_DRAW_LIMIT),
            next: 0,
        };
        let _ = keygen::<401, _>(&EES401, &mut rng);
    }

    /// An invertible `F` followed by eight scripted draws of the same
    /// non-invertible `g` reach `KEYGEN_DRAW_LIMIT` in the second loop.
    #[test]
    #[should_panic(expected = "consecutive candidates for g")]
    fn key_generation_panics_after_eight_non_invertible_g() {
        let good = random_ternary(&mut crate::CtrDrbgAes256::new(&[0x5au8; 48]), 401, 113, 113);
        let mut f = dense_401(&good);
        poly_scale(&mut f, 3, EES401.q_mask());
        f.coeffs[0] = f.coeffs[0].wrapping_add(1) & EES401.q_mask();
        assert!(invertible_mod_q(&f), "the scripted F must pass");
        let mut script = good.ones.clone();
        script.extend_from_slice(&good.neg_ones);
        let mut draws = draws_for(401, &script);
        let g = non_invertible_g_401();
        let mut g_script = g.ones.clone();
        g_script.extend_from_slice(&g.neg_ones);
        draws.extend(draws_for(401, &g_script).repeat(KEYGEN_DRAW_LIMIT));
        let mut rng = ScriptedRng { draws, next: 0 };
        let _ = keygen::<401, _>(&EES401, &mut rng);
    }

    /// An encryption whose first `b` step p refused, rerun under a source
    /// stuck on that `b`, is refused `ENCRYPT_ATTEMPT_LIMIT` times and
    /// reports the source broken.
    #[test]
    #[should_panic(expected = "the random source is broken")]
    fn encryption_under_a_source_stuck_on_a_refused_b_panics() {
        let b_len = EES401EP1_B_LEN;
        let (pk, draws) = ees401ep1_encryption_draws(500);
        let (i, log) = draws
            .iter()
            .enumerate()
            .find(|(_, log)| log.len() > b_len)
            .expect("an encryption that redrew b");
        let mut stuck = StuckRng(log[..b_len].to_vec());
        let _ = NtruEes401Ep1::encrypt(&pk, &[i as u8; 16], &mut stuck);
    }

    /// A source of all-one bytes makes every 32-bit index draw `u32::MAX`,
    /// which rejection sampling refuses, so key generation reports the
    /// source broken after `INDEX_DRAW_LIMIT` draws.
    #[test]
    #[should_panic(expected = "the random source is broken")]
    fn key_generation_under_a_source_of_all_ones_panics() {
        let _ = NtruEes401Ep1::keygen(&mut RepeatingRng(0xff));
    }

    #[test]
    fn ring_element_packing_matches_eess1_example() {
        // EESS #1 v3.1 §8.5.1 and v2 §2.3.5, q = 128: the bit string "0101101 0000010 1001101
        // 1100111 0001010" becomes "the octet string 5a 0a 6e 71 40". The
        // example polynomial prints its last coefficient as 12, but the bit
        // string and the octets both encode 10 (12 is 0001100, final octet
        // 0x80), so the self-consistent pair is what is checked here.
        let packed = [0x5au8, 0x0a, 0x6e, 0x71, 0x40];
        let mut out = [0u8; 5];
        pack_values(&[45, 2, 77, 103, 10], 7, &mut out);
        assert_eq!(out, packed);
        pack_values(&[45, 2, 77, 103, 12], 7, &mut out);
        assert_eq!(out[4], 0x80);
        let mut reader = BitReader::new(&packed);
        let values: Vec<u32> = (0..5).map(|_| reader.pull(7)).collect();
        assert_eq!(values, [45, 2, 77, 103, 10]);
        assert!(padding_bits_clear(&packed, 35));
        assert!(!padding_bits_clear(&[0x5a, 0x0a, 0x6e, 0x71, 0x41], 35));
    }

    #[test]
    fn hash_stream_uses_hashed_seed_and_four_octet_big_endian_counter() {
        let seed = b"sData";
        let mut z = [0u8; 20];
        HashKind::Sha1.digest(&[seed], &mut z);
        let mut expected = Vec::new();
        for counter in [[0u8, 0, 0, 0], [0, 0, 0, 1], [0, 0, 0, 2]] {
            let mut block = [0u8; 20];
            HashKind::Sha1.digest(&[&z, &counter], &mut block);
            expected.extend_from_slice(&block);
        }
        let mut stream = HashStream::new(HashKind::Sha1, seed, 1);
        let produced: Vec<u8> = (0..60).map(|_| stream.next_octet()).collect();
        assert_eq!(produced, expected);
    }

    #[test]
    fn igf2_reads_candidates_most_significant_bit_first() {
        let params = EesParams {
            n: 401,
            logq: 11,
            trapdoor: TrapdoorKind::Dense { df: 113 },
            dg: 133,
            dm0: 113,
            db_bits: 112,
            c_bits: 11,
            min_calls_r: 2,
            min_calls_mask: 1,
            pklen_bits: 112,
            oid: [0, 2, 4],
            hash: HashKind::Sha1,
        };
        let seed = b"seed";
        let mut stream = HashStream::new(params.hash, seed, 2);
        let octets: Vec<u8> = (0..40).map(|_| stream.next_octet()).collect();
        let mut expected = Vec::new();
        for k in 0..(40 * 8) / 11 {
            let mut v = 0u32;
            for bit in k * 11..k * 11 + 11 {
                v = (v << 1) | u32::from((octets[bit / 8] >> (7 - bit % 8)) & 1);
            }
            if v < params.index_limit() {
                expected.push((v % 401) as u16);
            }
        }
        let mut igf = IndexGenerator::new(seed, &params);
        let produced: Vec<u16> = (0..expected.len()).map(|_| igf.next_index()).collect();
        assert_eq!(produced, expected);
    }

    #[test]
    fn mgf_tp1_takes_base3_digits_least_significant_first() {
        let params = EesParams {
            n: 11,
            logq: 11,
            trapdoor: TrapdoorKind::Dense { df: 1 },
            dg: 1,
            dm0: 0,
            db_bits: 0,
            c_bits: 4,
            min_calls_r: 1,
            min_calls_mask: 1,
            pklen_bits: 0,
            oid: [0, 0, 0],
            hash: HashKind::Sha256,
        };
        let seed = b"R mod 4";
        let mut stream = HashStream::new(params.hash, seed, 1);
        let mut expected = Vec::new();
        while expected.len() < 11 {
            let octet = stream.next_octet();
            if octet < 243 {
                let mut rest = octet;
                for _ in 0..5 {
                    expected.push(rest % 3);
                    rest /= 3;
                }
            }
        }
        expected.truncate(11);
        assert_eq!(mgf_tp1::<11>(seed, &params).to_vec(), expected);
    }

    #[test]
    fn first_three_bits_become_first_two_trits() {
        // 0b110_101_01 ... : v = 6 → (2, 0), v = 5 → (1, 2).
        let trits = octets_to_trits::<5>(&[0b1101_0100, 0]);
        assert_eq!(trits, [2, 0, 1, 2, 0]);
        let mut back = [0u8; 2];
        assert_eq!(trits_to_octets(&trits, &mut back), 1);
        assert_eq!(back[0] & 0b1111_1100, 0b1101_0100);
    }

    #[test]
    fn trit_encoding_round_trips_and_flags_the_unused_pair() {
        let octets = [0xa7u8, 0x3c, 0x5e];
        let trits = octets_to_trits::<16>(&octets);
        let mut back = [0u8; 3];
        assert_eq!(trits_to_octets(&trits, &mut back), 1);
        assert_eq!(back, octets);

        let mut bad = trits;
        bad[2] = 2;
        bad[3] = 2;
        assert_eq!(trits_to_octets(&bad, &mut back), 0);
    }

    #[test]
    fn centring_is_the_half_open_interval() {
        let q = 2048;
        assert_eq!(centred_mod3(1023, q), 0); // 1023
        assert_eq!(centred_mod3(1024, q), 2); // −1024 ≡ 2
        assert_eq!(centred_mod3(2047, q), 2); // −1
        assert_eq!(centred_mod3(1, q), 1);
        assert_eq!(lift_trit(0, 2047), 0);
        assert_eq!(lift_trit(1, 2047), 1);
        assert_eq!(lift_trit(2, 2047), 2047);
    }

    #[test]
    fn branch_free_helpers() {
        assert_eq!((ct_eq(5, 5), ct_eq(5, 6), ct_eq(0, 0)), (1, 0, 1));
        assert_eq!((ct_ge(3, 3), ct_ge(4, 3), ct_ge(2, 3)), (1, 1, 0));
        assert_eq!((ct_select(1, 7, 9), ct_select(0, 7, 9)), (7, 9));
        assert_eq!(weight_ok(&[0, 1, 2, 0, 1, 2], 2), 1);
        assert_eq!(weight_ok(&[0, 1, 2, 0, 1, 1], 2), 0);
    }

    #[test]
    fn index_generator_ternary_takes_plus_then_minus() {
        let params = EesParams {
            n: 443,
            logq: 11,
            trapdoor: TrapdoorKind::ProductForm {
                df1: 9,
                df2: 8,
                df3: 5,
            },
            dg: 148,
            dm0: 115,
            db_bits: 256,
            c_bits: 9,
            min_calls_r: 8,
            min_calls_mask: 5,
            pklen_bits: 128,
            oid: [0, 3, 17],
            hash: HashKind::Sha256,
        };
        let mut raw = IndexGenerator::new(b"x", &params);
        let mut distinct = Vec::new();
        while distinct.len() < 18 {
            let i = raw.next_index();
            if !distinct.contains(&i) {
                distinct.push(i);
            }
        }
        let t = IndexGenerator::new(b"x", &params).ternary(9, 9);
        // (−1, −1) sets the failure flag and writes 111 (§10.2.3 step h).
        let mut bits = [0u8; 1];
        assert_eq!(trits_to_octets(&[2, 2], &mut bits), 0);
        assert_eq!(bits[0], 0b1110_0000);
        assert_eq!(t.ones, distinct[..9]);
        assert_eq!(t.neg_ones, distinct[9..]);
    }

    const EES401: EesParams = EesParams {
        n: 401,
        logq: 11,
        trapdoor: TrapdoorKind::Dense { df: 113 },
        dg: 133,
        dm0: 113,
        db_bits: 112,
        c_bits: 11,
        min_calls_r: 32,
        min_calls_mask: 9,
        pklen_bits: 112,
        oid: [0x00, 0x02, 0x04],
        hash: HashKind::Sha1,
    };

    /// Build a ciphertext the way `encrypt` does, but from an explicit padded
    /// block, explicit `sData` inputs and an adjustable representative.
    /// Returns the ciphertext and whether the representative meets `dm0`.
    fn craft(
        params: &EesParams,
        packed_h: &[u8],
        block: &[u8],
        seed_msg: &[u8],
        seed_b: &[u8],
        tweak: impl FnOnce(&mut [u8; 401]),
    ) -> (Vec<u8>, u32) {
        let q_mask = params.q_mask();
        let h = unpack_ring::<401>(packed_h, params);
        let mut sdata = params.oid.to_vec();
        sdata.extend_from_slice(seed_msg);
        sdata.extend_from_slice(seed_b);
        sdata.extend_from_slice(&packed_h[..params.htrunc_len()]);
        let r = blinding_value(&sdata, params);
        let mut big_r = Poly::<401>::zero();
        r.mul_dense(&h, &mut big_r);
        poly_mod_q(&mut big_r, q_mask);
        let mask = mgf_tp1::<401>(&pack_mod4(&big_r), params);
        let mut representative = octets_to_trits::<401>(block);
        for (t, &m) in representative.iter_mut().zip(mask.iter()) {
            *t = (*t + m) % 3;
        }
        tweak(&mut representative);
        let weight = weight_ok(&representative, params.dm0);
        let mut e = big_r;
        for (c, &t) in e.coeffs.iter_mut().zip(representative.iter()) {
            *c = c.wrapping_add(lift_trit(t, q_mask)) & q_mask;
        }
        let mut ct = vec![0u8; params.ciphertext_bytes()];
        pack_ring(&e, params, &mut ct);
        (ct, weight)
    }

    /// `b ‖ length ‖ body ‖ zeros`, `padded_message_bytes` long.
    fn padded_block(params: &EesParams, b: &[u8], length: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; params.padded_message_bytes()];
        m[..b.len()].copy_from_slice(b);
        m[b.len()] = length;
        m[b.len() + 1..b.len() + 1 + body.len()].copy_from_slice(body);
        m
    }

    /// The first ciphertext, over salts `[s; bLen]`, whose representative
    /// meets `dm0`.
    fn with_weight(make: impl Fn([u8; 14]) -> (Vec<u8>, u32)) -> Vec<u8> {
        (0..=255u8)
            .map(|s| make([s; 14]))
            .find(|(_, weight)| *weight == 1)
            .map(|(ct, _)| ct)
            .expect("some salt meets dm0")
    }

    #[test]
    fn each_decryption_failure_rule_rejects_on_its_own() {
        let params = EES401;
        let mut drbg = crate::CtrDrbgAes256::new(&[0x5au8; 48]);
        let (packed_h, trapdoor) = keygen::<401, _>(&params, &mut drbg);
        let decrypt_with = |ct: &[u8], p: &EesParams| decrypt::<401>(&trapdoor, &packed_h, ct, p);
        let max = params.max_message_bytes();
        let body_at = params.b_len() + LENGTH_OCTETS;
        // The message starts with 0xff, so trit pair 40 (bits 120–122, the
        // first three bits of the message) is (−1, 1).
        let msg = [0xffu8, 0x12, 0x34, 0x56, 0x78];
        let honest = |b: [u8; 14]| {
            let block = padded_block(&params, &b, msg.len() as u8, &msg);
            craft(&params, &packed_h, &block, &msg, &b, |_| {})
        };

        // Control: a well-formed ciphertext decrypts.
        let ct = with_weight(honest);
        assert_eq!(decrypt_with(&ct, &params), Ok(msg.to_vec()));

        // Step c: the same ciphertext fails once dm0 exceeds N/3.
        let strict = EesParams { dm0: 134, ..params };
        assert_eq!(
            decrypt_with(&ct, &strict),
            Err(NtruEesError::InvalidCiphertext)
        );

        // Step h: pair 40 decrypts to (−1, −1), which writes the same 111.
        let ct = with_weight(|b| {
            let block = padded_block(&params, &b, msg.len() as u8, &msg);
            craft(&params, &packed_h, &block, &msg, &b, |t| {
                t[81] = (t[81] + 1) % 3
            })
        });
        assert_eq!(
            decrypt_with(&ct, &params),
            Err(NtruEesError::InvalidCiphertext)
        );

        // Step k2: a length above maxMsgLenBytes fails, and cl is clamped to
        // step a's maxLen = ⌈401/8⌉ − 1 − 1 − 14 = 35 for the checks that
        // follow.
        assert_eq!(params.decryption_max_len(), 35);
        let long_body = vec![0x11u8; max];
        let ct = with_weight(|b| {
            let block = padded_block(&params, &b, max as u8 + 1, &long_body);
            craft(&params, &packed_h, &block, &long_body, &b, |_| {})
        });
        let recovered = recover::<401>(&trapdoor, &packed_h, &ct, &params);
        assert_eq!(recovered.cl, 35);
        assert_eq!(recovered.listed_checks, 0);
        assert_eq!(
            decrypt_with(&ct, &params),
            Err(NtruEesError::InvalidCiphertext)
        );
        let ct = with_weight(|b| {
            let block = padded_block(&params, &b, max as u8, &long_body);
            craft(&params, &packed_h, &block, &long_body, &b, |_| {})
        });
        assert_eq!(decrypt_with(&ct, &params), Ok(long_body.clone()));

        // Step k3: a nonzero octet in p0, first and last.
        for (at, value) in [(body_at + msg.len(), 0x80u8), (body_at + max, 0x60)] {
            let ct = with_weight(|b| {
                let mut block = padded_block(&params, &b, msg.len() as u8, &msg);
                block[at] = value;
                craft(&params, &packed_h, &block, &msg, &b, |_| {})
            });
            assert_eq!(
                decrypt_with(&ct, &params),
                Err(NtruEesError::InvalidCiphertext),
                "nonzero padding octet at {at}"
            );
        }

        // Step o: r derived from a different salt than the one in M.
        let ct = with_weight(|b| {
            let block = padded_block(&params, &b, msg.len() as u8, &msg);
            let mut other = b;
            other[0] ^= 1;
            craft(&params, &packed_h, &block, &msg, &other, |_| {})
        });
        assert_eq!(
            decrypt_with(&ct, &params),
            Err(NtruEesError::InvalidCiphertext)
        );
    }

    #[test]
    fn trit_packed_keys_reject_each_malformation_on_its_own() {
        // N = 7, df = 1: +1 at degree 0 and −1 at degree 1 is [7, 0].
        assert!(read_trits(&[7, 0], 7, 1).is_some());
        // 250 has the same five digits as 7; only the range check rejects it.
        assert!(read_trits(&[250, 0], 7, 1).is_none());
        // +1 at degree 7, past N − 1, with both counts still right.
        assert!(read_trits(&[6, 9], 7, 1).is_none());
        // The same key with the +1 at degree 6 is fine.
        assert!(read_trits(&[6, 3], 7, 1).is_some());
    }

    #[test]
    fn invertibility_mod_q_follows_invertibility_mod_2() {
        let mut one = Poly::<11>::zero();
        one.coeffs[0] = 1;
        assert!(invertible_mod_q(&one));
        // 1 + x + … + x¹⁰ divides x¹¹ − 1.
        let mut all_ones = Poly::<11>::zero();
        all_ones.coeffs.fill(1);
        assert!(!invertible_mod_q(&all_ones));
        // 1 − x³ vanishes at x = 1.
        let mut even = Poly::<11>::zero();
        even.coeffs[0] = 1;
        even.coeffs[3] = 2047;
        assert!(!invertible_mod_q(&even));
        // An element of T(2, 1).
        let mut g = Poly::<11>::zero();
        g.coeffs[0] = 1;
        g.coeffs[2] = 1;
        g.coeffs[5] = 2047;
        assert!(invertible_mod_q(&g));
    }

    /// The last decoded octet for every set: the bits past `M` (convention
    /// 10), the bits §10.2.3 step i truncates, the coefficients whose trits
    /// reach that octet, and that no tampering there decrypts. Where no bit
    /// lies past `M` (and for `ees677ep1`, whose one such bit shares its
    /// trit pair with the last bit of `p0`) the listed checks of §10.2.3
    /// already reject every tampering, since the octet belongs to `p0`. Each
    /// survey also round-trips `TRIALS` honest ciphertexts.
    #[test]
    fn last_decoded_octet_by_parameter_set() {
        use crate::public_key::{
            ntru_ees1087ep1, ntru_ees1087ep2, ntru_ees1171ep1, ntru_ees1499ep1, ntru_ees401ep1,
            ntru_ees443ep1, ntru_ees449ep1, ntru_ees541ep1, ntru_ees677ep1,
        };
        const TRIALS: usize = 16;
        // (set, survey, bits past M, bits step i truncates, coefficients)
        let surveys: [(&str, tamper::Survey, usize, usize, &[usize]); 9] = [
            (
                "ees401ep1",
                ntru_ees401ep1::tamper_survey(TRIALS),
                0,
                3,
                &[400],
            ),
            (
                "ees443ep1",
                ntru_ees443ep1::tamper_survey(TRIALS),
                2,
                2,
                &[442],
            ),
            (
                "ees449ep1",
                ntru_ees449ep1::tamper_survey(TRIALS),
                0,
                3,
                &[448],
            ),
            (
                "ees541ep1",
                ntru_ees541ep1::tamper_survey(TRIALS),
                0,
                5,
                &[538, 539, 540],
            ),
            (
                "ees677ep1",
                ntru_ees677ep1::tamper_survey(TRIALS),
                1,
                1,
                &[676],
            ),
            (
                "ees1087ep1",
                ntru_ees1087ep1::tamper_survey(TRIALS),
                0,
                0,
                &[1082, 1083, 1084, 1085, 1086],
            ),
            (
                "ees1087ep2",
                ntru_ees1087ep2::tamper_survey(TRIALS),
                0,
                0,
                &[1082, 1083, 1084, 1085, 1086],
            ),
            (
                "ees1171ep1",
                ntru_ees1171ep1::tamper_survey(TRIALS),
                0,
                6,
                &[1168, 1169, 1170],
            ),
            (
                "ees1499ep1",
                ntru_ees1499ep1::tamper_survey(TRIALS),
                2,
                2,
                &[1498],
            ),
        ];
        for (name, survey, past, truncated, positions) in &surveys {
            assert_eq!(survey.bits_past_message, *past, "{name}: bits past M");
            assert_eq!(survey.truncated_bits, *truncated, "{name}: truncated bits");
            assert_eq!(survey.positions, *positions, "{name}: coefficients");
            assert_eq!(survey.outcomes.len(), 4 * positions.len(), "{name}");
            for o in &survey.outcomes {
                assert_eq!(
                    o.after, 0,
                    "{name}: e[{}] {:+} decrypted",
                    o.position, o.delta
                );
                if *past == 0 || *name == "ees677ep1" {
                    assert_eq!(
                        o.before, 0,
                        "{name}: e[{}] {:+} passed the listed checks",
                        o.position, o.delta
                    );
                }
            }
        }
    }

    /// Asserts a survey of an `N` = 443 or 1499 set: only coefficient `N − 1`
    /// reaches past `M`; before convention 10's check, +1 there kept the
    /// plaintext about two times in three and −2 the remaining third; now
    /// nothing decrypts. Prints the counts.
    fn tampering_past_the_message_is_rejected(name: &str, n: usize, trials: usize) {
        let survey = match n {
            443 => crate::public_key::ntru_ees443ep1::tamper_survey(trials),
            1499 => crate::public_key::ntru_ees1499ep1::tamper_survey(trials),
            _ => unreachable!("no other set is malleable"),
        };
        assert_eq!(survey.positions, [n - 1], "{name}");
        for o in &survey.outcomes {
            println!(
                "{name}: e[{}] {:+}: plaintext kept {}/{trials} before the check, {}/{trials} after",
                o.position, o.delta, o.before, o.after
            );
            assert_eq!(
                o.after, 0,
                "{name}: e[{}] {:+} decrypted",
                o.position, o.delta
            );
        }
        let before = |delta| {
            survey
                .outcomes
                .iter()
                .find(|o| o.delta == delta)
                .map(|o| o.before)
                .expect("delta surveyed")
        };
        // +1 keeps cR when m'[N − 1] is 0 or −1, and −2 when it is 1; both
        // leave the trit 1, which writes 011 and changes only the bits past
        // M. −1 and +2 leave −1, whose 110 sets the last bit of p0.
        let (plus_one, minus_two) = (before(1), before(-2));
        // Each rate within 0.1 of its expectation: three standard deviations
        // over 200 trials.
        let near_thirds =
            |count: usize, thirds: usize| (30 * count).abs_diff(10 * thirds * trials) <= 3 * trials;
        assert!(near_thirds(plus_one, 2), "{name}: +1");
        assert!(near_thirds(minus_two, 1), "{name}: -2");
        assert!(plus_one + minus_two >= trials * 49 / 50, "{name}");
        assert_eq!((before(-1), before(2)), (0, 0), "{name}");
    }

    #[test]
    fn tampering_past_the_message_is_rejected_ees443ep1() {
        tampering_past_the_message_is_rejected("ees443ep1", 443, 600);
    }

    #[test]
    fn tampering_past_the_message_is_rejected_ees1499ep1() {
        tampering_past_the_message_is_rejected("ees1499ep1", 1499, 200);
    }

    /// Prints the crate-produced blocks of the vector file; run by
    /// `scripts/ees_ref_vectors/generate.sh`.
    #[test]
    #[ignore = "regenerates part of tests/vectors/ntru_ees_sves3_reference.txt"]
    fn emit_crate_vector_blocks() {
        let mut out = String::new();
        crate::public_key::ntru_ees401ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees449ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees677ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees1087ep2::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees541ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees1171ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees1087ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees1499ep1::emit_crate_vector_blocks(&mut out);
        crate::public_key::ntru_ees443ep1::emit_crate_vector_blocks(&mut out);
        println!("-----BEGIN CRATE BLOCKS-----{out}-----END CRATE BLOCKS-----");
    }
}
