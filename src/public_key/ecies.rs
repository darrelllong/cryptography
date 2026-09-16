//! Elliptic Curve Integrated Encryption Scheme (ECIES), as SEC 1 v2.0 §5.1
//! specifies it.
//!
//! Reference: *SEC 1: Elliptic Curve Cryptography*, Version 2.0, Certicom
//! Research for the Standards for Efficient Cryptography Group, May 21, 2009
//! (`pubs/sec1-v2-elliptic-curve-cryptography.pdf`). Section numbers in this
//! module are SEC 1 v2.0's unless they say otherwise.
//!
//! # Scheme setup (§5.1.1)
//!
//! SEC 1 specifies a family of schemes. The recipient V makes the choices and
//! the sender U must obtain them in an authentic manner (§5.1.1 step 6). An
//! [`EciesSetup`] carries every choice, each as a type whose variants are the
//! options SEC 1 lists, and both operations take one explicitly. Nothing in a
//! ciphertext names its setup, and this module has no default.
//!
//! | §5.1.1 step | Choice | Where |
//! |---|---|---|
//! | 1 | key derivation function (§3.6) | [`EciesKdf`] |
//! | 2 | MAC scheme (§3.7) | [`EciesMac`] |
//! | 3, 9 | symmetric encryption scheme (§3.8) and, for XOR, the backwards compatibility mode | [`EciesEncryption`] |
//! | 4 | standard (§3.3.1) or cofactor (§3.3.2) Diffie–Hellman primitive | [`EciesDhPrimitive`] |
//! | 5 | elliptic curve domain parameters | the key's [`CurveParams`] |
//! | 7 | point compression for `R` (§2.3.3) | [`EciesPointFormat`] |
//! | 8 | a SharedInfo₂ format that makes `EM ‖ SharedInfo₂` parse uniquely | the application (see below) |
//!
//! [`EciesSetup::RECOMMENDED`] is one documented choice.
//!
//! # Encryption operation (§5.1.3)
//!
//! [`EciesPublicKey::encrypt`] takes the message `M` and the optional
//! SharedInfo₁ and SharedInfo₂, and
//!
//! 1. selects an ephemeral key pair `(k, R)`, `R = k·G`, with the key pair
//!    generation primitive of §3.2.1;
//! 2. converts `R` to an octet string (§2.3.3), compressed or not as the
//!    setup says;
//! 3. derives the shared secret field element `z` from `k` and the
//!    recipient's `Q_V` with the setup's primitive: `z = x(k·Q_V)` (§3.3.1) or
//!    `z = x(h·k·Q_V)` (§3.3.2), "invalid" if that point is `O`;
//! 4. converts `z` to the octet string `Z` (§2.3.5);
//! 5. derives `enckeylen + mackeylen` octets of keying data `K` from `Z` and
//!    SharedInfo₁ with the KDF;
//! 6. takes the encryption key `EK` from the left of `K` and the MAC key `MK`
//!    from the right, except that the XOR scheme outside backwards
//!    compatibility mode takes `MK` from the left and `EK` from the right;
//! 7. encrypts `EM = ENC_EK(M)`;
//! 8. computes the tag `D = MAC_MK(EM ‖ SharedInfo₂)`;
//! 9. outputs `C = R ‖ EM ‖ D`, the octet-string form step 9 permits.
//!
//! # Decryption operation (§5.1.4)
//!
//! [`EciesPrivateKey::decrypt`]
//!
//! 1. parses `C`: a leading octet `02` or `03` makes `R` the first
//!    `mlen + 1` octets and `04` the first `2·mlen + 1`, where
//!    `mlen = ⌈log₂ q / 8⌉`; any other leading octet is invalid. `D` is the
//!    last `maclen` octets and `EM` lies between;
//! 2. converts `R` to a point (§2.3.4), which rejects coordinates outside the
//!    field and points off the curve;
//! 3. requires `R` to be a valid public key (§3.2.2.1: `R ≠ O` and `n·R = O`
//!    as well) under standard Diffie–Hellman, or at least a partially valid
//!    one (§3.2.3.1: `R ≠ O`) under cofactor Diffie–Hellman;
//! 4. derives `z` from its private key `d_V` and `R` with the setup's
//!    primitive, "invalid" if the shared point is `O`;
//! 5. converts `z` to `Z` (§2.3.5);
//! 6. derives `K` from `Z` and SharedInfo₁ as encryption did (for XOR,
//!    `enckeylen = |EM|`);
//! 7. splits `K` into `EK` and `MK` as encryption did;
//! 8. checks, in constant time, that `D = MAC_MK(EM ‖ SharedInfo₂)`;
//! 9. only then decrypts `EM` under `EK` and outputs `M`.
//!
//! Every failure is SEC 1's single outcome "invalid", returned as `None`. The
//! setup's point format governs encryption only: step 1 accepts either
//! encoding of `R`.
//!
//! # Ciphertext layout
//!
//! ```text
//! C = R || EM || D
//!
//! R   the §2.3.3 encoding of the ephemeral point R = k·G
//!       EciesPointFormat::Uncompressed   04 || X || Y     1 + 2·mlen octets
//!       EciesPointFormat::Compressed     02 || X  or
//!                                        03 || X          1 + mlen octets
//!     mlen = ⌈log₂ q / 8⌉ = CurveParams::coord_len (32 for P-256, 21 for K-163)
//! EM  ENC_EK(M): |M| octets for every scheme SEC 1 lists
//! D   maclen octets: x/8 for HMAC-Hash-x, 16 for CMAC-AES-x
//! ```
//!
//! No IV or initial counter block travels with `C`: §3.8 fixes both at zero,
//! which is sound only because every encryption derives a fresh key. Under
//! [`EciesSetup::RECOMMENDED`] on P-256 a ciphertext is `|M| + 97` octets.
//!
//! # SharedInfo₁ and SharedInfo₂
//!
//! Both are optional inputs in SEC 1. An absent value contributes nothing to
//! the concatenation it appears in, so "absent" and an empty slice are the
//! same input: pass `&[]`. The decryptor must supply the values the encryptor
//! used.
//!
//! - SharedInfo₁ is the KDF's shared data: `K_i = Hash(Z ‖ Counter ‖ SharedInfo₁)`.
//! - SharedInfo₂ follows `EM` in the MAC input. §5.1.1 step 8 requires a
//!   format under which `EM ‖ SharedInfo₂` parses uniquely, for example a
//!   suffix-free one that ends in its own length. Without one, octets can move
//!   between the end of `EM` and the start of SharedInfo₂ under the same tag,
//!   and the recipient accepts a truncated or extended plaintext (Appendix
//!   B.4.1). This module cannot check the application's format.
//!
//! # Malleability SEC 1 accepts
//!
//! `R` is not an input to the key derivation, so a ciphertext has other valid
//! forms with the same plaintext, which Appendix B.4.1 calls benign
//! malleability: `−R` in place of `R` (the shared point's x-coordinate does not
//! change), the other encoding of `R`, and under cofactor Diffie–Hellman
//! `±R + S` for any `S` whose order divides `h`. None of them changes the
//! plaintext. An application that needs a unique ciphertext can put `R` into
//! SharedInfo₁, as Appendix B.4.1 suggests.
//!
//! # Known answers
//!
//! The unit tests hold this module to external evidence:
//!
//! - GEC 2 v0.3 §3.1–3.3 (`tests/vectors/sec1_gec2_ecaes.txt`), the ECIES
//!   test vectors SEC 1 Appendix B.4.1 cites: every intermediate value and the
//!   ciphertext, on secp160r1 and on sect163k1 (K-163) under both
//!   Diffie–Hellman primitives;
//! - NIST CAVP's ANS X9.63-2001 KDF vectors
//!   (`tests/vectors/cavp_ansx963_2001_kdf.rsp`): ANSI-X9.63-KDF under every
//!   hash SEC 1 lists, with and without shared data;
//! - NIST CAVP's ECC CDH primitive vectors
//!   (`tests/vectors/cavp_kas_ecc_cdh_primitive.txt`): the cofactor
//!   Diffie–Hellman primitive and the §2.3.5 conversion on every NIST prime
//!   and binary curve.
//!
//! # Side channels and scrubbing
//!
//! Scalar multiplication is not constant-time; see [`ec`]. The tag comparison
//! is. Every secret this module holds is wiped when it is dropped. The
//! ephemeral scalar `k`, the product `h·d` and the coordinates of the shared
//! point are `BigUint`s, whose limbs `rump` wipes on drop: this crate turns
//! `rump`'s `wipe` feature on unconditionally in its `Cargo.toml`, so no
//! build leaves them behind. `Z`, the keying data `K` and the tag recomputed
//! for checking live in a buffer that wipes itself on drop, and the block
//! ciphers take their keys through their `new_wiping` constructors, which
//! wipe the key octets once the schedule is built.
//!
//! [`ec`]: crate::public_key::ec

use core::fmt;

use crate::ciphers::aes::{Aes128, Aes192, Aes256};
use crate::ciphers::des::TripleDes;
use crate::hash::hmac::Hmac;
use crate::hash::sha1::Sha1;
use crate::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use crate::hash::Digest;
use crate::modes::{Cbc, Cmac, Ctr};
use crate::public_key::ec::{AffinePoint, CurveParams};
use crate::{BlockCipher, Csprng};
use rump::BigUint;

/// SEC 1 §3.8: the IV of every CBC scheme and the initial counter block of
/// every CTR scheme is the all-zero block, and neither is transmitted.
const ZERO_BLOCK: [u8; 16] = [0; 16];

// ─── Scheme setup (SEC 1 §5.1.1) ─────────────────────────────────────────────

/// A hash function from the list of SEC 1 §3.5, for the key derivation
/// function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EciesHash {
    /// SHA-1 (FIPS 180-4). SEC 1 v1.0 allowed only SHA-1 in ECIES; it is here
    /// to interoperate with v1.0 peers and to reproduce the GEC 2 vectors.
    Sha1,
    /// SHA-224 (FIPS 180-4).
    Sha224,
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
}

/// The key derivation function (SEC 1 §5.1.1 step 1).
///
/// SEC 1 §3.6 lists four functions. IKEv2-KDF and TLS-KDF are reserved for
/// Diffie–Hellman inside IKEv2 and TLS. SEC 1 does not define how
/// SharedInfo₁ becomes the input of NIST-800-56-Concatenation-KDF, and it is
/// not implemented. ANSI-X9.63-KDF (§3.6.1) is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EciesKdf {
    /// ANSI-X9.63-KDF (SEC 1 §3.6.1) over the given hash:
    /// `K = Hash(Z ‖ 00000001 ‖ SharedInfo₁) ‖ Hash(Z ‖ 00000002 ‖ SharedInfo₁) ‖ …`,
    /// with a 32-bit big-endian counter, cut to the leftmost `keydatalen`
    /// octets.
    AnsiX963(EciesHash),
}

/// The symmetric encryption scheme (SEC 1 §5.1.1 steps 3 and 9), from the
/// list of SEC 1 §3.8.
///
/// The CBC schemes encrypt only messages that are one or more whole blocks:
/// SEC 1 names no padding, and SP 800-38A Appendix A (`pubs/sp800-38a.pdf`)
/// requires CBC plaintext to be a positive multiple of the block length and
/// leaves padding outside its scope. XOR and CTR take messages of any length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EciesEncryption {
    /// The XOR encryption scheme (SEC 1 §3.8), `EM = M ⊕ EK` with
    /// `enckeylen = |M|`, laid out as SEC 1 v2.0 requires: `MK` is the leftmost
    /// `mackeylen` octets of `K` and `EK` the rest (§5.1.3 step 6).
    Xor,
    /// The XOR encryption scheme in the backwards compatibility mode of
    /// §5.1.1 step 9, which keeps SEC 1 v1.0's layout: `EK` leftmost, `MK`
    /// rightmost.
    ///
    /// Appendix B.4.1 shows an attacker who knows `mackeylen` octets in the
    /// middle of a variable-length message can turn its ciphertext into a
    /// valid encryption of a modified prefix, and advises against this mode
    /// unless messages have a fixed length, as in key transport. Use it only to
    /// interoperate with SEC 1 v1.0.
    XorBackwardsCompatible,
    /// 3-key TDES in CBC mode (SEC 1 §3.8, ANS X9.52): a 24-octet key read as
    /// `K1 ‖ K2 ‖ K3` with the low bit of every octet replaced by odd parity,
    /// and a zero IV. Messages must be whole 8-octet blocks. The parity
    /// replacement changes no ciphertext: DES discards the parity bits in
    /// PC-1 (FIPS 46-3), and the key screen compares components with them
    /// stripped. A derived key with a weak, semi-weak or repeated component
    /// is refused as [`EciesError::RejectedDerivedKey`].
    TdesCbc,
    /// AES-128 in CBC mode (SEC 1 §3.8, SP 800-38A) with a zero IV. Messages
    /// must be whole 16-octet blocks.
    Aes128Cbc,
    /// AES-192 in CBC mode with a zero IV. Messages must be whole 16-octet
    /// blocks.
    Aes192Cbc,
    /// AES-256 in CBC mode with a zero IV. Messages must be whole 16-octet
    /// blocks.
    Aes256Cbc,
    /// AES-128 in CTR mode (SEC 1 §3.8, SP 800-38A) with an all-zero initial
    /// counter block.
    Aes128Ctr,
    /// AES-192 in CTR mode with an all-zero initial counter block.
    Aes192Ctr,
    /// AES-256 in CTR mode with an all-zero initial counter block.
    Aes256Ctr,
}

/// The MAC scheme (SEC 1 §5.1.1 step 2), from the list of SEC 1 §3.7.
///
/// `HMAC-Hash-x` is HMAC (FIPS 198-1) under a `hashlen`-octet key with the
/// tag cut to the leftmost `x/8` octets; `CMAC-AES-x` is CMAC (SP 800-38B)
/// over AES with an `x`-bit key and a 16-octet tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EciesMac {
    /// HMAC-SHA-1-160: 20-octet key, 20-octet tag.
    HmacSha1_160,
    /// HMAC-SHA-1-80: 20-octet key, 10-octet tag.
    HmacSha1_80,
    /// HMAC-SHA-224-112: 28-octet key, 14-octet tag.
    HmacSha224_112,
    /// HMAC-SHA-224-224: 28-octet key, 28-octet tag.
    HmacSha224_224,
    /// HMAC-SHA-256-128: 32-octet key, 16-octet tag.
    HmacSha256_128,
    /// HMAC-SHA-256-256: 32-octet key, 32-octet tag.
    HmacSha256_256,
    /// HMAC-SHA-384-192: 48-octet key, 24-octet tag.
    HmacSha384_192,
    /// HMAC-SHA-384-384: 48-octet key, 48-octet tag.
    ///
    /// SEC 1 v2.0 §3.7 prints this entry as "HMAC–SHA-384–284 with 48 octet
    /// or 384 bit keys". Under the section's own notation the last number is
    /// the tag length in bits, and 284 is not a whole number of octets; the
    /// pairing with SHA-512-512 and SHA-256-256 makes 384 the evident reading.
    HmacSha384_384,
    /// HMAC-SHA-512-256: 64-octet key, 32-octet tag.
    HmacSha512_256,
    /// HMAC-SHA-512-512: 64-octet key, 64-octet tag.
    HmacSha512_512,
    /// CMAC-AES-128: 16-octet key, 16-octet tag.
    CmacAes128,
    /// CMAC-AES-192: 24-octet key, 16-octet tag.
    CmacAes192,
    /// CMAC-AES-256: 32-octet key, 16-octet tag.
    CmacAes256,
}

/// The Diffie–Hellman primitive (SEC 1 §5.1.1 step 4).
///
/// On curves with cofactor `h = 1`, which includes every prime curve in this
/// crate, both primitives compute the same `z`. On the binary B/K curves
/// (`h = 2` or `4`) they do not, so sender and recipient must agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EciesDhPrimitive {
    /// The elliptic curve Diffie–Hellman primitive (§3.3.1),
    /// `z = x(d·Q)`. The peer's point must be fully valid (§3.2.2.1),
    /// including `n·Q = O`, which decryption checks for `R`.
    Standard,
    /// The elliptic curve cofactor Diffie–Hellman primitive (§3.3.2),
    /// `z = x(h·d·Q)`. Multiplying by `h` clears any small-order component, so
    /// the peer's point need only be partially valid (§3.2.3.1).
    Cofactor,
}

/// Whether the encryption operation represents `R` with point compression
/// (SEC 1 §5.1.1 step 7, §2.3.3).
///
/// This choice shapes encryption only. Decryption accepts either encoding, as
/// §5.1.4 step 1 parses `R` by its leading octet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EciesPointFormat {
    /// `04 ‖ X ‖ Y`, `1 + 2·mlen` octets.
    Uncompressed,
    /// `02 ‖ X` or `03 ‖ X`, `1 + mlen` octets.
    Compressed,
}

/// The SEC 1 §5.1.1 scheme setup: every choice ECIES leaves to the recipient.
///
/// Sender and recipient must use the same setup, and §5.1.1 step 6 requires
/// the sender to obtain it in an authentic manner; a ciphertext does not
/// record it. The domain parameters, the fifth choice, belong to the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EciesSetup {
    kdf: EciesKdf,
    encryption: EciesEncryption,
    mac: EciesMac,
    dh: EciesDhPrimitive,
    point_format: EciesPointFormat,
}

impl EciesSetup {
    /// The setup this crate recommends, aimed at the 128-bit security level
    /// of P-256:
    ///
    /// - [`EciesKdf::AnsiX963`] over [`EciesHash::Sha256`] with
    ///   [`EciesMac::HmacSha256_256`]: §3.5 asks for a hash of twice the
    ///   desired security level for key derivation and for HMAC in ECIES.
    /// - [`EciesEncryption::Aes128Ctr`]: a 128-bit key at the same level. CTR
    ///   rather than CBC because SEC 1 defines no CBC padding, so the CBC
    ///   schemes take whole blocks only; a block cipher rather than XOR
    ///   because Appendix B.4.1 prefers one for long messages, which under
    ///   XOR need as much KDF output as they have octets.
    /// - [`EciesDhPrimitive::Cofactor`]: on the prime curves (`h = 1`) it
    ///   computes the same `z` as the standard primitive; on the binary B/K
    ///   curves (`h = 2` or `4`) it clears a small-order component of `R`
    ///   itself, so `R` needs only partial validation and decryption skips
    ///   the `n·R` multiplication (§3.3.2, Appendix B.4.1).
    /// - [`EciesPointFormat::Uncompressed`]: decoding `R` takes no square
    ///   root.
    ///
    /// For curves above that level (P-384, P-521, B/K-409 and B/K-571) build
    /// a setup with a longer hash, AES key and tag through [`EciesSetup::new`].
    pub const RECOMMENDED: Self = Self::new(
        EciesKdf::AnsiX963(EciesHash::Sha256),
        EciesEncryption::Aes128Ctr,
        EciesMac::HmacSha256_256,
        EciesDhPrimitive::Cofactor,
        EciesPointFormat::Uncompressed,
    );

    /// A setup from the five choices of SEC 1 §5.1.1 steps 1–4, 7 and 9.
    #[must_use]
    pub const fn new(
        kdf: EciesKdf,
        encryption: EciesEncryption,
        mac: EciesMac,
        dh: EciesDhPrimitive,
        point_format: EciesPointFormat,
    ) -> Self {
        Self {
            kdf,
            encryption,
            mac,
            dh,
            point_format,
        }
    }

    /// The key derivation function.
    #[must_use]
    pub const fn kdf(self) -> EciesKdf {
        self.kdf
    }

    /// The symmetric encryption scheme.
    #[must_use]
    pub const fn encryption(self) -> EciesEncryption {
        self.encryption
    }

    /// The MAC scheme.
    #[must_use]
    pub const fn mac(self) -> EciesMac {
        self.mac
    }

    /// The Diffie–Hellman primitive.
    #[must_use]
    pub const fn dh_primitive(self) -> EciesDhPrimitive {
        self.dh
    }

    /// Whether encryption compresses `R`.
    #[must_use]
    pub const fn point_format(self) -> EciesPointFormat {
        self.point_format
    }
}

/// Why the ECIES encryption operation (SEC 1 §5.1.3) output "invalid".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EciesError {
    /// The Diffie–Hellman primitive met the point at infinity (§3.3.1 and
    /// §3.3.2, step 2). Encryption reaches it only on domain parameters
    /// whose subgroup order is not the order of `G`; decryption reaches it
    /// on valid parameters too, under the cofactor primitive, when the `R`
    /// read from the wire has order dividing `h` (partial validation, §3.2.3.1,
    /// admits such a point and `h·d·R = O` then rejects it).
    InvalidSharedSecret,
    /// ANSI-X9.63-KDF refused (§3.6.1 steps 1–2): `|Z| + |SharedInfo₁| + 4`
    /// reached the hash's maximum input length, or `keydatalen` reached
    /// `hashlen × (2³² − 1)`. Under XOR, `keydatalen` grows with the message.
    KeyDataTooLong,
    /// A CBC scheme was given a message that is empty or not a whole number of
    /// blocks. SEC 1 names no padding, and SP 800-38A Appendix A requires one
    /// or more complete blocks.
    MessageNotBlockAligned,
    /// 3-key TDES refused the key derived for this message because a
    /// component is weak or semi-weak or two components repeat (SP 800-67),
    /// with probability about 2⁻⁵⁰ per message. SEC 1 §3.8 has no such step;
    /// the refusal is this crate's policy, applied by its TDES constructor
    /// to every key and passed on here rather than encrypting under a key
    /// the crate would not accept elsewhere. A sender that meets it draws a
    /// fresh ephemeral key by encrypting again.
    RejectedDerivedKey,
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// Public key for ECIES: an ordinary SEC 1 elliptic curve public key `Q_V`
/// (§3.2) together with its domain parameters.
#[derive(Clone, Debug)]
pub struct EciesPublicKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Public point `Q = d·G`.
    q: AffinePoint,
}

/// Private key for ECIES: an ordinary SEC 1 elliptic curve key pair
/// `(d_V, Q_V)` (§3.2).
#[derive(Clone)]
pub struct EciesPrivateKey {
    /// Full short-Weierstrass curve parameters for this key.
    curve: CurveParams,
    /// Secret scalar `d ∈ [1, n)`.
    d: BigUint,
    /// Cached public point `Q = d·G`.
    q: AffinePoint,
}

/// Namespace for ECIES key generation.
pub struct Ecies;

// ─── EciesPublicKey ──────────────────────────────────────────────────────────

impl EciesPublicKey {
    /// The curve parameters for this key.
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The public point `Q = d·G`.
    #[must_use]
    pub fn public_point(&self) -> &AffinePoint {
        &self.q
    }

    /// Encode the public point as an uncompressed SEC 1 point octet string
    /// (§2.3.3), `04 ‖ X ‖ Y`. The identity, which no constructor of this
    /// type admits, would encode as the single octet `00`.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.curve.encode_point(&self.q)
    }

    /// Rebuild a public key from a SEC 1 point octet string (§2.3.4) and
    /// explicit curve parameters.
    ///
    /// Returns `None` unless the point is a valid public key (§3.2.2.1): not
    /// the point at infinity, with coordinates in the field, on the curve, and
    /// in the prime-order subgroup.
    #[must_use]
    pub fn from_wire_bytes(curve: CurveParams, bytes: &[u8]) -> Option<Self> {
        let q = curve.decode_point(bytes)?;
        if !curve.is_valid_public_point(&q) {
            return None;
        }
        Some(Self { curve, q })
    }

    /// Encrypt `message` for the holder of the matching private key: the
    /// ECIES encryption operation of SEC 1 §5.1.3 under `setup`.
    ///
    /// `shared_info1` and `shared_info2` are SEC 1's optional SharedInfo₁
    /// (KDF input) and SharedInfo₂ (MAC input); pass `&[]` for an absent value.
    /// The recipient needs the same setup and the same two values. Every call
    /// draws a fresh ephemeral key pair from `rng`. The output is
    /// `R ‖ EM ‖ D`, laid out in the [module documentation](self).
    ///
    /// Every constructor of this key validates the point (§3.2.2.1), which is
    /// the assurance §5.1.2 step 2 asks of the sender under either
    /// Diffie–Hellman primitive.
    ///
    /// # Errors
    ///
    /// The reason SEC 1's operation outputs "invalid":
    ///
    /// - [`EciesError::MessageNotBlockAligned`] when a CBC scheme gets a
    ///   message that is empty or not a whole number of blocks;
    /// - [`EciesError::KeyDataTooLong`] when ANSI-X9.63-KDF cannot produce the
    ///   keying data, which takes a message of about `hashlen × 2³²` octets
    ///   under XOR;
    /// - [`EciesError::RejectedDerivedKey`] when 3-key TDES refuses the derived
    ///   key;
    /// - [`EciesError::InvalidSharedSecret`] only on invalid domain parameters.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the §3.2.1 sampler
    /// rejects (`rump::random::random_nonzero_below`'s bound). Each draw is
    /// accepted with probability at least one half, so a working source
    /// reaches this with probability at most `2⁻²⁵⁶`; a source stuck on zero
    /// reaches it at once.
    pub fn encrypt<R: Csprng>(
        &self,
        setup: EciesSetup,
        message: &[u8],
        shared_info1: &[u8],
        shared_info2: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, EciesError> {
        // Step 1: the ephemeral private key from the §3.2.1 primitive, which
        // samples k uniformly from [1, n − 1]; R = k·G follows.
        let k = self.curve.random_scalar(rng);
        self.encrypt_under_ephemeral(setup, &k, message, shared_info1, shared_info2)
    }

    /// The encryption operation of SEC 1 §5.1.3 for a given ephemeral
    /// private key `k ∈ [1, n − 1]`. [`Self::encrypt`] draws `k`; the known
    /// answer tests supply the published one.
    fn encrypt_under_ephemeral(
        &self,
        setup: EciesSetup,
        k: &BigUint,
        message: &[u8],
        shared_info1: &[u8],
        shared_info2: &[u8],
    ) -> Result<Vec<u8>, EciesError> {
        let curve = &self.curve;
        // Step 1: R = k·G.
        let r = curve.scalar_mul(&curve.base_point(), k);
        // Step 2: R as an octet string, compressed or not per the setup.
        let r_octets = setup.point_format.encode(curve, &r);
        // Steps 3–4: z from the setup's primitive, as the octet string Z.
        let z = setup.dh.shared_secret(curve, k, &self.q)?;
        // Step 5: enckeylen + mackeylen octets of K from Z and SharedInfo₁.
        let enc_key_len = setup.encryption.key_len(message.len());
        let key_data_len = enc_key_len
            .checked_add(setup.mac.key_len())
            .ok_or(EciesError::KeyDataTooLong)?;
        let keying_data = setup.kdf.derive(z.as_slice(), shared_info1, key_data_len)?;
        drop(z);
        // Step 6: EK and MK.
        let (ek, mk) = setup.encryption.split_keying_data(
            keying_data.as_slice(),
            enc_key_len,
            setup.mac.key_len(),
        );
        // Step 7: EM = ENC_EK(M).
        let em = setup.encryption.encrypt(ek, message)?;
        // Step 8: D = MAC_MK(EM ‖ SharedInfo₂).
        let d = setup.mac.tag(mk, &em, shared_info2);
        // Step 9: C = R ‖ EM ‖ D.
        let mut c = Vec::with_capacity(r_octets.len() + em.len() + d.as_slice().len());
        c.extend_from_slice(&r_octets);
        c.extend_from_slice(&em);
        c.extend_from_slice(d.as_slice());
        Ok(c)
    }
}

crate::public_key::ec_io::impl_ec_public_key_io!(
    EciesPublicKey,
    "CRYPTOGRAPHY ECIES PUBLIC KEY",
    "EciesPublicKey"
);

// ─── EciesPrivateKey ─────────────────────────────────────────────────────────

impl EciesPrivateKey {
    /// The curve parameters for this key.
    #[must_use]
    pub fn curve(&self) -> &CurveParams {
        &self.curve
    }

    /// The private scalar `d ∈ [1, n)`.
    #[must_use]
    pub fn private_scalar(&self) -> &BigUint {
        &self.d
    }

    /// Derive the matching public key `Q = d·G`.
    #[must_use]
    pub fn to_public_key(&self) -> EciesPublicKey {
        EciesPublicKey {
            curve: self.curve.clone(),
            q: self.q.clone(),
        }
    }

    /// Decrypt `ciphertext`: the ECIES decryption operation of SEC 1 §5.1.4
    /// under `setup`, which must be the setup the sender used, with the same
    /// SharedInfo₁ and SharedInfo₂ (`&[]` for an absent value).
    ///
    /// Returns `None`, SEC 1's single outcome "invalid", when `C` does not
    /// parse, `R` lacks the validity its Diffie–Hellman primitive requires,
    /// the shared point is `O`, the tag does not verify, or a CBC ciphertext
    /// is not whole blocks. The tag is checked, in constant time, before
    /// anything is decrypted, so no plaintext exists on a failure path.
    #[must_use]
    pub fn decrypt(
        &self,
        setup: EciesSetup,
        ciphertext: &[u8],
        shared_info1: &[u8],
        shared_info2: &[u8],
    ) -> Option<Vec<u8>> {
        let curve = &self.curve;
        // Step 1: C = R ‖ EM ‖ D, with R's length read from its leading octet.
        let r_len = match *ciphertext.first()? {
            0x02 | 0x03 => 1 + curve.coord_len,
            0x04 => 1 + 2 * curve.coord_len,
            _ => return None,
        };
        let em_end = ciphertext.len().checked_sub(setup.mac.tag_len())?;
        let em_len = em_end.checked_sub(r_len)?;
        let (r_octets, rest) = ciphertext.split_at(r_len);
        let (em, d) = rest.split_at(em_len);
        // Step 2: the point R (§2.3.4).
        let r = curve.decode_point(r_octets)?;
        // Step 3: the assurance the Diffie–Hellman primitive requires.
        if !setup.dh.assures(curve, &r) {
            return None;
        }
        // Steps 4–5: z from d_V and R, as the octet string Z.
        let z = setup.dh.shared_secret(curve, &self.d, &r).ok()?;
        // Step 6: K from Z and SharedInfo₁.
        let enc_key_len = setup.encryption.key_len(em.len());
        let key_data_len = enc_key_len.checked_add(setup.mac.key_len())?;
        let keying_data = setup
            .kdf
            .derive(z.as_slice(), shared_info1, key_data_len)
            .ok()?;
        drop(z);
        // Step 7: EK and MK.
        let (ek, mk) = setup.encryption.split_keying_data(
            keying_data.as_slice(),
            enc_key_len,
            setup.mac.key_len(),
        );
        // Step 8: the tag, before any decryption.
        if !setup.mac.tag_matches(mk, em, shared_info2, d) {
            return None;
        }
        // Step 9: M.
        setup.encryption.decrypt(ek, em)
    }
}

crate::public_key::ec_io::impl_ec_private_key_io!(
    EciesPrivateKey,
    "CRYPTOGRAPHY ECIES PRIVATE KEY",
    "EciesPrivateKey"
);

crate::public_key::ec_pkix::impl_ec_key_encodings!(EciesPublicKey, EciesPrivateKey, Unrestricted);

impl fmt::Debug for EciesPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EciesPrivateKey(<redacted>)")
    }
}

// ─── Ecies namespace ─────────────────────────────────────────────────────────

impl Ecies {
    /// Generate a random ECIES key pair on `curve` with the key pair
    /// generation primitive of SEC 1 §3.2.1: `d` uniform in `[1, n − 1]` by
    /// rejection sampling, `Q = d·G`.
    ///
    /// # Panics
    ///
    /// Panics if `rng` yields 256 consecutive draws the sampler rejects
    /// (`rump::random::random_nonzero_below`'s bound). Each draw is accepted
    /// with probability at least one half, so a working source reaches this
    /// with probability at most `2⁻²⁵⁶`; a source stuck on zero, or on values
    /// at or above `n` within its bit width, reaches it at once.
    #[must_use]
    pub fn generate<R: Csprng>(
        curve: CurveParams,
        rng: &mut R,
    ) -> (EciesPublicKey, EciesPrivateKey) {
        let (d, q) = curve.generate_keypair(rng);
        (
            EciesPublicKey {
                curve: curve.clone(),
                q: q.clone(),
            },
            EciesPrivateKey { curve, d, q },
        )
    }
}

// ─── Components (SEC 1 §2.3, §3.3, §3.6, §3.7, §3.8) ─────────────────────────

/// Secret octets wiped on drop: `Z`, the keying data `K`, and tags.
struct SecretOctets(Vec<u8>);

impl SecretOctets {
    fn zeroed(len: usize) -> Self {
        Self(vec![0; len])
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Keep the leftmost `len` octets, wiping the rest before letting go.
    fn truncate(&mut self, len: usize) {
        if let Some(tail) = self.0.get_mut(len..) {
            crate::zeroize_slice(tail);
        }
        self.0.truncate(len);
    }
}

impl Drop for SecretOctets {
    fn drop(&mut self) {
        crate::zeroize_slice(self.0.as_mut_slice());
    }
}

impl EciesPointFormat {
    /// SEC 1 §2.3.3, with or without point compression.
    fn encode(self, curve: &CurveParams, point: &AffinePoint) -> Vec<u8> {
        match self {
            Self::Uncompressed => curve.encode_point(point),
            Self::Compressed => curve.encode_point_compressed(point),
        }
    }
}

impl EciesDhPrimitive {
    /// The assurance this primitive requires of the peer's point
    /// (§5.1.2 step 2, §5.1.4 step 3).
    ///
    /// The point comes from [`CurveParams::decode_point`] (§2.3.4), which has
    /// already rejected coordinates outside the field and points off the
    /// curve. Full validation (§3.2.2.1) adds `Q ≠ O` and `n·Q = O`; partial
    /// validation (§3.2.3.1) adds `Q ≠ O`, and the curve equation is restated.
    fn assures(self, curve: &CurveParams, point: &AffinePoint) -> bool {
        match self {
            Self::Standard => curve.is_valid_public_point(point),
            Self::Cofactor => !point.is_infinity() && curve.is_on_curve(point),
        }
    }

    /// The Diffie–Hellman primitive (§3.3.1 or §3.3.2) followed by the
    /// field-element-to-octet-string conversion (§2.3.5): `Z`.
    ///
    /// For a binary field the coordinate is stored as its polynomial's bit
    /// pattern, so its big-endian integer octets are the §2.3.5 conversion
    /// too; `coord_len` is `⌈m/8⌉` there and `⌈log₂ p / 8⌉` for a prime.
    fn shared_secret(
        self,
        curve: &CurveParams,
        private_scalar: &BigUint,
        public_point: &AffinePoint,
    ) -> Result<SecretOctets, EciesError> {
        let point = match self {
            Self::Cofactor if curve.h != 1 => {
                // h·d as an integer. Reducing it modulo n would keep the
                // small-order component that multiplying by h exists to clear.
                let cofactor_scalar = private_scalar.mul(&BigUint::from_u64(curve.h));
                curve.diffie_hellman(&cofactor_scalar, public_point)
            }
            Self::Standard | Self::Cofactor => curve.diffie_hellman(private_scalar, public_point),
        };
        // Step 2 of either primitive.
        if point.is_infinity() {
            return Err(EciesError::InvalidSharedSecret);
        }
        Ok(SecretOctets(point.x.to_be_bytes_padded(curve.coord_len)))
    }
}

impl EciesHash {
    /// `hashmaxlen` of SEC 1 §3.5: messages must be shorter than this many
    /// octets.
    const fn max_input_len(self) -> u128 {
        match self {
            Self::Sha1 | Self::Sha224 | Self::Sha256 => (1 << 61) - 1,
            Self::Sha384 | Self::Sha512 => (1 << 125) - 1,
        }
    }
}

impl EciesKdf {
    /// `keydatalen` octets of keying data from `Z` and SharedInfo₁.
    fn derive(
        self,
        z: &[u8],
        shared_info1: &[u8],
        key_data_len: usize,
    ) -> Result<SecretOctets, EciesError> {
        match self {
            Self::AnsiX963(hash) => {
                let max = hash.max_input_len();
                match hash {
                    EciesHash::Sha1 => ansi_x963_kdf::<Sha1>(z, shared_info1, key_data_len, max),
                    EciesHash::Sha224 => {
                        ansi_x963_kdf::<Sha224>(z, shared_info1, key_data_len, max)
                    }
                    EciesHash::Sha256 => {
                        ansi_x963_kdf::<Sha256>(z, shared_info1, key_data_len, max)
                    }
                    EciesHash::Sha384 => {
                        ansi_x963_kdf::<Sha384>(z, shared_info1, key_data_len, max)
                    }
                    EciesHash::Sha512 => {
                        ansi_x963_kdf::<Sha512>(z, shared_info1, key_data_len, max)
                    }
                }
            }
        }
    }
}

/// ANSI-X9.63-KDF, SEC 1 §3.6.1, over the hash `H` whose `hashmaxlen` is
/// `hash_max_len`.
fn ansi_x963_kdf<H: Digest>(
    z: &[u8],
    shared_info: &[u8],
    key_data_len: usize,
    hash_max_len: u128,
) -> Result<SecretOctets, EciesError> {
    let hash_len = H::OUTPUT_LEN;
    // Step 1: |Z| + |SharedInfo| + 4 < hashmaxlen.
    if z.len() as u128 + shared_info.len() as u128 + 4 >= hash_max_len {
        return Err(EciesError::KeyDataTooLong);
    }
    // Step 2: keydatalen < hashlen × (2³² − 1).
    if key_data_len as u128 >= hash_len as u128 * u128::from(u32::MAX) {
        return Err(EciesError::KeyDataTooLong);
    }
    // Steps 3–4: K_i = Hash(Z ‖ Counter ‖ SharedInfo) for Counter = 1, 2, …
    // Step 2 bounds the block count by 2³² − 1, so the counter never wraps.
    let blocks = key_data_len.div_ceil(hash_len);
    let total = blocks
        .checked_mul(hash_len)
        .ok_or(EciesError::KeyDataTooLong)?;
    let mut keying_data = SecretOctets::zeroed(total);
    let mut counter: u32 = 1;
    for block in keying_data.as_mut_slice().chunks_exact_mut(hash_len) {
        let mut hasher = H::new();
        hasher.update(z);
        hasher.update(&counter.to_be_bytes());
        hasher.update(shared_info);
        hasher.finalize_into(block);
        counter = counter.wrapping_add(1);
    }
    // Step 5: the leftmost keydatalen octets.
    keying_data.truncate(key_data_len);
    Ok(keying_data)
}

impl EciesEncryption {
    /// `enckeylen` (§3.8.1) for `data_len` octets of plaintext or ciphertext:
    /// an XOR key is as long as the data, a block cipher's is fixed.
    const fn key_len(self, data_len: usize) -> usize {
        match self {
            Self::Xor | Self::XorBackwardsCompatible => data_len,
            Self::Aes128Cbc | Self::Aes128Ctr => 16,
            Self::TdesCbc | Self::Aes192Cbc | Self::Aes192Ctr => 24,
            Self::Aes256Cbc | Self::Aes256Ctr => 32,
        }
    }

    /// §5.1.3 step 6 and §5.1.4 step 7: split the `enckeylen + mackeylen`
    /// octets of `K` into `(EK, MK)`: `EK` the leftmost `enckeylen` octets,
    /// except under XOR outside backwards compatibility mode, where `MK` is
    /// the leftmost `mackeylen` octets and `EK` the rest.
    fn split_keying_data(
        self,
        keying_data: &[u8],
        enc_key_len: usize,
        mac_key_len: usize,
    ) -> (&[u8], &[u8]) {
        match self {
            Self::Xor => {
                let (mk, ek) = keying_data.split_at(mac_key_len);
                (ek, mk)
            }
            _ => keying_data.split_at(enc_key_len),
        }
    }

    /// Whether this scheme takes `len` octets: CBC only whole blocks, one or
    /// more (SP 800-38A Appendix A); XOR and CTR any length.
    fn accepts_len(self, len: usize) -> bool {
        match self {
            Self::TdesCbc => len != 0 && len.is_multiple_of(8),
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => {
                len != 0 && len.is_multiple_of(16)
            }
            Self::Xor
            | Self::XorBackwardsCompatible
            | Self::Aes128Ctr
            | Self::Aes192Ctr
            | Self::Aes256Ctr => true,
        }
    }

    /// The encryption operation of §3.8.3: `EM = ENC_EK(M)`.
    fn encrypt(self, ek: &[u8], message: &[u8]) -> Result<Vec<u8>, EciesError> {
        if !self.accepts_len(message.len()) {
            return Err(EciesError::MessageNotBlockAligned);
        }
        Ok(match self {
            Self::Xor | Self::XorBackwardsCompatible => xor_with(ek, message),
            Self::TdesCbc => cbc_encrypt(tdes_3key(ek)?, message),
            Self::Aes128Cbc => cbc_encrypt(aes128(ek), message),
            Self::Aes192Cbc => cbc_encrypt(aes192(ek), message),
            Self::Aes256Cbc => cbc_encrypt(aes256(ek), message),
            Self::Aes128Ctr => ctr_apply(aes128(ek), message),
            Self::Aes192Ctr => ctr_apply(aes192(ek), message),
            Self::Aes256Ctr => ctr_apply(aes256(ek), message),
        })
    }

    /// The decryption operation of §3.8.4: `M` from `EM`, or `None` for
    /// "invalid".
    fn decrypt(self, ek: &[u8], em: &[u8]) -> Option<Vec<u8>> {
        if !self.accepts_len(em.len()) {
            return None;
        }
        Some(match self {
            Self::Xor | Self::XorBackwardsCompatible => xor_with(ek, em),
            Self::TdesCbc => cbc_decrypt(tdes_3key(ek).ok()?, em),
            Self::Aes128Cbc => cbc_decrypt(aes128(ek), em),
            Self::Aes192Cbc => cbc_decrypt(aes192(ek), em),
            Self::Aes256Cbc => cbc_decrypt(aes256(ek), em),
            Self::Aes128Ctr => ctr_apply(aes128(ek), em),
            Self::Aes192Ctr => ctr_apply(aes192(ek), em),
            Self::Aes256Ctr => ctr_apply(aes256(ek), em),
        })
    }
}

/// The XOR encryption scheme of §3.8 in either direction; `key` is as long as
/// `data`.
fn xor_with(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter().zip(key).map(|(d, k)| d ^ k).collect()
}

fn cbc_encrypt<C: BlockCipher>(cipher: C, message: &[u8]) -> Vec<u8> {
    let mut data = message.to_vec();
    Cbc::new(cipher).encrypt_nopad(&ZERO_BLOCK[..C::BLOCK_LEN], &mut data);
    data
}

fn cbc_decrypt<C: BlockCipher>(cipher: C, em: &[u8]) -> Vec<u8> {
    let mut data = em.to_vec();
    Cbc::new(cipher).decrypt_nopad(&ZERO_BLOCK[..C::BLOCK_LEN], &mut data);
    data
}

fn ctr_apply<C: BlockCipher>(cipher: C, input: &[u8]) -> Vec<u8> {
    let mut data = input.to_vec();
    Ctr::new(cipher).apply_keystream(&ZERO_BLOCK[..C::BLOCK_LEN], &mut data);
    data
}

fn aes128(key: &[u8]) -> Aes128 {
    let mut schedule_input = [0u8; 16];
    schedule_input.copy_from_slice(key);
    Aes128::new_wiping(&mut schedule_input)
}

fn aes192(key: &[u8]) -> Aes192 {
    let mut schedule_input = [0u8; 24];
    schedule_input.copy_from_slice(key);
    Aes192::new_wiping(&mut schedule_input)
}

fn aes256(key: &[u8]) -> Aes256 {
    let mut schedule_input = [0u8; 32];
    schedule_input.copy_from_slice(key);
    Aes256::new_wiping(&mut schedule_input)
}

/// 3-key TDES from a 24-octet key, as §3.8 describes: `K1 ‖ K2 ‖ K3`, eight
/// octets each, with "the appropriate bits" replaced by parity bits, which
/// FIPS 46-3 places in the low bit of every octet and sets for odd parity.
/// The replacement is inert: DES reads its 56 key bits through PC-1, which
/// discards the parity positions, and the constructor's weak-key and
/// repeated-component screen compares with them stripped. It is done so
/// that the key octets are the ones §3.8 names.
fn tdes_3key(key: &[u8]) -> Result<TripleDes, EciesError> {
    let mut schedule_input = [0u8; 24];
    for (dst, &src) in schedule_input.iter_mut().zip(key) {
        let key_bits = src & 0xFE;
        *dst = key_bits | u8::from(key_bits.count_ones().is_multiple_of(2));
    }
    TripleDes::new_3key_wiping(&mut schedule_input).map_err(|_| EciesError::RejectedDerivedKey)
}

impl EciesMac {
    /// `maclen`, the tag length in octets (§3.7.1).
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::HmacSha1_80 => 10,
            Self::HmacSha224_112 => 14,
            Self::HmacSha256_128 | Self::CmacAes128 | Self::CmacAes192 | Self::CmacAes256 => 16,
            Self::HmacSha1_160 => 20,
            Self::HmacSha384_192 => 24,
            Self::HmacSha224_224 => 28,
            Self::HmacSha256_256 | Self::HmacSha512_256 => 32,
            Self::HmacSha384_384 => 48,
            Self::HmacSha512_512 => 64,
        }
    }

    /// `mackeylen`, the key length in octets (§3.7.1).
    const fn key_len(self) -> usize {
        match self {
            Self::CmacAes128 => 16,
            Self::HmacSha1_160 | Self::HmacSha1_80 => 20,
            Self::CmacAes192 => 24,
            Self::HmacSha224_112 | Self::HmacSha224_224 => 28,
            Self::HmacSha256_128 | Self::HmacSha256_256 | Self::CmacAes256 => 32,
            Self::HmacSha384_192 | Self::HmacSha384_384 => 48,
            Self::HmacSha512_256 | Self::HmacSha512_512 => 64,
        }
    }

    /// The tagging operation of §3.7.3 on `EM ‖ SharedInfo₂`.
    fn tag(self, mk: &[u8], em: &[u8], shared_info2: &[u8]) -> SecretOctets {
        let mut tag = match self {
            Self::HmacSha1_160 | Self::HmacSha1_80 => hmac_tag::<Sha1>(mk, em, shared_info2),
            Self::HmacSha224_112 | Self::HmacSha224_224 => hmac_tag::<Sha224>(mk, em, shared_info2),
            Self::HmacSha256_128 | Self::HmacSha256_256 => hmac_tag::<Sha256>(mk, em, shared_info2),
            Self::HmacSha384_192 | Self::HmacSha384_384 => hmac_tag::<Sha384>(mk, em, shared_info2),
            Self::HmacSha512_256 | Self::HmacSha512_512 => hmac_tag::<Sha512>(mk, em, shared_info2),
            Self::CmacAes128 => cmac_tag(aes128(mk), em, shared_info2),
            Self::CmacAes192 => cmac_tag(aes192(mk), em, shared_info2),
            Self::CmacAes256 => cmac_tag(aes256(mk), em, shared_info2),
        };
        // HMAC-Hash-x keeps the leftmost x/8 octets; CMAC's tag is whole.
        tag.truncate(self.tag_len());
        tag
    }

    /// The tag checking operation of §3.7.4, comparing in constant time.
    fn tag_matches(self, mk: &[u8], em: &[u8], shared_info2: &[u8], d: &[u8]) -> bool {
        let expected = self.tag(mk, em, shared_info2);
        crate::ct::constant_time_eq_mask(expected.as_slice(), d) == u8::MAX
    }
}

fn hmac_tag<H: Digest>(key: &[u8], em: &[u8], shared_info2: &[u8]) -> SecretOctets {
    let mut mac = Hmac::<H>::new(key);
    mac.update(em);
    mac.update(shared_info2);
    let mut tag = SecretOctets::zeroed(H::OUTPUT_LEN);
    mac.finalize_into(tag.as_mut_slice());
    tag
}

fn cmac_tag<C: BlockCipher>(cipher: C, em: &[u8], shared_info2: &[u8]) -> SecretOctets {
    // CMAC here takes one slice, so EM ‖ SharedInfo₂ is assembled first; both
    // halves are public.
    let input = [em, shared_info2].concat();
    SecretOctets(Cmac::new(cipher).compute(&input))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        Ecies, EciesDhPrimitive, EciesEncryption, EciesError, EciesHash, EciesKdf, EciesMac,
        EciesPointFormat, EciesPrivateKey, EciesPublicKey, EciesSetup,
    };
    use crate::ciphers::aes::{Aes128, Aes256};
    use crate::hash::hmac::Hmac;
    use crate::hash::sha2::{Sha256, Sha512};
    use crate::modes::{Cbc, Cmac, Ctr};
    use crate::public_key::ec::{
        b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384, p521,
        secp256k1, AffinePoint, CurveParams,
    };
    use crate::test_utils::decode_hex;
    use crate::CtrDrbgAes256;
    use rump::BigUint;

    const GEC2_ECAES: &str = include_str!("../../tests/vectors/sec1_gec2_ecaes.txt");
    const CAVP_X963_KDF: &str = include_str!("../../tests/vectors/cavp_ansx963_2001_kdf.rsp");
    const CAVP_ECC_CDH: &str = include_str!("../../tests/vectors/cavp_kas_ecc_cdh_primitive.txt");

    /// How many of the 25 CAVP ECC CDH vectors per curve to check. Three per
    /// curve reach every NIST prime and binary curve; binary-curve scalar
    /// multiplication is slow in debug builds, and 25 runs the whole file.
    const CDH_VECTORS_PER_CURVE: usize = 3;

    const HASHES: [EciesHash; 5] = [
        EciesHash::Sha1,
        EciesHash::Sha224,
        EciesHash::Sha256,
        EciesHash::Sha384,
        EciesHash::Sha512,
    ];

    const ENCRYPTION_SCHEMES: [EciesEncryption; 9] = [
        EciesEncryption::Xor,
        EciesEncryption::XorBackwardsCompatible,
        EciesEncryption::TdesCbc,
        EciesEncryption::Aes128Cbc,
        EciesEncryption::Aes192Cbc,
        EciesEncryption::Aes256Cbc,
        EciesEncryption::Aes128Ctr,
        EciesEncryption::Aes192Ctr,
        EciesEncryption::Aes256Ctr,
    ];

    const MAC_SCHEMES: [EciesMac; 13] = [
        EciesMac::HmacSha1_160,
        EciesMac::HmacSha1_80,
        EciesMac::HmacSha224_112,
        EciesMac::HmacSha224_224,
        EciesMac::HmacSha256_128,
        EciesMac::HmacSha256_256,
        EciesMac::HmacSha384_192,
        EciesMac::HmacSha384_384,
        EciesMac::HmacSha512_256,
        EciesMac::HmacSha512_512,
        EciesMac::CmacAes128,
        EciesMac::CmacAes192,
        EciesMac::CmacAes256,
    ];

    const DH_PRIMITIVES: [EciesDhPrimitive; 2] =
        [EciesDhPrimitive::Standard, EciesDhPrimitive::Cofactor];

    const POINT_FORMATS: [EciesPointFormat; 2] =
        [EciesPointFormat::Uncompressed, EciesPointFormat::Compressed];

    fn rng() -> CtrDrbgAes256 {
        CtrDrbgAes256::new(&[0xef; 48])
    }

    crate::public_key::ec_io::ec_key_io_tests!(
        Ecies,
        EciesPublicKey,
        EciesPrivateKey,
        "CRYPTOGRAPHY ECIES PUBLIC KEY",
        "CRYPTOGRAPHY ECIES PRIVATE KEY",
        "EciesPublicKey",
        "EciesPrivateKey"
    );

    fn integer(text: &str, radix: u32) -> BigUint {
        let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        BigUint::from_str_radix(&digits, radix).expect("integer")
    }

    fn setup_with(
        hash: EciesHash,
        encryption: EciesEncryption,
        mac: EciesMac,
        dh: EciesDhPrimitive,
        point_format: EciesPointFormat,
    ) -> EciesSetup {
        EciesSetup::new(EciesKdf::AnsiX963(hash), encryption, mac, dh, point_format)
    }

    /// A key pair from a published private scalar.
    fn key_pair(curve: &CurveParams, d: BigUint) -> (EciesPublicKey, EciesPrivateKey) {
        let q = curve.scalar_mul(&curve.base_point(), &d);
        let private = EciesPrivateKey {
            curve: curve.clone(),
            d,
            q,
        };
        (private.to_public_key(), private)
    }

    /// secp160r1 from SEC 2 v1.0 §2.4.2
    /// (`pubs/sec2-v1.0-recommended-elliptic-curve-domain-parameters.pdf`),
    /// the curve of GEC 2 §3.1. SEC 2 v2.0 no longer lists it.
    fn secp160r1() -> CurveParams {
        CurveParams::new(
            integer("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 7FFFFFFF", 16),
            integer("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 7FFFFFFC", 16),
            integer("1C97BEFC 54BD7A8B 65ACF89F 81D4D4AD C565FA45", 16),
            integer("01 00000000 00000000 0001F4C8 F927AED3 CA752257", 16),
            1,
            integer("4A96B568 8EF57328 46646989 68C38BB9 13CBFC82", 16),
            integer("23A62855 3168947D 59DCC912 04235137 7AC5FB32", 16),
        )
        .expect("secp160r1 domain parameters")
    }

    fn message_for(encryption: EciesEncryption) -> Vec<u8> {
        let len = match encryption {
            EciesEncryption::TdesCbc
            | EciesEncryption::Aes128Cbc
            | EciesEncryption::Aes192Cbc
            | EciesEncryption::Aes256Cbc => 32u8,
            _ => 37u8,
        };
        (0..len)
            .map(|i| i.wrapping_mul(29).wrapping_add(3))
            .collect()
    }

    fn r_len(curve: &CurveParams, point_format: EciesPointFormat) -> usize {
        match point_format {
            EciesPointFormat::Uncompressed => 1 + 2 * curve.coord_len,
            EciesPointFormat::Compressed => 1 + curve.coord_len,
        }
    }

    /// Encrypt, check the §5.1.3 step 9 layout, and decrypt.
    fn round_trip(
        public: &EciesPublicKey,
        private: &EciesPrivateKey,
        setup: EciesSetup,
        rng: &mut CtrDrbgAes256,
    ) {
        let message = message_for(setup.encryption());
        let (info1, info2) = (b"SharedInfo1".as_slice(), b"SharedInfo2".as_slice());
        let c = public
            .encrypt(setup, &message, info1, info2, rng)
            .expect("encrypt");
        let r_len = r_len(public.curve(), setup.point_format());
        assert_eq!(
            c.len(),
            r_len + message.len() + setup.mac().tag_len(),
            "{setup:?}"
        );
        match setup.point_format() {
            EciesPointFormat::Uncompressed => assert_eq!(c[0], 0x04),
            EciesPointFormat::Compressed => assert!(c[0] == 0x02 || c[0] == 0x03),
        }
        assert_eq!(
            private.decrypt(setup, &c, info1, info2).as_deref(),
            Some(message.as_slice()),
            "{setup:?}"
        );
    }

    // ── GEC 2 known answers ──────────────────────────────────────────────────

    struct Gec2Case {
        fields: Vec<(String, String)>,
    }

    impl Gec2Case {
        fn get(&self, key: &str) -> &str {
            self.fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .unwrap_or_else(|| panic!("GEC 2 case lacks {key}"))
        }
    }

    fn gec2_case(section: &str) -> Gec2Case {
        let header = format!("[{section}]");
        let mut in_section = false;
        let mut fields = Vec::new();
        for line in GEC2_ECAES.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                if in_section {
                    break;
                }
                in_section = line == header;
                continue;
            }
            if in_section {
                let (name, value) = line.split_once(" = ").expect("name = value");
                fields.push((name.to_owned(), value.to_owned()));
            }
        }
        assert!(!fields.is_empty(), "no GEC 2 section {section}");
        Gec2Case { fields }
    }

    /// GEC 2's setup: ANSI-X9.63-KDF with SHA-1, HMAC-SHA-1-160, XOR with SEC 1
    /// v1.0's key layout, compressed points.
    fn gec2_setup(dh: EciesDhPrimitive) -> EciesSetup {
        setup_with(
            EciesHash::Sha1,
            EciesEncryption::XorBackwardsCompatible,
            EciesMac::HmacSha1_160,
            dh,
            EciesPointFormat::Compressed,
        )
    }

    /// Reproduce one GEC 2 ECAES example step by step, then as a whole.
    fn check_gec2(section: &str) {
        let case = gec2_case(section);
        let curve = match case.get("curve") {
            "secp160r1" => secp160r1(),
            "sect163k1" => k163(),
            other => panic!("unexpected GEC 2 curve {other}"),
        };
        let dh = match case.get("dh") {
            "standard" => EciesDhPrimitive::Standard,
            "cofactor" => EciesDhPrimitive::Cofactor,
            other => panic!("unexpected GEC 2 primitive {other}"),
        };
        let setup = gec2_setup(dh);
        let (public, private) = key_pair(&curve, integer(case.get("dV_dec"), 10));

        // Key deployment: Q_V is GEC 2's compressed point, and it validates.
        let q_octets = decode_hex(case.get("QV"));
        assert_eq!(
            curve.encode_point_compressed(public.public_point()),
            q_octets,
            "{section} QV"
        );
        let recipient = EciesPublicKey::from_wire_bytes(curve.clone(), &q_octets)
            .expect("GEC 2's QV is a valid public key");
        assert_eq!(recipient.public_point(), public.public_point());

        let message = decode_hex(case.get("M"));
        let k = integer(case.get("k_dec"), 10);

        // §5.1.3 steps 1–2.
        let r = curve.scalar_mul(&curve.base_point(), &k);
        assert_eq!(
            setup.point_format().encode(&curve, &r),
            decode_hex(case.get("R")),
            "{section} R"
        );
        // Steps 3–4.
        let z = setup
            .dh_primitive()
            .shared_secret(&curve, &k, recipient.public_point())
            .expect("z");
        assert_eq!(z.as_slice(), decode_hex(case.get("Z")), "{section} Z");
        // Step 5.
        let enc_key_len = setup.encryption().key_len(message.len());
        let keying_data = setup
            .kdf()
            .derive(z.as_slice(), &[], enc_key_len + setup.mac().key_len())
            .expect("K");
        assert_eq!(
            keying_data.as_slice(),
            decode_hex(case.get("K")),
            "{section} K"
        );
        // Step 6.
        let (ek, mk) = setup.encryption().split_keying_data(
            keying_data.as_slice(),
            enc_key_len,
            setup.mac().key_len(),
        );
        assert_eq!(ek, decode_hex(case.get("EK")), "{section} EK");
        assert_eq!(mk, decode_hex(case.get("MK")), "{section} MK");
        // Step 7.
        let em = setup.encryption().encrypt(ek, &message).expect("EM");
        assert_eq!(em, decode_hex(case.get("EM")), "{section} EM");
        // Step 8.
        let d = setup.mac().tag(mk, &em, &[]);
        assert_eq!(d.as_slice(), decode_hex(case.get("D")), "{section} D");
        // Step 9, and the whole operation through the key.
        let c = decode_hex(case.get("C"));
        assert_eq!(
            c,
            [decode_hex(case.get("R")), em, decode_hex(case.get("D"))].concat(),
            "{section}: GEC 2's C is R || EM || D"
        );
        assert_eq!(
            recipient
                .encrypt_under_ephemeral(setup, &k, &message, &[], &[])
                .expect("encrypt"),
            c,
            "{section} C"
        );
        // §5.1.4 through the key.
        assert_eq!(
            private.decrypt(setup, &c, &[], &[]).as_deref(),
            Some(message.as_slice()),
            "{section} decryption"
        );
    }

    #[test]
    fn gec2_3_1_secp160r1() {
        check_gec2("3.1");
    }

    #[test]
    fn gec2_3_2_sect163k1_standard_diffie_hellman() {
        check_gec2("3.2");
    }

    #[test]
    fn gec2_3_3_sect163k1_cofactor_diffie_hellman() {
        check_gec2("3.3");
    }

    #[test]
    fn gec2_standard_and_cofactor_ciphertexts_differ_on_sect163k1() {
        // GEC 2 §3.2 and §3.3 share the key pair, the ephemeral key and R; only
        // the primitive differs, and with h = 2 so do z and the ciphertext.
        let standard = gec2_case("3.2");
        let cofactor = gec2_case("3.3");
        assert_eq!(standard.get("R"), cofactor.get("R"));
        assert_ne!(standard.get("Z"), cofactor.get("Z"));
        let (_, private) = key_pair(&k163(), integer(standard.get("dV_dec"), 10));
        let standard_c = decode_hex(standard.get("C"));
        let cofactor_c = decode_hex(cofactor.get("C"));
        assert!(private
            .decrypt(
                gec2_setup(EciesDhPrimitive::Cofactor),
                &standard_c,
                &[],
                &[]
            )
            .is_none());
        assert!(private
            .decrypt(
                gec2_setup(EciesDhPrimitive::Standard),
                &cofactor_c,
                &[],
                &[]
            )
            .is_none());
    }

    // ── NIST CAVP known answers ──────────────────────────────────────────────

    #[test]
    fn ansi_x963_kdf_matches_nist_cavp_vectors() {
        let mut hash = None;
        let mut key_data_bits = 0usize;
        let mut z = Vec::new();
        let mut shared_info = Vec::new();
        let mut checked = [0usize; 5];
        for line in CAVP_X963_KDF.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(group) = line.strip_prefix('[').and_then(|g| g.strip_suffix(']')) {
                match group {
                    "SHA-1" => hash = Some(EciesHash::Sha1),
                    "SHA-224" => hash = Some(EciesHash::Sha224),
                    "SHA-256" => hash = Some(EciesHash::Sha256),
                    "SHA-384" => hash = Some(EciesHash::Sha384),
                    "SHA-512" => hash = Some(EciesHash::Sha512),
                    _ => {
                        if let Some(bits) = group.strip_prefix("key data length = ") {
                            key_data_bits = bits.parse().expect("key data length");
                        }
                    }
                }
                continue;
            }
            let (name, value) = line.split_once('=').expect("name = value");
            let value = value.trim();
            match name.trim() {
                "COUNT" => {}
                "Z" => z = decode_hex(value),
                "SharedInfo" => shared_info = decode_hex(value),
                "key_data" => {
                    let expected = decode_hex(value);
                    assert_eq!(expected.len() * 8, key_data_bits);
                    let hash = hash.expect("a hash group precedes its vectors");
                    let derived = EciesKdf::AnsiX963(hash)
                        .derive(&z, &shared_info, expected.len())
                        .expect("key data");
                    assert_eq!(derived.as_slice(), expected, "{hash:?}, key_data {value}");
                    let index = HASHES.iter().position(|&h| h == hash).expect("listed");
                    checked[index] += 1;
                }
                other => panic!("unexpected CAVP field {other}"),
            }
        }
        // Two groups of ten per hash: without and with SharedInfo.
        assert_eq!(checked, [20; 5]);
    }

    fn nist_curve(name: &str) -> CurveParams {
        match name {
            "P-192" => p192(),
            "P-224" => p224(),
            "P-256" => p256(),
            "P-384" => p384(),
            "P-521" => p521(),
            "K-163" => k163(),
            "K-233" => k233(),
            "K-283" => k283(),
            "K-409" => k409(),
            "K-571" => k571(),
            "B-163" => b163(),
            "B-233" => b233(),
            "B-283" => b283(),
            "B-409" => b409(),
            "B-571" => b571(),
            other => panic!("unexpected CAVP curve {other}"),
        }
    }

    #[test]
    fn cofactor_diffie_hellman_matches_nist_cavp_ecc_cdh_vectors() {
        let mut curve: Option<CurveParams> = None;
        let mut curves = 0usize;
        let mut taken = 0usize;
        let mut checked = 0usize;
        let (mut peer_x, mut peer_y, mut d, mut own_x, mut own_y) = (None, None, None, None, None);
        for line in CAVP_ECC_CDH.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|g| g.strip_suffix(']')) {
                curve = Some(nist_curve(name));
                curves += 1;
                taken = 0;
                continue;
            }
            let (name, value) = line.split_once('=').expect("name = value");
            let value = value.trim();
            match name.trim() {
                "COUNT" => {}
                "QCAVSx" => peer_x = Some(integer(value, 16)),
                "QCAVSy" => peer_y = Some(integer(value, 16)),
                "dIUT" => d = Some(integer(value, 16)),
                "QIUTx" => own_x = Some(integer(value, 16)),
                "QIUTy" => own_y = Some(integer(value, 16)),
                "ZIUT" => {
                    let curve = curve.as_ref().expect("a curve group precedes its vectors");
                    let peer = AffinePoint::new(
                        peer_x.take().expect("QCAVSx"),
                        peer_y.take().expect("QCAVSy"),
                    );
                    let d = d.take().expect("dIUT");
                    let own = AffinePoint::new(
                        own_x.take().expect("QIUTx"),
                        own_y.take().expect("QIUTy"),
                    );
                    if taken < CDH_VECTORS_PER_CURVE {
                        assert!(EciesDhPrimitive::Cofactor.assures(curve, &peer));
                        if taken == 0 {
                            assert_eq!(curve.scalar_mul(&curve.base_point(), &d), own);
                        }
                        let z = EciesDhPrimitive::Cofactor
                            .shared_secret(curve, &d, &peer)
                            .expect("z");
                        assert_eq!(z.as_slice(), decode_hex(value), "ZIUT {value}");
                        checked += 1;
                    }
                    taken += 1;
                }
                other => panic!("unexpected CAVP field {other}"),
            }
        }
        assert_eq!(curves, 15);
        assert_eq!(checked, 15 * CDH_VECTORS_PER_CURVE);
    }

    // ── The standard's composition, transcribed step by step ─────────────────

    /// ANSI-X9.63-KDF with SHA-256 written out from §3.6.1.
    fn x963_sha256_by_hand(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut counter = 1u32;
        while out.len() < len {
            out.extend_from_slice(&Sha256::digest(
                &[z, &counter.to_be_bytes(), shared_info].concat(),
            ));
            counter += 1;
        }
        out.truncate(len);
        out
    }

    /// ANSI-X9.63-KDF with SHA-512 written out from §3.6.1.
    fn x963_sha512_by_hand(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut counter = 1u32;
        while out.len() < len {
            out.extend_from_slice(&Sha512::digest(
                &[z, &counter.to_be_bytes(), shared_info].concat(),
            ));
            counter += 1;
        }
        out.truncate(len);
        out
    }

    #[test]
    fn recommended_setup_composes_as_section_5_1_3_states() {
        let curve = p256();
        let (public, private) = key_pair(&curve, integer("C0FFEE 0123456789ABCDEF", 16));
        let k = integer("0DDBA11 FEEDFACE CAFEBABE", 16);
        let message = b"SEC 1 section 5.1.3, step by step";
        let (info1, info2) = (b"alpha".as_slice(), b"beta\x00\x04".as_slice());

        // Steps 1–4: R, and Z = x(k·Q) (h = 1, so both primitives agree).
        let r = curve.scalar_mul(&curve.base_point(), &k);
        let shared = curve.scalar_mul(public.public_point(), &k);
        let z = shared.x.to_be_bytes_padded(32);
        // Step 5: enckeylen 16 (AES-128) + mackeylen 32 (HMAC-SHA-256).
        let keying_data = x963_sha256_by_hand(&z, info1, 48);
        // Step 6: EK leftmost, MK rightmost.
        let (ek, mk) = keying_data.split_at(16);
        // Step 7: AES-128-CTR from an all-zero counter block.
        let mut em = message.to_vec();
        Ctr::new(Aes128::new(ek.try_into().expect("16 octets")))
            .apply_keystream(&[0u8; 16], &mut em);
        // Step 8: HMAC-SHA-256 on EM ‖ SharedInfo₂, all 32 octets.
        let d = Hmac::<Sha256>::compute(mk, &[em.as_slice(), info2].concat());
        // Step 9.
        let expected = [curve.encode_point(&r), em, d].concat();

        let setup = EciesSetup::RECOMMENDED;
        assert_eq!(
            public
                .encrypt_under_ephemeral(setup, &k, message, info1, info2)
                .expect("encrypt"),
            expected
        );
        assert_eq!(
            private.decrypt(setup, &expected, info1, info2).as_deref(),
            Some(message.as_slice())
        );
    }

    #[test]
    fn aes_cbc_and_cmac_compose_as_section_5_1_3_states() {
        let curve = p256();
        let (public, private) = key_pair(&curve, integer("5EC1 0005 0001 0003", 16));
        let k = integer("A5A5A5A5 0F0F0F0F", 16);
        let message = [0x5au8; 48];
        let info1 = b"shared one".as_slice();
        let setup = setup_with(
            EciesHash::Sha256,
            EciesEncryption::Aes256Cbc,
            EciesMac::CmacAes256,
            EciesDhPrimitive::Standard,
            EciesPointFormat::Compressed,
        );

        let r = curve.scalar_mul(&curve.base_point(), &k);
        let z = curve
            .scalar_mul(public.public_point(), &k)
            .x
            .to_be_bytes_padded(32);
        // enckeylen 32 (AES-256) + mackeylen 32 (CMAC-AES-256).
        let keying_data = x963_sha256_by_hand(&z, info1, 64);
        let (ek, mk) = keying_data.split_at(32);
        // AES-256-CBC with a zero IV and no padding: 48 octets are 3 blocks.
        let mut em = message.to_vec();
        Cbc::new(Aes256::new(ek.try_into().expect("32 octets"))).encrypt_nopad(&[0u8; 16], &mut em);
        // CMAC-AES-256 on EM (SharedInfo₂ absent), 16 octets.
        let d = Cmac::new(Aes256::new(mk.try_into().expect("32 octets"))).compute(&em);
        let expected = [curve.encode_point_compressed(&r), em, d].concat();

        assert_eq!(
            public
                .encrypt_under_ephemeral(setup, &k, &message, info1, &[])
                .expect("encrypt"),
            expected
        );
        assert_eq!(
            private.decrypt(setup, &expected, info1, &[]).as_deref(),
            Some(message.as_slice())
        );
    }

    #[test]
    fn xor_takes_the_mac_key_from_the_left_of_k() {
        // §5.1.3 step 6: outside backwards compatibility mode, XOR parses MK
        // from the left of K and EK from the right. On sect163k1 (h = 2) with
        // the cofactor primitive, z = x(2·k·Q).
        let curve = k163();
        let (public, private) = key_pair(&curve, integer("1234567890ABCDEF1234567", 16));
        let k = integer("ABCDEF0123456789ABCDEF", 16);
        let message = b"eleven octets and some more";
        let info2 = b"info two".as_slice();
        let setup = setup_with(
            EciesHash::Sha512,
            EciesEncryption::Xor,
            EciesMac::HmacSha512_256,
            EciesDhPrimitive::Cofactor,
            EciesPointFormat::Uncompressed,
        );

        let r = curve.scalar_mul(&curve.base_point(), &k);
        let two_k = k.mul(&BigUint::from_u64(2));
        let z = curve
            .scalar_mul(public.public_point(), &two_k)
            .x
            .to_be_bytes_padded(21);
        // mackeylen 64 (HMAC-SHA-512) + enckeylen |M|.
        let keying_data = x963_sha512_by_hand(&z, &[], 64 + message.len());
        let (mk, ek) = keying_data.split_at(64);
        let em: Vec<u8> = message.iter().zip(ek).map(|(m, e)| m ^ e).collect();
        let mut d = Hmac::<Sha512>::compute(mk, &[em.as_slice(), info2].concat());
        d.truncate(32);
        let expected = [curve.encode_point(&r), em, d].concat();

        assert_eq!(
            public
                .encrypt_under_ephemeral(setup, &k, message, &[], info2)
                .expect("encrypt"),
            expected
        );
        assert_eq!(
            private.decrypt(setup, &expected, &[], info2).as_deref(),
            Some(message.as_slice())
        );
        // The same ciphertext does not verify under the v1.0 layout.
        let v1 = setup_with(
            EciesHash::Sha512,
            EciesEncryption::XorBackwardsCompatible,
            EciesMac::HmacSha512_256,
            EciesDhPrimitive::Cofactor,
            EciesPointFormat::Uncompressed,
        );
        assert!(private.decrypt(v1, &expected, &[], info2).is_none());
    }

    #[test]
    fn keying_data_split_follows_section_5_1_3_step_6() {
        let keying_data: Vec<u8> = (0u8..60).collect();
        let (ek, mk) = EciesEncryption::Xor.split_keying_data(&keying_data, 28, 32);
        assert_eq!((mk, ek), keying_data.split_at(32));
        let (ek, mk) =
            EciesEncryption::XorBackwardsCompatible.split_keying_data(&keying_data, 28, 32);
        assert_eq!((ek, mk), keying_data.split_at(28));
        let (ek, mk) = EciesEncryption::Aes256Ctr.split_keying_data(&keying_data, 32, 28);
        assert_eq!((ek, mk), keying_data.split_at(32));
    }

    // ── Options: the lists of SEC 1 §3.7 and §3.8, round trips ───────────────

    #[test]
    fn mac_key_and_tag_lengths_are_section_3_7s() {
        for mac in MAC_SCHEMES {
            let expected = match mac {
                EciesMac::HmacSha1_160 => (20, 20),
                EciesMac::HmacSha1_80 => (20, 10),
                EciesMac::HmacSha224_112 => (28, 14),
                EciesMac::HmacSha224_224 => (28, 28),
                EciesMac::HmacSha256_128 => (32, 16),
                EciesMac::HmacSha256_256 => (32, 32),
                EciesMac::HmacSha384_192 => (48, 24),
                EciesMac::HmacSha384_384 => (48, 48),
                EciesMac::HmacSha512_256 => (64, 32),
                EciesMac::HmacSha512_512 => (64, 64),
                EciesMac::CmacAes128 => (16, 16),
                EciesMac::CmacAes192 => (24, 16),
                EciesMac::CmacAes256 => (32, 16),
            };
            assert_eq!((mac.key_len(), mac.tag_len()), expected, "{mac:?}");
        }
    }

    #[test]
    fn encryption_key_lengths_are_section_3_8s() {
        for encryption in ENCRYPTION_SCHEMES {
            let expected = match encryption {
                EciesEncryption::Xor | EciesEncryption::XorBackwardsCompatible => 37,
                EciesEncryption::Aes128Cbc | EciesEncryption::Aes128Ctr => 16,
                EciesEncryption::TdesCbc
                | EciesEncryption::Aes192Cbc
                | EciesEncryption::Aes192Ctr => 24,
                EciesEncryption::Aes256Cbc | EciesEncryption::Aes256Ctr => 32,
            };
            assert_eq!(encryption.key_len(37), expected, "{encryption:?}");
        }
    }

    #[test]
    fn recommended_setup_is_the_documented_one() {
        let setup = EciesSetup::RECOMMENDED;
        assert_eq!(setup.kdf(), EciesKdf::AnsiX963(EciesHash::Sha256));
        assert_eq!(setup.encryption(), EciesEncryption::Aes128Ctr);
        assert_eq!(setup.mac(), EciesMac::HmacSha256_256);
        assert_eq!(setup.dh_primitive(), EciesDhPrimitive::Cofactor);
        assert_eq!(setup.point_format(), EciesPointFormat::Uncompressed);
    }

    #[test]
    fn roundtrip_every_encryption_scheme_on_prime_and_binary_curves() {
        let mut rng = rng();
        for curve in [p256(), k163()] {
            let (public, private) = Ecies::generate(curve, &mut rng);
            for encryption in ENCRYPTION_SCHEMES {
                let setup = setup_with(
                    EciesHash::Sha256,
                    encryption,
                    EciesMac::HmacSha256_256,
                    EciesDhPrimitive::Cofactor,
                    EciesPointFormat::Uncompressed,
                );
                round_trip(&public, &private, setup, &mut rng);
            }
        }
    }

    #[test]
    fn roundtrip_every_mac_scheme() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        for mac in MAC_SCHEMES {
            let setup = setup_with(
                EciesHash::Sha256,
                EciesEncryption::Aes128Ctr,
                mac,
                EciesDhPrimitive::Standard,
                EciesPointFormat::Compressed,
            );
            round_trip(&public, &private, setup, &mut rng);
        }
    }

    #[test]
    fn roundtrip_every_kdf_hash() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(b163(), &mut rng);
        for hash in HASHES {
            let setup = setup_with(
                hash,
                EciesEncryption::Xor,
                EciesMac::CmacAes128,
                EciesDhPrimitive::Cofactor,
                EciesPointFormat::Compressed,
            );
            round_trip(&public, &private, setup, &mut rng);
        }
    }

    #[test]
    fn roundtrip_both_primitives_and_point_formats_on_prime_and_binary_curves() {
        let mut rng = rng();
        for curve in [p256(), secp256k1(), p384(), b163(), k163(), k233()] {
            let (public, private) = Ecies::generate(curve, &mut rng);
            for dh in DH_PRIMITIVES {
                for point_format in POINT_FORMATS {
                    let setup = setup_with(
                        EciesHash::Sha256,
                        EciesEncryption::Aes128Ctr,
                        EciesMac::HmacSha256_256,
                        dh,
                        point_format,
                    );
                    round_trip(&public, &private, setup, &mut rng);
                }
            }
        }
    }

    #[test]
    fn empty_message_round_trips_where_the_scheme_allows_it() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let c = public
            .encrypt(setup, &[], &[], &[], &mut rng)
            .expect("encrypt");
        assert_eq!(c.len(), 97);
        assert_eq!(
            private.decrypt(setup, &c, &[], &[]).as_deref(),
            Some(&[][..])
        );
    }

    #[test]
    fn encrypt_is_randomized() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let c1 = public.encrypt(setup, b"same message", &[], &[], &mut rng);
        let c2 = public.encrypt(setup, b"same message", &[], &[], &mut rng);
        assert_ne!(c1.expect("encrypt"), c2.expect("encrypt"));
    }

    // ── §5.1.4 rejections ────────────────────────────────────────────────────

    #[test]
    fn step_1_rejects_unknown_leading_octets_and_short_ciphertexts() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        // With an empty message, C is exactly R (65 octets) ‖ D (32 octets),
        // so every proper prefix is too short to parse.
        let c = public
            .encrypt(setup, &[], &[], &[], &mut rng)
            .expect("encrypt");
        for len in 0..c.len() {
            assert!(
                private.decrypt(setup, &c[..len], &[], &[]).is_none(),
                "{len}"
            );
        }
        for leading in [0x00u8, 0x01, 0x05, 0x06, 0x07, 0xff] {
            let mut bad = c.clone();
            bad[0] = leading;
            assert!(
                private.decrypt(setup, &bad, &[], &[]).is_none(),
                "{leading:#04x}"
            );
        }
        assert!(private.decrypt(setup, &[0x00], &[], &[]).is_none());
    }

    #[test]
    fn steps_2_and_3_reject_r_that_is_not_a_valid_point() {
        let curve = p256();
        let mut rng = rng();
        let (public, private) = Ecies::generate(curve.clone(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let c = public
            .encrypt(setup, b"reject R", &[], &[], &mut rng)
            .expect("encrypt");
        let r_len = r_len(&curve, EciesPointFormat::Uncompressed);
        let body = &c[r_len..];

        // Off the curve.
        let mut off_curve = c.clone();
        off_curve[1 + 31] ^= 0x01;
        assert!(private.decrypt(setup, &off_curve, &[], &[]).is_none());

        // A coordinate outside the field: X = p.
        let mut out_of_field = c.clone();
        out_of_field[1..33].copy_from_slice(&curve.p.to_be_bytes_padded(32));
        assert!(private.decrypt(setup, &out_of_field, &[], &[]).is_none());

        // A compressed x-coordinate with no point above it.
        let missing_x = (1u64..)
            .map(|x| {
                [
                    [0x02u8].as_slice(),
                    &BigUint::from_u64(x).to_be_bytes_padded(32),
                ]
                .concat()
            })
            .find(|octets| curve.decode_point(octets).is_none())
            .expect("half of all x have no point");
        let bad = [missing_x.as_slice(), body].concat();
        assert!(private.decrypt(setup, &bad, &[], &[]).is_none());
    }

    /// The point `(0, 1)` of order 2 on sect163k1 (`y² + xy = x³ + x² + 1`).
    fn sect163k1_order_two_point(curve: &CurveParams) -> AffinePoint {
        let t = AffinePoint::new(BigUint::zero(), BigUint::one());
        assert!(curve.is_on_curve(&t));
        assert!(curve.scalar_mul(&t, &BigUint::from_u64(2)).is_infinity());
        t
    }

    #[test]
    fn step_3_standard_primitive_rejects_r_outside_the_subgroup() {
        let curve = k163();
        let t = sect163k1_order_two_point(&curve);
        let mut rng = rng();
        let (public, private) = Ecies::generate(curve.clone(), &mut rng);
        let setup = setup_with(
            EciesHash::Sha256,
            EciesEncryption::Aes128Ctr,
            EciesMac::HmacSha256_256,
            EciesDhPrimitive::Standard,
            EciesPointFormat::Uncompressed,
        );
        let c = public
            .encrypt(setup, b"small subgroup", &[], &[], &mut rng)
            .expect("encrypt");
        let r_len = r_len(&curve, EciesPointFormat::Uncompressed);
        let r = curve.decode_point(&c[..r_len]).expect("R");

        assert!(!EciesDhPrimitive::Standard.assures(&curve, &t));
        let r_plus_t = curve.add(&r, &t);
        assert!(curve.is_on_curve(&r_plus_t));
        for substitute in [t, r_plus_t] {
            let bad = [curve.encode_point(&substitute).as_slice(), &c[r_len..]].concat();
            assert!(private.decrypt(setup, &bad, &[], &[]).is_none());
        }
    }

    #[test]
    fn step_4_cofactor_primitive_clears_the_small_subgroup() {
        let curve = k163();
        let t = sect163k1_order_two_point(&curve);
        let mut rng = rng();
        let (public, private) = Ecies::generate(curve.clone(), &mut rng);
        let setup = setup_with(
            EciesHash::Sha256,
            EciesEncryption::Aes128Ctr,
            EciesMac::HmacSha256_256,
            EciesDhPrimitive::Cofactor,
            EciesPointFormat::Uncompressed,
        );
        let message = b"cofactor";
        let c = public
            .encrypt(setup, message, &[], &[], &mut rng)
            .expect("encrypt");
        let r_len = r_len(&curve, EciesPointFormat::Uncompressed);
        let r = curve.decode_point(&c[..r_len]).expect("R");

        // T is partially valid, and h·d·T = O makes the primitive "invalid".
        assert!(EciesDhPrimitive::Cofactor.assures(&curve, &t));
        assert_eq!(
            EciesDhPrimitive::Cofactor
                .shared_secret(&curve, private.private_scalar(), &t)
                .err(),
            Some(EciesError::InvalidSharedSecret)
        );
        let bad = [curve.encode_point(&t).as_slice(), &c[r_len..]].concat();
        assert!(private.decrypt(setup, &bad, &[], &[]).is_none());

        // R + T gives the same h·d·(R + T) = h·d·R: benign malleability
        // (Appendix B.4.1), the plaintext unchanged.
        let r_plus_t = curve.add(&r, &t);
        let substituted = [curve.encode_point(&r_plus_t).as_slice(), &c[r_len..]].concat();
        assert_eq!(
            private.decrypt(setup, &substituted, &[], &[]).as_deref(),
            Some(message.as_slice())
        );
    }

    #[test]
    fn negated_and_re_encoded_r_decrypt_to_the_same_plaintext() {
        // Appendix B.4.1: −R has the shared point's x-coordinate, and §5.1.4
        // step 1 accepts either encoding of R. Neither changes the plaintext.
        let curve = p256();
        let mut rng = rng();
        let (public, private) = Ecies::generate(curve.clone(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let message = b"benign";
        let c = public
            .encrypt(setup, message, &[], &[], &mut rng)
            .expect("encrypt");
        let r_len = r_len(&curve, EciesPointFormat::Uncompressed);
        let r = curve.decode_point(&c[..r_len]).expect("R");
        for substitute in [
            curve.encode_point(&curve.negate(&r)),
            curve.encode_point_compressed(&r),
        ] {
            let other = [substitute.as_slice(), &c[r_len..]].concat();
            assert_ne!(other, c);
            assert_eq!(
                private.decrypt(setup, &other, &[], &[]).as_deref(),
                Some(message.as_slice())
            );
        }
    }

    #[test]
    fn step_8_rejects_a_changed_tag_em_or_length() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let c = public
            .encrypt(setup, b"tamper with me", &[], &[], &mut rng)
            .expect("encrypt");
        let last = c.len() - 1;
        for position in [65, 65 + 7, last - 32, last] {
            let mut bad = c.clone();
            bad[position] ^= 0x80;
            assert!(
                private.decrypt(setup, &bad, &[], &[]).is_none(),
                "{position}"
            );
        }
        assert!(private.decrypt(setup, &c[..last], &[], &[]).is_none());
        let extended = [c.as_slice(), &[0]].concat();
        assert!(private.decrypt(setup, &extended, &[], &[]).is_none());
    }

    #[test]
    fn shared_info_binds_the_kdf_and_the_mac() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let message = b"bound";
        let c = public
            .encrypt(setup, message, b"info one", b"info two", &mut rng)
            .expect("encrypt");
        assert_eq!(
            private
                .decrypt(setup, &c, b"info one", b"info two")
                .as_deref(),
            Some(message.as_slice())
        );
        for (info1, info2) in [
            (b"info onE".as_slice(), b"info two".as_slice()),
            (b"info one", b"info twO"),
            (b"", b"info two"),
            (b"info one", b""),
            (b"info two", b"info one"),
        ] {
            assert!(private.decrypt(setup, &c, info1, info2).is_none());
        }
    }

    #[test]
    fn the_mac_input_is_em_then_shared_info2_with_no_separator() {
        // §5.1.1 step 8 and Appendix B.4.1: D covers EM ‖ SharedInfo₂, so an
        // octet moved from the end of EM to the front of SharedInfo₂ keeps the
        // tag valid and the recipient gets a truncated plaintext. The format
        // of SharedInfo₂ has to prevent this; the scheme does not.
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let message = b"pay 1000";
        let c = public
            .encrypt(setup, message, &[], &[], &mut rng)
            .expect("encrypt");
        let em_end = c.len() - setup.mac().tag_len();
        let moved = [c[em_end - 1]];
        let shortened = [&c[..em_end - 1], &c[em_end..]].concat();
        assert_eq!(
            private.decrypt(setup, &shortened, &[], &moved).as_deref(),
            Some(&message[..message.len() - 1])
        );
    }

    #[test]
    fn decryption_needs_the_same_setup_and_key() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let (_, stranger) = Ecies::generate(p256(), &mut rng);
        let setup = EciesSetup::RECOMMENDED;
        let message = b"setup";
        let c = public
            .encrypt(setup, message, &[], &[], &mut rng)
            .expect("encrypt");
        assert!(stranger.decrypt(setup, &c, &[], &[]).is_none());
        for other in [
            setup_with(
                EciesHash::Sha384,
                EciesEncryption::Aes128Ctr,
                EciesMac::HmacSha256_256,
                EciesDhPrimitive::Cofactor,
                EciesPointFormat::Uncompressed,
            ),
            setup_with(
                EciesHash::Sha256,
                EciesEncryption::Aes256Ctr,
                EciesMac::HmacSha256_256,
                EciesDhPrimitive::Cofactor,
                EciesPointFormat::Uncompressed,
            ),
            setup_with(
                EciesHash::Sha256,
                EciesEncryption::Aes128Ctr,
                EciesMac::HmacSha256_128,
                EciesDhPrimitive::Cofactor,
                EciesPointFormat::Uncompressed,
            ),
        ] {
            assert!(private.decrypt(other, &c, &[], &[]).is_none(), "{other:?}");
        }
        // With h = 1 the primitives agree, and the point format binds only
        // encryption, so these setups still decrypt.
        for same in [
            setup_with(
                EciesHash::Sha256,
                EciesEncryption::Aes128Ctr,
                EciesMac::HmacSha256_256,
                EciesDhPrimitive::Standard,
                EciesPointFormat::Uncompressed,
            ),
            setup_with(
                EciesHash::Sha256,
                EciesEncryption::Aes128Ctr,
                EciesMac::HmacSha256_256,
                EciesDhPrimitive::Cofactor,
                EciesPointFormat::Compressed,
            ),
        ] {
            assert_eq!(
                private.decrypt(same, &c, &[], &[]).as_deref(),
                Some(message.as_slice())
            );
        }
    }

    #[test]
    fn cbc_takes_whole_blocks_only() {
        let curve = p256();
        let mut rng = rng();
        let (public, private) = key_pair(&curve, integer("CBC0CBC0CBC0", 16));
        let setup = setup_with(
            EciesHash::Sha256,
            EciesEncryption::Aes128Cbc,
            EciesMac::HmacSha256_256,
            EciesDhPrimitive::Cofactor,
            EciesPointFormat::Uncompressed,
        );
        for len in [0usize, 1, 15, 17, 31] {
            assert_eq!(
                public.encrypt(setup, &vec![7; len], &[], &[], &mut rng),
                Err(EciesError::MessageNotBlockAligned),
                "{len}"
            );
        }
        for len in [0usize, 7, 9] {
            assert_eq!(
                EciesEncryption::TdesCbc.encrypt(&[0x40; 24], &vec![7; len]),
                Err(EciesError::MessageNotBlockAligned)
            );
        }

        // §5.1.4 step 9: a 17-octet EM under a valid tag is still "invalid".
        let k = integer("17171717", 16);
        let r = curve.scalar_mul(&curve.base_point(), &k);
        let z = EciesDhPrimitive::Cofactor
            .shared_secret(&curve, &k, public.public_point())
            .expect("z");
        let keying_data = setup.kdf().derive(z.as_slice(), &[], 16 + 32).expect("K");
        let (_, mk) = keying_data.as_slice().split_at(16);
        let em = [0x11u8; 17];
        let d = setup.mac().tag(mk, &em, &[]);
        let c = [curve.encode_point(&r).as_slice(), &em, d.as_slice()].concat();
        assert!(private.decrypt(setup, &c, &[], &[]).is_none());
    }

    /// The TDES-CBC composition of §3.8 against the installed OpenSSL:
    /// `enc -des-ede3-cbc` with the zero IV and no padding on the derived
    /// key must give the same `EM`. The key is SP 800-67's example
    /// `0123456789ABCDEF 23456789ABCDEF01 456789ABCDEF0123` with every
    /// parity bit flipped, so that the raw key and its parity-adjusted form
    /// differ in all 24 octets; OpenSSL encrypts identically under both,
    /// which is the PC-1 fact the parity note states. Skips loudly when no
    /// `openssl` binary is available.
    #[test]
    fn tdes_cbc_matches_openssl_des_ede3_cbc() {
        use crate::test_utils::{encode_hex, openssl_enc};
        const TEST: &str = "tdes_cbc_matches_openssl_des_ede3_cbc";
        let odd_parity = decode_hex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
        let key: Vec<u8> = odd_parity.iter().map(|b| b ^ 0x01).collect();
        let adjusted: Vec<u8> = key
            .iter()
            .map(|&b| {
                let bits = b & 0xFE;
                bits | u8::from(bits.count_ones().is_multiple_of(2))
            })
            .collect();
        assert_eq!(adjusted, odd_parity);
        let message: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(0x9d)).collect();
        let ours = EciesEncryption::TdesCbc
            .encrypt(&key, &message)
            .expect("no weak or repeated component");
        assert_eq!(
            EciesEncryption::TdesCbc.decrypt(&key, &ours).as_deref(),
            Some(message.as_slice())
        );
        for key_form in [&key, &adjusted] {
            let Some(reference) = openssl_enc(
                "-des-ede3-cbc",
                &encode_hex(key_form),
                Some("0000000000000000"),
                &message,
            )
            .or_skip(TEST) else {
                return;
            };
            assert_eq!(ours, reference, "key {}", encode_hex(key_form));
        }
    }

    #[test]
    fn tdes_refuses_a_derived_key_whose_components_collapse() {
        // An all-zero key becomes 01…01 once the parity bits are set: a weak
        // DES key, three times over.
        assert_eq!(
            EciesEncryption::TdesCbc.encrypt(&[0; 24], &[0; 8]),
            Err(EciesError::RejectedDerivedKey)
        );
        assert!(EciesEncryption::TdesCbc
            .decrypt(&[0; 24], &[0; 8])
            .is_none());
    }

    /// The §3.6.1 step 2 bound `hashlen × (2³² − 1)` is a `usize` only on
    /// 64-bit targets.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn kdf_refuses_key_data_at_the_section_3_6_1_bound() {
        for (hash, hash_len) in [(EciesHash::Sha1, 20usize), (EciesHash::Sha512, 64)] {
            let bound = hash_len * usize::try_from(u32::MAX).expect("64-bit usize");
            assert_eq!(
                EciesKdf::AnsiX963(hash).derive(&[1; 20], &[], bound).err(),
                Some(EciesError::KeyDataTooLong)
            );
        }
    }

    #[test]
    fn diffie_hellman_with_the_point_at_infinity_is_invalid() {
        let curve = p256();
        for dh in DH_PRIMITIVES {
            assert!(!dh.assures(&curve, &AffinePoint::infinity()));
            assert_eq!(
                dh.shared_secret(&curve, &BigUint::from_u64(5), &AffinePoint::infinity())
                    .err(),
                Some(EciesError::InvalidSharedSecret)
            );
        }
    }

    // ── Keys ─────────────────────────────────────────────────────────────────

    #[test]
    fn wire_bytes_reject_the_point_at_infinity() {
        assert!(EciesPublicKey::from_wire_bytes(p256(), &[0x00]).is_none());
    }

    #[test]
    fn to_public_key_matches() {
        let mut rng = rng();
        let (public, private) = Ecies::generate(p256(), &mut rng);
        let derived = private.to_public_key();
        assert_eq!(derived.q, public.q);
        let setup = EciesSetup::RECOMMENDED;
        let c = derived
            .encrypt(setup, b"derived key test", &[], &[], &mut rng)
            .expect("encrypt");
        assert_eq!(
            private.decrypt(setup, &c, &[], &[]).as_deref(),
            Some(b"derived key test".as_slice())
        );
    }

    #[test]
    fn public_key_binary_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let blob = public.to_key_blob();
        let recovered = EciesPublicKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p256(), &mut rng);
        let bytes = public.to_wire_bytes();
        let recovered = EciesPublicKey::from_wire_bytes(p256(), &bytes).expect("from_bytes");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_binary_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(p256(), &mut rng);
        let blob = private.to_key_blob();
        let recovered = EciesPrivateKey::from_key_blob(&blob).expect("from_binary");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(p384(), &mut rng);
        let pem = public.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECIES PUBLIC KEY"));
        let recovered = EciesPublicKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(p384(), &mut rng);
        let pem = private.to_pem();
        assert!(pem.contains("CRYPTOGRAPHY ECIES PRIVATE KEY"));
        let recovered = EciesPrivateKey::from_pem(&pem).expect("from_pem");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn public_key_xml_roundtrip() {
        let mut rng = rng();
        let (public, _) = Ecies::generate(secp256k1(), &mut rng);
        let xml = public.to_xml();
        assert!(xml.contains("EciesPublicKey"));
        let recovered = EciesPublicKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.q, public.q);
    }

    #[test]
    fn private_key_xml_roundtrip() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(secp256k1(), &mut rng);
        let xml = private.to_xml();
        let recovered = EciesPrivateKey::from_xml(&xml).expect("from_xml");
        assert_eq!(recovered.d, private.d);
    }

    #[test]
    fn debug_private_key_redacted() {
        let mut rng = rng();
        let (_, private) = Ecies::generate(p256(), &mut rng);
        assert_eq!(format!("{private:?}"), "EciesPrivateKey(<redacted>)");
    }

    // ── Public-key validation (SEC 1 §3.2.2.1) ───────────────────────────────

    /// Whether the crate's SEC 1 wire, key blob, PEM and XML decoders accept
    /// `key`'s point.
    fn accepted_by(key: &super::EciesPublicKey) -> [bool; 4] {
        [
            super::EciesPublicKey::from_wire_bytes(key.curve.clone(), &key.to_wire_bytes())
                .is_some(),
            super::EciesPublicKey::from_key_blob(&key.to_key_blob()).is_some(),
            super::EciesPublicKey::from_pem(&key.to_pem()).is_some(),
            super::EciesPublicKey::from_xml(&key.to_xml()).is_some(),
        ]
    }

    /// The identity, a point off the curve, and points outside the subgroup
    /// of order `n` are refused on every crate entry point, and a key
    /// assembled around them cannot encrypt. Honest keys pass.
    #[test]
    fn public_key_imports_refuse_the_identity_and_every_invalid_point() {
        let mut rng = rng();
        let (p256_key, _) = Ecies::generate(p256(), &mut rng);
        let curve = p256_key.curve.clone();

        let identity = super::EciesPublicKey {
            curve: curve.clone(),
            q: AffinePoint::infinity(),
        };
        assert_eq!(identity.to_wire_bytes(), [0x00]);
        assert!(super::EciesPublicKey::from_wire_bytes(curve.clone(), &[0x00]).is_none());
        assert_eq!(accepted_by(&identity), [false; 4]);
        assert!(identity
            .encrypt(super::EciesSetup::RECOMMENDED, b"m", &[], &[], &mut rng)
            .is_err());

        let off_curve = super::EciesPublicKey {
            curve: curve.clone(),
            q: AffinePoint::new(
                p256_key.q.x.clone(),
                p256_key.q.y.add(&BigUint::one()).rem(&curve.p),
            ),
        };
        assert!(!curve.is_on_curve(&off_curve.q));
        assert_eq!(accepted_by(&off_curve), [false; 4]);

        let k163 = k163();
        let (k163_key, _) = Ecies::generate(k163.clone(), &mut rng);
        let t = sect163k1_order_two_point(&k163);
        for point in [t.clone(), k163.add(&k163_key.q, &t)] {
            assert!(!k163.is_in_prime_subgroup(&point));
            let key = super::EciesPublicKey {
                curve: k163.clone(),
                q: point,
            };
            assert_eq!(accepted_by(&key), [false; 4]);
        }

        assert_eq!(accepted_by(&p256_key), [true; 4]);
        assert_eq!(accepted_by(&k163_key), [true; 4]);
    }

    /// Parameters claiming the order `3n` for P-256's `G`, under which
    /// `d = n` is in range but `d·G = ∞`. The decoders refuse the encoded key
    /// before reading `d`: `3n` is composite, so the parameters are neither a
    /// named curve nor valid under SEC 1 §3.1.1.2.1, and
    /// `CurveParams::from_explicit` rejects them.
    #[test]
    fn private_key_whose_public_point_is_the_identity_is_refused() {
        let named = p256();
        let tripled = CurveParams::new(
            named.p.clone(),
            named.a.clone(),
            named.b.clone(),
            named.n.mul(&BigUint::from_u64(3)),
            named.h,
            named.gx.clone(),
            named.gy.clone(),
        )
        .expect("3n is odd");
        let broken = super::EciesPrivateKey {
            curve: tripled.clone(),
            d: named.n.clone(),
            q: AffinePoint::infinity(),
        };
        assert!(super::EciesPrivateKey::from_key_blob(&broken.to_key_blob()).is_none());
        assert!(super::EciesPrivateKey::from_pem(&broken.to_pem()).is_none());
        assert!(super::EciesPrivateKey::from_xml(&broken.to_xml()).is_none());
        // The same scalar and point under P-256's own parameters are accepted.
        let control = super::EciesPrivateKey {
            curve: named.clone(),
            d: BigUint::one(),
            q: named.base_point(),
        };
        assert!(super::EciesPrivateKey::from_key_blob(&control.to_key_blob()).is_some());
    }
}
