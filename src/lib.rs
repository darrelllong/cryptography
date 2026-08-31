//! Classical and modern block ciphers, stream ciphers, and DRBGs
//! implemented in pure, safe, portable Rust directly from their published
//! specifications.
//!
//! Public-key primitives are variable-time and intentionally live under
//! [`crate::vt`] to make that side-channel property explicit.
//!
//! Entropy warning:
//! - This crate does not provide an operating-system entropy source.
//! - [`CtrDrbgAes256`] is a deterministic DRBG, not a seed generator.
//! - Callers must provide high-entropy external seed material for all
//!   randomness-dependent operations.
//!
//! Safety policy:
//! - `#![deny(unsafe_code)]` is enforced crate-wide. The only exception in a
//!   default build is the audited volatile-write zeroization helper
//!   [`zeroize_slice`], which cannot be expressed in safe Rust. The sole
//!   dependency, the sibling `rump` multiprecision crate (extracted from this
//!   tree), is built with its `wipe` feature — always enabled by this crate —
//!   so every `BigUint` volatile-wipes its live limbs on drop and rump's
//!   shrink paths, exponentiation ladder, and samplers wipe the buffers they
//!   abandon, behind rump's own copy of the same audited helper.
//! - The opt-in `arm-sha3` cargo feature additionally enables an `unsafe`
//!   NEON Keccak path on aarch64 (FEAT_SHA3, runtime-detected). Builds
//!   without that feature contain no other `unsafe`.

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod ct;
#[cfg(test)]
mod test_utils;

pub use ct::zeroize_slice;

#[cfg(feature = "ct_profile")]
pub use ct::{
    ct_profile_measure_helper_costs, ct_profile_reset, ct_profile_snapshot, CtAnfHelperCostsNs,
    CtAnfProfile,
};

pub mod ciphers;
pub mod cprng;
pub mod hash;
pub mod modes;
pub mod public_key;

pub use ciphers::{
    aes, camellia, cast128, chacha20, des, grasshopper, magma, present, rabbit, salsa20, seed,
    serpent, simon, sm4, snow3g, speck, twofish, zuc,
};

/// Common interface for block ciphers.
///
/// Every cipher exposes in-place `encrypt` / `decrypt` operating on a byte
/// slice whose length must equal `Self::BLOCK_LEN`.
pub trait BlockCipher {
    /// Block length in bytes.
    const BLOCK_LEN: usize;
    /// Encrypt one block in-place. Panics if `block.len() != BLOCK_LEN`.
    fn encrypt(&self, block: &mut [u8]);
    /// Decrypt one block in-place. Panics if `block.len() != BLOCK_LEN`.
    fn decrypt(&self, block: &mut [u8]);
}

/// Common interface for stream ciphers.
///
/// Stream ciphers encrypt and decrypt by XORing keystream bytes into a mutable
/// buffer. The same operation is used in both directions.
pub trait StreamCipher {
    /// XOR keystream bytes into `buf` in place.
    fn fill(&mut self, buf: &mut [u8]);

    /// Alias for [`Self::fill`] for callers that prefer this terminology.
    fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

/// Common interface for AEAD constructions with detached tags.
pub trait Aead {
    /// Detached authentication tag type.
    type Tag;

    /// Encrypt `data` in place and return its authentication tag.
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag;

    /// Decrypt `data` in place after authenticating `tag`.
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool;

    /// Encrypt `plaintext` and return `(ciphertext, tag)`.
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, Self::Tag) {
        let mut out = plaintext.to_vec();
        let tag = self.encrypt_in_place(nonce, aad, &mut out);
        (out, tag)
    }

    /// Decrypt `ciphertext` and return plaintext on successful authentication.
    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &Self::Tag,
    ) -> Option<Vec<u8>> {
        let mut out = ciphertext.to_vec();
        if !self.decrypt_in_place(nonce, aad, &mut out, tag) {
            return None;
        }
        Some(out)
    }
}

/// Common interface for byte-oriented CSPRNG/DRBG outputs.
pub trait Csprng {
    /// Fill `out` with pseudorandom bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// Convenience helper for consumers that want one machine word at a time.
    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill_bytes(&mut out);
        u64::from_be_bytes(out)
    }
}

pub use ciphers::aes::{Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct};
pub use ciphers::camellia::{
    Camellia, Camellia128, Camellia128Ct, Camellia192, Camellia192Ct, Camellia256, Camellia256Ct,
    CamelliaCt,
};
pub use ciphers::cast128::{Cast128, Cast128Ct, Cast5, Cast5Ct};
pub use ciphers::chacha20::{ChaCha20, XChaCha20};
pub use ciphers::des::{key_schedule, Des, DesCt, KeySchedule, TDesMode, TripleDes};
pub use ciphers::grasshopper::{Grasshopper, GrasshopperCt};
pub use ciphers::magma::{Magma, MagmaCt};
pub use ciphers::present::{Present, Present128, Present128Ct, Present80, Present80Ct, PresentCt};
pub use ciphers::rabbit::Rabbit;
pub use ciphers::salsa20::Salsa20;
pub use ciphers::seed::{Seed, SeedCt};
pub use ciphers::serpent::{
    Serpent, Serpent128, Serpent128Ct, Serpent192, Serpent192Ct, Serpent256, Serpent256Ct,
    SerpentCt,
};
pub use ciphers::simon::{
    Simon128_128, Simon128_192, Simon128_256, Simon32_64, Simon48_72, Simon48_96, Simon64_128,
    Simon64_96, Simon96_144, Simon96_96,
};
pub use ciphers::sm4::{Sm4, Sm4Ct, Sms4, Sms4Ct};
pub use ciphers::snow3g::{Snow3g, Snow3gCt};
pub use ciphers::speck::{
    Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96, Speck64_128,
    Speck64_96, Speck96_144, Speck96_96,
};
pub use ciphers::twofish::{
    Twofish, Twofish128, Twofish128Ct, Twofish192, Twofish192Ct, Twofish256, Twofish256Ct,
    TwofishCt,
};
pub use ciphers::zuc::{Zuc128, Zuc128Ct};

pub use cprng::ctr_drbg::CtrDrbgAes256;
pub use hash::hkdf::Hkdf;
pub use hash::hmac::Hmac;
pub use hash::md5::Md5;
pub use hash::ripemd160::Ripemd160;
pub use hash::sha1::Sha1;
pub use hash::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
pub use hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
pub use hash::{Digest, Xof};
pub use modes::{
    Aes128GcmSiv, Aes256GcmSiv, AesKeyWrap, Cbc, Ccm, Cfb, Cfb8, ChaCha20Poly1305, Cmac, Ctr, Eax,
    Ecb, Gcm, GcmVt, Gmac, GmacVt, Ocb, Ofb, Poly1305, Siv, Xts,
};

impl StreamCipher for ChaCha20 {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for XChaCha20 {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for Salsa20 {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for Rabbit {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for Snow3g {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for Snow3gCt {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for Zuc128 {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl StreamCipher for Zuc128Ct {
    fn fill(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

impl<C: BlockCipher> Aead for Gcm<C> {
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        self.encrypt(nonce, aad, data)
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        self.decrypt(nonce, aad, data, tag)
    }
}

impl<C: BlockCipher> Aead for GcmVt<C> {
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        self.encrypt(nonce, aad, data)
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        self.decrypt(nonce, aad, data, tag)
    }
}

impl<C: BlockCipher, const TAG_LEN: usize> Aead for Ccm<C, TAG_LEN> {
    type Tag = [u8; TAG_LEN];

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        self.encrypt(nonce, aad, data)
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        self.decrypt(nonce, aad, data, tag)
    }
}

impl Aead for ChaCha20Poly1305 {
    type Tag = [u8; 16];

    /// Panics if `nonce.len() != 12`.
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .expect("ChaCha20-Poly1305 nonce must be 12 bytes");
        self.encrypt_in_place(nonce, aad, data)
    }

    /// Panics if `nonce.len() != 12`.
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .expect("ChaCha20-Poly1305 nonce must be 12 bytes");
        self.decrypt_in_place(nonce, aad, data, tag)
    }
}

impl<C: BlockCipher> Aead for Siv<C> {
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        let (ciphertext, tag) = self.encrypt(nonce, aad, data);
        data.copy_from_slice(&ciphertext);
        tag
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        self.decrypt(nonce, aad, data, tag)
    }
}

impl<C: BlockCipher> Aead for Eax<C> {
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        self.encrypt(nonce, aad, data)
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        self.decrypt(nonce, aad, data, tag)
    }
}

impl<C: BlockCipher> Aead for Ocb<C> {
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        self.encrypt(nonce, aad, data)
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        self.decrypt(nonce, aad, data, tag)
    }
}

impl Aead for Aes128GcmSiv {
    type Tag = [u8; 16];

    /// Panics if `nonce.len() != 12`.
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .expect("AES-GCM-SIV nonce must be 12 bytes");
        self.encrypt(nonce, aad, data)
    }

    /// Panics if `nonce.len() != 12`.
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .expect("AES-GCM-SIV nonce must be 12 bytes");
        self.decrypt(nonce, aad, data, tag)
    }
}

impl Aead for Aes256GcmSiv {
    type Tag = [u8; 16];

    /// Panics if `nonce.len() != 12`.
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Self::Tag {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .expect("AES-GCM-SIV nonce must be 12 bytes");
        self.encrypt(nonce, aad, data)
    }

    /// Panics if `nonce.len() != 12`.
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> bool {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .expect("AES-GCM-SIV nonce must be 12 bytes");
        self.decrypt(nonce, aad, data, tag)
    }
}

/// Explicit variable-time public-key surface.
///
/// Most items in this namespace use variable-time big-integer and ECC arithmetic
/// and are unsuitable for side-channel exposed production signing/decryption.
///
/// Exception: `X25519` and `X448` (RFC 7748) are constant-time. They live
/// here because they share serialization conventions with the rest of the
/// public-key surface, but the scalar-mult primitive itself is hardened
/// against timing side channels on the secret scalar.
pub mod vt {
    pub use crate::public_key::cocks::{Cocks, CocksPrivateKey, CocksPublicKey};
    pub use crate::public_key::dh::{Dh, DhParams, DhPrivateKey, DhPublicKey};
    pub use crate::public_key::dsa::{Dsa, DsaPrivateKey, DsaPublicKey, DsaSignature};
    pub use crate::public_key::ec::{
        b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384, p521,
        secp256k1, AffinePoint, CurveParams,
    };
    pub use crate::public_key::ec_elgamal::{
        EcElGamal, EcElGamalCiphertext, EcElGamalPrivateKey, EcElGamalPublicKey,
    };
    pub use crate::public_key::ecdh::{Ecdh, EcdhPrivateKey, EcdhPublicKey};
    pub use crate::public_key::ecdsa::{Ecdsa, EcdsaPrivateKey, EcdsaPublicKey, EcdsaSignature};
    pub use crate::public_key::ecies::{Ecies, EciesPrivateKey, EciesPublicKey};
    pub use crate::public_key::ed25519::{
        Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    };
    pub use crate::public_key::eddsa::{EdDsa, EdDsaPrivateKey, EdDsaPublicKey, EdDsaSignature};
    pub use crate::public_key::edwards_dh::{EdwardsDh, EdwardsDhPrivateKey, EdwardsDhPublicKey};
    pub use crate::public_key::edwards_elgamal::{
        EdwardsElGamal, EdwardsElGamalCiphertext, EdwardsElGamalPrivateKey, EdwardsElGamalPublicKey,
    };
    pub use crate::public_key::elgamal::{
        ElGamal, ElGamalCiphertext, ElGamalPrivateKey, ElGamalPublicKey,
    };
    pub use crate::public_key::ml_dsa::{
        MlDsa, MlDsaParameterSet, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature,
    };
    pub use crate::public_key::ml_kem::{
        MlKem, MlKemCiphertext, MlKemParameterSet, MlKemPrivateKey, MlKemPublicKey,
        MlKemSharedSecret,
    };
    pub use crate::public_key::ntru_ees1087ep1::{
        NtruEes1087Ep1, NtruEes1087Ep1Ciphertext, NtruEes1087Ep1PrivateKey, NtruEes1087Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees1087ep2::{
        NtruEes1087Ep2, NtruEes1087Ep2Ciphertext, NtruEes1087Ep2PrivateKey, NtruEes1087Ep2PublicKey,
    };
    pub use crate::public_key::ntru_ees1171ep1::{
        NtruEes1171Ep1, NtruEes1171Ep1Ciphertext, NtruEes1171Ep1PrivateKey, NtruEes1171Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees1499ep1::{
        NtruEes1499Ep1, NtruEes1499Ep1Ciphertext, NtruEes1499Ep1PrivateKey, NtruEes1499Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees401ep1::{
        NtruEes401Ep1, NtruEes401Ep1Ciphertext, NtruEes401Ep1PrivateKey, NtruEes401Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees443ep1::{
        NtruEes443Ep1, NtruEes443Ep1Ciphertext, NtruEes443Ep1PrivateKey, NtruEes443Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees449ep1::{
        NtruEes449Ep1, NtruEes449Ep1Ciphertext, NtruEes449Ep1PrivateKey, NtruEes449Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees541ep1::{
        NtruEes541Ep1, NtruEes541Ep1Ciphertext, NtruEes541Ep1PrivateKey, NtruEes541Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees677ep1::{
        NtruEes677Ep1, NtruEes677Ep1Ciphertext, NtruEes677Ep1PrivateKey, NtruEes677Ep1PublicKey,
    };
    pub use crate::public_key::ntru_ees_core::NtruEesError;
    pub use crate::public_key::ntru_hps509::{
        NtruHps509, NtruHps509Ciphertext, NtruHps509PrivateKey, NtruHps509PublicKey,
        NtruHps509SharedSecret,
    };
    pub use crate::public_key::ntru_hps677::{
        NtruHps677, NtruHps677Ciphertext, NtruHps677PrivateKey, NtruHps677PublicKey,
        NtruHps677SharedSecret,
    };
    pub use crate::public_key::ntru_hps821::{
        NtruHps821, NtruHps821Ciphertext, NtruHps821PrivateKey, NtruHps821PublicKey,
        NtruHps821SharedSecret,
    };
    pub use crate::public_key::ntru_hrss701::{
        NtruHrss701, NtruHrss701Ciphertext, NtruHrss701PrivateKey, NtruHrss701PublicKey,
        NtruHrss701SharedSecret,
    };
    pub use crate::public_key::paillier::{Paillier, PaillierPrivateKey, PaillierPublicKey};
    pub use crate::public_key::rabin::{Rabin, RabinPrivateKey, RabinPublicKey};
    pub use crate::public_key::rsa::{Rsa, RsaPrivateKey, RsaPublicKey};
    pub use crate::public_key::rsa_pkcs1::{RsaOaep, RsaPss};
    pub use crate::public_key::schmidt_samoa::{
        SchmidtSamoa, SchmidtSamoaPrivateKey, SchmidtSamoaPublicKey,
    };
    pub use crate::public_key::x25519::{X25519PrivateKey, X25519PublicKey, X25519};
    pub use crate::public_key::x448::{X448PrivateKey, X448PublicKey, X448};
    pub use rump::modular::{MontgomeryContext, MontgomeryResidue, MontgomeryScratch};
    pub use rump::{BigInt, BigUint, Sign};
}

#[cfg(test)]
mod scrub;
