//! PKCS #1 v2.2 wrappers for the raw RSA primitive.
//!
//! The raw [`crate::Rsa`] type intentionally exposes only the trapdoor
//! permutation. This module layers the standards-based encodings on top:
//!
//! - `RSAES-OAEP` for encryption/decryption
//! - `RSASSA-PSS` for signing/verification
//!
//! The underlying math stays the same, but these wrappers add the encoding,
//! masking, and message hashing steps from RFC 8017 so callers can actually
//! use the primitive safely.

use core::marker::PhantomData;

use crate::hash::Digest;
use crate::public_key::rsa::{RsaPrivateKey, RsaPublicKey};
use crate::Csprng;
use rump::BigUint;

// RFC 8017's `k`: the octet length of the RSA modulus `n`.
fn modulus_len_bytes(modulus: &BigUint) -> usize {
    modulus.bits().div_ceil(8)
}

fn mgf1<H: Digest>(seed: &[u8], out_len: usize) -> Vec<u8> {
    // RFC 8017 Mask Generation Function 1 (MGF1): hash
    // `seed || counter_be32` and concatenate blocks until enough mask bytes
    // have been produced.
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0u32;
    while out.len() < out_len {
        let mut digest_input = Vec::with_capacity(seed.len() + 4);
        digest_input.extend_from_slice(seed);
        digest_input.extend_from_slice(&counter.to_be_bytes());
        let block = H::digest(&digest_input);
        let take = (out_len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

fn i2osp(value: &BigUint, len: usize) -> Option<Vec<u8>> {
    // RFC 8017 Integer-to-Octet-String Primitive (I2OSP): fixed-width
    // big-endian integer encoding.
    let bytes = value.to_be_bytes();
    if bytes.len() > len {
        return None;
    }
    let mut out = vec![0u8; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

fn os2ip(bytes: &[u8]) -> BigUint {
    // RFC 8017 Octet-String-to-Integer Primitive (OS2IP): big-endian octet
    // string to non-negative integer.
    BigUint::from_be_bytes(bytes)
}

#[inline]
fn ct_eq_u8_mask(a: u8, b: u8) -> u8 {
    let x = u16::from(a ^ b);
    let is_zero = u8::try_from((x.wrapping_sub(1) >> 8) & 1).expect("bit fits in u8");
    0u8.wrapping_sub(is_zero)
}

#[inline]
fn ct_nonzero_u8_mask(x: u8) -> u8 {
    ct_eq_u8_mask(x, 0) ^ u8::MAX
}

#[inline]
fn ct_mask_to_usize(mask: u8) -> usize {
    0usize.wrapping_sub(usize::from(mask >> 7))
}

/// RFC 8017 `RSAES-OAEP`.
pub struct RsaOaep<H: Digest>(PhantomData<H>);

impl<H: Digest> RsaOaep<H> {
    /// Encrypt one message using `RSAES-OAEP`.
    ///
    /// The caller supplies the OAEP seed explicitly so the standard encoding
    /// can be tested deterministically without coupling this layer to a
    /// particular RNG.
    #[must_use]
    pub fn encrypt(
        public: &RsaPublicKey,
        label: &[u8],
        message: &[u8],
        seed: &[u8],
    ) -> Option<Vec<u8>> {
        let h_len = H::OUTPUT_LEN;
        let k = modulus_len_bytes(public.modulus());
        if seed.len() != h_len || k < 2 * h_len + 2 || message.len() > k - 2 * h_len - 2 {
            return None;
        }

        let l_hash = H::digest(label);
        let mut db = Vec::with_capacity(k - h_len - 1);
        // RFC 8017: DB = lHash || PS || 0x01 || M, with PS sized so the full
        // encoded message fits into `k` octets.
        db.extend_from_slice(&l_hash);
        db.resize(k - h_len - message.len() - 2, 0);
        db.push(0x01);
        db.extend_from_slice(message);

        // OAEP cross-masks the two halves so neither the seed nor the data
        // block can be recovered independently.
        let db_mask = mgf1::<H>(seed, k - h_len - 1);
        let mut masked_db = db;
        for (byte, mask) in masked_db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }

        let seed_mask = mgf1::<H>(&masked_db, h_len);
        let mut masked_seed = seed.to_vec();
        for (byte, mask) in masked_seed.iter_mut().zip(seed_mask.iter()) {
            *byte ^= *mask;
        }

        let mut encoded = Vec::with_capacity(k);
        // RFC 8017 requires a leading zero octet so the encoded message is
        // interpreted as an integer strictly below the modulus-width bound.
        encoded.push(0x00);
        encoded.extend_from_slice(&masked_seed);
        encoded.extend_from_slice(&masked_db);

        let encoded_int = os2ip(&encoded);
        let ciphertext = public.encrypt_raw(&encoded_int);
        i2osp(&ciphertext, k)
    }

    /// Encrypt one message using `RSAES-OAEP` with a caller-supplied CSPRNG.
    ///
    /// The deterministic `encrypt(..., seed)` entry point remains useful for
    /// KATs and differential testing; this helper is the ergonomic path for
    /// normal use.
    #[must_use]
    pub fn encrypt_rng<R: Csprng>(
        public: &RsaPublicKey,
        label: &[u8],
        message: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let mut seed = vec![0u8; H::OUTPUT_LEN];
        rng.fill_bytes(&mut seed);
        Self::encrypt(public, label, message, &seed)
    }

    /// Decrypt one `RSAES-OAEP` ciphertext.
    ///
    /// The RSA private operation here is **unblinded**. Prefer
    /// [`Self::decrypt_rng`] when a CSPRNG is available so the variable-time
    /// bigint stack never sees the raw attacker-chosen ciphertext.
    #[must_use]
    pub fn decrypt(private: &RsaPrivateKey, label: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        if ciphertext.len() != k || k < 2 * H::OUTPUT_LEN + 2 {
            return None;
        }
        let encoded_int = private.decrypt_raw(&os2ip(ciphertext));
        Self::oaep_decode(label, k, &encoded_int)
    }

    /// Decrypt one `RSAES-OAEP` ciphertext with CSPRNG-driven ciphertext
    /// blinding on the RSA private operation (Brumley–Boneh timing-attack
    /// countermeasure). Functionally identical to [`Self::decrypt`].
    #[must_use]
    pub fn decrypt_rng<R: crate::Csprng>(
        private: &RsaPrivateKey,
        label: &[u8],
        ciphertext: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        if ciphertext.len() != k || k < 2 * H::OUTPUT_LEN + 2 {
            return None;
        }
        let encoded_int = private.decrypt_raw_blinded(&os2ip(ciphertext), rng);
        Self::oaep_decode(label, k, &encoded_int)
    }

    /// Shared OAEP decode of the recovered integer (constant-time validation),
    /// used by both the blinded and unblinded decrypt paths.
    fn oaep_decode(label: &[u8], k: usize, encoded_int: &BigUint) -> Option<Vec<u8>> {
        let h_len = H::OUTPUT_LEN;
        // Always `Some`: raw RSA decryption returns a value in `[0, n)`, and
        // the modulus occupies exactly `k` bytes.
        let encoded = i2osp(encoded_int, k)?;

        let (masked_seed, masked_db) = encoded[1..].split_at(h_len);
        let seed_mask = mgf1::<H>(masked_db, h_len);
        let mut seed = masked_seed.to_vec();
        for (byte, mask) in seed.iter_mut().zip(seed_mask.iter()) {
            *byte ^= *mask;
        }

        let db_mask = mgf1::<H>(&seed, k - h_len - 1);
        let mut db = masked_db.to_vec();
        for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }

        let l_hash = H::digest(label);
        // Full-scan OAEP validation: keep the whole parse branchless so a
        // malformed ciphertext does not become a timing oracle (the classic
        // Manger-style padding-oracle failure mode).
        let mut saw_separator = 0u8;
        let mut bad_padding = ct_nonzero_u8_mask(encoded[0]);
        bad_padding |= crate::ct::constant_time_eq_mask(&db[..h_len], &l_hash) ^ u8::MAX;
        let mut msg_idx = 0usize;
        for (idx, &byte) in db[h_len..].iter().enumerate() {
            let is_zero = ct_eq_u8_mask(byte, 0);
            let is_one = ct_eq_u8_mask(byte, 0x01);
            let before_separator = saw_separator ^ u8::MAX;
            bad_padding |= before_separator & (is_zero ^ u8::MAX) & (is_one ^ u8::MAX);

            let take_separator = before_separator & is_one;
            let mask = ct_mask_to_usize(take_separator);
            let candidate_idx = h_len + idx + 1;
            msg_idx = (msg_idx & !mask) | (candidate_idx & mask);
            saw_separator |= take_separator;
        }

        if saw_separator != u8::MAX || bad_padding != 0 {
            return None;
        }
        Some(db[msg_idx..].to_vec())
    }
}

/// RFC 8017 `RSASSA-PSS`.
pub struct RsaPss<H: Digest>(PhantomData<H>);

impl<H: Digest> RsaPss<H> {
    /// Build the RFC 8017 §9.1.1 PSS-encoded integer representative, shared by
    /// the blinded and unblinded signing paths.
    fn pss_encode(private: &RsaPrivateKey, message: &[u8], salt: &[u8]) -> Option<BigUint> {
        // RFC 8017 uses `emBits = modBits - 1` so the encoded representative
        // is guaranteed to stay below the modulus.
        let em_bits = private.modulus().bits().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let h_len = H::OUTPUT_LEN;
        if em_len < h_len + salt.len() + 2 {
            return None;
        }

        let m_hash = H::digest(message);
        // RFC 8017 §9.1.1 step 5 prefixes eight zero octets before hashing the
        // message hash and salt into `H`.
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&m_hash);
        m_prime.extend_from_slice(salt);
        let h = H::digest(&m_prime);

        let mut db = vec![0u8; em_len - salt.len() - h_len - 2];
        db.push(0x01);
        db.extend_from_slice(salt);

        let db_mask = mgf1::<H>(&h, em_len - h_len - 1);
        for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }

        let unused_bits = (8 * em_len) - em_bits;
        if unused_bits != 0 {
            db[0] &= 0xff_u8 >> unused_bits;
        }

        let mut encoded = db;
        encoded.extend_from_slice(&h);
        // RFC 8017 §9.1.1 ends the encoded message with the fixed trailer
        // field 0xbc.
        encoded.push(0xbc);

        Some(os2ip(&encoded))
    }

    /// Sign one message using `RSASSA-PSS`.
    ///
    /// The caller supplies the salt explicitly so the encoding is fully
    /// deterministic under test. The RSA private operation is **unblinded**;
    /// prefer [`Self::sign_rng`] for production signing.
    #[must_use]
    pub fn sign(private: &RsaPrivateKey, message: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        let encoded_int = Self::pss_encode(private, message, salt)?;
        let signature_int = private.decrypt_raw(&encoded_int);
        i2osp(&signature_int, k)
    }

    /// Sign one message using `RSASSA-PSS` with a fresh random salt and
    /// CSPRNG-driven ciphertext blinding on the RSA private operation.
    ///
    /// The deterministic `sign(..., salt)` variant remains for fixed-vector
    /// testing; this is the production signing path (fresh salt + blinding).
    #[must_use]
    pub fn sign_rng<R: Csprng>(
        private: &RsaPrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        let mut salt = vec![0u8; H::OUTPUT_LEN];
        rng.fill_bytes(&mut salt);
        let encoded_int = Self::pss_encode(private, message, &salt)?;
        let signature_int = private.decrypt_raw_blinded(&encoded_int, rng);
        i2osp(&signature_int, k)
    }

    /// Verify one `RSASSA-PSS` signature.
    #[must_use]
    pub fn verify(public: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
        let k = modulus_len_bytes(public.modulus());
        let em_bits = public.modulus().bits().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let h_len = H::OUTPUT_LEN;
        if signature.len() != k || em_len < h_len + 2 {
            return false;
        }

        let signature_int = os2ip(signature);
        let encoded_int = public.encrypt_raw(&signature_int);
        // Always `Some`: raw RSA encryption returns a value in `[0, n)`, and
        // the modulus is chosen so that the encoded message fits into `em_len`.
        let Some(mut encoded) = i2osp(&encoded_int, em_len) else {
            return false;
        };
        let mut bad_padding = ct_eq_u8_mask(encoded.last().copied().unwrap_or(0), 0xbc) ^ u8::MAX;

        let h_index = em_len - h_len - 1;
        let h = encoded[h_index..h_index + h_len].to_vec();
        let masked_db = &mut encoded[..h_index];
        let unused_bits = (8 * em_len) - em_bits;
        // RFC 8017 §9.1.2 step 6 checks the unused top bits in `maskedDB`
        // before the MGF1 mask is removed.
        if unused_bits != 0 {
            bad_padding |= ct_nonzero_u8_mask(masked_db[0] >> (8 - unused_bits));
        }

        let db_mask = mgf1::<H>(&h, h_index);
        for (byte, mask) in masked_db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }
        if unused_bits != 0 {
            masked_db[0] &= 0xff_u8 >> unused_bits;
        }

        // Full-scan PSS validation mirrors the OAEP approach: do not stop at
        // the first malformed byte, because verification should not leak where
        // the separator structure failed or turn into a format oracle. This
        // is the same "no early parse oracle" discipline used to avoid
        // Manger-style OAEP padding oracles on the decryption side.
        let mut saw_separator = 0u8;
        let mut one_index = 0usize;
        for (idx, &byte) in masked_db.iter().enumerate() {
            let is_zero = ct_eq_u8_mask(byte, 0);
            let is_one = ct_eq_u8_mask(byte, 0x01);
            let before_separator = saw_separator ^ u8::MAX;
            bad_padding |= before_separator & (is_zero ^ u8::MAX) & (is_one ^ u8::MAX);

            let take_separator = before_separator & is_one;
            let mask = ct_mask_to_usize(take_separator);
            one_index = (one_index & !mask) | (idx & mask);
            saw_separator |= take_separator;
        }
        bad_padding |= saw_separator ^ u8::MAX;
        if bad_padding != 0 {
            return false;
        }
        let salt = &masked_db[one_index + 1..];

        let m_hash = H::digest(message);
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&m_hash);
        m_prime.extend_from_slice(salt);
        let expected_h = H::digest(&m_prime);
        crate::ct::constant_time_eq_mask(&h, &expected_h) == u8::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::{RsaOaep, RsaPss};
    use crate::public_key::rsa::{Rsa, RsaPrivateKey, RsaPublicKey};
    use crate::{CtrDrbgAes256, Sha1, Sha512};
    use rump::BigUint;

    fn decode_hex(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            cleaned.len() % 2,
            0,
            "hex input must have an even number of nybbles"
        );
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex byte"))
            .collect()
    }

    fn from_hex(hex: &str) -> BigUint {
        BigUint::from_be_bytes(&decode_hex(hex))
    }

    fn large_reference_key() -> (RsaPublicKey, RsaPrivateKey) {
        let p = BigUint::from_be_bytes(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b,
        ]);
        let q = BigUint::from_be_bytes(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x15,
        ]);
        Rsa::from_primes(&p, &q).expect("valid larger RSA key")
    }

    #[test]
    fn oaep_roundtrip() {
        let (public, private) = large_reference_key();
        let seed = [0x42u8; 20];
        let ciphertext =
            RsaOaep::<Sha1>::encrypt(&public, b"label", b"hello", &seed).expect("message fits");
        let plaintext =
            RsaOaep::<Sha1>::decrypt(&private, b"label", &ciphertext).expect("valid OAEP");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn oaep_rejects_wrong_label() {
        let (public, private) = large_reference_key();
        let seed = [0x11u8; 20];
        let ciphertext =
            RsaOaep::<Sha1>::encrypt(&public, b"label", b"hello", &seed).expect("message fits");
        assert!(RsaOaep::<Sha1>::decrypt(&private, b"other", &ciphertext).is_none());
    }

    #[test]
    fn oaep_rejects_wrong_length_inputs() {
        let (public, private) = large_reference_key();
        assert!(RsaOaep::<Sha1>::encrypt(&public, b"", b"hello", &[0x55; 19]).is_none());
        assert!(RsaOaep::<Sha1>::decrypt(&private, b"", &[0u8; 3]).is_none());
    }

    #[test]
    fn pss_sign_and_verify() {
        let (public, private) = large_reference_key();
        let salt = [0x33u8; 8];
        let signature = RsaPss::<Sha1>::sign(&private, b"abc", &salt).expect("message fits");
        assert!(RsaPss::<Sha1>::verify(&public, b"abc", &signature));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abd", &signature));
    }

    #[test]
    fn pss_rejects_bad_lengths() {
        let (public, private) = large_reference_key();
        assert!(RsaPss::<Sha1>::sign(&private, b"abc", &[0x44; 26]).is_none());
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &[0u8; 3]));
    }

    #[test]
    fn oaep_encrypt_rng_roundtrip() {
        let (public, private) = large_reference_key();
        let mut drbg = CtrDrbgAes256::new(&[0x21; 48]);
        let ciphertext =
            RsaOaep::<Sha1>::encrypt_rng(&public, b"label", b"hello", &mut drbg).expect("OAEP");
        let plaintext =
            RsaOaep::<Sha1>::decrypt(&private, b"label", &ciphertext).expect("valid OAEP");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn pss_sign_rng_and_verify() {
        let (public, private) = large_reference_key();
        let mut drbg = CtrDrbgAes256::new(&[0x22; 48]);
        let signature = RsaPss::<Sha1>::sign_rng(&private, b"abc", &mut drbg).expect("PSS");
        assert!(RsaPss::<Sha1>::verify(&public, b"abc", &signature));
    }

    #[test]
    fn nist_cavp_pss_sigver_sha1_vector_passes() {
        // NIST CAVP, SigVerPSS_186-3.rsp:
        //   [mod = 1024], SHAAlg = SHA1, Result = P
        let n = from_hex(
            "ec996bc93e81094436fd5fc2eef511782eb40fe60cc6f27f24bc8728d686537f\
             1caa82cfcfa5c323604b6918d7cd0318d98395c855c7c7ada6fc447f192283cdc\
             81e7291e232336019d4dac12356b93a349883cd2c0a7d2eae9715f1cc6dd657ce\
             a5cb2c46ce6468794b326b33f1bff61a00fa72931345ca6768365e1eb906dd",
        );
        let e = from_hex("90c6d3");
        let msg = decode_hex(
            "a4daf4621676917e28493a585d9baffca3755e77e1f18e3ccfb3dec60ab8ee7e\
             684f5cde8864f2d7ae041d70ce1ea1b1e7878cbf93416848dbfdb5214fde972e\
             5780cb83c439dfc8aa9fa3e2724adbd02bdb36d2213c84d1b12a23fb5bf1baae\
             19772a97ef7cc21bc420b3f570a6c321167745f9b46a489ff8420f9a5679c1c4",
        );
        let signature = decode_hex(
            "319c62984acd52423e59a17d27d4eca7722703b054a71a1ee5f7a218b6f4a274\
             632eaf8ef2a577a7e8a7f654b8deb1ec9b1e529cf93459cc8af4c6df6fffabc3\
             edded0c421604ea2aae35836b05fd9de7abd78540d45fd6d0ea714733a3427b0\
             0d9d6404db8ede4a27932b47d88243eefcbffe1e55841823def30c57de7562cf",
        );

        let public = RsaPublicKey::from_components(e, n);
        assert!(RsaPss::<Sha1>::verify(&public, &msg, &signature));
    }

    #[test]
    fn nist_acvp_kts_oaep_sha512_decrypt_vector_matches_plaintext() {
        // NIST ACVP sample vectors:
        //   KTS-IFC (SP800-56Br2), scheme KTS-OAEP-Party_V-confirmation,
        //   noKdfKc, tgId=1, tcId=1.
        //
        // In this profile, ktsParameter is empty and kasMode=noKdfKc, so
        // decrypted OAEP plaintext equals iutK directly (126 bytes).
        let p = from_hex(
            "FFC4F61CF26222F2174A525AE0ED01A1E075215D4111F1AF0153EFC595FE4DD1\
             0CB795A2CEB5C84AC44D62CA50BD170503924B27ED4EB09467C4D1BBADE73F79\
             14A318F7F304342C9D0FACF1A55974D20E9DACD578627425AE88A702E2655A71\
             3E0823C59025A3AF67C48962745E1C0FC7B32007597E813868A91C96B49BF127",
        );
        let q = from_hex(
            "EB385875212FF27BF89C38ACC52B86DA0AF8EA779DA30D153F40A375BE116791\
             4DCA207C241653B030671FF700C0714A6CCFDDC0C25F430CB47C8C74DF22E318\
             93396C3676F3A9E7B9ACD6E0AFC292CBB48298A22AFBCABA01966FCDFE0C5D06\
             48CFB9938C26CD047107BC8C1945A2244A8B813C292CE74CCCF95D43F71BEF75",
        );
        let e = from_hex("03DA3A5B37");
        let expected_n = from_hex(
            "EB021963239BD53F5A6F292232E0A91F342350CC3266C9DECB773E2D5CF27E82\
             6A95DB350FC2EA88CCA3326E5723DCDA9460C5E2A16F7DF3BB12DBB4C2479D4F\
             7FEBA15B48AC09510E0838F08AD7C37235B10A0DE1A405E578E6213B00341E26\
             F7FE13D4164AACC5FD14DFAA805C7D49FCC39CFBC8F1D2C37EB172B14EE50E5E\
             213E2DF280C4FB5816E84956F4E14DE26EFAF29338CA7DCD532FC85CDF460D30\
             79099EC42D0E71175A2FCDC0CCF084492D6D39A0D99CFDD11FD509BB656A9A6C\
             E142FC09768C109CA67241208217B25CFEE41A8A7BCBDDD6F0EF325B073DDE20\
             E508F680170EA9D4F3F2DBE1424510ECD3488842D023E063B17C8DD231859FD3",
        );
        let ciphertext = decode_hex(
            "D735FC3D4D1C557AE8F0454CF14474F3CD9A54EA8F746DBA6EFAE490B47674F7\
             D4EFBFC9E0EEA80A14F6DD584AFC2AAE28BAA625AAFDBC29D79802BC6838E953\
             FBC1B70DEBAF654B6B65E8157A666DF83DEC0638AD48101416EFD919065357FA\
             CE7B59D543D60B1FB814D532045729D6E10EC3B3277C9F351224EAA565D870B1\
             73428929F38D2A33CEA0439BB7204409E5808EB7E6261FF6B6D1260CEB402848\
             C2015D326F492322D21DF114776AC2802A2B552A9A714FB4C96A1CEDAF0CE033\
             73CCFC45ABA877A83CD16AED12CC0B52D1201FD95866B4781DAB9603A1E08993\
             DC2CD3A5DFA37F3EEB1468FBDB104555805C0BE35F03F20C6559C2C8571E7A60",
        );
        let expected_plaintext = decode_hex(
            "AB7243906E58D5322155945B9AB764941648FCF37F355FD78FB8636768FE6A1A\
             C020DFE4C041C98BE155087347D56F94F2C3C07E685E328A5604D237E4B78729\
             C8DB31094B5758D7C66452B2C0B6DC61EF471EF02833F6F12A2B3B18198FEF34\
             07C92923375FDB10B3E8B15E505CB6921CEBC7D3EB8FF3F2FE686827680B",
        );

        let (public, private) =
            Rsa::from_primes_with_exponent(&p, &q, &e).expect("vector RSA key must be valid");
        assert_eq!(
            public.modulus(),
            &expected_n,
            "vector transcription mismatch"
        );

        let plaintext =
            RsaOaep::<Sha512>::decrypt(&private, b"", &ciphertext).expect("valid OAEP vector");
        assert_eq!(plaintext, expected_plaintext);
    }
}
