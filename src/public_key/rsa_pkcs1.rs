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
use crate::public_key::bigint::BigUint;
use crate::{RsaPrivateKey, RsaPublicKey};

fn modulus_len_bytes(modulus: &BigUint) -> usize {
    modulus.bits().div_ceil(8)
}

fn mgf1<H: Digest>(seed: &[u8], out_len: usize) -> Vec<u8> {
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
    let bytes = value.to_be_bytes();
    if bytes.len() > len {
        return None;
    }
    let mut out = vec![0u8; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

fn os2ip(bytes: &[u8]) -> BigUint {
    BigUint::from_be_bytes(bytes)
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
        db.extend_from_slice(&l_hash);
        db.resize(k - h_len - message.len() - 2, 0);
        db.push(0x01);
        db.extend_from_slice(message);

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
        encoded.push(0x00);
        encoded.extend_from_slice(&masked_seed);
        encoded.extend_from_slice(&masked_db);

        let encoded_int = os2ip(&encoded);
        let ciphertext = public.encrypt_raw(&encoded_int);
        i2osp(&ciphertext, k)
    }

    /// Decrypt one `RSAES-OAEP` ciphertext.
    #[must_use]
    pub fn decrypt(private: &RsaPrivateKey, label: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let h_len = H::OUTPUT_LEN;
        let k = modulus_len_bytes(private.modulus());
        if ciphertext.len() != k || k < 2 * h_len + 2 {
            return None;
        }

        let ciphertext_int = os2ip(ciphertext);
        let encoded_int = private.decrypt_raw(&ciphertext_int);
        let encoded = i2osp(&encoded_int, k)?;

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
        let mut saw_separator = 0u8;
        let mut bad_padding = u8::from(encoded[0] != 0);
        bad_padding |= u8::from(!crate::ct::constant_time_eq(&db[..h_len], &l_hash));
        let mut msg_idx = 0usize;
        for (idx, &byte) in db[h_len..].iter().enumerate() {
            let is_zero = u8::from(byte == 0);
            let is_one = u8::from(byte == 0x01);
            let before_separator = saw_separator ^ 1;
            bad_padding |= before_separator & (is_zero ^ 1) & (is_one ^ 1);

            let take_separator = before_separator & is_one;
            let mask = 0usize.wrapping_sub(usize::from(take_separator));
            let candidate_idx = h_len + idx + 1;
            msg_idx = (msg_idx & !mask) | (candidate_idx & mask);
            saw_separator |= take_separator;
        }

        if saw_separator == 0 || bad_padding != 0 {
            return None;
        }
        Some(db[msg_idx..].to_vec())
    }
}

/// RFC 8017 `RSASSA-PSS`.
pub struct RsaPss<H: Digest>(PhantomData<H>);

impl<H: Digest> RsaPss<H> {
    /// Sign one message using `RSASSA-PSS`.
    ///
    /// The caller supplies the salt explicitly so the encoding is fully
    /// deterministic under test.
    #[must_use]
    pub fn sign(private: &RsaPrivateKey, message: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        let em_bits = private.modulus().bits().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let h_len = H::OUTPUT_LEN;
        if em_len < h_len + salt.len() + 2 {
            return None;
        }

        let m_hash = H::digest(message);
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
       encoded.push(0xbc);

        let encoded_int = os2ip(&encoded);
        let signature_int = private.decrypt_raw(&encoded_int);
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
        let Some(mut encoded) = i2osp(&encoded_int, em_len) else {
            return false;
        };
        let mut bad_padding = u8::from(encoded.last().copied() != Some(0xbc));

        let h_index = em_len - h_len - 1;
        let h = encoded[h_index..h_index + h_len].to_vec();
        let masked_db = &mut encoded[..h_index];
        let unused_bits = (8 * em_len) - em_bits;
        if unused_bits != 0 {
            bad_padding |= masked_db[0] >> (8 - unused_bits);
        }

        let db_mask = mgf1::<H>(&h, h_index);
        for (byte, mask) in masked_db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }
        if unused_bits != 0 {
            masked_db[0] &= 0xff_u8 >> unused_bits;
        }

        let mut saw_separator = 0u8;
        let mut one_index = 0usize;
        for (idx, &byte) in masked_db.iter().enumerate() {
            let is_zero = u8::from(byte == 0);
            let is_one = u8::from(byte == 0x01);
            let before_separator = saw_separator ^ 1;
            bad_padding |= before_separator & (is_zero ^ 1) & (is_one ^ 1);

            let take_separator = before_separator & is_one;
            let mask = 0usize.wrapping_sub(usize::from(take_separator));
            one_index = (one_index & !mask) | (idx & mask);
            saw_separator |= take_separator;
        }
        bad_padding |= saw_separator ^ 1;
        if bad_padding != 0 {
            return false;
        }
        let salt = &masked_db[one_index + 1..];

        let m_hash = H::digest(message);
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&m_hash);
        m_prime.extend_from_slice(salt);
        let expected_h = H::digest(&m_prime);
        crate::ct::constant_time_eq(&h, &expected_h)
    }
}

#[cfg(test)]
mod tests {
    use super::{RsaOaep, RsaPss};
    use crate::public_key::bigint::BigUint;
    use crate::public_key::rsa::Rsa;
    use crate::Sha1;

    fn large_reference_key() -> (crate::RsaPublicKey, crate::RsaPrivateKey) {
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
    fn pss_sign_and_verify() {
        let (public, private) = large_reference_key();
        let salt = [0x33u8; 8];
        let signature = RsaPss::<Sha1>::sign(&private, b"abc", &salt).expect("message fits");
        assert!(RsaPss::<Sha1>::verify(&public, b"abc", &signature));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abd", &signature));
    }
}
