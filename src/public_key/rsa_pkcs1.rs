//! PKCS #1 v2.2 wrappers for the raw RSA primitive.
//!
//! The raw [`Rsa`](crate::vt::Rsa) type intentionally exposes only the trapdoor
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
use crate::zeroize_slice;
use crate::Csprng;
use rump::BigUint;

// RFC 8017's `k`: the octet length of the RSA modulus `n`.
fn modulus_len_bytes(modulus: &BigUint) -> usize {
    modulus.bits().div_ceil(8)
}

/// RFC 8017 B.2.1 MGF1: `T = Hash(mgfSeed ‖ C₀) ‖ Hash(mgfSeed ‖ C₁) ‖ …`
/// with `C` the four-octet big-endian counter, truncated to `maskLen`
/// octets. Step 1 puts a ceiling on the mask, `maskLen ≤ 2^32 · hLen`, so
/// that the counter never exceeds four octets; a longer request is the
/// "mask too long" error and returns `None`.
fn mgf1<H: Digest>(seed: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let h_len = H::OUTPUT_LEN;
    // Step 3 runs the counter from 0 to ⌈maskLen / hLen⌉ − 1; step 1's bound
    // is exactly the condition that the last counter value fits in u32.
    let blocks = out_len.div_ceil(h_len);
    if let Some(last) = blocks.checked_sub(1) {
        u32::try_from(last).ok()?;
    }
    let mut out = Vec::with_capacity(out_len);
    for counter in 0..blocks {
        let counter = u32::try_from(counter).ok()?;
        let mut digest_input = Vec::with_capacity(seed.len() + 4);
        digest_input.extend_from_slice(seed);
        digest_input.extend_from_slice(&counter.to_be_bytes());
        let mut block = H::digest(&digest_input);
        let take = (out_len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        // The seed is OAEP's secret randomness (or a PSS hash); neither the
        // hash input nor the surplus mask bytes may linger.
        zeroize_slice(digest_input.as_mut_slice());
        zeroize_slice(block.as_mut_slice());
    }
    Some(out)
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

/// `0xff` when `a == b`, `0x00` otherwise, with no branch and no fallible
/// conversion: `a ^ b` is widened to 16 bits so that subtracting one borrows
/// into bit 8 exactly when it was zero; that bit, negated in two's
/// complement, is the 16-bit mask, whose low byte is returned.
#[inline]
fn ct_eq_u8_mask(a: u8, b: u8) -> u8 {
    let x = u16::from(a ^ b);
    let is_zero = (x.wrapping_sub(1) >> 8) & 1;
    let [low, _] = 0u16.wrapping_sub(is_zero).to_le_bytes();
    low
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
        let mut db_mask = mgf1::<H>(seed, k - h_len - 1)?;
        let mut masked_db = db;
        for (byte, mask) in masked_db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }

        let mut seed_mask = mgf1::<H>(&masked_db, h_len)?;
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
        // The encoded message EM and its halves are as secret as the
        // plaintext (each half unmasks the other); wipe them before they
        // are freed. `encoded_int` is a BigUint, which rump wipes.
        for buffer in [
            &mut encoded,
            &mut masked_seed,
            &mut masked_db,
            &mut seed_mask,
            &mut db_mask,
        ] {
            zeroize_slice(buffer.as_mut_slice());
        }
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
        let ciphertext = Self::encrypt(public, label, message, &seed);
        zeroize_slice(seed.as_mut_slice());
        ciphertext
    }

    /// Decrypt one `RSAES-OAEP` ciphertext.
    ///
    /// The RSA private operation here is **unblinded**. Prefer
    /// [`Self::decrypt_rng`] when a CSPRNG is available so the variable-time
    /// bigint stack never sees the raw attacker-chosen ciphertext.
    #[must_use]
    pub fn decrypt(private: &RsaPrivateKey, label: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        let ciphertext_int = Self::oaep_ciphertext_representative(private, k, ciphertext)?;
        let encoded_int = private.decrypt_raw(&ciphertext_int);
        Self::oaep_decode(label, k, &encoded_int)
    }

    /// RFC 8017 §7.1.2 steps 1 and 2a: the ciphertext must be exactly `k`
    /// octets, the key large enough for the hash, and the representative
    /// `c = OS2IP(C)` must satisfy `0 ≤ c < n` (RSADP, §5.1.2 step 1) before
    /// the private operation runs.
    fn oaep_ciphertext_representative(
        private: &RsaPrivateKey,
        k: usize,
        ciphertext: &[u8],
    ) -> Option<BigUint> {
        if ciphertext.len() != k || k < 2 * H::OUTPUT_LEN + 2 {
            return None;
        }
        let ciphertext_int = os2ip(ciphertext);
        if &ciphertext_int >= private.modulus() {
            return None;
        }
        Some(ciphertext_int)
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
        let ciphertext_int = Self::oaep_ciphertext_representative(private, k, ciphertext)?;
        let encoded_int = private.decrypt_raw_blinded(&ciphertext_int, rng);
        Self::oaep_decode(label, k, &encoded_int)
    }

    /// RFC 8017 §7.1.2 step 3, EME-OAEP decoding of the recovered integer,
    /// shared by the blinded and unblinded decrypt paths. Step 3g's three
    /// conditions — no `0x01` separator, `lHash′ ≠ lHash`, `Y ≠ 0` — are
    /// folded into one mask over a full scan of `DB`, so that, as the note
    /// under step 3g requires, which of them failed is not distinguishable
    /// by timing (Manger's attack).
    fn oaep_decode(label: &[u8], k: usize, encoded_int: &BigUint) -> Option<Vec<u8>> {
        let h_len = H::OUTPUT_LEN;
        // Always `Some`: raw RSA decryption returns a value in `[0, n)`, and
        // the modulus occupies exactly `k` bytes.
        let mut encoded = i2osp(encoded_int, k)?;

        // Step 3b: EM = Y ‖ maskedSeed ‖ maskedDB. Y is read here, before the
        // encoded message is wiped, and folded into the mask below.
        let y_nonzero = ct_nonzero_u8_mask(encoded[0]);
        let (masked_seed, masked_db) = encoded[1..].split_at(h_len);
        // Steps 3c–3d.
        let mut seed_mask = mgf1::<H>(masked_db, h_len)?;
        let mut seed = masked_seed.to_vec();
        for (byte, mask) in seed.iter_mut().zip(seed_mask.iter()) {
            *byte ^= *mask;
        }

        // Steps 3e–3f.
        let mut db_mask = mgf1::<H>(&seed, k - h_len - 1)?;
        let mut db = masked_db.to_vec();
        for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }
        // Only the recovered message leaves this function; the encoded
        // message, seed, masks and data block are wiped on every path.
        zeroize_slice(encoded.as_mut_slice());
        zeroize_slice(seed.as_mut_slice());
        zeroize_slice(seed_mask.as_mut_slice());
        zeroize_slice(db_mask.as_mut_slice());

        // Step 3g: DB = lHash′ ‖ PS ‖ 0x01 ‖ M.
        let l_hash = H::digest(label);
        let mut saw_separator = 0u8;
        let mut bad_padding = y_nonzero;
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

        let message = if saw_separator == u8::MAX && bad_padding == 0 {
            Some(db[msg_idx..].to_vec())
        } else {
            None
        };
        zeroize_slice(db.as_mut_slice());
        message
    }
}

/// RFC 8017 `RSASSA-PSS`.
///
/// The salt length `sLen` is a parameter of the scheme (RFC 8017 §8.1, §9.1:
/// an option of EMSA-PSS, fixed for a given key by its `RSASSA-PSS-params`).
/// The signer states it through the salt it supplies, or through `salt_len`
/// on the random-salt path, and the verifier states it through `salt_len`:
/// EMSA-PSS-VERIFY step 10 checks that the encoded message carries exactly
/// that many salt octets, so a signature made with another salt length does
/// not verify.
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
        // §9.1.1 step 3.
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

        let db_mask = mgf1::<H>(&h, em_len - h_len - 1)?;
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

    /// Sign one message using `RSASSA-PSS` with the given salt; its length
    /// is the scheme's `sLen`, which the verifier must be given.
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

    /// Sign one message using `RSASSA-PSS` with a fresh random salt of
    /// `salt_len` octets and CSPRNG-driven ciphertext blinding on the RSA
    /// private operation.
    ///
    /// `salt_len` is the scheme's `sLen`; `H::OUTPUT_LEN` is the usual
    /// choice (RFC 8017 §8.1 and RFC 4055 §3.1 recommend `sLen = hLen`), and
    /// the verifier must be given the same value. The deterministic
    /// `sign(..., salt)` variant remains for fixed-vector testing; this is
    /// the production signing path (fresh salt + blinding).
    #[must_use]
    pub fn sign_rng<R: Csprng>(
        private: &RsaPrivateKey,
        message: &[u8],
        salt_len: usize,
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let k = modulus_len_bytes(private.modulus());
        let mut salt = vec![0u8; salt_len];
        rng.fill_bytes(&mut salt);
        let encoded_int = Self::pss_encode(private, message, &salt);
        zeroize_slice(salt.as_mut_slice());
        let signature_int = private.decrypt_raw_blinded(&encoded_int?, rng);
        i2osp(&signature_int, k)
    }

    /// Verify one `RSASSA-PSS` signature made with a salt of `salt_len`
    /// octets (RFC 8017 §8.1.2, with EMSA-PSS-VERIFY of §9.1.2).
    ///
    /// Every check of §9.1.2 is applied — the `0xbc` trailer (step 4), the
    /// zero high bits of `maskedDB` (step 6), the `emLen − hLen − sLen − 2`
    /// zero octets and the `0x01` separator (step 10), and `H = H′`
    /// (step 14) — and they are accumulated into one mask over the whole
    /// encoded message rather than reported one at a time.
    #[must_use]
    pub fn verify(
        public: &RsaPublicKey,
        message: &[u8],
        signature: &[u8],
        salt_len: usize,
    ) -> bool {
        let k = modulus_len_bytes(public.modulus());
        let em_bits = public.modulus().bits().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let h_len = H::OUTPUT_LEN;
        // §8.1.2 step 1 and §9.1.2 step 3.
        if signature.len() != k || em_len < h_len + salt_len + 2 {
            return false;
        }

        let signature_int = os2ip(signature);
        // RFC 8017 §8.1.2 step 2a / RSAVP1 (§5.2.2 step 1): the signature
        // representative must satisfy 0 ≤ s < n.
        if &signature_int >= public.modulus() {
            return false;
        }
        let encoded_int = public.encrypt_raw(&signature_int);
        // Always `Some`: raw RSA encryption returns a value in `[0, n)`, and
        // the modulus is chosen so that the encoded message fits into `em_len`.
        let Some(mut encoded) = i2osp(&encoded_int, em_len) else {
            return false;
        };
        // Step 4.
        let mut bad_padding = ct_eq_u8_mask(encoded.last().copied().unwrap_or(0), 0xbc) ^ u8::MAX;

        // Step 5.
        let h_index = em_len - h_len - 1;
        let h = encoded[h_index..h_index + h_len].to_vec();
        let masked_db = &mut encoded[..h_index];
        let unused_bits = (8 * em_len) - em_bits;
        // Step 6 checks the unused top bits in `maskedDB` before the MGF1
        // mask is removed.
        if unused_bits != 0 {
            bad_padding |= ct_nonzero_u8_mask(masked_db[0] >> (8 - unused_bits));
        }

        // Steps 7–9.
        let Some(db_mask) = mgf1::<H>(&h, h_index) else {
            return false;
        };
        for (byte, mask) in masked_db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }
        if unused_bits != 0 {
            masked_db[0] &= 0xff_u8 >> unused_bits;
        }
        let db = masked_db;

        // Step 10: DB = PS ‖ 0x01 ‖ salt with PS the leftmost
        // emLen − hLen − sLen − 2 octets, all zero. The separator's position
        // follows from `sLen`; it is not searched for. Every octet of PS is
        // examined, so a malformed encoding takes the same path as a good one.
        let separator = em_len - h_len - salt_len - 2;
        for &byte in &db[..separator] {
            bad_padding |= ct_nonzero_u8_mask(byte);
        }
        bad_padding |= ct_eq_u8_mask(db[separator], 0x01) ^ u8::MAX;
        // Step 11.
        let salt = &db[separator + 1..];

        // Steps 12–14.
        let m_hash = H::digest(message);
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&m_hash);
        m_prime.extend_from_slice(salt);
        let expected_h = H::digest(&m_prime);
        bad_padding |= crate::ct::constant_time_eq_mask(&h, &expected_h) ^ u8::MAX;
        bad_padding == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{i2osp, mgf1, os2ip};
    use super::{RsaOaep, RsaPss};
    use crate::public_key::rsa::{Rsa, RsaPrivateKey, RsaPublicKey};
    use crate::test_utils::decode_hex;
    use crate::{CtrDrbgAes256, Sha1, Sha512};
    use rump::BigUint;

    /// Not a published vector. p = 2^184 + 27 is the smallest prime above
    /// 2^184 and q = 2^184 + 277 is another prime just above it, chosen so the
    /// modulus is wide enough for OAEP and PSS encodings. The tests that use
    /// this key check round trips and the RFC 8017 encoding rules, not known
    /// answers.
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

    /// RFC 8017 §5.1.2 / §5.2.2: a representative at or above `n` is "out of
    /// range" and must be rejected before any RSA operation, even when its
    /// octet string has the right length `k`.
    #[test]
    fn oaep_and_pss_reject_representatives_at_or_above_modulus() {
        let (public, private) = large_reference_key();
        let k = public.modulus().bits().div_ceil(8);
        let n_bytes = public.modulus().to_be_bytes_padded(k);
        let mut above = public.modulus().add(&BigUint::one()).to_be_bytes_padded(k);
        assert_eq!(n_bytes.len(), k);
        assert!(RsaOaep::<Sha1>::decrypt(&private, b"", &n_bytes).is_none());
        assert!(RsaOaep::<Sha1>::decrypt(&private, b"", &above).is_none());
        let mut drbg = CtrDrbgAes256::new(&[0x23; 48]);
        assert!(RsaOaep::<Sha1>::decrypt_rng(&private, b"", &n_bytes, &mut drbg).is_none());
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &n_bytes, 20));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &above, 20));
        // An all-ones string of the right length is the largest such value.
        above.fill(0xff);
        assert!(RsaOaep::<Sha1>::decrypt(&private, b"", &above).is_none());
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &above, 20));
    }

    /// RFC 8017 §9.1.2 takes `sLen` as an input: the signature verifies with
    /// the salt length it was made with and with no other, because step 10
    /// fixes where the `0x01` separator must sit.
    #[test]
    fn pss_sign_and_verify() {
        let (public, private) = large_reference_key();
        let salt = [0x33u8; 8];
        let signature = RsaPss::<Sha1>::sign(&private, b"abc", &salt).expect("message fits");
        assert!(RsaPss::<Sha1>::verify(&public, b"abc", &signature, 8));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abd", &signature, 8));
        for other_len in [0usize, 7, 9, 20, 24] {
            assert!(
                !RsaPss::<Sha1>::verify(&public, b"abc", &signature, other_len),
                "sLen = {other_len}"
            );
        }
    }

    /// §9.1.1 step 3 and §9.1.2 step 3: `emLen ≥ hLen + sLen + 2`. The
    /// 368-bit key has `emLen = 46` and SHA-1 `hLen = 20`, so `sLen ≤ 24`.
    #[test]
    fn pss_rejects_bad_lengths() {
        let (public, private) = large_reference_key();
        assert!(RsaPss::<Sha1>::sign(&private, b"abc", &[0x44; 25]).is_none());
        let signature = RsaPss::<Sha1>::sign(&private, b"abc", &[0x44; 24]).expect("sLen = 24");
        assert!(RsaPss::<Sha1>::verify(&public, b"abc", &signature, 24));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &signature, 25));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &[0u8; 3], 20));
    }

    /// RFC 8017 B.2.1 step 1: `maskLen > 2^32 · hLen` is "mask too long".
    /// SHA-1 has `hLen = 20`; the bound itself is accepted, one more octet
    /// is refused before anything is allocated.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn mgf1_refuses_a_mask_longer_than_the_counter_allows() {
        let bound = (1usize << 32) * 20;
        assert!(mgf1::<Sha1>(b"seed", bound + 1).is_none());
        // At `maskLen = bound` the last counter value is 2^32 − 1, which
        // fits; the mask itself is 80 GiB, so only the length arithmetic
        // is exercised here, through a mask one block long.
        assert_eq!(mgf1::<Sha1>(b"seed", 20).map(|m| m.len()), Some(20));
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
        let signature = RsaPss::<Sha1>::sign_rng(&private, b"abc", 20, &mut drbg).expect("PSS");
        assert!(RsaPss::<Sha1>::verify(&public, b"abc", &signature, 20));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &signature, 19));
        assert!(!RsaPss::<Sha1>::verify(&public, b"abc", &signature, 21));
    }

    /// The blinded decrypt path (`decrypt_raw_blinded` under OAEP) recovers
    /// the plaintext from ciphertexts made both ways, and refuses a
    /// representative at or above `n` (RFC 8017 §7.1.2 step 2b).
    #[test]
    fn oaep_decrypt_rng_roundtrip() {
        let (public, private) = large_reference_key();
        let mut drbg = CtrDrbgAes256::new(&[0x24; 48]);
        let fixed = RsaOaep::<Sha1>::encrypt(&public, b"label", b"hello", &[0x42u8; 20])
            .expect("message fits");
        let random = RsaOaep::<Sha1>::encrypt_rng(&public, b"label", b"hello", &mut drbg)
            .expect("message fits");
        assert_eq!(
            RsaOaep::<Sha1>::decrypt_rng(&private, b"label", &fixed, &mut drbg).as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(
            RsaOaep::<Sha1>::decrypt_rng(&private, b"label", &random, &mut drbg).as_deref(),
            Some(&b"hello"[..])
        );
        assert!(RsaOaep::<Sha1>::decrypt_rng(&private, b"other", &fixed, &mut drbg).is_none());
        let k = public.modulus().bits().div_ceil(8);
        let n_bytes = public.modulus().to_be_bytes_padded(k);
        assert!(RsaOaep::<Sha1>::decrypt_rng(&private, b"label", &n_bytes, &mut drbg).is_none());
    }

    /// An edit to the unmasked OAEP parts `(Y, DB)` before masking.
    type Tamper = Box<dyn FnOnce(&mut u8, &mut Vec<u8>)>;

    /// RFC 8017 §7.1.1 encoding with the unmasked parts exposed to `tamper`
    /// before masking, then the raw public operation of §7.1.1 step 3. With
    /// no tampering this is exactly `RsaOaep::encrypt`.
    fn oaep_ciphertext_with(
        public: &RsaPublicKey,
        label: &[u8],
        message: &[u8],
        seed: &[u8; 20],
        tamper: impl FnOnce(&mut u8, &mut Vec<u8>),
    ) -> Vec<u8> {
        let h_len = 20;
        let k = public.modulus().bits().div_ceil(8);
        let mut db = Sha1::digest(label).to_vec();
        db.resize(k - h_len - message.len() - 2, 0);
        db.push(0x01);
        db.extend_from_slice(message);
        let mut y = 0u8;
        tamper(&mut y, &mut db);

        let db_mask = mgf1::<Sha1>(seed, k - h_len - 1).expect("mask length");
        let masked_db: Vec<u8> = db.iter().zip(&db_mask).map(|(b, m)| b ^ m).collect();
        let seed_mask = mgf1::<Sha1>(&masked_db, h_len).expect("mask length");
        let masked_seed: Vec<u8> = seed.iter().zip(&seed_mask).map(|(b, m)| b ^ m).collect();
        let mut encoded = vec![y];
        encoded.extend_from_slice(&masked_seed);
        encoded.extend_from_slice(&masked_db);
        i2osp(&public.encrypt_raw(&os2ip(&encoded)), k).expect("fits in k octets")
    }

    /// RFC 8017 §7.1.2 step 3g, through the public API on a key whose
    /// modulus is a whole number of octets (384 bits, so `k = 48` and a
    /// nonzero `Y` still leaves `EM < n`): each of the three conditions —
    /// `Y ≠ 0`, `lHash′ ≠ lHash`, no `0x01` separator (a nonzero octet in PS
    /// counts) — is a decryption error on both the unblinded and the blinded
    /// path, and the untampered control decrypts.
    #[test]
    fn oaep_decrypt_rejects_each_step_3g_condition() {
        let (public, private) = full_width_key();
        assert_eq!(public.modulus().bits() % 8, 0);
        let seed = [0x5eu8; 20];
        let h_len = 20;
        let message = b"hi";

        let control = oaep_ciphertext_with(&public, b"label", message, &seed, |_, _| {});
        assert_eq!(
            control,
            RsaOaep::<Sha1>::encrypt(&public, b"label", message, &seed).expect("fits")
        );
        assert_eq!(
            RsaOaep::<Sha1>::decrypt(&private, b"label", &control).as_deref(),
            Some(&message[..])
        );

        // The first 0x01 after lHash is the separator, so a 0x01 written
        // into PS is not tampering: it is the valid encoding of a longer
        // message whose first octets are the rest of PS.
        let longer = oaep_ciphertext_with(&public, b"label", message, &seed, |_, db| {
            db[h_len] = 0x01;
        });
        assert_eq!(
            RsaOaep::<Sha1>::decrypt(&private, b"label", &longer).as_deref(),
            Some(&[0x00, 0x00, 0x00, 0x01, b'h', b'i'][..])
        );

        let tampered: [(&str, Tamper); 4] = [
            ("nonzero Y", Box::new(|y, _| *y = 0x01)),
            ("flipped lHash octet", Box::new(|_, db| db[0] ^= 0x80)),
            ("nonzero PS octet", Box::new(move |_, db| db[h_len] = 0x02)),
            (
                "separator cleared",
                Box::new(move |_, db| {
                    let separator = db.len() - message.len() - 1;
                    assert_eq!(db[separator], 0x01);
                    db[separator] = 0x00;
                }),
            ),
        ];
        for (what, tamper) in tampered {
            let ciphertext = oaep_ciphertext_with(&public, b"label", message, &seed, tamper);
            assert_ne!(ciphertext, control, "{what}");
            assert!(
                RsaOaep::<Sha1>::decrypt(&private, b"label", &ciphertext).is_none(),
                "{what}"
            );
            let mut drbg = CtrDrbgAes256::new(&[0x25; 48]);
            assert!(
                RsaOaep::<Sha1>::decrypt_rng(&private, b"label", &ciphertext, &mut drbg).is_none(),
                "{what}"
            );
        }
    }

    /// Not a published vector. p = 2^192 − 237 and q = 2^192 − 333 are the
    /// two largest primes below 2^192, so `n` is 384 bits with its top 192
    /// bits all set but the last ten: an encoded message with its top bit
    /// set is still below `n`, which lets the §9.1.2 step 6 check be
    /// exercised on its own.
    fn full_width_key() -> (RsaPublicKey, RsaPrivateKey) {
        let mut top = BigUint::one();
        top.shl_bits(192);
        let p = top.sub(&BigUint::from_u64(237));
        let q = top.sub(&BigUint::from_u64(333));
        Rsa::from_primes(&p, &q).expect("valid full-width RSA key")
    }

    /// RFC 8017 §9.1.1 EMSA-PSS-ENCODE as an octet string of `emLen`.
    fn pss_encoded_message(private: &RsaPrivateKey, message: &[u8], salt: &[u8]) -> Vec<u8> {
        let em_len = (private.modulus().bits() - 1).div_ceil(8);
        let em = RsaPss::<Sha1>::pss_encode(private, message, salt).expect("message fits");
        i2osp(&em, em_len).expect("fits in emLen octets")
    }

    /// RFC 8017 §8.1.1 steps 2–3 on an already encoded message: `s = EM^d`.
    fn pss_signature_of(private: &RsaPrivateKey, encoded: &[u8]) -> Vec<u8> {
        let k = private.modulus().bits().div_ceil(8);
        i2osp(&private.decrypt_raw(&os2ip(encoded)), k).expect("fits in k octets")
    }

    /// RFC 8017 §9.1.2 steps 4, 6 and 10 each refuse a tampered encoding:
    /// the trailer, the unused high bits of `maskedDB`, a nonzero octet in
    /// PS, and a separator that is not `0x01`. The control verifies.
    #[test]
    fn pss_verify_rejects_trailer_top_bits_and_separator_tampering() {
        let (public, private) = full_width_key();
        assert_eq!(public.modulus().bits(), 384);
        let salt = [0x6au8; 20];
        let h_len = 20;
        let em_len = 48;
        let encoded = pss_encoded_message(&private, b"abc", &salt);
        assert_eq!(encoded.len(), em_len);
        assert!(RsaPss::<Sha1>::verify(
            &public,
            b"abc",
            &pss_signature_of(&private, &encoded),
            20
        ));

        // Step 4: trailer.
        let mut trailer = encoded.clone();
        trailer[em_len - 1] = 0xbd;
        assert!(!RsaPss::<Sha1>::verify(
            &public,
            b"abc",
            &pss_signature_of(&private, &trailer),
            20
        ));

        // Step 6: emBits = 383, so one unused high bit in maskedDB[0].
        let mut top_bit = encoded.clone();
        assert_eq!(top_bit[0] & 0x80, 0);
        top_bit[0] |= 0x80;
        assert!(os2ip(&top_bit) < *public.modulus());
        assert!(!RsaPss::<Sha1>::verify(
            &public,
            b"abc",
            &pss_signature_of(&private, &top_bit),
            20
        ));

        // Step 10: unmask DB, corrupt it, mask it again so the hash H and
        // therefore dbMask are unchanged.
        let h_index = em_len - h_len - 1;
        let db_mask = mgf1::<Sha1>(&encoded[h_index..h_index + h_len], h_index).expect("mask");
        let mut db: Vec<u8> = encoded[..h_index]
            .iter()
            .zip(&db_mask)
            .map(|(b, m)| b ^ m)
            .collect();
        db[0] &= 0x7f;
        let separator = em_len - h_len - 20 - 2;
        assert_eq!(db[separator], 0x01);
        assert!(db[..separator].iter().all(|&b| b == 0));
        let remask = |db: &[u8]| -> Vec<u8> {
            let mut em: Vec<u8> = db.iter().zip(&db_mask).map(|(b, m)| b ^ m).collect();
            em[0] &= 0x7f;
            em.extend_from_slice(&encoded[h_index..]);
            em
        };
        assert_eq!(remask(&db), encoded);
        for (what, index, value) in [
            ("separator cleared", separator, 0x00u8),
            ("separator replaced", separator, 0x02),
            ("nonzero PS octet", 1, 0x01),
            ("nonzero first PS octet", 0, 0x40),
        ] {
            let mut bad = db.clone();
            bad[index] = value;
            let signature = pss_signature_of(&private, &remask(&bad));
            assert!(
                !RsaPss::<Sha1>::verify(&public, b"abc", &signature, 20),
                "{what}"
            );
        }
    }

    #[test]
    fn nist_cavp_pss_sigver_sha1_vector_passes() {
        // NIST CAVP, SigVerPSS_186-3.rsp:
        //   [mod = 1024], SHAAlg = SHA1, Result = P
        let n = BigUint::from_be_bytes(&decode_hex(
            "ec996bc93e81094436fd5fc2eef511782eb40fe60cc6f27f24bc8728d686537f\
             1caa82cfcfa5c323604b6918d7cd0318d98395c855c7c7ada6fc447f192283cdc\
             81e7291e232336019d4dac12356b93a349883cd2c0a7d2eae9715f1cc6dd657ce\
             a5cb2c46ce6468794b326b33f1bff61a00fa72931345ca6768365e1eb906dd",
        ));
        let e = BigUint::from_be_bytes(&decode_hex("90c6d3"));
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
        // The vector's SaltVal is 20 octets: sLen = hLen.
        assert!(RsaPss::<Sha1>::verify(&public, &msg, &signature, 20));
        assert!(!RsaPss::<Sha1>::verify(&public, &msg, &signature, 19));
        assert!(!RsaPss::<Sha1>::verify(&public, &msg, &signature, 21));
        assert!(!RsaPss::<Sha1>::verify(&public, &msg, &signature, 0));
    }

    #[test]
    fn nist_acvp_kts_oaep_sha512_decrypt_vector_matches_plaintext() {
        // NIST ACVP sample vectors:
        //   KTS-IFC (SP800-56Br2), scheme KTS-OAEP-Party_V-confirmation,
        //   noKdfKc, tgId=1, tcId=1.
        //
        // In this profile, ktsParameter is empty and kasMode=noKdfKc, so
        // decrypted OAEP plaintext equals iutK directly (126 bytes).
        let p = BigUint::from_be_bytes(&decode_hex(
            "FFC4F61CF26222F2174A525AE0ED01A1E075215D4111F1AF0153EFC595FE4DD1\
             0CB795A2CEB5C84AC44D62CA50BD170503924B27ED4EB09467C4D1BBADE73F79\
             14A318F7F304342C9D0FACF1A55974D20E9DACD578627425AE88A702E2655A71\
             3E0823C59025A3AF67C48962745E1C0FC7B32007597E813868A91C96B49BF127",
        ));
        let q = BigUint::from_be_bytes(&decode_hex(
            "EB385875212FF27BF89C38ACC52B86DA0AF8EA779DA30D153F40A375BE116791\
             4DCA207C241653B030671FF700C0714A6CCFDDC0C25F430CB47C8C74DF22E318\
             93396C3676F3A9E7B9ACD6E0AFC292CBB48298A22AFBCABA01966FCDFE0C5D06\
             48CFB9938C26CD047107BC8C1945A2244A8B813C292CE74CCCF95D43F71BEF75",
        ));
        let e = BigUint::from_be_bytes(&decode_hex("03DA3A5B37"));
        let expected_n = BigUint::from_be_bytes(&decode_hex(
            "EB021963239BD53F5A6F292232E0A91F342350CC3266C9DECB773E2D5CF27E82\
             6A95DB350FC2EA88CCA3326E5723DCDA9460C5E2A16F7DF3BB12DBB4C2479D4F\
             7FEBA15B48AC09510E0838F08AD7C37235B10A0DE1A405E578E6213B00341E26\
             F7FE13D4164AACC5FD14DFAA805C7D49FCC39CFBC8F1D2C37EB172B14EE50E5E\
             213E2DF280C4FB5816E84956F4E14DE26EFAF29338CA7DCD532FC85CDF460D30\
             79099EC42D0E71175A2FCDC0CCF084492D6D39A0D99CFDD11FD509BB656A9A6C\
             E142FC09768C109CA67241208217B25CFEE41A8A7BCBDDD6F0EF325B073DDE20\
             E508F680170EA9D4F3F2DBE1424510ECD3488842D023E063B17C8DD231859FD3",
        ));
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
