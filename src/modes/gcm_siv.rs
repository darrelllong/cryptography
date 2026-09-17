//! AES-GCM-SIV (RFC 8452).
//!
//! [`AesGcmSiv<C>`] is RFC 8452 over an AES implementation `C`, with 96-bit
//! nonces and 16-byte detached tags. RFC 8452 §4 defines the mode for AES-128
//! and AES-256 only, and this crate has two implementations of each, so `C`
//! is one of four types, named by the aliases [`Aes128GcmSiv`],
//! [`Aes256GcmSiv`], [`Aes128GcmSivCt`] and [`Aes256GcmSivCt`].
//!
//! # Nonce reuse
//!
//! GCM-SIV is misuse-resistant: encryption is deterministic, so repeating a
//! nonce under the same key only reveals whether two messages are identical.
//! It does not leak plaintext contents or the authentication key. Unique
//! nonces are still preferred.

use super::ghash::polyval;
use crate::{Aes128, Aes128Ct, Aes256, Aes256Ct, BlockCipher};

mod sealed {
    pub trait Sealed {}
}

/// An AES instance AES-GCM-SIV runs over.
///
/// RFC 8452 §4 takes a key-generating key of 16 bytes (AES-128) or 32 bytes
/// (AES-256), derives a message-encryption key of the same size, and uses AES
/// of that size for both the derivation and the encryption. `KEY_LEN` selects
/// the profile and `Key` is the array type of the key-generating key. The
/// trait is sealed: it is implemented for [`Aes128`], [`Aes256`], [`Aes128Ct`]
/// and [`Aes256Ct`], the four AES types RFC 8452 covers.
pub trait GcmSivBlockCipher: BlockCipher + sealed::Sealed {
    /// The key array: `[u8; 16]` for AES-128, `[u8; 32]` for AES-256.
    type Key;

    /// Key length in bytes, 16 or 32.
    const KEY_LEN: usize;

    /// Expand a key-generating key.
    fn from_key(key: &Self::Key) -> Self;

    /// Expand the `KEY_LEN`-byte message-encryption key RFC 8452 §4 derives.
    ///
    /// # Panics
    ///
    /// Panics if `key.len() != KEY_LEN`.
    fn from_derived_key(key: &[u8]) -> Self;
}

macro_rules! impl_gcm_siv_block_cipher {
    ($Cipher:ty, $key_len:literal) => {
        impl sealed::Sealed for $Cipher {}

        impl GcmSivBlockCipher for $Cipher {
            type Key = [u8; $key_len];
            const KEY_LEN: usize = $key_len;

            fn from_key(key: &Self::Key) -> Self {
                Self::new(key)
            }

            fn from_derived_key(key: &[u8]) -> Self {
                let key: &[u8; $key_len] = key
                    .try_into()
                    .expect("derived key length is the profile's key length");
                Self::new(key)
            }
        }
    };
}

impl_gcm_siv_block_cipher!(Aes128, 16);
impl_gcm_siv_block_cipher!(Aes256, 32);
impl_gcm_siv_block_cipher!(Aes128Ct, 16);
impl_gcm_siv_block_cipher!(Aes256Ct, 32);

/// POLYVAL block length, in bytes (RFC 8452 §3: 16-octet field elements).
const BLOCK_BYTES: usize = 16;

/// The two little-endian 64-bit bit-lengths that close the POLYVAL input
/// (RFC 8452 §4).
const LENGTH_FIELD_BYTES: usize = 2 * 8;

/// Zeros to the next multiple of a block, and none when the length already is
/// one (RFC 8452 §4's `pad`).
const fn padding(len: usize) -> usize {
    (BLOCK_BYTES - (len % BLOCK_BYTES)) % BLOCK_BYTES
}

#[inline]
fn pad16(input: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(input);
    out.resize(out.len() + padding(input.len()), 0);
}

/// The POLYVAL input `pad(AAD) || pad(plaintext) || len(AAD) || len(plaintext)`
/// of RFC 8452 §4, lengths in bits, little-endian.
///
/// The capacity is exact, so building it never reallocates and abandons a
/// partial copy of the plaintext; the caller wipes the result.
fn gcm_siv_s_input(aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        aad.len()
            + padding(aad.len())
            + plaintext.len()
            + padding(plaintext.len())
            + LENGTH_FIELD_BYTES,
    );
    pad16(aad, &mut out);
    pad16(plaintext, &mut out);
    out.extend_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
    out.extend_from_slice(&((plaintext.len() as u64) * 8).to_le_bytes());
    out
}

#[inline]
fn increment_le32(block: &mut [u8; 16]) {
    let mut ctr = u32::from_le_bytes(block[..4].try_into().expect("4 bytes"));
    ctr = ctr.wrapping_add(1);
    block[..4].copy_from_slice(&ctr.to_le_bytes());
}

/// RFC 8452 §6 length limits, checked before any plaintext is produced so a
/// panic never unwinds past an unwiped buffer.
fn assert_gcm_siv_lengths(aad_len: usize, text_len: usize) {
    // Compare as u64 so the `1 << 36` constant does not overflow `usize` on
    // 32-bit targets (where it would be a compile-time error). On such targets
    // the RFC 8452 limit is unreachable anyway since `len` maxes out at 2^32-1.
    assert!(aad_len as u64 <= (1u64 << 36), "AAD exceeds RFC 8452 limit");
    assert!(
        text_len as u64 <= (1u64 << 36),
        "plaintext exceeds RFC 8452 limit"
    );
}

/// RFC 8452 §4 key derivation into caller-owned buffers: `auth_key` receives
/// the POLYVAL key and `enc_key` (16 or 32 bytes) the message-encryption key.
///
/// Each key-generating output block contributes its first eight bytes; the
/// block buffer is wiped before returning.
fn derive_key_bytes<C: BlockCipher>(
    keygen: &C,
    nonce: &[u8; 12],
    auth_key: &mut [u8; 16],
    enc_key: &mut [u8],
) {
    debug_assert!(enc_key.len() == 16 || enc_key.len() == 32);
    let mut block = [0u8; 16];
    for i in 0..2 + enc_key.len() / 8 {
        let i_u32 = u32::try_from(i).expect("counter fits u32");
        block[..4].copy_from_slice(&i_u32.to_le_bytes());
        block[4..].copy_from_slice(nonce);
        keygen.encrypt(&mut block);
        if i < 2 {
            auth_key[8 * i..8 * i + 8].copy_from_slice(&block[..8]);
        } else {
            enc_key[8 * (i - 2)..8 * (i - 2) + 8].copy_from_slice(&block[..8]);
        }
    }
    crate::ct::zeroize_slice(block.as_mut_slice());
}

/// The per-nonce keys RFC 8452 §4 derives from the key-generating key: the
/// POLYVAL authentication key and the message-encryption AES instance.
///
/// The AES instance wipes its own schedule on drop; the authentication key is
/// wiped by this type's `Drop`.
struct NonceKeys<C> {
    auth_key: [u8; 16],
    enc: C,
}

impl<C: GcmSivBlockCipher> NonceKeys<C> {
    fn derive(keygen: &C, nonce: &[u8; 12]) -> Self {
        let mut auth_key = [0u8; 16];
        let mut enc_key = [0u8; 32];
        derive_key_bytes(keygen, nonce, &mut auth_key, &mut enc_key[..C::KEY_LEN]);
        let enc = C::from_derived_key(&enc_key[..C::KEY_LEN]);
        let keys = Self { auth_key, enc };
        // `auth_key` was copied into `keys`, and the raw encryption key is
        // already expanded into `enc`: wipe both stack originals.
        crate::ct::zeroize_slice(auth_key.as_mut_slice());
        crate::ct::zeroize_slice(enc_key.as_mut_slice());
        keys
    }
}

impl<C> Drop for NonceKeys<C> {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.auth_key.as_mut_slice());
    }
}

/// The RFC 8452 §4 tag over `aad` and `plaintext` under `keys`.
///
/// The POLYVAL input buffer holds a padded copy of `plaintext`, which on the
/// decrypt path is not authenticated yet, so it is wiped before returning.
fn gcm_siv_tag<C: BlockCipher>(
    keys: &NonceKeys<C>,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; 16] {
    let mut s_input = gcm_siv_s_input(aad, plaintext);
    let mut tag = polyval(&keys.auth_key, &s_input);
    crate::ct::zeroize_slice(s_input.as_mut_slice());
    for i in 0..12 {
        tag[i] ^= nonce[i];
    }
    tag[15] &= 0x7f;
    keys.enc.encrypt(&mut tag);
    tag
}

/// AES-CTR with a little-endian 32-bit counter (RFC 8452 §4) over `data` in
/// place, starting from `tag` with its top bit set. The counter and keystream
/// blocks are wiped before returning.
fn aes_ctr_le32_apply<C: BlockCipher>(enc: &C, tag: &[u8; 16], data: &mut [u8]) {
    let mut counter = *tag;
    counter[15] |= 0x80;
    let mut stream = [0u8; 16];
    for chunk in data.chunks_mut(BLOCK_BYTES) {
        stream = counter;
        enc.encrypt(&mut stream);
        for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key;
        }
        increment_le32(&mut counter);
    }
    crate::ct::zeroize_slice(stream.as_mut_slice());
    crate::ct::zeroize_slice(counter.as_mut_slice());
}

/// AES-GCM-SIV (RFC 8452) over the AES implementation `C`.
///
/// `C` fixes both the key size and the AES code path. The aliases name the
/// four combinations:
///
/// | Alias              | `C`         | RFC 8452 name           | AES timing |
/// |--------------------|-------------|-------------------------|------------|
/// | [`Aes128GcmSiv`]   | [`Aes128`]  | `AEAD_AES_128_GCM_SIV`  | T-table    |
/// | [`Aes256GcmSiv`]   | [`Aes256`]  | `AEAD_AES_256_GCM_SIV`  | T-table    |
/// | [`Aes128GcmSivCt`] | [`Aes128Ct`]| `AEAD_AES_128_GCM_SIV`  | constant   |
/// | [`Aes256GcmSivCt`] | [`Aes256Ct`]| `AEAD_AES_256_GCM_SIV`  | constant   |
///
/// # Timing
///
/// POLYVAL is computed on the constant-time GHASH table multiply of this
/// module's parent (no secret-dependent branch or memory access). Every AES
/// invocation, the RFC 8452 §4 key derivation, the tag encryption and the
/// AES-CTR keystream, is `C`'s: with [`Aes128`] or [`Aes256`] its T-table
/// indices are secret key and data, so those two aliases are variable-time;
/// with [`Aes128Ct`] or [`Aes256Ct`] the whole AEAD has no secret-dependent
/// memory access or branch. The two paths agree bit for bit; the `Ct` alias
/// is the choice whenever timing matters.
///
/// # Nonce reuse
///
/// Encryption is deterministic, so repeating a nonce under the same key
/// reveals only whether two messages are identical. Unique nonces are still
/// preferred.
pub struct AesGcmSiv<C> {
    keygen: C,
}

/// `AEAD_AES_128_GCM_SIV` on the T-table AES-128 (variable-time).
pub type Aes128GcmSiv = AesGcmSiv<Aes128>;

/// `AEAD_AES_256_GCM_SIV` on the T-table AES-256 (variable-time).
pub type Aes256GcmSiv = AesGcmSiv<Aes256>;

/// `AEAD_AES_128_GCM_SIV` on the constant-time AES-128.
pub type Aes128GcmSivCt = AesGcmSiv<Aes128Ct>;

/// `AEAD_AES_256_GCM_SIV` on the constant-time AES-256.
pub type Aes256GcmSivCt = AesGcmSiv<Aes256Ct>;

impl<C: GcmSivBlockCipher> AesGcmSiv<C> {
    /// Expand the key-generating key (RFC 8452 §4), 16 bytes for AES-128 and
    /// 32 for AES-256.
    pub fn new(key: &C::Key) -> Self {
        Self {
            keygen: C::from_key(key),
        }
    }

    /// Encrypt `data` in place and return a detached 16-byte tag.
    ///
    /// # Panics
    ///
    /// Panics if `aad` or `data` is longer than the RFC 8452 §6 bound of 2^36
    /// bytes.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        assert_gcm_siv_lengths(aad.len(), data.len());
        let keys = NonceKeys::derive(&self.keygen, nonce);
        let tag = gcm_siv_tag(&keys, nonce, aad, data);
        aes_ctr_le32_apply(&keys.enc, &tag, data);
        tag
    }

    /// Verify `tag` and decrypt `data` in place on success.
    ///
    /// Decrypts into a heap copy, recomputes the tag over it, and commits to
    /// `data` only on a match. Returns `false` and leaves `data` unchanged
    /// when the tag does not verify.
    ///
    /// # Panics
    ///
    /// Panics if `aad` or `data` is longer than the RFC 8452 §6 bound of 2^36
    /// bytes.
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        assert_gcm_siv_lengths(aad.len(), data.len());
        let keys = NonceKeys::derive(&self.keygen, nonce);
        let mut plaintext = data.to_vec();
        aes_ctr_le32_apply(&keys.enc, tag, &mut plaintext);
        let mut expected = gcm_siv_tag(&keys, nonce, aad, &plaintext);
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        if authentic {
            data.copy_from_slice(&plaintext);
        }
        // The heap copy is unauthenticated plaintext on failure and a duplicate
        // on success; on failure `expected` is a valid tag for the attacker's
        // ciphertext.
        crate::ct::zeroize_slice(&mut plaintext);
        crate::ct::zeroize_slice(expected.as_mut_slice());
        authentic
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_key_bytes, polyval, Aes128GcmSiv, Aes128GcmSivCt, Aes256GcmSiv, Aes256GcmSivCt,
        NonceKeys,
    };
    use crate::test_utils::decode_hex;
    use crate::Aes128;
    use core::mem::MaybeUninit;

    #[test]
    fn polyval_worked_example_rfc8452_appendix_a() {
        let h = <[u8; 16]>::try_from(decode_hex("25629347589242761d31f826ba4b757b")).expect("h");
        let x1 = <[u8; 16]>::try_from(decode_hex("4f4f95668c83dfb6401762bb2d01a262")).expect("x1");
        let x2 = <[u8; 16]>::try_from(decode_hex("d1a24ddd2721d006bbe45f20d3c9f362")).expect("x2");
        let mut input = Vec::new();
        input.extend_from_slice(&x1);
        input.extend_from_slice(&x2);
        assert_eq!(
            polyval(&h, &input),
            <[u8; 16]>::try_from(decode_hex("f7a3b47b846119fae5b7866cf5e5b77e")).expect("out")
        );
    }

    #[test]
    fn derive_keys_match_first_rfc8452_vector() {
        let key =
            <[u8; 16]>::try_from(decode_hex("01000000000000000000000000000000")).expect("key");
        let nonce = <[u8; 12]>::try_from(decode_hex("030000000000000000000000")).expect("nonce");
        let keygen = Aes128::new(&key);

        // The derivation writes into caller-owned fixed buffers, so the test
        // inspects exactly the bytes the production path expands and wipes.
        let mut auth_key = [0u8; 16];
        let mut enc_key = [0u8; 16];
        derive_key_bytes(&keygen, &nonce, &mut auth_key, &mut enc_key);
        assert_eq!(
            auth_key,
            <[u8; 16]>::try_from(decode_hex("d9b360279694941ac5dbc6987ada7377")).expect("ak")
        );
        assert_eq!(
            enc_key.as_slice(),
            decode_hex("4004a0dcd862f2a57360219d2d44ef6c").as_slice()
        );

        let keys = NonceKeys::derive(&keygen, &nonce);
        assert_eq!(keys.auth_key, auth_key);
        let mut block = [0u8; 16];
        crate::BlockCipher::encrypt(&keys.enc, &mut block);
        assert_eq!(block, Aes128::new(&enc_key).encrypt_block(&[0u8; 16]));
    }

    #[test]
    fn rfc8452_c1_first_three_vectors_encrypt_and_decrypt() {
        let key =
            <[u8; 16]>::try_from(decode_hex("01000000000000000000000000000000")).expect("key");
        let nonce = <[u8; 12]>::try_from(decode_hex("030000000000000000000000")).expect("nonce");
        let aead = Aes128GcmSiv::new(&key);
        let aead_ct = Aes128GcmSivCt::new(&key);

        let cases = [
            ("", "dc20e2d83f25705bb49e439eca56de25"),
            (
                "0100000000000000",
                "b5d839330ac7b786578782fff6013b815b287c22493a364c",
            ),
            (
                "010000000000000000000000",
                "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639",
            ),
        ];

        for (pt_hex, result_hex) in cases {
            let mut data = decode_hex(pt_hex);
            let expected = decode_hex(result_hex);
            let tag = aead.encrypt(&nonce, &[], &mut data);

            let mut combined = data.clone();
            combined.extend_from_slice(&tag);
            assert_eq!(combined, expected);

            let mut data_ct = decode_hex(pt_hex);
            assert_eq!(aead_ct.encrypt(&nonce, &[], &mut data_ct), tag);
            assert_eq!(data_ct, data);

            assert!(aead_ct.decrypt(&nonce, &[], &mut data_ct, &tag));
            assert!(aead.decrypt(&nonce, &[], &mut data, &tag));
            assert_eq!(data, decode_hex(pt_hex));
            assert_eq!(data_ct, data);
        }
    }

    #[test]
    fn tamper_rejected() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"aad";
        let aead = Aes128GcmSiv::new(&key);
        let mut data = b"gcm siv plaintext".to_vec();
        let tag = aead.encrypt(&nonce, aad, &mut data);

        data[0] ^= 1;
        let snapshot = data.clone();
        assert!(!aead.decrypt(&nonce, aad, &mut data, &tag));
        assert_eq!(data, snapshot);
    }

    /// RFC 8452 Appendix C.2, first three vectors: pins the six-block AES-256
    /// key derivation and the AES-256 encryption path, which the AES-128
    /// vectors cannot reach, on both AES implementations.
    #[test]
    fn rfc8452_c2_first_three_vectors_encrypt_and_decrypt() {
        let key = <[u8; 32]>::try_from(decode_hex(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ))
        .expect("key");
        let nonce = <[u8; 12]>::try_from(decode_hex("030000000000000000000000")).expect("nonce");
        let aead = Aes256GcmSiv::new(&key);
        let aead_ct = Aes256GcmSivCt::new(&key);

        let cases = [
            ("", "07f5f4169bbf55a8400cd47ea6fd400f"),
            (
                "0100000000000000",
                "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
            ),
            (
                "010000000000000000000000",
                "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
            ),
        ];

        for (pt_hex, result_hex) in cases {
            let mut data = decode_hex(pt_hex);
            let expected = decode_hex(result_hex);
            let tag = aead.encrypt(&nonce, &[], &mut data);

            let mut combined = data.clone();
            combined.extend_from_slice(&tag);
            assert_eq!(combined, expected);

            let mut data_ct = decode_hex(pt_hex);
            assert_eq!(aead_ct.encrypt(&nonce, &[], &mut data_ct), tag);
            assert_eq!(data_ct, data);

            assert!(aead_ct.decrypt(&nonce, &[], &mut data_ct, &tag));
            assert!(aead.decrypt(&nonce, &[], &mut data, &tag));
            assert_eq!(data, decode_hex(pt_hex));
            assert_eq!(data_ct, data);
        }
    }

    #[test]
    fn aes256_roundtrip_smoke() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let aad = b"header";
        let aead = Aes256GcmSiv::new(&key);
        let mut data = b"payload".to_vec();
        let tag = aead.encrypt(&nonce, aad, &mut data);
        assert!(aead.decrypt(&nonce, aad, &mut data, &tag));
        assert_eq!(data, b"payload");
    }

    /// The per-nonce keys leave nothing behind: after `NonceKeys` is dropped
    /// in place, its POLYVAL key and the AES schedule inside it read as zero.
    #[test]
    #[allow(unsafe_code)] // observes the bytes a `Drop` leaves behind
    fn nonce_keys_are_wiped_on_drop() {
        let keygen = Aes128::new(&[0x5au8; 16]);
        let mut slot = MaybeUninit::new(NonceKeys::derive(&keygen, &[0xa5u8; 12]));
        let size = core::mem::size_of::<NonceKeys<Aes128>>();
        // SAFETY: `slot` is initialised, and the byte view covers exactly the
        // value's storage, which stays allocated (and holds initialised bytes)
        // until `slot` goes out of scope; nothing uses the value after the
        // drop except this byte-level inspection.
        let (before, after) = unsafe {
            let bytes = core::slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size);
            let before = bytes.iter().filter(|&&b| b != 0).count();
            core::ptr::drop_in_place(slot.as_mut_ptr());
            let after = bytes.iter().filter(|&&b| b != 0).count();
            (before, after)
        };
        assert!(before > 16, "the live keys are not all zero");
        assert_eq!(after, 0, "bytes left after drop");
    }
}
