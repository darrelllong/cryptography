//! ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! This module implements the IETF 96-bit-nonce ChaCha20-Poly1305 profile:
//! - one-time Poly1305 key from ChaCha20 block counter 0
//! - payload encryption with ChaCha20 block counter 1+
//! - AEAD MAC input `AAD || pad16 || CT || pad16 || len(AAD) || len(CT)`

use crate::modes::poly1305::poly1305_mac;
use crate::ChaCha20;

/// RFC 8439 §2.8 plaintext bound, 2^38 − 64 bytes: the payload keystream runs
/// from block 1 through block `u32::MAX`, 64 bytes each. One more byte would
/// need block 0 again, which is the Poly1305 one-time-key block.
const MAX_PLAINTEXT_BYTES: u64 = ((1u64 << 32) - 1) * CHACHA20_BLOCK_BYTES as u64;

/// ChaCha20 keystream bytes per block (RFC 8439 §2.3).
const CHACHA20_BLOCK_BYTES: usize = 64;

/// Poly1305 block length, in bytes, and so the width `pad16` pads to
/// (RFC 8439 §2.5 and §2.8).
const POLY1305_BLOCK_BYTES: usize = 16;

/// The two little-endian 64-bit lengths that close the MAC input
/// (RFC 8439 §2.8).
const LENGTH_FIELD_BYTES: usize = 2 * 8;

/// `pad16(data)` of RFC 8439 §2.8: zeros to the next multiple of the Poly1305
/// block, and none when the length is already a multiple.
const fn padding(len: usize) -> usize {
    (POLY1305_BLOCK_BYTES - (len % POLY1305_BLOCK_BYTES)) % POLY1305_BLOCK_BYTES
}

#[inline]
fn plaintext_len_allowed(len: usize) -> bool {
    u64::try_from(len).is_ok_and(|len| len <= MAX_PLAINTEXT_BYTES)
}

fn build_poly1305_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        aad.len()
            + padding(aad.len())
            + ciphertext.len()
            + padding(ciphertext.len())
            + LENGTH_FIELD_BYTES,
    );
    data.extend_from_slice(aad);
    data.resize(data.len() + padding(aad.len()), 0);
    data.extend_from_slice(ciphertext);
    data.resize(data.len() + padding(ciphertext.len()), 0);
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data
}

/// ChaCha20-Poly1305 AEAD (RFC 8439).
///
/// # Nonce reuse
///
/// Reusing a nonce under the same key leaks the XOR of the plaintexts and
/// repeats the one-time Poly1305 key for that nonce, enabling forgeries.
/// Never reuse a `(key, nonce)` pair.
///
/// # Examples
///
/// ```rust
/// use cryptography::ChaCha20Poly1305;
///
/// let key = [0x42u8; 32];
/// let nonce = [0x24u8; 12];
/// let aad = b"header";
/// let plaintext = b"message";
///
/// let aead = ChaCha20Poly1305::new(&key);
/// let (ciphertext, tag) = aead.encrypt(&nonce, aad, plaintext);
/// let recovered = aead
///     .decrypt(&nonce, aad, &ciphertext, &tag)
///     .expect("valid tag");
/// assert_eq!(recovered, plaintext);
/// ```
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Construct from a 256-bit key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Construct and wipe the caller-provided key buffer.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Write the Poly1305 one-time key for `nonce`, the first 32 bytes of
    /// keystream block 0, into `otk`.
    ///
    /// The keystream is XORed straight into the zeroed buffer, so no copy of
    /// block 0 is left on the stack; the temporary `ChaCha20` wipes its own
    /// block, which holds the rest of block 0, when it drops.
    fn poly1305_one_time_key(&self, nonce: &[u8; 12], otk: &mut [u8; 32]) {
        *otk = [0u8; 32];
        ChaCha20::with_counter(&self.key, nonce, 0).apply_keystream(otk);
    }

    /// Encrypt `data` in place and return the detached tag.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` exceeds the RFC 8439 §2.8 bound of 2^38 − 64
    /// (`274_877_906_880`) bytes per `(key, nonce)`: the payload counter would
    /// otherwise have to wrap onto block 0, the one-time-key block.
    #[must_use]
    pub fn encrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        assert!(
            plaintext_len_allowed(data.len()),
            "ChaCha20-Poly1305 plaintext too large: max {MAX_PLAINTEXT_BYTES} bytes per key/nonce"
        );
        let mut stream = ChaCha20::with_counter(&self.key, nonce, 1);
        stream.apply_keystream(data);

        let mut otk = [0u8; 32];
        self.poly1305_one_time_key(nonce, &mut otk);
        let mac_data = build_poly1305_input(aad, data);
        let tag = poly1305_mac(&mac_data, &otk);
        crate::ct::zeroize_slice(otk.as_mut_slice());
        tag
    }

    /// Decrypt `data` in place after authenticating `tag`.
    ///
    /// Returns `false` and leaves `data` untouched on authentication failure,
    /// and also when `data` is longer than the RFC 8439 §2.8 bound of
    /// 2^38 − 64 bytes (no valid ciphertext of that length exists).
    #[must_use]
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        if !plaintext_len_allowed(data.len()) {
            return false;
        }
        let mut otk = [0u8; 32];
        self.poly1305_one_time_key(nonce, &mut otk);
        let mac_data = build_poly1305_input(aad, data);
        let mut expected = poly1305_mac(&mac_data, &otk);
        crate::ct::zeroize_slice(otk.as_mut_slice());
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        // On failure `expected` is a valid tag for the attacker's ciphertext.
        crate::ct::zeroize_slice(expected.as_mut_slice());
        if authentic {
            ChaCha20::with_counter(&self.key, nonce, 1).apply_keystream(data);
        }
        authentic
    }

    /// Encrypt and return `(ciphertext, tag)`.
    ///
    /// # Panics
    ///
    /// Panics if `plaintext.len()` exceeds the RFC 8439 §2.8 bound of
    /// 2^38 − 64 bytes, as [`ChaCha20Poly1305::encrypt_in_place`] does.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut out = plaintext.to_vec();
        let tag = self.encrypt_in_place(nonce, aad, &mut out);
        (out, tag)
    }

    /// Decrypt and return plaintext on successful authentication.
    #[must_use]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Option<Vec<u8>> {
        let mut out = ciphertext.to_vec();
        if !self.decrypt_in_place(nonce, aad, &mut out, tag) {
            return None;
        }
        Some(out)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.key.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::{poly1305_mac, ChaCha20Poly1305};
    use crate::test_utils::decode_hex;

    #[test]
    fn roundtrip_with_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"chacha20-poly1305 roundtrip";
        let aead = ChaCha20Poly1305::new(&key);

        let (ciphertext, tag) = aead.encrypt(&nonce, aad, plaintext);
        let recovered = aead
            .decrypt(&nonce, aad, &ciphertext, &tag)
            .expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"aad";
        let plaintext = b"payload";
        let aead = ChaCha20Poly1305::new(&key);
        let (mut ciphertext, tag) = aead.encrypt(&nonce, aad, plaintext);
        ciphertext[0] ^= 0x01;
        assert!(aead.decrypt(&nonce, aad, &ciphertext, &tag).is_none());
    }

    #[test]
    fn rfc8439_aead_vector() {
        let key = <[u8; 32]>::try_from(decode_hex(
            "808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f",
        ))
        .expect("key");
        let nonce = <[u8; 12]>::try_from(decode_hex("070000004041424344454647")).expect("nonce");
        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = decode_hex(
            "4c616469657320616e642047656e746c\
             656d656e206f662074686520636c6173\
             73206f66202739393a20496620492063\
             6f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220\
             746865206675747572652c2073756e73\
             637265656e20776f756c642062652069\
             742e",
        );
        let expected_ciphertext = decode_hex(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        let expected_tag =
            <[u8; 16]>::try_from(decode_hex("1ae10b594f09e26a7e902ecbd0600691")).expect("tag");

        let aead = ChaCha20Poly1305::new(&key);
        let (ciphertext, tag) = aead.encrypt(&nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        let key = <[u8; 32]>::try_from(decode_hex(
            "85d6be7857556d337f4452fe42d506a8\
             0103808afb0db2fd4abff6af4149f51b",
        ))
        .expect("key");
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(msg, &key);
        let expected =
            <[u8; 16]>::try_from(decode_hex("a8061dc1305136c6c22b8baf0c0127a9")).expect("tag");
        assert_eq!(tag, expected);
    }

    #[test]
    fn property_roundtrip_and_tamper_detection() {
        let mut state = 0x1234_5678_9abc_def0u64;
        fn next_u8(state: &mut u64) -> u8 {
            *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (*state >> 32) as u8
        }

        for _case in 0..64 {
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 12];
            for b in key.iter_mut() {
                *b = next_u8(&mut state);
            }
            for b in nonce.iter_mut() {
                *b = next_u8(&mut state);
            }

            let aad_len = usize::from(next_u8(&mut state) % 48);
            let msg_len = usize::from(next_u8(&mut state) % 96);

            let mut aad = vec![0u8; aad_len];
            let mut msg = vec![0u8; msg_len];
            for b in aad.iter_mut() {
                *b = next_u8(&mut state);
            }
            for b in msg.iter_mut() {
                *b = next_u8(&mut state);
            }

            let aead = ChaCha20Poly1305::new(&key);
            let (mut ct, tag) = aead.encrypt(&nonce, &aad, &msg);
            let pt = aead.decrypt(&nonce, &aad, &ct, &tag).expect("decrypt");
            assert_eq!(pt, msg);

            if !ct.is_empty() {
                ct[0] ^= 0x01;
                assert!(aead.decrypt(&nonce, &aad, &ct, &tag).is_none());
            }
        }
    }

    /// RFC 8439 §2.8: the payload may use every keystream block from 1 through
    /// `u32::MAX`, so the length bound is exactly that much keystream, and the
    /// payload stream refuses to wrap onto block 0 (the one-time-key block).
    #[test]
    fn plaintext_bound_is_the_payload_keystream() {
        assert_eq!(super::MAX_PLAINTEXT_BYTES, (1u64 << 38) - 64);
        assert!(super::plaintext_len_allowed(0));
        if let Ok(max) = usize::try_from(super::MAX_PLAINTEXT_BYTES) {
            assert!(super::plaintext_len_allowed(max));
            assert!(!super::plaintext_len_allowed(max + 1));
        }

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut payload = crate::ChaCha20::with_counter(&key, &nonce, 1);
        payload.set_counter(u32::MAX);
        let _ = payload.keystream_block();
        let wrapped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            payload.apply_keystream(&mut [0u8; 1]);
        }));
        assert!(
            wrapped.is_err(),
            "the payload stream must not reach block 0"
        );
    }
}
