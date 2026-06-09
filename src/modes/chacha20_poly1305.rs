//! ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! This module implements the IETF 96-bit-nonce ChaCha20-Poly1305 profile:
//! - one-time Poly1305 key from ChaCha20 block counter 0
//! - payload encryption with ChaCha20 block counter 1+
//! - AEAD MAC input `AAD || pad16 || CT || pad16 || len(AAD) || len(CT)`

use crate::modes::poly1305::poly1305_mac;
use crate::ChaCha20;

fn build_poly1305_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        aad.len()
            + ((16 - (aad.len() % 16)) % 16)
            + ciphertext.len()
            + ((16 - (ciphertext.len() % 16)) % 16)
            + 16,
    );
    data.extend_from_slice(aad);
    if !aad.len().is_multiple_of(16) {
        data.resize(data.len() + (16 - (aad.len() % 16)), 0);
    }
    data.extend_from_slice(ciphertext);
    if !ciphertext.len().is_multiple_of(16) {
        data.resize(data.len() + (16 - (ciphertext.len() % 16)), 0);
    }
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

    fn poly1305_one_time_key(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let mut c = ChaCha20::with_counter(&self.key, nonce, 0);
        let block = c.keystream_block();
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&block[..32]);
        otk
    }

    /// Encrypt `data` in place and return the detached tag.
    #[must_use]
    pub fn encrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let mut stream = ChaCha20::with_counter(&self.key, nonce, 1);
        stream.apply_keystream(data);

        let mut otk = self.poly1305_one_time_key(nonce);
        let mac_data = build_poly1305_input(aad, data);
        let tag = poly1305_mac(&mac_data, &otk);
        crate::ct::zeroize_slice(otk.as_mut_slice());
        tag
    }

    /// Decrypt `data` in place after authenticating `tag`.
    ///
    /// Returns `false` on authentication failure and leaves `data` untouched.
    #[must_use]
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let mut otk = self.poly1305_one_time_key(nonce);
        let mac_data = build_poly1305_input(aad, data);
        let expected = poly1305_mac(&mac_data, &otk);
        crate::ct::zeroize_slice(otk.as_mut_slice());
        if crate::ct::constant_time_eq_mask(&expected, tag) != u8::MAX {
            return false;
        }

        let mut stream = ChaCha20::with_counter(&self.key, nonce, 1);
        stream.apply_keystream(data);
        true
    }

    /// Encrypt and return `(ciphertext, tag)`.
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

    fn unhex(input: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

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
        let key = <[u8; 32]>::try_from(unhex(
            "808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f",
        ))
        .expect("key");
        let nonce = <[u8; 12]>::try_from(unhex("070000004041424344454647")).expect("nonce");
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = unhex(
            "4c616469657320616e642047656e746c\
             656d656e206f662074686520636c6173\
             73206f66202739393a20496620492063\
             6f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220\
             746865206675747572652c2073756e73\
             637265656e20776f756c642062652069\
             742e",
        );
        let expected_ciphertext = unhex(
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
            <[u8; 16]>::try_from(unhex("1ae10b594f09e26a7e902ecbd0600691")).expect("tag");

        let aead = ChaCha20Poly1305::new(&key);
        let (ciphertext, tag) = aead.encrypt(&nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        let key = <[u8; 32]>::try_from(unhex(
            "85d6be7857556d337f4452fe42d506a8\
             0103808afb0db2fd4abff6af4149f51b",
        ))
        .expect("key");
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(msg, &key);
        let expected =
            <[u8; 16]>::try_from(unhex("a8061dc1305136c6c22b8baf0c0127a9")).expect("tag");
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
}
