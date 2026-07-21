//! Synthetic IV (SIV) authenticated encryption (RFC 5297).
//!
//! This module implements the AES-SIV construction with CMAC-based S2V and
//! CTR encryption. The caller supplies separate block-cipher instances for the
//! CMAC key half and CTR key half.

use super::{dbl, dbl_block};
use crate::BlockCipher;

#[inline]
fn xor_block(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[inline]
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

fn cmac_compute<C: BlockCipher>(cipher: &C, data: &[u8]) -> [u8; 16] {
    assert_eq!(C::BLOCK_LEN, 16, "SIV requires a 128-bit block cipher");
    let blk = C::BLOCK_LEN;
    let mut l = vec![0u8; blk];
    cipher.encrypt(&mut l);
    let k1 = dbl(&l);
    let k2 = dbl(&k1);

    let n = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(blk)
    };
    let last_complete = !data.is_empty() && data.len().is_multiple_of(blk);

    let mut x = vec![0u8; blk];
    let mut y = vec![0u8; blk];

    for block in data.chunks(blk).take(n.saturating_sub(1)) {
        y.copy_from_slice(&x);
        xor_in_place(&mut y, block);
        cipher.encrypt(&mut y);
        x.copy_from_slice(&y);
    }

    let mut m_last = vec![0u8; blk];
    if last_complete {
        let start = (n - 1) * blk;
        m_last.copy_from_slice(&data[start..start + blk]);
        xor_in_place(&mut m_last, &k1);
    } else {
        let start = (n - 1) * blk;
        let rem = data.len().saturating_sub(start);
        if rem != 0 {
            m_last[..rem].copy_from_slice(&data[start..]);
        }
        m_last[rem] = 0x80;
        xor_in_place(&mut m_last, &k2);
    }

    xor_in_place(&mut m_last, &x);
    cipher.encrypt(&mut m_last);
    m_last.try_into().expect("CMAC output is one block")
}

#[inline]
fn cmac_block<C: BlockCipher>(cipher: &C, data: &[u8]) -> [u8; 16] {
    cmac_compute(cipher, data)
}

fn s2v<C: BlockCipher>(mac_cipher: &C, components: &[&[u8]], plaintext: &[u8]) -> [u8; 16] {
    // RFC 5297 S2V with plaintext as the final component.
    let mut d = cmac_block(mac_cipher, &[0u8; 16]);
    for component in components {
        d = xor_block(dbl_block(d), cmac_block(mac_cipher, component));
    }

    let t = if plaintext.len() >= 16 {
        let mut t = plaintext.to_vec();
        let start = t.len() - 16;
        for i in 0..16 {
            t[start + i] ^= d[i];
        }
        t
    } else {
        let mut padded = [0u8; 16];
        padded[..plaintext.len()].copy_from_slice(plaintext);
        padded[plaintext.len()] = 0x80;
        let mixed = xor_block(dbl_block(d), padded);
        mixed.to_vec()
    };

    cmac_block(mac_cipher, &t)
}

#[inline]
fn clear_siv_ctr_bits(counter: &mut [u8; 16]) {
    // RFC 5297 section 2.6: clear bit 31 and bit 63.
    counter[8] &= 0x7f;
    counter[12] &= 0x7f;
}

#[inline]
fn increment_be32(block: &mut [u8; 16]) {
    for b in block[12..].iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

fn ctr_apply<C: BlockCipher>(cipher: &C, initial_counter: &[u8; 16], data: &mut [u8]) {
    let mut counter = *initial_counter;
    for chunk in data.chunks_mut(16) {
        let mut stream = counter;
        cipher.encrypt(&mut stream);
        for i in 0..chunk.len() {
            chunk[i] ^= stream[i];
        }
        increment_be32(&mut counter);
    }
}

/// RFC 5297 SIV construction parameterized by two block-cipher instances.
///
/// # Nonce reuse
///
/// SIV is misuse-resistant: encryption is deterministic, so repeating a nonce
/// (or omitting one) only reveals whether two messages are identical. It does
/// not leak plaintext contents or authentication keys. Unique nonces are
/// still preferred.
pub struct Siv<C> {
    mac_cipher: C,
    ctr_cipher: C,
}

impl<C> Siv<C> {
    /// Construct from separate CMAC and CTR ciphers.
    pub fn new(mac_cipher: C, ctr_cipher: C) -> Self {
        Self {
            mac_cipher,
            ctr_cipher,
        }
    }

    /// Borrow the CMAC-side cipher.
    pub fn mac_cipher(&self) -> &C {
        &self.mac_cipher
    }

    /// Borrow the CTR-side cipher.
    pub fn ctr_cipher(&self) -> &C {
        &self.ctr_cipher
    }
}

impl<C: BlockCipher> Siv<C> {
    /// Encrypt using an explicit ordered vector of associated-data components.
    pub fn encrypt_with_components(
        &self,
        components: &[&[u8]],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        let tag = s2v(&self.mac_cipher, components, plaintext);
        let mut counter = tag;
        clear_siv_ctr_bits(&mut counter);

        let mut ciphertext = plaintext.to_vec();
        ctr_apply(&self.ctr_cipher, &counter, &mut ciphertext);
        (ciphertext, tag)
    }

    /// Decrypt/authenticate using an explicit vector of associated-data components.
    pub fn decrypt_with_components(
        &self,
        components: &[&[u8]],
        ciphertext: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let mut counter = *tag;
        clear_siv_ctr_bits(&mut counter);

        let mut plaintext = ciphertext.to_vec();
        ctr_apply(&self.ctr_cipher, &counter, &mut plaintext);
        let expected = s2v(&self.mac_cipher, components, &plaintext);
        if crate::ct::constant_time_eq_mask(&expected, tag) != u8::MAX {
            // SIV must decrypt before authenticating (S2V is over plaintext),
            // so zeroize the speculative plaintext before dropping on failure.
            crate::ct::zeroize_slice(&mut plaintext);
            return false;
        }
        ciphertext.copy_from_slice(&plaintext);
        true
    }

    /// Encrypt and return `(ciphertext, detached_tag)`.
    ///
    /// RFC 5297 treats the `nonce` as an associated-data component.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
        if nonce.is_empty() {
            self.encrypt_with_components(&[aad], plaintext)
        } else {
            self.encrypt_with_components(&[aad, nonce], plaintext)
        }
    }

    /// Authenticate and decrypt in place.
    ///
    /// Returns `false` and leaves `ciphertext` unchanged on failure.
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        if nonce.is_empty() {
            self.decrypt_with_components(&[aad], ciphertext, tag)
        } else {
            self.decrypt_with_components(&[aad, nonce], ciphertext, tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Siv;
    use crate::Aes128;

    fn unhex_ws(input: &str) -> Vec<u8> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        let mut out = Vec::with_capacity(compact.len() / 2);
        let bytes = compact.as_bytes();
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
    fn rfc5297_a1_deterministic_vector() {
        // RFC 5297 Appendix A.1.
        let key = <[u8; 32]>::try_from(unhex_ws(
            "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
             f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
        ))
        .expect("key");
        let k1: [u8; 16] = key[..16].try_into().expect("k1");
        let k2: [u8; 16] = key[16..].try_into().expect("k2");
        let aad = unhex_ws("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");
        let nonce: [u8; 0] = [];
        let plaintext = unhex_ws("11223344 55667788 99aabbcc ddee");
        let expected_tag =
            <[u8; 16]>::try_from(unhex_ws("85632d07 c6e8f37f 950acd32 0a2ecc93")).expect("tag");
        let expected_ct = unhex_ws("40c02b96 90c4dc04 daef7f6a fe5c");

        let siv = Siv::new(Aes128::new(&k1), Aes128::new(&k2));
        let (ct, tag) = siv.encrypt(&nonce, &aad, &plaintext);
        assert_eq!(tag, expected_tag);
        assert_eq!(ct, expected_ct);

        let mut roundtrip = ct.clone();
        assert!(siv.decrypt(&nonce, &aad, &mut roundtrip, &tag));
        assert_eq!(roundtrip, plaintext);
    }

    #[test]
    fn rfc5297_a2_nonce_based_vector() {
        // RFC 5297 Appendix A.2.
        let key = <[u8; 32]>::try_from(unhex_ws(
            "7f7e7d7c 7b7a7978 77767574 73727170
             40414243 44454647 48494a4b 4c4d4e4f",
        ))
        .expect("key");
        let k1: [u8; 16] = key[..16].try_into().expect("k1");
        let k2: [u8; 16] = key[16..].try_into().expect("k2");
        let ad1 = unhex_ws(
            "00112233 44556677 8899aabb ccddeeff
             deaddada deaddada ffeeddcc bbaa9988
             77665544 33221100",
        );
        let ad2 = unhex_ws("10203040 50607080 90a0");
        let nonce = unhex_ws("09f91102 9d74e35b d84156c5 635688c0");
        let plaintext = unhex_ws(
            "74686973 20697320 736f6d65 20706c61
             696e7465 78742074 6f20656e 63727970
             74207573 696e6720 5349562d 414553",
        );
        let expected_tag =
            <[u8; 16]>::try_from(unhex_ws("7bdb6e3b 432667eb 06f4d14b ff2fbd0f")).expect("tag");
        let expected_ct = unhex_ws(
            "cb900f2f ddbe4043 26601965 c889bf17
             dba77ceb 094fa663 b7a3f748 ba8af829
             ea64ad54 4a272e9c 485b62a3 fd5c0d",
        );

        let siv = Siv::new(Aes128::new(&k1), Aes128::new(&k2));
        let (ct, tag) = siv.encrypt_with_components(&[&ad1, &ad2, &nonce], &plaintext);
        assert_eq!(tag, expected_tag);
        assert_eq!(ct, expected_ct);

        let mut roundtrip = ct.clone();
        assert!(siv.decrypt_with_components(&[&ad1, &ad2, &nonce], &mut roundtrip, &tag));
        assert_eq!(roundtrip, plaintext);
    }

    #[test]
    fn tamper_rejected_without_plaintext_commit() {
        let k1 = [0x11u8; 16];
        let k2 = [0x22u8; 16];
        let nonce = [0x33u8; 16];
        let aad = b"aad";
        let plaintext = b"siv plaintext".to_vec();
        let siv = Siv::new(Aes128::new(&k1), Aes128::new(&k2));
        let (mut ct, tag) = siv.encrypt(&nonce, aad, &plaintext);

        ct[0] ^= 1;
        let snapshot = ct.clone();
        assert!(!siv.decrypt(&nonce, aad, &mut ct, &tag));
        assert_eq!(ct, snapshot);
    }
}
