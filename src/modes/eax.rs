//! EAX authenticated encryption mode.
//!
//! EAX combines CMAC and CTR for nonce-based authenticated encryption over
//! 128-bit block ciphers.

use crate::BlockCipher;

#[inline]
fn increment_be(counter: &mut [u8; 16]) {
    for b in counter.iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

#[inline]
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

#[inline]
fn rb_for(block_len: usize) -> u8 {
    match block_len {
        8 => 0x1b,
        16 => 0x87,
        _ => panic!("CMAC only supports 64-bit or 128-bit block ciphers"),
    }
}

fn dbl(block: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; block.len()];
    let mut carry = 0u8;
    for (o, &b) in out.iter_mut().rev().zip(block.iter().rev()) {
        *o = (b << 1) | carry;
        carry = b >> 7;
    }
    if carry != 0 {
        let last = out.len() - 1;
        out[last] ^= rb_for(block.len());
    }
    out
}

fn cmac_compute<C: BlockCipher>(cipher: &C, data: &[u8]) -> [u8; 16] {
    assert_eq!(C::BLOCK_LEN, 16, "EAX requires a 128-bit block cipher");
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

fn eax_omac<C: BlockCipher>(cipher: &C, domain: u8, data: &[u8]) -> [u8; 16] {
    let mut prefixed = Vec::with_capacity(16 + data.len());
    prefixed.extend_from_slice(&[0u8; 15]);
    prefixed.push(domain);
    prefixed.extend_from_slice(data);
    cmac_compute(cipher, &prefixed)
}

fn ctr_apply<C: BlockCipher>(cipher: &C, initial_counter: &[u8; 16], data: &mut [u8]) {
    let mut counter = *initial_counter;
    for chunk in data.chunks_mut(16) {
        let mut stream = counter;
        cipher.encrypt(&mut stream);
        for i in 0..chunk.len() {
            chunk[i] ^= stream[i];
        }
        increment_be(&mut counter);
    }
}

/// EAX AEAD with a full 16-byte detached tag.
///
/// # Nonce reuse
///
/// Reusing a nonce under the same key breaks both confidentiality and
/// authenticity: the CTR keystream repeats and the OMAC tags become related.
/// Never reuse a `(key, nonce)` pair.
pub struct Eax<C> {
    cipher: C,
}

impl<C> Eax<C> {
    /// Wrap a 128-bit block cipher in EAX mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Eax<C> {
    /// Encrypt `data` in place and return a detached 16-byte tag.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        assert_eq!(C::BLOCK_LEN, 16, "EAX requires a 128-bit block cipher");

        let n_tag = eax_omac(&self.cipher, 0, nonce);
        let h_tag = eax_omac(&self.cipher, 1, aad);

        ctr_apply(&self.cipher, &n_tag, data);
        let c_tag = eax_omac(&self.cipher, 2, data);

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = n_tag[i] ^ h_tag[i] ^ c_tag[i];
        }
        tag
    }

    /// Verify and decrypt `data` in place.
    ///
    /// Returns `false` and leaves `data` unchanged on authentication failure.
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        assert_eq!(C::BLOCK_LEN, 16, "EAX requires a 128-bit block cipher");

        let n_tag = eax_omac(&self.cipher, 0, nonce);
        let h_tag = eax_omac(&self.cipher, 1, aad);
        let c_tag = eax_omac(&self.cipher, 2, data);
        let mut expected = [0u8; 16];
        for i in 0..16 {
            expected[i] = n_tag[i] ^ h_tag[i] ^ c_tag[i];
        }

        if crate::ct::constant_time_eq_mask(&expected, tag) != u8::MAX {
            return false;
        }

        ctr_apply(&self.cipher, &n_tag, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::Eax;
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
    fn eax_aes128_eprint_2003_069_known_vectors() {
        // Official EAX KATs from Bellare-Rogaway-Wagner, "A Conventional
        // Authenticated-Encryption Mode" (ePrint 2003/069), mirrored in
        // Wycheproof as `Ktv` cases for AES-EAX.
        //
        // Format per vector: key, nonce, aad, plaintext, ciphertext, tag.
        let vectors = [
            (
                "233952dee4d5ed5f9b9c6d6ff80ff478",
                "62ec67f9c3a4a407fcb2a8c49031a8b3",
                "6bfb914fd07eae6b",
                "",
                "",
                "e037830e8389f27b025a2d6527e79d01",
            ),
            (
                "91945d3f4dcbee0bf45ef52255f095a4",
                "becaf043b0a23d843194ba972c66debd",
                "fa3bfd4806eb53fa",
                "f7fb",
                "19dd",
                "5c4c9331049d0bdab0277408f67967e5",
            ),
            (
                "01f74ad64077f2e704c0f60ada3dd523",
                "70c3db4f0d26368400a10ed05d2bff5e",
                "234a3463c1264ac6",
                "1a47cb4933",
                "d851d5bae0",
                "3a59f238a23e39199dc9266626c40f80",
            ),
            (
                "d07cf6cbb7f313bdde66b727afd3c5e8",
                "8408dfff3c1a2b1292dc199e46b7d617",
                "33cce2eabff5a79d",
                "481c9e39b1",
                "632a9d131a",
                "d4c168a4225d8e1ff755939974a7bede",
            ),
            (
                "35b6d0580005bbc12b0587124557d2c2",
                "fdb6b06676eedc5c61d74276e1f8e816",
                "aeb96eaebe2970e9",
                "40d0c07da5e4",
                "071dfe16c675",
                "cb0677e536f73afe6a14b74ee49844dd",
            ),
            (
                "bd8e6e11475e60b268784c38c62feb22",
                "6eac5c93072d8e8513f750935e46da1b",
                "d4482d1ca78dce0f",
                "4de3b35c3fc039245bd1fb7d",
                "835bb4f15d743e350e728414",
                "abb8644fd6ccb86947c5e10590210a4f",
            ),
            (
                "7c77d6e813bed5ac98baa417477a2e7d",
                "1a8c98dcd73d38393b2bf1569deefc19",
                "65d2017990d62528",
                "8b0a79306c9ce7ed99dae4f87f8dd61636",
                "02083e3979da014812f59f11d52630da30",
                "137327d10649b0aa6e1c181db617d7f2",
            ),
            (
                "5fff20cafab119ca2fc73549e20f5b0d",
                "dde59b97d722156d4d9aff2bc7559826",
                "54b9f04e6a09189a",
                "1bda122bce8a8dbaf1877d962b8592dd2d56",
                "2ec47b2c4954a489afc7ba4897edcdae8cc3",
                "3b60450599bd02c96382902aef7f832a",
            ),
            (
                "a4a4782bcffd3ec5e7ef6d8c34a56123",
                "b781fcf2f75fa5a8de97a9ca48e522ec",
                "899a175897561d7e",
                "6cf36720872b8513f6eab1a8a44438d5ef11",
                "0de18fd0fdd91e7af19f1d8ee8733938b1e8",
                "e7f6d2231618102fdb7fe55ff1991700",
            ),
            (
                "8395fcf1e95bebd697bd010bc766aac3",
                "22e7add93cfc6393c57ec0b3c17d6b44",
                "126735fcc320d25a",
                "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
                "cb8920f87a6c75cff39627b56e3ed197c552d295a7",
                "cfc46afc253b4652b1af3795b124ab6e",
            ),
        ];

        for (idx, (key_hex, nonce_hex, aad_hex, pt_hex, ct_hex, tag_hex)) in
            vectors.iter().enumerate()
        {
            let key = <[u8; 16]>::try_from(unhex_ws(key_hex)).expect("16-byte key");
            let nonce = unhex_ws(nonce_hex);
            let aad = unhex_ws(aad_hex);
            let mut plaintext = unhex_ws(pt_hex);
            let expected_ciphertext = unhex_ws(ct_hex);
            let expected_tag = <[u8; 16]>::try_from(unhex_ws(tag_hex)).expect("16-byte tag");

            let eax = Eax::new(Aes128::new(&key));
            let tag = eax.encrypt(&nonce, &aad, &mut plaintext);
            assert_eq!(
                plaintext, expected_ciphertext,
                "ciphertext mismatch for EAX KAT #{idx}"
            );
            assert_eq!(tag, expected_tag, "tag mismatch for EAX KAT #{idx}");

            assert!(
                eax.decrypt(&nonce, &aad, &mut plaintext, &tag),
                "decrypt failed for EAX KAT #{idx}"
            );
            assert_eq!(
                plaintext,
                unhex_ws(pt_hex),
                "plaintext mismatch after decrypt for EAX KAT #{idx}"
            );
        }
    }

    #[test]
    fn eax_tamper_rejected() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 16];
        let aad = b"aad";
        let mut data = b"eax data".to_vec();
        let eax = Eax::new(Aes128::new(&key));
        let tag = eax.encrypt(&nonce, aad, &mut data);

        data[0] ^= 1;
        let snapshot = data.clone();
        assert!(!eax.decrypt(&nonce, aad, &mut data, &tag));
        assert_eq!(data, snapshot);
    }

    #[test]
    fn eax_roundtrip_various_lengths() {
        let key = [0x42u8; 16];
        let eax = Eax::new(Aes128::new(&key));
        for msg_len in [0usize, 1, 2, 15, 16, 17, 31, 32, 33] {
            let nonce = vec![0x24; 13];
            let aad = vec![0x35; 11];
            let mut data = vec![0u8; msg_len];
            for (i, b) in data.iter_mut().enumerate() {
                *b = u8::try_from(i & 0xff).expect("byte");
            }
            let original = data.clone();
            let tag = eax.encrypt(&nonce, &aad, &mut data);
            assert!(eax.decrypt(&nonce, &aad, &mut data, &tag));
            assert_eq!(data, original);
        }
    }
}
