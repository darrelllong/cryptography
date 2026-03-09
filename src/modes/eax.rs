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
