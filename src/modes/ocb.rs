//! OCB authenticated encryption (RFC 7253, OCB3).
//!
//! This implementation targets 128-bit block ciphers and the default 128-bit
//! authentication tag profile.

use crate::BlockCipher;

#[inline]
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[inline]
fn dbl_block(block: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    if carry != 0 {
        out[15] ^= 0x87;
    }
    out
}

#[inline]
fn ntz(i: usize) -> usize {
    i.trailing_zeros() as usize
}

#[inline]
fn split_blocks(data: &[u8]) -> (&[u8], &[u8]) {
    let full = data.len() / 16 * 16;
    (&data[..full], &data[full..])
}

fn nonce_block_from_bytes(tag_len_bits: usize, nonce: &[u8]) -> [u8; 16] {
    assert!(nonce.len() <= 15, "OCB nonce must be at most 120 bits");
    let n_bits = nonce.len() * 8;
    let tag_mod = tag_len_bits % 128;

    let mut n_aligned = [0u8; 16];
    n_aligned[16 - nonce.len()..].copy_from_slice(nonce);
    let n_val = u128::from_be_bytes(n_aligned);

    let nonce_val = ((tag_mod as u128) << 121) | (1u128 << n_bits) | n_val;
    nonce_val.to_be_bytes()
}

fn stretch_from_ktop(ktop: [u8; 16]) -> [u8; 24] {
    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }
    stretch
}

fn offset_from_stretch(stretch: &[u8; 24], bottom: u8) -> [u8; 16] {
    let byte_off = usize::from(bottom / 8);
    let bit_off = usize::from(bottom % 8);
    let mut out = [0u8; 16];

    if bit_off == 0 {
        out.copy_from_slice(&stretch[byte_off..byte_off + 16]);
        return out;
    }

    for i in 0..16 {
        let b0 = stretch.get(byte_off + i).copied().unwrap_or(0);
        let b1 = stretch.get(byte_off + i + 1).copied().unwrap_or(0);
        out[i] = (b0 << bit_off) | (b1 >> (8 - bit_off));
    }
    out
}

fn hash_associated_data<C: BlockCipher>(
    cipher: &C,
    l_star: [u8; 16],
    l_dollar: [u8; 16],
    aad: &[u8],
) -> [u8; 16] {
    let mut l_table = vec![dbl_block(l_dollar)];
    let mut sum = [0u8; 16];
    let mut offset = [0u8; 16];

    let (full, partial) = split_blocks(aad);
    for (idx, block) in full.chunks_exact(16).enumerate() {
        let i = idx + 1;
        let tz = ntz(i);
        while l_table.len() <= tz {
            let next = dbl_block(*l_table.last().expect("L table non-empty"));
            l_table.push(next);
        }
        offset = xor_block(&offset, &l_table[tz]);

        let mut x = [0u8; 16];
        x.copy_from_slice(block);
        x = xor_block(&x, &offset);
        cipher.encrypt(&mut x);
        sum = xor_block(&sum, &x);
    }

    if !partial.is_empty() {
        offset = xor_block(&offset, &l_star);
        let mut cipher_input = [0u8; 16];
        cipher_input[..partial.len()].copy_from_slice(partial);
        cipher_input[partial.len()] = 0x80;
        cipher_input = xor_block(&cipher_input, &offset);
        cipher.encrypt(&mut cipher_input);
        sum = xor_block(&sum, &cipher_input);
    }

    sum
}

/// OCB3 authenticated encryption with a 16-byte detached tag.
pub struct Ocb<C> {
    cipher: C,
}

impl<C> Ocb<C> {
    /// Wrap a 128-bit block cipher in RFC 7253 OCB mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ocb<C> {
    fn compute_offsets(&self, nonce: &[u8]) -> ([u8; 16], [u8; 16], [u8; 16], Vec<[u8; 16]>) {
        assert_eq!(C::BLOCK_LEN, 16, "OCB requires a 128-bit block cipher");
        let mut l_star = [0u8; 16];
        self.cipher.encrypt(&mut l_star);
        let l_dollar = dbl_block(l_star);
        let l0 = dbl_block(l_dollar);

        let nonce_block = nonce_block_from_bytes(128, nonce);
        let bottom = nonce_block[15] & 0x3f;
        let mut ktop_input = nonce_block;
        ktop_input[15] &= 0xC0;
        self.cipher.encrypt(&mut ktop_input);
        let stretch = stretch_from_ktop(ktop_input);
        let offset0 = offset_from_stretch(&stretch, bottom);

        (l_star, l_dollar, offset0, vec![l0])
    }

    /// Encrypt `data` in place and return a detached 16-byte tag.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let (l_star, l_dollar, mut offset, mut l_table) = self.compute_offsets(nonce);
        let aad_hash = hash_associated_data(&self.cipher, l_star, l_dollar, aad);

        let (full_len, partial_len) = (data.len() / 16 * 16, data.len() % 16);
        let mut checksum = [0u8; 16];

        for (idx, block) in data[..full_len].chunks_exact_mut(16).enumerate() {
            let i = idx + 1;
            let tz = ntz(i);
            while l_table.len() <= tz {
                let next = dbl_block(*l_table.last().expect("L table non-empty"));
                l_table.push(next);
            }
            offset = xor_block(&offset, &l_table[tz]);

            let mut p = [0u8; 16];
            p.copy_from_slice(block);
            checksum = xor_block(&checksum, &p);

            p = xor_block(&p, &offset);
            self.cipher.encrypt(&mut p);
            p = xor_block(&p, &offset);
            block.copy_from_slice(&p);
        }

        if partial_len != 0 {
            offset = xor_block(&offset, &l_star);
            let mut pad = offset;
            self.cipher.encrypt(&mut pad);

            let partial = &mut data[full_len..];
            let mut partial_plain = [0u8; 16];
            partial_plain[..partial.len()].copy_from_slice(partial);
            for i in 0..partial.len() {
                partial[i] ^= pad[i];
            }

            partial_plain[partial.len()] = 0x80;
            checksum = xor_block(&checksum, &partial_plain);
        }

        let mut tag_input = xor_block(&checksum, &offset);
        tag_input = xor_block(&tag_input, &l_dollar);
        self.cipher.encrypt(&mut tag_input);
        xor_block(&tag_input, &aad_hash)
    }

    /// Verify `tag` and decrypt `data` in place on success.
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let (l_star, l_dollar, mut offset, mut l_table) = self.compute_offsets(nonce);
        let aad_hash = hash_associated_data(&self.cipher, l_star, l_dollar, aad);

        let (full_len, partial_len) = (data.len() / 16 * 16, data.len() % 16);
        let mut checksum = [0u8; 16];

        let mut plaintext = data.to_vec();
        for (idx, block) in plaintext[..full_len].chunks_exact_mut(16).enumerate() {
            let i = idx + 1;
            let tz = ntz(i);
            while l_table.len() <= tz {
                let next = dbl_block(*l_table.last().expect("L table non-empty"));
                l_table.push(next);
            }
            offset = xor_block(&offset, &l_table[tz]);

            let mut c = [0u8; 16];
            c.copy_from_slice(block);
            c = xor_block(&c, &offset);
            self.cipher.decrypt(&mut c);
            c = xor_block(&c, &offset);
            checksum = xor_block(&checksum, &c);
            block.copy_from_slice(&c);
        }

        if partial_len != 0 {
            offset = xor_block(&offset, &l_star);
            let mut pad = offset;
            self.cipher.encrypt(&mut pad);
            let partial = &mut plaintext[full_len..];
            for i in 0..partial.len() {
                partial[i] ^= pad[i];
            }
            let mut padded_p = [0u8; 16];
            padded_p[..partial.len()].copy_from_slice(partial);
            padded_p[partial.len()] = 0x80;
            checksum = xor_block(&checksum, &padded_p);
        }

        let mut tag_input = xor_block(&checksum, &offset);
        tag_input = xor_block(&tag_input, &l_dollar);
        self.cipher.encrypt(&mut tag_input);
        let expected = xor_block(&tag_input, &aad_hash);
        if crate::ct::constant_time_eq_mask(&expected, tag) != u8::MAX {
            return false;
        }

        data.copy_from_slice(&plaintext);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::Ocb;
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
    fn rfc7253_sample_vector_1_empty() {
        let key = <[u8; 16]>::try_from(unhex_ws("000102030405060708090A0B0C0D0E0F")).expect("key");
        let nonce = unhex_ws("BBAA99887766554433221100");
        let aad = [];
        let mut pt = vec![];
        let expected = unhex_ws("785407BFFFC8AD9EDCC5520AC9111EE6");

        let ocb = Ocb::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, &aad, &mut pt);
        assert_eq!(pt, Vec::<u8>::new());
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    #[test]
    fn rfc7253_sample_vector_2_short_aad_and_pt() {
        let key = <[u8; 16]>::try_from(unhex_ws("000102030405060708090A0B0C0D0E0F")).expect("key");
        let nonce = unhex_ws("BBAA99887766554433221101");
        let aad = unhex_ws("0001020304050607");
        let mut pt = unhex_ws("0001020304050607");
        let expected = unhex_ws("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009");

        let ocb = Ocb::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, &aad, &mut pt);
        let mut out = pt.clone();
        out.extend_from_slice(&tag);
        assert_eq!(out, expected);

        assert!(ocb.decrypt(&nonce, &aad, &mut pt, &tag));
        assert_eq!(pt, unhex_ws("0001020304050607"));
    }

    #[test]
    fn rfc7253_sample_vector_4_short_pt_no_aad() {
        let key = <[u8; 16]>::try_from(unhex_ws("000102030405060708090A0B0C0D0E0F")).expect("key");
        let nonce = unhex_ws("BBAA99887766554433221103");
        let aad = [];
        let mut pt = unhex_ws("0001020304050607");
        let expected = unhex_ws("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9");

        let ocb = Ocb::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, &aad, &mut pt);
        let mut out = pt.clone();
        out.extend_from_slice(&tag);
        assert_eq!(out, expected);
    }

    #[test]
    fn ocb_rejects_tampered_tag() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"aad";
        let mut msg = b"ocb message".to_vec();
        let ocb = Ocb::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, aad, &mut msg);

        let mut tampered_tag = tag;
        tampered_tag[0] ^= 1;
        let snapshot = msg.clone();
        assert!(!ocb.decrypt(&nonce, aad, &mut msg, &tampered_tag));
        assert_eq!(msg, snapshot);
    }
}
