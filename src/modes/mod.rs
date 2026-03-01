//! Generic block-cipher modes of operation.
//!
//! Implemented in this layer:
//!
//! - SP 800-38A confidentiality modes: ECB, CBC, CFB (full-block), OFB, CTR
//! - SP 800-38B authentication mode: CMAC
//! - SP 800-38D authenticated mode: GCM / GMAC
//! - SP 800-38E storage mode: XTS (128-bit block ciphers only)
//!
//! These adapters are generic over any `BlockCipher` in the crate, so the same
//! wrapper works with AES, DES, Camellia, PRESENT, and the other block
//! primitives exposed here.
//!
//! Higher-level special-purpose modes such as key wrap (SP 800-38F) and
//! AES-GCM-SIV (RFC 8452) are still intentionally left for a later layer; they
//! need additional domain-specific machinery beyond the basic block-cipher
//! adapters here.

use crate::BlockCipher;

#[inline]
fn assert_block_multiple<C: BlockCipher>(buf: &[u8]) {
    assert_eq!(
        buf.len() % C::BLOCK_LEN,
        0,
        "buffer length must be a multiple of the block length"
    );
}

#[inline]
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

#[inline]
fn increment_be(counter: &mut [u8]) {
    for b in counter.iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
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

#[inline]
fn assert_block_128<C: BlockCipher>() {
    assert_eq!(
        C::BLOCK_LEN,
        16,
        "this mode requires a 128-bit block cipher"
    );
}

#[inline]
fn xor_block16_in_place(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

#[inline]
fn increment_be32(counter: &mut [u8; 16]) {
    for b in counter[12..].iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

#[inline]
fn gf_mul_x_xts(tweak: &mut [u8; 16]) {
    // XTS treats the tweak as a little-endian polynomial element.
    let mut carry = 0u8;
    for b in tweak.iter_mut() {
        let next = *b >> 7;
        *b = (*b << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

#[inline]
fn xex_encrypt_block<C: BlockCipher>(cipher: &C, tweak: &[u8; 16], block: &mut [u8; 16]) {
    xor_block16_in_place(block, tweak);
    cipher.encrypt(block);
    xor_block16_in_place(block, tweak);
}

#[inline]
fn xex_decrypt_block<C: BlockCipher>(cipher: &C, tweak: &[u8; 16], block: &mut [u8; 16]) {
    xor_block16_in_place(block, tweak);
    cipher.decrypt(block);
    xor_block16_in_place(block, tweak);
}

#[inline]
fn ghash_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    // Portable reference GHASH multiplication. This is not constant-time; use
    // a CLMUL-backed implementation or a dedicated constant-time GHASH path in
    // production code with a strict side-channel threat model.
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if ((x >> (127 - i)) & 1) != 0 {
            z ^= v;
        }
        if (v & 1) == 0 {
            v >>= 1;
        } else {
            v = (v >> 1) ^ R;
        }
    }
    z
}

fn ghash_update(y: &mut u128, h: u128, data: &[u8]) {
    let mut block = [0u8; 16];
    for chunk in data.chunks(16) {
        block.fill(0);
        block[..chunk.len()].copy_from_slice(chunk);
        *y ^= u128::from_be_bytes(block);
        *y = ghash_mul(*y, h);
    }
}

fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut y = 0u128;
    ghash_update(&mut y, h, aad);
    ghash_update(&mut y, h, ciphertext);

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) << 3).to_be_bytes());
    y ^= u128::from_be_bytes(len_block);
    ghash_mul(y, h)
}

#[inline]
fn ghash_iv(h: u128, iv: &[u8]) -> [u8; 16] {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        return j0;
    }
    ghash(h, &[], iv).to_be_bytes()
}

#[inline]
fn gcm_hash_subkey<C: BlockCipher>(cipher: &C) -> u128 {
    let mut h = [0u8; 16];
    cipher.encrypt(&mut h);
    u128::from_be_bytes(h)
}

#[inline]
fn counter_keystream<C: BlockCipher>(cipher: &C, counter: &[u8; 16]) -> [u8; 16] {
    let mut out = *counter;
    cipher.encrypt(&mut out);
    out
}

fn gcm_compute_tag<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    assert_block_128::<C>();
    let h = gcm_hash_subkey(cipher);
    let j0 = ghash_iv(h, nonce);
    let s = ghash(h, aad, ciphertext);
    let tag_mask = u128::from_be_bytes(counter_keystream(cipher, &j0));
    (s ^ tag_mask).to_be_bytes()
}

fn gcm_compute_tag_with_h<C: BlockCipher>(
    cipher: &C,
    h: u128,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let j0 = ghash_iv(h, nonce);
    let s = ghash(h, aad, ciphertext);
    let tag_mask = u128::from_be_bytes(counter_keystream(cipher, &j0));
    (s ^ tag_mask).to_be_bytes()
}

/// Electronic Codebook (ECB) mode.
///
/// This is included because SP 800-38A defines it, but it should only be used
/// for single-block operations or controlled test vectors. It leaks repeated
/// plaintext patterns.
pub struct Ecb<C> {
    cipher: C,
}

impl<C> Ecb<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ecb<C> {
    pub fn encrypt_nopad(&self, data: &mut [u8]) {
        assert_block_multiple::<C>(data);
        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            self.cipher.encrypt(block);
        }
    }

    pub fn decrypt_nopad(&self, data: &mut [u8]) {
        assert_block_multiple::<C>(data);
        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            self.cipher.decrypt(block);
        }
    }
}

/// Cipher Block Chaining (CBC) mode.
pub struct Cbc<C> {
    cipher: C,
}

impl<C> Cbc<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Cbc<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn encrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut prev = iv.to_vec();
        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            xor_in_place(block, &prev);
            self.cipher.encrypt(block);
            prev.copy_from_slice(block);
        }
    }

    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn decrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut prev = iv.to_vec();
        let mut tmp = vec![0u8; C::BLOCK_LEN];

        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            tmp.copy_from_slice(block);
            self.cipher.decrypt(block);
            xor_in_place(block, &prev);
            prev.copy_from_slice(&tmp);
        }
    }
}

/// Cipher Feedback (CFB) mode with a segment size equal to the full block.
pub struct Cfb<C> {
    cipher: C,
}

impl<C> Cfb<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Cfb<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn encrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut feedback = iv.to_vec();
        let mut keystream = feedback.clone();

        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            keystream.copy_from_slice(&feedback);
            self.cipher.encrypt(&mut keystream);
            xor_in_place(block, &keystream);
            feedback.copy_from_slice(block);
        }
    }

    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn decrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut feedback = iv.to_vec();
        let mut keystream = feedback.clone();
        let mut tmp = vec![0u8; C::BLOCK_LEN];

        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            tmp.copy_from_slice(block);
            keystream.copy_from_slice(&feedback);
            self.cipher.encrypt(&mut keystream);
            xor_in_place(block, &keystream);
            feedback.copy_from_slice(&tmp);
        }
    }
}

/// Output Feedback (OFB) mode.
pub struct Ofb<C> {
    cipher: C,
}

impl<C> Ofb<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ofb<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size.
    pub fn apply_keystream(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");

        let mut feedback = iv.to_vec();
        for chunk in data.chunks_mut(C::BLOCK_LEN) {
            self.cipher.encrypt(&mut feedback);
            xor_in_place(chunk, &feedback[..chunk.len()]);
        }
    }
}

/// Counter (CTR) mode with a big-endian incrementing counter block.
pub struct Ctr<C> {
    cipher: C,
}

impl<C> Ctr<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ctr<C> {
    /// # Panics
    ///
    /// Panics if `counter.len()` does not match the block size.
    pub fn apply_keystream(&self, counter: &[u8], data: &mut [u8]) {
        assert_eq!(counter.len(), C::BLOCK_LEN, "wrong counter length");

        let mut ctr = counter.to_vec();
        let mut stream = ctr.clone();

        for chunk in data.chunks_mut(C::BLOCK_LEN) {
            stream.copy_from_slice(&ctr);
            self.cipher.encrypt(&mut stream);
            xor_in_place(chunk, &stream[..chunk.len()]);
            increment_be(&mut ctr);
        }
    }
}

/// XEX-based Tweaked `CodeBook` mode with ciphertext Stealing (XTS).
///
/// This implementation supports 128-bit block ciphers, which is the case
/// covered by SP 800-38E / XTS-AES.
pub struct Xts<C> {
    data_cipher: C,
    tweak_cipher: C,
}

impl<C> Xts<C> {
    pub fn new(data_cipher: C, tweak_cipher: C) -> Self {
        Self {
            data_cipher,
            tweak_cipher,
        }
    }

    pub fn data_cipher(&self) -> &C {
        &self.data_cipher
    }

    pub fn tweak_cipher(&self) -> &C {
        &self.tweak_cipher
    }
}

impl<C: BlockCipher> Xts<C> {
    /// # Panics
    ///
    /// Panics if the wrapped cipher does not have a 128-bit block size, or if
    /// `data` is shorter than one complete block.
    pub fn encrypt_sector(&self, tweak_value: &[u8; 16], data: &mut [u8]) {
        assert_block_128::<C>();
        assert!(
            data.len() >= 16,
            "XTS requires at least one complete block in each data unit"
        );

        let full_blocks = data.len() / 16;
        let rem = data.len() % 16;

        let mut tweak = *tweak_value;
        self.tweak_cipher.encrypt(&mut tweak);

        if rem == 0 {
            for block in data.chunks_exact_mut(16) {
                let mut tmp = [0u8; 16];
                tmp.copy_from_slice(block);
                xex_encrypt_block(&self.data_cipher, &tweak, &mut tmp);
                block.copy_from_slice(&tmp);
                gf_mul_x_xts(&mut tweak);
            }
            return;
        }

        for block in data[..(full_blocks - 1) * 16].chunks_exact_mut(16) {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(block);
            xex_encrypt_block(&self.data_cipher, &tweak, &mut tmp);
            block.copy_from_slice(&tmp);
            gf_mul_x_xts(&mut tweak);
        }

        let last_full_start = (full_blocks - 1) * 16;
        let mut cc = [0u8; 16];
        cc.copy_from_slice(&data[last_full_start..last_full_start + 16]);
        xex_encrypt_block(&self.data_cipher, &tweak, &mut cc);

        let mut pp = [0u8; 16];
        pp[..rem].copy_from_slice(&data[last_full_start + 16..]);
        pp[rem..].copy_from_slice(&cc[rem..]);
        data[last_full_start + 16..].copy_from_slice(&cc[..rem]);

        let mut next_tweak = tweak;
        gf_mul_x_xts(&mut next_tweak);
        xex_encrypt_block(&self.data_cipher, &next_tweak, &mut pp);
        data[last_full_start..last_full_start + 16].copy_from_slice(&pp);
    }

    /// # Panics
    ///
    /// Panics if the wrapped cipher does not have a 128-bit block size, or if
    /// `data` is shorter than one complete block.
    pub fn decrypt_sector(&self, tweak_value: &[u8; 16], data: &mut [u8]) {
        assert_block_128::<C>();
        assert!(
            data.len() >= 16,
            "XTS requires at least one complete block in each data unit"
        );

        let full_blocks = data.len() / 16;
        let rem = data.len() % 16;

        let mut tweak = *tweak_value;
        self.tweak_cipher.encrypt(&mut tweak);

        if rem == 0 {
            for block in data.chunks_exact_mut(16) {
                let mut tmp = [0u8; 16];
                tmp.copy_from_slice(block);
                xex_decrypt_block(&self.data_cipher, &tweak, &mut tmp);
                block.copy_from_slice(&tmp);
                gf_mul_x_xts(&mut tweak);
            }
            return;
        }

        for block in data[..(full_blocks - 1) * 16].chunks_exact_mut(16) {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(block);
            xex_decrypt_block(&self.data_cipher, &tweak, &mut tmp);
            block.copy_from_slice(&tmp);
            gf_mul_x_xts(&mut tweak);
        }

        let last_full_start = (full_blocks - 1) * 16;
        let mut next_tweak = tweak;
        gf_mul_x_xts(&mut next_tweak);

        let mut pp = [0u8; 16];
        pp.copy_from_slice(&data[last_full_start..last_full_start + 16]);
        xex_decrypt_block(&self.data_cipher, &next_tweak, &mut pp);

        let mut cc = [0u8; 16];
        cc[..rem].copy_from_slice(&data[last_full_start + 16..]);
        cc[rem..].copy_from_slice(&pp[rem..]);

        let mut last_full = cc;
        xex_decrypt_block(&self.data_cipher, &tweak, &mut last_full);

        data[last_full_start..last_full_start + 16].copy_from_slice(&last_full);
        data[last_full_start + 16..].copy_from_slice(&pp[..rem]);
    }
}

/// Cipher-based Message Authentication Code (CMAC).
pub struct Cmac<C> {
    cipher: C,
}

impl<C> Cmac<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

/// Galois/Counter Mode (GCM) with a full 128-bit authentication tag.
pub struct Gcm<C> {
    cipher: C,
}

impl<C> Gcm<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Gcm<C> {
    pub fn compute_tag(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        gcm_compute_tag(&self.cipher, nonce, aad, ciphertext)
    }

    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        assert_block_128::<C>();
        let mut h = [0u8; 16];
        self.cipher.encrypt(&mut h);
        let h = u128::from_be_bytes(h);
        let j0 = ghash_iv(h, nonce);
        let mut counter = j0;
        increment_be32(&mut counter);

        for chunk in data.chunks_mut(16) {
            let stream = counter_keystream(&self.cipher, &counter);
            xor_in_place(chunk, &stream[..chunk.len()]);
            increment_be32(&mut counter);
        }

        let s = ghash(h, aad, data);
        let tag_mask = u128::from_be_bytes(counter_keystream(&self.cipher, &j0));
        (s ^ tag_mask).to_be_bytes()
    }

    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        assert_block_128::<C>();
        let h = gcm_hash_subkey(&self.cipher);
        let expected = gcm_compute_tag_with_h(&self.cipher, h, nonce, aad, data);
        if !crate::ct::constant_time_eq(&expected, tag) {
            return false;
        }
        let j0 = ghash_iv(h, nonce);
        let mut counter = j0;
        increment_be32(&mut counter);

        for chunk in data.chunks_mut(16) {
            let stream = counter_keystream(&self.cipher, &counter);
            xor_in_place(chunk, &stream[..chunk.len()]);
            increment_be32(&mut counter);
        }

        true
    }
}

/// Galois Message Authentication Code (GMAC).
pub struct Gmac<C> {
    cipher: C,
}

impl<C> Gmac<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Gmac<C> {
    pub fn compute(&self, nonce: &[u8], aad: &[u8]) -> [u8; 16] {
        gcm_compute_tag(&self.cipher, nonce, aad, &[])
    }

    pub fn verify(&self, nonce: &[u8], aad: &[u8], tag: &[u8]) -> bool {
        crate::ct::constant_time_eq(&self.compute(nonce, aad), tag)
    }
}

impl<C: BlockCipher> Cmac<C> {
    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        let blk = C::BLOCK_LEN;
        let mut l = vec![0u8; blk];
        self.cipher.encrypt(&mut l);
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
            self.cipher.encrypt(&mut y);
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
        self.cipher.encrypt(&mut m_last);
        m_last
    }

    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        crate::ct::constant_time_eq(&self.compute(data), tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Aes128;
    fn parse<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for i in 0..N {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn ecb_aes128_sp800_38a() {
        let key = parse::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let mut data = [
            parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
            parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            parse::<16>("3ad77bb40d7a3660a89ecaf32466ef97"),
            parse::<16>("f5d3d58503b9699de785895a96fdbaaf"),
            parse::<16>("43b1cd7f598ece23881b00e3ed030688"),
            parse::<16>("7b0c785e27e8ad3f8223207104725dd4"),
        ]
        .concat();

        Ecb::new(Aes128::new(&key)).encrypt_nopad(&mut data);
        assert_eq!(data, expected);
        Ecb::new(Aes128::new(&key)).decrypt_nopad(&mut data);
        assert_eq!(
            data,
            [
                parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
                parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cbc_aes128_sp800_38a() {
        let key = parse::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = parse::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
            parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            parse::<16>("7649abac8119b246cee98e9b12e9197d"),
            parse::<16>("5086cb9b507219ee95db113a917678b2"),
            parse::<16>("73bed6b8e3c1743b7116e69e22229516"),
            parse::<16>("3ff1caa1681fac09120eca307586e1a7"),
        ]
        .concat();

        let mode = Cbc::new(Aes128::new(&key));
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(
            data,
            [
                parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
                parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cfb_aes128_sp800_38a() {
        let key = parse::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = parse::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
            parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            parse::<16>("3b3fd92eb72dad20333449f8e83cfb4a"),
            parse::<16>("c8a64537a0b3a93fcde3cdad9f1ce58b"),
            parse::<16>("26751f67a3cbb140b1808cf187a4f4df"),
            parse::<16>("c04b05357c5d1c0eeac4c66f9ff7f2e6"),
        ]
        .concat();

        let mode = Cfb::new(Aes128::new(&key));
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(
            data,
            [
                parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
                parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn ofb_aes128_sp800_38a() {
        let key = parse::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = parse::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
            parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            parse::<16>("3b3fd92eb72dad20333449f8e83cfb4a"),
            parse::<16>("7789508d16918f03f53c52dac54ed825"),
            parse::<16>("9740051e9c5fecf64344f7a82260edcc"),
            parse::<16>("304c6528f659c77866a510d9c1d6ae5e"),
        ]
        .concat();

        let mode = Ofb::new(Aes128::new(&key));
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(
            data,
            [
                parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
                parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn ctr_aes128_sp800_38a() {
        let key = parse::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let ctr = parse::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = [
            parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
            parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            parse::<16>("874d6191b620e3261bef6864990db6ce"),
            parse::<16>("9806f66b7970fdff8617187bb9fffdff"),
            parse::<16>("5ae4df3edbd5d35e5b4f09020db03eab"),
            parse::<16>("1e031dda2fbe03d1792170a0f3009cee"),
        ]
        .concat();

        let mode = Ctr::new(Aes128::new(&key));
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(
            data,
            [
                parse::<16>("6bc1bee22e409f96e93d7e117393172a"),
                parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                parse::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                parse::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cmac_aes128_sp800_38b() {
        let key = parse::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let mode = Cmac::new(Aes128::new(&key));

        assert_eq!(
            mode.compute(&[]),
            parse::<16>("bb1d6929e95937287fa37d129b756746").to_vec()
        );
        assert_eq!(
            mode.compute(&parse::<16>("6bc1bee22e409f96e93d7e117393172a")),
            parse::<16>("070a16b46b4d4144f79bdd9dd04a287c").to_vec()
        );
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&parse::<16>("6bc1bee22e409f96e93d7e117393172a"));
        msg.extend_from_slice(&parse::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"));
        msg.extend_from_slice(&parse::<8>("30c81c46a35ce411"));
        assert_eq!(
            mode.compute(&msg),
            parse::<16>("dfa66747de9ae63030ca32611497c827").to_vec()
        );
        assert!(mode.verify(&msg, &parse::<16>("dfa66747de9ae63030ca32611497c827")));
    }

    #[test]
    fn xts_aes128_two_block_matches_openssl() {
        let key1 = parse::<16>("000102030405060708090a0b0c0d0e0f");
        let key2 = parse::<16>("101112131415161718191a1b1c1d1e1f");
        let tweak = [0u8; 16];
        let mut data =
            parse::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let expected =
            parse::<32>("74a109aabf1937c022d19da4b96cbc40b8ddc9c0653a7fb0dc8425c7ef276dea");

        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_sector(&tweak, &mut data);
        assert_eq!(
            data,
            parse::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[test]
    fn xts_aes128_ciphertext_stealing_matches_openssl() {
        let key1 = parse::<16>("000102030405060708090a0b0c0d0e0f");
        let key2 = parse::<16>("101112131415161718191a1b1c1d1e1f");
        let tweak = [0u8; 16];
        let mut data =
            parse::<31>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let expected =
            parse::<31>("03ab02ee0037b6327b1110429d562a8674a109aabf1937c022d19da4b96cbc");

        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_sector(&tweak, &mut data);
        assert_eq!(
            data,
            parse::<31>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        );
    }

    #[test]
    fn xts_aes128_runtime_cross_check_with_openssl() {
        let key1 = parse::<16>("000102030405060708090a0b0c0d0e0f");
        let key2 = parse::<16>("101112131415161718191a1b1c1d1e1f");
        let tweak = [0u8; 16];
        let plaintext =
            parse::<31>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");

        let Some(expected) = crate::ct::run_openssl(
            &[
                "enc",
                "-aes-128-xts",
                "-e",
                "-nopad",
                "-K",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "-iv",
                "00000000000000000000000000000000",
            ],
            &plaintext,
        ) else {
            return;
        };

        let mut data = plaintext;
        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data.as_slice(), expected.as_slice());
    }

    #[test]
    fn ctr_des_roundtrip_generic() {
        let key = parse::<8>("133457799bbcdff1");
        let counter = parse::<8>("0123456789abcdef");
        let original = *b"generic DES mode path!";
        let mut data = original;

        let mode = Ctr::new(crate::Des::new(&key));
        mode.apply_keystream(&counter, &mut data);
        assert_ne!(data, original);
        mode.apply_keystream(&counter, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn gcm_aes128_empty_plaintext_nist() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut data = Vec::new();
        let mode = Gcm::new(Aes128::new(&key));

        let tag = mode.encrypt(&iv, &[], &mut data);
        assert_eq!(data, Vec::<u8>::new());
        assert_eq!(tag, parse::<16>("58e2fccefa7e3061367f1d57a4e7455a"));
        assert!(mode.decrypt(&iv, &[], &mut data, &tag));
    }

    #[test]
    fn gcm_aes128_single_block_nist() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut data = [0u8; 16];
        let expected_ct = parse::<16>("0388dace60b6a392f328c2b971b2fe78");
        let expected_tag = parse::<16>("ab6e47d42cec13bdf53a67b21257bddf");
        let mode = Gcm::new(Aes128::new(&key));

        let tag = mode.encrypt(&iv, &[], &mut data);
        assert_eq!(data, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&iv, &[], &mut data, &tag));
        assert_eq!(data, [0u8; 16]);
    }

    #[test]
    fn gcm_aes128_with_aad_nist() {
        let key = parse::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = parse::<12>("cafebabefacedbaddecaf888");
        let aad = parse::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut data = parse::<64>(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b391aafd255",
        );
        let expected_ct = parse::<64>(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091473f5985",
        );
        let expected_tag = parse::<16>("da80ce830cfda02da2a218a1744f4c76");
        let mode = Gcm::new(Aes128::new(&key));

        let tag = mode.encrypt(&iv, &aad, &mut data);
        assert_eq!(data, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&iv, &aad, &mut data, &tag));
        assert_eq!(
            data,
            parse::<64>(
                "d9313225f88406e5a55909c5aff5269a\
                 86a7a9531534f7da2e4c303d8a318a72\
                 1c3c0c95956809532fcf0e2449a6b525\
                 b16aedf5aa0de657ba637b391aafd255",
            )
        );
    }

    #[test]
    fn gcm_rejects_wrong_tag_without_decrypting() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut data = [0u8; 16];
        let mode = Gcm::new(Aes128::new(&key));
        let tag = mode.encrypt(&iv, &[], &mut data);
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let ciphertext = data;

        assert!(!mode.decrypt(&iv, &[], &mut data, &bad_tag));
        assert_eq!(data, ciphertext);
    }

    #[test]
    fn gmac_matches_gcm_on_empty_plaintext() {
        let key = parse::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = parse::<12>("cafebabefacedbaddecaf888");
        let aad = parse::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let gcm = Gcm::new(Aes128::new(&key));
        let gmac = Gmac::new(Aes128::new(&key));
        let tag = gmac.compute(&iv, &aad);

        assert_eq!(tag, gcm.compute_tag(&iv, &aad, &[]));
        assert!(gmac.verify(&iv, &aad, &tag));
    }
}
