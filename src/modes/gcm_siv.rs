//! AES-GCM-SIV (RFC 8452).
//!
//! This module provides fixed-profile AES-128-GCM-SIV and AES-256-GCM-SIV
//! constructions with 96-bit nonces and 16-byte detached tags.

use crate::{Aes128, Aes256, BlockCipher};

#[inline]
fn ghash_mul(x: u128, y: u128) -> u128 {
    // SP 800-38D field polynomial x^128 + x^7 + x^2 + x + 1, reused by POLYVAL
    // through byte/bit reversal in RFC 8452. In reflected GHASH bit order,
    // x^7 + x^2 + x + 1 is encoded as 0xe1 in the most-significant byte.
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        // Branch-free conditional xor via all-ones/all-zero masks.
        let bit = u8::try_from((x >> (127 - i)) & 1).expect("single bit");
        let bit_mask = 0u128.wrapping_sub(u128::from(bit));
        z ^= v & bit_mask;

        let lsb = u8::try_from(v & 1).expect("single bit");
        let lsb_mask = 0u128.wrapping_sub(u128::from(lsb));
        v = (v >> 1) ^ (R & lsb_mask);
    }
    z
}

#[inline]
fn mulx_ghash(v: u128) -> u128 {
    // Multiply by x in the reflected GHASH field representation.
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
    if (v & 1) != 0 {
        (v >> 1) ^ R
    } else {
        v >> 1
    }
}

#[inline]
fn byte_reverse(block: [u8; 16]) -> [u8; 16] {
    let mut out = block;
    out.reverse();
    out
}

fn polyval(h: [u8; 16], input: &[u8]) -> [u8; 16] {
    let h_ghash = mulx_ghash(u128::from_be_bytes(byte_reverse(h)));
    let mut acc = 0u128;
    for chunk in input.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        acc ^= u128::from_be_bytes(byte_reverse(block));
        acc = ghash_mul(acc, h_ghash);
    }
    byte_reverse(acc.to_be_bytes())
}

#[inline]
fn pad16(input: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(input);
    if !input.len().is_multiple_of(16) {
        out.resize(out.len() + (16 - (input.len() % 16)), 0);
    }
}

fn gcm_siv_s_input(aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        aad.len()
            + ((16 - (aad.len() % 16)) % 16)
            + plaintext.len()
            + ((16 - (plaintext.len() % 16)) % 16)
            + 16,
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

enum EncCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl EncCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        match self {
            Self::Aes128(c) => c.encrypt(block),
            Self::Aes256(c) => c.encrypt(block),
        }
    }
}

fn derive_keys<C: BlockCipher>(
    keygen: &C,
    nonce: &[u8; 12],
    aes256_enc: bool,
) -> ([u8; 16], Vec<u8>, EncCipher) {
    let mut outs = [[0u8; 16]; 6];
    let count = if aes256_enc { 6 } else { 4 };
    for (i, slot) in outs.iter_mut().take(count).enumerate() {
        let mut block = [0u8; 16];
        let i_u32 = u32::try_from(i).expect("counter fits u32");
        block[..4].copy_from_slice(&i_u32.to_le_bytes());
        block[4..].copy_from_slice(nonce);
        keygen.encrypt(&mut block);
        *slot = block;
    }

    let mut auth_key = [0u8; 16];
    auth_key[..8].copy_from_slice(&outs[0][..8]);
    auth_key[8..].copy_from_slice(&outs[1][..8]);

    if aes256_enc {
        let mut enc_key = [0u8; 32];
        enc_key[..8].copy_from_slice(&outs[2][..8]);
        enc_key[8..16].copy_from_slice(&outs[3][..8]);
        enc_key[16..24].copy_from_slice(&outs[4][..8]);
        enc_key[24..32].copy_from_slice(&outs[5][..8]);
        (
            auth_key,
            enc_key.to_vec(),
            EncCipher::Aes256(Aes256::new(&enc_key)),
        )
    } else {
        let mut enc_key = [0u8; 16];
        enc_key[..8].copy_from_slice(&outs[2][..8]);
        enc_key[8..].copy_from_slice(&outs[3][..8]);
        (
            auth_key,
            enc_key.to_vec(),
            EncCipher::Aes128(Aes128::new(&enc_key)),
        )
    }
}

fn encrypt_core<C: BlockCipher>(
    keygen: &C,
    aes256_enc: bool,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16], [u8; 16], EncCipher) {
    assert!(aad.len() <= (1usize << 36), "AAD exceeds RFC 8452 limit");
    assert!(
        plaintext.len() <= (1usize << 36),
        "plaintext exceeds RFC 8452 limit"
    );

    let (auth_key, _enc_key, enc_cipher) = derive_keys(keygen, nonce, aes256_enc);
    let s_input = gcm_siv_s_input(aad, plaintext);
    let mut s = polyval(auth_key, &s_input);
    for i in 0..12 {
        s[i] ^= nonce[i];
    }
    s[15] &= 0x7f;

    let mut tag = s;
    enc_cipher.encrypt_block(&mut tag);

    let mut counter = tag;
    counter[15] |= 0x80;
    let ciphertext = aes_ctr_le32_enc(&enc_cipher, &counter, plaintext);
    (ciphertext, tag, auth_key, enc_cipher)
}

fn aes_ctr_le32_enc(enc: &EncCipher, initial_counter: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut block = *initial_counter;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let mut stream = block;
        enc.encrypt_block(&mut stream);
        for i in 0..chunk.len() {
            out.push(chunk[i] ^ stream[i]);
        }
        increment_le32(&mut block);
    }
    out
}

/// AES-128-GCM-SIV (RFC 8452).
pub struct Aes128GcmSiv {
    keygen: Aes128,
}

impl Aes128GcmSiv {
    /// Construct from a 128-bit key-generating key.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            keygen: Aes128::new(key),
        }
    }

    /// Encrypt `data` in place and return a detached 16-byte tag.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let (ciphertext, tag, _, _) = encrypt_core(&self.keygen, false, nonce, aad, data);
        data.copy_from_slice(&ciphertext);
        tag
    }

    /// Verify and decrypt in place.
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let (_, _, _, enc_cipher) = encrypt_core(&self.keygen, false, nonce, aad, &[]);
        let mut counter = *tag;
        counter[15] |= 0x80;
        let mut plaintext = aes_ctr_le32_enc(&enc_cipher, &counter, data);
        let (_, expected_tag, _, _) = encrypt_core(&self.keygen, false, nonce, aad, &plaintext);
        if crate::ct::constant_time_eq_mask(&expected_tag, tag) != u8::MAX {
            crate::ct::zeroize_slice(&mut plaintext);
            return false;
        }
        data.copy_from_slice(&plaintext);
        true
    }
}

/// AES-256-GCM-SIV (RFC 8452).
pub struct Aes256GcmSiv {
    keygen: Aes256,
}

impl Aes256GcmSiv {
    /// Construct from a 256-bit key-generating key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            keygen: Aes256::new(key),
        }
    }

    /// Encrypt `data` in place and return a detached 16-byte tag.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let (ciphertext, tag, _, _) = encrypt_core(&self.keygen, true, nonce, aad, data);
        data.copy_from_slice(&ciphertext);
        tag
    }

    /// Verify and decrypt in place.
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let (_, _, _, enc_cipher) = encrypt_core(&self.keygen, true, nonce, aad, &[]);
        let mut counter = *tag;
        counter[15] |= 0x80;
        let mut plaintext = aes_ctr_le32_enc(&enc_cipher, &counter, data);
        let (_, expected_tag, _, _) = encrypt_core(&self.keygen, true, nonce, aad, &plaintext);
        if crate::ct::constant_time_eq_mask(&expected_tag, tag) != u8::MAX {
            crate::ct::zeroize_slice(&mut plaintext);
            return false;
        }
        data.copy_from_slice(&plaintext);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_keys, polyval, Aes128GcmSiv};
    use crate::{Aes128, Aes256GcmSiv};

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
    fn polyval_worked_example_rfc8452_appendix_a() {
        let h = <[u8; 16]>::try_from(unhex_ws("25629347589242761d31f826ba4b757b")).expect("h");
        let x1 = <[u8; 16]>::try_from(unhex_ws("4f4f95668c83dfb6401762bb2d01a262")).expect("x1");
        let x2 = <[u8; 16]>::try_from(unhex_ws("d1a24ddd2721d006bbe45f20d3c9f362")).expect("x2");
        let mut input = Vec::new();
        input.extend_from_slice(&x1);
        input.extend_from_slice(&x2);
        assert_eq!(
            polyval(h, &input),
            <[u8; 16]>::try_from(unhex_ws("f7a3b47b846119fae5b7866cf5e5b77e")).expect("out")
        );
    }

    #[test]
    fn derive_keys_match_first_rfc8452_vector() {
        let key = <[u8; 16]>::try_from(unhex_ws("01000000000000000000000000000000")).expect("key");
        let nonce = <[u8; 12]>::try_from(unhex_ws("030000000000000000000000")).expect("nonce");
        let keygen = Aes128::new(&key);
        let (auth_key, enc_key, enc_cipher) = derive_keys(&keygen, &nonce, false);
        assert_eq!(
            auth_key,
            <[u8; 16]>::try_from(unhex_ws("d9b360279694941ac5dbc6987ada7377")).expect("ak")
        );
        assert_eq!(enc_key, unhex_ws("4004a0dcd862f2a57360219d2d44ef6c"));
        match enc_cipher {
            super::EncCipher::Aes128(_) => {}
            _ => panic!("expected AES-128 enc key"),
        };
    }

    #[test]
    fn rfc8452_c1_first_three_vectors_encrypt_and_decrypt() {
        let key = <[u8; 16]>::try_from(unhex_ws("01000000000000000000000000000000")).expect("key");
        let nonce = <[u8; 12]>::try_from(unhex_ws("030000000000000000000000")).expect("nonce");
        let aead = Aes128GcmSiv::new(&key);

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
            let mut data = unhex_ws(pt_hex);
            let expected = unhex_ws(result_hex);
            let tag = aead.encrypt(&nonce, &[], &mut data);

            let mut combined = data.clone();
            combined.extend_from_slice(&tag);
            assert_eq!(combined, expected);

            assert!(aead.decrypt(&nonce, &[], &mut data, &tag));
            assert_eq!(data, unhex_ws(pt_hex));
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
}
