#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::inline_always,
    clippy::must_use_candidate,
    clippy::trivially_copy_pass_by_ref
)]

//! ChaCha20 and XChaCha20 stream ciphers.
//!
//! `ChaCha20` follows RFC 8439: 20 rounds, 32-byte key, 12-byte nonce, and a
//! 32-bit block counter. `XChaCha20` derives a one-time subkey with HChaCha20
//! from the first 16 bytes of a 24-byte nonce, then uses the remaining 8 bytes
//! in the IETF ChaCha20 layout.

const CONSTANTS: [u8; 16] = *b"expand 32-byte k";

#[inline(always)]
fn load_u32_le(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(bytes);
    u32::from_le_bytes(tmp)
}

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut xa, mut xb, mut xc, mut xd) = (state[a], state[b], state[c], state[d]);

    xa = xa.wrapping_add(xb);
    xd ^= xa;
    xd = xd.rotate_left(16);

    xc = xc.wrapping_add(xd);
    xb ^= xc;
    xb = xb.rotate_left(12);

    xa = xa.wrapping_add(xb);
    xd ^= xa;
    xd = xd.rotate_left(8);

    xc = xc.wrapping_add(xd);
    xb ^= xc;
    xb = xb.rotate_left(7);

    (state[a], state[b], state[c], state[d]) = (xa, xb, xc, xd);
}

#[inline]
fn chacha20_block_words(state: &[u32; 16]) -> [u32; 16] {
    let mut x = *state;

    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);

        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }

    for i in 0..16 {
        x[i] = x[i].wrapping_add(state[i]);
    }

    x
}

#[inline]
fn chacha20_block_bytes(state: &[u32; 16]) -> [u8; 64] {
    let words = chacha20_block_words(state);
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&words[i].to_le_bytes());
    }
    out
}

#[inline]
fn state_from_key_nonce(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    [
        load_u32_le(&CONSTANTS[0..4]),
        load_u32_le(&CONSTANTS[4..8]),
        load_u32_le(&CONSTANTS[8..12]),
        load_u32_le(&CONSTANTS[12..16]),
        load_u32_le(&key[0..4]),
        load_u32_le(&key[4..8]),
        load_u32_le(&key[8..12]),
        load_u32_le(&key[12..16]),
        load_u32_le(&key[16..20]),
        load_u32_le(&key[20..24]),
        load_u32_le(&key[24..28]),
        load_u32_le(&key[28..32]),
        counter,
        load_u32_le(&nonce[0..4]),
        load_u32_le(&nonce[4..8]),
        load_u32_le(&nonce[8..12]),
    ]
}

#[inline]
fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [
        load_u32_le(&CONSTANTS[0..4]),
        load_u32_le(&CONSTANTS[4..8]),
        load_u32_le(&CONSTANTS[8..12]),
        load_u32_le(&CONSTANTS[12..16]),
        load_u32_le(&key[0..4]),
        load_u32_le(&key[4..8]),
        load_u32_le(&key[8..12]),
        load_u32_le(&key[12..16]),
        load_u32_le(&key[16..20]),
        load_u32_le(&key[20..24]),
        load_u32_le(&key[24..28]),
        load_u32_le(&key[28..32]),
        load_u32_le(&nonce[0..4]),
        load_u32_le(&nonce[4..8]),
        load_u32_le(&nonce[8..12]),
        load_u32_le(&nonce[12..16]),
    ];

    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let output = [
        state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15],
    ];
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&output[i].to_le_bytes());
    }
    out
}

/// ChaCha20 stream cipher (RFC 8439 / IETF variant).
pub struct ChaCha20 {
    state: [u32; 16],
    block: [u8; 64],
    offset: usize,
}

impl ChaCha20 {
    /// Create a ChaCha20 instance with a 32-byte key, 12-byte nonce, and counter 0.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self::with_counter(key, nonce, 0)
    }

    /// Create a ChaCha20 instance at an arbitrary 64-byte block counter.
    pub fn with_counter(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        Self {
            state: state_from_key_nonce(key, nonce, counter),
            block: [0u8; 64],
            offset: 64,
        }
    }

    /// Create and wipe the caller's key and nonce buffers.
    pub fn new_wiping(key: &mut [u8; 32], nonce: &mut [u8; 12]) -> Self {
        let out = Self::new(key, nonce);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        out
    }

    #[inline]
    fn refill(&mut self) {
        self.block = chacha20_block_bytes(&self.state);
        self.offset = 0;
        self.state[12] = self.state[12].wrapping_add(1);
    }

    /// XOR the ChaCha20 keystream into `buf` in place.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let mut done = 0usize;
        while done < buf.len() {
            if self.offset == 64 {
                self.refill();
            }
            let take = core::cmp::min(64 - self.offset, buf.len() - done);
            for i in 0..take {
                buf[done + i] ^= self.block[self.offset + i];
            }
            self.offset += take;
            done += take;
        }
    }

    /// Fill `buf` with keystream bytes by XORing into the existing contents.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.apply_keystream(buf);
    }

    /// Return the next 64 bytes of keystream.
    pub fn keystream_block(&mut self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.apply_keystream(&mut out);
        out
    }

    /// Seek to a 64-byte block boundary.
    pub fn set_counter(&mut self, counter: u32) {
        self.state[12] = counter;
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 64;
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 0;
    }
}

/// XChaCha20 stream cipher using HChaCha20-derived subkeys.
pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    /// Create an XChaCha20 instance with a 32-byte key and 24-byte nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        Self::with_counter(key, nonce, 0)
    }

    /// Create an XChaCha20 instance at an arbitrary 64-byte block counter.
    pub fn with_counter(key: &[u8; 32], nonce: &[u8; 24], counter: u32) -> Self {
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&nonce[..16]);
        let mut subkey = hchacha20(key, &prefix);

        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..]);

        let inner = ChaCha20::with_counter(&subkey, &chacha_nonce, counter);
        crate::ct::zeroize_slice(subkey.as_mut_slice());
        Self { inner }
    }

    /// Create and wipe the caller's key and nonce buffers.
    pub fn new_wiping(key: &mut [u8; 32], nonce: &mut [u8; 24]) -> Self {
        let out = Self::new(key, nonce);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        out
    }

    /// XOR the XChaCha20 keystream into `buf` in place.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.inner.apply_keystream(buf);
    }

    /// Fill `buf` with keystream bytes by XORing into the existing contents.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.inner.fill(buf);
    }

    /// Return the next 64 bytes of keystream.
    pub fn keystream_block(&mut self) -> [u8; 64] {
        self.inner.keystream_block()
    }

    /// Seek to a 64-byte block boundary.
    pub fn set_counter(&mut self, counter: u32) {
        self.inner.set_counter(counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    #[test]
    fn chacha20_rfc8439_block1_vector() {
        let mut key = [0u8; 32];
        for i in 0u8..32 {
            key[usize::from(i)] = i;
        }
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut c = ChaCha20::with_counter(&key, &nonce, 1);
        let block = c.keystream_block();
        assert_eq!(
            hex(&block),
            "10f1e7e4d13b5915500fdd1fa32071c4".to_owned()
                + "c7d1f4c733c068030422aa9ac3d46c4e"
                + "d2826446079faa0914c2d705d98b02a2"
                + "b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn hchacha20_draft_vector() {
        let mut key = [0u8; 32];
        for i in 0u8..32 {
            key[usize::from(i)] = i;
        }
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        let subkey = hchacha20(&key, &nonce);
        assert_eq!(
            hex(&subkey),
            "82413b4227b27bfed30e42508a877d73".to_owned() + "a0f9e4d58a74a853c12ec41326d3ecdc"
        );
    }

    #[test]
    fn xchacha20_matches_hchacha20_plus_chacha20() {
        let mut key = [0u8; 32];
        for i in 0u8..32 {
            key[usize::from(i)] = i.wrapping_mul(7);
        }
        let mut nonce = [0u8; 24];
        for i in 0u8..24 {
            nonce[usize::from(i)] = i.wrapping_mul(11);
        }

        let mut x = XChaCha20::with_counter(&key, &nonce, 5);
        let mut x_stream = [0u8; 96];
        x.fill(&mut x_stream);

        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&nonce[..16]);
        let mut subkey = hchacha20(&key, &prefix);
        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..]);
        let mut c = ChaCha20::with_counter(&subkey, &chacha_nonce, 5);
        let mut c_stream = [0u8; 96];
        c.fill(&mut c_stream);
        crate::ct::zeroize_slice(subkey.as_mut_slice());

        assert_eq!(x_stream, c_stream);
    }

    #[test]
    fn chacha20_roundtrip_xor() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let msg = *b"chacha20 applies its stream directly to caller buffers....";

        let mut enc = ChaCha20::new(&key, &nonce);
        let mut ct = msg;
        enc.apply_keystream(&mut ct);

        let mut dec = ChaCha20::new(&key, &nonce);
        dec.apply_keystream(&mut ct);

        assert_eq!(ct, msg);
    }
}
