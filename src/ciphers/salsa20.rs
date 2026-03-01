#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::inline_always,
    clippy::must_use_candidate,
    clippy::trivially_copy_pass_by_ref
)]

//! Salsa20 stream cipher — Daniel J. Bernstein's original Snuffle design.
//!
//! This is the standard 20-round Salsa20 core with an 8-byte nonce and a
//! 64-byte keystream block. It supports both the original 16-byte and 32-byte
//! key forms from the published specification.

const SIGMA: [u8; 16] = *b"expand 32-byte k";
const TAU: [u8; 16] = *b"expand 16-byte k";

#[inline(always)]
fn load_u32_le(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(bytes);
    u32::from_le_bytes(tmp)
}

#[inline(always)]
fn quarter_round(y0: &mut u32, y1: &mut u32, y2: &mut u32, y3: &mut u32) {
    *y1 ^= y0.wrapping_add(*y3).rotate_left(7);
    *y2 ^= y1.wrapping_add(*y0).rotate_left(9);
    *y3 ^= y2.wrapping_add(*y1).rotate_left(13);
    *y0 ^= y3.wrapping_add(*y2).rotate_left(18);
}

#[inline]
fn salsa20_block(state: &[u32; 16]) -> [u8; 64] {
    let mut x = *state;

    for _ in 0..10 {
        let (mut y0, mut y4, mut y8, mut y12) = (x[0], x[4], x[8], x[12]);
        quarter_round(&mut y0, &mut y4, &mut y8, &mut y12);
        (x[0], x[4], x[8], x[12]) = (y0, y4, y8, y12);

        let (mut y5, mut y9, mut y13, mut y1) = (x[5], x[9], x[13], x[1]);
        quarter_round(&mut y5, &mut y9, &mut y13, &mut y1);
        (x[5], x[9], x[13], x[1]) = (y5, y9, y13, y1);

        let (mut y10, mut y14, mut y2, mut y6) = (x[10], x[14], x[2], x[6]);
        quarter_round(&mut y10, &mut y14, &mut y2, &mut y6);
        (x[10], x[14], x[2], x[6]) = (y10, y14, y2, y6);

        let (mut y15, mut y3, mut y7, mut y11) = (x[15], x[3], x[7], x[11]);
        quarter_round(&mut y15, &mut y3, &mut y7, &mut y11);
        (x[15], x[3], x[7], x[11]) = (y15, y3, y7, y11);

        let (mut y0, mut y1, mut y2, mut y3) = (x[0], x[1], x[2], x[3]);
        quarter_round(&mut y0, &mut y1, &mut y2, &mut y3);
        (x[0], x[1], x[2], x[3]) = (y0, y1, y2, y3);

        let (mut y5, mut y6, mut y7, mut y4) = (x[5], x[6], x[7], x[4]);
        quarter_round(&mut y5, &mut y6, &mut y7, &mut y4);
        (x[5], x[6], x[7], x[4]) = (y5, y6, y7, y4);

        let (mut y10, mut y11, mut y8, mut y9) = (x[10], x[11], x[8], x[9]);
        quarter_round(&mut y10, &mut y11, &mut y8, &mut y9);
        (x[10], x[11], x[8], x[9]) = (y10, y11, y8, y9);

        let (mut y15, mut y12, mut y13, mut y14) = (x[15], x[12], x[13], x[14]);
        quarter_round(&mut y15, &mut y12, &mut y13, &mut y14);
        (x[15], x[12], x[13], x[14]) = (y15, y12, y13, y14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

#[inline]
fn key_setup(key: &[u8], nonce: &[u8; 8], counter: u64) -> [u32; 16] {
    assert!(
        key.len() == 16 || key.len() == 32,
        "Salsa20 key length must be 16 or 32 bytes, got {}",
        key.len()
    );

    let constants = if key.len() == 32 { &SIGMA } else { &TAU };
    let k0 = &key[..16];
    let k1 = if key.len() == 32 {
        &key[16..32]
    } else {
        &key[..16]
    };

    [
        load_u32_le(&constants[0..4]),
        load_u32_le(&k0[0..4]),
        load_u32_le(&k0[4..8]),
        load_u32_le(&k0[8..12]),
        load_u32_le(&k0[12..16]),
        load_u32_le(&constants[4..8]),
        load_u32_le(&nonce[0..4]),
        load_u32_le(&nonce[4..8]),
        counter as u32,
        (counter >> 32) as u32,
        load_u32_le(&constants[8..12]),
        load_u32_le(&k1[0..4]),
        load_u32_le(&k1[4..8]),
        load_u32_le(&k1[8..12]),
        load_u32_le(&k1[12..16]),
        load_u32_le(&constants[12..16]),
    ]
}

/// Salsa20 stream cipher (20-round variant).
///
/// `Salsa20` keeps its 16-word state plus one cached 64-byte keystream block.
/// `apply_keystream` XORs the generated stream into caller-owned buffers, so
/// the same method handles both encryption and decryption.
pub struct Salsa20 {
    state: [u32; 16],
    block: [u8; 64],
    offset: usize,
}

impl Salsa20 {
    /// Create a Salsa20 instance with a 32-byte key and 8-byte nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        Self::with_key_bytes(key, nonce)
    }

    /// Create a Salsa20 instance with either a 16-byte or 32-byte key.
    pub fn with_key_bytes(key: &[u8], nonce: &[u8; 8]) -> Self {
        Self::with_counter(key, nonce, 0)
    }

    /// Create a Salsa20 instance at an arbitrary 64-byte block counter.
    pub fn with_counter(key: &[u8], nonce: &[u8; 8], counter: u64) -> Self {
        Self {
            state: key_setup(key, nonce, counter),
            block: [0u8; 64],
            offset: 64,
        }
    }

    /// Create with a 32-byte key and wipe the caller's key and nonce buffers.
    pub fn new_wiping(key: &mut [u8; 32], nonce: &mut [u8; 8]) -> Self {
        let out = Self::new(key, nonce);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        out
    }

    /// Create with a 16- or 32-byte key and wipe the caller's key and nonce.
    pub fn with_key_bytes_wiping(key: &mut [u8], nonce: &mut [u8; 8]) -> Self {
        let out = Self::with_key_bytes(key, nonce);
        crate::ct::zeroize_slice(key);
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        out
    }

    #[inline]
    fn refill(&mut self) {
        self.block = salsa20_block(&self.state);
        self.offset = 0;
        self.state[8] = self.state[8].wrapping_add(1);
        if self.state[8] == 0 {
            self.state[9] = self.state[9].wrapping_add(1);
        }
    }

    /// XOR the Salsa20 keystream into `buf` in place.
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

    /// Return the next 64 bytes of keystream, respecting the current stream position.
    pub fn keystream_block(&mut self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.apply_keystream(&mut out);
        out
    }

    /// Seek to a 64-byte block boundary.
    pub fn set_counter(&mut self, counter: u64) {
        self.state[8] = counter as u32;
        self.state[9] = (counter >> 32) as u32;
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 64;
    }
}

impl Drop for Salsa20 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 0;
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
    fn salsa20_128bit_estream_vector0_first_block() {
        let mut key = [0u8; 16];
        key[0] = 0x80;
        let nonce = [0u8; 8];
        let mut s = Salsa20::with_key_bytes(&key, &nonce);
        let block = s.keystream_block();
        assert_eq!(
            hex(&block),
            "4dfa5e481da23ea09a31022050859936".to_owned()
                + "da52fcee218005164f267cb65f5cfd7f"
                + "2b4f97e0ff16924a52df269515110a07"
                + "f9e460bc65ef95da58f740b7d1dbb0aa"
        );
    }

    #[test]
    fn salsa20_256bit_estream_vector0_first_block() {
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let nonce = [0u8; 8];
        let mut s = Salsa20::new(&key, &nonce);
        let block = s.keystream_block();
        assert_eq!(
            hex(&block),
            "e3be8fdd8beca2e3ea8ef9475b29a6e7".to_owned()
                + "003951e1097a5c38d23b7a5fad9f6844"
                + "b22c97559e2723c7cbbd3fe4fc8d9a07"
                + "44652a83e72a9c461876af4d7ef1a117"
        );
    }

    #[test]
    fn salsa20_roundtrip_xor() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 8];
        let msg = *b"the same function encrypts and decrypts with xor.....";

        let mut enc = Salsa20::new(&key, &nonce);
        let mut ct = msg;
        enc.apply_keystream(&mut ct);

        let mut dec = Salsa20::new(&key, &nonce);
        dec.apply_keystream(&mut ct);

        assert_eq!(ct, msg);
    }

    #[test]
    fn salsa20_chunked_stream_matches_one_shot() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 8];

        let mut one = Salsa20::new(&key, &nonce);
        let mut full = [0u8; 96];
        one.fill(&mut full);

        let mut two = Salsa20::new(&key, &nonce);
        let mut split = [0u8; 96];
        two.fill(&mut split[..17]);
        two.fill(&mut split[17..81]);
        two.fill(&mut split[81..]);

        assert_eq!(full, split);
    }
}
