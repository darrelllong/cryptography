//! `ChaCha20` and `XChaCha20` stream ciphers.
//!
//! `ChaCha20` follows RFC 8439: 20 rounds, 32-byte key, 12-byte nonce, and a
//! 32-bit block counter. `XChaCha20` derives a one-time subkey with `HChaCha20`
//! from the first 16 bytes of a 24-byte nonce, then uses the remaining 8 bytes
//! in the IETF `ChaCha20` layout.
//!
//! The design intent is the same as in the `ChaCha` paper and later RFC profile:
//! keep the core purely ARX (add-rotate-XOR) so software implementations are
//! fast, portable, and naturally closer to constant-time than table-driven
//! stream ciphers.

const CONSTANTS: [u8; 16] = *b"expand 32-byte k";

#[inline]
fn load_u32_le(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(bytes);
    u32::from_le_bytes(tmp)
}

#[inline]
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

/// The 20 ChaCha rounds (ten column-then-diagonal double rounds) in place.
#[inline]
fn chacha20_rounds(x: &mut [u32; 16]) {
    for _ in 0..10 {
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 1, 5, 9, 13);
        quarter_round(x, 2, 6, 10, 14);
        quarter_round(x, 3, 7, 11, 15);

        quarter_round(x, 0, 5, 10, 15);
        quarter_round(x, 1, 6, 11, 12);
        quarter_round(x, 2, 7, 8, 13);
        quarter_round(x, 3, 4, 9, 14);
    }
}

/// One ChaCha20 block (RFC 8439 §2.3) for `state`, serialized into `out`.
///
/// The permuted working copy is wiped before returning: it differs from the
/// keystream block by exactly the input state, so the two together would
/// reveal the key.
#[inline]
fn chacha20_block_into(state: &[u32; 16], out: &mut [u8; 64]) {
    let mut x = *state;
    chacha20_rounds(&mut x);
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
    }
    crate::ct::zeroize_slice(x.as_mut_slice());
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

    chacha20_rounds(&mut state);

    // HChaCha20 keeps the "outer" words after 20 rounds; that is exactly the
    // subkey extraction step the XChaCha construction uses to turn a 24-byte
    // nonce into a one-time ChaCha20 key.
    let mut out = [0u8; 32];
    for (i, word) in [0usize, 1, 2, 3, 12, 13, 14, 15].into_iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&state[word].to_le_bytes());
    }
    // Without ChaCha's feed-forward the rounds are an invertible permutation,
    // so the full permuted state would give back the key: only the subkey
    // words may leave this function.
    crate::ct::zeroize_slice(state.as_mut_slice());
    out
}

/// `ChaCha20` stream cipher (RFC 8439 / IETF variant).
///
/// The block counter is 32 bits, so one `(key, nonce)` addresses at most 2^32
/// blocks (2^38 bytes) of keystream. A request for keystream past the block at
/// counter `u32::MAX` panics instead of wrapping to block 0 and repeating
/// keystream; [`ChaCha20::set_counter`] starts a new range.
pub struct ChaCha20 {
    state: [u32; 16],
    block: [u8; 64],
    offset: usize,
    // Set once the block for counter `u32::MAX` has been generated: the
    // counter has no further value to take.
    exhausted: bool,
}

impl ChaCha20 {
    /// Create a `ChaCha20` instance with a 32-byte key, 12-byte nonce, and counter 0.
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self::with_counter(key, nonce, 0)
    }

    /// Create a `ChaCha20` instance at an arbitrary 64-byte block counter.
    #[must_use]
    pub fn with_counter(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        Self {
            state: state_from_key_nonce(key, nonce, counter),
            block: [0u8; 64],
            offset: 64,
            exhausted: false,
        }
    }

    /// Create and wipe the caller's key and nonce buffers.
    pub fn new_wiping(key: &mut [u8; 32], nonce: &mut [u8; 12]) -> Self {
        let out = Self::new(key, nonce);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        out
    }

    /// Keystream bytes still available before the block counter would wrap:
    /// the unread rest of the current block, plus one block for every counter
    /// value from the next one through `u32::MAX`.
    fn keystream_remaining(&self) -> u64 {
        let buffered = u64::try_from(64 - self.offset).expect("offset is at most 64");
        let blocks = if self.exhausted {
            0
        } else {
            (1u64 << 32) - u64::from(self.state[12])
        };
        buffered + blocks * 64
    }

    #[inline]
    fn refill(&mut self) {
        debug_assert!(!self.exhausted, "apply_keystream checks the counter bound");
        chacha20_block_into(&self.state, &mut self.block);
        self.offset = 0;
        let (next, wrapped) = self.state[12].overflowing_add(1);
        self.state[12] = next;
        self.exhausted = wrapped;
    }

    /// XOR the `ChaCha20` keystream into `buf` in place.
    ///
    /// # Panics
    ///
    /// Panics, before modifying `buf`, if `buf` is longer than the keystream
    /// left under the 32-bit block counter: RFC 8439 defines no block after
    /// counter `u32::MAX`, and wrapping to block 0 would repeat keystream.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        assert!(
            u64::try_from(buf.len()).is_ok_and(|len| len <= self.keystream_remaining()),
            "ChaCha20 block counter exhausted: the 32-bit counter would wrap and repeat keystream"
        );
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

    /// Fill `buf` with keystream bytes by `XORing` into the existing contents.
    ///
    /// # Panics
    ///
    /// Panics under the same block-counter bound as
    /// [`ChaCha20::apply_keystream`].
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.apply_keystream(buf);
    }

    /// Return the next 64 bytes of keystream.
    ///
    /// # Panics
    ///
    /// Panics if fewer than 64 bytes of keystream remain under the 32-bit
    /// block counter.
    pub fn keystream_block(&mut self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.apply_keystream(&mut out);
        out
    }

    /// Seek to a 64-byte block boundary. Seeking also re-arms a stream whose
    /// block counter was exhausted.
    pub fn set_counter(&mut self, counter: u32) {
        self.state[12] = counter;
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 64;
        self.exhausted = false;
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 0;
    }
}

/// `XChaCha20` stream cipher using HChaCha20-derived subkeys.
pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    /// Create an `XChaCha20` instance with a 32-byte key and 24-byte nonce.
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        Self::with_counter(key, nonce, 0)
    }

    /// Create an `XChaCha20` instance at an arbitrary 64-byte block counter.
    #[must_use]
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

    /// XOR the `XChaCha20` keystream into `buf` in place.
    ///
    /// # Panics
    ///
    /// Panics, before modifying `buf`, if `buf` is longer than the keystream
    /// left under the inner `ChaCha20`'s 32-bit block counter.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.inner.apply_keystream(buf);
    }

    /// Fill `buf` with keystream bytes by `XORing` into the existing contents.
    ///
    /// # Panics
    ///
    /// Panics under the same block-counter bound as
    /// [`XChaCha20::apply_keystream`].
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.inner.fill(buf);
    }

    /// Return the next 64 bytes of keystream.
    ///
    /// # Panics
    ///
    /// Panics if fewer than 64 bytes of keystream remain under the 32-bit
    /// block counter.
    pub fn keystream_block(&mut self) -> [u8; 64] {
        self.inner.keystream_block()
    }

    /// Seek to a 64-byte block boundary, re-arming an exhausted counter.
    pub fn set_counter(&mut self, counter: u32) {
        self.inner.set_counter(counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::encode_hex;

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
            encode_hex(&block),
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
            encode_hex(&subkey),
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

    /// The block at counter `u32::MAX` is the last one RFC 8439's 32-bit
    /// counter addresses, and it is produced normally.
    #[test]
    fn last_counter_block_is_available() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut seeked = ChaCha20::new(&key, &nonce);
        seeked.set_counter(u32::MAX);
        let mut direct = ChaCha20::with_counter(&key, &nonce, u32::MAX);
        assert_eq!(seeked.keystream_block(), direct.keystream_block());
    }

    #[test]
    #[should_panic(expected = "ChaCha20 block counter exhausted")]
    fn keystream_past_the_last_block_panics() {
        let mut c = ChaCha20::new(&[0x42u8; 32], &[0x24u8; 12]);
        c.set_counter(u32::MAX);
        let _ = c.keystream_block();
        c.apply_keystream(&mut [0u8; 1]);
    }

    /// A request that does not fit is refused whole: no partial keystream is
    /// written, and a seek re-arms the stream.
    #[test]
    fn counter_exhaustion_is_checked_before_any_output() {
        let mut c = ChaCha20::new(&[0x42u8; 32], &[0x24u8; 12]);
        c.set_counter(u32::MAX);
        let mut buf = [0xa5u8; 65];
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.apply_keystream(&mut buf);
        }));
        assert!(refused.is_err());
        assert_eq!(buf, [0xa5u8; 65]);

        c.set_counter(0);
        c.apply_keystream(&mut buf);
        assert_ne!(buf, [0xa5u8; 65]);
    }

    #[test]
    #[should_panic(expected = "ChaCha20 block counter exhausted")]
    fn xchacha20_past_the_last_block_panics() {
        let mut x = XChaCha20::new(&[7u8; 32], &[9u8; 24]);
        x.set_counter(u32::MAX);
        x.apply_keystream(&mut [0u8; 65]);
    }

    /// `ChaCha20::new_wiping` zeroes the caller's key and nonce and yields the
    /// same stream as `new`.
    #[test]
    fn chacha20_new_wiping_zeroes_inputs_and_matches_new() {
        let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).expect("i < 32"));
        let nonce: [u8; 12] = core::array::from_fn(|i| u8::try_from(i * 5).expect("i < 12"));
        let mut expected = [0u8; 100];
        ChaCha20::new(&key, &nonce).fill(&mut expected);

        let mut key_buf = key;
        let mut nonce_buf = nonce;
        let mut cipher = ChaCha20::new_wiping(&mut key_buf, &mut nonce_buf);
        assert_eq!(key_buf, [0u8; 32]);
        assert_eq!(nonce_buf, [0u8; 12]);
        let mut out = [0u8; 100];
        cipher.fill(&mut out);
        assert_eq!(out, expected);
    }

    /// `XChaCha20::new_wiping` zeroes the caller's key and 24-byte nonce and
    /// yields the same stream as `new`.
    #[test]
    fn xchacha20_new_wiping_zeroes_inputs_and_matches_new() {
        let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i * 7).expect("i < 32"));
        let nonce: [u8; 24] = core::array::from_fn(|i| u8::try_from(i * 11).expect("i < 24"));
        let mut expected = [0u8; 100];
        XChaCha20::new(&key, &nonce).fill(&mut expected);

        let mut key_buf = key;
        let mut nonce_buf = nonce;
        let mut cipher = XChaCha20::new_wiping(&mut key_buf, &mut nonce_buf);
        assert_eq!(key_buf, [0u8; 32]);
        assert_eq!(nonce_buf, [0u8; 24]);
        let mut out = [0u8; 100];
        cipher.fill(&mut out);
        assert_eq!(out, expected);
    }
}
