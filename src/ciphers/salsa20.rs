//! Salsa20 stream cipher — Daniel J. Bernstein's original Snuffle design.
//!
//! This is the standard 20-round Salsa20 core with an 8-byte nonce and a
//! 64-byte keystream block. It supports both the original 16-byte and 32-byte
//! key forms from the published specification.
//!
//! The code keeps the original Salsa20 layout instead of rewriting it into a
//! ChaCha-like form so the state words remain easy to compare directly against
//! the published eSTREAM-family vectors.

// Salsa20 specification constants for 256-bit (`sigma`) and 128-bit (`tau`) keys.
/// Salsa20's state is sixteen 32-bit words, and one permutation of it yields
/// a 64-byte keystream block (Bernstein, "Salsa20 specification", §§4–8).
const STATE_WORDS: usize = 16;
const WORD_BYTES: usize = 4;
const BLOCK_BYTES: usize = STATE_WORDS * WORD_BYTES;

/// Twenty rounds, applied as ten column-and-row double rounds (§7, §8).
const DOUBLE_ROUNDS: usize = 10;

/// The two key sizes, each with its own constant string (§9).
const KEY_BYTES: usize = 32;
const SHORT_KEY_BYTES: usize = 16;
const NONCE_BYTES: usize = 8;

const SIGMA: [u8; 16] = *b"expand 32-byte k";
const TAU: [u8; 16] = *b"expand 16-byte k";

#[inline]
fn load_u32_le(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(bytes);
    u32::from_le_bytes(tmp)
}

#[inline]
fn quarter_round(y0: &mut u32, y1: &mut u32, y2: &mut u32, y3: &mut u32) {
    // Salsa20 quarter-round rotation constants from Bernstein's original design.
    // ChaCha deliberately changed these to 16/12/8/7; we keep Salsa's 7/9/13/18.
    *y1 ^= y0.wrapping_add(*y3).rotate_left(7);
    *y2 ^= y1.wrapping_add(*y0).rotate_left(9);
    *y3 ^= y2.wrapping_add(*y1).rotate_left(13);
    *y0 ^= y3.wrapping_add(*y2).rotate_left(18);
}

#[inline]
fn salsa20_block(state: &[u32; STATE_WORDS]) -> [u8; BLOCK_BYTES] {
    let mut x = *state;

    for _ in 0..DOUBLE_ROUNDS {
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

    let mut out = [0u8; BLOCK_BYTES];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
    }
    // The permuted working copy differs from the keystream block by exactly
    // the input state, so together they would give back the key.
    crate::ct::zeroize_slice(x.as_mut_slice());
    out
}

/// The key lengths the Salsa20 specification defines: 32 bytes with the
/// `sigma` constants, 16 bytes with `tau`.
#[inline]
fn is_valid_key_len(len: usize) -> bool {
    len == 16 || len == 32
}

#[inline]
fn key_setup(key: &[u8], nonce: [u8; NONCE_BYTES], counter: u64) -> [u32; STATE_WORDS] {
    assert!(
        is_valid_key_len(key.len()),
        "Salsa20 key length must be {SHORT_KEY_BYTES} or {KEY_BYTES} bytes, got {}",
        key.len()
    );

    // Salsa20 swaps the sigma/tau constants depending on whether the caller is
    // using the 32-byte or legacy 16-byte key form.
    let constants = if key.len() == KEY_BYTES { &SIGMA } else { &TAU };
    let k0 = &key[..SHORT_KEY_BYTES];
    let k1 = if key.len() == KEY_BYTES {
        &key[SHORT_KEY_BYTES..KEY_BYTES]
    } else {
        &key[..16]
    };

    let counter_bytes = counter.to_le_bytes();
    let counter_low = u32::from_le_bytes([
        counter_bytes[0],
        counter_bytes[1],
        counter_bytes[2],
        counter_bytes[3],
    ]);
    let counter_high = u32::from_le_bytes([
        counter_bytes[4],
        counter_bytes[5],
        counter_bytes[6],
        counter_bytes[7],
    ]);

    [
        load_u32_le(&constants[0..4]),
        load_u32_le(&k0[0..4]),
        load_u32_le(&k0[4..8]),
        load_u32_le(&k0[8..12]),
        load_u32_le(&k0[12..16]),
        load_u32_le(&constants[4..8]),
        load_u32_le(&nonce[0..4]),
        load_u32_le(&nonce[4..8]),
        counter_low,
        counter_high,
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
    state: [u32; STATE_WORDS],
    block: [u8; BLOCK_BYTES],
    offset: usize,
}

impl Salsa20 {
    /// Create a Salsa20 instance with a 32-byte key and 8-byte nonce.
    #[must_use]
    pub fn new(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> Self {
        Self::with_key_bytes(key, nonce)
    }

    /// Create a Salsa20 instance with either a 16-byte or 32-byte key.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` is neither 16 nor 32, the two key lengths the
    /// Salsa20 specification defines.
    #[must_use]
    pub fn with_key_bytes(key: &[u8], nonce: &[u8; NONCE_BYTES]) -> Self {
        Self::with_counter(key, nonce, 0)
    }

    /// Create a Salsa20 instance at an arbitrary 64-byte block counter.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` is neither 16 nor 32.
    #[must_use]
    pub fn with_counter(key: &[u8], nonce: &[u8; NONCE_BYTES], counter: u64) -> Self {
        Self {
            state: key_setup(key, *nonce, counter),
            block: [0u8; 64],
            offset: 64,
        }
    }

    /// Create with a 32-byte key and wipe the caller's key and nonce buffers.
    pub fn new_wiping(key: &mut [u8; KEY_BYTES], nonce: &mut [u8; NONCE_BYTES]) -> Self {
        let out = Self::new(key, nonce);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        out
    }

    /// Create with a 16- or 32-byte key and wipe the caller's key and nonce.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` is neither 16 nor 32. The key and nonce buffers
    /// are wiped before the length is checked, so they are zero on the panic
    /// path as well.
    pub fn with_key_bytes_wiping(key: &mut [u8], nonce: &mut [u8; NONCE_BYTES]) -> Self {
        let valid = is_valid_key_len(key.len());
        let state = valid.then(|| key_setup(key, *nonce, 0));
        crate::ct::zeroize_slice(key);
        crate::ct::zeroize_slice(nonce.as_mut_slice());
        assert!(
            valid,
            "Salsa20 key length must be {SHORT_KEY_BYTES} or {KEY_BYTES} bytes, got {}",
            key.len()
        );
        Self {
            state: state.expect("state was built when the key length was valid"),
            block: [0u8; 64],
            offset: 64,
        }
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

    /// Fill `buf` with keystream bytes by `XORing` into the existing contents.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.apply_keystream(buf);
    }

    /// Return the next 64 bytes of keystream, respecting the current stream position.
    pub fn keystream_block(&mut self) -> [u8; 64] {
        let mut out = [0u8; BLOCK_BYTES];
        self.apply_keystream(&mut out);
        out
    }

    /// Seek to a 64-byte block boundary.
    pub fn set_counter(&mut self, counter: u64) {
        let counter_bytes = counter.to_le_bytes();
        self.state[8] = u32::from_le_bytes([
            counter_bytes[0],
            counter_bytes[1],
            counter_bytes[2],
            counter_bytes[3],
        ]);
        self.state[9] = u32::from_le_bytes([
            counter_bytes[4],
            counter_bytes[5],
            counter_bytes[6],
            counter_bytes[7],
        ]);
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
    use crate::test_utils::{decode_hex, encode_hex};

    // eSTREAM vectors: ECRYPT Stream Cipher Project, Salsa20 submission,
    // `full/verified.test-vectors` ("stream is generated by encrypting 512
    // zero bytes"). Set 1, vector #0 is the key with only its first bit set
    // and the all-zero IV; the file publishes stream[0..63],
    // stream[192..255], stream[256..319] and stream[448..511]. Blocks 3, 4
    // and 7 pin the counter's placement in state words 8 and 9.

    struct EstreamSet1Vector0 {
        stream_0: &'static str,
        stream_192: &'static str,
        stream_256: &'static str,
        stream_448: &'static str,
    }

    fn assert_estream_set1_vector0(key: &[u8], v: &EstreamSet1Vector0) {
        let mut cipher = Salsa20::with_key_bytes(key, &[0u8; 8]);
        let mut stream = [0u8; 512];
        cipher.fill(&mut stream);
        for (start, expected) in [
            (0, v.stream_0),
            (192, v.stream_192),
            (256, v.stream_256),
            (448, v.stream_448),
        ] {
            assert_eq!(
                stream[start..start + 64].as_ref(),
                decode_hex(expected).as_slice(),
                "stream[{start}..{}]",
                start + 63
            );
        }
    }

    /// Salsa20 (128-bit key) verified test vectors, Set 1, vector #0.
    #[test]
    fn salsa20_128bit_estream_set1_vector0() {
        let mut key = [0u8; 16];
        key[0] = 0x80;
        assert_estream_set1_vector0(
            &key,
            &EstreamSet1Vector0 {
                stream_0: "4DFA5E481DA23EA09A31022050859936\
                       DA52FCEE218005164F267CB65F5CFD7F\
                       2B4F97E0FF16924A52DF269515110A07\
                       F9E460BC65EF95DA58F740B7D1DBB0AA",
                stream_192: "DA9C1581F429E0A00F7D67E23B730676\
                         783B262E8EB43A25F55FB90B3E753AEF\
                         8C6713EC66C51881111593CCB3E8CB8F\
                         8DE124080501EEEB389C4BCB6977CF95",
                stream_256: "7D5789631EB4554400E1E025935DFA7B\
                         3E9039D61BDC58A8697D36815BF1985C\
                         EFDF7AE112E5BB81E37ECF0616CE7147\
                         FC08A93A367E08631F23C03B00A8DA2F",
                stream_448: "B375703739DACED4DD4059FD71C3C47F\
                         C2F9939670FAD4A46066ADCC6A564578\
                         3308B90FFB72BE04A6B147CBE38CC0C3\
                         B9267C296A92A7C69873F9F263BE9703",
            },
        );
    }

    /// Salsa20 (256-bit key) verified test vectors, Set 1, vector #0.
    #[test]
    fn salsa20_256bit_estream_set1_vector0() {
        let mut key = [0u8; 32];
        key[0] = 0x80;
        assert_estream_set1_vector0(
            &key,
            &EstreamSet1Vector0 {
                stream_0: "E3BE8FDD8BECA2E3EA8EF9475B29A6E7\
                       003951E1097A5C38D23B7A5FAD9F6844\
                       B22C97559E2723C7CBBD3FE4FC8D9A07\
                       44652A83E72A9C461876AF4D7EF1A117",
                stream_192: "57BE81F47B17D9AE7C4FF15429A73E10\
                         ACF250ED3A90A93C711308A74C6216A9\
                         ED84CD126DA7F28E8ABF8BB63517E1CA\
                         98E712F4FB2E1A6AED9FDC73291FAA17",
                stream_256: "958211C4BA2EBD5838C635EDB81F513A\
                         91A294E194F1C039AEEC657DCE40AA7E\
                         7C0AF57CACEFA40C9F14B71A4B3456A6\
                         3E162EC7D8D10B8FFB1810D71001B618",
                stream_448: "696AFCFD0CDDCC83C7E77F11A649D79A\
                         CDC3354E9635FF137E929933A0BD6F53\
                         77EFA105A3A4266B7C0D089D08F1E855\
                         CC32B15B93784A36E56A76CC64BC8477",
            },
        );
    }

    /// `new` is the 32-byte form of `with_key_bytes`.
    #[test]
    fn new_matches_with_key_bytes() {
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let mut a = Salsa20::new(&key, &[0u8; 8]);
        let mut b = Salsa20::with_key_bytes(&key, &[0u8; 8]);
        assert_eq!(
            encode_hex(&a.keystream_block()),
            encode_hex(&b.keystream_block())
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

    /// The 64-bit block counter occupies state words 8 (low) and 9 (high):
    /// running the stream from block 2^32 − 1 carries into word 9, and lands
    /// on the block that `with_counter` and `set_counter` address as 2^32.
    #[test]
    fn counter_carries_across_the_32_bit_boundary() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 8];

        let mut running = Salsa20::with_counter(&key, &nonce, u64::from(u32::MAX));
        let mut two_blocks = [0u8; 128];
        running.fill(&mut two_blocks);

        let mut direct_last = Salsa20::with_counter(&key, &nonce, u64::from(u32::MAX));
        assert_eq!(direct_last.keystream_block(), two_blocks[..64]);

        let mut direct_next = Salsa20::with_counter(&key, &nonce, 1u64 << 32);
        assert_eq!(direct_next.keystream_block(), two_blocks[64..]);

        let mut seeked = Salsa20::new(&key, &nonce);
        seeked.set_counter(u64::from(u32::MAX));
        let mut seeked_blocks = [0u8; 128];
        seeked.fill(&mut seeked_blocks);
        assert_eq!(seeked_blocks, two_blocks);

        // Block 2^32 is not block 0: the carry is a real change of state.
        let mut block_zero = Salsa20::new(&key, &nonce);
        assert_ne!(block_zero.keystream_block(), two_blocks[64..]);
    }

    /// `set_counter` on a live stream discards the buffered block and resumes
    /// at the requested block boundary.
    #[test]
    fn set_counter_seeks_to_block_boundary() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 8];
        let mut reference = Salsa20::with_counter(&key, &nonce, 7);
        let mut expected = [0u8; 100];
        reference.fill(&mut expected);

        let mut cipher = Salsa20::new(&key, &nonce);
        cipher.fill(&mut [0u8; 13]);
        cipher.set_counter(7);
        let mut out = [0u8; 100];
        cipher.fill(&mut out);
        assert_eq!(out, expected);
    }

    /// `new_wiping` zeroes the caller's key and nonce and yields the same
    /// stream as `new`.
    #[test]
    fn new_wiping_zeroes_inputs_and_matches_new() {
        let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).expect("i < 32"));
        let nonce = [0x77u8; 8];
        let mut expected = [0u8; 100];
        Salsa20::new(&key, &nonce).fill(&mut expected);

        let mut key_buf = key;
        let mut nonce_buf = nonce;
        let mut cipher = Salsa20::new_wiping(&mut key_buf, &mut nonce_buf);
        assert_eq!(key_buf, [0u8; 32]);
        assert_eq!(nonce_buf, [0u8; 8]);
        let mut out = [0u8; 100];
        cipher.fill(&mut out);
        assert_eq!(out, expected);
    }

    /// `with_key_bytes_wiping` zeroes the caller's key and nonce for both key
    /// lengths and yields the same stream as `with_key_bytes`.
    #[test]
    fn with_key_bytes_wiping_zeroes_inputs_and_matches_with_key_bytes() {
        for len in [16usize, 32] {
            let key: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 3).expect("< 96"))
                .collect();
            let nonce = [0x88u8; 8];
            let mut expected = [0u8; 100];
            Salsa20::with_key_bytes(&key, &nonce).fill(&mut expected);

            let mut key_buf = key.clone();
            let mut nonce_buf = nonce;
            let mut cipher = Salsa20::with_key_bytes_wiping(&mut key_buf, &mut nonce_buf);
            assert_eq!(key_buf, vec![0u8; len], "key of {len} bytes");
            assert_eq!(nonce_buf, [0u8; 8]);
            let mut out = [0u8; 100];
            cipher.fill(&mut out);
            assert_eq!(out, expected, "key of {len} bytes");
        }
    }

    /// A key of the wrong length is refused, but not before the caller's key
    /// and nonce have been wiped.
    #[test]
    fn with_key_bytes_wiping_wipes_before_refusing_a_bad_length() {
        let mut key = [0xA5u8; 24];
        let mut nonce = [0x5Au8; 8];
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Salsa20::with_key_bytes_wiping(&mut key, &mut nonce);
        }));
        assert!(refused.is_err());
        assert_eq!(key, [0u8; 24]);
        assert_eq!(nonce, [0u8; 8]);
    }

    #[test]
    #[should_panic(expected = "Salsa20 key length must be 16 or 32 bytes, got 24")]
    fn with_key_bytes_wiping_refuses_a_bad_length() {
        let _ = Salsa20::with_key_bytes_wiping(&mut [0u8; 24], &mut [0u8; 8]);
    }

    #[test]
    #[should_panic(expected = "Salsa20 key length must be 16 or 32 bytes, got 24")]
    fn with_key_bytes_refuses_a_bad_length() {
        let _ = Salsa20::with_key_bytes(&[0u8; 24], &[0u8; 8]);
    }
}
