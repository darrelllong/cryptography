//! Fast-key-erasure ChaCha20.
//!
//! D. J. Bernstein, "Fast-key-erasure random-number generators", 23 July 2017,
//! <https://blog.cr.yp.to/20170723-random.html>. The state is a 256-bit
//! ChaCha20 key. Each refill computes [`REFILL`] bytes of ChaCha20 keystream
//! under that key, with the all-zero nonce and block counter 0 (RFC 8439),
//! replaces the key with the first [`KEY`] bytes and serves the rest in order,
//! overwriting each byte with zero as it is served.
//!
//! What a later compromise of the whole state reveals: the current key, hence
//! all future output until fresh key material is mixed in, and the unserved
//! bytes of the current refill. What it does not: output already served,
//! because the key that produced it has been replaced and recovering it from
//! its successor would break ChaCha20. The construction adds no entropy; its
//! output is as unpredictable as the key it starts from and what
//! [`FastKeyErasure::reseed`] mixes in.

use crate::ct::zeroize_slice;
use crate::{ChaCha20, Csprng};

/// Keystream bytes per refill: eight ChaCha20 blocks.
pub const REFILL: usize = 512;

/// Bytes of each refill that become the next key.
pub const KEY: usize = 32;

/// ChaCha20 with fast key erasure.
pub struct FastKeyErasure {
    key: [u8; KEY],
    buffer: [u8; REFILL],
    /// The next unserved byte of `buffer`; `REFILL` when none is left.
    position: usize,
}

impl FastKeyErasure {
    /// A generator whose first key is `key`. The caller's copy is not wiped.
    #[must_use]
    pub fn new(key: [u8; KEY]) -> Self {
        Self {
            key,
            buffer: [0; REFILL],
            position: REFILL,
        }
    }

    /// Replace the key with the first `KEY` bytes of keystream and keep the
    /// rest to serve.
    fn refill(&mut self) {
        let mut stream = [0u8; REFILL];
        ChaCha20::new(&self.key, &[0u8; 12]).keystream(&mut stream);
        self.key.copy_from_slice(&stream[..KEY]);
        self.buffer[KEY..].copy_from_slice(&stream[KEY..]);
        zeroize_slice(stream.as_mut_slice());
        self.position = KEY;
    }

    /// Serve the next `out.len()` bytes, erasing each from the buffer.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.position == REFILL {
                self.refill();
            }
            let take = (REFILL - self.position).min(out.len() - done);
            let served = &mut self.buffer[self.position..self.position + take];
            out[done..done + take].copy_from_slice(served);
            zeroize_slice(served);
            self.position += take;
            done += take;
        }
    }

    /// Mix fresh key material in: XOR `fresh` into the key and discard the
    /// unserved buffer, so the next byte comes from a refill under the new
    /// key.
    pub fn reseed(&mut self, fresh: &[u8; KEY]) {
        for (k, f) in self.key.iter_mut().zip(fresh) {
            *k ^= f;
        }
        zeroize_slice(self.buffer.as_mut_slice());
        self.position = REFILL;
    }

    /// The next 4 bytes, little-endian.
    pub fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill(&mut word);
        u32::from_le_bytes(word)
    }

    /// The next 8 bytes, little-endian.
    pub fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill(&mut word);
        u64::from_le_bytes(word)
    }
}

impl Csprng for FastKeyErasure {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.fill(out);
    }

    /// The next 8 bytes, little-endian, as [`FastKeyErasure::next_u64`].
    fn next_u64(&mut self) -> u64 {
        FastKeyErasure::next_u64(self)
    }
}

impl Drop for FastKeyErasure {
    fn drop(&mut self) {
        zeroize_slice(self.key.as_mut_slice());
        zeroize_slice(self.buffer.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decode_hex;

    /// Output is the keystream past its first `KEY` bytes, and the next refill
    /// is keyed by those bytes, computed here with `apply_keystream` on zeros.
    #[test]
    fn output_is_keystream_under_rotating_keys() {
        let key: [u8; KEY] = core::array::from_fn(|i| u8::try_from(i).expect("small"));
        let mut rng = FastKeyErasure::new(key);
        let mut out = [0u8; 2 * (REFILL - KEY)];
        rng.fill(&mut out);

        let mut first = [0u8; REFILL];
        ChaCha20::new(&key, &[0; 12]).apply_keystream(&mut first);
        assert_eq!(out[..REFILL - KEY], first[KEY..]);
        let next_key: [u8; KEY] = first[..KEY].try_into().expect("32 bytes");
        let mut second = [0u8; REFILL];
        ChaCha20::new(&next_key, &[0; 12]).apply_keystream(&mut second);
        assert_eq!(out[REFILL - KEY..], second[KEY..]);
    }

    /// The first 960 bytes for key 00 01 ... 1f, pinned at their first 64 and
    /// last 32 bytes. The expected bytes are the OpenSSL 3.6 `chacha20`
    /// keystream (`openssl enc -chacha20 -iv` 32 zero hex digits, counter 0
    /// and zero nonce) over 512 zero bytes under the key, then under the key
    /// taken from that stream's first 32 bytes, without the key bytes; that
    /// tool reproduces the RFC 8439 §2.3.2 block with the same IV layout.
    #[test]
    fn first_refills_match_openssl_chacha20() {
        let key: [u8; KEY] = core::array::from_fn(|i| u8::try_from(i).expect("small"));
        let mut rng = FastKeyErasure::new(key);
        let mut out = [0u8; 2 * (REFILL - KEY)];
        rng.fill(&mut out);
        assert_eq!(
            out[..64].to_vec(),
            decode_hex(
                "2b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c\
                 18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c"
            )
        );
        assert_eq!(
            out[out.len() - 32..].to_vec(),
            decode_hex("d0649d0f9a4306e3aa7c5bcf77cc8d04a1f80e367a24ee97a867b2295c945177")
        );
    }

    /// Served bytes are erased from the buffer, and the state holds no copy.
    #[test]
    fn served_bytes_are_erased() {
        let mut rng = FastKeyErasure::new([7; KEY]);
        let word = rng.next_u64().to_le_bytes();
        assert_eq!(rng.buffer[KEY..KEY + 8], [0; 8]);
        assert!(!rng.buffer.windows(8).any(|w| w == word));
        assert!(!rng.key.windows(8).any(|w| w == word));
    }

    /// Reseeding XORs into the key and drops the unserved bytes: the next
    /// output is a refill under `key ⊕ fresh`.
    #[test]
    fn reseed_mixes_into_the_key_and_discards_the_buffer() {
        let mut rng = FastKeyErasure::new([3; KEY]);
        let _ = rng.next_u32();
        let key_after_refill = rng.key;
        rng.reseed(&[0x5c; KEY]);
        assert_eq!(rng.buffer, [0; REFILL]);
        let mut mixed = key_after_refill;
        for k in &mut mixed {
            *k ^= 0x5c;
        }
        let mut expected = FastKeyErasure::new(mixed);
        assert_eq!(rng.next_u64(), expected.next_u64());
    }

    /// Words are little-endian and follow on from each other across a refill.
    #[test]
    fn words_are_little_endian_across_refills() {
        let mut bytes_rng = FastKeyErasure::new([9; KEY]);
        let mut words_rng = FastKeyErasure::new([9; KEY]);
        let mut bytes = vec![0u8; 8 * 70];
        bytes_rng.fill(&mut bytes);
        for chunk in bytes.chunks(8) {
            assert_eq!(
                words_rng.next_u64(),
                u64::from_le_bytes(chunk.try_into().expect("8"))
            );
        }
    }
}
