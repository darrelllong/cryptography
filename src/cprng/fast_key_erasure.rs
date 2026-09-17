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

/// The ChaCha20 nonce of every refill. Each key is used for exactly one
/// refill and then replaced, so a fixed nonce never repeats a (key, nonce)
/// pair; the construction needs no nonce state.
const NONCE: [u8; 12] = [0; 12];

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

    /// Output bytes one refill serves: the keystream past the next key.
    const SERVED: usize = REFILL - KEY;

    /// Take the next key from the front of a refill's keystream and write the
    /// rest to `out`, which must be [`FastKeyErasure::SERVED`] bytes.
    ///
    /// The two writes are consecutive bytes of one ChaCha20 keystream, so
    /// this is the refill's `stream[..KEY]` and `stream[KEY..]` without a
    /// copy of the served bytes.
    fn refill_into(&mut self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::SERVED);
        let mut stream = ChaCha20::new(&self.key, &NONCE);
        stream.keystream(&mut self.key);
        stream.keystream(out);
    }

    /// Serve the next `out.len()` bytes.
    ///
    /// Whole refills go straight to the caller, so their bytes never enter
    /// the generator; a partial refill is buffered, and each buffered byte is
    /// erased as it is served.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        if self.position < REFILL {
            let take = (REFILL - self.position).min(out.len());
            let served = &mut self.buffer[self.position..self.position + take];
            out[..take].copy_from_slice(served);
            zeroize_slice(served);
            self.position += take;
            done = take;
        }
        while out.len() - done >= Self::SERVED {
            let (start, end) = (done, done + Self::SERVED);
            self.refill_into(&mut out[start..end]);
            done = end;
        }
        if done < out.len() {
            let mut served = [0u8; Self::SERVED];
            self.refill_into(&mut served);
            self.buffer[KEY..].copy_from_slice(&served);
            zeroize_slice(served.as_mut_slice());
            self.position = KEY;
            let take = out.len() - done;
            let from_buffer = &mut self.buffer[KEY..KEY + take];
            out[done..].copy_from_slice(from_buffer);
            zeroize_slice(from_buffer);
            self.position += take;
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

    /// A served byte is in no buffer the generator keeps: not the pool it
    /// came from, not the key, and not the next refill's pool.
    #[test]
    fn served_bytes_survive_nowhere_in_the_state() {
        const SERVED: usize = REFILL - KEY + 7;
        let mut rng = FastKeyErasure::new([0x33; KEY]);
        let mut out = [0u8; SERVED];
        rng.fill(&mut out);
        let window = 8;
        for start in 0..=out.len() - window {
            let served = &out[start..start + window];
            assert!(!rng.buffer.windows(window).any(|w| w == served));
            assert!(!rng.key.windows(window).any(|w| w == served));
        }
    }

    /// A caller that panics part way through a fill leaves the served bytes
    /// erased from the buffer: `fill` erases each byte as it copies it, so an
    /// unwind cannot expose bytes the caller already holds.
    #[test]
    fn an_interrupted_fill_leaves_no_served_bytes_behind() {
        let mut rng = FastKeyErasure::new([0x44; KEY]);
        let mut first = [0u8; 64];
        rng.fill(&mut first);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut out = [0u8; 64];
            rng.fill(&mut out);
            panic!("caller unwinds holding {out:?}");
        }));
        assert!(unwound.is_err());
        assert_eq!(rng.buffer[KEY..KEY + 128], [0; 128]);
    }

    /// After a compromise that reads the whole state, reseeding with key
    /// material the attacker does not have puts the stream beyond what the
    /// captured state predicts.
    #[test]
    fn reseed_after_a_compromise_leaves_the_captured_state_behind() {
        let mut rng = FastKeyErasure::new([0x55; KEY]);
        let mut discard = [0u8; 16];
        rng.fill(&mut discard);
        let captured_key = rng.key;
        let captured_buffer = rng.buffer;
        rng.reseed(&[0x9e; KEY]);
        let mut after = [0u8; 64];
        rng.fill(&mut after);

        let mut attacker = FastKeyErasure::new(captured_key);
        attacker.buffer = captured_buffer;
        attacker.position = KEY + discard.len();
        let mut predicted = [0u8; 64];
        attacker.fill(&mut predicted);
        assert_ne!(after, predicted);
    }

    /// The core keeps no process identity: a second process running this same
    /// test binary, with the same key, produces the same bytes. Reseeding on
    /// a fork is the caller's policy, not the construction's.
    #[test]
    fn a_second_process_with_the_same_key_produces_the_same_stream() {
        const CHILD: &str = "CRYPTOGRAPHY_FAST_KEY_ERASURE_CHILD";
        let mut ours = [0u8; 32];
        FastKeyErasure::new([0x77; KEY]).fill(&mut ours);
        let hex = crate::test_utils::encode_hex(&ours);
        if std::env::var_os(CHILD).is_some() {
            println!("{hex}");
            return;
        }
        let exe = std::env::current_exe().expect("this test binary");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "cprng::fast_key_erasure::tests::a_second_process_with_the_same_key_produces_the_same_stream",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run this test binary again");
        assert!(output.status.success(), "child: {output:?}");
        let child = String::from_utf8(output.stdout).expect("test output is text");
        assert!(
            child.lines().any(|line| line.trim() == hex),
            "child printed {child}, expected {hex}"
        );
    }

    /// The stream does not depend on how a caller splits it: whole refills go
    /// straight to the caller, a partial one through the buffer, and the
    /// bytes are the same either way.
    #[test]
    fn the_stream_is_the_same_however_requests_are_split() {
        const TOTAL: usize = 4 * REFILL + 13;
        let mut whole = [0u8; TOTAL];
        FastKeyErasure::new([0x6b; KEY]).fill(&mut whole);
        // Each shape is a run of request lengths; whatever is left over is one
        // final request. Single bytes, lengths either side of a refill's
        // served bytes, whole refills, and all but one byte at once.
        let served = REFILL - KEY;
        let shapes: [Vec<usize>; 4] = [
            vec![1; TOTAL],
            vec![7, served - 1, served, served + 1],
            vec![served; 3],
            vec![TOTAL - 1],
        ];
        for mut shape in shapes {
            let taken: usize = shape.iter().sum();
            if taken < TOTAL {
                shape.push(TOTAL - taken);
            }
            assert_eq!(shape.iter().sum::<usize>(), TOTAL);
            let mut rng = FastKeyErasure::new([0x6b; KEY]);
            let mut got = Vec::with_capacity(TOTAL);
            for len in shape {
                let mut chunk = vec![0u8; len];
                rng.fill(&mut chunk);
                got.extend_from_slice(&chunk);
            }
            assert_eq!(got, whole);
        }
    }

    /// Throughput of a bulk fill, which writes whole refills straight to the
    /// caller, against one that goes through the buffer a word at a time.
    /// Release-only: a debug build measures the compiler.
    #[test]
    #[ignore = "release-only timing experiment"]
    fn bulk_fill_is_priced_against_word_at_a_time() {
        use std::time::Instant;
        const BYTES: usize = 16 << 20;
        const SAMPLES: usize = 7;
        let mebibyte = f64::from(1u32 << 20);
        let mut fastest_bulk = f64::INFINITY;
        let mut fastest_words = f64::INFINITY;
        for _ in 0..SAMPLES {
            let mut rng = FastKeyErasure::new([0x2c; KEY]);
            let mut buffer = vec![0u8; BYTES];
            let start = Instant::now();
            rng.fill(&mut buffer);
            fastest_bulk = fastest_bulk.min(start.elapsed().as_secs_f64());

            let mut rng = FastKeyErasure::new([0x2c; KEY]);
            let start = Instant::now();
            for _ in 0..BYTES / 8 {
                core::hint::black_box(rng.next_u64());
            }
            fastest_words = fastest_words.min(start.elapsed().as_secs_f64());
        }
        let mib = BYTES as f64 / mebibyte;
        eprintln!(
            "fast key erasure: bulk {:.0} MiB/s, next_u64 {:.0} MiB/s",
            mib / fastest_bulk,
            mib / fastest_words
        );
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
