//! SHA-1 from FIPS 180-4.
//!
//! SHA-1 is retained here for compatibility and HMAC support. It is no longer
//! recommended for collision-sensitive applications due to practical chosen-prefix
//! collision attacks.

use super::Digest;

// FIPS 180-4 §5.3.1 initial hash value H(0) for SHA-1.
/// FIPS 180-4 §1: SHA-1 works on 512-bit blocks of 32-bit words, keeps five of
/// them as the hash value, runs eighty rounds, and produces 160 bits.
const BLOCK_BYTES: usize = 64;
const WORD_BYTES: usize = 4;
const STATE_WORDS: usize = 5;
const ROUNDS: usize = 80;
const DIGEST_BYTES: usize = STATE_WORDS * WORD_BYTES;
/// The first sixteen schedule words are the block itself (§6.1.2 step 1).
const BLOCK_WORDS: usize = BLOCK_BYTES / WORD_BYTES;
/// §5.1.1 padding: a `0x80` byte, zeros, and the 64-bit big-endian length.
const PAD_START: u8 = 0x80;
const LENGTH_BYTES: usize = 8;
const LENGTH_OFFSET: usize = BLOCK_BYTES - LENGTH_BYTES;

const IV: [u32; STATE_WORDS] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

// FIPS 180-4 §4.1.1: the logical functions f_0, f_1, ..., f_79, each taking
// three 32-bit words x, y, z to one. The Standard writes ∧ for bitwise AND,
// ⊕ for XOR, and ¬ for the complement (§2.2.2).

/// Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z), which is f_t for 0 ≤ t ≤ 19 (FIPS 180-4
/// §4.1.1).
#[allow(non_snake_case)]
#[inline]
const fn Ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Parity(x, y, z) = x ⊕ y ⊕ z, which is f_t for 20 ≤ t ≤ 39 and for
/// 60 ≤ t ≤ 79 (FIPS 180-4 §4.1.1).
#[allow(non_snake_case)]
#[inline]
const fn Parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z), which is f_t for 40 ≤ t ≤ 59
/// (FIPS 180-4 §4.1.1).
#[allow(non_snake_case)]
#[inline]
const fn Maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// f_t(x, y, z), FIPS 180-4 §4.1.1 equation (4.1).
#[inline]
const fn f(t: usize, x: u32, y: u32, z: u32) -> u32 {
    match t {
        0..=19 => Ch(x, y, z),
        20..=39 => Parity(x, y, z),
        40..=59 => Maj(x, y, z),
        60..=79 => Parity(x, y, z),
        _ => panic!("f_t is defined for 0 <= t <= 79"),
    }
}

/// K_t, the eighty constant 32-bit words of FIPS 180-4 §4.2.1 equation (4.14).
#[allow(non_snake_case)]
#[inline]
const fn K(t: usize) -> u32 {
    match t {
        0..=19 => 0x5a82_7999,
        20..=39 => 0x6ed9_eba1,
        40..=59 => 0x8f1b_bcdc,
        60..=79 => 0xca62_c1d6,
        _ => panic!("K_t is defined for 0 <= t <= 79"),
    }
}

/// FIPS 180-4 §6.1.2, SHA-1 hash computation: steps 1 to 4 for one message
/// block M^(i). `H` holds the (i-1)st hash value H_0^(i-1), ..., H_4^(i-1) on
/// entry and the ith, H_0^(i), ..., H_4^(i), on return. Addition (+) is
/// performed modulo 2^32, and ROTL^n(x) is `x.rotate_left(n)` (§3.2).
// Step 3 indexes W by the Standard's round index t, which f_t and K_t take as
// well, rather than iterating over W as Clippy's needless_range_loop prefers.
#[allow(non_snake_case, clippy::needless_range_loop)]
#[inline]
fn compress(H: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_BYTES]) {
    // 1. Prepare the message schedule, {W_t}. The first sixteen words are the
    //    block's M_0^(i), ..., M_15^(i), each big-endian (§3.1, §5.2.1).
    let mut W = [0u32; ROUNDS];
    for (t, M_t) in block.chunks_exact(WORD_BYTES).enumerate() {
        W[t] = u32::from_be_bytes([M_t[0], M_t[1], M_t[2], M_t[3]]);
    }
    for t in BLOCK_WORDS..ROUNDS {
        W[t] = (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]).rotate_left(1);
    }

    // 2. Initialize the five working variables, a, b, c, d, and e, with the
    //    (i-1)st hash value.
    let [mut a, mut b, mut c, mut d, mut e] = *H;

    // 3. For t=0 to 79:
    for t in 0..ROUNDS {
        let T = a
            .rotate_left(5)
            .wrapping_add(f(t, b, c, d))
            .wrapping_add(e)
            .wrapping_add(K(t))
            .wrapping_add(W[t]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = T;
    }

    // 4. Compute the ith intermediate hash value H^(i).
    H[0] = a.wrapping_add(H[0]);
    H[1] = b.wrapping_add(H[1]);
    H[2] = c.wrapping_add(H[2]);
    H[3] = d.wrapping_add(H[3]);
    H[4] = e.wrapping_add(H[4]);

    // The schedule expands the block's message words; under HMAC the first
    // block is the key xor ipad.
    crate::ct::zeroize_slice(W.as_mut_slice());
}

/// Streaming SHA-1 state (FIPS 180-4).
///
/// Absorbs input in 64-byte blocks via [`Sha1::update`] and produces a 20-byte
/// digest via [`Sha1::finalize`]; [`Sha1::digest`] is the one-shot form.
/// Cloning captures the mid-stream state, so a common prefix can be hashed
/// once and extended along several branches. SHA-1's collision resistance is
/// broken (chosen-prefix collisions are practical); use it only for legacy
/// interoperability or HMAC, per the module warning.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; STATE_WORDS],
    block: [u8; BLOCK_BYTES],
    pos: usize,
    bit_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Compression-function block size in bytes (512 bits). This is the
    /// rate at which input is consumed and the pad width HMAC keys are
    /// sized against.
    pub const BLOCK_LEN: usize = BLOCK_BYTES;
    /// Digest length in bytes (160 bits).
    pub const OUTPUT_LEN: usize = DIGEST_BYTES;

    /// Create a fresh hasher: the FIPS 180-4 §5.3.1 initial hash value and
    /// an empty (zero-length) message.
    #[must_use]
    pub fn new() -> Self {
        <Self as Digest>::new()
    }

    /// Absorb more message bytes. May be called any number of times with
    /// arbitrary chunk sizes; the digest depends only on the concatenation
    /// of all chunks. The message length is tracked modulo 2^64 bits, as
    /// FIPS 180-4 padding requires.
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }

    /// Apply the FIPS 180-4 `0x80` / length padding, consume the hasher, and
    /// return the 20-byte digest (state words serialized big-endian). Keep a
    /// [`Clone`] beforehand if the stream must continue past this point.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 20] {
        let mut out = [0u8; 20];
        self.finalize_in_place(&mut out);
        // `self` drops here, and `Drop` wipes the final chaining state.
        out
    }

    /// One-shot convenience: hash `data` in a single call. Equivalent to
    /// `new` + `update` + `finalize`, returning the 20-byte digest.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    /// FIPS 180-4 §5.1.1 padding and the final §6.1.2 compression(s), then
    /// the big-endian chaining value into `out` (§6.1.2, the final step). The
    /// state is left holding the final chaining value; the callers decide
    /// whether it is dropped (`finalize`) or replaced (`finalize_reset`).
    fn finalize_in_place(&mut self, out: &mut [u8; 20]) {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u64) * 8);

        self.block[self.pos] = PAD_START;
        self.pos += 1;

        if self.pos > LENGTH_OFFSET {
            self.block[self.pos..].fill(0);
            compress(&mut self.state, &self.block);
            self.block = [0u8; BLOCK_BYTES];
            self.pos = 0;
        }

        self.block[self.pos..LENGTH_OFFSET].fill(0);
        self.block[LENGTH_OFFSET..].copy_from_slice(&self.bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);

        for (chunk, word) in out.chunks_exact_mut(WORD_BYTES).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

// The bodies of `new` and `update` live here; the same-named inherent
// methods delegate through the trait path, so neither pair can turn into
// silent recursion if one half is removed.
impl Digest for Sha1 {
    const BLOCK_LEN: usize = BLOCK_BYTES;
    const OUTPUT_LEN: usize = DIGEST_BYTES;

    /// The FIPS 180-4 §5.3.1 initial hash value and an empty message.
    fn new() -> Self {
        Self {
            state: IV,
            block: [0u8; BLOCK_BYTES],
            pos: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (BLOCK_BYTES - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == BLOCK_BYTES {
                compress(&mut self.state, &self.block);
                self.block = [0u8; BLOCK_BYTES];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(8 * BLOCK_BYTES as u64);
            }
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        let out: &mut [u8; 20] = out.try_into().expect("wrong digest length");
        self.finalize_in_place(out);
    }

    fn finalize_reset(&mut self, out: &mut [u8]) {
        let out: &mut [u8; 20] = out.try_into().expect("wrong digest length");
        self.finalize_in_place(out);
        // Assigning a fresh value drops the consumed one, and `Drop` wipes
        // its chaining state and block buffer.
        *self = <Self as Digest>::new();
    }

    fn zeroize(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.bit_len = 0;
    }
}

impl Drop for Sha1 {
    fn drop(&mut self) {
        // Under HMAC the chaining state and buffered block are key material.
        Digest::zeroize(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::encode_hex;

    /// `finalize_reset` leaves a fresh instance, `zeroize` scrubs the whole
    /// state, and the type wipes itself on drop.
    #[test]
    fn finalize_reset_and_zeroize_scrub_the_state() {
        let msg = b"HMAC feeds key material through this state";
        let mut h = Sha1::new();
        h.update(msg);
        let mut out = [0u8; 20];
        crate::hash::Digest::finalize_reset(&mut h, &mut out);
        assert_eq!(out, Sha1::digest(msg));
        assert_eq!(
            (h.state, h.block, h.pos, h.bit_len),
            (IV, [0u8; 64], 0, 0),
            "finalize_reset leaves a fresh instance"
        );

        let mut h = Sha1::new();
        h.update(b"a partial block");
        crate::hash::Digest::zeroize(&mut h);
        assert_eq!(
            (h.state, h.block, h.pos, h.bit_len),
            ([0u32; 5], [0u8; 64], 0, 0)
        );
        assert!(core::mem::needs_drop::<Sha1>());
    }

    #[test]
    fn sha1_empty() {
        assert_eq!(
            encode_hex(&Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn sha1_abc_streaming() {
        let mut h = Sha1::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn sha1_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha1", "-binary"], msg)
            .or_skip("sha1_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha1::digest(msg).as_slice(), expected.as_slice());
    }
}
