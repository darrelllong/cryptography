//! Serpent block cipher — AES submission / FSE 1998.
//!
//! 128-bit block cipher with three standard key sizes:
//!
//! - `Serpent128` / `Serpent128Ct`
//! - `Serpent192` / `Serpent192Ct`
//! - `Serpent256` / `Serpent256Ct`
//!
//! # Byte order
//!
//! The Serpent paper (§2, "The Cipher") represents every value in
//! little-endian form: word 0 is the least significant 32-bit word, and bit 0
//! is the least significant bit of word 0. This API takes that representation
//! byte for byte: block byte 0 is the least significant byte of word 0, and
//! key byte 0 is the least significant byte of the key. It is the byte order
//! used by the NESSIE test vectors and by deployed Serpent libraries, so
//! `Serpent128::new(&[0x80, 0, .., 0]).encrypt_block(&[0; 16])` yields
//! `264E5481EFF42A4606ABDA06C0BFDA3D`.
//!
//! The known-answer files shipped with the AES submission (`ecb_vk.txt`,
//! `ecb_vt.txt`, …) write each value "as a plain 128-bit hex number", most
//! significant byte first. A submission vector `(K, P, C)` is therefore
//! satisfied here as `encrypt(rev(K), rev(P)) == rev(C)`, where `rev`
//! reverses the byte string; the tests pin both presentations.
//!
//! # Key padding
//!
//! Keys shorter than 256 bits are extended as the paper prescribes: a single
//! `1` bit is appended at the most significant end, followed by zeros.
//!
//! # Round function
//!
//! All types share one word-parallel bitsliced S-box: each 4->4 S-box is
//! evaluated directly on the four 32-bit bitslice registers via its algebraic
//! normal form (word-wide `AND`/`XOR` only), substituting all 32 lanes at
//! once. The instruction sequence and memory accesses are independent of the
//! key and the data, so the round function is constant-time by construction;
//! the `*Ct` names are aliases of the corresponding types, retained so that
//! Serpent presents the same fast/`Ct` pair as the other block ciphers.

use crate::ct::zeroize_slice;
use crate::BlockCipher;

// Serpent key-schedule constant PHI = floor(2^32 * (sqrt(5)-1)/2).

/// Block size in bytes: Serpent is a 128-bit block cipher, held as four
/// 32-bit words (paper §2).
const BLOCK_BYTES: usize = 16;
const STATE_WORDS: usize = 4;
const WORD_BYTES: usize = BLOCK_BYTES / STATE_WORDS;

/// The key is padded to 256 bits before the schedule runs (paper §2).
const PADDED_KEY_BYTES: usize = 32;
const KEY128_BYTES: usize = 16;
const KEY192_BYTES: usize = 24;
const KEY256_BYTES: usize = 32;

/// Thirty-two rounds take thirty-three round keys, the last one whitening the
/// output (paper §2).
const ROUNDS: usize = 32;
const ROUND_KEYS: usize = ROUNDS + 1;

/// The eight S-boxes, used in turn and reused every eighth round (paper §2).
const SBOX_COUNT: usize = 8;

/// The prekey recurrence starts from the eight words of the padded key and
/// runs far enough to fill every round key: `w_-8..w_-1` then `w_0..w_131`.
const PREKEY_SEED_WORDS: usize = PADDED_KEY_BYTES / WORD_BYTES;
const PREKEY_WORDS: usize = PREKEY_SEED_WORDS + STATE_WORDS * ROUND_KEYS;

const PHI: u32 = 0x9E37_79B9;

// S-boxes from the Serpent AES submission (Anderson/Biham/Knudsen, 1998).
const SBOXES: [[u8; 16]; SBOX_COUNT] = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
];

// Inverse S-box tables from the same Serpent submission.
const INV_SBOXES: [[u8; 16]; SBOX_COUNT] = [
    [13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2],
    [5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0],
    [12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7],
    [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1],
    [5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1],
    [8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0],
    [15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11],
    [3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2],
];

const fn build_sboxes_anf(sboxes: &[[u8; 16]; SBOX_COUNT]) -> [[u16; STATE_WORDS]; SBOX_COUNT] {
    let mut out = [[0u16; 4]; 8];
    let mut i = 0usize;
    while i < 8 {
        out[i] = crate::ct::build_nibble_sbox_anf(&sboxes[i]);
        i += 1;
    }
    out
}

const SBOXES_ANF: [[u16; STATE_WORDS]; SBOX_COUNT] = build_sboxes_anf(&SBOXES);
const INV_SBOXES_ANF: [[u16; STATE_WORDS]; SBOX_COUNT] = build_sboxes_anf(&INV_SBOXES);

/// Apply one 4-bit S-box to all 32 bitslice lanes at once, word-parallel.
///
/// **Bitslice representation.**  Serpent stores one 128-bit block as four 32-bit
/// words `[x0, x1, x2, x3]`.  Bit `i` of word `j` is the `j`th input bit of the
/// `i`th of the 32 parallel 4-bit S-box "lanes" (`x0` = least-significant nibble
/// bit).
///
/// **How it works.**  Every S-box output bit is a GF(2) multilinear polynomial
/// (Algebraic Normal Form) in the four input bits.  `coeffs[j]` packs the ANF of
/// output bit `j`: bit `m` is set iff monomial `m` is present, where `m` is the
/// 4-bit subset mask over `{x0, x1, x2, x3}`.  Building the 16 monomial products
/// once and XOR-accumulating the selected ones evaluates the S-box on all 32
/// lanes simultaneously with a fixed sequence of word-wide `AND`/`XOR`s — no
/// per-lane loop, no table read.
///
/// The operation sequence and memory-access pattern depend only on the
/// (public) round-selected `coeffs`, never on block or key data, so this is
/// constant-time.  The `coeffs` are compile-time constants from
/// [`crate::ct::build_nibble_sbox_anf`], so the output is bit-for-bit identical
/// to a direct table lookup.
#[inline]
fn apply_sbox_words(words: [u32; STATE_WORDS], coeffs: [u16; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let [x0, x1, x2, x3] = words;

    // mono[m] = AND over k of x_k for each bit k set in the subset mask m;
    // mono[0] is the empty product = 1, i.e. all-ones in every lane.
    let mut mono = [0u32; 16];
    mono[0] = u32::MAX;
    mono[1] = x0;
    mono[2] = x1;
    mono[4] = x2;
    mono[8] = x3;
    mono[3] = x0 & x1;
    mono[5] = x0 & x2;
    mono[6] = x1 & x2;
    mono[9] = x0 & x3;
    mono[10] = x1 & x3;
    mono[12] = x2 & x3;
    mono[7] = mono[3] & x2;
    mono[11] = mono[3] & x3;
    mono[13] = mono[5] & x3;
    mono[14] = mono[6] & x3;
    mono[15] = mono[7] & x3;

    let mut out = [0u32; STATE_WORDS];
    let mut j = 0usize;
    while j < 4 {
        let c = coeffs[j];
        let mut acc = 0u32;
        let mut m = 0usize;
        while m < 16 {
            // Include monomial m iff its ANF coefficient bit is set.  `present`
            // is derived only from the public, round-selected coefficients — not
            // from secret data — so accumulation stays constant-time.
            let present = 0u32.wrapping_sub(u32::from((c >> m) & 1));
            acc ^= mono[m] & present;
            m += 1;
        }
        out[j] = acc;
        j += 1;
    }
    out
}

#[inline]
fn apply_sbox_round(words: [u32; STATE_WORDS], round: usize) -> [u32; STATE_WORDS] {
    apply_sbox_words(words, SBOXES_ANF[round & 7])
}

#[inline]
fn apply_inv_sbox_round(words: [u32; STATE_WORDS], round: usize) -> [u32; STATE_WORDS] {
    apply_sbox_words(words, INV_SBOXES_ANF[round & 7])
}

/// Lane-by-lane table lookup: the S-box definition applied directly, kept as
/// the oracle the word-parallel evaluation is tested against.
#[cfg(test)]
fn apply_sbox_table(words: [u32; STATE_WORDS], table: &[u8; 16]) -> [u32; STATE_WORDS] {
    let [x0, x1, x2, x3] = words;
    let mut out = [0u32; STATE_WORDS];
    let mut bit = 0u32;
    while bit < 32 {
        let nibble = (((x0 >> bit) & 1)
            | (((x1 >> bit) & 1) << 1)
            | (((x2 >> bit) & 1) << 2)
            | (((x3 >> bit) & 1) << 3)) as usize;
        let s = table[nibble];
        out[0] |= u32::from(s & 1) << bit;
        out[1] |= u32::from((s >> 1) & 1) << bit;
        out[2] |= u32::from((s >> 2) & 1) << bit;
        out[3] |= u32::from((s >> 3) & 1) << bit;
        bit += 1;
    }
    out
}

#[inline]
fn lt(words: [u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut x0 = words[0].rotate_left(13);
    let mut x2 = words[2].rotate_left(3);
    let mut x1 = words[1] ^ x0 ^ x2;
    let mut x3 = words[3] ^ x2 ^ (x0 << 3);
    x1 = x1.rotate_left(1);
    x3 = x3.rotate_left(7);
    x0 ^= x1 ^ x3;
    x2 ^= x3 ^ (x1 << 7);
    x0 = x0.rotate_left(5);
    x2 = x2.rotate_left(22);
    [x0, x1, x2, x3]
}

#[inline]
fn inv_lt(words: [u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut x0 = words[0].rotate_right(5);
    let mut x1 = words[1];
    let mut x2 = words[2].rotate_right(22);
    let mut x3 = words[3];
    x2 ^= x3 ^ (x1 << 7);
    x0 ^= x1 ^ x3;
    x3 = x3.rotate_right(7);
    x1 = x1.rotate_right(1);
    x3 ^= x2 ^ (x0 << 3);
    x1 ^= x0 ^ x2;
    x2 = x2.rotate_right(3);
    x0 = x0.rotate_right(13);
    [x0, x1, x2, x3]
}

/// Block bytes to the paper's little-endian words: word `j` is bytes
/// `4j..4j+4`, least significant byte first.
#[inline]
fn words_from_block(block: &[u8; BLOCK_BYTES]) -> [u32; STATE_WORDS] {
    [
        u32::from_le_bytes(block[0..4].try_into().unwrap()),
        u32::from_le_bytes(block[4..8].try_into().unwrap()),
        u32::from_le_bytes(block[8..12].try_into().unwrap()),
        u32::from_le_bytes(block[12..16].try_into().unwrap()),
    ]
}

#[inline]
fn block_from_words(words: [u32; STATE_WORDS]) -> [u8; BLOCK_BYTES] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&words[0].to_le_bytes());
    out[4..8].copy_from_slice(&words[1].to_le_bytes());
    out[8..12].copy_from_slice(&words[2].to_le_bytes());
    out[12..16].copy_from_slice(&words[3].to_le_bytes());
    out
}

/// Expand a 16-, 24- or 32-byte key into the 33 round keys, written directly
/// into `out` (the caller's struct field). Short keys are padded with a `1`
/// bit at the most significant end followed by zeros (paper §2); the prekeys
/// `w_{-8}..w_131` follow the paper's affine recurrence and the round keys are
/// the S-boxed prekey groups, S-box `(3 - i) mod 8` for round key `i`.
fn expand_round_keys<const N: usize>(
    user_key: &[u8; N],
    out: &mut [[u32; STATE_WORDS]; ROUND_KEYS],
) {
    let mut padded = [0u8; PADDED_KEY_BYTES];
    padded[..N].copy_from_slice(user_key);
    if N < PADDED_KEY_BYTES {
        padded[N] = 1;
    }

    let mut words = [0u32; PREKEY_WORDS];
    let mut i = 0usize;
    while i < PREKEY_SEED_WORDS {
        let off = WORD_BYTES * i;
        words[i] = u32::from_le_bytes(padded[off..off + WORD_BYTES].try_into().unwrap());
        i += 1;
    }
    while i < PREKEY_WORDS {
        words[i] = (words[i - 8]
            ^ words[i - 5]
            ^ words[i - 3]
            ^ words[i - 1]
            ^ PHI
            ^ u32::try_from(i - PREKEY_SEED_WORDS).expect("round-key index fits in u32"))
        .rotate_left(11);
        i += 1;
    }

    let mut input = [0u32; STATE_WORDS];
    let mut round = 0usize;
    while round < ROUND_KEYS {
        let sbox_idx = (3usize.wrapping_sub(round)) & (SBOX_COUNT - 1);
        let first = PREKEY_SEED_WORDS + STATE_WORDS * round;
        input.copy_from_slice(&words[first..first + STATE_WORDS]);
        out[round] = apply_sbox_words(input, SBOXES_ANF[sbox_idx]);
        round += 1;
    }

    // The padded key and the 140-word prekey are the user key in other
    // shapes: only the round keys may outlive this call.
    zeroize_slice(padded.as_mut_slice());
    zeroize_slice(words.as_mut_slice());
    zeroize_slice(input.as_mut_slice());
}

fn serpent_encrypt_words(
    mut state: [u32; STATE_WORDS],
    round_keys: &[[u32; STATE_WORDS]; ROUND_KEYS],
) -> [u32; STATE_WORDS] {
    let mut round = 0usize;
    while round < ROUNDS - 1 {
        state[0] ^= round_keys[round][0];
        state[1] ^= round_keys[round][1];
        state[2] ^= round_keys[round][2];
        state[3] ^= round_keys[round][3];
        state = apply_sbox_round(state, round);
        state = lt(state);
        round += 1;
    }

    state[0] ^= round_keys[ROUNDS - 1][0];
    state[1] ^= round_keys[ROUNDS - 1][1];
    state[2] ^= round_keys[ROUNDS - 1][2];
    state[3] ^= round_keys[ROUNDS - 1][3];
    state = apply_sbox_round(state, ROUNDS - 1);
    state[0] ^= round_keys[ROUNDS][0];
    state[1] ^= round_keys[ROUNDS][1];
    state[2] ^= round_keys[ROUNDS][2];
    state[3] ^= round_keys[ROUNDS][3];
    state
}

fn serpent_decrypt_words(
    mut state: [u32; STATE_WORDS],
    round_keys: &[[u32; STATE_WORDS]; ROUND_KEYS],
) -> [u32; STATE_WORDS] {
    state[0] ^= round_keys[ROUNDS][0];
    state[1] ^= round_keys[ROUNDS][1];
    state[2] ^= round_keys[ROUNDS][2];
    state[3] ^= round_keys[ROUNDS][3];
    state = apply_inv_sbox_round(state, ROUNDS - 1);
    state[0] ^= round_keys[ROUNDS - 1][0];
    state[1] ^= round_keys[ROUNDS - 1][1];
    state[2] ^= round_keys[ROUNDS - 1][2];
    state[3] ^= round_keys[ROUNDS - 1][3];

    let mut round = ROUNDS - 1;
    while round > 0 {
        round -= 1;
        state = inv_lt(state);
        state = apply_inv_sbox_round(state, round);
        state[0] ^= round_keys[round][0];
        state[1] ^= round_keys[round][1];
        state[2] ^= round_keys[round][2];
        state[3] ^= round_keys[round][3];
    }

    state
}

macro_rules! serpent_type {
    ($name:ident, $name_ct:ident, $key_len:expr, $doc:literal, $doc_ct:literal) => {
        #[doc = $doc]
        pub struct $name {
            round_keys: [[u32; STATE_WORDS]; ROUND_KEYS],
        }

        impl $name {
            /// Expand the user key into the 33 Serpent round keys.
            #[must_use]
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut cipher = Self {
                    round_keys: [[0u32; STATE_WORDS]; ROUND_KEYS],
                };
                expand_round_keys(key, &mut cipher.round_keys);
                cipher
            }

            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let cipher = Self::new(key);
                zeroize_slice(key);
                cipher
            }

            /// Encrypt one 128-bit block (little-endian words, see the module
            /// documentation).
            #[must_use]
            pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
                block_from_words(serpent_encrypt_words(
                    words_from_block(block),
                    &self.round_keys,
                ))
            }

            /// Decrypt one 128-bit block (little-endian words, see the module
            /// documentation).
            #[must_use]
            pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
                block_from_words(serpent_decrypt_words(
                    words_from_block(block),
                    &self.round_keys,
                ))
            }
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = 16;

            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; BLOCK_BYTES] = (&*block).try_into().expect("wrong block length");
                let ct = self.encrypt_block(arr);
                block.copy_from_slice(&ct);
            }

            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; BLOCK_BYTES] = (&*block).try_into().expect("wrong block length");
                let pt = self.decrypt_block(arr);
                block.copy_from_slice(&pt);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                for rk in &mut self.round_keys {
                    zeroize_slice(rk);
                }
            }
        }

        #[doc = $doc_ct]
        pub type $name_ct = $name;
    };
}

serpent_type!(
    Serpent128,
    Serpent128Ct,
    KEY128_BYTES,
    "Serpent with a 128-bit key: 32 rounds over four little-endian 32-bit words, with the word-parallel bitsliced S-box (constant-time by construction).",
    "Alias of [`Serpent128`], retained for API symmetry with the other block ciphers: the shipped round function is already table-free, so there is no separate constant-time implementation."
);
serpent_type!(
    Serpent192,
    Serpent192Ct,
    KEY192_BYTES,
    "Serpent with a 192-bit key: 32 rounds over four little-endian 32-bit words, with the word-parallel bitsliced S-box (constant-time by construction).",
    "Alias of [`Serpent192`], retained for API symmetry with the other block ciphers: the shipped round function is already table-free, so there is no separate constant-time implementation."
);
serpent_type!(
    Serpent256,
    Serpent256Ct,
    KEY256_BYTES,
    "Serpent with a 256-bit key: 32 rounds over four little-endian 32-bit words, with the word-parallel bitsliced S-box (constant-time by construction).",
    "Alias of [`Serpent256`], retained for API symmetry with the other block ciphers: the shipped round function is already table-free, so there is no separate constant-time implementation."
);

/// Default Serpent instantiation: alias for [`Serpent128`] (128-bit key).
pub type Serpent = Serpent128;
/// Alias of [`Serpent`] (that is, of [`Serpent128`]), retained for API
/// symmetry: the shipped round function is already constant-time.
pub type SerpentCt = Serpent128Ct;

#[cfg(test)]
mod tests {
    // Known answers come from the Serpent AES submission package by Anderson,
    // Biham and Knudsen, https://www.cl.cam.ac.uk/~rja14/Papers/serpent.tar.gz
    // (SHA-256 7af7efb13c537d707db45dc727b2d998
    // 7df8e7f137a04a056dbedf6995e9b748), directory `floppy4/`: `ecb_vk.txt`
    // (variable key, plaintext zero) and `ecb_vt.txt` (variable text, key
    // zero). Those files write values most significant byte first, so each
    // entry is checked as `encrypt(rev(K), rev(P)) == rev(C)` in this API's
    // little-endian byte order (module documentation). `ecb_vk.txt` I=121 for
    // the 128-bit key is the byte-reversed form of the NESSIE-format vector
    // (key 80 00..00, plaintext zero, ciphertext 264E5481…), which is also
    // pinned directly.
    use super::*;
    use crate::test_utils::decode_hex;

    /// Small deterministic xorshift64 PRNG for reproducible pseudorandom tests.
    struct XorShift64(u64);
    impl XorShift64 {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    /// Prove the word-parallel bitsliced S-box is bit-for-bit identical to the
    /// lane-by-lane table lookup, for every S-box (forward and inverse).
    ///
    /// Part (a) is exhaustive over the S-box *definition*: for each of the 8
    /// S-boxes and each of the 16 nibble inputs, drive all 32 lanes with that one
    /// nibble and compare against the table oracle — this covers every entry of
    /// every S-box table.  Part (b) then fuzzes mixed-lane words so that arbitrary
    /// combinations of the 32 independent lanes are exercised together.
    #[test]
    fn word_parallel_sbox_matches_table_reference() {
        // (a) Exhaustive: all 16 nibble inputs x all 8 S-boxes, forward + inverse.
        for i in 0..8 {
            for n in 0u32..16 {
                let w = [
                    if n & 1 != 0 { u32::MAX } else { 0 },
                    if n & 2 != 0 { u32::MAX } else { 0 },
                    if n & 4 != 0 { u32::MAX } else { 0 },
                    if n & 8 != 0 { u32::MAX } else { 0 },
                ];
                assert_eq!(
                    apply_sbox_words(w, SBOXES_ANF[i]),
                    apply_sbox_table(w, &SBOXES[i]),
                    "forward S-box {i} nibble {n}"
                );
                assert_eq!(
                    apply_sbox_words(w, INV_SBOXES_ANF[i]),
                    apply_sbox_table(w, &INV_SBOXES[i]),
                    "inverse S-box {i} nibble {n}"
                );
            }
        }

        // (b) Fuzz mixed-lane words against the table oracle.
        let mut rng = XorShift64(0x2545_f491_4f6c_dd1d);
        for _ in 0..20_000 {
            let w = [
                rng.next() as u32,
                (rng.next() >> 9) as u32,
                rng.next() as u32,
                (rng.next() >> 21) as u32,
            ];
            for i in 0..8 {
                assert_eq!(
                    apply_sbox_words(w, SBOXES_ANF[i]),
                    apply_sbox_table(w, &SBOXES[i]),
                    "forward S-box {i} words {w:08x?}"
                );
                assert_eq!(
                    apply_sbox_words(w, INV_SBOXES_ANF[i]),
                    apply_sbox_table(w, &INV_SBOXES[i]),
                    "inverse S-box {i} words {w:08x?}"
                );
            }
        }
    }

    /// The inverse S-box tables invert the forward tables entry by entry.
    #[test]
    fn inverse_sboxes_invert_forward_sboxes() {
        for i in 0..8 {
            for x in 0u8..16 {
                assert_eq!(INV_SBOXES[i][SBOXES[i][x as usize] as usize], x, "S{i}");
            }
        }
    }

    /// Encrypt/decrypt several thousand pseudorandom blocks under random keys
    /// for all three key sizes, asserting round-trip identity.
    #[test]
    fn encrypt_decrypt_roundtrip_random() {
        let mut rng = XorShift64(0x9e37_79b9_7f4a_7c15);
        for _ in 0..4000 {
            let mut key = [0u8; 32];
            for b in key.iter_mut() {
                *b = rng.next() as u8;
            }
            let mut pt = [0u8; 16];
            for b in pt.iter_mut() {
                *b = rng.next() as u8;
            }
            let k16: [u8; 16] = key[..16].try_into().unwrap();
            let k24: [u8; 24] = key[..24].try_into().unwrap();

            let cipher = Serpent128::new(&k16);
            assert_eq!(cipher.decrypt_block(&cipher.encrypt_block(&pt)), pt, "128");
            let cipher = Serpent192::new(&k24);
            assert_eq!(cipher.decrypt_block(&cipher.encrypt_block(&pt)), pt, "192");
            let cipher = Serpent256::new(&key);
            assert_eq!(cipher.decrypt_block(&cipher.encrypt_block(&pt)), pt, "256");
        }
    }

    /// NESSIE-format vector (Serpent-128, key 80 00..00, plaintext zero) in
    /// this API's byte order, with no reversal.
    #[test]
    fn serpent128_standard_byte_order_vector() {
        let mut key = [0u8; 16];
        key[0] = 0x80;
        let pt = [0u8; 16];
        let ct: [u8; 16] = decode_hex("264E5481EFF42A4606ABDA06C0BFDA3D")
            .try_into()
            .unwrap();
        let cipher = Serpent128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        // `SerpentCt`/`Serpent128Ct` name the same type.
        let cipher: SerpentCt = Serpent128Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
    }

    fn reversed<const N: usize>(hex: &str) -> [u8; N] {
        let mut bytes: [u8; N] = decode_hex(hex).try_into().unwrap();
        bytes.reverse();
        bytes
    }

    /// Check one submission-file entry: `encrypt(rev(K), rev(P)) == rev(C)`
    /// for each key size, dispatching on the key length.
    fn check_submission_entry(label: &str, key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let pt: [u8; 16] = reversed(pt_hex);
        let ct: [u8; 16] = reversed(ct_hex);
        let (enc, dec) = match key_hex.len() / 2 {
            16 => {
                let c = Serpent128::new(&reversed::<16>(key_hex));
                (c.encrypt_block(&pt), c.decrypt_block(&ct))
            }
            24 => {
                let c = Serpent192::new(&reversed::<24>(key_hex));
                (c.encrypt_block(&pt), c.decrypt_block(&ct))
            }
            32 => {
                let c = Serpent256::new(&reversed::<32>(key_hex));
                (c.encrypt_block(&pt), c.decrypt_block(&ct))
            }
            other => panic!("unexpected key length {other}"),
        };
        assert_eq!(enc, ct, "{label}: encrypt");
        assert_eq!(dec, pt, "{label}: decrypt");
    }

    /// `floppy4/ecb_vk.txt` (plaintext zero): I=1 and I=121 for each key size.
    #[test]
    fn submission_variable_key_vectors() {
        const ZERO: &str = "00000000000000000000000000000000";
        let entries = [
            (
                "128 I=1",
                "80000000000000000000000000000000",
                "49afbfad9d5a34052cd8ffa5986bd2dd",
            ),
            (
                "128 I=121",
                "00000000000000000000000000000080",
                "3ddabfc006daab06462af4ef81544e26",
            ),
            (
                "192 I=1",
                "800000000000000000000000000000000000000000000000",
                "e78e5402c7195568ac3678f7a3f60c66",
            ),
            (
                "192 I=121",
                "000000000000000000000000000000800000000000000000",
                "093c1029c5eb09844c39dcb42a6ac5eb",
            ),
            (
                "256 I=1",
                "8000000000000000000000000000000000000000000000000000000000000000",
                "abed96e766bf28cbc0ebd21a82ef0819",
            ),
            (
                "256 I=121",
                "0000000000000000000000000000008000000000000000000000000000000000",
                "eb5d9352b3615c55e895550b497191c1",
            ),
        ];
        for (label, key, ct) in entries {
            check_submission_entry(label, key, ZERO, ct);
        }
    }

    /// `floppy4/ecb_vt.txt` (key zero): I=1 and I=121 for each key size.
    #[test]
    fn submission_variable_text_vectors() {
        const KEY128: &str = "00000000000000000000000000000000";
        const KEY192: &str = "000000000000000000000000000000000000000000000000";
        const KEY256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
        const PT1: &str = "80000000000000000000000000000000";
        const PT121: &str = "00000000000000000000000000000080";
        let entries = [
            ("128 I=1", KEY128, PT1, "10b5ffb720b8cb9002a1142b0ba2e94a"),
            (
                "128 I=121",
                KEY128,
                PT121,
                "bbbcb8648c674426d8dd58c3e75db3a3",
            ),
            ("192 I=1", KEY192, PT1, "b10b271ba25257e1294f2b51f076d0d9"),
            (
                "192 I=121",
                KEY192,
                PT121,
                "bb8a615964c174450d7e68ad32f4f523",
            ),
            ("256 I=1", KEY256, PT1, "da5a7992b1b4ae6f8c004bc8a7de5520"),
            (
                "256 I=121",
                KEY256,
                PT121,
                "6e567fcf2b853dd8ecc3d58a5e671483",
            ),
        ];
        for (label, key, pt, ct) in entries {
            check_submission_entry(label, key, pt, ct);
        }
    }

    /// The `BlockCipher` entry points reject a wrong-length block.
    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_rejects_wrong_length() {
        let cipher = Serpent128::new(&[0u8; 16]);
        let mut short = [0u8; 15];
        cipher.encrypt(&mut short);
    }
}
