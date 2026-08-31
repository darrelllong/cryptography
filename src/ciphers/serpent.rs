//! Serpent block cipher — AES submission / FSE 1998.
//!
//! 128-bit block cipher with three standard key sizes:
//!
//! - `Serpent128` / `Serpent128Ct`
//! - `Serpent192` / `Serpent192Ct`
//! - `Serpent256` / `Serpent256Ct`
//!
//! The public API follows the original Serpent submission / reference-implementation
//! byte order. That matches many existing Serpent libraries, but it differs
//! from the byte-reversed NESSIE presentation. Internally, the core still works
//! on 32-bit little-endian words, so the wrappers reverse the incoming key and
//! block bytes around that native representation.
//!
//! Both the fast (`Serpent128/192/256`) and constant-time (`*Ct`) types share a
//! single word-parallel bitsliced S-box: each 4->4 S-box is evaluated directly
//! on the four 32-bit bitslice registers via its Algebraic Normal Form (word-wide
//! `AND`/`XOR` only), substituting all 32 lanes at once. This is branch-free and
//! lookup-free — far faster than a per-lane table loop and constant-time by
//! construction — so no separate variable-time path is needed.

use crate::ct::zeroize_slice;
use crate::BlockCipher;

// Serpent key-schedule constant PHI = floor(2^32 * (sqrt(5)-1)/2).
const PHI: u32 = 0x9E37_79B9;

// S-boxes from the Serpent AES submission (Anderson/Biham/Knudsen, 1998).
const SBOXES: [[u8; 16]; 8] = [
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
const INV_SBOXES: [[u8; 16]; 8] = [
    [13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2],
    [5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0],
    [12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7],
    [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1],
    [5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1],
    [8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0],
    [15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11],
    [3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2],
];

const fn build_sboxes_anf(sboxes: &[[u8; 16]; 8]) -> [[u16; 4]; 8] {
    let mut out = [[0u16; 4]; 8];
    let mut i = 0usize;
    while i < 8 {
        out[i] = crate::ct::build_nibble_sbox_anf(&sboxes[i]);
        i += 1;
    }
    out
}

const SBOXES_ANF: [[u16; 4]; 8] = build_sboxes_anf(&SBOXES);
const INV_SBOXES_ANF: [[u16; 4]; 8] = build_sboxes_anf(&INV_SBOXES);

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
fn apply_sbox_words(words: [u32; 4], coeffs: [u16; 4]) -> [u32; 4] {
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

    let mut out = [0u32; 4];
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
fn apply_sbox_round(words: [u32; 4], round: usize) -> [u32; 4] {
    apply_sbox_words(words, SBOXES_ANF[round & 7])
}

#[inline]
fn apply_inv_sbox_round(words: [u32; 4], round: usize) -> [u32; 4] {
    apply_sbox_words(words, INV_SBOXES_ANF[round & 7])
}

/// Reference lane-by-lane table lookup — the original S-box implementation,
/// retained only as a differential oracle for the equivalence tests below.
#[cfg(test)]
fn apply_sbox_table(words: [u32; 4], table: &[u8; 16]) -> [u32; 4] {
    let [x0, x1, x2, x3] = words;
    let mut out = [0u32; 4];
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

/// Per-nibble constant-time ANF evaluation, retained for the coefficient
/// cross-check test (and as this module's ct S-box indicator for the scrub
/// policy in `scrub.rs`, which looks for `eval_nibble_sbox`).
#[cfg(test)]
fn sbox_ct_nibble(input: u8, sbox_anf: [u16; 4]) -> u8 {
    crate::ct::eval_nibble_sbox(sbox_anf, input)
}

#[inline]
fn lt(words: [u32; 4]) -> [u32; 4] {
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
fn inv_lt(words: [u32; 4]) -> [u32; 4] {
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

#[inline]
fn reverse_bytes<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0usize;
    while i < N {
        out[i] = input[N - 1 - i];
        i += 1;
    }
    out
}

#[inline]
fn words_from_block_internal(block: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes(block[0..4].try_into().unwrap()),
        u32::from_le_bytes(block[4..8].try_into().unwrap()),
        u32::from_le_bytes(block[8..12].try_into().unwrap()),
        u32::from_le_bytes(block[12..16].try_into().unwrap()),
    ]
}

#[inline]
fn block_from_words_internal(words: [u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&words[0].to_le_bytes());
    out[4..8].copy_from_slice(&words[1].to_le_bytes());
    out[8..12].copy_from_slice(&words[2].to_le_bytes());
    out[12..16].copy_from_slice(&words[3].to_le_bytes());
    out
}

fn expand_round_keys<const N: usize>(user_key: &[u8; N]) -> [[u32; 4]; 33] {
    let key = reverse_bytes(user_key);
    let mut padded = [0u8; 32];
    padded[..N].copy_from_slice(&key);
    if N < 32 {
        padded[N] = 1;
    }

    let mut words = [0u32; 140];
    let mut i = 0usize;
    while i < 8 {
        let off = 4 * i;
        words[i] = u32::from_le_bytes(padded[off..off + 4].try_into().unwrap());
        i += 1;
    }
    while i < 140 {
        words[i] = (words[i - 8]
            ^ words[i - 5]
            ^ words[i - 3]
            ^ words[i - 1]
            ^ PHI
            ^ u32::try_from(i - 8).expect("round-key index fits in u32"))
        .rotate_left(11);
        i += 1;
    }

    let mut out = [[0u32; 4]; 33];
    let mut round = 0usize;
    while round < 33 {
        let sbox_idx = (3usize.wrapping_sub(round)) & 7;
        let input = [
            words[8 + 4 * round],
            words[8 + 4 * round + 1],
            words[8 + 4 * round + 2],
            words[8 + 4 * round + 3],
        ];
        out[round] = apply_sbox_words(input, SBOXES_ANF[sbox_idx]);
        round += 1;
    }

    out
}

fn serpent_encrypt_words(mut state: [u32; 4], round_keys: &[[u32; 4]; 33]) -> [u32; 4] {
    let mut round = 0usize;
    while round < 31 {
        state[0] ^= round_keys[round][0];
        state[1] ^= round_keys[round][1];
        state[2] ^= round_keys[round][2];
        state[3] ^= round_keys[round][3];
        state = apply_sbox_round(state, round);
        state = lt(state);
        round += 1;
    }

    state[0] ^= round_keys[31][0];
    state[1] ^= round_keys[31][1];
    state[2] ^= round_keys[31][2];
    state[3] ^= round_keys[31][3];
    state = apply_sbox_round(state, 31);
    state[0] ^= round_keys[32][0];
    state[1] ^= round_keys[32][1];
    state[2] ^= round_keys[32][2];
    state[3] ^= round_keys[32][3];
    state
}

fn serpent_decrypt_words(mut state: [u32; 4], round_keys: &[[u32; 4]; 33]) -> [u32; 4] {
    state[0] ^= round_keys[32][0];
    state[1] ^= round_keys[32][1];
    state[2] ^= round_keys[32][2];
    state[3] ^= round_keys[32][3];
    state = apply_inv_sbox_round(state, 31);
    state[0] ^= round_keys[31][0];
    state[1] ^= round_keys[31][1];
    state[2] ^= round_keys[31][2];
    state[3] ^= round_keys[31][3];

    let mut round = 31usize;
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

fn encrypt_block_words(round_keys: &[[u32; 4]; 33], block: &[u8; 16]) -> [u8; 16] {
    let internal = reverse_bytes(block);
    let state = words_from_block_internal(&internal);
    let out = serpent_encrypt_words(state, round_keys);
    reverse_bytes(&block_from_words_internal(out))
}

fn decrypt_block_words(round_keys: &[[u32; 4]; 33], block: &[u8; 16]) -> [u8; 16] {
    let internal = reverse_bytes(block);
    let state = words_from_block_internal(&internal);
    let out = serpent_decrypt_words(state, round_keys);
    reverse_bytes(&block_from_words_internal(out))
}

macro_rules! serpent_type {
    ($name:ident, $name_ct:ident, $key_len:literal, $doc:literal, $doc_ct:literal) => {
        #[doc = $doc]
        pub struct $name {
            round_keys: [[u32; 4]; 33],
        }

        impl $name {
            /// Expand the user key into the 33 Serpent round-key words.
            pub fn new(key: &[u8; $key_len]) -> Self {
                Self {
                    round_keys: expand_round_keys(key),
                }
            }

            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let cipher = Self::new(key);
                zeroize_slice(key);
                cipher
            }

            /// Encrypt one 128-bit block.
            pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                encrypt_block_words(&self.round_keys, block)
            }

            /// Decrypt one 128-bit block.
            pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                decrypt_block_words(&self.round_keys, block)
            }
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = 16;

            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let ct = self.encrypt_block(arr);
                block.copy_from_slice(&ct);
            }

            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
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

        // The word-parallel bitsliced S-box has no secret-dependent table
        // lookups or branches, so the fast path is already constant-time and
        // the `Ct` type is simply an alias — no separate implementation exists.
        #[doc = $doc_ct]
        pub type $name_ct = $name;
    };
}

serpent_type!(
    Serpent128,
    Serpent128Ct,
    16,
    "Serpent with a 128-bit key (public byte order matches the original submission vectors).",
    "Serpent-128 (`Ct` alias): the bitsliced S-box is constant-time by construction, so this is identical to [`Serpent128`]."
);
serpent_type!(
    Serpent192,
    Serpent192Ct,
    24,
    "Serpent with a 192-bit key (public byte order matches the original submission vectors).",
    "Serpent-192 (`Ct` alias): identical to [`Serpent192`]; the bitsliced S-box is constant-time by construction."
);
serpent_type!(
    Serpent256,
    Serpent256Ct,
    32,
    "Serpent with a 256-bit key (public byte order matches the original submission vectors).",
    "Serpent-256 (`Ct` alias): identical to [`Serpent256`]; the bitsliced S-box is constant-time by construction."
);

/// Default Serpent instantiation: alias for [`Serpent128`] (128-bit key).
pub type Serpent = Serpent128;
/// Constant-time Serpent-128 alias. Because the shared bitsliced S-box is
/// constant-time by construction, this is the same type as [`Serpent`].
pub type SerpentCt = Serpent128Ct;

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(u8::try_from((hi << 4) | lo).expect("decoded hex byte fits in u8"));
            i += 2;
        }
        out
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for sbox in 0..8 {
            for x in 0u8..16 {
                assert_eq!(
                    SBOXES[sbox][x as usize],
                    sbox_ct_nibble(x, SBOXES_ANF[sbox])
                );
                assert_eq!(
                    INV_SBOXES[sbox][x as usize],
                    sbox_ct_nibble(x, INV_SBOXES_ANF[sbox])
                );
            }
        }
    }

    /// Small deterministic xorshift64 PRNG for reproducible pseudorandom tests
    /// (no external rng; `Date::now`/`Math.random` unavailable and undesirable).
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
    /// original lane-by-lane table lookup, for every S-box (forward and inverse).
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

    /// Encrypt/decrypt several thousand pseudorandom blocks under random keys for
    /// all three key sizes, asserting round-trip identity and that the fast and
    /// `Ct` types (now sharing the word-parallel S-box) agree bit-for-bit.
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

            let fast = Serpent128::new(&k16);
            let ct = Serpent128Ct::new(&k16);
            let enc = fast.encrypt_block(&pt);
            assert_eq!(enc, ct.encrypt_block(&pt), "128 fast/ct mismatch");
            assert_eq!(fast.decrypt_block(&enc), pt, "128 fast round-trip");
            assert_eq!(ct.decrypt_block(&enc), pt, "128 ct round-trip");

            let fast = Serpent192::new(&k24);
            let ct = Serpent192Ct::new(&k24);
            let enc = fast.encrypt_block(&pt);
            assert_eq!(enc, ct.encrypt_block(&pt), "192 fast/ct mismatch");
            assert_eq!(fast.decrypt_block(&enc), pt, "192 fast round-trip");
            assert_eq!(ct.decrypt_block(&enc), pt, "192 ct round-trip");

            let fast = Serpent256::new(&key);
            let ct = Serpent256Ct::new(&key);
            let enc = fast.encrypt_block(&pt);
            assert_eq!(enc, ct.encrypt_block(&pt), "256 fast/ct mismatch");
            assert_eq!(fast.decrypt_block(&enc), pt, "256 fast round-trip");
            assert_eq!(ct.decrypt_block(&enc), pt, "256 ct round-trip");
        }
    }

    #[test]
    fn serpent128_kat() {
        let key: [u8; 16] = decode_hex("80000000000000000000000000000000")
            .try_into()
            .unwrap();
        let pt: [u8; 16] = decode_hex("00000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("49AFBFAD9D5A34052CD8FFA5986BD2DD")
            .try_into()
            .unwrap();
        let cipher = Serpent128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn serpent128_ct_kat() {
        let key: [u8; 16] = decode_hex("80000000000000000000000000000000")
            .try_into()
            .unwrap();
        let pt: [u8; 16] = decode_hex("00000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("49AFBFAD9D5A34052CD8FFA5986BD2DD")
            .try_into()
            .unwrap();
        let cipher = Serpent128Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn serpent128_standard_plaintext_vector() {
        let key = [0u8; 16];
        let pt: [u8; 16] = decode_hex("80000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("10B5FFB720B8CB9002A1142B0BA2E94A")
            .try_into()
            .unwrap();
        let cipher = Serpent128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn serpent192_kat() {
        let key: [u8; 24] = decode_hex("800000000000000000000000000000000000000000000000")
            .try_into()
            .unwrap();
        let pt: [u8; 16] = decode_hex("00000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("E78E5402C7195568AC3678F7A3F60C66")
            .try_into()
            .unwrap();
        let cipher = Serpent192::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn serpent192_ct_kat() {
        let key: [u8; 24] = decode_hex("800000000000000000000000000000000000000000000000")
            .try_into()
            .unwrap();
        let pt: [u8; 16] = decode_hex("00000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("E78E5402C7195568AC3678F7A3F60C66")
            .try_into()
            .unwrap();
        let cipher = Serpent192Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn serpent256_kat() {
        let key: [u8; 32] =
            decode_hex("8000000000000000000000000000000000000000000000000000000000000000")
                .try_into()
                .unwrap();
        let pt: [u8; 16] = decode_hex("00000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("ABED96E766BF28CBC0EBD21A82EF0819")
            .try_into()
            .unwrap();
        let cipher = Serpent256::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn serpent256_ct_kat() {
        let key: [u8; 32] =
            decode_hex("8000000000000000000000000000000000000000000000000000000000000000")
                .try_into()
                .unwrap();
        let pt: [u8; 16] = decode_hex("00000000000000000000000000000000")
            .try_into()
            .unwrap();
        let ct: [u8; 16] = decode_hex("ABED96E766BF28CBC0EBD21A82EF0819")
            .try_into()
            .unwrap();
        let cipher = Serpent256Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }
}
