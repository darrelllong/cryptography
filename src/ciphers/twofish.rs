//! Twofish block cipher — AES submission (1998).
//!
//! 128-bit block cipher with the three key sizes the submission defines
//! (paper §4.3: "Twofish is defined for keys of length N = 128, N = 192, and
//! N = 256"):
//!
//! - `Twofish128` / `Twofish128Ct`
//! - `Twofish192` / `Twofish192Ct`
//! - `Twofish256` / `Twofish256Ct`
//!
//! Paper §4.3.1 admits shorter keys by padding them with zero bytes up to the
//! next defined length; this crate exposes only the three defined lengths, so
//! a caller with a shorter key performs that zero padding itself.
//!
//! The fast path keeps direct lookup tables for the 8-bit `q0` / `q1`
//! permutations used inside the keyed `h` function. `Ct` variants evaluate the
//! same permutations from the published 4-bit building blocks with fixed-scan
//! nibble selection so the round function and key schedule avoid
//! secret-indexed table reads.

use crate::ct::zeroize_slice;
use crate::BlockCipher;

// Twofish key-schedule stride constant from the submission.
const RHO: u32 = 0x0101_0101;
// Twofish uses two GF(2^8) reduction polynomials:
// - MDS matrix multiply: v(x) = x^8 + x^6 + x^5 + x^3 + 1 (0x169)
// - RS key compressor:  w(x) = x^8 + x^6 + x^3 + x^2 + 1 (0x14d)
const MDS_GF_POLY: u16 = 0x0169;
const RS_GF_POLY: u16 = 0x014d;

const Q0_T0: [u8; 16] = [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4];
const Q0_T1: [u8; 16] = [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13];
const Q0_T2: [u8; 16] = [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1];
const Q0_T3: [u8; 16] = [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10];

const Q1_T0: [u8; 16] = [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5];
const Q1_T1: [u8; 16] = [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8];
const Q1_T2: [u8; 16] = [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15];
const Q1_T3: [u8; 16] = [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10];

// Reed-Solomon matrix used to compress each 64-bit key chunk into S-box key words.
const RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];

// Maximum-distance-separable matrix for the `h()` output diffusion layer.
const MDS: [[u8; 4]; 4] = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
];

#[inline]
const fn nibble_lookup(table: &[u8; 16], idx: u8) -> u8 {
    table[idx as usize]
}

#[inline]
const fn ror4(x: u8) -> u8 {
    ((x >> 1) | ((x & 1) << 3)) & 0x0f
}

// Twofish defines q0 / q1 as 8-bit bijections built from two rounds of a
// balanced Feistel network over nibble pairs, interleaved with four fixed
// 4-bit lookup stages (T0..T3).  We keep that structure visible so the fast
// and `Ct` paths share the same logic and only differ in how each nibble is
// selected (direct table vs. `ct_lookup_u8_16`).
//
// One round of the Feistel mix: given upper nibble `a` and lower nibble `b`,
//   a' = a ^ b
//   b' = a ^ ror4(b) ^ ((a << 3) & 0xf)
// where ror4 is a 4-bit right rotation.  This provides the avalanche that
// makes q a non-trivial permutation despite the small nibble tables.
const fn q_perm_const(x: u8, which: usize) -> u8 {
    let (t0, t1, t2, t3) = if which == 0 {
        (&Q0_T0, &Q0_T1, &Q0_T2, &Q0_T3)
    } else {
        (&Q1_T0, &Q1_T1, &Q1_T2, &Q1_T3)
    };

    let a0 = x >> 4;
    let b0 = x & 0x0f;
    // Round 1 Feistel mix.
    let a1 = a0 ^ b0;
    let b1 = a0 ^ ror4(b0) ^ ((a0 << 3) & 0x0f);
    // Two independent nibble lookups.
    let a2 = nibble_lookup(t0, a1);
    let b2 = nibble_lookup(t1, b1);
    // Round 2 Feistel mix.
    let a3 = a2 ^ b2;
    let b3 = a2 ^ ror4(b2) ^ ((a2 << 3) & 0x0f);
    // Final two independent nibble lookups.
    let a4 = nibble_lookup(t2, a3);
    let b4 = nibble_lookup(t3, b3);
    (b4 << 4) | a4
}

const fn build_q(which: usize) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0u8;
    loop {
        out[i as usize] = q_perm_const(i, which);
        if i == u8::MAX {
            break;
        }
        i = i.wrapping_add(1);
    }
    out
}

const Q0: [u8; 256] = build_q(0);
const Q1: [u8; 256] = build_q(1);

#[inline]
fn q_perm_ct(x: u8, which: usize) -> u8 {
    let (t0, t1, t2, t3) = if which == 0 {
        (&Q0_T0, &Q0_T1, &Q0_T2, &Q0_T3)
    } else {
        (&Q1_T0, &Q1_T1, &Q1_T2, &Q1_T3)
    };

    let a0 = x >> 4;
    let b0 = x & 0x0f;
    let a1 = a0 ^ b0;
    let b1 = a0 ^ ror4(b0) ^ ((a0 << 3) & 0x0f);
    let a2 = crate::ct::ct_lookup_u8_16(t0, a1);
    let b2 = crate::ct::ct_lookup_u8_16(t1, b1);
    let a3 = a2 ^ b2;
    let b3 = a2 ^ ror4(b2) ^ ((a2 << 3) & 0x0f);
    let a4 = crate::ct::ct_lookup_u8_16(t2, a3);
    let b4 = crate::ct::ct_lookup_u8_16(t3, b3);
    (b4 << 4) | a4
}

#[inline]
fn q_perm(x: u8, which: usize, use_ct: bool) -> u8 {
    if use_ct {
        q_perm_ct(x, which)
    } else if which == 0 {
        Q0[x as usize]
    } else {
        Q1[x as usize]
    }
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8, poly: u16) -> u8 {
    let mut out = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        out ^= a & mask;
        let hi = a & 0x80;
        a <<= 1;
        a ^= ((poly & 0xff) as u8) & 0u8.wrapping_sub((hi >> 7) & 1);
        b >>= 1;
    }
    out
}

fn rs_encode(bytes: [u8; 8]) -> u32 {
    // The RS matrix compresses each 64-bit key chunk into one S-box key word.
    let mut out = [0u8; 4];
    let mut row = 0usize;
    while row < 4 {
        let mut acc = 0u8;
        let mut col = 0usize;
        while col < 8 {
            acc ^= gf_mul(RS[row][col], bytes[col], RS_GF_POLY);
            col += 1;
        }
        out[row] = acc;
        row += 1;
    }
    u32::from_le_bytes(out)
}

#[inline]
fn b(word: u32, idx: usize) -> u8 {
    ((word >> (idx * 8)) & 0xff) as u8
}

fn mds_multiply(y: [u8; 4]) -> u32 {
    // Twofish's keyed `h()` function always ends with the fixed 4x4 MDS mix.
    let mut out = [0u8; 4];
    let mut row = 0usize;
    while row < 4 {
        let mut acc = 0u8;
        let mut col = 0usize;
        while col < 4 {
            acc ^= gf_mul(MDS[row][col], y[col], MDS_GF_POLY);
            col += 1;
        }
        out[row] = acc;
        row += 1;
    }
    u32::from_le_bytes(out)
}

// One column of the fixed 4x4 MDS mix, packed as the little-endian `u32` it
// contributes to `mds_multiply`'s output.  Because both the MDS layer and
// `u32::from_le_bytes` are linear over XOR, `mds_multiply(y)` equals the XOR of
// `mds_column(j, y[j])` across the four columns — the identity that lets the
// keyed S-box and the MDS diffusion collapse into one table lookup.
fn mds_column(col: usize, val: u8) -> u32 {
    let mut out = [0u8; 4];
    let mut row = 0usize;
    while row < 4 {
        out[row] = gf_mul(MDS[row][col], val, MDS_GF_POLY);
        row += 1;
    }
    u32::from_le_bytes(out)
}

// The keyed q-permutation cascade for a single input byte at column `j`, before
// the MDS mix. This is the one definition of Twofish's per-byte `h` transform:
// `h()` applies it to all four bytes, and the fast-path table builder maps it
// over all 256 inputs per column. Keeping it per byte is what makes that
// precomputation possible — each pre-MDS output byte depends only on its input
// byte. `s` is the key material (`l` in `h`); `use_ct` selects the constant-time
// q-permutation.
fn keyed_h_byte(v: u8, j: usize, s: &[u32; 4], words: usize, use_ct: bool) -> u8 {
    // Which q-permutation each column uses in the extra 192-/256-bit layers.
    const W4: [usize; 4] = [1, 0, 0, 1];
    const W3: [usize; 4] = [1, 1, 0, 0];

    let mut y = v;
    if words == 4 {
        y = q_perm(y, W4[j], use_ct) ^ b(s[3], j);
    }
    if words >= 3 {
        y = q_perm(y, W3[j], use_ct) ^ b(s[2], j);
    }

    // The shared 128-bit keyed core from the submission paper.
    match j {
        0 => q_perm(
            q_perm(q_perm(y, 0, use_ct) ^ b(s[1], 0), 0, use_ct) ^ b(s[0], 0),
            1,
            use_ct,
        ),
        1 => q_perm(
            q_perm(q_perm(y, 1, use_ct) ^ b(s[1], 1), 0, use_ct) ^ b(s[0], 1),
            0,
            use_ct,
        ),
        2 => q_perm(
            q_perm(q_perm(y, 0, use_ct) ^ b(s[1], 2), 1, use_ct) ^ b(s[0], 2),
            1,
            use_ct,
        ),
        3 => q_perm(
            q_perm(q_perm(y, 1, use_ct) ^ b(s[1], 3), 1, use_ct) ^ b(s[0], 3),
            0,
            use_ct,
        ),
        _ => unreachable!(),
    }
}

/// The fast path's four keyed 256-entry tables: the S-box cascade composed
/// with one MDS column. Built once per key, they turn each `h()` on the hot
/// round path into four table lookups and three XORs, replacing two keyed
/// `h()` evaluations (each with sixteen loop-based GF multiplies) per round.
///
/// The tables are secret key material (they depend on `S`); the fast path is
/// already documented as using secret-indexed lookups, so they change nothing
/// about its side-channel posture. They sit behind a `Box` so moving a cipher
/// copies one pointer instead of 4 KB of key-derived data that could never be
/// wiped, and the one heap copy wipes itself on drop.
struct KeyedTables(Box<[[u32; 256]; 4]>);

impl KeyedTables {
    /// All-zero tables on the heap, to be filled in place by [`Self::fill`].
    fn empty() -> Self {
        Self(Box::new([[0u32; 256]; 4]))
    }

    /// Fill the tables from an expanded schedule's S-box key words.
    fn fill(&mut self, key: &TwofishKey) {
        let tables = &mut self.0;
        let mut j = 0usize;
        while j < 4 {
            let mut v = 0usize;
            while v < 256 {
                let hb = keyed_h_byte(v as u8, j, &key.s, key.words, false);
                tables[j][v] = mds_column(j, hb);
                v += 1;
            }
            j += 1;
        }
    }

    /// FAST-path evaluation of the keyed `h()` via the precomputed tables.
    #[inline]
    fn h(&self, x: u32) -> u32 {
        let tables = &self.0;
        tables[0][(x & 0xff) as usize]
            ^ tables[1][((x >> 8) & 0xff) as usize]
            ^ tables[2][((x >> 16) & 0xff) as usize]
            ^ tables[3][((x >> 24) & 0xff) as usize]
    }
}

impl Drop for KeyedTables {
    fn drop(&mut self) {
        for table in self.0.iter_mut() {
            zeroize_slice(table);
        }
    }
}

// The keyed function `h`: apply the per-byte cascade to each of the four input
// bytes, then mix the results through the MDS matrix. The Ct path computes this
// directly (with `use_ct`); the fast path precomputes it as tables via
// `KeyedTables::build`, which maps the same `keyed_h_byte` over every input.
fn h(x: u32, l: &[u32; 4], words: usize, use_ct: bool) -> u32 {
    let xb = x.to_le_bytes();
    let y = [
        keyed_h_byte(xb[0], 0, l, words, use_ct),
        keyed_h_byte(xb[1], 1, l, words, use_ct),
        keyed_h_byte(xb[2], 2, l, words, use_ct),
        keyed_h_byte(xb[3], 3, l, words, use_ct),
    ];
    mds_multiply(y)
}

/// One Twofish key schedule: the 40 whitening and round subkeys, the S-box
/// key words `S`, and the key length in 64-bit words.
///
/// Deliberately not `Copy`, so it is never silently duplicated by value, and
/// it wipes itself on drop. The fast types pair it with [`KeyedTables`]; the
/// constant-time types carry it alone.
struct TwofishKey {
    subkeys: [u32; 40],
    s: [u32; 4],
    words: usize,
}

impl TwofishKey {
    /// An all-zero schedule for a key of `words` 64-bit words (2, 3 or 4),
    /// to be filled in place by [`Self::expand`].
    fn empty(words: usize) -> Self {
        Self {
            subkeys: [0u32; 40],
            s: [0u32; 4],
            words,
        }
    }

    /// Expand a 16-, 24-, or 32-byte key into this schedule, evaluating `h()`
    /// through the constant-time q-permutations when `use_ct` is set. Subkeys
    /// and `S` are written straight into `self`; the key's even and odd words
    /// `Me`/`Mo` are wiped before returning.
    fn expand<const N: usize>(&mut self, key: &[u8; N], use_ct: bool) {
        let words = N / 8;
        debug_assert_eq!(words, self.words);
        let mut me = [0u32; 4];
        let mut mo = [0u32; 4];

        let mut word_idx = 0usize;
        while word_idx < words {
            // Even and odd 32-bit words feed separate `h()` calls in the subkey
            // schedule, while the RS matrix derives the S-box key words in reverse
            // chunk order.
            me[word_idx] =
                u32::from_le_bytes(key[word_idx * 8..word_idx * 8 + 4].try_into().unwrap());
            mo[word_idx] =
                u32::from_le_bytes(key[word_idx * 8 + 4..word_idx * 8 + 8].try_into().unwrap());
            let chunk: &[u8; 8] = key[word_idx * 8..word_idx * 8 + 8].try_into().unwrap();
            self.s[words - 1 - word_idx] = rs_encode(*chunk);
            word_idx += 1;
        }

        let mut subkey_idx = 0usize;
        while subkey_idx < 20 {
            // K[0..3] are input whitening, K[4..7] output whitening, and the
            // remaining 32 words supply the 16 rounds.
            let even_input = u32::try_from(2 * subkey_idx).expect("subkey index fits in u32");
            let odd_input = even_input + 1;
            let even_g = h(even_input.wrapping_mul(RHO), &me, words, use_ct);
            let odd_g = h(odd_input.wrapping_mul(RHO), &mo, words, use_ct).rotate_left(8);
            self.subkeys[2 * subkey_idx] = even_g.wrapping_add(odd_g);
            self.subkeys[2 * subkey_idx + 1] = even_g
                .wrapping_add(odd_g.wrapping_add(odd_g))
                .rotate_left(9);
            subkey_idx += 1;
        }

        zeroize_slice(&mut me);
        zeroize_slice(&mut mo);
    }

    #[inline]
    fn round_f(&self, h_round: &impl Fn(u32) -> u32, x0: u32, x1: u32, round: usize) -> (u32, u32) {
        // Twofish's round function is the pair of keyed `g()` calls followed by
        // the pseudo-Hadamard transform and round subkey injection.
        let t0 = h_round(x0);
        let t1 = h_round(x1.rotate_left(8));
        let f0 = t0
            .wrapping_add(t1)
            .wrapping_add(self.subkeys[8 + 2 * round]);
        let f1 = t0
            .wrapping_add(t1.wrapping_add(t1))
            .wrapping_add(self.subkeys[8 + 2 * round + 1]);
        (f0, f1)
    }

    /// Encrypt one block with `h_round` as the keyed `h()`: table lookups on
    /// the fast path, direct constant-time evaluation on the `Ct` path. Each
    /// path is monomorphized, so no per-round branch selects between them.
    fn encrypt_block(&self, h_round: impl Fn(u32) -> u32, block: &[u8; 16]) -> [u8; 16] {
        let mut x0 = u32::from_le_bytes(block[0..4].try_into().unwrap()) ^ self.subkeys[0];
        let mut x1 = u32::from_le_bytes(block[4..8].try_into().unwrap()) ^ self.subkeys[1];
        let mut x2 = u32::from_le_bytes(block[8..12].try_into().unwrap()) ^ self.subkeys[2];
        let mut x3 = u32::from_le_bytes(block[12..16].try_into().unwrap()) ^ self.subkeys[3];

        let mut round = 0usize;
        while round < 8 {
            // Two rounds are grouped per loop so the Feistel word swap stays
            // explicit without introducing a separate temporary block shuffle.
            let (f0, f1) = self.round_f(&h_round, x0, x1, 2 * round);
            x2 = (x2 ^ f0).rotate_right(1);
            x3 = x3.rotate_left(1) ^ f1;

            let (f0, f1) = self.round_f(&h_round, x2, x3, 2 * round + 1);
            x0 = (x0 ^ f0).rotate_right(1);
            x1 = x1.rotate_left(1) ^ f1;

            round += 1;
        }

        let c0 = x2 ^ self.subkeys[4];
        let c1 = x3 ^ self.subkeys[5];
        let c2 = x0 ^ self.subkeys[6];
        let c3 = x1 ^ self.subkeys[7];

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&c0.to_le_bytes());
        out[4..8].copy_from_slice(&c1.to_le_bytes());
        out[8..12].copy_from_slice(&c2.to_le_bytes());
        out[12..16].copy_from_slice(&c3.to_le_bytes());
        out
    }

    /// Decrypt one block with `h_round` as the keyed `h()`.
    fn decrypt_block(&self, h_round: impl Fn(u32) -> u32, block: &[u8; 16]) -> [u8; 16] {
        let mut x2 = u32::from_le_bytes(block[0..4].try_into().unwrap()) ^ self.subkeys[4];
        let mut x3 = u32::from_le_bytes(block[4..8].try_into().unwrap()) ^ self.subkeys[5];
        let mut x0 = u32::from_le_bytes(block[8..12].try_into().unwrap()) ^ self.subkeys[6];
        let mut x1 = u32::from_le_bytes(block[12..16].try_into().unwrap()) ^ self.subkeys[7];

        let mut round = 8usize;
        while round > 0 {
            round -= 1;

            // Decryption walks the same structure backward with the round
            // subkeys consumed in reverse order.
            let (f0, f1) = self.round_f(&h_round, x2, x3, 2 * round + 1);
            x1 = (x1 ^ f1).rotate_right(1);
            x0 = x0.rotate_left(1) ^ f0;

            let (f0, f1) = self.round_f(&h_round, x0, x1, 2 * round);
            x3 = (x3 ^ f1).rotate_right(1);
            x2 = x2.rotate_left(1) ^ f0;
        }

        let p0 = x0 ^ self.subkeys[0];
        let p1 = x1 ^ self.subkeys[1];
        let p2 = x2 ^ self.subkeys[2];
        let p3 = x3 ^ self.subkeys[3];

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&p0.to_le_bytes());
        out[4..8].copy_from_slice(&p1.to_le_bytes());
        out[8..12].copy_from_slice(&p2.to_le_bytes());
        out[12..16].copy_from_slice(&p3.to_le_bytes());
        out
    }
}

impl Drop for TwofishKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.subkeys);
        zeroize_slice(&mut self.s);
    }
}

macro_rules! define_twofish_type {
    ($name:ident, $name_ct:ident, $key_len:expr) => {
        /// Twofish (AES submission, 1998) fast software path for the key
        /// size named in the type: 128-bit block, 16 rounds. Key expansion
        /// precomputes four keyed 256-entry S-box/MDS tables so each
        /// round's `h()` becomes four secret-indexed lookups and three
        /// xors; all key-derived material is zeroized on drop.
        pub struct $name {
            key: TwofishKey,
            tables: KeyedTables,
        }

        impl $name {
            /// Expand the user key into the whitening and round subkeys and
            /// build the keyed tables, both written directly into the new
            /// instance.
            #[must_use]
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut cipher = Self {
                    key: TwofishKey::empty($key_len / 8),
                    tables: KeyedTables::empty(),
                };
                cipher.key.expand(key, false);
                cipher.tables.fill(&cipher.key);
                cipher
            }

            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let out = Self::new(key);
                zeroize_slice(key);
                out
            }

            /// Encrypt one 128-bit block through the keyed tables
            /// (secret-indexed lookups; not constant-time).
            #[must_use]
            pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                self.key.encrypt_block(|x| self.tables.h(x), block)
            }

            /// Decrypt one 128-bit block through the keyed tables
            /// (secret-indexed lookups; not constant-time).
            #[must_use]
            pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                self.key.decrypt_block(|x| self.tables.h(x), block)
            }
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = 16;

            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.encrypt_block(arr);
                block.copy_from_slice(&out);
            }

            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.decrypt_block(arr);
                block.copy_from_slice(&out);
            }
        }

        /// Constant-time Twofish for the same key size: it skips the keyed
        /// table precomputation and instead evaluates every `h()` — in the
        /// key schedule and per round — from the published 4-bit `q0`/`q1`
        /// building blocks with fixed-scan nibble selection, so no table
        /// read is indexed by secret data. It carries only the key schedule,
        /// which is zeroized on drop.
        pub struct $name_ct {
            key: TwofishKey,
        }

        impl $name_ct {
            /// Expand the user key into the whitening and round subkeys,
            /// written directly into the new instance.
            #[must_use]
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut cipher = Self {
                    key: TwofishKey::empty($key_len / 8),
                };
                cipher.key.expand(key, true);
                cipher
            }

            /// Expand the key and then wipe the caller-owned key buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let out = Self::new(key);
                zeroize_slice(key);
                out
            }

            /// Encrypt one 128-bit block with the software constant-time path.
            #[must_use]
            pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                let key = &self.key;
                key.encrypt_block(|x| h(x, &key.s, key.words, true), block)
            }

            /// Decrypt one 128-bit block with the software constant-time path.
            #[must_use]
            pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                let key = &self.key;
                key.decrypt_block(|x| h(x, &key.s, key.words, true), block)
            }
        }

        impl BlockCipher for $name_ct {
            const BLOCK_LEN: usize = 16;

            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.encrypt_block(arr);
                block.copy_from_slice(&out);
            }

            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                let out = self.decrypt_block(arr);
                block.copy_from_slice(&out);
            }
        }
    };
}

define_twofish_type!(Twofish128, Twofish128Ct, 16);
define_twofish_type!(Twofish192, Twofish192Ct, 24);
define_twofish_type!(Twofish256, Twofish256Ct, 32);

/// Default Twofish instantiation: alias for [`Twofish128`] (128-bit key).
pub type Twofish = Twofish128;
/// Constant-time Twofish-128 alias.
pub type TwofishCt = Twofish128Ct;

#[cfg(test)]
mod tests {
    // Known answers come from the Twofish AES-submission package
    // (Counterpane Systems, 1998): `ECB_TBL.TXT` ("Full Encryptions" tables,
    // entries I=1..5 for each key size, whose keys and plaintexts chain from
    // the previous ciphertexts) and `ECB_E_M.TXT` (ECB encryption Monte Carlo
    // test, KEYSIZE=128, I=0..2). The random sweep checks the fast path
    // against the constant-time path.
    use super::*;
    use crate::test_utils::decode_hex_array;

    /// Run one `ECB_TBL.TXT` entry through both paths of the given types.
    macro_rules! check_tbl_entry {
        ($fast:ident, $slow:ident, $klen:literal, $key:expr, $pt:expr, $ct:expr) => {{
            let key = decode_hex_array::<$klen>($key);
            let pt = decode_hex_array::<16>($pt);
            let ct = decode_hex_array::<16>($ct);
            let fast = $fast::new(&key);
            let slow = $slow::new(&key);
            assert_eq!(fast.encrypt_block(&pt), ct, "fast encrypt {}", $key);
            assert_eq!(slow.encrypt_block(&pt), ct, "ct encrypt {}", $key);
            assert_eq!(fast.decrypt_block(&ct), pt, "fast decrypt {}", $key);
            assert_eq!(slow.decrypt_block(&ct), pt, "ct decrypt {}", $key);
        }};
    }

    /// `ECB_TBL.TXT`, KEYSIZE=128, I=1..5.
    #[test]
    fn ecb_tbl_128() {
        let entries = [
            (
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9F589F5CF6122C32B6BFEC2F2AE8C35A",
            ),
            (
                "00000000000000000000000000000000",
                "9F589F5CF6122C32B6BFEC2F2AE8C35A",
                "D491DB16E7B1C39E86CB086B789F5419",
            ),
            (
                "9F589F5CF6122C32B6BFEC2F2AE8C35A",
                "D491DB16E7B1C39E86CB086B789F5419",
                "019F9809DE1711858FAAC3A3BA20FBC3",
            ),
            (
                "D491DB16E7B1C39E86CB086B789F5419",
                "019F9809DE1711858FAAC3A3BA20FBC3",
                "6363977DE839486297E661C6C9D668EB",
            ),
            (
                "019F9809DE1711858FAAC3A3BA20FBC3",
                "6363977DE839486297E661C6C9D668EB",
                "816D5BD0FAE35342BF2A7412C246F752",
            ),
        ];
        for (key, pt, ct) in entries {
            check_tbl_entry!(Twofish128, Twofish128Ct, 16, key, pt, ct);
        }
    }

    /// `ECB_TBL.TXT`, KEYSIZE=192, I=1..5.
    #[test]
    fn ecb_tbl_192() {
        let entries = [
            (
                "000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "EFA71F788965BD4453F860178FC19101",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "EFA71F788965BD4453F860178FC19101",
                "88B2B2706B105E36B446BB6D731A1E88",
            ),
            (
                "EFA71F788965BD4453F860178FC191010000000000000000",
                "88B2B2706B105E36B446BB6D731A1E88",
                "39DA69D6BA4997D585B6DC073CA341B2",
            ),
            (
                "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
                "39DA69D6BA4997D585B6DC073CA341B2",
                "182B02D81497EA45F9DAACDC29193A65",
            ),
            (
                "39DA69D6BA4997D585B6DC073CA341B288B2B2706B105E36",
                "182B02D81497EA45F9DAACDC29193A65",
                "7AFF7A70CA2FF28AC31DD8AE5DAAAB63",
            ),
        ];
        for (key, pt, ct) in entries {
            check_tbl_entry!(Twofish192, Twofish192Ct, 24, key, pt, ct);
        }
    }

    /// `ECB_TBL.TXT`, KEYSIZE=256, I=1..5.
    #[test]
    fn ecb_tbl_256() {
        let entries = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "57FF739D4DC92C1BD7FC01700CC8216F",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "57FF739D4DC92C1BD7FC01700CC8216F",
                "D43BB7556EA32E46F2A282B7D45B4E0D",
            ),
            (
                "57FF739D4DC92C1BD7FC01700CC8216F00000000000000000000000000000000",
                "D43BB7556EA32E46F2A282B7D45B4E0D",
                "90AFE91BB288544F2C32DC239B2635E6",
            ),
            (
                "D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F",
                "90AFE91BB288544F2C32DC239B2635E6",
                "6CB4561C40BF0A9705931CB6D408E7FA",
            ),
            (
                "90AFE91BB288544F2C32DC239B2635E6D43BB7556EA32E46F2A282B7D45B4E0D",
                "6CB4561C40BF0A9705931CB6D408E7FA",
                "3059D6D61753B958D92F4781C8640E58",
            ),
        ];
        for (key, pt, ct) in entries {
            check_tbl_entry!(Twofish256, Twofish256Ct, 32, key, pt, ct);
        }
    }

    /// `ECB_E_M.TXT`, KEYSIZE=128, I=0..2: each entry encrypts its plaintext
    /// 10,000 times in ECB, feeding every ciphertext back as the next
    /// plaintext; the next entry's key is the previous key XOR the final
    /// ciphertext and its plaintext is that ciphertext.
    #[test]
    fn ecb_encrypt_monte_carlo_128() {
        let entries = [
            (
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "282BE7E4FA1FBDC29661286F1F310B7E",
            ),
            (
                "282BE7E4FA1FBDC29661286F1F310B7E",
                "282BE7E4FA1FBDC29661286F1F310B7E",
                "C8E1D477621ACC37742BD16032075654",
            ),
            (
                "E0CA3393980571F5E24AF90F2D365D2A",
                "C8E1D477621ACC37742BD16032075654",
                "D5187E7D6B8BE9517DAC4A8AF4A552EA",
            ),
        ];
        let mut key = [0u8; 16];
        let mut pt = [0u8; 16];
        for (i, (file_key, file_pt, file_ct)) in entries.into_iter().enumerate() {
            assert_eq!(key, decode_hex_array::<16>(file_key), "I={i} key");
            assert_eq!(pt, decode_hex_array::<16>(file_pt), "I={i} plaintext");
            let cipher = Twofish128::new(&key);
            let mut block = pt;
            for _ in 0..10_000 {
                block = cipher.encrypt_block(&block);
            }
            assert_eq!(block, decode_hex_array::<16>(file_ct), "I={i} ciphertext");
            for (k, c) in key.iter_mut().zip(block) {
                *k ^= c;
            }
            pt = block;
        }
    }

    /// The `BlockCipher` entry points reject a wrong-length block.
    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_rejects_wrong_length() {
        let cipher = Twofish128::new(&[0u8; 16]);
        let mut long = [0u8; 17];
        cipher.encrypt(&mut long);
    }

    /// The constant-time types carry only the key schedule, not the fast
    /// path's 4 KB of keyed tables; the fast types hold those tables behind a
    /// pointer; and every Twofish type wipes itself on drop.
    #[test]
    fn ct_types_carry_no_keyed_tables_and_all_types_wipe() {
        assert!(core::mem::size_of::<Twofish256Ct>() < 256);
        assert!(core::mem::size_of::<Twofish256>() < 256 + 16);
        for needs_drop in [
            core::mem::needs_drop::<Twofish128>(),
            core::mem::needs_drop::<Twofish128Ct>(),
            core::mem::needs_drop::<Twofish192>(),
            core::mem::needs_drop::<Twofish192Ct>(),
            core::mem::needs_drop::<Twofish256>(),
            core::mem::needs_drop::<Twofish256Ct>(),
        ] {
            assert!(needs_drop);
        }
    }

    // Deterministic xorshift64* PRNG so the differential test needs no
    // external rng and reproduces bit-for-bit across runs.
    struct XorShift64(u64);

    impl XorShift64 {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    #[test]
    fn fast_roundtrip_and_ct_equivalence_random() {
        // Several thousand pseudorandom blocks under fresh pseudorandom keys:
        // the FAST path must round-trip every block, and its ciphertext must
        // match the constant-time path bit-for-bit (proving the precomputed
        // keyed tables equal the direct h() evaluation).
        let mut rng = XorShift64(0x1234_5678_9ABC_DEF1);

        macro_rules! sweep {
            ($fast:ident, $slow:ident, $klen:expr, $iters:expr) => {{
                let mut n = 0usize;
                while n < $iters {
                    let mut key = [0u8; $klen];
                    let mut pt = [0u8; 16];
                    rng.fill(&mut key);
                    rng.fill(&mut pt);
                    let fast = $fast::new(&key);
                    let slow = $slow::new(&key);
                    let ct = fast.encrypt_block(&pt);
                    assert_eq!(
                        ct,
                        slow.encrypt_block(&pt),
                        "fast != ct enc ({} bit)",
                        $klen * 8
                    );
                    assert_eq!(
                        fast.decrypt_block(&ct),
                        pt,
                        "fast roundtrip ({} bit)",
                        $klen * 8
                    );
                    assert_eq!(
                        slow.decrypt_block(&ct),
                        pt,
                        "ct roundtrip ({} bit)",
                        $klen * 8
                    );
                    n += 1;
                }
            }};
        }

        sweep!(Twofish128, Twofish128Ct, 16, 2000);
        sweep!(Twofish192, Twofish192Ct, 24, 2000);
        sweep!(Twofish256, Twofish256Ct, 32, 2000);
    }

    #[test]
    fn q_tables_match_ct_path() {
        let mut i = 0usize;
        while i < 256 {
            let idx = u8::try_from(i).expect("Q table index fits in u8");
            assert_eq!(Q0[i], q_perm_ct(idx, 0));
            assert_eq!(Q1[i], q_perm_ct(idx, 1));
            i += 1;
        }
    }
}
