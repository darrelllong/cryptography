//! AES (Rijndael, 128-bit block) — AES-128, AES-192, AES-256.
//!
//! Implemented from FIPS PUB 197 (2001), the complete Rijndael specification
//! for a 128-bit block width with 10, 12, or 14 rounds depending on key length.
//!
//! # Default path — fast software T-tables
//!
//! The active encrypt/decrypt path uses the classic T-table software design:
//! each middle round folds `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey`
//! into four 256-entry `u32` lookup tables computed at compile time from the
//! FIPS 197 S-boxes.
//!
//! This software path is optimized for throughput, not constant-time
//! behavior: the table index is the secret state, so its running time and
//! cache footprint depend on key and plaintext. `Aes128`, `Aes192` and
//! `Aes256` are therefore variable-time. Use `Aes128Ct`, `Aes192Ct`, or
//! `Aes256Ct`, whose S-box is the Boyar-Peralta boolean circuit, when
//! constant-time behavior matters. This crate carries no hardware AES path
//! (no intrinsics in-tree); the AES-NI and `ARMv8` comparators under `fast/`
//! measure what one would buy.
//!
//! # Tests
//! Known answers come from three sources, each named where it is used:
//! FIPS 197 Appendix C.1-C.3 (the worked examples) as literals; the NIST CAVP
//! `KAT_AES.zip` archive (CAVS 11.1, 2011-04-22, from csrc.nist.gov) for the
//! ECBGFSbox, ECBKeySbox, ECBVarKey and ECBVarTxt samples; and the installed
//! `openssl` tool as a black-box oracle. Every table-driven vector is run
//! through the T-table type and the `Ct` type, in both directions.

// ─────────────────────────────────────────────────────────────────────────────
// FIPS 197 S-boxes  (§ 4.2.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Forward S-box — FIPS 197, Figure 7.
/// SBOX[x] = `affine_transform(gf_inv(x))`  in GF(2⁸) mod 0x11b.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Inverse S-box — FIPS 197, Figure 14.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Key schedule round constants — FIPS 197, § 5.2.
/// RCON[i] = [x^i in GF(2⁸), 0, 0, 0] packed big-endian into a u32.
const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

// ─────────────────────────────────────────────────────────────────────────────
// GF(2⁸) arithmetic  (mod x⁸ + x⁴ + x³ + x + 1 = 0x11b)
//
// All `const fn`s so the compiler evaluates them at compile time when building
// the T-tables.  None of these appear in any hot path.
// ─────────────────────────────────────────────────────────────────────────────

/// Multiply by x (the polynomial generator) — equivalent to a left shift
/// followed by a conditional XOR to reduce modulo the irreducible polynomial.
const fn xtime(a: u8) -> u8 {
    (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7))
}

const fn mul3(a: u8) -> u8 {
    xtime(a) ^ a
}
const fn mul4(a: u8) -> u8 {
    xtime(xtime(a))
}
const fn mul8(a: u8) -> u8 {
    xtime(xtime(xtime(a)))
}
const fn mul9(a: u8) -> u8 {
    mul8(a) ^ a
}
const fn mul11(a: u8) -> u8 {
    mul8(a) ^ xtime(a) ^ a
}
const fn mul13(a: u8) -> u8 {
    mul8(a) ^ mul4(a) ^ a
}
const fn mul14(a: u8) -> u8 {
    mul8(a) ^ mul4(a) ^ xtime(a)
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption T-tables  (computed at compile time from SBOX)
//
// Each table folds SubBytes + one column of MixColumns into a single u32
// lookup.  TE1–TE3 are right-rotations of TE0, so together they cover all
// four output-byte positions.
//
// Derivation for TE0 (FIPS 197, § 5.1.3 MixColumns matrix row 0):
//
//   TE0[a] = [ 2·S[a],   S[a],   S[a], 3·S[a] ]   (big-endian bytes)
//           = (xtime(s) << 24) | (s << 16) | (s << 8) | mul3(s)
//   TE1[a] = TE0[a].rotate_right(8)    ← row 1 contribution
//   TE2[a] = TE0[a].rotate_right(16)   ← row 2
//   TE3[a] = TE0[a].rotate_right(24)   ← row 3
//
// One middle round (r = 1..NR-1), column 0 of output:
//   t0 = TE0[s0>>24] ^ TE1[(s1>>16)&0xff] ^ TE2[(s2>>8)&0xff] ^ TE3[s3&0xff] ^ rk[4r]
//   (ShiftRows is implicit: column j of output samples rows from columns
//    j, j+1, j+2, j+3 mod 4 of the current state.)
// ─────────────────────────────────────────────────────────────────────────────

const TE0: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let s = SBOX[i];
        t[i] =
            ((xtime(s) as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (mul3(s) as u32);
        i += 1;
    }
    t
};

const TE1: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = TE0[i].rotate_right(8);
        i += 1;
    }
    t
};
const TE2: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = TE0[i].rotate_right(16);
        i += 1;
    }
    t
};
const TE3: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = TE0[i].rotate_right(24);
        i += 1;
    }
    t
};

// ─────────────────────────────────────────────────────────────────────────────
// Decryption T-tables  (computed at compile time from INV_SBOX)
//
// Derivation for TD0 (InvMixColumns matrix, FIPS 197, § 5.3.3):
//
//   TD0[a] = [ 14·Si[a],  9·Si[a], 13·Si[a], 11·Si[a] ]  (big-endian bytes)
//   TD1..TD3 are right-rotations of TD0.
//
// One inverse middle round, column 0:
//   t0 = TD0[s0>>24] ^ TD1[(s3>>16)&0xff] ^ TD2[(s2>>8)&0xff] ^ TD3[s1&0xff] ^ rk[4r]
//   (InvShiftRows is implicit in the column sampling pattern; note the indices
//    s3,s2,s1 rather than the s1,s2,s3 of the forward direction.)
//
// Round keys are pre-transformed by make_dec_rk() for the equivalent inverse
// cipher, so the decryption loop can mirror the forward T-table structure.
// ─────────────────────────────────────────────────────────────────────────────

const TD0: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let s = INV_SBOX[i];
        t[i] = ((mul14(s) as u32) << 24)
            | ((mul9(s) as u32) << 16)
            | ((mul13(s) as u32) << 8)
            | (mul11(s) as u32);
        i += 1;
    }
    t
};

const TD1: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = TD0[i].rotate_right(8);
        i += 1;
    }
    t
};
const TD2: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = TD0[i].rotate_right(16);
        i += 1;
    }
    t
};
const TD3: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = TD0[i].rotate_right(24);
        i += 1;
    }
    t
};

/// Block size in bytes: AES is a 128-bit block cipher (FIPS 197 §3.4).
const BLOCK_BYTES: usize = 16;

/// `Nb`: the state is four 32-bit columns (FIPS 197 §3.4).
const NB: usize = 4;

/// Bytes in a state column, and so in a key-schedule word.
const WORD_BYTES: usize = BLOCK_BYTES / NB;

/// FIPS 197 Table 5: key length and round count per variant. The expanded key
/// holds `Nb * (Nr + 1)` words (§5.2).
const AES128_KEY_BYTES: usize = 16;
const AES192_KEY_BYTES: usize = 24;
const AES256_KEY_BYTES: usize = 32;
const AES128_ROUNDS: usize = 10;
const AES192_ROUNDS: usize = 12;
const AES256_ROUNDS: usize = 14;
const fn expanded_words(rounds: usize) -> usize {
    NB * (rounds + 1)
}

/// Signals in the Boyar-Peralta S-box circuit (ePrint 2011/332): the top
/// linear transform's `T1..T27`, the shared nonlinear part's `M1..M63`, and
/// the eight wires of a byte.
const BYTE_BITS: usize = 8;
const TOP_LINEAR_SIGNALS: usize = 27;
const NONLINEAR_SIGNALS: usize = 63;

// ─────────────────────────────────────────────────────────────────────────────
// Key expansion — FIPS 197, § 5.2
//
// SubWord applies SBOX to each byte of a 32-bit word.
// RotWord is a left rotation by one byte (≡ rotate_left(8)).
// RCON[i] = [x^i, 0, 0, 0] in GF(2⁸), pre-tabulated above.
//
// The number of round-key words is NR + 1 columns × 4 words/column:
//   AES-128: NK=4, NR=10 → 44 words
//   AES-192: NK=6, NR=12 → 52 words
//   AES-256: NK=8, NR=14 → 60 words
// ─────────────────────────────────────────────────────────────────────────────

fn sub_word(w: u32) -> u32 {
    u32::from(SBOX[(w >> 24) as usize]) << 24
        | u32::from(SBOX[((w >> 16) & 0xff) as usize]) << 16
        | u32::from(SBOX[((w >> 8) & 0xff) as usize]) << 8
        | u32::from(SBOX[(w & 0xff) as usize])
}

/// FIPS 197 § 5.2 `KeyExpansion`, written into `w` in place.
///
/// `key` is the cipher key (16, 24 or 32 bytes, so `Nk` = 4, 6 or 8) and `w`
/// the caller's round-key array of `4 · (Nr + 1)` words, which is the field
/// of the cipher struct itself: the schedule is never assembled in a
/// separate local that would then be moved, leaving a dead copy behind. The
/// only word-sized temporary is wiped before return.
///
/// `sub_word` is the `SubWord` evaluator: the S-box table for the T-table
/// types, the Boyar-Peralta circuit for the `Ct` types, so the `Ct` key
/// setup performs no secret-indexed reads either. The extra `SubWord` at
/// `i mod Nk = 4` applies when `Nk > 6`, i.e. to AES-256 only.
fn expand_key(key: &[u8], w: &mut [u32], sub_word: fn(u32) -> u32) {
    let nk = key.len() / WORD_BYTES;
    debug_assert!(matches!(nk, 4 | 6 | 8) && key.len() == WORD_BYTES * nk);
    debug_assert_eq!(w.len(), NB * (nk + 7));
    for (word, bytes) in w.iter_mut().zip(key.chunks_exact(WORD_BYTES)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("four key bytes"));
    }
    let mut t = 0u32;
    for i in nk..w.len() {
        t = w[i - 1];
        if i % nk == 0 {
            t = sub_word(t.rotate_left(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }
        w[i] = w[i - nk] ^ t;
    }
    crate::ct::zeroize_slice(core::slice::from_mut(&mut t));
}

// ─────────────────────────────────────────────────────────────────────────────
// Decryption key schedule — equivalent inverse cipher (FIPS 197 § 5.3.5)
//
// The T-table decryption path folds InvSubBytes + InvMixColumns into the TD
// tables, so the middle-round keys must be pre-transformed with
// InvMixColumns.
// ─────────────────────────────────────────────────────────────────────────────

fn inv_mix_col(w: u32) -> u32 {
    TD0[SBOX[(w >> 24) as usize] as usize]
        ^ TD1[SBOX[((w >> 16) & 0xff) as usize] as usize]
        ^ TD2[SBOX[((w >> 8) & 0xff) as usize] as usize]
        ^ TD3[SBOX[(w & 0xff) as usize] as usize]
}

/// Build the decryption round-key schedule from the forward expanded key.
/// `enc_rk` and `dec_rk` must have the same length (NR+1)*4.
fn make_dec_rk(enc_rk: &[u32], dec_rk: &mut [u32], nr: usize) {
    dec_rk[..NB].copy_from_slice(&enc_rk[nr * NB..nr * NB + NB]);
    for r in 1..nr {
        for j in 0..NB {
            dec_rk[r * NB + j] = inv_mix_col(enc_rk[(nr - r) * NB + j]);
        }
    }
    dec_rk[nr * NB..nr * NB + NB].copy_from_slice(&enc_rk[..NB]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cipher core — pure, safe Rust T-table implementation
//
// State is held as four u32 words, one per column (big-endian byte order):
//   s0 = state[0][0]<<24 | state[1][0]<<16 | state[2][0]<<8 | state[3][0]
//
// `rk`  — flat slice of forward round-key words, length (NR+1)×4.
// `dk`  — flat slice of decryption round-key words (from make_dec_rk).
// `nr`  — number of rounds (10 / 12 / 14).
// ─────────────────────────────────────────────────────────────────────────────

fn aes_encrypt(block: &[u8; BLOCK_BYTES], rk: &[u32], nr: usize) -> [u8; BLOCK_BYTES] {
    let mut s0 = u32::from_be_bytes(block[0..4].try_into().unwrap()) ^ rk[0];
    let mut s1 = u32::from_be_bytes(block[4..8].try_into().unwrap()) ^ rk[1];
    let mut s2 = u32::from_be_bytes(block[8..12].try_into().unwrap()) ^ rk[2];
    let mut s3 = u32::from_be_bytes(block[12..16].try_into().unwrap()) ^ rk[3];

    for r in 1..nr {
        let k = NB * r;
        let t0 = TE0[(s0 >> 24) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize]
            ^ rk[k];
        let t1 = TE0[(s1 >> 24) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize]
            ^ rk[k + 1];
        let t2 = TE0[(s2 >> 24) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize]
            ^ rk[k + 2];
        let t3 = TE0[(s3 >> 24) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize]
            ^ rk[k + 3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    let k = NB * nr;
    let c0 = u32::from(SBOX[(s0 >> 24) as usize]) << 24
        | u32::from(SBOX[((s1 >> 16) & 0xff) as usize]) << 16
        | u32::from(SBOX[((s2 >> 8) & 0xff) as usize]) << 8
        | u32::from(SBOX[(s3 & 0xff) as usize]);
    let c1 = u32::from(SBOX[(s1 >> 24) as usize]) << 24
        | u32::from(SBOX[((s2 >> 16) & 0xff) as usize]) << 16
        | u32::from(SBOX[((s3 >> 8) & 0xff) as usize]) << 8
        | u32::from(SBOX[(s0 & 0xff) as usize]);
    let c2 = u32::from(SBOX[(s2 >> 24) as usize]) << 24
        | u32::from(SBOX[((s3 >> 16) & 0xff) as usize]) << 16
        | u32::from(SBOX[((s0 >> 8) & 0xff) as usize]) << 8
        | u32::from(SBOX[(s1 & 0xff) as usize]);
    let c3 = u32::from(SBOX[(s3 >> 24) as usize]) << 24
        | u32::from(SBOX[((s0 >> 16) & 0xff) as usize]) << 16
        | u32::from(SBOX[((s1 >> 8) & 0xff) as usize]) << 8
        | u32::from(SBOX[(s2 & 0xff) as usize]);

    let mut out = [0u8; BLOCK_BYTES];
    out[0..4].copy_from_slice(&(c0 ^ rk[k]).to_be_bytes());
    out[4..8].copy_from_slice(&(c1 ^ rk[k + 1]).to_be_bytes());
    out[8..12].copy_from_slice(&(c2 ^ rk[k + 2]).to_be_bytes());
    out[12..16].copy_from_slice(&(c3 ^ rk[k + 3]).to_be_bytes());
    out
}

fn aes_decrypt(block: &[u8; BLOCK_BYTES], dk: &[u32], nr: usize) -> [u8; BLOCK_BYTES] {
    let mut s0 = u32::from_be_bytes(block[0..4].try_into().unwrap()) ^ dk[0];
    let mut s1 = u32::from_be_bytes(block[4..8].try_into().unwrap()) ^ dk[1];
    let mut s2 = u32::from_be_bytes(block[8..12].try_into().unwrap()) ^ dk[2];
    let mut s3 = u32::from_be_bytes(block[12..16].try_into().unwrap()) ^ dk[3];

    for r in 1..nr {
        let k = NB * r;
        let t0 = TD0[(s0 >> 24) as usize]
            ^ TD1[((s3 >> 16) & 0xff) as usize]
            ^ TD2[((s2 >> 8) & 0xff) as usize]
            ^ TD3[(s1 & 0xff) as usize]
            ^ dk[k];
        let t1 = TD0[(s1 >> 24) as usize]
            ^ TD1[((s0 >> 16) & 0xff) as usize]
            ^ TD2[((s3 >> 8) & 0xff) as usize]
            ^ TD3[(s2 & 0xff) as usize]
            ^ dk[k + 1];
        let t2 = TD0[(s2 >> 24) as usize]
            ^ TD1[((s1 >> 16) & 0xff) as usize]
            ^ TD2[((s0 >> 8) & 0xff) as usize]
            ^ TD3[(s3 & 0xff) as usize]
            ^ dk[k + 2];
        let t3 = TD0[(s3 >> 24) as usize]
            ^ TD1[((s2 >> 16) & 0xff) as usize]
            ^ TD2[((s1 >> 8) & 0xff) as usize]
            ^ TD3[(s0 & 0xff) as usize]
            ^ dk[k + 3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    let k = NB * nr;
    let p0 = u32::from(INV_SBOX[(s0 >> 24) as usize]) << 24
        | u32::from(INV_SBOX[((s3 >> 16) & 0xff) as usize]) << 16
        | u32::from(INV_SBOX[((s2 >> 8) & 0xff) as usize]) << 8
        | u32::from(INV_SBOX[(s1 & 0xff) as usize]);
    let p1 = u32::from(INV_SBOX[(s1 >> 24) as usize]) << 24
        | u32::from(INV_SBOX[((s0 >> 16) & 0xff) as usize]) << 16
        | u32::from(INV_SBOX[((s3 >> 8) & 0xff) as usize]) << 8
        | u32::from(INV_SBOX[(s2 & 0xff) as usize]);
    let p2 = u32::from(INV_SBOX[(s2 >> 24) as usize]) << 24
        | u32::from(INV_SBOX[((s1 >> 16) & 0xff) as usize]) << 16
        | u32::from(INV_SBOX[((s0 >> 8) & 0xff) as usize]) << 8
        | u32::from(INV_SBOX[(s3 & 0xff) as usize]);
    let p3 = u32::from(INV_SBOX[(s3 >> 24) as usize]) << 24
        | u32::from(INV_SBOX[((s2 >> 16) & 0xff) as usize]) << 16
        | u32::from(INV_SBOX[((s1 >> 8) & 0xff) as usize]) << 8
        | u32::from(INV_SBOX[(s0 & 0xff) as usize]);

    let mut out = [0u8; BLOCK_BYTES];
    out[0..4].copy_from_slice(&(p0 ^ dk[k]).to_be_bytes());
    out[4..8].copy_from_slice(&(p1 ^ dk[k + 1]).to_be_bytes());
    out[8..12].copy_from_slice(&(p2 ^ dk[k + 2]).to_be_bytes());
    out[12..16].copy_from_slice(&(p3 ^ dk[k + 3]).to_be_bytes());
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Alternate software-only constant-time path — Boyar-Peralta S-box circuits
//
// This path keeps the AES round structure bytewise, but replaces S-box table
// lookups with the depth-16 straight-line circuits of J. Boyar and R.
// Peralta, "A depth-16 circuit for the AES S-box", IACR Cryptology ePrint
// Archive, Report 2011/332, the version received 2011-06-22 (the only one
// posted). Section 6 of that paper lists the circuits as straight-line
// programs over XOR (`+`), XNOR (`#`) and AND (`x`):
//
//   Figure 5  top linear transform, forward     (U0..U7 → T1..T27)
//   Figure 6  top linear transform, reverse     (U0..U7 → T*, R*, Y5)
//   Figure 7  shared nonlinear part             (M1..M63; D = U7 forward,
//                                                D = Y5 reverse)
//   Figure 8  bottom linear transform, forward  (L0..L29 → S0..S7)
//   Figure 9  bottom linear transform, reverse  (P0..P29 → W0..W7)
//
// The gates below are transcribed from those listings gate for gate, with
// the paper's 1-based T/M names shifted to 0-based array slots: `t[k]` is
// the paper's `T(k+1)`, `m[k]` its `M(k+1)`; the `l*` and `p*` names keep the
// paper's numbers. Figure 9 numbers its gates P0..P29 with no P21 (P20 is
// followed by P22), so `p21` is absent here too: it is a gap in the paper's
// numbering, not a missing gate. Figure 6 lists the reverse top linear layer
// out of order under two families of names (T and R) plus `Y5`; that layer
// is stored in evaluation order instead, and `inv_sbox_bool_linear` gives the
// slot-to-name table so each gate can be checked against the figure. The
// paper reports that the circuits were verified exhaustively against FIPS
// 197; `bool_sbox_matches_tables` repeats that check against `SBOX` and
// `INV_SBOX` here.
//
// Each byte is treated as eight 0/1 "wires" (`u0..u7`, most significant
// first), the intermediate nodes are local temporaries, and the eight output
// wires are packed back into a byte. Every gate is an XOR, XNOR or AND of
// single bits, so the evaluation has no secret-dependent memory access or
// branch.
//
// What holds that in place is the emitted code: `scripts/ct_codegen.sh`
// classifies every conditional branch in the release assembly of
// `Aes128Ct::encrypt_block`. Under rustc 1.93.1 on `aarch64-apple-darwin` and
// rustc 1.95.0 on `x86_64-unknown-linux-gnu` it holds three: the round loop,
// and two index checks on the round-key slice. Neither the key nor the block
// reaches a branch or a table index. All three widths call `aes_encrypt_ct`
// with their round count, so that reading is the reading for `Aes192Ct` and
// `Aes256Ct` as well.
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn xnor(a: u8, b: u8) -> u8 {
    (a ^ b) ^ 1
}

#[inline]
fn bit(input: u8, idx: u8) -> u8 {
    (input >> (7 - idx)) & 1
}

// The Boyar-Peralta circuit treats one AES byte as eight single-bit wires in
// MSB-first order. `bit()` extracts those wires, and `pack_bits()` reassembles
// the resulting output wires into the normal AES byte layout.
#[inline]
fn pack_bits(bits: [u8; 8]) -> u8 {
    (bits[0] << 7)
        | (bits[1] << 6)
        | (bits[2] << 5)
        | (bits[3] << 4)
        | (bits[4] << 3)
        | (bits[5] << 2)
        | (bits[6] << 1)
        | bits[7]
}

/// Forward AES S-box via the Boyar-Peralta straight-line circuit (ePrint
/// 2011/332, Figures 5, 7 and 8).
///
/// The operation is exactly the same S-box as `SBOX[input]`; it is just
/// represented as boolean logic instead of a lookup table. The `^ 1` terms in
/// the final output stage are the paper's XNOR outputs (S1, S2, S6, S7) and
/// encode the affine constant of the AES S-box.
#[inline]
fn sbox_bool(input: u8) -> u8 {
    let (bits, linear_terms) = sbox_bool_linear(input);
    let non_linear_terms = sbox_bool_nonlinear(bits, linear_terms);
    sbox_bool_output(non_linear_terms)
}

/// Figure 5: `t[k]` is the paper's `T(k+1)`.
fn sbox_bool_linear(input: u8) -> ([u8; BYTE_BITS], [u8; TOP_LINEAR_SIGNALS]) {
    let bits = [
        bit(input, 0),
        bit(input, 1),
        bit(input, 2),
        bit(input, 3),
        bit(input, 4),
        bit(input, 5),
        bit(input, 6),
        bit(input, 7),
    ];
    let [u0, u1, u2, u3, u4, u5, u6, u7] = bits;

    let mut t = [0u8; TOP_LINEAR_SIGNALS];
    t[0] = u0 ^ u3;
    t[1] = u0 ^ u5;
    t[2] = u0 ^ u6;
    t[3] = u3 ^ u5;
    t[4] = u4 ^ u6;
    t[5] = t[0] ^ t[4];
    t[6] = u1 ^ u2;
    t[7] = u7 ^ t[5];
    t[8] = u7 ^ t[6];
    t[9] = t[5] ^ t[6];
    t[10] = u1 ^ u5;
    t[11] = u2 ^ u5;
    t[12] = t[2] ^ t[3];
    t[13] = t[5] ^ t[10];
    t[14] = t[4] ^ t[10];
    t[15] = t[4] ^ t[11];
    t[16] = t[8] ^ t[15];
    t[17] = u3 ^ u7;
    t[18] = t[6] ^ t[17];
    t[19] = t[0] ^ t[18];
    t[20] = u6 ^ u7;
    t[21] = t[6] ^ t[20];
    t[22] = t[1] ^ t[21];
    t[23] = t[1] ^ t[9];
    t[24] = t[19] ^ t[16];
    t[25] = t[2] ^ t[15];
    t[26] = t[0] ^ t[11];

    (bits, t)
}

/// Figure 7 with `D = U7`: `m[k]` is the paper's `M(k+1)`.
fn sbox_bool_nonlinear(
    bits: [u8; BYTE_BITS],
    t: [u8; TOP_LINEAR_SIGNALS],
) -> [u8; NONLINEAR_SIGNALS] {
    let u7 = bits[7];
    let mut m = [0u8; NONLINEAR_SIGNALS];
    m[0] = t[12] & t[5];
    m[1] = t[22] & t[7];
    m[2] = t[13] ^ m[0];
    m[3] = t[18] & u7;
    m[4] = m[3] ^ m[0];
    m[5] = t[2] & t[15];
    m[6] = t[21] & t[8];
    m[7] = t[25] ^ m[5];
    m[8] = t[19] & t[16];
    m[9] = m[8] ^ m[5];
    m[10] = t[0] & t[14];
    m[11] = t[3] & t[26];
    m[12] = m[11] ^ m[10];
    m[13] = t[1] & t[9];
    m[14] = m[13] ^ m[10];
    m[15] = m[2] ^ m[1];
    m[16] = m[4] ^ t[23];
    m[17] = m[7] ^ m[6];
    m[18] = m[9] ^ m[14];
    m[19] = m[15] ^ m[12];
    m[20] = m[16] ^ m[14];
    m[21] = m[17] ^ m[12];
    m[22] = m[18] ^ t[24];
    m[23] = m[21] ^ m[22];
    m[24] = m[21] & m[19];
    m[25] = m[20] ^ m[24];
    m[26] = m[19] ^ m[20];
    m[27] = m[22] ^ m[24];
    m[28] = m[27] & m[26];
    m[29] = m[25] & m[23];
    m[30] = m[19] & m[22];
    m[31] = m[26] & m[30];
    m[32] = m[26] ^ m[24];
    m[33] = m[20] & m[21];
    m[34] = m[23] & m[33];
    m[35] = m[23] ^ m[24];
    m[36] = m[20] ^ m[28];
    m[37] = m[31] ^ m[32];
    m[38] = m[22] ^ m[29];
    m[39] = m[34] ^ m[35];
    m[40] = m[37] ^ m[39];
    m[41] = m[36] ^ m[38];
    m[42] = m[36] ^ m[37];
    m[43] = m[38] ^ m[39];
    m[44] = m[41] ^ m[40];
    m[45] = m[43] & t[5];
    m[46] = m[39] & t[7];
    m[47] = m[38] & u7;
    m[48] = m[42] & t[15];
    m[49] = m[37] & t[8];
    m[50] = m[36] & t[16];
    m[51] = m[41] & t[14];
    m[52] = m[44] & t[26];
    m[53] = m[40] & t[9];
    m[54] = m[43] & t[12];
    m[55] = m[39] & t[22];
    m[56] = m[38] & t[18];
    m[57] = m[42] & t[2];
    m[58] = m[37] & t[21];
    m[59] = m[36] & t[19];
    m[60] = m[41] & t[0];
    m[61] = m[44] & t[3];
    m[62] = m[40] & t[1];
    m
}

/// Figure 8: `l*` keep the paper's numbers; the packed bits are S0..S7.
fn sbox_bool_output(m: [u8; NONLINEAR_SIGNALS]) -> u8 {
    let l0 = m[60] ^ m[61];
    let l1 = m[49] ^ m[55];
    let l2 = m[45] ^ m[47];
    let l3 = m[46] ^ m[54];
    let l4 = m[53] ^ m[57];
    let l5 = m[48] ^ m[60];
    let l6 = m[61] ^ l5;
    let l7 = m[45] ^ l3;
    let l8 = m[50] ^ m[58];
    let l9 = m[51] ^ m[52];
    let l10 = m[52] ^ l4;
    let l11 = m[59] ^ l2;
    let l12 = m[47] ^ m[50];
    let l13 = m[49] ^ l0;
    let l14 = m[51] ^ m[60];
    let l15 = m[54] ^ l1;
    let l16 = m[55] ^ l0;
    let l17 = m[56] ^ l1;
    let l18 = m[57] ^ l8;
    let l19 = m[62] ^ l4;
    let l20 = l0 ^ l1;
    let l21 = l1 ^ l7;
    let l22 = l3 ^ l12;
    let l23 = l18 ^ l2;
    let l24 = l15 ^ l9;
    let l25 = l6 ^ l10;
    let l26 = l7 ^ l9;
    let l27 = l8 ^ l10;
    let l28 = l11 ^ l14;
    let l29 = l11 ^ l17;

    pack_bits([
        l6 ^ l24,
        (l16 ^ l26) ^ 1,
        (l19 ^ l28) ^ 1,
        l6 ^ l21,
        l20 ^ l22,
        l25 ^ l29,
        (l13 ^ l27) ^ 1,
        (l6 ^ l23) ^ 1,
    ])
}

/// Inverse AES S-box via the reverse-direction Boyar-Peralta circuit (ePrint
/// 2011/332, Figures 6, 7 and 9).
///
/// As above, this computes the same mapping as `INV_SBOX[input]` without using
/// a secret-indexed lookup.
#[inline]
fn inv_sbox_bool(input: u8) -> u8 {
    let linear_terms = inv_sbox_bool_linear(input);
    let non_linear_terms = inv_sbox_bool_nonlinear(linear_terms);
    inv_sbox_bool_output(non_linear_terms)
}

/// Figure 6, stored in evaluation order. Slot → paper name:
///
/// ```text
/// t[0]  T23   t[1]  T22   t[2]  T2    t[3]  T1    t[4]  T24   t[5]  R5
/// t[6]  T8    t[7]  T19   t[8]  T9    t[9]  T10   t[10] T13   t[11] T3
/// t[12] T25   t[13] R13   t[14] T17   t[15] T20   t[16] T4    t[17] R17
/// t[18] R18   t[19] R19   t[20] Y5    t[21] T6    t[22] T16   t[23] T27
/// t[24] T15   t[25] T14   t[26] T26
/// ```
///
/// `t[20]` is `Y5`, the reverse direction's `D` input to Figure 7.
fn inv_sbox_bool_linear(input: u8) -> [u8; TOP_LINEAR_SIGNALS] {
    let u0 = bit(input, 0);
    let u1 = bit(input, 1);
    let u2 = bit(input, 2);
    let u3 = bit(input, 3);
    let u4 = bit(input, 4);
    let u5 = bit(input, 5);
    let u6 = bit(input, 6);
    let u7 = bit(input, 7);

    let mut t = [0u8; TOP_LINEAR_SIGNALS];
    t[0] = u0 ^ u3;
    t[1] = xnor(u1, u3);
    t[2] = xnor(u0, u1);
    t[3] = u3 ^ u4;
    t[4] = xnor(u4, u7);
    t[5] = u6 ^ u7;
    t[6] = xnor(u1, t[0]);
    t[7] = t[1] ^ t[5];
    t[8] = xnor(u7, t[3]);
    t[9] = t[2] ^ t[4];
    t[10] = t[2] ^ t[5];
    t[11] = t[3] ^ t[5];
    t[12] = xnor(u2, t[3]);
    t[13] = u1 ^ u6;
    t[14] = xnor(u2, t[7]);
    t[15] = t[4] ^ t[13];
    t[16] = u4 ^ t[6];
    t[17] = xnor(u2, u5);
    t[18] = xnor(u5, u6);
    t[19] = xnor(u2, u4);
    t[20] = u0 ^ t[17];
    t[21] = t[1] ^ t[17];
    t[22] = t[13] ^ t[19];
    t[23] = t[3] ^ t[18];
    t[24] = t[9] ^ t[23];
    t[25] = t[9] ^ t[18];
    t[26] = t[11] ^ t[22];
    t
}

/// Figure 7 with `D = Y5` (`t[20]`): `m[k]` is the paper's `M(k+1)`, and the
/// `T` operands are read through the slot table on `inv_sbox_bool_linear`.
fn inv_sbox_bool_nonlinear(t: [u8; TOP_LINEAR_SIGNALS]) -> [u8; NONLINEAR_SIGNALS] {
    let mut m = [0u8; NONLINEAR_SIGNALS];
    m[0] = t[10] & t[21];
    m[1] = t[0] & t[6];
    m[2] = t[25] ^ m[0];
    m[3] = t[7] & t[20];
    m[4] = m[3] ^ m[0];
    m[5] = t[11] & t[22];
    m[6] = t[1] & t[8];
    m[7] = t[26] ^ m[5];
    m[8] = t[15] & t[14];
    m[9] = m[8] ^ m[5];
    m[10] = t[3] & t[24];
    m[11] = t[16] & t[23];
    m[12] = m[11] ^ m[10];
    m[13] = t[2] & t[9];
    m[14] = m[13] ^ m[10];
    m[15] = m[2] ^ m[1];
    m[16] = m[4] ^ t[4];
    m[17] = m[7] ^ m[6];
    m[18] = m[9] ^ m[14];
    m[19] = m[15] ^ m[12];
    m[20] = m[16] ^ m[14];
    m[21] = m[17] ^ m[12];
    m[22] = m[18] ^ t[12];
    m[23] = m[21] ^ m[22];
    m[24] = m[21] & m[19];
    m[25] = m[20] ^ m[24];
    m[26] = m[19] ^ m[20];
    m[27] = m[22] ^ m[24];
    m[28] = m[27] & m[26];
    m[29] = m[25] & m[23];
    m[30] = m[19] & m[22];
    m[31] = m[26] & m[30];
    m[32] = m[26] ^ m[24];
    m[33] = m[20] & m[21];
    m[34] = m[23] & m[33];
    m[35] = m[23] ^ m[24];
    m[36] = m[20] ^ m[28];
    m[37] = m[31] ^ m[32];
    m[38] = m[22] ^ m[29];
    m[39] = m[34] ^ m[35];
    m[40] = m[37] ^ m[39];
    m[41] = m[36] ^ m[38];
    m[42] = m[36] ^ m[37];
    m[43] = m[38] ^ m[39];
    m[44] = m[41] ^ m[40];
    m[45] = m[43] & t[21];
    m[46] = m[39] & t[6];
    m[47] = m[38] & t[20];
    m[48] = m[42] & t[22];
    m[49] = m[37] & t[8];
    m[50] = m[36] & t[14];
    m[51] = m[41] & t[24];
    m[52] = m[44] & t[23];
    m[53] = m[40] & t[9];
    m[54] = m[43] & t[10];
    m[55] = m[39] & t[0];
    m[56] = m[38] & t[7];
    m[57] = m[42] & t[11];
    m[58] = m[37] & t[1];
    m[59] = m[36] & t[15];
    m[60] = m[41] & t[3];
    m[61] = m[44] & t[16];
    m[62] = m[40] & t[2];
    m
}

/// Figure 9: `p*` keep the paper's numbers (which skip P21); the packed bits
/// are W0..W7.
fn inv_sbox_bool_output(m: [u8; NONLINEAR_SIGNALS]) -> u8 {
    let p0 = m[51] ^ m[60];
    let p1 = m[57] ^ m[58];
    let p2 = m[53] ^ m[61];
    let p3 = m[46] ^ m[49];
    let p4 = m[47] ^ m[55];
    let p5 = m[45] ^ m[50];
    let p6 = m[48] ^ m[59];
    let p7 = p0 ^ p1;
    let p8 = m[49] ^ m[52];
    let p9 = m[54] ^ m[62];
    let p10 = m[56] ^ p4;
    let p11 = p0 ^ p3;
    let p12 = m[45] ^ m[47];
    let p13 = m[48] ^ m[50];
    let p14 = m[48] ^ m[61];
    let p15 = m[53] ^ m[58];
    let p16 = m[56] ^ m[60];
    let p17 = m[57] ^ p2;
    let p18 = m[62] ^ p5;
    let p19 = p2 ^ p3;
    let p20 = p4 ^ p6;
    let p22 = p2 ^ p7;
    let p23 = p7 ^ p8;
    let p24 = p5 ^ p7;
    let p25 = p6 ^ p10;
    let p26 = p9 ^ p11;
    let p27 = p10 ^ p18;
    let p28 = p11 ^ p25;
    let p29 = p15 ^ p20;

    pack_bits([
        p13 ^ p22,
        p26 ^ p29,
        p17 ^ p28,
        p12 ^ p22,
        p23 ^ p27,
        p19 ^ p24,
        p14 ^ p23,
        p9 ^ p16,
    ])
}

// `SubWord` for the Ct key schedule (passed to `expand_key`): the same
// `KeyExpansion`, with the Boyar-Peralta S-box replacing the table lookup.
fn sub_word_bool(w: u32) -> u32 {
    u32::from(sbox_bool((w >> 24) as u8)) << 24
        | u32::from(sbox_bool(((w >> 16) & 0xff) as u8)) << 16
        | u32::from(sbox_bool(((w >> 8) & 0xff) as u8)) << 8
        | u32::from(sbox_bool((w & 0xff) as u8))
}

// The bytewise Ct decrypt path uses the direct inverse round functions, so it
// only needs the encryption round keys in reverse order. Unlike the fast
// T-table path, there is no equivalent-inverse table transform here.
fn make_dec_rk_ct(enc_rk: &[u32], dec_rk: &mut [u32], nr: usize) {
    for r in 0..=nr {
        let src = (nr - r) * 4;
        let dst = r * 4;
        dec_rk[dst..dst + 4].copy_from_slice(&enc_rk[src..src + 4]);
    }
}

#[inline]
fn add_round_key_ct(state: &mut [u8; BLOCK_BYTES], rk: &[u32]) {
    for c in 0..NB {
        let word = rk[c].to_be_bytes();
        for r in 0..WORD_BYTES {
            state[WORD_BYTES * c + r] ^= word[r];
        }
    }
}

#[inline]
fn sub_bytes_ct(state: &mut [u8; BLOCK_BYTES]) {
    for b in state.iter_mut() {
        *b = sbox_bool(*b);
    }
}

#[inline]
fn inv_sub_bytes_ct(state: &mut [u8; BLOCK_BYTES]) {
    for b in state.iter_mut() {
        *b = inv_sbox_bool(*b);
    }
}

#[inline]
fn shift_rows_ct(state: &mut [u8; BLOCK_BYTES]) {
    let t = *state;
    state[0] = t[0];
    state[1] = t[5];
    state[2] = t[10];
    state[3] = t[15];
    state[4] = t[4];
    state[5] = t[9];
    state[6] = t[14];
    state[7] = t[3];
    state[8] = t[8];
    state[9] = t[13];
    state[10] = t[2];
    state[11] = t[7];
    state[12] = t[12];
    state[13] = t[1];
    state[14] = t[6];
    state[15] = t[11];
}

#[inline]
fn inv_shift_rows_ct(state: &mut [u8; BLOCK_BYTES]) {
    let t = *state;
    state[0] = t[0];
    state[1] = t[13];
    state[2] = t[10];
    state[3] = t[7];
    state[4] = t[4];
    state[5] = t[1];
    state[6] = t[14];
    state[7] = t[11];
    state[8] = t[8];
    state[9] = t[5];
    state[10] = t[2];
    state[11] = t[15];
    state[12] = t[12];
    state[13] = t[9];
    state[14] = t[6];
    state[15] = t[3];
}

#[inline]
fn mix_columns_ct(state: &mut [u8; BLOCK_BYTES]) {
    for c in 0..NB {
        let i = WORD_BYTES * c;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;

        state[i] = a0 ^ t ^ xtime(a0 ^ a1);
        state[i + 1] = a1 ^ t ^ xtime(a1 ^ a2);
        state[i + 2] = a2 ^ t ^ xtime(a2 ^ a3);
        state[i + 3] = a3 ^ t ^ xtime(a3 ^ a0);
    }
}

#[inline]
fn inv_mix_columns_ct(state: &mut [u8; BLOCK_BYTES]) {
    for c in 0..NB {
        let i = WORD_BYTES * c;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
        state[i + 1] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
        state[i + 2] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
        state[i + 3] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
    }
}

fn aes_encrypt_ct(block: &[u8; BLOCK_BYTES], rk: &[u32], nr: usize) -> [u8; BLOCK_BYTES] {
    let mut state = *block;
    add_round_key_ct(&mut state, &rk[..NB]);

    for r in 1..nr {
        sub_bytes_ct(&mut state);
        shift_rows_ct(&mut state);
        mix_columns_ct(&mut state);
        add_round_key_ct(&mut state, &rk[NB * r..NB * r + NB]);
    }

    sub_bytes_ct(&mut state);
    shift_rows_ct(&mut state);
    add_round_key_ct(&mut state, &rk[NB * nr..NB * nr + NB]);
    state
}

fn aes_decrypt_ct(block: &[u8; BLOCK_BYTES], dk: &[u32], nr: usize) -> [u8; BLOCK_BYTES] {
    let mut state = *block;
    add_round_key_ct(&mut state, &dk[..NB]);

    for r in 1..nr {
        inv_shift_rows_ct(&mut state);
        inv_sub_bytes_ct(&mut state);
        add_round_key_ct(&mut state, &dk[NB * r..NB * r + NB]);
        inv_mix_columns_ct(&mut state);
    }

    inv_shift_rows_ct(&mut state);
    inv_sub_bytes_ct(&mut state);
    add_round_key_ct(&mut state, &dk[NB * nr..NB * nr + NB]);
    state
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Define one AES type: its round-key fields, key setup that expands
/// straight into those fields, and the block functions.
///
/// `$expand_sub` is the `SubWord` evaluator handed to `expand_key`,
/// `$make_dec` builds the decryption schedule from the forward one, and
/// `$enc`/`$dec` are the round cores. Both schedules live in the struct from
/// the start (FIPS 197 § 5.2 for the forward schedule; § 5.3.5 for the
/// equivalent-inverse schedule of the T-table types, a plain reversal for the
/// `Ct` types), so repeated calls in either direction re-derive nothing.
macro_rules! define_aes {
    (
        $(#[$meta:meta])*
        $Name:ident, $key_len:expr, $words:expr, $nr:expr,
        $expand_sub:ident, $make_dec:ident, $enc:ident, $dec:ident,
        $timing:literal
    ) => {
        $(#[$meta])*
        pub struct $Name {
            enc_rk: [u32; $words],
            dec_rk: [u32; $words],
        }

        impl $Name {
            /// Expand the key into the forward round-key schedule and the
            /// decryption schedule, both written directly into the new
            /// instance's own arrays (no separately owned copy of a schedule
            /// exists during setup).
            #[must_use]
            pub fn new(key: &[u8; $key_len]) -> Self {
                let mut cipher = Self {
                    enc_rk: [0u32; $words],
                    dec_rk: [0u32; $words],
                };
                expand_key(key, &mut cipher.enc_rk, $expand_sub);
                $make_dec(&cipher.enc_rk, &mut cipher.dec_rk, $nr);
                cipher
            }

            /// Expand the key as `new` does, then wipe the caller-owned key
            /// buffer.
            pub fn new_wiping(key: &mut [u8; $key_len]) -> Self {
                let out = Self::new(key);
                crate::ct::zeroize_slice(key.as_mut_slice());
                out
            }

            #[doc = concat!("Encrypt one 16-byte block through the full round schedule. ", $timing)]
            #[must_use]
            pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
                $enc(block, &self.enc_rk, $nr)
            }

            #[doc = concat!("Decrypt one 16-byte block through the inverse round schedule. ", $timing)]
            #[must_use]
            pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
                $dec(block, &self.dec_rk, $nr)
            }
        }
    };
}

define_aes!(
    /// AES-128 cipher: 128-bit key, 10 rounds, T-table software path.
    ///
    /// Variable-time: the T-table indices are the secret state. Use
    /// [`Aes128Ct`] when timing matters.
    Aes128, AES128_KEY_BYTES, expanded_words(AES128_ROUNDS), AES128_ROUNDS, sub_word, make_dec_rk, aes_encrypt, aes_decrypt,
    "T-table path: variable-time in key and data; the `Ct` sibling type is the constant-time choice."
);
define_aes!(
    /// AES-192 cipher: 192-bit key, 12 rounds, T-table software path.
    ///
    /// Variable-time: the T-table indices are the secret state. Use
    /// [`Aes192Ct`] when timing matters.
    Aes192, AES192_KEY_BYTES, expanded_words(AES192_ROUNDS), AES192_ROUNDS, sub_word, make_dec_rk, aes_encrypt, aes_decrypt,
    "T-table path: variable-time in key and data; the `Ct` sibling type is the constant-time choice."
);
define_aes!(
    /// AES-256 cipher: 256-bit key, 14 rounds, T-table software path.
    ///
    /// Variable-time: the T-table indices are the secret state. Use
    /// [`Aes256Ct`] when timing matters.
    Aes256, AES256_KEY_BYTES, expanded_words(AES256_ROUNDS), AES256_ROUNDS, sub_word, make_dec_rk, aes_encrypt, aes_decrypt,
    "T-table path: variable-time in key and data; the `Ct` sibling type is the constant-time choice."
);
define_aes!(
    /// AES-128 constant-time software path.
    ///
    /// Same external API as [`Aes128`], with the T-table round core replaced
    /// by a bytewise implementation whose S-box is the Boyar-Peralta boolean
    /// circuit (ePrint 2011/332); `SubWord` in key setup goes through the
    /// same circuit, so neither key setup nor the block functions perform a
    /// secret-indexed table read.
    Aes128Ct, AES128_KEY_BYTES, expanded_words(AES128_ROUNDS), AES128_ROUNDS, sub_word_bool, make_dec_rk_ct, aes_encrypt_ct, aes_decrypt_ct,
    "Bytewise path with the Boyar-Peralta S-box circuit: no secret-dependent memory access or branch, at a throughput cost versus the T-table type."
);
define_aes!(
    /// AES-192 constant-time software path: the counterpart of [`Aes192`]
    /// built like [`Aes128Ct`].
    Aes192Ct, AES192_KEY_BYTES, expanded_words(AES192_ROUNDS), AES192_ROUNDS, sub_word_bool, make_dec_rk_ct, aes_encrypt_ct, aes_decrypt_ct,
    "Bytewise path with the Boyar-Peralta S-box circuit: no secret-dependent memory access or branch, at a throughput cost versus the T-table type."
);
define_aes!(
    /// AES-256 constant-time software path: the counterpart of [`Aes256`]
    /// built like [`Aes128Ct`].
    Aes256Ct, AES256_KEY_BYTES, expanded_words(AES256_ROUNDS), AES256_ROUNDS, sub_word_bool, make_dec_rk_ct, aes_encrypt_ct, aes_decrypt_ct,
    "Bytewise path with the Boyar-Peralta S-box circuit: no secret-dependent memory access or branch, at a throughput cost versus the T-table type."
);

/// Encryption-only AES-256 for `CTR_DRBG`.
///
/// SP 800-90A Rev. 1 § 10.2.1 calls only `Block_Encrypt`, and `CTR_DRBG`
/// rekeys on every update, so a keyed instance there needs the forward
/// schedule alone; building the inverse schedule each time would be
/// discarded work. These types carry just that schedule and have no decrypt
/// method, so nothing can call a decryption that was never keyed. The module
/// is crate-visible only; the types are nominally `pub` so the DRBG's sealed
/// cipher trait may name them.
pub(crate) mod encrypt_only {
    use super::{
        aes_encrypt, aes_encrypt_ct, expand_key, sub_word, sub_word_bool, AES256_KEY_BYTES,
        AES256_ROUNDS, BLOCK_BYTES,
    };

    macro_rules! define_aes256_encryptor {
        ($(#[$meta:meta])* $Name:ident, $expand_sub:ident, $enc:ident) => {
            $(#[$meta])*
            pub struct $Name {
                rk: [u32; super::expanded_words(AES256_ROUNDS)],
            }

            impl $Name {
                /// Expand the forward schedule (FIPS 197 § 5.2) into the new
                /// instance's own array.
                pub(crate) fn new(key: &[u8; AES256_KEY_BYTES]) -> Self {
                    let mut out = Self {
                        rk: [0u32; super::expanded_words(AES256_ROUNDS)],
                    };
                    expand_key(key, &mut out.rk, $expand_sub);
                    out
                }

                /// Encrypt one block through the 14 rounds.
                pub(crate) fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
                    $enc(block, &self.rk, AES256_ROUNDS)
                }
            }

            impl Drop for $Name {
                fn drop(&mut self) {
                    crate::ct::zeroize_slice(self.rk.as_mut_slice());
                }
            }
        };
    }

    define_aes256_encryptor!(
        /// Forward-only AES-256 on the T-table path (variable-time, like
        /// [`super::Aes256`]).
        Aes256Encryptor, sub_word, aes_encrypt
    );
    define_aes256_encryptor!(
        /// Forward-only AES-256 on the Boyar-Peralta path (constant-time, like
        /// [`super::Aes256Ct`]).
        Aes256CtEncryptor, sub_word_bool, aes_encrypt_ct
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockCipher trait implementations
// ─────────────────────────────────────────────────────────────────────────────

macro_rules! impl_block_cipher_aes {
    ($Name:ident) => {
        impl crate::BlockCipher for $Name {
            const BLOCK_LEN: usize = 16;
            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.encrypt_block(arr));
            }
            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.decrypt_block(arr));
            }
        }
    };
}

impl_block_cipher_aes!(Aes128);
impl_block_cipher_aes!(Aes192);
impl_block_cipher_aes!(Aes256);
impl_block_cipher_aes!(Aes128Ct);
impl_block_cipher_aes!(Aes192Ct);
impl_block_cipher_aes!(Aes256Ct);

macro_rules! impl_drop_aes {
    ($Name:ident) => {
        impl Drop for $Name {
            fn drop(&mut self) {
                // AES retains both forward and reverse schedules for reuse.
                crate::ct::zeroize_slice(self.enc_rk.as_mut_slice());
                crate::ct::zeroize_slice(self.dec_rk.as_mut_slice());
            }
        }
    };
}

impl_drop_aes!(Aes128);
impl_drop_aes!(Aes192);
impl_drop_aes!(Aes256);
impl_drop_aes!(Aes128Ct);
impl_drop_aes!(Aes192Ct);
impl_drop_aes!(Aes256Ct);

// ─────────────────────────────────────────────────────────────────────────────
// Tests — FIPS 197 Appendix C, NIST CAVP KAT_AES (CAVS 11.1), OpenSSL oracle
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decode_hex_array;
    use crate::BlockCipher;

    /// Both paths' encryption of one block under a key of the case's length.
    type BothPaths = fn(&[u8], &[u8; 16]) -> ([u8; 16], [u8; 16]);

    /// One known answer through both implementations of a key size: the
    /// T-table type and the `Ct` type each encrypt `pt` to `ct` and decrypt
    /// `ct` to `pt`, through the `BlockCipher` trait.
    fn kat_pair<F: BlockCipher, S: BlockCipher>(fast: &F, slow: &S, key: &str, pt: &str, ct: &str) {
        fn one<C: BlockCipher>(name: &str, cipher: &C, key: &str, pt: &str, ct: &str) {
            let pt_bytes = decode_hex_array::<16>(pt);
            let ct_bytes = decode_hex_array::<16>(ct);
            let mut block = pt_bytes;
            cipher.encrypt(&mut block);
            assert_eq!(block, ct_bytes, "{name} enc {key}/{pt}");
            cipher.decrypt(&mut block);
            assert_eq!(block, pt_bytes, "{name} dec {key}/{ct}");
        }
        one("fast", fast, key, pt, ct);
        one("Ct", slow, key, pt, ct);
    }
    fn kat128(key: &str, pt: &str, ct: &str) {
        let k = decode_hex_array::<16>(key);
        kat_pair(&Aes128::new(&k), &Aes128Ct::new(&k), key, pt, ct);
    }
    fn kat192(key: &str, pt: &str, ct: &str) {
        let k = decode_hex_array::<24>(key);
        kat_pair(&Aes192::new(&k), &Aes192Ct::new(&k), key, pt, ct);
    }
    fn kat256(key: &str, pt: &str, ct: &str) {
        let k = decode_hex_array::<32>(key);
        kat_pair(&Aes256::new(&k), &Aes256Ct::new(&k), key, pt, ct);
    }

    // ── FIPS 197 Appendix C — example vectors ────────────────────────────────
    // The worked examples: key bytes 00, 01, 02, ... and the plaintext
    // 00112233445566778899aabbccddeeff. C.1 is AES-128, C.2 AES-192, C.3
    // AES-256; the ciphertexts are the "output" lines of each.

    #[test]
    fn fips197_appendix_c1_aes128() {
        kat128(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn fips197_appendix_c2_aes192() {
        kat192(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn fips197_appendix_c3_aes256() {
        kat256(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }

    /// FIPS 197 Appendix A.1: the last round key of the expanded AES-128 key
    /// 2b7e151628aed2a6abf7158809cf4f3c is w[40..44] =
    /// d014f9a8 c9ee2589 e13f0cc8 b6630ca6, for both `SubWord` evaluators.
    #[test]
    fn fips197_appendix_a1_key_expansion() {
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let expected = [0xd014_f9a8, 0xc9ee_2589, 0xe13f_0cc8, 0xb663_0ca6];
        for sub in [sub_word as fn(u32) -> u32, sub_word_bool] {
            let mut w = [0u32; 44];
            expand_key(&key, &mut w, sub);
            assert_eq!(w[40..44], expected);
            assert_eq!(w[4], 0xa0fa_fe17, "w[4] of A.1");
        }
    }

    /// Decryption on the two paths agrees on arbitrary blocks (the KATs cover
    /// the tabulated ones): the equivalent-inverse schedule of the T-table
    /// path and the plain reversed schedule of the `Ct` path invert the same
    /// cipher.
    #[test]
    fn decrypt_fast_matches_ct_on_arbitrary_blocks() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |out: &mut [u8]| {
            for chunk in out.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let bytes = state.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        };
        for _ in 0..64 {
            let mut k128 = [0u8; 16];
            let mut k192 = [0u8; 24];
            let mut k256 = [0u8; 32];
            let mut block = [0u8; 16];
            next(&mut k128);
            next(&mut k192);
            next(&mut k256);
            next(&mut block);
            assert_eq!(
                Aes128::new(&k128).decrypt_block(&block),
                Aes128Ct::new(&k128).decrypt_block(&block)
            );
            assert_eq!(
                Aes192::new(&k192).decrypt_block(&block),
                Aes192Ct::new(&k192).decrypt_block(&block)
            );
            assert_eq!(
                Aes256::new(&k256).decrypt_block(&block),
                Aes256Ct::new(&k256).decrypt_block(&block)
            );
            assert_eq!(
                Aes256::new(&k256).encrypt_block(&block),
                encrypt_only::Aes256Encryptor::new(&k256).encrypt_block(&block),
                "forward-only schedule"
            );
            assert_eq!(
                Aes256Ct::new(&k256).encrypt_block(&block),
                encrypt_only::Aes256CtEncryptor::new(&k256).encrypt_block(&block),
                "forward-only Ct schedule"
            );
        }
    }

    /// The `BlockCipher` trait refuses any length other than the 16-byte
    /// block.
    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_trait_refuses_wrong_block_length() {
        let cipher = Aes128::new(&[0u8; 16]);
        let mut block = [0u8; 17];
        cipher.encrypt(&mut block);
    }

    #[test]
    fn bool_sbox_matches_tables() {
        for x in 0u16..=255 {
            let b = u8::try_from(x).expect("table index fits in u8");
            assert_eq!(sbox_bool(b), SBOX[x as usize], "sbox {x:02x}");
            assert_eq!(inv_sbox_bool(b), INV_SBOX[x as usize], "inv_sbox {x:02x}");
        }
    }

    const KEYSBOX_128_CASES: [(&str, &str, &str); 21] = [
        (
            "10a58869d74be5a374cf867cfb473859",
            "00000000000000000000000000000000",
            "6d251e6944b051e04eaa6fb4dbf78465",
        ),
        (
            "caea65cdbb75e9169ecd22ebe6e54675",
            "00000000000000000000000000000000",
            "6e29201190152df4ee058139def610bb",
        ),
        (
            "a2e2fa9baf7d20822ca9f0542f764a41",
            "00000000000000000000000000000000",
            "c3b44b95d9d2f25670eee9a0de099fa3",
        ),
        (
            "b6364ac4e1de1e285eaf144a2415f7a0",
            "00000000000000000000000000000000",
            "5d9b05578fc944b3cf1ccf0e746cd581",
        ),
        (
            "64cf9c7abc50b888af65f49d521944b2",
            "00000000000000000000000000000000",
            "f7efc89d5dba578104016ce5ad659c05",
        ),
        (
            "47d6742eefcc0465dc96355e851b64d9",
            "00000000000000000000000000000000",
            "0306194f666d183624aa230a8b264ae7",
        ),
        (
            "3eb39790678c56bee34bbcdeccf6cdb5",
            "00000000000000000000000000000000",
            "858075d536d79ccee571f7d7204b1f67",
        ),
        (
            "64110a924f0743d500ccadae72c13427",
            "00000000000000000000000000000000",
            "35870c6a57e9e92314bcb8087cde72ce",
        ),
        (
            "18d8126516f8a12ab1a36d9f04d68e51",
            "00000000000000000000000000000000",
            "6c68e9be5ec41e22c825b7c7affb4363",
        ),
        (
            "f530357968578480b398a3c251cd1093",
            "00000000000000000000000000000000",
            "f5df39990fc688f1b07224cc03e86cea",
        ),
        (
            "da84367f325d42d601b4326964802e8e",
            "00000000000000000000000000000000",
            "bba071bcb470f8f6586e5d3add18bc66",
        ),
        (
            "e37b1c6aa2846f6fdb413f238b089f23",
            "00000000000000000000000000000000",
            "43c9f7e62f5d288bb27aa40ef8fe1ea8",
        ),
        (
            "6c002b682483e0cabcc731c253be5674",
            "00000000000000000000000000000000",
            "3580d19cff44f1014a7c966a69059de5",
        ),
        (
            "143ae8ed6555aba96110ab58893a8ae1",
            "00000000000000000000000000000000",
            "806da864dd29d48deafbe764f8202aef",
        ),
        (
            "b69418a85332240dc82492353956ae0c",
            "00000000000000000000000000000000",
            "a303d940ded8f0baff6f75414cac5243",
        ),
        (
            "71b5c08a1993e1362e4d0ce9b22b78d5",
            "00000000000000000000000000000000",
            "c2dabd117f8a3ecabfbb11d12194d9d0",
        ),
        (
            "e234cdca2606b81f29408d5f6da21206",
            "00000000000000000000000000000000",
            "fff60a4740086b3b9c56195b98d91a7b",
        ),
        (
            "13237c49074a3da078dc1d828bb78c6f",
            "00000000000000000000000000000000",
            "8146a08e2357f0caa30ca8c94d1a0544",
        ),
        (
            "3071a2a48fe6cbd04f1a129098e308f8",
            "00000000000000000000000000000000",
            "4b98e06d356deb07ebb824e5713f7be3",
        ),
        (
            "90f42ec0f68385f2ffc5dfc03a654dce",
            "00000000000000000000000000000000",
            "7a20a53d460fc9ce0423a7a0764c6cf2",
        ),
        (
            "febd9a24d8b65c1c787d50a4ed3619a9",
            "00000000000000000000000000000000",
            "f4a70d8af877f9b02b4c40df57d45b17",
        ),
    ];

    // ── ECBGFSbox: key=0, plaintext chosen to stress the S-box ───────────────
    // NIST CAVP KAT_AES: ECBGFSbox128/192/256.rsp, the ENCRYPT tables in
    // full (7, 6 and 5 entries).
    #[test]
    fn gfsbox_128() {
        let v = [
            (
                "00000000000000000000000000000000",
                "f34481ec3cc627bacd5dc3fb08f273e6",
                "0336763e966d92595a567cc9ce537f5e",
            ),
            (
                "00000000000000000000000000000000",
                "9798c4640bad75c7c3227db910174e72",
                "a9a1631bf4996954ebc093957b234589",
            ),
            (
                "00000000000000000000000000000000",
                "96ab5c2ff612d9dfaae8c31f30c42168",
                "ff4f8391a6a40ca5b25d23bedd44a597",
            ),
            (
                "00000000000000000000000000000000",
                "6a118a874519e64e9963798a503f1d35",
                "dc43be40be0e53712f7e2bf5ca707209",
            ),
            (
                "00000000000000000000000000000000",
                "cb9fceec81286ca3e989bd979b0cb284",
                "92beedab1895a94faa69b632e5cc47ce",
            ),
            (
                "00000000000000000000000000000000",
                "b26aeb1874e47ca8358ff22378f09144",
                "459264f4798f6a78bacb89c15ed3d601",
            ),
            (
                "00000000000000000000000000000000",
                "58c8e00b2631686d54eab84b91f0aca1",
                "08a4e2efec8a8e3312ca7460b9040bbf",
            ),
        ];
        for (k, p, c) in v {
            kat128(k, p, c);
        }
    }

    #[test]
    fn gfsbox_192() {
        let v = [
            (
                "000000000000000000000000000000000000000000000000",
                "1b077a6af4b7f98229de786d7516b639",
                "275cfc0413d8ccb70513c3859b1d0f72",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "9c2d8842e5f48f57648205d39a239af1",
                "c9b8135ff1b5adc413dfd053b21bd96d",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "bff52510095f518ecca60af4205444bb",
                "4a3650c3371ce2eb35e389a171427440",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "51719783d3185a535bd75adc65071ce1",
                "4f354592ff7c8847d2d0870ca9481b7c",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "26aa49dcfe7629a8901a69a9914e6dfd",
                "d5e08bf9a182e857cf40b3a36ee248cc",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "941a4773058224e1ef66d10e0a6ee782",
                "067cd9d3749207791841562507fa9626",
            ),
        ];
        for (k, p, c) in v {
            kat192(k, p, c);
        }
    }

    #[test]
    fn gfsbox_256() {
        let v = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "014730f80ac625fe84f026c60bfd547d",
                "5c9d844ed46f9885085e5d6a4f94c7d7",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0b24af36193ce4665f2825d7b4749c98",
                "a9ff75bd7cf6613d3731c77c3b6d0c04",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "761c1fe41a18acf20d241650611d90f1",
                "623a52fcea5d443e48d9181ab32c7421",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "8a560769d605868ad80d819bdba03771",
                "38f2c7ae10612415d27ca190d27da8b4",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "91fbef2d15a97816060bee1feaa49afe",
                "1bc704f1bce135ceb810341b216d7abe",
            ),
        ];
        for (k, p, c) in v {
            kat256(k, p, c);
        }
    }

    // ── ECBKeySbox: plaintext=0, key chosen to stress the key schedule ────────
    // NIST CAVP KAT_AES: ECBKeySbox128.rsp in full (21 entries); the first
    // five of ECBKeySbox192.rsp and first ten of ECBKeySbox256.rsp.
    #[test]
    fn keysbox_128() {
        for (k, p, c) in KEYSBOX_128_CASES {
            kat128(k, p, c);
        }
    }

    #[test]
    fn keysbox_192() {
        let v = [
            (
                "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd",
                "00000000000000000000000000000000",
                "0956259c9cd5cfd0181cca53380cde06",
            ),
            (
                "15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29",
                "00000000000000000000000000000000",
                "8e4e18424e591a3d5b6f0876f16f8594",
            ),
            (
                "a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c",
                "00000000000000000000000000000000",
                "93f3270cfc877ef17e106ce938979cb0",
            ),
            (
                "cd62376d5ebb414917f0c78f05266433dc9192a1ec943300",
                "00000000000000000000000000000000",
                "7f6c25ff41858561bb62f36492e93c29",
            ),
            (
                "502a6ab36984af268bf423c7f509205207fc1552af4a91e5",
                "00000000000000000000000000000000",
                "8e06556dcbb00b809a025047cff2a940",
            ),
        ];
        for (k, p, c) in v {
            kat192(k, p, c);
        }
    }

    #[test]
    fn keysbox_256() {
        let v = [
            (
                "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
                "00000000000000000000000000000000",
                "46f2fb342d6f0ab477476fc501242c5f",
            ),
            (
                "28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64",
                "00000000000000000000000000000000",
                "4bf3b0a69aeb6657794f2901b1440ad4",
            ),
            (
                "c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c",
                "00000000000000000000000000000000",
                "352065272169abf9856843927d0674fd",
            ),
            (
                "984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627",
                "00000000000000000000000000000000",
                "4307456a9e67813b452e15fa8fffe398",
            ),
            (
                "b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f",
                "00000000000000000000000000000000",
                "4663446607354989477a5c6f0f007ef4",
            ),
            (
                "1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9",
                "00000000000000000000000000000000",
                "531c2c38344578b84d50b3c917bbb6e1",
            ),
            (
                "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf",
                "00000000000000000000000000000000",
                "fc6aec906323480005c58e7e1ab004ad",
            ),
            (
                "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9",
                "00000000000000000000000000000000",
                "a3944b95ca0b52043584ef02151926a8",
            ),
            (
                "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e",
                "00000000000000000000000000000000",
                "a74289fe73a4c123ca189ea1e1b49ad5",
            ),
            (
                "6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707",
                "00000000000000000000000000000000",
                "b91d4ea4488644b56cf0812fa7fcf5fc",
            ),
        ];
        for (k, p, c) in v {
            kat256(k, p, c);
        }
    }

    // ── ECBVarKey: leading-ones key ramp, zero plaintext ─────────────────────
    // NIST CAVP KAT_AES: ECBVarKey128/192/256.rsp, the first entries. The
    // keys are 80.., c0.., e0.., f0.., ...: entry i has its i+1 leading bits
    // set (the full table walks all 128, 192 or 256 bits), not a single bit.
    #[test]
    fn varkey_128() {
        let v = [
            (
                "80000000000000000000000000000000",
                "00000000000000000000000000000000",
                "0edd33d3c621e546455bd8ba1418bec8",
            ),
            (
                "c0000000000000000000000000000000",
                "00000000000000000000000000000000",
                "4bc3f883450c113c64ca42e1112a9e87",
            ),
            (
                "e0000000000000000000000000000000",
                "00000000000000000000000000000000",
                "72a1da770f5d7ac4c9ef94d822affd97",
            ),
            (
                "f0000000000000000000000000000000",
                "00000000000000000000000000000000",
                "970014d634e2b7650777e8e84d03ccd8",
            ),
            (
                "f8000000000000000000000000000000",
                "00000000000000000000000000000000",
                "f17e79aed0db7e279e955b5f493875a7",
            ),
            (
                "fc000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9ed5a75136a940d0963da379db4af26a",
            ),
            (
                "fe000000000000000000000000000000",
                "00000000000000000000000000000000",
                "c4295f83465c7755e8fa364bac6a7ea5",
            ),
            (
                "ff000000000000000000000000000000",
                "00000000000000000000000000000000",
                "b1d758256b28fd850ad4944208cf1155",
            ),
        ];
        for (k, p, c) in v {
            kat128(k, p, c);
        }
    }

    #[test]
    fn varkey_192() {
        let v = [
            (
                "800000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "de885dc87f5a92594082d02cc1e1b42c",
            ),
            (
                "c00000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "132b074e80f2a597bf5febd8ea5da55e",
            ),
            (
                "e00000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "6eccedf8de592c22fb81347b79f2db1f",
            ),
            (
                "f00000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "180b09f267c45145db2f826c2582d35c",
            ),
            (
                "f80000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "edd807ef7652d7eb0e13c8b5e15b3bc0",
            ),
            (
                "fc0000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9978bcf8dd8fd72241223ad24b31b8a4",
            ),
        ];
        for (k, p, c) in v {
            kat192(k, p, c);
        }
    }

    #[test]
    fn varkey_256() {
        let v = [
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "e35a6dcb19b201a01ebcfa8aa22b5759",
            ),
            (
                "c000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "b29169cdcf2d83e838125a12ee6aa400",
            ),
            (
                "e000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "d8f3a72fc3cdf74dfaf6c3e6b97b2fa6",
            ),
            (
                "f000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "1c777679d50037c79491a94da76a9a35",
            ),
            (
                "f800000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9cf4893ecafa0a0247a898e040691559",
            ),
            (
                "fc00000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "8fbb413703735326310a269bd3aa94b2",
            ),
        ];
        for (k, p, c) in v {
            kat256(k, p, c);
        }
    }

    // ── ECBVarTxt: zero key, leading-ones plaintext ramp ──────────────────────
    // NIST CAVP KAT_AES: ECBVarTxt128/192/256.rsp, the first entries; the
    // plaintexts ramp 80.., c0.., e0.., ... as the VarKey keys do.
    #[test]
    fn vartxt_128() {
        let v = [
            (
                "00000000000000000000000000000000",
                "80000000000000000000000000000000",
                "3ad78e726c1ec02b7ebfe92b23d9ec34",
            ),
            (
                "00000000000000000000000000000000",
                "c0000000000000000000000000000000",
                "aae5939c8efdf2f04e60b9fe7117b2c2",
            ),
            (
                "00000000000000000000000000000000",
                "e0000000000000000000000000000000",
                "f031d4d74f5dcbf39daaf8ca3af6e527",
            ),
            (
                "00000000000000000000000000000000",
                "f0000000000000000000000000000000",
                "96d9fd5cc4f07441727df0f33e401a36",
            ),
            (
                "00000000000000000000000000000000",
                "f8000000000000000000000000000000",
                "30ccdb044646d7e1f3ccea3dca08b8c0",
            ),
            (
                "00000000000000000000000000000000",
                "fc000000000000000000000000000000",
                "16ae4ce5042a67ee8e177b7c587ecc82",
            ),
            (
                "00000000000000000000000000000000",
                "fe000000000000000000000000000000",
                "b6da0bb11a23855d9c5cb1b4c6412e0a",
            ),
            (
                "00000000000000000000000000000000",
                "ff000000000000000000000000000000",
                "db4f1aa530967d6732ce4715eb0ee24b",
            ),
        ];
        for (k, p, c) in v {
            kat128(k, p, c);
        }
    }

    #[test]
    fn vartxt_192() {
        let v = [
            (
                "000000000000000000000000000000000000000000000000",
                "80000000000000000000000000000000",
                "6cd02513e8d4dc986b4afe087a60bd0c",
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "c0000000000000000000000000000000",
                "2ce1f8b7e30627c1c4519eada44bc436",
            ),
        ];
        for (k, p, c) in v {
            kat192(k, p, c);
        }
    }

    #[test]
    fn vartxt_256() {
        let v = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "80000000000000000000000000000000",
                "ddc6bf790c15760d8d9aeb6f9a75fd4e",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "c0000000000000000000000000000000",
                "0a6bdc6d4c1e6280301fd8e97ddbe601",
            ),
        ];
        for (k, p, c) in v {
            kat256(k, p, c);
        }
    }

    // ── Compile-time table spot-checks (verify GF arithmetic) ────────────────
    #[test]
    fn te0_spot_check() {
        // SBOX[0]=0x63; xtime(0x63)=0xc6; mul3(0x63)=0xc6^0x63=0xa5
        // TE0[0] = 0xc6_63_63_a5
        assert_eq!(TE0[0], 0xc663_63a5);
        // SBOX[1]=0x7c; xtime(0x7c)=0xf8; mul3(0x7c)=0xf8^0x7c=0x84
        assert_eq!(TE0[1], 0xf87c_7c84);
    }

    #[test]
    fn td0_spot_check() {
        // INV_SBOX[0]=0x52; mul14=0x51, mul9=0xf4, mul13=0xa7, mul11=0x50
        assert_eq!(TD0[0], 0x51f4_a750);
    }

    /// OpenSSL `enc` as a black-box oracle for the three key sizes, on a key
    /// and block that appear in no table above, for both paths. Skips loudly
    /// when no `openssl` is installed.
    #[test]
    fn aes_matches_openssl_ecb() {
        let key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        let pt_hex = "6bc1bee22e409f96e93d7e117393172a";
        let pt = decode_hex_array::<16>(pt_hex);
        let cases: [(&str, usize, BothPaths); 3] = [
            ("-aes-128-ecb", 16, |k, p| {
                let k: &[u8; 16] = k.try_into().expect("16-byte key");
                (
                    Aes128::new(k).encrypt_block(p),
                    Aes128Ct::new(k).encrypt_block(p),
                )
            }),
            ("-aes-192-ecb", 24, |k, p| {
                let k: &[u8; 24] = k.try_into().expect("24-byte key");
                (
                    Aes192::new(k).encrypt_block(p),
                    Aes192Ct::new(k).encrypt_block(p),
                )
            }),
            ("-aes-256-ecb", 32, |k, p| {
                let k: &[u8; 32] = k.try_into().expect("32-byte key");
                (
                    Aes256::new(k).encrypt_block(p),
                    Aes256Ct::new(k).encrypt_block(p),
                )
            }),
        ];
        for (flag, key_len, ours) in cases {
            let key_hex = &key_hex[..2 * key_len];
            let Some(expected) = crate::test_utils::openssl_enc(flag, key_hex, None, &pt)
                .or_skip(&format!("aes_matches_openssl_ecb {flag}"))
            else {
                continue;
            };
            let key = crate::test_utils::decode_hex(key_hex);
            let (fast, slow) = ours(&key, &pt);
            assert_eq!(fast.as_slice(), expected.as_slice(), "{flag} fast path");
            assert_eq!(slow.as_slice(), expected.as_slice(), "{flag} Ct path");
        }
    }
}
