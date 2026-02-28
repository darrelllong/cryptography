/// AES (Rijndael, 128-bit block) — AES-128, AES-192, AES-256.
///
/// Implemented from FIPS PUB 197 (2001), the complete Rijndael specification
/// for a 128-bit block width with 10, 12, or 14 rounds depending on key length.
///
/// # Default path — fast software T-tables
///
/// The active encrypt/decrypt path uses the classic T-table software design:
/// each middle round folds SubBytes, ShiftRows, MixColumns, and AddRoundKey
/// into four 256-entry `u32` lookup tables computed at compile time from the
/// FIPS 197 S-boxes.
///
/// This software path is intentionally optimized for throughput, not
/// constant-time behavior.  Use `Aes128Ct`, `Aes192Ct`, or `Aes256Ct` for the
/// software-only Boyar-Peralta path when constant-time behavior matters.
/// Hardware AES (for example AES-NI or ARMv8 Crypto Extensions) is still the
/// preferred option when it is available.
///
/// # Tests
/// All vectors are from NIST CAVP KAT_AES.zip (CAVS 11.1, 2011-04-22),
/// downloaded directly from csrc.nist.gov.

// ─────────────────────────────────────────────────────────────────────────────
// FIPS 197 S-boxes  (§ 4.2.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Forward S-box — FIPS 197, Figure 7.
/// SBOX[x] = affine_transform(gf_inv(x))  in GF(2⁸) mod 0x11b.
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
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
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

const fn mul2(a: u8) -> u8 {
    xtime(a)
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
    mul8(a) ^ mul2(a) ^ a
}
const fn mul13(a: u8) -> u8 {
    mul8(a) ^ mul4(a) ^ a
}
const fn mul14(a: u8) -> u8 {
    mul8(a) ^ mul4(a) ^ mul2(a)
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
//           = (mul2(s) << 24) | (s << 16) | (s << 8) | mul3(s)
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
        t[i] = ((mul2(s) as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (mul3(s) as u32);
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
    (SBOX[(w >> 24) as usize] as u32) << 24
        | (SBOX[((w >> 16) & 0xff) as usize] as u32) << 16
        | (SBOX[((w >> 8) & 0xff) as usize] as u32) << 8
        | (SBOX[(w & 0xff) as usize] as u32)
}

fn expand_128(key: &[u8; 16]) -> [u32; 44] {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = sub_word(t.rotate_left(8)) ^ RCON[i / 4 - 1];
        }
        w[i] = w[i - 4] ^ t;
    }
    w
}

fn expand_192(key: &[u8; 24]) -> [u32; 52] {
    let mut w = [0u32; 52];
    for i in 0..6 {
        w[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 6..52 {
        let mut t = w[i - 1];
        if i % 6 == 0 {
            t = sub_word(t.rotate_left(8)) ^ RCON[i / 6 - 1];
        }
        w[i] = w[i - 6] ^ t;
    }
    w
}

fn expand_256(key: &[u8; 32]) -> [u32; 60] {
    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 8..60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = sub_word(t.rotate_left(8)) ^ RCON[i / 8 - 1];
        } else if i % 8 == 4 {
            t = sub_word(t);
        } // extra SubWord for 256-bit
        w[i] = w[i - 8] ^ t;
    }
    w
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
    dec_rk[0..4].copy_from_slice(&enc_rk[nr * 4..nr * 4 + 4]);
    for r in 1..nr {
        for j in 0..4 {
            dec_rk[r * 4 + j] = inv_mix_col(enc_rk[(nr - r) * 4 + j]);
        }
    }
    dec_rk[nr * 4..nr * 4 + 4].copy_from_slice(&enc_rk[0..4]);
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

fn aes_encrypt(block: &[u8; 16], rk: &[u32], nr: usize) -> [u8; 16] {
    let mut s0 = u32::from_be_bytes(block[0..4].try_into().unwrap()) ^ rk[0];
    let mut s1 = u32::from_be_bytes(block[4..8].try_into().unwrap()) ^ rk[1];
    let mut s2 = u32::from_be_bytes(block[8..12].try_into().unwrap()) ^ rk[2];
    let mut s3 = u32::from_be_bytes(block[12..16].try_into().unwrap()) ^ rk[3];

    for r in 1..nr {
        let k = 4 * r;
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

    let k = 4 * nr;
    let c0 = (SBOX[(s0 >> 24) as usize] as u32) << 24
        | (SBOX[((s1 >> 16) & 0xff) as usize] as u32) << 16
        | (SBOX[((s2 >> 8) & 0xff) as usize] as u32) << 8
        | (SBOX[(s3 & 0xff) as usize] as u32);
    let c1 = (SBOX[(s1 >> 24) as usize] as u32) << 24
        | (SBOX[((s2 >> 16) & 0xff) as usize] as u32) << 16
        | (SBOX[((s3 >> 8) & 0xff) as usize] as u32) << 8
        | (SBOX[(s0 & 0xff) as usize] as u32);
    let c2 = (SBOX[(s2 >> 24) as usize] as u32) << 24
        | (SBOX[((s3 >> 16) & 0xff) as usize] as u32) << 16
        | (SBOX[((s0 >> 8) & 0xff) as usize] as u32) << 8
        | (SBOX[(s1 & 0xff) as usize] as u32);
    let c3 = (SBOX[(s3 >> 24) as usize] as u32) << 24
        | (SBOX[((s0 >> 16) & 0xff) as usize] as u32) << 16
        | (SBOX[((s1 >> 8) & 0xff) as usize] as u32) << 8
        | (SBOX[(s2 & 0xff) as usize] as u32);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(c0 ^ rk[k]).to_be_bytes());
    out[4..8].copy_from_slice(&(c1 ^ rk[k + 1]).to_be_bytes());
    out[8..12].copy_from_slice(&(c2 ^ rk[k + 2]).to_be_bytes());
    out[12..16].copy_from_slice(&(c3 ^ rk[k + 3]).to_be_bytes());
    out
}

fn aes_decrypt(block: &[u8; 16], dk: &[u32], nr: usize) -> [u8; 16] {
    let mut s0 = u32::from_be_bytes(block[0..4].try_into().unwrap()) ^ dk[0];
    let mut s1 = u32::from_be_bytes(block[4..8].try_into().unwrap()) ^ dk[1];
    let mut s2 = u32::from_be_bytes(block[8..12].try_into().unwrap()) ^ dk[2];
    let mut s3 = u32::from_be_bytes(block[12..16].try_into().unwrap()) ^ dk[3];

    for r in 1..nr {
        let k = 4 * r;
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

    let k = 4 * nr;
    let p0 = (INV_SBOX[(s0 >> 24) as usize] as u32) << 24
        | (INV_SBOX[((s3 >> 16) & 0xff) as usize] as u32) << 16
        | (INV_SBOX[((s2 >> 8) & 0xff) as usize] as u32) << 8
        | (INV_SBOX[(s1 & 0xff) as usize] as u32);
    let p1 = (INV_SBOX[(s1 >> 24) as usize] as u32) << 24
        | (INV_SBOX[((s0 >> 16) & 0xff) as usize] as u32) << 16
        | (INV_SBOX[((s3 >> 8) & 0xff) as usize] as u32) << 8
        | (INV_SBOX[(s2 & 0xff) as usize] as u32);
    let p2 = (INV_SBOX[(s2 >> 24) as usize] as u32) << 24
        | (INV_SBOX[((s1 >> 16) & 0xff) as usize] as u32) << 16
        | (INV_SBOX[((s0 >> 8) & 0xff) as usize] as u32) << 8
        | (INV_SBOX[(s3 & 0xff) as usize] as u32);
    let p3 = (INV_SBOX[(s3 >> 24) as usize] as u32) << 24
        | (INV_SBOX[((s2 >> 16) & 0xff) as usize] as u32) << 16
        | (INV_SBOX[((s1 >> 8) & 0xff) as usize] as u32) << 8
        | (INV_SBOX[(s0 & 0xff) as usize] as u32);

    let mut out = [0u8; 16];
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
// lookups with the depth-16 Boyar-Peralta straight-line circuits from
// "A depth-16 circuit for the AES S-box" (NIST / IACR ePrint 2011/332).
// Each S-box evaluation is a fixed sequence of XOR, XNOR, and AND on eight
// 0/1 bit variables; there is no table scan and no finite-field inversion.
// ─────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn xnor(a: u8, b: u8) -> u8 {
    (a ^ b) ^ 1
}

#[inline(always)]
fn bit(input: u8, idx: u8) -> u8 {
    (input >> (7 - idx)) & 1
}

#[inline(always)]
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

#[inline(always)]
fn sbox_bool(input: u8) -> u8 {
    let u0 = bit(input, 0);
    let u1 = bit(input, 1);
    let u2 = bit(input, 2);
    let u3 = bit(input, 3);
    let u4 = bit(input, 4);
    let u5 = bit(input, 5);
    let u6 = bit(input, 6);
    let u7 = bit(input, 7);

    let t1 = u0 ^ u3;
    let t2 = u0 ^ u5;
    let t3 = u0 ^ u6;
    let t4 = u3 ^ u5;
    let t5 = u4 ^ u6;
    let t6 = t1 ^ t5;
    let t7 = u1 ^ u2;
    let t8 = u7 ^ t6;
    let t9 = u7 ^ t7;
    let t10 = t6 ^ t7;
    let t11 = u1 ^ u5;
    let t12 = u2 ^ u5;
    let t13 = t3 ^ t4;
    let t14 = t6 ^ t11;
    let t15 = t5 ^ t11;
    let t16 = t5 ^ t12;
    let t17 = t9 ^ t16;
    let t18 = u3 ^ u7;
    let t19 = t7 ^ t18;
    let t20 = t1 ^ t19;
    let t21 = u6 ^ u7;
    let t22 = t7 ^ t21;
    let t23 = t2 ^ t22;
    let t24 = t2 ^ t10;
    let t25 = t20 ^ t17;
    let t26 = t3 ^ t16;
    let t27 = t1 ^ t12;

    let m1 = t13 & t6;
    let m2 = t23 & t8;
    let m3 = t14 ^ m1;
    let m4 = t19 & u7;
    let m5 = m4 ^ m1;
    let m6 = t3 & t16;
    let m7 = t22 & t9;
    let m8 = t26 ^ m6;
    let m9 = t20 & t17;
    let m10 = m9 ^ m6;
    let m11 = t1 & t15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let m14 = t2 & t10;
    let m15 = m14 ^ m11;
    let m16 = m3 ^ m2;
    let m17 = m5 ^ t24;
    let m18 = m8 ^ m7;
    let m19 = m10 ^ m15;
    let m20 = m16 ^ m13;
    let m21 = m17 ^ m15;
    let m22 = m18 ^ m13;
    let m23 = m19 ^ t25;
    let m24 = m22 ^ m23;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m27 = m20 ^ m21;
    let m28 = m23 ^ m25;
    let m29 = m28 & m27;
    let m30 = m26 & m24;
    let m31 = m20 & m23;
    let m32 = m27 & m31;
    let m33 = m27 ^ m25;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m36 = m24 ^ m25;
    let m37 = m21 ^ m29;
    let m38 = m32 ^ m33;
    let m39 = m23 ^ m30;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m42 = m37 ^ m39;
    let m43 = m37 ^ m38;
    let m44 = m39 ^ m40;
    let m45 = m42 ^ m41;
    let m46 = m44 & t6;
    let m47 = m40 & t8;
    let m48 = m39 & u7;
    let m49 = m43 & t16;
    let m50 = m38 & t9;
    let m51 = m37 & t17;
    let m52 = m42 & t15;
    let m53 = m45 & t27;
    let m54 = m41 & t10;
    let m55 = m44 & t13;
    let m56 = m40 & t23;
    let m57 = m39 & t19;
    let m58 = m43 & t3;
    let m59 = m38 & t22;
    let m60 = m37 & t20;
    let m61 = m42 & t1;
    let m62 = m45 & t4;
    let m63 = m41 & t2;

    let l0 = m61 ^ m62;
    let l1 = m50 ^ m56;
    let l2 = m46 ^ m48;
    let l3 = m47 ^ m55;
    let l4 = m54 ^ m58;
    let l5 = m49 ^ m61;
    let l6 = m62 ^ l5;
    let l7 = m46 ^ l3;
    let l8 = m51 ^ m59;
    let l9 = m52 ^ m53;
    let l10 = m53 ^ l4;
    let l11 = m60 ^ l2;
    let l12 = m48 ^ m51;
    let l13 = m50 ^ l0;
    let l14 = m52 ^ m61;
    let l15 = m55 ^ l1;
    let l16 = m56 ^ l0;
    let l17 = m57 ^ l1;
    let l18 = m58 ^ l8;
    let l19 = m63 ^ l4;
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

#[inline(always)]
fn inv_sbox_bool(input: u8) -> u8 {
    let u0 = bit(input, 0);
    let u1 = bit(input, 1);
    let u2 = bit(input, 2);
    let u3 = bit(input, 3);
    let u4 = bit(input, 4);
    let u5 = bit(input, 5);
    let u6 = bit(input, 6);
    let u7 = bit(input, 7);

    let t23 = u0 ^ u3;
    let t22 = xnor(u1, u3);
    let t2 = xnor(u0, u1);
    let t1 = u3 ^ u4;
    let t24 = xnor(u4, u7);
    let r5 = u6 ^ u7;
    let t8 = xnor(u1, t23);
    let t19 = t22 ^ r5;
    let t9 = xnor(u7, t1);
    let t10 = t2 ^ t24;
    let t13 = t2 ^ r5;
    let t3 = t1 ^ r5;
    let t25 = xnor(u2, t1);
    let r13 = u1 ^ u6;
    let t17 = xnor(u2, t19);
    let t20 = t24 ^ r13;
    let t4 = u4 ^ t8;
    let r17 = xnor(u2, u5);
    let r18 = xnor(u5, u6);
    let r19 = xnor(u2, u4);
    let y5 = u0 ^ r17;
    let t6 = t22 ^ r17;
    let t16 = r13 ^ r19;
    let t27 = t1 ^ r18;
    let t15 = t10 ^ t27;
    let t14 = t10 ^ r18;
    let t26 = t3 ^ t16;

    let m1 = t13 & t6;
    let m2 = t23 & t8;
    let m3 = t14 ^ m1;
    let m4 = t19 & y5;
    let m5 = m4 ^ m1;
    let m6 = t3 & t16;
    let m7 = t22 & t9;
    let m8 = t26 ^ m6;
    let m9 = t20 & t17;
    let m10 = m9 ^ m6;
    let m11 = t1 & t15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let m14 = t2 & t10;
    let m15 = m14 ^ m11;
    let m16 = m3 ^ m2;
    let m17 = m5 ^ t24;
    let m18 = m8 ^ m7;
    let m19 = m10 ^ m15;
    let m20 = m16 ^ m13;
    let m21 = m17 ^ m15;
    let m22 = m18 ^ m13;
    let m23 = m19 ^ t25;
    let m24 = m22 ^ m23;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m27 = m20 ^ m21;
    let m28 = m23 ^ m25;
    let m29 = m28 & m27;
    let m30 = m26 & m24;
    let m31 = m20 & m23;
    let m32 = m27 & m31;
    let m33 = m27 ^ m25;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m36 = m24 ^ m25;
    let m37 = m21 ^ m29;
    let m38 = m32 ^ m33;
    let m39 = m23 ^ m30;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m42 = m37 ^ m39;
    let m43 = m37 ^ m38;
    let m44 = m39 ^ m40;
    let m45 = m42 ^ m41;
    let m46 = m44 & t6;
    let m47 = m40 & t8;
    let m48 = m39 & y5;
    let m49 = m43 & t16;
    let m50 = m38 & t9;
    let m51 = m37 & t17;
    let m52 = m42 & t15;
    let m53 = m45 & t27;
    let m54 = m41 & t10;
    let m55 = m44 & t13;
    let m56 = m40 & t23;
    let m57 = m39 & t19;
    let m58 = m43 & t3;
    let m59 = m38 & t22;
    let m60 = m37 & t20;
    let m61 = m42 & t1;
    let m62 = m45 & t4;
    let m63 = m41 & t2;

    let p0 = m52 ^ m61;
    let p1 = m58 ^ m59;
    let p2 = m54 ^ m62;
    let p3 = m47 ^ m50;
    let p4 = m48 ^ m56;
    let p5 = m46 ^ m51;
    let p6 = m49 ^ m60;
    let p7 = p0 ^ p1;
    let p8 = m50 ^ m53;
    let p9 = m55 ^ m63;
    let p10 = m57 ^ p4;
    let p11 = p0 ^ p3;
    let p12 = m46 ^ m48;
    let p13 = m49 ^ m51;
    let p14 = m49 ^ m62;
    let p15 = m54 ^ m59;
    let p16 = m57 ^ m61;
    let p17 = m58 ^ p2;
    let p18 = m63 ^ p5;
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

fn sub_word_bool(w: u32) -> u32 {
    (sbox_bool((w >> 24) as u8) as u32) << 24
        | (sbox_bool(((w >> 16) & 0xff) as u8) as u32) << 16
        | (sbox_bool(((w >> 8) & 0xff) as u8) as u32) << 8
        | (sbox_bool((w & 0xff) as u8) as u32)
}

fn expand_128_bool(key: &[u8; 16]) -> [u32; 44] {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = sub_word_bool(t.rotate_left(8)) ^ RCON[i / 4 - 1];
        }
        w[i] = w[i - 4] ^ t;
    }
    w
}

fn expand_192_bool(key: &[u8; 24]) -> [u32; 52] {
    let mut w = [0u32; 52];
    for i in 0..6 {
        w[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 6..52 {
        let mut t = w[i - 1];
        if i % 6 == 0 {
            t = sub_word_bool(t.rotate_left(8)) ^ RCON[i / 6 - 1];
        }
        w[i] = w[i - 6] ^ t;
    }
    w
}

fn expand_256_bool(key: &[u8; 32]) -> [u32; 60] {
    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 8..60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = sub_word_bool(t.rotate_left(8)) ^ RCON[i / 8 - 1];
        } else if i % 8 == 4 {
            t = sub_word_bool(t);
        }
        w[i] = w[i - 8] ^ t;
    }
    w
}

fn make_dec_rk_ct(enc_rk: &[u32], dec_rk: &mut [u32], nr: usize) {
    for r in 0..=nr {
        let src = (nr - r) * 4;
        let dst = r * 4;
        dec_rk[dst..dst + 4].copy_from_slice(&enc_rk[src..src + 4]);
    }
}

#[inline(always)]
fn add_round_key_ct(state: &mut [u8; 16], rk: &[u32]) {
    for c in 0..4 {
        let word = rk[c].to_be_bytes();
        for r in 0..4 {
            state[4 * c + r] ^= word[r];
        }
    }
}

#[inline(always)]
fn sub_bytes_ct(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = sbox_bool(*b);
    }
}

#[inline(always)]
fn inv_sub_bytes_ct(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = inv_sbox_bool(*b);
    }
}

#[inline(always)]
fn shift_rows_ct(state: &mut [u8; 16]) {
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

#[inline(always)]
fn inv_shift_rows_ct(state: &mut [u8; 16]) {
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

#[inline(always)]
fn mix_columns_ct(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
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

#[inline(always)]
fn inv_mix_columns_ct(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
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

fn aes_encrypt_ct(block: &[u8; 16], rk: &[u32], nr: usize) -> [u8; 16] {
    let mut state = *block;
    add_round_key_ct(&mut state, &rk[0..4]);

    for r in 1..nr {
        sub_bytes_ct(&mut state);
        shift_rows_ct(&mut state);
        mix_columns_ct(&mut state);
        add_round_key_ct(&mut state, &rk[4 * r..4 * r + 4]);
    }

    sub_bytes_ct(&mut state);
    shift_rows_ct(&mut state);
    add_round_key_ct(&mut state, &rk[4 * nr..4 * nr + 4]);
    state
}

fn aes_decrypt_ct(block: &[u8; 16], dk: &[u32], nr: usize) -> [u8; 16] {
    let mut state = *block;
    add_round_key_ct(&mut state, &dk[0..4]);

    for r in 1..nr {
        inv_shift_rows_ct(&mut state);
        inv_sub_bytes_ct(&mut state);
        add_round_key_ct(&mut state, &dk[4 * r..4 * r + 4]);
        inv_mix_columns_ct(&mut state);
    }

    inv_shift_rows_ct(&mut state);
    inv_sub_bytes_ct(&mut state);
    add_round_key_ct(&mut state, &dk[4 * nr..4 * nr + 4]);
    state
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// AES-128 cipher: 128-bit key, 10 rounds.
pub struct Aes128 {
    enc_rk: [u32; 44],
    dec_rk: [u32; 44],
}
impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let enc_rk = expand_128(key);
        let mut dec_rk = [0u32; 44];
        make_dec_rk(&enc_rk, &mut dec_rk, 10);
        Self { enc_rk, dec_rk }
    }
    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt(block, &self.enc_rk, 10)
    }
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt(block, &self.dec_rk, 10)
    }
}

/// AES-192 cipher: 192-bit key, 12 rounds.
pub struct Aes192 {
    enc_rk: [u32; 52],
    dec_rk: [u32; 52],
}
impl Aes192 {
    pub fn new(key: &[u8; 24]) -> Self {
        let enc_rk = expand_192(key);
        let mut dec_rk = [0u32; 52];
        make_dec_rk(&enc_rk, &mut dec_rk, 12);
        Self { enc_rk, dec_rk }
    }
    pub fn new_wiping(key: &mut [u8; 24]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt(block, &self.enc_rk, 12)
    }
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt(block, &self.dec_rk, 12)
    }
}

/// AES-256 cipher: 256-bit key, 14 rounds.
pub struct Aes256 {
    enc_rk: [u32; 60],
    dec_rk: [u32; 60],
}
impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let enc_rk = expand_256(key);
        let mut dec_rk = [0u32; 60];
        make_dec_rk(&enc_rk, &mut dec_rk, 14);
        Self { enc_rk, dec_rk }
    }
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt(block, &self.enc_rk, 14)
    }
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt(block, &self.dec_rk, 14)
    }
}

/// AES-128 constant-time software path.
///
/// This keeps the same external API as `Aes128`, but swaps the T-table round
/// core for a bytewise implementation whose S-box is an explicit
/// Boyar-Peralta-style boolean circuit. The separate type keeps the default
/// `Aes128` fast while still offering a software-only constant-time option.
pub struct Aes128Ct {
    enc_rk: [u32; 44],
    dec_rk: [u32; 44],
}
impl Aes128Ct {
    pub fn new(key: &[u8; 16]) -> Self {
        let enc_rk = expand_128_bool(key);
        let mut dec_rk = [0u32; 44];
        make_dec_rk_ct(&enc_rk, &mut dec_rk, 10);
        Self { enc_rk, dec_rk }
    }
    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt_ct(block, &self.enc_rk, 10)
    }
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt_ct(block, &self.dec_rk, 10)
    }
}

/// AES-192 constant-time software path.
///
/// This is the software-only constant-time counterpart to `Aes192`, using the
/// same Boyar-Peralta-style boolean S-box strategy as `Aes128Ct`.
pub struct Aes192Ct {
    enc_rk: [u32; 52],
    dec_rk: [u32; 52],
}
impl Aes192Ct {
    pub fn new(key: &[u8; 24]) -> Self {
        let enc_rk = expand_192_bool(key);
        let mut dec_rk = [0u32; 52];
        make_dec_rk_ct(&enc_rk, &mut dec_rk, 12);
        Self { enc_rk, dec_rk }
    }
    pub fn new_wiping(key: &mut [u8; 24]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt_ct(block, &self.enc_rk, 12)
    }
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt_ct(block, &self.dec_rk, 12)
    }
}

/// AES-256 constant-time software path.
///
/// This is the software-only constant-time counterpart to `Aes256`, using the
/// same Boyar-Peralta-style boolean S-box strategy as `Aes128Ct`.
pub struct Aes256Ct {
    enc_rk: [u32; 60],
    dec_rk: [u32; 60],
}
impl Aes256Ct {
    pub fn new(key: &[u8; 32]) -> Self {
        let enc_rk = expand_256_bool(key);
        let mut dec_rk = [0u32; 60];
        make_dec_rk_ct(&enc_rk, &mut dec_rk, 14);
        Self { enc_rk, dec_rk }
    }
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt_ct(block, &self.enc_rk, 14)
    }
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt_ct(block, &self.dec_rk, 14)
    }
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
// Tests — NIST CAVP KAT_AES vectors (CAVS 11.1, csrc.nist.gov)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    fn kat128(key: &str, pt: &str, ct: &str) {
        let c = Aes128::new(&parse(key));
        assert_eq!(
            c.encrypt_block(&parse(pt)),
            parse::<16>(ct),
            "enc {key}/{pt}"
        );
        assert_eq!(
            c.decrypt_block(&parse(ct)),
            parse::<16>(pt),
            "dec {key}/{ct}"
        );
    }
    fn kat192(key: &str, pt: &str, ct: &str) {
        let c = Aes192::new(&parse(key));
        assert_eq!(
            c.encrypt_block(&parse(pt)),
            parse::<16>(ct),
            "enc {key}/{pt}"
        );
        assert_eq!(
            c.decrypt_block(&parse(ct)),
            parse::<16>(pt),
            "dec {key}/{ct}"
        );
    }
    fn kat256(key: &str, pt: &str, ct: &str) {
        let c = Aes256::new(&parse(key));
        assert_eq!(
            c.encrypt_block(&parse(pt)),
            parse::<16>(ct),
            "enc {key}/{pt}"
        );
        assert_eq!(
            c.decrypt_block(&parse(ct)),
            parse::<16>(pt),
            "dec {key}/{ct}"
        );
    }

    #[test]
    fn bool_sbox_matches_tables() {
        for x in 0u16..=255 {
            let b = x as u8;
            assert_eq!(sbox_bool(b), SBOX[x as usize], "sbox {x:02x}");
            assert_eq!(inv_sbox_bool(b), INV_SBOX[x as usize], "inv_sbox {x:02x}");
        }
    }

    #[test]
    fn ct_128_kat() {
        let key = parse::<16>("00000000000000000000000000000000");
        let pt = parse::<16>("f34481ec3cc627bacd5dc3fb08f273e6");
        let ct = parse::<16>("0336763e966d92595a567cc9ce537f5e");
        let fast = Aes128::new(&key);
        let slow = Aes128Ct::new(&key);
        assert_eq!(slow.encrypt_block(&pt), ct);
        assert_eq!(slow.decrypt_block(&ct), pt);
        assert_eq!(slow.encrypt_block(&pt), fast.encrypt_block(&pt));
    }

    #[test]
    fn ct_192_kat() {
        let key = parse::<24>("000000000000000000000000000000000000000000000000");
        let pt = parse::<16>("1b077a6af4b7f98229de786d7516b639");
        let ct = parse::<16>("275cfc0413d8ccb70513c3859b1d0f72");
        let fast = Aes192::new(&key);
        let slow = Aes192Ct::new(&key);
        assert_eq!(slow.encrypt_block(&pt), ct);
        assert_eq!(slow.decrypt_block(&ct), pt);
        assert_eq!(slow.encrypt_block(&pt), fast.encrypt_block(&pt));
    }

    #[test]
    fn ct_256_kat() {
        let key = parse::<32>("0000000000000000000000000000000000000000000000000000000000000000");
        let pt = parse::<16>("014730f80ac625fe84f026c60bfd547d");
        let ct = parse::<16>("5c9d844ed46f9885085e5d6a4f94c7d7");
        let fast = Aes256::new(&key);
        let slow = Aes256Ct::new(&key);
        assert_eq!(slow.encrypt_block(&pt), ct);
        assert_eq!(slow.decrypt_block(&ct), pt);
        assert_eq!(slow.encrypt_block(&pt), fast.encrypt_block(&pt));
    }

    // ── ECBGFSbox: key=0, plaintext chosen to stress the S-box ───────────────
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
    #[test]
    fn keysbox_128() {
        let v = [
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
        for (k, p, c) in v {
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

    // ── ECBVarKey: one bit set in key, zero plaintext ─────────────────────────
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

    // ── ECBVarTxt: zero key, one bit set in plaintext ─────────────────────────
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

    // ── Compile-time table spot-checks (verify GF arithmetic) ────────────────
    #[test]
    fn te0_spot_check() {
        // SBOX[0]=0x63; mul2(0x63)=0xc6; mul3(0x63)=0xc6^0x63=0xa5
        // TE0[0] = 0xc6_63_63_a5
        assert_eq!(TE0[0], 0xc66363a5);
        // SBOX[1]=0x7c; mul2(0x7c)=0xf8; mul3(0x7c)=0xf8^0x7c=0x84
        assert_eq!(TE0[1], 0xf87c7c84);
    }

    #[test]
    fn td0_spot_check() {
        // INV_SBOX[0]=0x52; mul14=0x51, mul9=0xf4, mul13=0xa7, mul11=0x50
        assert_eq!(TD0[0], 0x51f4a750);
    }
}
