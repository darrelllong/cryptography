//! DES and Triple-DES (TDEA) implemented from FIPS PUB 46-3 and NIST SP
//! 800-67 Rev. 2.
//!
//! All tables are transcribed verbatim from the FIPS 46-3 document
//! (<https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf>).
//!
//! # Status of the algorithms
//!
//! Single DES is not an approved algorithm: FIPS 46-3 was withdrawn on 19 May
//! 2005 (Federal Register 70 FR 28907), and SP 800-131A Rev. 2 § 2 lists no
//! use of it. `Des` and `DesCt` exist as the primitive inside TDEA and for
//! interoperating with legacy data; they refuse the weak and semi-weak keys
//! (see [`is_weak_or_semi_weak_key`] for exactly which) and nothing else.
//!
//! TDEA is on its way out too. SP 800-131A Rev. 2 (March 2019) § 2.1:
//! three-key TDEA encryption was deprecated through 2023 and is disallowed
//! after 31 December 2023; two-key TDEA encryption is disallowed; decryption
//! of either is legacy use. SP 800-67 Rev. 2 § 3.1 also limits a key bundle
//! to 2^20 64-bit blocks. `TripleDes` and `TripleDesCt` build keying options
//! 1 (3TDEA) and 2 (2TDEA) of SP 800-67 Rev. 2 § 3.1 and refuse the
//! degenerate bundles those options exclude; keying option 3 of SP 800-67
//! Rev. 1 (K1 = K2 = K3, plain DES) was withdrawn in Rev. 2 and is not
//! constructible through the public API.
//!
//! # Paths
//!
//! `Des` and `TripleDes` are the fast byte-table and fused `SP_TABLE`
//! software path, variable-time because the table indices are the secret
//! round state. `DesCt` and `TripleDesCt` replace the secret-indexed round
//! function with loop-based permutations and packed ANF evaluation of the DES
//! S-boxes (`sbox_ct`, checked exhaustively against `SBOXES`). Both TDEA
//! types report their keying option through `mode()`.
//!
//! # Tests
//!
//! Known answers are, each named at its use: the NIST CAVP `KAT_TDES.zip`
//! tables (CAVS 11.1, 2011-04-21, from csrc.nist.gov: TECBvartext,
//! TECBinvperm, TECBvarkey, TECBpermop, TECBsubtab, whose "KEYs" bundles
//! are K1 = K2 = K3); the worked 3TDEA example of SP 800-67 Rev. 2 Appendix
//! B; and the installed `openssl` tool as a black-box oracle. The remaining
//! tests are differential (fast against `Ct`) or check the key screens.

// ─────────────────────────────────────────────────────────────────────────────
// Widths FIPS 46-3 and SP 800-67 Rev. 2 fix
// ─────────────────────────────────────────────────────────────────────────────

/// DES enciphers a 64-bit block under a 64-bit key, eight of whose bits are
/// parity (FIPS 46-3 §1 and Appendix A).
const BLOCK_BYTES: usize = 8;
const KEY_BYTES: usize = BLOCK_BYTES;
const BYTE_BITS: usize = 8;
const BLOCK_BITS: usize = BYTE_BITS * BLOCK_BYTES;

/// The Feistel halves L and R (FIPS 46-3 §"Enciphering").
const HALF_BITS: usize = BLOCK_BITS / 2;

/// E expands R to 48 bits, which PC-2 also selects for a subkey; PC-1 keeps
/// the 56 key bits that carry no parity.
const EXPANDED_BITS: usize = 48;
const SUBKEY_BITS: usize = EXPANDED_BITS;
const KEY_BITS_AFTER_PC1: usize = 56;

/// C and D, the halves of the PC-1 output that the schedule rotates.
const CD_HALF_BITS: usize = KEY_BITS_AFTER_PC1 / 2;

/// Sixteen rounds, each with its own subkey (FIPS 46-3 §"Enciphering").
const ROUNDS: usize = 16;

/// The eight S-boxes take six bits and give four (FIPS 46-3 Appendix 1).
const SBOX_COUNT: usize = 8;
const SBOX_INPUT_BITS: usize = 6;
const SBOX_OUTPUT_BITS: usize = 4;
const SBOX_INPUTS: usize = 1 << SBOX_INPUT_BITS;

/// The keying options of SP 800-67 Rev. 2 §3.1: a three-key and a two-key
/// bundle of DES keys.
const TDEA3_KEY_BYTES: usize = 3 * KEY_BYTES;
const TDEA2_KEY_BYTES: usize = 2 * KEY_BYTES;

// ─────────────────────────────────────────────────────────────────────────────
// FIPS 46-3 Tables (1-indexed positions, converted to 0-indexed in code)
// ─────────────────────────────────────────────────────────────────────────────

/// Initial Permutation (IP) — FIPS 46-3, Table "Initial Permutation IP"
/// Entry i gives the 1-indexed bit position in the 64-bit input whose value
/// becomes bit i of the output (MSB = bit 1).
const IP: [u8; BLOCK_BITS] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final Permutation (IP⁻¹) — FIPS 46-3, Table "Inverse Initial Permutation IP⁻¹"
const FP: [u8; BLOCK_BITS] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansion function E — FIPS 46-3, Table "Expansion Permutation E"
/// Maps the 32-bit right half to 48 bits.
const E: [u8; EXPANDED_BITS] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// Permutation P — FIPS 46-3, Table "Permutation Function P"
/// Applied to the 32-bit output of the 8 S-boxes.
const P: [u8; HALF_BITS] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

/// Permuted Choice 1 (PC-1) — FIPS 46-3, Table "Permuted Choice 1 (PC-1)"
/// Selects and permutes 56 bits of the 64-bit key (discards parity bits).
/// First 28 entries select bits for C0, next 28 for D0.
const PC1: [u8; KEY_BITS_AFTER_PC1] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// Permuted Choice 2 (PC-2) — FIPS 46-3, Table "Permuted Choice 2 (PC-2)"
/// Selects 48 bits from the 56-bit shifted key halves to form each round key.
const PC2: [u8; SUBKEY_BITS] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Key schedule rotation amounts — FIPS 46-3, Table "Number of Bit Rotations"
/// Number of left-circular shifts applied to each key half in rounds 1–16.
const SHIFTS: [u8; ROUNDS] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// S-boxes S1–S8 — FIPS 46-3, Tables "Selection Functions S1–S8"
///
/// Each S-box maps a 6-bit input to a 4-bit output.  The 6 input bits b1..b6
/// (where b1 is MSB of the 6-bit value) select row r = (b1<<1)|b6 and
/// column c = b2..b5.
const SBOXES: [[u8; SBOX_INPUTS]; SBOX_COUNT] = [
    // S1
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    // S2
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    // S3
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    // S4
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    // S5
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    // S6
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    // S7
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    // S8
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Build packed ANF coefficients for `DesCt`: 64-bit monomial masks per output
/// bit, one mask per S-box.  Runtime evaluates via subset-mask intersection and
/// parity, avoiding secret-indexed S-box lookups entirely.
const fn build_sbox_anf() -> [[u64; SBOX_OUTPUT_BITS]; SBOX_COUNT] {
    let mut out = [[0u64; SBOX_OUTPUT_BITS]; SBOX_COUNT];
    let mut sbox_idx = 0usize;
    while sbox_idx < SBOX_COUNT {
        let mut bit_idx = 0usize;
        while bit_idx < SBOX_OUTPUT_BITS {
            let mut coeffs = [0u8; SBOX_INPUTS];
            let mut x = 0usize;
            while x < SBOX_INPUTS {
                let row = ((x & 0x20) >> 4) | (x & 0x01);
                let col = (x >> 1) & 0x0f;
                coeffs[x] = (SBOXES[sbox_idx][row * 16 + col] >> bit_idx) & 1;
                x += 1;
            }

            let mut var = 0usize;
            while var < SBOX_INPUT_BITS {
                let stride = 1usize << var;
                let mut mask = 0usize;
                while mask < SBOX_INPUTS {
                    if mask & stride != 0 {
                        coeffs[mask] ^= coeffs[mask ^ stride];
                    }
                    mask += 1;
                }
                var += 1;
            }

            let mut packed = 0u64;
            let mut monomial = 0usize;
            while monomial < 64 {
                packed |= (coeffs[monomial] as u64) << monomial;
                monomial += 1;
            }
            out[sbox_idx][bit_idx] = packed;
            bit_idx += 1;
        }
        sbox_idx += 1;
    }
    out
}

const SBOX_ANF: [[u64; SBOX_OUTPUT_BITS]; SBOX_COUNT] = build_sbox_anf();

// ─────────────────────────────────────────────────────────────────────────────
// Byte-level precomputed permutation tables (used by `Des`, not `DesCt`)
//
// table[byte_idx][byte_val] = that byte's contribution to the permuted output.
// OR-ing all eight byte contributions gives the full result.
// ─────────────────────────────────────────────────────────────────────────────

const fn build_perm64(perm: &[u8; BLOCK_BITS]) -> [[u64; 256]; BLOCK_BYTES] {
    let mut table = [[0u64; 256]; BLOCK_BYTES];
    let mut i = 0usize;
    while i < BLOCK_BITS {
        let src = (perm[i] - 1) as usize; // 0-indexed (0 = MSB of u64)
        let src_byte = src / BYTE_BITS;
        let src_bit = src % BYTE_BITS; // 0 = MSB of that byte
        let out_bit = BLOCK_BITS - 1 - i;
        let mut v = 0usize;
        while v < 256 {
            if (v >> (7 - src_bit)) & 1 == 1 {
                table[src_byte][v] |= 1u64 << out_bit;
            }
            v += 1;
        }
        i += 1;
    }
    table
}

const fn build_perm_e(perm: &[u8; EXPANDED_BITS]) -> [[u64; 256]; HALF_BITS / BYTE_BITS] {
    let mut table = [[0u64; 256]; HALF_BITS / BYTE_BITS];
    let mut i = 0usize;
    while i < EXPANDED_BITS {
        let src = (perm[i] - 1) as usize; // 0-indexed (0 = MSB of 32-bit R)
        let src_byte = src / BYTE_BITS;
        let src_bit = src % BYTE_BITS;
        let out_bit = EXPANDED_BITS - 1 - i;
        let mut v = 0usize;
        while v < 256 {
            if (v >> (7 - src_bit)) & 1 == 1 {
                table[src_byte][v] |= 1u64 << out_bit;
            }
            v += 1;
        }
        i += 1;
    }
    table
}

/// Apply the P permutation to a (possibly sparse) 32-bit S-output word.
///
/// Used at compile time to build the fused S+P table, and at runtime by the
/// constant-time f-function (`f_ct`) on the secret S-box output. The bit move
/// is written branch-free — no `if` on secret data — so the runtime use never
/// conditions control flow on `s`.
const fn apply_p_to_partial(s: u32) -> u32 {
    let mut out = 0u32;
    let mut i = 0u32;
    while i < HALF_BITS as u32 {
        // P[i] is the 1-indexed FIPS source bit for output FIPS bit (i+1).
        // FIPS bit k ↔ u32 bit (32−k).
        let src_bit = HALF_BITS as u32 - P[i as usize] as u32; // 0 = LSB
        let dst_bit = HALF_BITS as u32 - 1 - i;
        out |= ((s >> src_bit) & 1) << dst_bit;
        i += 1;
    }
    out
}

/// Build the fused S+P table: 8 S-boxes × 64 inputs → P-permuted u32 contribution.
///
/// `SP_TABLE`[i][b6] = `P(S_i(b6)` placed at bits [28−4i .. 31−4i] of the 32-bit word).
/// Since P is a linear permutation, P(s0|s1|…|s7) = P(s0)|P(s1)|…|P(s7),
/// so OR-ing all 8 entries gives the correct f-function output.
/// Reduces 8 S-box + 4 P byte-table lookups per round to 8 SP lookups.
const fn build_sp() -> [[u32; 64]; 8] {
    let mut sp = [[0u32; 64]; 8];
    let mut i = 0u32;
    while i < 8 {
        let mut j = 0usize; // raw 6-bit input b6
        while j < 64 {
            let row = ((j & 0x20) >> 4) | (j & 0x01); // bits 5 and 0
            let col = (j >> 1) & 0x0F; // bits 4..1
            let sval = SBOXES[i as usize][row * 16 + col] as u32;
            // S-box i places its 4-bit output at u32 bits [28−4i .. 31−4i].
            let partial = sval << (28u32 - 4 * i);
            sp[i as usize][j] = apply_p_to_partial(partial);
            j += 1;
        }
        i += 1;
    }
    sp
}

static IP_TABLE: [[u64; 256]; 8] = build_perm64(&IP);
static FP_TABLE: [[u64; 256]; 8] = build_perm64(&FP);
static E_TABLE: [[u64; 256]; 4] = build_perm_e(&E);
static SP_TABLE: [[u32; 64]; 8] = build_sp();

#[inline]
fn fast_perm64(x: u64, t: &[[u64; 256]; BLOCK_BYTES]) -> u64 {
    t[0][(x >> 56) as usize]
        | t[1][((x >> 48) & 0xff) as usize]
        | t[2][((x >> 40) & 0xff) as usize]
        | t[3][((x >> 32) & 0xff) as usize]
        | t[4][((x >> 24) & 0xff) as usize]
        | t[5][((x >> 16) & 0xff) as usize]
        | t[6][((x >> 8) & 0xff) as usize]
        | t[7][(x & 0xff) as usize]
}

#[inline]
fn fast_expand(r: u32, t: &[[u64; 256]; HALF_BITS / BYTE_BITS]) -> u64 {
    t[0][(r >> 24) as usize]
        | t[1][((r >> 16) & 0xff) as usize]
        | t[2][((r >> 8) & 0xff) as usize]
        | t[3][(r & 0xff) as usize]
}

// ─────────────────────────────────────────────────────────────────────────────
// Bit-manipulation helpers  (used only by key_schedule — not in the hot path)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract bit `pos` (1-indexed, MSB = 1) from a 64-bit big-endian block.
#[inline]
fn bit64(block: u64, pos: u8) -> u64 {
    (block >> (64 - pos)) & 1
}

/// Apply a permutation table to a 64-bit block.
/// Each entry in `table` is a 1-indexed source bit position.
fn permute64(input: u64, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for (i, &src) in table.iter().enumerate() {
        out |= bit64(input, src) << (table.len() - 1 - i);
    }
    out
}

#[inline]
fn rotate_left(val: u32, n: u8, bits: u8) -> u32 {
    let mask = (1u32 << bits) - 1;
    ((val << n) | (val >> (bits - n))) & mask
}

// ─────────────────────────────────────────────────────────────────────────────
// Key schedule
// ─────────────────────────────────────────────────────────────────────────────

/// A 16-round DES key schedule: 16 × 48-bit subkeys.
pub type KeySchedule = [u64; ROUNDS];

/// Generate the key schedule from a 64-bit key (including parity bits).
/// Returns 16 subkeys, each 48 bits (stored in the low 48 bits of u64).
///
/// For decryption, pass the returned schedule reversed to the block
/// function (`Des::decrypt` does this internally).
#[must_use]
pub fn key_schedule(mut key: u64) -> KeySchedule {
    // PC-1: select and permute 56 bits.
    // The first 28 bits of pc1_out form C0, the next 28 bits form D0.
    let mut pc1_out = permute64(key, &PC1);

    let mut c_bytes = ((pc1_out >> CD_HALF_BITS) & 0x0FFF_FFFF).to_be_bytes();
    let mut d_bytes = (pc1_out & 0x0FFF_FFFF).to_be_bytes();
    let mut c = u32::from_be_bytes([c_bytes[4], c_bytes[5], c_bytes[6], c_bytes[7]]); // bits 1-28 → C0
    let mut d = u32::from_be_bytes([d_bytes[4], d_bytes[5], d_bytes[6], d_bytes[7]]); // bits 29-56 → D0

    let mut schedule = [0u64; ROUNDS];
    let mut cd_shifted = 0u64;
    for i in 0..ROUNDS {
        c = rotate_left(c, SHIFTS[i], CD_HALF_BITS as u8);
        d = rotate_left(d, SHIFTS[i], CD_HALF_BITS as u8);

        // Merge C and D into a 56-bit value for PC-2 selection.
        // C occupies the upper 28 bits; D the lower 28.
        //
        // PC-2 references bit positions 1–56 within the 56-bit CD register.
        // We represent CD as a 64-bit value with the 56 bits in the MSBs
        // (i.e., shifted left by 8 so that position 1 in the FIPS table
        //  corresponds to bit 63 of our u64).
        cd_shifted = ((u64::from(c) << CD_HALF_BITS) | u64::from(d)) << BYTE_BITS;
        schedule[i] = permute64(cd_shifted, &PC2);
    }

    // The sixteen shifts total 28, so C16 = C0 and D16 = D0: the registers end
    // as the PC-1 key bits themselves. Wipe them, their byte forms, and this
    // function's copy of the key; only the subkeys leave.
    crate::ct::zeroize_slice(c_bytes.as_mut_slice());
    crate::ct::zeroize_slice(d_bytes.as_mut_slice());
    for word in [&mut key, &mut pc1_out, &mut cd_shifted] {
        crate::ct::zeroize_slice(core::slice::from_mut(word));
    }
    for half in [&mut c, &mut d] {
        crate::ct::zeroize_slice(core::slice::from_mut(half));
    }
    schedule
}

// ─────────────────────────────────────────────────────────────────────────────
// The Feistel f-function
// ─────────────────────────────────────────────────────────────────────────────

/// The DES f-function: f(R, K) = P(S(E(R) ⊕ K))
fn f(r: u32, subkey: u64) -> u32 {
    let xored = fast_expand(r, &E_TABLE) ^ subkey;

    let mut result = 0u32;
    for (i, sp_row) in SP_TABLE.iter().enumerate() {
        let shift = EXPANDED_BITS - SBOX_INPUT_BITS * (i + 1);
        let b6 = ((xored >> shift) & 0x3F) as usize;
        result |= sp_row[b6];
    }
    result
}

#[inline]
fn subset_mask6(x: u8) -> u64 {
    // Expand one 6-bit input into the set of all active monomials in
    // {1, x0, x1, ..., x0x1, ...}. Bit i decides whether the current mask is
    // duplicated with xi included. The final 64-bit value is indexed by the
    // monomial bitmask itself.
    let mut mask = 1u64;

    let bit0 = 0u64.wrapping_sub(u64::from(x & 1));
    mask |= (mask << 1) & bit0;

    let bit1 = 0u64.wrapping_sub(u64::from((x >> 1) & 1));
    mask |= (mask << 2) & bit1;

    let bit2 = 0u64.wrapping_sub(u64::from((x >> 2) & 1));
    mask |= (mask << 4) & bit2;

    let bit3 = 0u64.wrapping_sub(u64::from((x >> 3) & 1));
    mask |= (mask << 8) & bit3;

    let bit4 = 0u64.wrapping_sub(u64::from((x >> 4) & 1));
    mask |= (mask << 16) & bit4;

    let bit5 = 0u64.wrapping_sub(u64::from((x >> 5) & 1));
    mask |= (mask << 32) & bit5;

    mask
}

#[inline]
fn parity64(mut x: u64) -> u8 {
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    let nibble = u16::try_from(x).expect("masked parity nibble fits in u16");
    u8::try_from((0x6996u16 >> nibble) & 1).expect("parity bit fits in u8")
}

/// Evaluate one DES S-box from the packed ANF representation.
///
/// `subset_mask6` expands the active input monomials for this 6-bit input, and
/// each packed coefficient mask selects which monomials contribute to one
/// output bit. Taking parity of the intersection is exactly "sum the selected
/// ANF terms modulo 2".
#[inline]
fn sbox_ct(sbox_idx: usize, input: u8) -> u8 {
    let active = subset_mask6(input);
    let coeffs = &SBOX_ANF[sbox_idx];
    parity64(active & coeffs[0])
        | (parity64(active & coeffs[1]) << 1)
        | (parity64(active & coeffs[2]) << 2)
        | (parity64(active & coeffs[3]) << 3)
}

/// Constant-time DES f-function: same E / XOR-K / S / P steps as the fast
/// path, but S-boxes are evaluated via ANF and permutations via fixed loops
/// rather than secret-indexed byte tables.
fn f_ct(r: u32, subkey: u64) -> u32 {
    let mut expanded = 0u64;
    for (i, &src) in E.iter().enumerate() {
        let bit = u64::from((r >> (32 - src)) & 1);
        expanded |= bit << (47 - i);
    }
    let xored = expanded ^ subkey;

    let mut pre_p = 0u32;
    for i in 0..8usize {
        let shift = EXPANDED_BITS - SBOX_INPUT_BITS * (i + 1);
        let b6 = ((xored >> shift) & 0x3f) as u8;
        let sval = u32::from(sbox_ct(i, b6));
        pre_p |= sval << (28 - 4 * i);
    }

    apply_p_to_partial(pre_p)
}

// ─────────────────────────────────────────────────────────────────────────────
// DES single-block encrypt/decrypt
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt or decrypt a single 64-bit block under the given key schedule.
///
/// For encryption, pass `schedule` from [`key_schedule`].
/// For decryption, pass the schedule reversed: `let dec = { let mut s = ks; s.reverse(); s }`.
fn des_block(block: u64, schedule: &KeySchedule) -> u64 {
    let permuted = fast_perm64(block, &IP_TABLE);

    let mut l = u32::try_from((permuted >> 32) & 0xFFFF_FFFF).expect("upper DES half fits in u32");
    let mut r = u32::try_from(permuted & 0xFFFF_FFFF).expect("lower DES half fits in u32");

    for &subkey in schedule {
        let tmp = r;
        r = l ^ f(r, subkey);
        l = tmp;
    }

    // Pre-output: swap L and R, then apply FP via precomputed byte-table.
    let pre_output = (u64::from(r) << 32) | u64::from(l);
    fast_perm64(pre_output, &FP_TABLE)
}

fn des_block_ct(block: u64, schedule: &KeySchedule) -> u64 {
    let permuted = permute64(block, &IP);

    let mut l = u32::try_from((permuted >> 32) & 0xFFFF_FFFF).expect("upper DES half fits in u32");
    let mut r = u32::try_from(permuted & 0xFFFF_FFFF).expect("lower DES half fits in u32");

    for &subkey in schedule {
        let tmp = r;
        r = l ^ f_ct(r, subkey);
        l = tmp;
    }

    let pre_output = (u64::from(r) << 32) | u64::from(l);
    permute64(pre_output, &FP)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public DES interface
// ─────────────────────────────────────────────────────────────────────────────

/// A DES cipher keyed with a single 64-bit key (including parity bits).
pub struct Des {
    enc_schedule: KeySchedule,
    dec_schedule: KeySchedule,
}

/// A software-only constant-time DES path.
///
/// `DesCt` avoids the fast path's secret-indexed permutation and S-box tables.
/// Instead it keeps the same key schedule but evaluates IP/FP/E with fixed
/// loops and evaluates each S-box through the packed ANF bitset form above.
pub struct DesCt {
    enc_schedule: KeySchedule,
    dec_schedule: KeySchedule,
}

/// Error returned when a DES/TDEA constructor rejects key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesKeyError {
    /// The provided DES key is one of the four weak or twelve semi-weak keys
    /// (SP 800-67 Rev. 2 § 3.3.2); see [`is_weak_or_semi_weak_key`].
    WeakOrSemiWeakKey,
    /// Two TDEA key components carry the same 56 key bits (parity ignored),
    /// so the keying option would silently collapse: SP 800-67 §3.1 requires
    /// K1 ≠ K2 ≠ K3 for 3TDEA and K1 ≠ K2 for 2TDEA.
    RepeatedKeyComponent,
}

/// The four weak DES keys (SP 800-67 Rev. 2 § 3.3.2, first table), written
/// with odd parity as the standard prints them.
const WEAK_KEYS: [[u8; KEY_BYTES]; 4] = [
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
];

/// The six semi-weak DES key pairs (SP 800-67 Rev. 2 § 3.3.2, second table),
/// written with odd parity as the standard prints them.
const SEMI_WEAK_KEY_PAIRS: [([u8; KEY_BYTES], [u8; KEY_BYTES]); 6] = [
    (
        [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
        [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    ),
    (
        [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
        [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    ),
    (
        [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
        [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    ),
    (
        [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
        [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    ),
    (
        [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
        [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    ),
    (
        [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
        [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
    ),
];

#[inline]
fn strip_parity_bits(key: &[u8; KEY_BYTES]) -> [u8; KEY_BYTES] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = key[i] & 0xFE;
    }
    out
}

/// Return `true` when `key` is one of the four weak or twelve semi-weak DES
/// keys of SP 800-67 Rev. 2 § 3.3.2.
///
/// The parity bits are ignored, so every byte string that carries the 56 key
/// bits of a listed key is caught, whatever parity it was written with. The
/// scope is exactly those sixteen keys: the 48 "possibly weak" keys of FIPS
/// 74 (whose schedules contain only four distinct subkeys) are not screened,
/// and no other key-quality check is made.
///
/// The comparison against every listed key is accumulated without
/// short-circuiting, so the running time does not depend on how many leading
/// bytes of the secret key match a pattern.
#[must_use]
pub fn is_weak_or_semi_weak_key(key: &[u8; KEY_BYTES]) -> bool {
    let mut normalized = strip_parity_bits(key);
    let mut hit = 0u8;
    for wk in WEAK_KEYS.iter() {
        hit |= crate::ct::constant_time_eq_mask(&strip_parity_bits(wk), &normalized);
    }
    for (a, b) in SEMI_WEAK_KEY_PAIRS.iter() {
        hit |= crate::ct::constant_time_eq_mask(&strip_parity_bits(a), &normalized);
        hit |= crate::ct::constant_time_eq_mask(&strip_parity_bits(b), &normalized);
    }
    // `normalized` is the caller's key with only the parity bits cleared.
    crate::ct::zeroize_slice(normalized.as_mut_slice());
    hit != 0
}

impl Des {
    /// Create a new DES instance from an 8-byte key.
    pub fn new(key: &[u8; KEY_BYTES]) -> Result<Self, DesKeyError> {
        if is_weak_or_semi_weak_key(key) {
            return Err(DesKeyError::WeakOrSemiWeakKey);
        }
        Ok(Self::new_unchecked(key))
    }

    /// Create DES from an 8-byte key without the weak-key screen.
    ///
    /// Crate-internal: [`new`](Self::new) calls it after screening, and the
    /// CAVP tables (whose keys include the weak key `01..01`) are run through
    /// it in this module's tests.
    #[must_use]
    pub(crate) fn new_unchecked(key: &[u8; KEY_BYTES]) -> Self {
        // Both schedules are written straight into the struct, and the key's
        // integer form is wiped once they exist.
        let mut k = u64::from_be_bytes(*key);
        let mut cipher = Des {
            enc_schedule: key_schedule(k),
            dec_schedule: [0u64; 16],
        };
        cipher.dec_schedule = cipher.enc_schedule;
        cipher.dec_schedule.reverse();
        crate::ct::zeroize_slice(core::slice::from_mut(&mut k));
        cipher
    }

    /// Create a new DES instance and wipe the provided key buffer.
    pub fn new_wiping(key: &mut [u8; KEY_BYTES]) -> Result<Self, DesKeyError> {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt a single 64-bit block (ECB mode).
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        let b = u64::from_be_bytes(*block);
        des_block(b, &self.enc_schedule).to_be_bytes()
    }

    /// Decrypt a single 64-bit block (ECB mode).
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        let b = u64::from_be_bytes(*block);
        des_block(b, &self.dec_schedule).to_be_bytes()
    }
}

impl DesCt {
    /// Create a new constant-time DES instance from an 8-byte key.
    pub fn new(key: &[u8; KEY_BYTES]) -> Result<Self, DesKeyError> {
        if is_weak_or_semi_weak_key(key) {
            return Err(DesKeyError::WeakOrSemiWeakKey);
        }
        Ok(Self::new_unchecked(key))
    }

    /// Create constant-time DES from an 8-byte key without the weak-key
    /// screen; crate-internal, as [`Des::new_unchecked`] is.
    #[must_use]
    pub(crate) fn new_unchecked(key: &[u8; KEY_BYTES]) -> Self {
        let mut k = u64::from_be_bytes(*key);
        let mut cipher = DesCt {
            enc_schedule: key_schedule(k),
            dec_schedule: [0u64; 16],
        };
        cipher.dec_schedule = cipher.enc_schedule;
        cipher.dec_schedule.reverse();
        crate::ct::zeroize_slice(core::slice::from_mut(&mut k));
        cipher
    }

    /// Create a new constant-time DES instance and wipe the provided key buffer.
    pub fn new_wiping(key: &mut [u8; KEY_BYTES]) -> Result<Self, DesKeyError> {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt a single 64-bit block (ECB mode).
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        let b = u64::from_be_bytes(*block);
        des_block_ct(b, &self.enc_schedule).to_be_bytes()
    }

    /// Decrypt a single 64-bit block (ECB mode).
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        let b = u64::from_be_bytes(*block);
        des_block_ct(b, &self.dec_schedule).to_be_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Triple-DES (TDEA) — FIPS 46-3 §4, NIST SP 800-67 Rev. 2
// ─────────────────────────────────────────────────────────────────────────────
//
// TDEA operates as EDE (Encrypt-Decrypt-Encrypt), SP 800-67 Rev. 2 §3.2:
//   Encrypt:  C = E(K3, D(K2, E(K1, P)))
//   Decrypt:  P = D(K1, E(K2, D(K3, C)))
//
// Keying options (SP 800-67 Rev. 2 §3.1):
//   Option 1 (3TDEA): K1, K2, K3 independent — 168 key bits, 112-bit strength
//   Option 2 (2TDEA): K1 = K3 ≠ K2           — 112 key bits, 80-bit strength
//   Keying option 3 of Rev. 1 (K1 = K2 = K3, plain DES) was withdrawn in
//   Rev. 2. It is not constructible through the public API; the test-only
//   `new_single_key*` constructors build it for the CAVP "KEYs" tables.
//
// `new_3key` and `new_2key` reject a repeated component (compared with the
// parity bits stripped): 3TDEA with K1 = K3 is really 2TDEA, and either
// option with K1 = K2 is really single DES, so accepting such keys would
// silently downgrade the security strength the caller asked for.
//
// The NIST CAVP KAT_TDES tables use "KEYs = <hex>" meaning K1 = K2 = K3, which
// exercises the EDE path with a single key: E(K, D(K, E(K, P))) = E(K, P),
// since D∘E is the identity under one key.

/// Keying option for Triple-DES (NIST SP 800-67 §3.1).
///
/// Reported by [`TripleDes::mode`] and [`TripleDesCt::mode`] so callers that
/// need the effective security strength (112 bits for 3TDEA, 80 bits for
/// 2TDEA, 56 bits for the single-key degenerate case) can ask the cipher
/// instead of remembering which constructor built it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TDesMode {
    /// Keying option 1 (3TDEA): K1, K2, K3 mutually distinct (24-byte key).
    ThreeKey,
    /// Keying option 2 (2TDEA): K1 = K3 ≠ K2 (16-byte key K1 ∥ K2).
    TwoKey,
    /// Keying option 3 of SP 800-67 Rev. 1 (withdrawn in Rev. 2): K1 = K2 = K3,
    /// which degenerates to single DES. No public constructor builds it; it
    /// is reported only by instances this crate's own tests build for the
    /// NIST CAVP "KEYs" tables.
    SingleKey,
}

/// `true` when two DES key components carry the same 56 key bits, ignoring
/// the parity bits that DES discards in PC-1.
///
/// Evaluated without short-circuiting, like [`is_weak_or_semi_weak_key`], so
/// the running time does not depend on where the secret components differ.
#[inline]
fn same_des_key(a: &[u8; KEY_BYTES], b: &[u8; KEY_BYTES]) -> bool {
    let mut a_bits = strip_parity_bits(a);
    let mut b_bits = strip_parity_bits(b);
    let same = crate::ct::constant_time_eq_mask(&a_bits, &b_bits) != 0;
    // Both are key components with only the parity bits cleared.
    crate::ct::zeroize_slice(a_bits.as_mut_slice());
    crate::ct::zeroize_slice(b_bits.as_mut_slice());
    same
}

/// The six resident subkey schedules of a TDEA instance, plus the keying
/// option that built them.
///
/// Shared by [`TripleDes`] and [`TripleDesCt`]: the key schedule is the same
/// for both paths (FIPS 46-3 PC-1/PC-2 with the round-shift table), only the
/// per-block DES core differs, so the two public types wrap one of these and
/// pass their core function to [`TdeaSchedules::encrypt`] and
/// [`TdeaSchedules::decrypt`]. Holding all six schedules keeps repeated ECB
/// calls from re-deriving anything.
struct TdeaSchedules {
    k1_enc: KeySchedule,
    k1_dec: KeySchedule,
    k2_enc: KeySchedule,
    k2_dec: KeySchedule,
    k3_enc: KeySchedule,
    k3_dec: KeySchedule,
    mode: TDesMode,
}

impl TdeaSchedules {
    /// Keying option 1 from K1 ∥ K2 ∥ K3, rejecting weak components first and
    /// then any pair of equal components (SP 800-67 requires the three keys
    /// to be independent; a repeated component silently collapses 3TDEA to
    /// 2TDEA or to single DES).
    fn three_key(key: &[u8; TDEA3_KEY_BYTES]) -> Result<Self, DesKeyError> {
        let k1: &[u8; KEY_BYTES] = key[..KEY_BYTES].try_into().expect("first DES key split");
        let k2: &[u8; KEY_BYTES] = key[KEY_BYTES..2 * KEY_BYTES]
            .try_into()
            .expect("second DES key split");
        let k3: &[u8; KEY_BYTES] = key[2 * KEY_BYTES..]
            .try_into()
            .expect("third DES key split");
        if is_weak_or_semi_weak_key(k1)
            | is_weak_or_semi_weak_key(k2)
            | is_weak_or_semi_weak_key(k3)
        {
            return Err(DesKeyError::WeakOrSemiWeakKey);
        }
        if same_des_key(k1, k2) | same_des_key(k2, k3) | same_des_key(k1, k3) {
            return Err(DesKeyError::RepeatedKeyComponent);
        }
        Ok(Self::from_keys(
            u64::from_be_bytes(*k1),
            u64::from_be_bytes(*k2),
            u64::from_be_bytes(*k3),
            TDesMode::ThreeKey,
        ))
    }

    /// Keying option 2 from K1 ∥ K2 with K3 = K1, rejecting weak components
    /// and K1 = K2 (which would collapse 2TDEA to single DES).
    fn two_key(key: &[u8; TDEA2_KEY_BYTES]) -> Result<Self, DesKeyError> {
        let k1: &[u8; KEY_BYTES] = key[..KEY_BYTES].try_into().expect("first DES key split");
        let k2: &[u8; KEY_BYTES] = key[KEY_BYTES..2 * KEY_BYTES]
            .try_into()
            .expect("second DES key split");
        if is_weak_or_semi_weak_key(k1) | is_weak_or_semi_weak_key(k2) {
            return Err(DesKeyError::WeakOrSemiWeakKey);
        }
        if same_des_key(k1, k2) {
            return Err(DesKeyError::RepeatedKeyComponent);
        }
        Ok(Self::from_keys(
            u64::from_be_bytes(*k1),
            u64::from_be_bytes(*k2),
            u64::from_be_bytes(*k1),
            TDesMode::TwoKey,
        ))
    }

    /// Withdrawn keying option 3: K1 = K2 = K3, with the weak-key screen.
    #[cfg(test)]
    fn single_key(key: &[u8; 8]) -> Result<Self, DesKeyError> {
        if is_weak_or_semi_weak_key(key) {
            return Err(DesKeyError::WeakOrSemiWeakKey);
        }
        Ok(Self::single_key_unchecked(key))
    }

    /// Withdrawn keying option 3 without the weak-key screen.
    #[cfg(test)]
    fn single_key_unchecked(key: &[u8; 8]) -> Self {
        let mut k = u64::from_be_bytes(*key);
        let keys = Self::from_keys(k, k, k, TDesMode::SingleKey);
        crate::ct::zeroize_slice(core::slice::from_mut(&mut k));
        keys
    }

    /// Build all six schedules in place from the three key components, then
    /// wipe this function's copies of the components.
    fn from_keys(mut k1: u64, mut k2: u64, mut k3: u64, mode: TDesMode) -> Self {
        let mut keys = TdeaSchedules {
            k1_enc: key_schedule(k1),
            k1_dec: [0u64; 16],
            k2_enc: key_schedule(k2),
            k2_dec: [0u64; 16],
            k3_enc: key_schedule(k3),
            k3_dec: [0u64; 16],
            mode,
        };
        keys.k1_dec = keys.k1_enc;
        keys.k2_dec = keys.k2_enc;
        keys.k3_dec = keys.k3_enc;
        keys.k1_dec.reverse();
        keys.k2_dec.reverse();
        keys.k3_dec.reverse();
        for component in [&mut k1, &mut k2, &mut k3] {
            crate::ct::zeroize_slice(core::slice::from_mut(component));
        }
        keys
    }

    /// C = E(K3, D(K2, E(K1, P))) with `core` as the single-DES block function.
    #[inline]
    fn encrypt(&self, block: &[u8; 8], core: fn(u64, &KeySchedule) -> u64) -> [u8; 8] {
        let p = u64::from_be_bytes(*block);
        let t1 = core(p, &self.k1_enc); // E with K1
        let t2 = core(t1, &self.k2_dec); // D with K2
        let c = core(t2, &self.k3_enc); // E with K3
        c.to_be_bytes()
    }

    /// P = D(K1, E(K2, D(K3, C))) with `core` as the single-DES block function.
    #[inline]
    fn decrypt(&self, block: &[u8; 8], core: fn(u64, &KeySchedule) -> u64) -> [u8; 8] {
        let c = u64::from_be_bytes(*block);
        let t1 = core(c, &self.k3_dec); // D with K3
        let t2 = core(t1, &self.k2_enc); // E with K2
        let p = core(t2, &self.k1_dec); // D with K1
        p.to_be_bytes()
    }
}

impl Drop for TdeaSchedules {
    fn drop(&mut self) {
        // TDEA keeps six schedules resident; wipe all of them on drop.
        crate::ct::zeroize_slice(self.k1_enc.as_mut_slice());
        crate::ct::zeroize_slice(self.k1_dec.as_mut_slice());
        crate::ct::zeroize_slice(self.k2_enc.as_mut_slice());
        crate::ct::zeroize_slice(self.k2_dec.as_mut_slice());
        crate::ct::zeroize_slice(self.k3_enc.as_mut_slice());
        crate::ct::zeroize_slice(self.k3_dec.as_mut_slice());
    }
}

/// A Triple-DES (TDEA) cipher on the fast table-driven DES core.
///
/// Wraps the same key material as [`TripleDesCt`]; only the per-block core
/// differs. The schedules are wiped on drop.
pub struct TripleDes {
    keys: TdeaSchedules,
}

/// A Triple-DES (TDEA) cipher on the constant-time DES core of [`DesCt`].
///
/// Identical constructors, weak-key screening, keying-option rules and
/// zeroization policy to [`TripleDes`]; each of the three DES passes runs
/// through `des_block_ct`, so no secret-indexed table lookup occurs.
pub struct TripleDesCt {
    keys: TdeaSchedules,
}

/// Generate the public TDEA surface for one wrapper type around
/// [`TdeaSchedules`], parameterised on the single-DES block core it uses.
macro_rules! impl_tdea {
    ($name:ident, $core:ident) => {
        impl $name {
            /// Construct a 3TDEA instance (keying option 1) from a 24-byte key
            /// K1 ∥ K2 ∥ K3.
            ///
            /// # Errors
            ///
            /// [`DesKeyError::WeakOrSemiWeakKey`] if any component is weak or
            /// semi-weak; [`DesKeyError::RepeatedKeyComponent`] if any two
            /// components carry the same 56 key bits (parity ignored).
            pub fn new_3key(key: &[u8; 24]) -> Result<Self, DesKeyError> {
                TdeaSchedules::three_key(key).map(|keys| Self { keys })
            }

            /// Construct a 3TDEA instance and wipe the provided key buffer.
            pub fn new_3key_wiping(key: &mut [u8; 24]) -> Result<Self, DesKeyError> {
                let out = Self::new_3key(key);
                crate::ct::zeroize_slice(key.as_mut_slice());
                out
            }

            /// Construct a 2TDEA instance (keying option 2) from a 16-byte key
            /// K1 ∥ K2, with K3 = K1.
            ///
            /// # Errors
            ///
            /// [`DesKeyError::WeakOrSemiWeakKey`] if either component is weak
            /// or semi-weak; [`DesKeyError::RepeatedKeyComponent`] if K1 = K2
            /// (parity ignored), which would collapse the cipher to single DES.
            pub fn new_2key(key: &[u8; 16]) -> Result<Self, DesKeyError> {
                TdeaSchedules::two_key(key).map(|keys| Self { keys })
            }

            /// Construct a 2TDEA instance and wipe the provided key buffer.
            pub fn new_2key_wiping(key: &mut [u8; 16]) -> Result<Self, DesKeyError> {
                let out = Self::new_2key(key);
                crate::ct::zeroize_slice(key.as_mut_slice());
                out
            }

            /// Test-only: one DES key as K1 = K2 = K3, the keying option 3
            /// that SP 800-67 Rev. 2 withdrew, with the weak-key screen.
            #[cfg(test)]
            pub(crate) fn new_single_key(key: &[u8; 8]) -> Result<Self, DesKeyError> {
                TdeaSchedules::single_key(key).map(|keys| Self { keys })
            }

            /// Test-only: K1 = K2 = K3 without the weak-key screen, for the
            /// NIST CAVP "KEYs" tables whose key is the weak key `01..01`.
            #[cfg(test)]
            #[must_use]
            pub(crate) fn new_single_key_unchecked(key: &[u8; 8]) -> Self {
                Self {
                    keys: TdeaSchedules::single_key_unchecked(key),
                }
            }

            /// The keying option this instance was built with.
            #[must_use]
            pub fn mode(&self) -> TDesMode {
                self.keys.mode
            }

            /// Encrypt a single 64-bit block: C = E(K3, D(K2, E(K1, P)))
            #[must_use]
            pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
                self.keys.encrypt(block, $core)
            }

            /// Decrypt a single 64-bit block: P = D(K1, E(K2, D(K3, C)))
            #[must_use]
            pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
                self.keys.decrypt(block, $core)
            }
        }

        impl crate::BlockCipher for $name {
            const BLOCK_LEN: usize = 8;
            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.encrypt_block(arr));
            }
            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.decrypt_block(arr));
            }
        }
    };
}

impl_tdea!(TripleDes, des_block);
impl_tdea!(TripleDesCt, des_block_ct);

// ─────────────────────────────────────────────────────────────────────────────
// BlockCipher trait implementations
// ─────────────────────────────────────────────────────────────────────────────

impl crate::BlockCipher for Des {
    const BLOCK_LEN: usize = 8;
    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.encrypt_block(arr));
    }
    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.decrypt_block(arr));
    }
}

impl crate::BlockCipher for DesCt {
    const BLOCK_LEN: usize = 8;
    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.encrypt_block(arr));
    }
    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        block.copy_from_slice(&self.decrypt_block(arr));
    }
}

impl Drop for Des {
    fn drop(&mut self) {
        // DES instances retain both schedules for repeated ECB calls.
        crate::ct::zeroize_slice(self.enc_schedule.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_schedule.as_mut_slice());
    }
}

impl Drop for DesCt {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.enc_schedule.as_mut_slice());
        crate::ct::zeroize_slice(self.dec_schedule.as_mut_slice());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — sources are named per test: NIST CAVP KAT_TDES.zip (CAVS 11.1),
// SP 800-67 Rev. 2 Appendix B, OpenSSL as oracle, and differential checks
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decode_hex_array;

    /// Run a single NIST CAVP TDES ECB test vector using the TDES EDE path
    /// (K1=K2=K3 per the "KEYs" notation in the .rsp files).
    fn tdes_kat(key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let key = decode_hex_array::<8>(key_hex);
        let pt = decode_hex_array::<8>(pt_hex);
        let ct = decode_hex_array::<8>(ct_hex);
        let cipher = TripleDes::new_single_key_unchecked(&key);
        assert_eq!(
            cipher.encrypt_block(&pt),
            ct,
            "encrypt mismatch: key={key_hex} pt={pt_hex}"
        );
        assert_eq!(
            cipher.decrypt_block(&ct),
            pt,
            "decrypt mismatch: key={key_hex} ct={ct_hex}"
        );
    }

    /// Run a DES ECB test using the single-key DES path.
    fn des_kat(key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let key = decode_hex_array::<8>(key_hex);
        let pt = decode_hex_array::<8>(pt_hex);
        let ct = decode_hex_array::<8>(ct_hex);
        let cipher = Des::new_unchecked(&key);
        assert_eq!(
            cipher.encrypt_block(&pt),
            ct,
            "encrypt mismatch: key={key_hex} pt={pt_hex}"
        );
        assert_eq!(
            cipher.decrypt_block(&ct),
            pt,
            "decrypt mismatch: key={key_hex} ct={ct_hex}"
        );
    }

    fn des_ct_kat(key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let key = decode_hex_array::<8>(key_hex);
        let pt = decode_hex_array::<8>(pt_hex);
        let ct = decode_hex_array::<8>(ct_hex);
        let fast = Des::new_unchecked(&key);
        let slow = DesCt::new_unchecked(&key);
        assert_eq!(
            slow.encrypt_block(&pt),
            ct,
            "encrypt mismatch: key={key_hex} pt={pt_hex}"
        );
        assert_eq!(
            slow.decrypt_block(&ct),
            pt,
            "decrypt mismatch: key={key_hex} ct={ct_hex}"
        );
        assert_eq!(
            slow.encrypt_block(&pt),
            fast.encrypt_block(&pt),
            "DesCt must match Des for key={key_hex} pt={pt_hex}"
        );
    }

    // ── TECBvartext.rsp — Variable Plaintext KAT ─────────────────────────────
    // Key 0101010101010101 (every key bit 0, odd parity): this is the weak
    // key whose sixteen subkeys are all zero. Each plaintext has exactly one
    // bit set, walking from the MSB to the LSB.
    // From NIST CAVP KAT_TDES/TECBvartext.rsp (CAVS 11.1, 2011-04-21).

    #[test]
    fn vartext_all_64() {
        // Full 64-vector known-answer test for the variable-plaintext category.
        let cases: &[(&str, &str, &str)] = &[
            ("0101010101010101", "8000000000000000", "95f8a5e5dd31d900"),
            ("0101010101010101", "4000000000000000", "dd7f121ca5015619"),
            ("0101010101010101", "2000000000000000", "2e8653104f3834ea"),
            ("0101010101010101", "1000000000000000", "4bd388ff6cd81d4f"),
            ("0101010101010101", "0800000000000000", "20b9e767b2fb1456"),
            ("0101010101010101", "0400000000000000", "55579380d77138ef"),
            ("0101010101010101", "0200000000000000", "6cc5defaaf04512f"),
            ("0101010101010101", "0100000000000000", "0d9f279ba5d87260"),
            ("0101010101010101", "0080000000000000", "d9031b0271bd5a0a"),
            ("0101010101010101", "0040000000000000", "424250b37c3dd951"),
            ("0101010101010101", "0020000000000000", "b8061b7ecd9a21e5"),
            ("0101010101010101", "0010000000000000", "f15d0f286b65bd28"),
            ("0101010101010101", "0008000000000000", "add0cc8d6e5deba1"),
            ("0101010101010101", "0004000000000000", "e6d5f82752ad63d1"),
            ("0101010101010101", "0002000000000000", "ecbfe3bd3f591a5e"),
            ("0101010101010101", "0001000000000000", "f356834379d165cd"),
            ("0101010101010101", "0000800000000000", "2b9f982f20037fa9"),
            ("0101010101010101", "0000400000000000", "889de068a16f0be6"),
            ("0101010101010101", "0000200000000000", "e19e275d846a1298"),
            ("0101010101010101", "0000100000000000", "329a8ed523d71aec"),
            ("0101010101010101", "0000080000000000", "e7fce22557d23c97"),
            ("0101010101010101", "0000040000000000", "12a9f5817ff2d65d"),
            ("0101010101010101", "0000020000000000", "a484c3ad38dc9c19"),
            ("0101010101010101", "0000010000000000", "fbe00a8a1ef8ad72"),
            ("0101010101010101", "0000008000000000", "750d079407521363"),
            ("0101010101010101", "0000004000000000", "64feed9c724c2faf"),
            ("0101010101010101", "0000002000000000", "f02b263b328e2b60"),
            ("0101010101010101", "0000001000000000", "9d64555a9a10b852"),
            ("0101010101010101", "0000000800000000", "d106ff0bed5255d7"),
            ("0101010101010101", "0000000400000000", "e1652c6b138c64a5"),
            ("0101010101010101", "0000000200000000", "e428581186ec8f46"),
            ("0101010101010101", "0000000100000000", "aeb5f5ede22d1a36"),
            ("0101010101010101", "0000000080000000", "e943d7568aec0c5c"),
            ("0101010101010101", "0000000040000000", "df98c8276f54b04b"),
            ("0101010101010101", "0000000020000000", "b160e4680f6c696f"),
            ("0101010101010101", "0000000010000000", "fa0752b07d9c4ab8"),
            ("0101010101010101", "0000000008000000", "ca3a2b036dbc8502"),
            ("0101010101010101", "0000000004000000", "5e0905517bb59bcf"),
            ("0101010101010101", "0000000002000000", "814eeb3b91d90726"),
            ("0101010101010101", "0000000001000000", "4d49db1532919c9f"),
            ("0101010101010101", "0000000000800000", "25eb5fc3f8cf0621"),
            ("0101010101010101", "0000000000400000", "ab6a20c0620d1c6f"),
            ("0101010101010101", "0000000000200000", "79e90dbc98f92cca"),
            ("0101010101010101", "0000000000100000", "866ecedd8072bb0e"),
            ("0101010101010101", "0000000000080000", "8b54536f2f3e64a8"),
            ("0101010101010101", "0000000000040000", "ea51d3975595b86b"),
            ("0101010101010101", "0000000000020000", "caffc6ac4542de31"),
            ("0101010101010101", "0000000000010000", "8dd45a2ddf90796c"),
            ("0101010101010101", "0000000000008000", "1029d55e880ec2d0"),
            ("0101010101010101", "0000000000004000", "5d86cb23639dbea9"),
            ("0101010101010101", "0000000000002000", "1d1ca853ae7c0c5f"),
            ("0101010101010101", "0000000000001000", "ce332329248f3228"),
            ("0101010101010101", "0000000000000800", "8405d1abe24fb942"),
            ("0101010101010101", "0000000000000400", "e643d78090ca4207"),
            ("0101010101010101", "0000000000000200", "48221b9937748a23"),
            ("0101010101010101", "0000000000000100", "dd7c0bbd61fafd54"),
            ("0101010101010101", "0000000000000080", "2fbc291a570db5c4"),
            ("0101010101010101", "0000000000000040", "e07c30d7e4e26e12"),
            ("0101010101010101", "0000000000000020", "0953e2258e8e90a1"),
            ("0101010101010101", "0000000000000010", "5b711bc4ceebf2ee"),
            ("0101010101010101", "0000000000000008", "cc083f1e6d9e85f6"),
            ("0101010101010101", "0000000000000004", "d2fd8867d50d2dfe"),
            ("0101010101010101", "0000000000000002", "06e7ea22ce92708f"),
            ("0101010101010101", "0000000000000001", "166b40b44aba4bd6"),
        ];
        for (k, pt, ct) in cases {
            tdes_kat(k, pt, ct);
        }
    }

    // ── TECBinvperm.rsp — Inverse Permutation KAT ───────────────────────────
    // The vartext pairs with plaintext and ciphertext swapped. This works
    // only because the key is weak: all sixteen subkeys are equal, so the
    // reversed schedule is the schedule and E_K is its own inverse (an
    // involution). DES under an ordinary key is not an involution. The table
    // therefore exercises encryption once more from the other side, ending
    // in IP⁻¹ on the vartext plaintexts.

    #[test]
    fn invperm_sample() {
        let cases = [
            ("0101010101010101", "95f8a5e5dd31d900", "8000000000000000"),
            ("0101010101010101", "dd7f121ca5015619", "4000000000000000"),
            ("0101010101010101", "166b40b44aba4bd6", "0000000000000001"),
        ];
        for (k, pt, ct) in cases {
            tdes_kat(k, pt, ct);
        }
    }

    // ── TECBvarkey.rsp — Variable Key KAT ───────────────────────────────────
    // Plaintext 0000000000000000; each key has exactly one of the 56 key
    // bits set, MSB first, the parity bits adjusted to keep odd parity.

    #[test]
    fn varkey_all_56() {
        let cases: &[(&str, &str, &str)] = &[
            ("8001010101010101", "0000000000000000", "95a8d72813daa94d"),
            ("4001010101010101", "0000000000000000", "0eec1487dd8c26d5"),
            ("2001010101010101", "0000000000000000", "7ad16ffb79c45926"),
            ("1001010101010101", "0000000000000000", "d3746294ca6a6cf3"),
            ("0801010101010101", "0000000000000000", "809f5f873c1fd761"),
            ("0401010101010101", "0000000000000000", "c02faffec989d1fc"),
            ("0201010101010101", "0000000000000000", "4615aa1d33e72f10"),
            ("0180010101010101", "0000000000000000", "2055123350c00858"),
            ("0140010101010101", "0000000000000000", "df3b99d6577397c8"),
            ("0120010101010101", "0000000000000000", "31fe17369b5288c9"),
            ("0110010101010101", "0000000000000000", "dfdd3cc64dae1642"),
            ("0108010101010101", "0000000000000000", "178c83ce2b399d94"),
            ("0104010101010101", "0000000000000000", "50f636324a9b7f80"),
            ("0102010101010101", "0000000000000000", "a8468ee3bc18f06d"),
            ("0101800101010101", "0000000000000000", "a2dc9e92fd3cde92"),
            ("0101400101010101", "0000000000000000", "cac09f797d031287"),
            ("0101200101010101", "0000000000000000", "90ba680b22aeb525"),
            ("0101100101010101", "0000000000000000", "ce7a24f350e280b6"),
            ("0101080101010101", "0000000000000000", "882bff0aa01a0b87"),
            ("0101040101010101", "0000000000000000", "25610288924511c2"),
            ("0101020101010101", "0000000000000000", "c71516c29c75d170"),
            ("0101018001010101", "0000000000000000", "5199c29a52c9f059"),
            ("0101014001010101", "0000000000000000", "c22f0a294a71f29f"),
            ("0101012001010101", "0000000000000000", "ee371483714c02ea"),
            ("0101011001010101", "0000000000000000", "a81fbd448f9e522f"),
            ("0101010801010101", "0000000000000000", "4f644c92e192dfed"),
            ("0101010401010101", "0000000000000000", "1afa9a66a6df92ae"),
            ("0101010201010101", "0000000000000000", "b3c1cc715cb879d8"),
            ("0101010180010101", "0000000000000000", "19d032e64ab0bd8b"),
            ("0101010140010101", "0000000000000000", "3cfaa7a7dc8720dc"),
            ("0101010120010101", "0000000000000000", "b7265f7f447ac6f3"),
            ("0101010110010101", "0000000000000000", "9db73b3c0d163f54"),
            ("0101010108010101", "0000000000000000", "8181b65babf4a975"),
            ("0101010104010101", "0000000000000000", "93c9b64042eaa240"),
            ("0101010102010101", "0000000000000000", "5570530829705592"),
            ("0101010101800101", "0000000000000000", "8638809e878787a0"),
            ("0101010101400101", "0000000000000000", "41b9a79af79ac208"),
            ("0101010101200101", "0000000000000000", "7a9be42f2009a892"),
            ("0101010101100101", "0000000000000000", "29038d56ba6d2745"),
            ("0101010101080101", "0000000000000000", "5495c6abf1e5df51"),
            ("0101010101040101", "0000000000000000", "ae13dbd561488933"),
            ("0101010101020101", "0000000000000000", "024d1ffa8904e389"),
            ("0101010101018001", "0000000000000000", "d1399712f99bf02e"),
            ("0101010101014001", "0000000000000000", "14c1d7c1cffec79e"),
            ("0101010101012001", "0000000000000000", "1de5279dae3bed6f"),
            ("0101010101011001", "0000000000000000", "e941a33f85501303"),
            ("0101010101010801", "0000000000000000", "da99dbbc9a03f379"),
            ("0101010101010401", "0000000000000000", "b7fc92f91d8e92e9"),
            ("0101010101010201", "0000000000000000", "ae8e5caa3ca04e85"),
            ("0101010101010180", "0000000000000000", "9cc62df43b6eed74"),
            ("0101010101010140", "0000000000000000", "d863dbb5c59a91a0"),
            ("0101010101010120", "0000000000000000", "a1ab2190545b91d7"),
            ("0101010101010110", "0000000000000000", "0875041e64c570f7"),
            ("0101010101010108", "0000000000000000", "5a594528bebef1cc"),
            ("0101010101010104", "0000000000000000", "fcdb3291de21f0c0"),
            ("0101010101010102", "0000000000000000", "869efd7f9f265a09"),
        ];
        for (k, pt, ct) in cases {
            tdes_kat(k, pt, ct);
        }
    }

    // ── TECBpermop.rsp — Permutation Operation KAT ──────────────────────────
    // Tests the P permutation and S-box interaction.

    #[test]
    fn permop_all_32() {
        let cases: &[(&str, &str, &str)] = &[
            ("1046913489980131", "0000000000000000", "88d55e54f54c97b4"),
            ("1007103489988020", "0000000000000000", "0c0cc00c83ea48fd"),
            ("10071034c8980120", "0000000000000000", "83bc8ef3a6570183"),
            ("1046103489988020", "0000000000000000", "df725dcad94ea2e9"),
            ("1086911519190101", "0000000000000000", "e652b53b550be8b0"),
            ("1086911519580101", "0000000000000000", "af527120c485cbb0"),
            ("5107b01519580101", "0000000000000000", "0f04ce393db926d5"),
            ("1007b01519190101", "0000000000000000", "c9f00ffc74079067"),
            ("3107915498080101", "0000000000000000", "7cfd82a593252b4e"),
            ("3107919498080101", "0000000000000000", "cb49a2f9e91363e3"),
            ("10079115b9080140", "0000000000000000", "00b588be70d23f56"),
            ("3107911598080140", "0000000000000000", "406a9a6ab43399ae"),
            ("1007d01589980101", "0000000000000000", "6cb773611dca9ada"),
            ("9107911589980101", "0000000000000000", "67fd21c17dbb5d70"),
            ("9107d01589190101", "0000000000000000", "9592cb4110430787"),
            ("1007d01598980120", "0000000000000000", "a6b7ff68a318ddd3"),
            ("1007940498190101", "0000000000000000", "4d102196c914ca16"),
            ("0107910491190401", "0000000000000000", "2dfa9f4573594965"),
            ("0107910491190101", "0000000000000000", "b46604816c0e0774"),
            ("0107940491190401", "0000000000000000", "6e7e6221a4f34e87"),
            ("19079210981a0101", "0000000000000000", "aa85e74643233199"),
            ("1007911998190801", "0000000000000000", "2e5a19db4d1962d6"),
            ("10079119981a0801", "0000000000000000", "23a866a809d30894"),
            ("1007921098190101", "0000000000000000", "d812d961f017d320"),
            ("100791159819010b", "0000000000000000", "055605816e58608f"),
            ("1004801598190101", "0000000000000000", "abd88e8b1b7716f1"),
            ("1004801598190102", "0000000000000000", "537ac95be69da1e1"),
            ("1004801598190108", "0000000000000000", "aed0f6ae3c25cdd8"),
            ("1002911498100104", "0000000000000000", "b3e35a5ee53e7b8d"),
            ("1002911598190104", "0000000000000000", "61c79c71921a2ef8"),
            ("1002911598100201", "0000000000000000", "e2f5728f0995013c"),
            ("1002911698100101", "0000000000000000", "1aeac39a61f0a464"),
        ];
        for (k, pt, ct) in cases {
            tdes_kat(k, pt, ct);
        }
    }

    // ── TECBsubtab.rsp — Substitution Table KAT ─────────────────────────────
    // Tests all 8 S-boxes with varied keys and plaintexts.

    #[test]
    fn subtab_all_19() {
        let cases: &[(&str, &str, &str)] = &[
            ("7ca110454a1a6e57", "01a1d6d039776742", "690f5b0d9a26939b"),
            ("0131d9619dc1376e", "5cd54ca83def57da", "7a389d10354bd271"),
            ("07a1133e4a0b2686", "0248d43806f67172", "868ebb51cab4599a"),
            ("3849674c2602319e", "51454b582ddf440a", "7178876e01f19b2a"),
            ("04b915ba43feb5b6", "42fd443059577fa2", "af37fb421f8c4095"),
            ("0113b970fd34f2ce", "059b5e0851cf143a", "86a560f10ec6d85b"),
            ("0170f175468fb5e6", "0756d8e0774761d2", "0cd3da020021dc09"),
            ("43297fad38e373fe", "762514b829bf486a", "ea676b2cb7db2b7a"),
            ("07a7137045da2a16", "3bdd119049372802", "dfd64a815caf1a0f"),
            ("04689104c2fd3b2f", "26955f6835af609a", "5c513c9c4886c088"),
            ("37d06bb516cb7546", "164d5e404f275232", "0a2aeeae3ff4ab77"),
            ("1f08260d1ac2465e", "6b056e18759f5cca", "ef1bf03e5dfa575a"),
            ("584023641aba6176", "004bd6ef09176062", "88bf0db6d70dee56"),
            ("025816164629b007", "480d39006ee762f2", "a1f9915541020b56"),
            ("49793ebc79b3258f", "437540c8698f3cfa", "6fbf1cafcffd0556"),
            ("4fb05e1515ab73a7", "072d43a077075292", "2f22e49bab7ca1ac"),
            ("49e95d6d4ca229bf", "02fe55778117f12a", "5a6b612cc26cce4a"),
            ("018310dc409b26d6", "1d9d5c5018f728c2", "5f4c038ed12b2e41"),
            ("1c587f1c13924fef", "305532286d6f295a", "63fac0d034d9f793"),
        ];
        for (k, pt, ct) in cases {
            tdes_kat(k, pt, ct);
        }
    }

    // ── Des struct — direct single-key DES ───────────────────────────────────
    // These reuse a subset of the NIST CAVP subtab vectors through the `Des`
    // public API (not the TDES path) to exercise the struct directly.

    #[test]
    fn des_direct_subtab() {
        let cases: &[(&str, &str, &str)] = &[
            ("7ca110454a1a6e57", "01a1d6d039776742", "690f5b0d9a26939b"),
            ("0131d9619dc1376e", "5cd54ca83def57da", "7a389d10354bd271"),
            ("07a1133e4a0b2686", "0248d43806f67172", "868ebb51cab4599a"),
        ];
        for (k, pt, ct) in cases {
            des_kat(k, pt, ct);
        }
    }

    #[test]
    fn des_ct_direct_subtab() {
        let cases: &[(&str, &str, &str)] = &[
            ("7ca110454a1a6e57", "01a1d6d039776742", "690f5b0d9a26939b"),
            ("0131d9619dc1376e", "5cd54ca83def57da", "7a389d10354bd271"),
            ("07a1133e4a0b2686", "0248d43806f67172", "868ebb51cab4599a"),
        ];
        for (k, pt, ct) in cases {
            des_ct_kat(k, pt, ct);
        }
    }

    // ── 3TDEA — three independent keys ──────────────────────────────────────
    // These exercise the full EDE path with K1 ≠ K2 ≠ K3.

    /// NIST SP 800-67 Rev. 2, Appendix B: the worked TECB example with
    /// K1 = 0123456789ABCDEF, K2 = 23456789ABCDEF01, K3 = 456789ABCDEF0123 on
    /// the plaintext "The qufck brown fox jump" (sic). Pins the K1/K2/K3
    /// ordering, which a round trip alone cannot distinguish from a swap.
    #[test]
    fn tdes_3key_sp800_67_appendix_b_kat() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        ];
        let cipher = TripleDes::new_3key(&key).expect("SP 800-67 keys are not weak");
        let vectors: [([u8; 8], [u8; 8]); 3] = [
            (
                *b"The qufc",
                [0xA8, 0x26, 0xFD, 0x8C, 0xE5, 0x3B, 0x85, 0x5F],
            ),
            (
                *b"k brown ",
                [0xCC, 0xE2, 0x1C, 0x81, 0x12, 0x25, 0x6F, 0xE6],
            ),
            (
                *b"fox jump",
                [0x68, 0xD5, 0xC0, 0x5D, 0xD9, 0xB6, 0xB9, 0x00],
            ),
        ];
        for (pt, ct) in vectors {
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    #[test]
    fn tdes_3key_roundtrip() {
        // K1=0133457799BBCDFF, K2=0011223344556677, K3=8899AABBCCDDEEFF
        let key: [u8; 24] = [
            0x01, 0x33, 0x45, 0x77, 0x99, 0xBB, 0xCD, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let pt: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let cipher = TripleDes::new_3key(&key).expect("non-weak TDES keys");
        let ct = cipher.encrypt_block(&pt);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    // ── 2TDEA — two independent keys (K1=K3) ────────────────────────────────

    #[test]
    fn tdes_2key_roundtrip() {
        let key: [u8; 16] = [
            0x01, 0x33, 0x45, 0x77, 0x99, 0xBB, 0xCD, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77,
        ];
        let pt: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let cipher = TripleDes::new_2key(&key).expect("non-weak TDES keys");
        let ct = cipher.encrypt_block(&pt);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    // ── Verify TDES K1=K2=K3 is identical to single DES ─────────────────────

    #[test]
    fn tdes_single_key_equals_des() {
        let key: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let pt: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let des = Des::new(&key).expect("non-weak DES key");
        let tdes = TripleDes::new_single_key(&key).expect("non-weak DES key");
        assert_eq!(
            des.encrypt_block(&pt),
            tdes.encrypt_block(&pt),
            "TDES(K,K,K) must equal DES(K) for same key and plaintext"
        );
    }

    #[test]
    fn des_matches_openssl_ecb() {
        let key_hex = "133457799bbcdff1";
        let pt_hex = "0123456789abcdef";
        let Some(expected) = crate::test_utils::openssl_enc(
            "-des-ecb",
            key_hex,
            None,
            &decode_hex_array::<8>(pt_hex),
        )
        .or_skip("des_matches_openssl_ecb") else {
            return;
        };

        let cipher = Des::new(&decode_hex_array::<8>(key_hex)).expect("non-weak DES key");
        assert_eq!(
            cipher
                .encrypt_block(&decode_hex_array::<8>(pt_hex))
                .as_slice(),
            expected.as_slice()
        );
        let cipher_ct = DesCt::new(&decode_hex_array::<8>(key_hex)).expect("non-weak DES key");
        assert_eq!(
            cipher_ct
                .encrypt_block(&decode_hex_array::<8>(pt_hex))
                .as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn tdes_matches_openssl_ecb() {
        let key_hex = "133457799bbcdff100112233445566778899aabbccddeeff";
        let pt_hex = "0123456789abcdef";
        let Some(expected) = crate::test_utils::openssl_enc(
            "-des-ede3-ecb",
            key_hex,
            None,
            &decode_hex_array::<8>(pt_hex),
        )
        .or_skip("tdes_matches_openssl_ecb") else {
            return;
        };

        let cipher =
            TripleDes::new_3key(&decode_hex_array::<24>(key_hex)).expect("non-weak TDES keys");
        assert_eq!(
            cipher
                .encrypt_block(&decode_hex_array::<8>(pt_hex))
                .as_slice(),
            expected.as_slice()
        );
        let cipher_ct =
            TripleDesCt::new_3key(&decode_hex_array::<24>(key_hex)).expect("non-weak TDES keys");
        assert_eq!(
            cipher_ct
                .encrypt_block(&decode_hex_array::<8>(pt_hex))
                .as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn des_weak_keys_are_rejected_by_checked_constructor() {
        // FIPS 74 / NIST weak-key set: checked constructors must reject these.
        let weak_keys: [[u8; 8]; 4] = [
            decode_hex_array::<8>("0101010101010101"),
            decode_hex_array::<8>("FEFEFEFEFEFEFEFE"),
            decode_hex_array::<8>("E0E0E0E0F1F1F1F1"),
            decode_hex_array::<8>("1F1F1F1F0E0E0E0E"),
        ];
        for key in weak_keys {
            assert!(matches!(
                Des::new(&key),
                Err(DesKeyError::WeakOrSemiWeakKey)
            ));
            assert!(matches!(
                DesCt::new(&key),
                Err(DesKeyError::WeakOrSemiWeakKey)
            ));
            assert!(matches!(
                TripleDes::new_single_key(&key),
                Err(DesKeyError::WeakOrSemiWeakKey)
            ));
        }
    }

    #[test]
    fn des_semi_weak_keys_are_rejected_by_checked_constructor() {
        // Semi-weak pairs are disallowed in checked constructors.
        let pairs: [([u8; 8], [u8; 8]); 6] = [
            (
                decode_hex_array::<8>("01FE01FE01FE01FE"),
                decode_hex_array::<8>("FE01FE01FE01FE01"),
            ),
            (
                decode_hex_array::<8>("1FE01FE00EF10EF1"),
                decode_hex_array::<8>("E01FE01FF10EF10E"),
            ),
            (
                decode_hex_array::<8>("01E001E001F101F1"),
                decode_hex_array::<8>("E001E001F101F101"),
            ),
            (
                decode_hex_array::<8>("1FFE1FFE0EFE0EFE"),
                decode_hex_array::<8>("FE1FFE1FFE0EFE0E"),
            ),
            (
                decode_hex_array::<8>("011F011F010E010E"),
                decode_hex_array::<8>("1F011F010E010E01"),
            ),
            (
                decode_hex_array::<8>("E0FEE0FEF1FEF1FE"),
                decode_hex_array::<8>("FEE0FEE0FEF1FEF1"),
            ),
        ];
        for (k1, k2) in pairs {
            assert!(matches!(Des::new(&k1), Err(DesKeyError::WeakOrSemiWeakKey)));
            assert!(matches!(Des::new(&k2), Err(DesKeyError::WeakOrSemiWeakKey)));
            assert!(matches!(
                DesCt::new(&k1),
                Err(DesKeyError::WeakOrSemiWeakKey)
            ));
            assert!(matches!(
                DesCt::new(&k2),
                Err(DesKeyError::WeakOrSemiWeakKey)
            ));
        }
    }

    /// Under a weak key every subkey is the same, so encryption is an
    /// involution: this is the property behind the TECBinvperm table.
    #[test]
    fn weak_key_math_still_holds_in_unchecked_path() {
        let key = decode_hex_array::<8>("0101010101010101");
        let pt = decode_hex_array::<8>("0123456789ABCDEF");
        let des = Des::new_unchecked(&key);
        let ct = des.encrypt_block(&pt);
        assert_eq!(des.encrypt_block(&ct), pt);
    }

    /// The screen compares the 56 key bits, so a listed key written with the
    /// wrong (even) parity, or with any mix of parity bits, is still refused
    /// by every checked constructor.
    #[test]
    fn parity_flipped_weak_keys_are_refused() {
        let mut listed: Vec<[u8; 8]> = WEAK_KEYS.to_vec();
        for (a, b) in SEMI_WEAK_KEY_PAIRS {
            listed.push(a);
            listed.push(b);
        }
        assert_eq!(listed.len(), 16);
        for key in listed {
            for pattern in [0x01u8, 0x55, 0xaa, 0xff] {
                let mut flipped = key;
                for (i, byte) in flipped.iter_mut().enumerate() {
                    *byte ^= (pattern >> i) & 1;
                }
                assert!(is_weak_or_semi_weak_key(&flipped), "{flipped:02x?}");
                assert_eq!(
                    Des::new(&flipped).err(),
                    Some(DesKeyError::WeakOrSemiWeakKey),
                    "Des {flipped:02x?}"
                );
                assert_eq!(
                    DesCt::new(&flipped).err(),
                    Some(DesKeyError::WeakOrSemiWeakKey),
                    "DesCt {flipped:02x?}"
                );
                let mut bundle = [0u8; 24];
                bundle[..8].copy_from_slice(&KA);
                bundle[8..16].copy_from_slice(&flipped);
                bundle[16..].copy_from_slice(&KC);
                assert_eq!(
                    TripleDes::new_3key(&bundle).err(),
                    Some(DesKeyError::WeakOrSemiWeakKey),
                    "TripleDes {flipped:02x?}"
                );
                let mut pair = [0u8; 16];
                pair[..8].copy_from_slice(&flipped);
                pair[8..].copy_from_slice(&KB);
                assert_eq!(
                    TripleDesCt::new_2key(&pair).err(),
                    Some(DesKeyError::WeakOrSemiWeakKey),
                    "TripleDesCt {flipped:02x?}"
                );
            }
        }
        // The all-even-parity form of 01..01 is the all-zero key.
        assert!(is_weak_or_semi_weak_key(&[0u8; 8]));
    }

    /// The contract scrub.rs relies on: the ANF evaluation used by `DesCt`
    /// reproduces every entry of every FIPS 46-3 S-box table.
    #[test]
    fn sbox_ct_matches_tables() {
        for (i, table) in SBOXES.iter().enumerate() {
            for input in 0u8..64 {
                let row = usize::from(((input & 0x20) >> 4) | (input & 0x01));
                let col = usize::from((input >> 1) & 0x0f);
                assert_eq!(
                    sbox_ct(i, input),
                    table[row * 16 + col],
                    "S{} input {input:06b}",
                    i + 1
                );
            }
        }
    }

    /// The `BlockCipher` trait works on slices and refuses any length other
    /// than the block.
    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_trait_refuses_short_block() {
        use crate::BlockCipher;
        let cipher = Des::new(&decode_hex_array::<8>("133457799bbcdff1")).expect("non-weak");
        let mut short = [0u8; 7];
        cipher.encrypt(&mut short);
    }

    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_trait_refuses_long_block_on_decrypt() {
        use crate::BlockCipher;
        let key = decode_hex_array::<24>("133457799bbcdff100112233445566778899aabbccddeeff");
        let cipher = TripleDesCt::new_3key(&key).expect("non-weak");
        let mut long = [0u8; 16];
        cipher.decrypt(&mut long);
    }

    // ── TripleDesCt — constant-time core through the same TDEA composition ──

    /// The SP 800-67 Appendix B vectors must also hold on the constant-time
    /// core, pinning the K1/K2/K3 ordering there too.
    #[test]
    fn tdes_ct_3key_sp800_67_appendix_b_kat() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        ];
        let cipher = TripleDesCt::new_3key(&key).expect("SP 800-67 keys are not weak");
        let vectors: [([u8; 8], [u8; 8]); 3] = [
            (
                *b"The qufc",
                [0xA8, 0x26, 0xFD, 0x8C, 0xE5, 0x3B, 0x85, 0x5F],
            ),
            (
                *b"k brown ",
                [0xCC, 0xE2, 0x1C, 0x81, 0x12, 0x25, 0x6F, 0xE6],
            ),
            (
                *b"fox jump",
                [0x68, 0xD5, 0xC0, 0x5D, 0xD9, 0xB6, 0xB9, 0x00],
            ),
        ];
        for (pt, ct) in vectors {
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    /// Deterministic xorshift64* filler for differential tests; the seed is
    /// fixed so a failure reproduces.
    fn fill_bytes(state: &mut u64, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *state ^= *state >> 12;
            *state ^= *state << 25;
            *state ^= *state >> 27;
            *byte = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
    }

    #[test]
    fn tdes_and_tdes_ct_match_random_vectors_3key() {
        let mut rng = 0x3DE5_3DE5_0000_0001u64;
        let mut checked = 0;
        while checked < 128 {
            let mut key = [0u8; 24];
            let mut pt = [0u8; 8];
            fill_bytes(&mut rng, &mut key);
            fill_bytes(&mut rng, &mut pt);
            let (Ok(fast), Ok(slow)) = (TripleDes::new_3key(&key), TripleDesCt::new_3key(&key))
            else {
                // Both constructors apply the same screen; a random key that
                // trips it is skipped, not counted.
                assert_eq!(
                    TripleDes::new_3key(&key).err(),
                    TripleDesCt::new_3key(&key).err()
                );
                continue;
            };
            assert_eq!(fast.mode(), TDesMode::ThreeKey);
            assert_eq!(slow.mode(), TDesMode::ThreeKey);
            let ct = fast.encrypt_block(&pt);
            assert_eq!(slow.encrypt_block(&pt), ct, "3TDEA encrypt key={key:02x?}");
            assert_eq!(slow.decrypt_block(&ct), pt, "3TDEA decrypt key={key:02x?}");
            assert_eq!(fast.decrypt_block(&ct), pt);
            checked += 1;
        }
    }

    #[test]
    fn tdes_and_tdes_ct_match_random_vectors_2key() {
        let mut rng = 0x2DE5_2DE5_0000_0001u64;
        let mut checked = 0;
        while checked < 128 {
            let mut key = [0u8; 16];
            let mut pt = [0u8; 8];
            fill_bytes(&mut rng, &mut key);
            fill_bytes(&mut rng, &mut pt);
            let (Ok(fast), Ok(slow)) = (TripleDes::new_2key(&key), TripleDesCt::new_2key(&key))
            else {
                assert_eq!(
                    TripleDes::new_2key(&key).err(),
                    TripleDesCt::new_2key(&key).err()
                );
                continue;
            };
            assert_eq!(fast.mode(), TDesMode::TwoKey);
            assert_eq!(slow.mode(), TDesMode::TwoKey);
            let ct = fast.encrypt_block(&pt);
            assert_eq!(slow.encrypt_block(&pt), ct, "2TDEA encrypt key={key:02x?}");
            assert_eq!(slow.decrypt_block(&ct), pt, "2TDEA decrypt key={key:02x?}");
            assert_eq!(fast.decrypt_block(&ct), pt);
            checked += 1;
        }
    }

    #[test]
    fn tdes_ct_single_key_equals_des_ct() {
        let key: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let pt: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let des = DesCt::new(&key).expect("non-weak DES key");
        let tdes = TripleDesCt::new_single_key(&key).expect("non-weak DES key");
        assert_eq!(tdes.mode(), TDesMode::SingleKey);
        assert_eq!(des.encrypt_block(&pt), tdes.encrypt_block(&pt));
        assert_eq!(
            tdes.encrypt_block(&pt),
            TripleDes::new_single_key_unchecked(&key).encrypt_block(&pt)
        );
    }

    #[test]
    fn tdes_ct_block_cipher_trait_matches_fast() {
        use crate::BlockCipher;
        let key = decode_hex_array::<24>("133457799bbcdff100112233445566778899aabbccddeeff");
        let fast = TripleDes::new_3key(&key).expect("non-weak TDES keys");
        let slow = TripleDesCt::new_3key(&key).expect("non-weak TDES keys");
        let mut a = *b"blockone";
        let mut b = a;
        fast.encrypt(&mut a);
        slow.encrypt(&mut b);
        assert_eq!(a, b);
        slow.decrypt(&mut b);
        assert_eq!(b, *b"blockone");
    }

    // ── Keying-option independence (SP 800-67 §3.1) ─────────────────────────

    const KA: [u8; 8] = [0x01, 0x33, 0x45, 0x77, 0x99, 0xBB, 0xCD, 0xFF];
    const KB: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    const KC: [u8; 8] = [0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    fn cat3(k1: &[u8; 8], k2: &[u8; 8], k3: &[u8; 8]) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..8].copy_from_slice(k1);
        out[8..16].copy_from_slice(k2);
        out[16..].copy_from_slice(k3);
        out
    }

    fn cat2(k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(k1);
        out[8..].copy_from_slice(k2);
        out
    }

    /// KA with every parity bit flipped: a different byte string, the same
    /// 56 DES key bits.
    fn ka_parity_flipped() -> [u8; 8] {
        let mut k = KA;
        for byte in k.iter_mut() {
            *byte ^= 0x01;
        }
        k
    }

    #[test]
    fn tdes_3key_rejects_repeated_components() {
        let cases: [([u8; 24], &str); 4] = [
            (cat3(&KA, &KA, &KC), "K1 = K2"),
            (cat3(&KA, &KB, &KB), "K2 = K3"),
            (cat3(&KA, &KB, &KA), "K1 = K3 (would be 2TDEA)"),
            (cat3(&KA, &KB, &ka_parity_flipped()), "K1 = K3 up to parity"),
        ];
        for (key, why) in cases {
            assert_eq!(
                TripleDes::new_3key(&key).err(),
                Some(DesKeyError::RepeatedKeyComponent),
                "TripleDes must reject {why}"
            );
            assert_eq!(
                TripleDesCt::new_3key(&key).err(),
                Some(DesKeyError::RepeatedKeyComponent),
                "TripleDesCt must reject {why}"
            );
            let mut wiped = key;
            assert!(TripleDes::new_3key_wiping(&mut wiped).is_err());
            // The caller's key is erased even when the key is rejected.
            assert_eq!(wiped, [0u8; 24]);
        }
        // Three distinct components are accepted, and the screen order is
        // weak-key first.
        assert!(TripleDes::new_3key(&cat3(&KA, &KB, &KC)).is_ok());
        assert!(TripleDesCt::new_3key(&cat3(&KA, &KB, &KC)).is_ok());
        let weak_twice = cat3(&[0x01; 8], &[0x01; 8], &KC);
        assert_eq!(
            TripleDes::new_3key(&weak_twice).err(),
            Some(DesKeyError::WeakOrSemiWeakKey)
        );
    }

    #[test]
    fn tdes_2key_rejects_equal_halves() {
        for (key, why) in [
            (cat2(&KA, &KA), "K1 = K2"),
            (cat2(&KA, &ka_parity_flipped()), "K1 = K2 up to parity"),
        ] {
            assert_eq!(
                TripleDes::new_2key(&key).err(),
                Some(DesKeyError::RepeatedKeyComponent),
                "TripleDes must reject {why}"
            );
            assert_eq!(
                TripleDesCt::new_2key(&key).err(),
                Some(DesKeyError::RepeatedKeyComponent),
                "TripleDesCt must reject {why}"
            );
            let mut wiped = key;
            assert!(TripleDesCt::new_2key_wiping(&mut wiped).is_err());
            assert_eq!(wiped, [0u8; 16]);
        }
        assert!(TripleDes::new_2key(&cat2(&KA, &KB)).is_ok());
        assert!(TripleDesCt::new_2key(&cat2(&KA, &KB)).is_ok());
    }

    #[test]
    fn tdes_mode_reports_keying_option() {
        assert_eq!(
            TripleDes::new_3key(&cat3(&KA, &KB, &KC)).unwrap().mode(),
            TDesMode::ThreeKey
        );
        assert_eq!(
            TripleDes::new_2key(&cat2(&KA, &KB)).unwrap().mode(),
            TDesMode::TwoKey
        );
        assert_eq!(
            TripleDes::new_single_key(&KA).unwrap().mode(),
            TDesMode::SingleKey
        );
        assert_eq!(
            TripleDesCt::new_single_key_unchecked(&[0x01; 8]).mode(),
            TDesMode::SingleKey
        );
        let mut buf = cat3(&KA, &KB, &KC);
        let cipher = TripleDesCt::new_3key_wiping(&mut buf).unwrap();
        assert_eq!(cipher.mode(), TDesMode::ThreeKey);
        assert_eq!(buf, [0u8; 24]);
    }
}
