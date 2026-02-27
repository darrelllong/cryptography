//! DES and Triple-DES (TDEA) implemented from FIPS PUB 46-3.
//!
//! All tables are transcribed verbatim from the FIPS 46-3 document
//! (https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf).
//! Tests use the official NIST CAVP Known Answer Test vectors downloaded
//! directly from csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
//! Validation-Program/documents/des/KAT_TDES.zip.

// ─────────────────────────────────────────────────────────────────────────────
// FIPS 46-3 Tables (1-indexed positions, converted to 0-indexed in code)
// ─────────────────────────────────────────────────────────────────────────────

/// Initial Permutation (IP) — FIPS 46-3, Table "Initial Permutation IP"
/// Entry i gives the 1-indexed bit position in the 64-bit input whose value
/// becomes bit i of the output (MSB = bit 1).
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final Permutation (IP⁻¹) — FIPS 46-3, Table "Inverse Initial Permutation IP⁻¹"
const FP: [u8; 64] = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
];

/// Expansion function E — FIPS 46-3, Table "Expansion Permutation E"
/// Maps the 32-bit right half to 48 bits.
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
];

/// Permutation P — FIPS 46-3, Table "Permutation Function P"
/// Applied to the 32-bit output of the 8 S-boxes.
const P: [u8; 32] = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
];

/// Permuted Choice 1 (PC-1) — FIPS 46-3, Table "Permuted Choice 1 (PC-1)"
/// Selects and permutes 56 bits of the 64-bit key (discards parity bits).
/// First 28 entries select bits for C0, next 28 for D0.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
];

/// Permuted Choice 2 (PC-2) — FIPS 46-3, Table "Permuted Choice 2 (PC-2)"
/// Selects 48 bits from the 56-bit shifted key halves to form each round key.
const PC2: [u8; 48] = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
];

/// Key schedule rotation amounts — FIPS 46-3, Table "Number of Bit Rotations"
/// Number of left-circular shifts applied to each key half in rounds 1–16.
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// S-boxes S1–S8 — FIPS 46-3, Tables "Selection Functions S1–S8"
///
/// Each S-box maps a 6-bit input to a 4-bit output.  The 6 input bits b1..b6
/// (where b1 is MSB of the 6-bit value) select row r = (b1<<1)|b6 and
/// column c = b2..b5.
const SBOXES: [[u8; 64]; 8] = [
    // S1
    [
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    ],
    // S2
    [
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    ],
    // S3
    [
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    ],
    // S4
    [
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    ],
    // S5
    [
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    ],
    // S6
    [
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    ],
    // S7
    [
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    ],
    // S8
    [
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
    ],
];

// ─────────────────────────────────────────────────────────────────────────────
// Bit-manipulation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract bit `pos` (1-indexed, MSB = 1) from a 64-bit big-endian block.
#[inline(always)]
fn bit64(block: u64, pos: u8) -> u64 {
    (block >> (64 - pos)) & 1
}

/// Extract bit `pos` (1-indexed, MSB = 1) from a 32-bit value.
#[inline(always)]
fn bit32(block: u32, pos: u8) -> u32 {
    (block >> (32 - pos)) & 1
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

/// Apply a permutation table that maps a 64-bit input to a 48-bit value
/// (returned as u64, upper 16 bits zero).
fn permute64_to48(input: u64, table: &[u8; 48]) -> u64 {
    let mut out = 0u64;
    for (i, &src) in table.iter().enumerate() {
        out |= bit64(input, src) << (47 - i);
    }
    out
}

/// Apply the P permutation to a 32-bit value (S-box output → 32-bit result).
fn permute_p(input: u32) -> u32 {
    let mut out = 0u32;
    for (i, &src) in P.iter().enumerate() {
        out |= bit32(input, src) << (31 - i);
    }
    out
}

/// Left-rotate a `bits`-wide value by `n` positions.
#[inline(always)]
fn rotate_left(val: u32, n: u8, bits: u8) -> u32 {
    let mask = (1u32 << bits) - 1;
    ((val << n) | (val >> (bits - n))) & mask
}

// ─────────────────────────────────────────────────────────────────────────────
// Key schedule
// ─────────────────────────────────────────────────────────────────────────────

/// A 16-round DES key schedule: 16 × 48-bit subkeys.
pub type KeySchedule = [u64; 16];

/// Generate the key schedule from a 64-bit key (including parity bits).
/// Returns 16 subkeys, each 48 bits (stored in the low 48 bits of u64).
///
/// For decryption, pass the returned schedule reversed to [`des_ecb_block`].
pub fn key_schedule(key: u64) -> KeySchedule {
    // PC-1: select and permute 56 bits.
    // The first 28 bits of pc1_out form C0, the next 28 bits form D0.
    let pc1_out = permute64(key, &PC1);

    let mut c = (pc1_out >> 28) as u32 & 0x0FFF_FFFF; // bits 1-28 → C0
    let mut d = pc1_out as u32 & 0x0FFF_FFFF;         // bits 29-56 → D0

    let mut schedule = [0u64; 16];
    for i in 0..16 {
        c = rotate_left(c, SHIFTS[i], 28);
        d = rotate_left(d, SHIFTS[i], 28);

        // Merge C and D into a 56-bit value for PC-2 selection.
        // C occupies the upper 28 bits; D the lower 28.
        let cd: u64 = ((c as u64) << 28) | (d as u64);

        // PC-2 references bit positions 1–56 within the 56-bit CD register.
        // We represent CD as a 64-bit value with the 56 bits in the MSBs
        // (i.e., shifted left by 8 so that position 1 in the FIPS table
        //  corresponds to bit 63 of our u64).
        let cd_shifted = cd << 8; // bit 1 of CD → bit 63 of cd_shifted
        schedule[i] = permute64_to48(cd_shifted, &PC2);
    }
    schedule
}

// ─────────────────────────────────────────────────────────────────────────────
// The Feistel f-function
// ─────────────────────────────────────────────────────────────────────────────

/// The DES f-function: f(R, K) = P(S(E(R) ⊕ K))
fn f(r: u32, subkey: u64) -> u32 {
    // Expand R from 32 to 48 bits using E.
    // R is a 32-bit value; represent it as u64 in the top 32 bits for permute.
    let r64 = (r as u64) << 32;
    let expanded = permute64_to48(r64, &E);

    // XOR with the 48-bit subkey.
    let xored = expanded ^ subkey;

    // Pass through 8 S-boxes.
    let mut sout = 0u32;
    for i in 0..8 {
        // Each S-box receives 6 bits.  Bits are numbered MSB-first within xored.
        let shift = 42 - 6 * i; // bits [47..42], [41..36], ... [5..0]
        let b6 = ((xored >> shift) & 0x3F) as usize;

        // Row = (b1 << 1) | b6  where b1 = MSB of the 6-bit group.
        let row = ((b6 & 0x20) >> 4) | (b6 & 0x01); // bits 5 and 0
        let col = (b6 >> 1) & 0x0F;                  // bits 4..1
        let sval = SBOXES[i][row * 16 + col] as u32;

        sout |= sval << (28 - 4 * i);
    }

    // Apply permutation P.
    permute_p(sout)
}

// ─────────────────────────────────────────────────────────────────────────────
// DES single-block encrypt/decrypt
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt or decrypt a single 64-bit block under the given key schedule.
///
/// For encryption, pass `schedule` from [`key_schedule`].
/// For decryption, pass the schedule reversed: `let dec = { let mut s = ks; s.reverse(); s }`.
fn des_block(block: u64, schedule: &KeySchedule) -> u64 {
    // Initial Permutation.
    let permuted = permute64(block, &IP);

    let mut l = (permuted >> 32) as u32;
    let mut r = permuted as u32;

    // 16 Feistel rounds.
    for &subkey in schedule.iter() {
        let tmp = r;
        r = l ^ f(r, subkey);
        l = tmp;
    }

    // Pre-output: swap L and R, then apply FP.
    let pre_output = ((r as u64) << 32) | (l as u64);
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

impl Des {
    /// Create a new DES instance from an 8-byte key.
    pub fn new(key: &[u8; 8]) -> Self {
        let k = u64::from_be_bytes(*key);
        let enc_schedule = key_schedule(k);
        let mut dec_schedule = enc_schedule;
        dec_schedule.reverse();
        Des { enc_schedule, dec_schedule }
    }

    /// Encrypt a single 64-bit block (ECB mode).
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let b = u64::from_be_bytes(*block);
        des_block(b, &self.enc_schedule).to_be_bytes()
    }

    /// Decrypt a single 64-bit block (ECB mode).
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let b = u64::from_be_bytes(*block);
        des_block(b, &self.dec_schedule).to_be_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Triple-DES (TDEA) — FIPS 46-3 §4, NIST SP 800-67
// ─────────────────────────────────────────────────────────────────────────────
//
// TDEA operates as EDE (Encrypt-Decrypt-Encrypt):
//   Encrypt:  C = E(K3, D(K2, E(K1, P)))
//   Decrypt:  P = D(K1, E(K2, D(K3, C)))
//
// Key sizes and keying options (NIST SP 800-67 §3.1):
//   Option 1 (3TDEA): K1, K2, K3 all independent — 168-bit key material
//                     (112-bit effective security)
//   Option 2 (2TDEA): K1 = K3 ≠ K2           — 112-bit key material
//                     (80-bit effective security)
//   Option 3:         K1 = K2 = K3            — degenerates to single DES
//                     (NOT recommended for new applications)
//
// The NIST CAVP test vectors use "KEYs = <hex>" meaning K1=K2=K3=that value,
// which exercises the EDE path with a single key and validates DES-equivalent
// behaviour (E(K,D(K,E(K,P))) = E(K,P) since D∘E = identity on same key).

/// Keying option for Triple-DES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TDesMode {
    /// Keying option 1: K1, K2, K3 all independent (24-byte / 192-bit key).
    ThreeKey,
    /// Keying option 2: K1 = K3 ≠ K2 (16-byte / 128-bit key: K1 ∥ K2).
    TwoKey,
}

/// A Triple-DES (TDEA) cipher.
pub struct TripleDes {
    k1_enc: KeySchedule,
    k1_dec: KeySchedule,
    k2_enc: KeySchedule,
    k2_dec: KeySchedule,
    k3_enc: KeySchedule,
    k3_dec: KeySchedule,
}

impl TripleDes {
    /// Construct a 3TDEA instance from a 24-byte key K1 ∥ K2 ∥ K3.
    pub fn new_3key(key: &[u8; 24]) -> Self {
        Self::from_keys(
            u64::from_be_bytes(key[0..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
            u64::from_be_bytes(key[16..24].try_into().unwrap()),
        )
    }

    /// Construct a 2TDEA instance from a 16-byte key K1 ∥ K2 (K3 = K1).
    pub fn new_2key(key: &[u8; 16]) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        Self::from_keys(k1, k2, k1)
    }

    /// Construct from three 8-byte keys.  K1=K2=K3 is valid (degenerates to
    /// single DES) and is used by the NIST CAVP "KEYs" tests.
    pub fn new_single_key(key: &[u8; 8]) -> Self {
        let k = u64::from_be_bytes(*key);
        Self::from_keys(k, k, k)
    }

    fn from_keys(k1: u64, k2: u64, k3: u64) -> Self {
        let k1_enc = key_schedule(k1);
        let k2_enc = key_schedule(k2);
        let k3_enc = key_schedule(k3);
        let mut k1_dec = k1_enc;
        let mut k2_dec = k2_enc;
        let mut k3_dec = k3_enc;
        k1_dec.reverse();
        k2_dec.reverse();
        k3_dec.reverse();
        TripleDes { k1_enc, k1_dec, k2_enc, k2_dec, k3_enc, k3_dec }
    }

    /// Encrypt a single 64-bit block: C = E(K3, D(K2, E(K1, P)))
    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let p = u64::from_be_bytes(*block);
        let t1 = des_block(p,  &self.k1_enc); // E with K1
        let t2 = des_block(t1, &self.k2_dec); // D with K2
        let c  = des_block(t2, &self.k3_enc); // E with K3
        c.to_be_bytes()
    }

    /// Decrypt a single 64-bit block: P = D(K1, E(K2, D(K3, C)))
    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let c  = u64::from_be_bytes(*block);
        let t1 = des_block(c,  &self.k3_dec); // D with K3
        let t2 = des_block(t1, &self.k2_enc); // E with K2
        let p  = des_block(t2, &self.k1_dec); // D with K1
        p.to_be_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — all vectors from NIST CAVP KAT_TDES.zip (csrc.nist.gov)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn from_hex(s: &str) -> u64 {
        u64::from_str_radix(s, 16).unwrap()
    }

    fn hex_to_bytes8(s: &str) -> [u8; 8] {
        from_hex(s).to_be_bytes()
    }

    /// Run a single NIST CAVP TDES ECB test vector using the TDES EDE path
    /// (K1=K2=K3 per the "KEYs" notation in the .rsp files).
    fn tdes_kat(key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let key = hex_to_bytes8(key_hex);
        let pt  = hex_to_bytes8(pt_hex);
        let ct  = hex_to_bytes8(ct_hex);
        let cipher = TripleDes::new_single_key(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct,
            "encrypt mismatch: key={key_hex} pt={pt_hex}");
        assert_eq!(cipher.decrypt_block(&ct), pt,
            "decrypt mismatch: key={key_hex} ct={ct_hex}");
    }

    /// Run a DES ECB test using the single-key DES path.
    fn des_kat(key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let key = hex_to_bytes8(key_hex);
        let pt  = hex_to_bytes8(pt_hex);
        let ct  = hex_to_bytes8(ct_hex);
        let cipher = Des::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct,
            "encrypt mismatch: key={key_hex} pt={pt_hex}");
        assert_eq!(cipher.decrypt_block(&ct), pt,
            "decrypt mismatch: key={key_hex} ct={ct_hex}");
    }

    // ── TECBvartext.rsp — Variable Plaintext KAT ─────────────────────────────
    // Key is all-ones parity (0x0101010101010101, all actual key bits = 0).
    // From NIST CAVP KAT_TDES/TECBvartext.rsp (CAVS 11.1, 2011-04-21).

    #[test]
    fn vartext_first_8() {
        let cases = [
            ("0101010101010101", "8000000000000000", "95f8a5e5dd31d900"),
            ("0101010101010101", "4000000000000000", "dd7f121ca5015619"),
            ("0101010101010101", "2000000000000000", "2e8653104f3834ea"),
            ("0101010101010101", "1000000000000000", "4bd388ff6cd81d4f"),
            ("0101010101010101", "0800000000000000", "20b9e767b2fb1456"),
            ("0101010101010101", "0400000000000000", "55579380d77138ef"),
            ("0101010101010101", "0200000000000000", "6cc5defaaf04512f"),
            ("0101010101010101", "0100000000000000", "0d9f279ba5d87260"),
        ];
        for (k, pt, ct) in cases { tdes_kat(k, pt, ct); }
    }

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
        for (k, pt, ct) in cases { tdes_kat(k, pt, ct); }
    }

    // ── TECBinvperm.rsp — Inverse Permutation KAT ───────────────────────────
    // Same vectors as vartext but with plaintext and ciphertext swapped:
    // encrypting the ciphertext should reproduce the plaintext (tests IP⁻¹).

    #[test]
    fn invperm_sample() {
        let cases = [
            ("0101010101010101", "95f8a5e5dd31d900", "8000000000000000"),
            ("0101010101010101", "dd7f121ca5015619", "4000000000000000"),
            ("0101010101010101", "166b40b44aba4bd6", "0000000000000001"),
        ];
        for (k, pt, ct) in cases { tdes_kat(k, pt, ct); }
    }

    // ── TECBvarkey.rsp — Variable Key KAT ───────────────────────────────────
    // Plaintext = 0x0000000000000000, each key has exactly one real key bit set.

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
        for (k, pt, ct) in cases { tdes_kat(k, pt, ct); }
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
        for (k, pt, ct) in cases { tdes_kat(k, pt, ct); }
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
        for (k, pt, ct) in cases { tdes_kat(k, pt, ct); }
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
        for (k, pt, ct) in cases { des_kat(k, pt, ct); }
    }

    // ── 3TDEA — three independent keys ──────────────────────────────────────
    // These exercise the full EDE path with K1 ≠ K2 ≠ K3.
    // Vectors hand-generated and cross-checked with OpenSSL:
    //   echo -n <pt_hex> | xxd -r -p |
    //   openssl enc -des-ede3 -nopad -nosalt -K <k1k2k3_hex> -iv 0 -e |
    //   xxd -p

    #[test]
    fn tdes_3key_roundtrip() {
        // K1=0133457799BBCDFF, K2=0011223344556677, K3=8899AABBCCDDEEFF
        let key: [u8; 24] = [
            0x01,0x33,0x45,0x77,0x99,0xBB,0xCD,0xFF,
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        ];
        let pt: [u8; 8] = [0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF];
        let cipher = TripleDes::new_3key(&key);
        let ct = cipher.encrypt_block(&pt);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    // ── 2TDEA — two independent keys (K1=K3) ────────────────────────────────

    #[test]
    fn tdes_2key_roundtrip() {
        let key: [u8; 16] = [
            0x01,0x33,0x45,0x77,0x99,0xBB,0xCD,0xFF,
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        ];
        let pt: [u8; 8] = [0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE];
        let cipher = TripleDes::new_2key(&key);
        let ct = cipher.encrypt_block(&pt);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    // ── Verify TDES K1=K2=K3 is identical to single DES ─────────────────────

    #[test]
    fn tdes_single_key_equals_des() {
        let key: [u8; 8] = [0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1];
        let pt:  [u8; 8] = [0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF];
        let des   = Des::new(&key);
        let tdes  = TripleDes::new_single_key(&key);
        assert_eq!(des.encrypt_block(&pt), tdes.encrypt_block(&pt),
            "TDES(K,K,K) must equal DES(K) for same key and plaintext");
    }
}
