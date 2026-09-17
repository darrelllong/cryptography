//! CAST-128 / CAST5 block cipher — RFC 2144.
//!
//! 64-bit block cipher with variable key sizes from 40 to 128 bits in 8-bit
//! increments. The default `Cast128::new` constructor uses the full 128-bit
//! key size and therefore all 16 rounds. `with_key_bytes` supports the RFC's
//! shorter key sizes and automatically drops to 12 rounds for keys up to
//! and including 80 bits.
//!
//! The fast path keeps the direct 8-bit S-box tables from RFC 2144 Appendix A.
//! `Cast128Ct` uses a fixed-scan table selection helper so the round function
//! and key schedule avoid secret-indexed table reads in portable software.

use crate::ct::{ct_lookup_u32, zeroize_slice};
use crate::BlockCipher;

include!("cast128_tables.rs");

/// CAST-128 enciphers a 64-bit block (RFC 2144 §2.1); its key sizes are named
/// with the schedule below.
const BLOCK_BYTES: usize = 8;

/// Keys of 80 bits or less take twelve rounds, longer keys sixteen
/// (RFC 2144 §2.5).
const SHORT_KEY_BITS: usize = 80;
const SHORT_KEY_ROUNDS: usize = 12;
const ROUNDS: usize = 16;

/// The key schedule runs two x/z cycles, each emitting sixteen of the RFC's
/// intermediate `K` words: masking subkeys first, then rotation subkeys.
const SCHEDULE_CYCLES: usize = 2;
const WORDS_PER_CYCLE: usize = 16;

#[inline]
fn sbox(table: &[u32; 256], idx: u8, use_ct: bool) -> u32 {
    if use_ct {
        ct_lookup_u32(table, idx)
    } else {
        table[idx as usize]
    }
}

#[inline]
fn pack(bytes: &[u8; MAX_KEY_BYTES], a: usize, b: usize, c: usize, d: usize) -> u32 {
    u32::from_be_bytes([bytes[a], bytes[b], bytes[c], bytes[d]])
}

#[inline]
fn unpack(bytes: &mut [u8; MAX_KEY_BYTES], start: usize, value: u32) {
    bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

// The RFC key schedule alternates between 16-byte `x` and `z` states; these
// helpers implement those byte-to-byte recurrences directly so the published
// K1..K32 formulas stay readable. Each writes into a caller-owned buffer, so
// the key-derived states and intermediate K words live only in the caller's
// frame, where the key schedule wipes them.
fn x_to_z(x: &[u8; MAX_KEY_BYTES], z: &mut [u8; MAX_KEY_BYTES], use_ct: bool) {
    let w0 = pack(x, 0, 1, 2, 3)
        ^ sbox(&S5, x[13], use_ct)
        ^ sbox(&S6, x[15], use_ct)
        ^ sbox(&S7, x[12], use_ct)
        ^ sbox(&S8, x[14], use_ct)
        ^ sbox(&S7, x[8], use_ct);
    unpack(z, 0, w0);

    let w1 = pack(x, 8, 9, 10, 11)
        ^ sbox(&S5, z[0], use_ct)
        ^ sbox(&S6, z[2], use_ct)
        ^ sbox(&S7, z[1], use_ct)
        ^ sbox(&S8, z[3], use_ct)
        ^ sbox(&S8, x[10], use_ct);
    unpack(z, 4, w1);

    let w2 = pack(x, 12, 13, 14, 15)
        ^ sbox(&S5, z[7], use_ct)
        ^ sbox(&S6, z[6], use_ct)
        ^ sbox(&S7, z[5], use_ct)
        ^ sbox(&S8, z[4], use_ct)
        ^ sbox(&S5, x[9], use_ct);
    unpack(z, 8, w2);

    let w3 = pack(x, 4, 5, 6, 7)
        ^ sbox(&S5, z[10], use_ct)
        ^ sbox(&S6, z[9], use_ct)
        ^ sbox(&S7, z[11], use_ct)
        ^ sbox(&S8, z[8], use_ct)
        ^ sbox(&S6, x[11], use_ct);
    unpack(z, 12, w3);
}

fn z_to_x(z: &[u8; MAX_KEY_BYTES], x: &mut [u8; MAX_KEY_BYTES], use_ct: bool) {
    let w0 = pack(z, 8, 9, 10, 11)
        ^ sbox(&S5, z[5], use_ct)
        ^ sbox(&S6, z[7], use_ct)
        ^ sbox(&S7, z[4], use_ct)
        ^ sbox(&S8, z[6], use_ct)
        ^ sbox(&S7, z[0], use_ct);
    unpack(x, 0, w0);

    let w1 = pack(z, 0, 1, 2, 3)
        ^ sbox(&S5, x[0], use_ct)
        ^ sbox(&S6, x[2], use_ct)
        ^ sbox(&S7, x[1], use_ct)
        ^ sbox(&S8, x[3], use_ct)
        ^ sbox(&S8, z[2], use_ct);
    unpack(x, 4, w1);

    let w2 = pack(z, 4, 5, 6, 7)
        ^ sbox(&S5, x[7], use_ct)
        ^ sbox(&S6, x[6], use_ct)
        ^ sbox(&S7, x[5], use_ct)
        ^ sbox(&S8, x[4], use_ct)
        ^ sbox(&S5, z[1], use_ct);
    unpack(x, 8, w2);

    let w3 = pack(z, 12, 13, 14, 15)
        ^ sbox(&S5, x[10], use_ct)
        ^ sbox(&S6, x[9], use_ct)
        ^ sbox(&S7, x[11], use_ct)
        ^ sbox(&S8, x[8], use_ct)
        ^ sbox(&S6, z[3], use_ct);
    unpack(x, 12, w3);
}

fn extract_z_a(z: &[u8; MAX_KEY_BYTES], use_ct: bool, out: &mut [u32]) {
    out[0] = sbox(&S5, z[8], use_ct)
        ^ sbox(&S6, z[9], use_ct)
        ^ sbox(&S7, z[7], use_ct)
        ^ sbox(&S8, z[6], use_ct)
        ^ sbox(&S5, z[2], use_ct);
    out[1] = sbox(&S5, z[10], use_ct)
        ^ sbox(&S6, z[11], use_ct)
        ^ sbox(&S7, z[5], use_ct)
        ^ sbox(&S8, z[4], use_ct)
        ^ sbox(&S6, z[6], use_ct);
    out[2] = sbox(&S5, z[12], use_ct)
        ^ sbox(&S6, z[13], use_ct)
        ^ sbox(&S7, z[3], use_ct)
        ^ sbox(&S8, z[2], use_ct)
        ^ sbox(&S7, z[9], use_ct);
    out[3] = sbox(&S5, z[14], use_ct)
        ^ sbox(&S6, z[15], use_ct)
        ^ sbox(&S7, z[1], use_ct)
        ^ sbox(&S8, z[0], use_ct)
        ^ sbox(&S8, z[12], use_ct);
}

fn extract_x_a(x: &[u8; MAX_KEY_BYTES], use_ct: bool, out: &mut [u32]) {
    out[0] = sbox(&S5, x[3], use_ct)
        ^ sbox(&S6, x[2], use_ct)
        ^ sbox(&S7, x[12], use_ct)
        ^ sbox(&S8, x[13], use_ct)
        ^ sbox(&S5, x[8], use_ct);
    out[1] = sbox(&S5, x[1], use_ct)
        ^ sbox(&S6, x[0], use_ct)
        ^ sbox(&S7, x[14], use_ct)
        ^ sbox(&S8, x[15], use_ct)
        ^ sbox(&S6, x[13], use_ct);
    out[2] = sbox(&S5, x[7], use_ct)
        ^ sbox(&S6, x[6], use_ct)
        ^ sbox(&S7, x[8], use_ct)
        ^ sbox(&S8, x[9], use_ct)
        ^ sbox(&S7, x[3], use_ct);
    out[3] = sbox(&S5, x[5], use_ct)
        ^ sbox(&S6, x[4], use_ct)
        ^ sbox(&S7, x[10], use_ct)
        ^ sbox(&S8, x[11], use_ct)
        ^ sbox(&S8, x[7], use_ct);
}

fn extract_z_b(z: &[u8; MAX_KEY_BYTES], use_ct: bool, out: &mut [u32]) {
    out[0] = sbox(&S5, z[3], use_ct)
        ^ sbox(&S6, z[2], use_ct)
        ^ sbox(&S7, z[12], use_ct)
        ^ sbox(&S8, z[13], use_ct)
        ^ sbox(&S5, z[9], use_ct);
    out[1] = sbox(&S5, z[1], use_ct)
        ^ sbox(&S6, z[0], use_ct)
        ^ sbox(&S7, z[14], use_ct)
        ^ sbox(&S8, z[15], use_ct)
        ^ sbox(&S6, z[12], use_ct);
    out[2] = sbox(&S5, z[7], use_ct)
        ^ sbox(&S6, z[6], use_ct)
        ^ sbox(&S7, z[8], use_ct)
        ^ sbox(&S8, z[9], use_ct)
        ^ sbox(&S7, z[2], use_ct);
    out[3] = sbox(&S5, z[5], use_ct)
        ^ sbox(&S6, z[4], use_ct)
        ^ sbox(&S7, z[10], use_ct)
        ^ sbox(&S8, z[11], use_ct)
        ^ sbox(&S8, z[6], use_ct);
}

fn extract_x_b(x: &[u8; MAX_KEY_BYTES], use_ct: bool, out: &mut [u32]) {
    out[0] = sbox(&S5, x[8], use_ct)
        ^ sbox(&S6, x[9], use_ct)
        ^ sbox(&S7, x[7], use_ct)
        ^ sbox(&S8, x[6], use_ct)
        ^ sbox(&S5, x[3], use_ct);
    out[1] = sbox(&S5, x[10], use_ct)
        ^ sbox(&S6, x[11], use_ct)
        ^ sbox(&S7, x[5], use_ct)
        ^ sbox(&S8, x[4], use_ct)
        ^ sbox(&S6, x[7], use_ct);
    out[2] = sbox(&S5, x[12], use_ct)
        ^ sbox(&S6, x[13], use_ct)
        ^ sbox(&S7, x[3], use_ct)
        ^ sbox(&S8, x[2], use_ct)
        ^ sbox(&S7, x[8], use_ct);
    out[3] = sbox(&S5, x[14], use_ct)
        ^ sbox(&S6, x[15], use_ct)
        ^ sbox(&S7, x[1], use_ct)
        ^ sbox(&S8, x[0], use_ct)
        ^ sbox(&S8, x[13], use_ct);
}

fn round_f(data: u32, km: u32, kr: u8, round: usize, use_ct: bool) -> u32 {
    // CAST cycles through three different mixing formulas. The modulo on the
    // round index is the exact RFC rule for selecting F1 / F2 / F3.
    let i = match round % 3 {
        0 => km.wrapping_add(data).rotate_left(u32::from(kr)),
        1 => (km ^ data).rotate_left(u32::from(kr)),
        _ => km.wrapping_sub(data).rotate_left(u32::from(kr)),
    };
    let [ia, ib, ic, id] = i.to_be_bytes();
    match round % 3 {
        0 => (sbox(&S1, ia, use_ct) ^ sbox(&S2, ib, use_ct))
            .wrapping_sub(sbox(&S3, ic, use_ct))
            .wrapping_add(sbox(&S4, id, use_ct)),
        1 => {
            (sbox(&S1, ia, use_ct).wrapping_sub(sbox(&S2, ib, use_ct)))
                .wrapping_add(sbox(&S3, ic, use_ct))
                ^ sbox(&S4, id, use_ct)
        }
        _ => ((sbox(&S1, ia, use_ct).wrapping_add(sbox(&S2, ib, use_ct))) ^ sbox(&S3, ic, use_ct))
            .wrapping_sub(sbox(&S4, id, use_ct)),
    }
}

/// CAST-128 masking (`km`) and rotation (`kr`) subkeys plus the round count.
///
/// Not `Copy`, so it is never silently duplicated by value; it wipes itself on
/// drop, which covers both `Cast128` and `Cast128Ct`.
struct Subkeys {
    km: [u32; 16],
    kr: [u8; 16],
    rounds: usize,
}

impl Subkeys {
    /// An all-zero schedule, to be filled in place by [`expand_subkeys`].
    const fn empty() -> Self {
        Self {
            km: [0u32; 16],
            kr: [0u8; 16],
            rounds: 0,
        }
    }
}

impl Drop for Subkeys {
    fn drop(&mut self) {
        zeroize_slice(&mut self.km);
        zeroize_slice(&mut self.kr);
    }
}

/// Shortest key RFC 2144 §2.5 admits, in bytes (40 bits).
const MIN_KEY_BYTES: usize = 5;
/// Longest key RFC 2144 §2.5 admits, in bytes (128 bits).
const MAX_KEY_BYTES: usize = 16;

/// RFC 2144 §2.5 admits key sizes of 40 to 128 bits in 8-bit steps.
const fn key_len_is_valid(len: usize) -> bool {
    len >= MIN_KEY_BYTES && len <= MAX_KEY_BYTES
}

fn check_key_len(len: usize) {
    assert!(
        key_len_is_valid(len),
        "CAST-128 key length must be {MIN_KEY_BYTES}..={MAX_KEY_BYTES} bytes, got {len}"
    );
}

/// Expand a 5- to 16-byte key into `subkeys` (the caller's struct field).
/// Panics if the key length is outside RFC 2144 §2.5's range.
fn expand_subkeys(key: &[u8], use_ct: bool, subkeys: &mut Subkeys) {
    check_key_len(key.len());

    let mut x = [0u8; MAX_KEY_BYTES];
    x[..key.len()].copy_from_slice(key);
    // RFC 2144 §2.5: keys shorter than 128 bits are padded with zero bytes in
    // the least significant positions, and keys of 80 bits or less use 12
    // rounds instead of 16.
    subkeys.rounds = if key.len() * 8 <= SHORT_KEY_BITS {
        SHORT_KEY_ROUNDS
    } else {
        ROUNDS
    };

    let mut z = [0u8; MAX_KEY_BYTES];
    let mut k = [0u32; SCHEDULE_CYCLES * WORDS_PER_CYCLE];
    let mut offset = 0usize;

    for _ in 0..SCHEDULE_CYCLES {
        x_to_z(&x, &mut z, use_ct);
        extract_z_a(&z, use_ct, &mut k[offset..offset + 4]);
        z_to_x(&z, &mut x, use_ct);
        extract_x_a(&x, use_ct, &mut k[offset + 4..offset + 8]);
        x_to_z(&x, &mut z, use_ct);
        extract_z_b(&z, use_ct, &mut k[offset + 8..offset + 12]);
        z_to_x(&z, &mut x, use_ct);
        extract_x_b(&x, use_ct, &mut k[offset + 12..offset + 16]);
        offset += WORDS_PER_CYCLE;
    }

    let mut i = 0usize;
    while i < 16 {
        subkeys.km[i] = k[i];
        subkeys.kr[i] = (k[16 + i] & 0x1f) as u8;
        i += 1;
    }

    // `x` starts as the padded key, and `z` and `k` are its expansions: only
    // the subkeys may outlive this call.
    zeroize_slice(&mut x);
    zeroize_slice(&mut z);
    zeroize_slice(&mut k);
}

fn cast_encrypt(block: [u8; 8], subkeys: &Subkeys, use_ct: bool) -> [u8; BLOCK_BYTES] {
    let mut l = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut r = u32::from_be_bytes(block[4..8].try_into().unwrap());

    let mut i = 0usize;
    while i < subkeys.rounds {
        // Standard Feistel step: the right half becomes the next left half,
        // and the previous left half is mixed with F(right, subkey).
        let new_l = r;
        let new_r = l ^ round_f(r, subkeys.km[i], subkeys.kr[i], i, use_ct);
        l = new_l;
        r = new_r;
        i += 1;
    }

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&r.to_be_bytes());
    out[4..8].copy_from_slice(&l.to_be_bytes());
    out
}

fn cast_decrypt(block: [u8; 8], subkeys: &Subkeys, use_ct: bool) -> [u8; BLOCK_BYTES] {
    let mut l = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut r = u32::from_be_bytes(block[4..8].try_into().unwrap());

    let mut idx = subkeys.rounds;
    while idx > 0 {
        idx -= 1;
        // Decryption is the same Feistel structure with the round keys applied
        // in reverse order.
        let new_l = r;
        let new_r = l ^ round_f(r, subkeys.km[idx], subkeys.kr[idx], idx, use_ct);
        l = new_l;
        r = new_r;
    }

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&r.to_be_bytes());
    out[4..8].copy_from_slice(&l.to_be_bytes());
    out
}

/// CAST-128 fast software path: 64-bit block Feistel cipher of RFC 2144,
/// using the direct S-box tables from Appendix A (not constant-time).
pub struct Cast128 {
    subkeys: Subkeys,
}

impl Cast128 {
    /// Expand a full-length 16-byte (128-bit) key into the masking and
    /// rotation subkeys, written directly into the new instance; the cipher
    /// then runs all 16 rounds.
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self::with_key_bytes(key)
    }

    /// Expand a variable-length key of 5 to 16 bytes, the CAST5-40 through
    /// CAST5-128 range of RFC 2144 §2.5. Keys of 80 bits or less run 12
    /// rounds instead of 16. Panics if `key.len()` is outside `5..=16`.
    #[must_use]
    pub fn with_key_bytes(key: &[u8]) -> Self {
        let mut cipher = Self {
            subkeys: Subkeys::empty(),
        };
        expand_subkeys(key, false, &mut cipher.subkeys);
        cipher
    }

    /// Expand the key as `with_key_bytes` does, then wipe the caller-owned
    /// key buffer. The buffer is wiped whatever its length; if `key.len()`
    /// is outside `5..=16` the panic follows the wipe.
    pub fn with_key_bytes_wiping(key: &mut [u8]) -> Self {
        let mut cipher = Self {
            subkeys: Subkeys::empty(),
        };
        if key_len_is_valid(key.len()) {
            expand_subkeys(key, false, &mut cipher.subkeys);
        }
        zeroize_slice(key);
        check_key_len(key.len());
        cipher
    }

    /// Expand the key as `new` does, then wipe the caller-owned key buffer.
    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        zeroize_slice(key);
        out
    }

    /// Encrypt one 8-byte block through the 12 or 16 Feistel rounds selected
    /// by the key size; not constant-time.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        cast_encrypt(*block, &self.subkeys, false)
    }

    /// Decrypt one 8-byte block by applying the rounds with the subkeys in
    /// reverse order; not constant-time.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        cast_decrypt(*block, &self.subkeys, false)
    }
}

impl BlockCipher for Cast128 {
    const BLOCK_LEN: usize = 8;

    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let ct = self.encrypt_block(arr);
        block.copy_from_slice(&ct);
    }

    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let pt = self.decrypt_block(arr);
        block.copy_from_slice(&pt);
    }
}

/// CAST-128 constant-time software path: every S-box lookup scans the whole
/// 256-entry table with masked selection, so neither the rounds nor the key
/// schedule perform secret-indexed table reads (slower than `Cast128`).
pub struct Cast128Ct {
    subkeys: Subkeys,
}

impl Cast128Ct {
    /// Expand a full-length 16-byte (128-bit) key into the masking and
    /// rotation subkeys with fixed-scan S-box lookups, written directly into
    /// the new instance; all 16 rounds are used.
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self::with_key_bytes(key)
    }

    /// Expand a variable-length key of 5 to 16 bytes, the CAST5-40 through
    /// CAST5-128 range of RFC 2144 §2.5, with fixed-scan S-box lookups. Keys
    /// of 80 bits or less run 12 rounds instead of 16. Panics if `key.len()`
    /// is outside `5..=16`.
    #[must_use]
    pub fn with_key_bytes(key: &[u8]) -> Self {
        let mut cipher = Self {
            subkeys: Subkeys::empty(),
        };
        expand_subkeys(key, true, &mut cipher.subkeys);
        cipher
    }

    /// Expand the key as `with_key_bytes` does, then wipe the caller-owned
    /// key buffer. The buffer is wiped whatever its length; if `key.len()`
    /// is outside `5..=16` the panic follows the wipe.
    pub fn with_key_bytes_wiping(key: &mut [u8]) -> Self {
        let mut cipher = Self {
            subkeys: Subkeys::empty(),
        };
        if key_len_is_valid(key.len()) {
            expand_subkeys(key, true, &mut cipher.subkeys);
        }
        zeroize_slice(key);
        check_key_len(key.len());
        cipher
    }

    /// Expand the key as `new` does, then wipe the caller-owned key buffer.
    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        zeroize_slice(key);
        out
    }

    /// Encrypt one 8-byte block through the 12 or 16 Feistel rounds selected
    /// by the key size, with fixed-scan S-box lookups in place of direct
    /// indexing.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        cast_encrypt(*block, &self.subkeys, true)
    }

    /// Decrypt one 8-byte block by applying the rounds with the subkeys in
    /// reverse order, with fixed-scan S-box lookups in place of direct
    /// indexing.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        cast_decrypt(*block, &self.subkeys, true)
    }
}

impl BlockCipher for Cast128Ct {
    const BLOCK_LEN: usize = 8;

    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let ct = self.encrypt_block(arr);
        block.copy_from_slice(&ct);
    }

    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let pt = self.decrypt_block(arr);
        block.copy_from_slice(&pt);
    }
}

/// RFC 2144 also names this cipher CAST5; alias for `Cast128`.
pub type Cast5 = Cast128;
/// Constant-time CAST5 alias for `Cast128Ct`.
pub type Cast5Ct = Cast128Ct;

#[cfg(test)]
mod tests {
    // Known answers: RFC 2144 Appendix B.1, the single plaintext/key/ciphertext
    // sets for 128-, 80- and 40-bit keys, and Appendix B.2, the Full
    // Maintenance Test. `cast128_matches_openssl_ecb` is a cross-check against
    // OpenSSL's `cast5-ecb`, not a known answer.
    use super::*;
    use crate::test_utils::decode_hex;

    /// RFC 2144 Appendix B.2, Full Maintenance Test: 1,000,000 iterations in
    /// which the halves of `a` are encrypted under key `b` and then the
    /// halves of `b` under key `a`. Each iteration re-keys twice, so the run
    /// is 2,000,000 key schedules and 4,000,000 block encryptions.
    #[test]
    #[ignore = "RFC 2144 B.2 Full Maintenance Test: 2,000,000 key schedules and 4,000,000 encryptions; run with `cargo test --release -- --ignored`"]
    fn cast128_full_maintenance_test() {
        let mut a: [u8; 16] = decode_hex("0123456712345678234567893456789A")
            .try_into()
            .unwrap();
        let mut b = a;
        for _ in 0..1_000_000 {
            let under_b = Cast128::new(&b);
            let (al, ar) = a.split_at_mut(8);
            under_b.encrypt(al);
            under_b.encrypt(ar);
            let under_a = Cast128::new(&a);
            let (bl, br) = b.split_at_mut(8);
            under_a.encrypt(bl);
            under_a.encrypt(br);
        }
        assert_eq!(a.to_vec(), decode_hex("EEA9D0A249FD3BA6B3436FB89D6DCA92"));
        assert_eq!(b.to_vec(), decode_hex("B2C95EB00C31AD7180AC05B8E83D696E"));
    }

    #[test]
    #[should_panic(expected = "CAST-128 key length must be 5..=16 bytes, got 4")]
    fn key_length_below_range_rejected() {
        let _ = Cast128::with_key_bytes(&[0u8; 4]);
    }

    #[test]
    #[should_panic(expected = "CAST-128 key length must be 5..=16 bytes, got 17")]
    fn key_length_above_range_rejected() {
        let _ = Cast128Ct::with_key_bytes(&[0u8; 17]);
    }

    #[test]
    #[should_panic(expected = "CAST-128 key length must be 5..=16 bytes, got 0")]
    fn empty_key_rejected() {
        let _ = Cast128::with_key_bytes(&[]);
    }

    /// `with_key_bytes_wiping` clears the caller's buffer even when it then
    /// panics on the key length.
    #[test]
    fn wiping_constructor_wipes_before_rejecting() {
        let mut key = [0xA5u8; 17];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Cast128::with_key_bytes_wiping(&mut key)
        }));
        assert!(result.is_err(), "length 17 must be rejected");
        assert_eq!(key, [0u8; 17], "key buffer wiped despite the rejection");

        let mut key = [0xA5u8; 16];
        let cipher = Cast128Ct::with_key_bytes_wiping(&mut key);
        assert_eq!(key, [0u8; 16]);
        assert_eq!(
            cipher.encrypt_block(&[0u8; 8]),
            Cast128Ct::new(&[0xA5u8; 16]).encrypt_block(&[0u8; 8])
        );
    }

    /// The `BlockCipher` entry points reject a wrong-length block.
    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_rejects_wrong_length() {
        let cipher = Cast128::new(&[0u8; 16]);
        let mut long = [0u8; 16];
        cipher.encrypt(&mut long);
    }

    #[test]
    fn cast128_128bit_kat() {
        let key: [u8; 16] = decode_hex("0123456712345678234567893456789A")
            .try_into()
            .unwrap();
        let pt: [u8; 8] = decode_hex("0123456789ABCDEF").try_into().unwrap();
        let ct: [u8; 8] = decode_hex("238B4FE5847E44B2").try_into().unwrap();
        let cipher = Cast128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        let cipher_ct = Cast128Ct::new(&key);
        assert_eq!(cipher_ct.encrypt_block(&pt), ct);
        assert_eq!(cipher_ct.decrypt_block(&ct), pt);
    }

    #[test]
    fn cast128_80bit_kat() {
        let key = decode_hex("01234567123456782345");
        let pt: [u8; 8] = decode_hex("0123456789ABCDEF").try_into().unwrap();
        let ct: [u8; 8] = decode_hex("EB6A711A2C02271B").try_into().unwrap();
        let cipher = Cast128::with_key_bytes(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        let cipher_ct = Cast128Ct::with_key_bytes(&key);
        assert_eq!(cipher_ct.encrypt_block(&pt), ct);
        assert_eq!(cipher_ct.decrypt_block(&ct), pt);
    }

    #[test]
    fn cast128_40bit_kat() {
        let key = decode_hex("0123456712");
        let pt: [u8; 8] = decode_hex("0123456789ABCDEF").try_into().unwrap();
        let ct: [u8; 8] = decode_hex("7AC816D16E9B302E").try_into().unwrap();
        let cipher = Cast128::with_key_bytes(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        let cipher_ct = Cast128Ct::with_key_bytes(&key);
        assert_eq!(cipher_ct.encrypt_block(&pt), ct);
        assert_eq!(cipher_ct.decrypt_block(&ct), pt);
    }

    #[test]
    fn cast128_matches_openssl_ecb() {
        let key_hex = "0123456712345678234567893456789a";
        let pt_hex = "0123456789abcdef";
        let pt: [u8; 8] = decode_hex(pt_hex).try_into().unwrap();
        let Some(expected) = crate::test_utils::openssl_enc("-cast5-ecb", key_hex, None, &pt)
            .or_skip("cast128_matches_openssl_ecb")
        else {
            return;
        };

        let key: [u8; 16] = decode_hex(key_hex).try_into().unwrap();
        let cipher = Cast128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt).as_slice(), expected.as_slice());
    }
}
