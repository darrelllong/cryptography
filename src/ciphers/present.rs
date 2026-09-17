//! PRESENT lightweight block cipher — CHES 2007 / ISO/IEC 29192-2.
//!
//! 64-bit block cipher with two standard key schedules:
//!
//! - `Present80` / `Present80Ct`: 80-bit key
//! - `Present128` / `Present128Ct`: 128-bit key
//!
//! The round structure is a 31-round SP-network:
//!
//! ```text
//! state <- state xor round_key
//! state <- sbox_layer(state)
//! state <- p_layer(state)
//! ```
//!
//! followed by a final round-key xor. The fast path keeps the direct 4-bit
//! S-box table lookup. The Ct path uses a packed 16-term ANF form of the same
//! 4->4 bijection so substitution avoids secret-indexed table reads while the
//! rest of the permutation network stays unchanged.

/// PRESENT is a 64-bit block cipher with an 80- or 128-bit key (Bogdanov et
/// al., CHES 2007, §3).
const BLOCK_BYTES: usize = 8;
const BLOCK_BITS: usize = 8 * BLOCK_BYTES;
const KEY80_BYTES: usize = 10;
const KEY128_BYTES: usize = 16;

/// Thirty-one rounds, and a thirty-second key for the final whitening (§3).
const ROUNDS: usize = 31;
const ROUND_KEYS: usize = ROUNDS + 1;

/// The key register rotates left by 61 bits between rounds (§3, key
/// schedules for both key sizes).
const KEY_ROTATION: u32 = 61;

const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];
const INV_SBOX: [u8; 16] = [
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA,
];

const SBOX_ANF: [u16; 4] = crate::ct::build_nibble_sbox_anf(&SBOX);
const INV_SBOX_ANF: [u16; 4] = crate::ct::build_nibble_sbox_anf(&INV_SBOX);

#[inline]
fn sbox_ct_nibble(input: u8) -> u8 {
    crate::ct::eval_nibble_sbox(SBOX_ANF, input)
}

#[inline]
fn inv_sbox_ct_nibble(input: u8) -> u8 {
    crate::ct::eval_nibble_sbox(INV_SBOX_ANF, input)
}

#[inline]
fn sbox_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as usize;
        out |= u64::from(SBOX[nibble]) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn inv_sbox_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as usize;
        out |= u64::from(INV_SBOX[nibble]) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn sbox_layer_ct(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as u8;
        out |= u64::from(sbox_ct_nibble(nibble)) << (4 * i);
        i += 1;
    }
    out
}

#[inline]
fn inv_sbox_layer_ct(state: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 16 {
        let nibble = ((state >> (4 * i)) & 0x0f) as u8;
        out |= u64::from(inv_sbox_ct_nibble(nibble)) << (4 * i);
        i += 1;
    }
    out
}

/// Apply the PRESENT P-layer bit permutation (ISO/IEC 29192-2 §2.3).
///
/// The P-layer sends source bit `i` to destination bit `P(i)` where:
///   P(i) = 16·i mod 63   for i ∈ 0..62
///   P(63) = 63            (MSB is fixed)
///
/// The formula produces a full permutation on 63 elements because
/// gcd(16, 63) = 1 (easily verified: 63 = 3·16 + 15; 16 = 1·15 + 1; gcd = 1),
/// so "stride-16" cycles through all 63 bit positions before repeating.
///
/// Implementation: "scatter" mode — for each source bit, compute its
/// destination and set that bit in the output.
#[inline]
fn p_layer(state: u64) -> u64 {
    // PRESENT bit permutation:
    // P(i) = 16*i mod 63 for i in [0, 62], and P(63) = 63.
    // (Bogdanov et al., CHES 2007; ISO/IEC 29192-2.)
    let mut out = 0u64;
    let mut bit = 0usize;
    while bit < BLOCK_BITS - 1 {
        let dst = (16 * bit) % (BLOCK_BITS - 1);
        out |= ((state >> bit) & 1) << dst;
        bit += 1;
    }
    out |= ((state >> (BLOCK_BITS - 1)) & 1) << (BLOCK_BITS - 1);
    out
}

/// Inverse P-layer — "gather" mode using the same stride-16 formula.
///
/// `inv_p_layer` reads output bit `i` from source position `P(i) = 16·i mod 63`.
/// This is the inverse of `p_layer`'s scatter because gather-P undoes
/// scatter-P for any permutation P: gather-P(scatter-P(v))[i] = v[i].
/// (Proof: gather-P(scatter-P(v))[i] = scatter-P(v)[P(i)] = v[P⁻¹(P(i))] = v[i].)
#[inline]
fn inv_p_layer(state: u64) -> u64 {
    let mut out = 0u64;
    let mut bit = 0usize;
    while bit < BLOCK_BITS - 1 {
        let src = (16 * bit) % (BLOCK_BITS - 1);
        out |= ((state >> src) & 1) << bit;
        bit += 1;
    }
    out |= ((state >> (BLOCK_BITS - 1)) & 1) << (BLOCK_BITS - 1);
    out
}

fn present_encrypt(state: u64, round_keys: &[u64; ROUND_KEYS]) -> u64 {
    let mut s = state;
    let mut round = 0usize;
    while round < 31 {
        s ^= round_keys[round];
        s = sbox_layer(s);
        s = p_layer(s);
        round += 1;
    }
    s ^ round_keys[31]
}

fn present_encrypt_ct(state: u64, round_keys: &[u64; ROUND_KEYS]) -> u64 {
    let mut s = state;
    let mut round = 0usize;
    while round < 31 {
        s ^= round_keys[round];
        s = sbox_layer_ct(s);
        s = p_layer(s);
        round += 1;
    }
    s ^ round_keys[31]
}

fn present_decrypt(state: u64, round_keys: &[u64; ROUND_KEYS]) -> u64 {
    let mut s = state ^ round_keys[31];
    let mut round = 31usize;
    while round > 0 {
        round -= 1;
        s = inv_p_layer(s);
        s = inv_sbox_layer(s);
        s ^= round_keys[round];
    }
    s
}

fn present_decrypt_ct(state: u64, round_keys: &[u64; ROUND_KEYS]) -> u64 {
    let mut s = state ^ round_keys[31];
    let mut round = 31usize;
    while round > 0 {
        round -= 1;
        s = inv_p_layer(s);
        s = inv_sbox_layer_ct(s);
        s ^= round_keys[round];
    }
    s
}

/// Fast-path key-schedule S-box: a direct secret-indexed table lookup.
#[inline]
fn sbox_fast_nibble(input: u8) -> u8 {
    SBOX[(input & 0x0f) as usize]
}

/// PRESENT-80 key schedule (CHES 2007 paper, "The key schedule"): the 80-bit
/// register `k79..k0` is held in a `u128`, round key `i` is `k79..k16`, and
/// between rounds the register is rotated left by 61, its top nibble is
/// S-boxed and the round counter is XORed into `k19..k15`. The 32 round keys
/// are written directly into `out`.
fn expand_round_keys_80(key: &[u8; KEY80_BYTES], sbox: fn(u8) -> u8, out: &mut [u64; ROUND_KEYS]) {
    let mut reg = 0u128;
    for &b in key {
        reg = (reg << 8) | u128::from(b);
    }

    let mask80 = (1u128 << 80) - 1;

    for round in 1..=32u8 {
        out[(round - 1) as usize] = ((reg >> 16) & 0xffff_ffff_ffff_ffff) as u64;
        if round == 32 {
            break;
        }

        reg = ((reg << KEY_ROTATION) | (reg >> (80 - KEY_ROTATION))) & mask80;
        let top = ((reg >> 76) & 0x0f) as u8;
        reg &= !(0x0fu128 << 76);
        reg |= u128::from(sbox(top)) << 76;
        reg ^= u128::from(round) << 15;
    }

    // The 80-bit key register: after the last round it still determines the
    // whole schedule.
    crate::ct::zeroize_slice(core::slice::from_mut(&mut reg));
}

/// PRESENT-128 key schedule (CHES 2007 paper, Appendix II): round key `i` is
/// `k127..k64`; between rounds the register is rotated left by 61, its top two
/// nibbles are S-boxed and the round counter is XORed into `k66..k62`. The 32
/// round keys are written directly into `out`.
fn expand_round_keys_128(
    key: &[u8; KEY128_BYTES],
    sbox: fn(u8) -> u8,
    out: &mut [u64; ROUND_KEYS],
) {
    let mut reg = u128::from_be_bytes(*key);

    for round in 1..=32u8 {
        out[(round - 1) as usize] = (reg >> 64) as u64;
        if round == 32 {
            break;
        }

        reg = reg.rotate_left(KEY_ROTATION);

        let top = ((reg >> 124) & 0x0f) as u8;
        reg &= !(0x0fu128 << 124);
        reg |= u128::from(sbox(top)) << 124;

        let next = ((reg >> 120) & 0x0f) as u8;
        reg &= !(0x0fu128 << 120);
        reg |= u128::from(sbox(next)) << 120;

        reg ^= u128::from(round) << 62;
    }

    // The 128-bit key register: after the last round it still determines the
    // whole schedule.
    crate::ct::zeroize_slice(core::slice::from_mut(&mut reg));
}

/// PRESENT-80 fast software path.
pub struct Present80 {
    round_keys: [u64; ROUND_KEYS],
}

impl Present80 {
    /// Expand the 80-bit key (big-endian) into the 32 round keys of the
    /// CHES 2007 schedule, S-boxing the register's top nibble each step
    /// with a direct (secret-indexed) table lookup. The schedule is written
    /// directly into the new instance.
    #[must_use]
    pub fn new(key: &[u8; KEY80_BYTES]) -> Self {
        let mut cipher = Self {
            round_keys: [0u64; 32],
        };
        expand_round_keys_80(key, sbox_fast_nibble, &mut cipher.round_keys);
        cipher
    }

    /// Expand the key as [`Self::new`] does, then zeroize the caller-owned
    /// key buffer so the master key survives only as expanded round keys.
    pub fn new_wiping(key: &mut [u8; KEY80_BYTES]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt one 64-bit block (big-endian): 31 SP-network rounds plus a
    /// final round-key xor. Returns the ciphertext; the input is untouched.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_encrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    /// Decrypt one 64-bit block (big-endian) by applying the inverse
    /// P-layer and inverse S-box layer through the 31 rounds in reverse.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_decrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// PRESENT-80 constant-time software path.
pub struct Present80Ct {
    round_keys: [u64; ROUND_KEYS],
}

impl Present80Ct {
    /// Expand the 80-bit key (big-endian) into the 32 round keys, with the
    /// schedule's per-step S-box evaluated in packed ANF form so key
    /// expansion itself performs no secret-indexed table reads. The schedule
    /// is written directly into the new instance.
    #[must_use]
    pub fn new(key: &[u8; KEY80_BYTES]) -> Self {
        let mut cipher = Self {
            round_keys: [0u64; 32],
        };
        expand_round_keys_80(key, sbox_ct_nibble, &mut cipher.round_keys);
        cipher
    }

    /// Expand the key as [`Self::new`] does, then zeroize the caller-owned
    /// key buffer so the master key survives only as expanded round keys.
    pub fn new_wiping(key: &mut [u8; KEY80_BYTES]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt one 64-bit block (big-endian): the same 31 rounds plus final
    /// key xor as the fast path, but each S-box layer evaluates the packed
    /// ANF form of the 4-bit S-box instead of a secret-indexed table.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_encrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    /// Decrypt one 64-bit block (big-endian) through the 31 rounds in
    /// reverse; the inverse S-box layer is evaluated in packed ANF form so
    /// substitution avoids secret-indexed table reads.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_decrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// PRESENT-128 fast software path.
pub struct Present128 {
    round_keys: [u64; ROUND_KEYS],
}

impl Present128 {
    /// Expand the 128-bit key (big-endian) into the 32 round keys; the
    /// 128-bit schedule S-boxes the register's top two nibbles each step,
    /// here via direct (secret-indexed) table lookups. The schedule is
    /// written directly into the new instance.
    #[must_use]
    pub fn new(key: &[u8; KEY128_BYTES]) -> Self {
        let mut cipher = Self {
            round_keys: [0u64; 32],
        };
        expand_round_keys_128(key, sbox_fast_nibble, &mut cipher.round_keys);
        cipher
    }

    /// Expand the key as [`Self::new`] does, then zeroize the caller-owned
    /// key buffer so the master key survives only as expanded round keys.
    pub fn new_wiping(key: &mut [u8; KEY128_BYTES]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt one 64-bit block (big-endian): 31 SP-network rounds plus a
    /// final round-key xor. Returns the ciphertext; the input is untouched.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_encrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    /// Decrypt one 64-bit block (big-endian) by applying the inverse
    /// P-layer and inverse S-box layer through the 31 rounds in reverse.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_decrypt(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// PRESENT-128 constant-time software path.
pub struct Present128Ct {
    round_keys: [u64; ROUND_KEYS],
}

impl Present128Ct {
    /// Expand the 128-bit key (big-endian) into the 32 round keys; the
    /// schedule's two per-step S-box applications are evaluated in packed
    /// ANF form so key expansion performs no secret-indexed table reads. The
    /// schedule is written directly into the new instance.
    #[must_use]
    pub fn new(key: &[u8; KEY128_BYTES]) -> Self {
        let mut cipher = Self {
            round_keys: [0u64; 32],
        };
        expand_round_keys_128(key, sbox_ct_nibble, &mut cipher.round_keys);
        cipher
    }

    /// Expand the key as [`Self::new`] does, then zeroize the caller-owned
    /// key buffer so the master key survives only as expanded round keys.
    pub fn new_wiping(key: &mut [u8; KEY128_BYTES]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Encrypt one 64-bit block (big-endian): the same 31 rounds plus final
    /// key xor as the fast path, but each S-box layer evaluates the packed
    /// ANF form of the 4-bit S-box instead of a secret-indexed table.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_encrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }

    /// Decrypt one 64-bit block (big-endian) through the 31 rounds in
    /// reverse; the inverse S-box layer is evaluated in packed ANF form so
    /// substitution avoids secret-indexed table reads.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        present_decrypt_ct(u64::from_be_bytes(*block), &self.round_keys).to_be_bytes()
    }
}

/// The original PRESENT instantiation from the CHES 2007 paper (80-bit key).
pub type Present = Present80;
/// Constant-time PRESENT-80 alias.
pub type PresentCt = Present80Ct;

macro_rules! impl_block_cipher {
    ($name:ty) => {
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

impl_block_cipher!(Present80);
impl_block_cipher!(Present80Ct);
impl_block_cipher!(Present128);
impl_block_cipher!(Present128Ct);

macro_rules! impl_drop_zeroize {
    ($name:ty) => {
        impl Drop for $name {
            fn drop(&mut self) {
                crate::ct::zeroize_slice(self.round_keys.as_mut_slice());
            }
        }
    };
}

impl_drop_zeroize!(Present80);
impl_drop_zeroize!(Present80Ct);
impl_drop_zeroize!(Present128);
impl_drop_zeroize!(Present128Ct);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decode_hex_array;

    #[test]
    fn ct_sbox_matches_tables() {
        for x in 0u8..16 {
            assert_eq!(sbox_ct_nibble(x), SBOX[x as usize]);
            assert_eq!(inv_sbox_ct_nibble(x), INV_SBOX[x as usize]);
        }
    }

    #[test]
    fn present80_kats() {
        // CHES 2007 Appendix I.
        let cases = [
            (
                decode_hex_array::<10>("00000000000000000000"),
                decode_hex_array::<8>("0000000000000000"),
                decode_hex_array::<8>("5579c1387b228445"),
            ),
            (
                decode_hex_array::<10>("ffffffffffffffffffff"),
                decode_hex_array::<8>("0000000000000000"),
                decode_hex_array::<8>("e72c46c0f5945049"),
            ),
            (
                decode_hex_array::<10>("00000000000000000000"),
                decode_hex_array::<8>("ffffffffffffffff"),
                decode_hex_array::<8>("a112ffc72f68417b"),
            ),
            (
                decode_hex_array::<10>("ffffffffffffffffffff"),
                decode_hex_array::<8>("ffffffffffffffff"),
                decode_hex_array::<8>("3333dcd3213210d2"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Present80::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    #[test]
    fn present80_ct_kats() {
        let cases = [
            (
                decode_hex_array::<10>("00000000000000000000"),
                decode_hex_array::<8>("0000000000000000"),
                decode_hex_array::<8>("5579c1387b228445"),
            ),
            (
                decode_hex_array::<10>("ffffffffffffffffffff"),
                decode_hex_array::<8>("0000000000000000"),
                decode_hex_array::<8>("e72c46c0f5945049"),
            ),
            (
                decode_hex_array::<10>("00000000000000000000"),
                decode_hex_array::<8>("ffffffffffffffff"),
                decode_hex_array::<8>("a112ffc72f68417b"),
            ),
            (
                decode_hex_array::<10>("ffffffffffffffffffff"),
                decode_hex_array::<8>("ffffffffffffffff"),
                decode_hex_array::<8>("3333dcd3213210d2"),
            ),
        ];

        for (key, pt, ct) in cases {
            let cipher = Present80Ct::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    /// PRESENT-128 values for the all-zero and all-one keys and plaintexts.
    /// The CHES 2007 paper publishes known answers only for PRESENT-80
    /// (Appendix I) and gives the 128-bit key schedule in Appendix II without
    /// vectors. These four values are pinned by two implementations that share
    /// no code: the production path and the bit-level transcription of the
    /// paper in [`bitwise`], which `present128_matches_bitwise_transcription`
    /// also compares on random keys.
    fn present128_reference_cases() -> [([u8; 16], [u8; 8], [u8; 8]); 4] {
        [
            (
                decode_hex_array::<16>("00000000000000000000000000000000"),
                decode_hex_array::<8>("0000000000000000"),
                decode_hex_array::<8>("96db702a2e6900af"),
            ),
            (
                decode_hex_array::<16>("ffffffffffffffffffffffffffffffff"),
                decode_hex_array::<8>("0000000000000000"),
                decode_hex_array::<8>("13238c710272a5d8"),
            ),
            (
                decode_hex_array::<16>("00000000000000000000000000000000"),
                decode_hex_array::<8>("ffffffffffffffff"),
                decode_hex_array::<8>("3c6019e5e5edd563"),
            ),
            (
                decode_hex_array::<16>("ffffffffffffffffffffffffffffffff"),
                decode_hex_array::<8>("ffffffffffffffff"),
                decode_hex_array::<8>("628d9fbd4218e5b4"),
            ),
        ]
    }

    #[test]
    fn present128_kats() {
        for (key, pt, ct) in present128_reference_cases() {
            let cipher = Present128::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
            assert_eq!(bitwise::encrypt(&pt, &bitwise::round_keys_128(&key)), ct);
        }
    }

    #[test]
    fn present128_ct_kats() {
        for (key, pt, ct) in present128_reference_cases() {
            let cipher = Present128Ct::new(&key);
            assert_eq!(cipher.encrypt_block(&pt), ct);
            assert_eq!(cipher.decrypt_block(&ct), pt);
        }
    }

    /// PRESENT transcribed from the CHES 2007 paper bit by bit, as an
    /// independent oracle for the packed production code.
    ///
    /// State bits `b63..b0`, key register bits `k79..k0` / `k127..k0` and
    /// round-key bits `κ63..κ0` are individual `bool`s indexed by the paper's
    /// bit numbers, so every step below is the paper's sentence rather than a
    /// shift-and-mask reformulation of it:
    ///
    /// - sBoxLayer: `w_i = b_{4i+3} ‖ b_{4i+2} ‖ b_{4i+1} ‖ b_{4i}` through S;
    /// - pLayer: "bit i of state is moved to bit position P(i)", with `P`
    ///   the paper's table;
    /// - 80-bit key schedule: `K_i = k79..k16`; then `[k79..k0] =
    ///   [k18..k19]` (rotate left 61), `[k79..k76] = S[k79..k76]`,
    ///   `[k19..k15] ^= round_counter`;
    /// - 128-bit key schedule (Appendix II): `K_i = k127..k64`; then rotate
    ///   left 61, `[k127..k124] = S[..]`, `[k123..k120] = S[..]`,
    ///   `[k66..k62] ^= round_counter`.
    ///
    /// Hex strings in the paper's vectors are read most significant digit
    /// first, so byte 0 of a key or block carries its highest-numbered bits.
    mod bitwise {
        use super::SBOX;

        /// The paper's pLayer table: entry `i` is `P(i)`.
        #[rustfmt::skip]
        const P: [usize; 64] = [
             0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
             4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
             8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
            12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63,
        ];

        /// Bits of `bytes` indexed by bit number: bit `8n - 1` is the most
        /// significant bit of `bytes[0]`, bit 0 the least significant bit of
        /// the last byte.
        fn to_bits(bytes: &[u8]) -> Vec<bool> {
            let n = bytes.len() * 8;
            (0..n)
                .map(|bit| (bytes[bytes.len() - 1 - bit / 8] >> (bit % 8)) & 1 == 1)
                .collect()
        }

        fn from_bits(bits: &[bool]) -> Vec<u8> {
            let mut out = vec![0u8; bits.len() / 8];
            for (bit, &set) in bits.iter().enumerate() {
                if set {
                    let idx = out.len() - 1 - bit / 8;
                    out[idx] |= 1 << (bit % 8);
                }
            }
            out
        }

        /// Replace bits `lo+3 .. lo` (most significant first) by their S-box image.
        fn sbox_nibble(bits: &mut [bool], lo: usize) {
            let input = (0..4).fold(0u8, |acc, j| acc | (u8::from(bits[lo + j]) << j));
            let output = SBOX[input as usize];
            for j in 0..4 {
                bits[lo + j] = (output >> j) & 1 == 1;
            }
        }

        /// Rotate the register left by 61 positions: new `k_j` is old
        /// `k_{(j + n - 61) mod n}`, so new `k_{n-1}` is old `k_{n-62}`.
        fn rotate_left_61(reg: &[bool]) -> Vec<bool> {
            let n = reg.len();
            (0..n).map(|j| reg[(j + n - 61) % n]).collect()
        }

        fn xor_round_counter(reg: &mut [bool], lo: usize, round: usize) {
            for j in 0..5 {
                reg[lo + j] ^= (round >> j) & 1 == 1;
            }
        }

        pub(super) fn round_keys_80(key: &[u8; 10]) -> Vec<[bool; 64]> {
            let mut reg = to_bits(key);
            let mut keys = Vec::with_capacity(32);
            for round in 1..=32 {
                keys.push(reg[16..80].try_into().unwrap());
                reg = rotate_left_61(&reg);
                sbox_nibble(&mut reg, 76);
                xor_round_counter(&mut reg, 15, round);
            }
            keys
        }

        pub(super) fn round_keys_128(key: &[u8; 16]) -> Vec<[bool; 64]> {
            let mut reg = to_bits(key);
            let mut keys = Vec::with_capacity(32);
            for round in 1..=32 {
                keys.push(reg[64..128].try_into().unwrap());
                reg = rotate_left_61(&reg);
                sbox_nibble(&mut reg, 124);
                sbox_nibble(&mut reg, 120);
                xor_round_counter(&mut reg, 62, round);
            }
            keys
        }

        pub(super) fn encrypt(pt: &[u8; 8], round_keys: &[[bool; 64]]) -> [u8; 8] {
            let mut state: [bool; 64] = to_bits(pt).try_into().unwrap();
            for round_key in &round_keys[..31] {
                for (s, k) in state.iter_mut().zip(round_key) {
                    *s ^= k;
                }
                for i in 0..16 {
                    sbox_nibble(&mut state, 4 * i);
                }
                let mut permuted = [false; 64];
                for (i, &bit) in state.iter().enumerate() {
                    permuted[P[i]] = bit;
                }
                state = permuted;
            }
            for (s, k) in state.iter_mut().zip(&round_keys[31]) {
                *s ^= k;
            }
            from_bits(&state).try_into().unwrap()
        }
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn fill_bytes(state: &mut u64, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = xorshift64(state).to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    /// The bit-level transcription reproduces the paper's Appendix I
    /// PRESENT-80 known answers, which qualifies it as an oracle.
    #[test]
    fn bitwise_transcription_matches_appendix_i() {
        let cases = [
            (
                "00000000000000000000",
                "0000000000000000",
                "5579c1387b228445",
            ),
            (
                "ffffffffffffffffffff",
                "0000000000000000",
                "e72c46c0f5945049",
            ),
            (
                "00000000000000000000",
                "ffffffffffffffff",
                "a112ffc72f68417b",
            ),
            (
                "ffffffffffffffffffff",
                "ffffffffffffffff",
                "3333dcd3213210d2",
            ),
        ];
        for (key, pt, ct) in cases {
            let rks = bitwise::round_keys_80(&decode_hex_array::<10>(key));
            assert_eq!(
                bitwise::encrypt(&decode_hex_array::<8>(pt), &rks),
                decode_hex_array::<8>(ct)
            );
        }
    }

    /// Random keys and plaintexts through the packed PRESENT-80 and PRESENT-128
    /// paths and the bit-level transcription: the two agree, which pins the
    /// key byte order that the all-zero/all-one vectors cannot distinguish.
    #[test]
    fn present_matches_bitwise_transcription() {
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200 {
            let mut key80 = [0u8; 10];
            let mut key128 = [0u8; 16];
            let mut pt = [0u8; 8];
            fill_bytes(&mut rng, &mut key80);
            fill_bytes(&mut rng, &mut key128);
            fill_bytes(&mut rng, &mut pt);

            let expected80 = bitwise::encrypt(&pt, &bitwise::round_keys_80(&key80));
            let fast = Present80::new(&key80);
            let ct = Present80Ct::new(&key80);
            assert_eq!(fast.encrypt_block(&pt), expected80, "Present80");
            assert_eq!(ct.encrypt_block(&pt), expected80, "Present80Ct");
            assert_eq!(fast.decrypt_block(&expected80), pt, "Present80 decrypt");
            assert_eq!(ct.decrypt_block(&expected80), pt, "Present80Ct decrypt");

            let expected128 = bitwise::encrypt(&pt, &bitwise::round_keys_128(&key128));
            let fast = Present128::new(&key128);
            let ct = Present128Ct::new(&key128);
            assert_eq!(fast.encrypt_block(&pt), expected128, "Present128");
            assert_eq!(ct.encrypt_block(&pt), expected128, "Present128Ct");
            assert_eq!(fast.decrypt_block(&expected128), pt, "Present128 decrypt");
            assert_eq!(ct.decrypt_block(&expected128), pt, "Present128Ct decrypt");
        }
    }

    /// The `BlockCipher` entry points reject a wrong-length block.
    #[test]
    #[should_panic(expected = "wrong block length")]
    fn block_cipher_rejects_wrong_length() {
        use crate::BlockCipher;
        let cipher = Present80::new(&[0u8; 10]);
        let mut long = [0u8; 9];
        cipher.encrypt(&mut long);
    }
}
