//! MD5 from RFC 1321.
//!
//! MD5 is retained for legacy compatibility. It is broken for collision
//! resistance and should not be used for new integrity designs. It also keeps
//! the Merkle-Damgaard length-extension property, so plain `MD5(key || msg)` is
//! not a secure MAC construction.

use super::Digest;

// RFC 1321 §3.3 initial state words (A, B, C, D).
const IV: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

// RFC 1321 §3.4: four auxiliary functions, each taking three 32-bit words to
// one. The RFC writes XY for the bitwise AND of X and Y, X v Y for their OR,
// X xor Y for their exclusive-or, and not(X) for the complement (§2).

/// F(X,Y,Z) = XY v not(X) Z, RFC 1321 §3.4: in each bit position, if X then Y
/// else Z.
#[allow(non_snake_case)]
#[inline]
const fn F(X: u32, Y: u32, Z: u32) -> u32 {
    (X & Y) | (!X & Z)
}

/// G(X,Y,Z) = XZ v Y not(Z), RFC 1321 §3.4.
#[allow(non_snake_case)]
#[inline]
const fn G(X: u32, Y: u32, Z: u32) -> u32 {
    (X & Z) | (Y & !Z)
}

/// H(X,Y,Z) = X xor Y xor Z, RFC 1321 §3.4: the bitwise parity of its inputs.
#[allow(non_snake_case)]
#[inline]
const fn H(X: u32, Y: u32, Z: u32) -> u32 {
    X ^ Y ^ Z
}

/// I(X,Y,Z) = Y xor (X v not(Z)), RFC 1321 §3.4.
#[allow(non_snake_case)]
#[inline]
const fn I(X: u32, Y: u32, Z: u32) -> u32 {
    Y ^ (X | !Z)
}

/// The table T[1 ... 64] of RFC 1321 §3.4, where T[i] "is equal to the integer
/// part of 4294967296 times abs(sin(i)), where i is in radians". Rust counts
/// from zero, so the RFC's T[i] is `T[i - 1]` here. The words were computed
/// from that definition and are laid out four to a row, one row per row of
/// operations in the rounds; the `t_is_the_integer_part_of_4294967296_abs_sin_i`
/// test recomputes them.
#[rustfmt::skip]
const T: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee,
    0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa,
    0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05,
    0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039,
    0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

/// RFC 1321 §3.4, Step 4, for one 16-word block: copy the block into X, save
/// the registers A, B, C, and D as AA, BB, CC, and DD, perform the four rounds
/// of sixteen operations, and add the saved values back in. `state` holds the
/// registers (A, B, C, D).
#[allow(non_snake_case)]
#[inline]
fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    // Copy block i into X. The RFC reads each four bytes as a word "with the
    // low-order (least significant) byte given first" (§2).
    let mut X = [0u32; 16];
    for (j, bytes) in block.chunks_exact(4).enumerate() {
        X[j] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }

    let [mut A, mut B, mut C, mut D] = *state;

    // Save A as AA, B as BB, C as CC, and D as DD.
    let (AA, BB, CC, DD) = (A, B, C, D);

    // Each round is written as the RFC lists it. With the round's auxiliary
    // function (F, G, H, or I) in place of Fn, [abcd k s i] denotes the
    // operation
    //
    //     a = b + ((a + Fn(b,c,d) + X[k] + T[i]) <<< s)
    //
    // where "+" is addition modulo 2^32, X <<< s rotates X left by s bits, and
    // the four letters name the registers that play a, b, c, and d.
    macro_rules! round {
        ($Fn:ident: $([$abcd:ident $k:literal $s:literal $i:literal])*) => {
            $(round!(@op $Fn, $abcd, $k, $s, $i);)*
        };
        (@op $Fn:ident, ABCD, $($ksi:literal),*) => { round!(@step $Fn, A, B, C, D, $($ksi),*) };
        (@op $Fn:ident, DABC, $($ksi:literal),*) => { round!(@step $Fn, D, A, B, C, $($ksi),*) };
        (@op $Fn:ident, CDAB, $($ksi:literal),*) => { round!(@step $Fn, C, D, A, B, $($ksi),*) };
        (@op $Fn:ident, BCDA, $($ksi:literal),*) => { round!(@step $Fn, B, C, D, A, $($ksi),*) };
        (@step $Fn:ident, $a:ident, $b:ident, $c:ident, $d:ident,
            $k:literal, $s:literal, $i:literal) => {
            $a = $b.wrapping_add(
                $a.wrapping_add($Fn($b, $c, $d))
                    .wrapping_add(X[$k])
                    .wrapping_add(T[$i - 1])
                    .rotate_left($s),
            )
        };
    }

    // Round 1.
    round! { F:
        [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
        [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
        [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
        [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
    }

    // Round 2.
    round! { G:
        [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
        [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
        [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
        [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
    }

    // Round 3.
    round! { H:
        [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
        [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
        [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
        [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
    }

    // Round 4.
    round! { I:
        [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
        [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
        [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
        [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
    }

    // Then perform the following additions. (That is increment each of the
    // four registers by the value it had before this block was started.)
    A = A.wrapping_add(AA);
    B = B.wrapping_add(BB);
    C = C.wrapping_add(CC);
    D = D.wrapping_add(DD);

    *state = [A, B, C, D];

    // X holds the block's message words; under HMAC the first block is the
    // key xor ipad.
    crate::ct::zeroize_slice(X.as_mut_slice());
}

/// Streaming MD5 state (RFC 1321).
///
/// Absorbs input in 64-byte blocks via [`Md5::update`] and produces a
/// 16-byte digest via [`Md5::finalize`]; [`Md5::digest`] is the one-shot
/// form. Cloning captures the mid-stream state, so a common prefix can be
/// hashed once and extended along several branches. MD5's collision
/// resistance is thoroughly broken and it length-extends, so use it only
/// for legacy interoperability, per the module warning.
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    pos: usize,
    bit_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// Compression-function block size in bytes (512 bits). This is the
    /// rate at which input is consumed and the pad width HMAC keys are
    /// sized against.
    pub const BLOCK_LEN: usize = 64;
    /// Digest length in bytes (128 bits).
    pub const OUTPUT_LEN: usize = 16;

    /// Create a fresh hasher: the RFC 1321 §3.3 initial state (A, B, C, D)
    /// and an empty (zero-length) message.
    #[must_use]
    pub fn new() -> Self {
        <Self as Digest>::new()
    }

    /// Absorb more message bytes. May be called any number of times with
    /// arbitrary chunk sizes; the digest depends only on the concatenation
    /// of all chunks. The message length is tracked modulo 2^64 bits, as
    /// RFC 1321 padding requires.
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }

    /// Apply the RFC 1321 `0x80` / little-endian length padding, consume the
    /// hasher, and return the 16-byte digest (state words serialized
    /// little-endian). Keep a [`Clone`] beforehand if the stream must
    /// continue past this point.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.finalize_in_place(&mut out);
        // `self` drops here, and `Drop` wipes the final chaining state.
        out
    }

    /// One-shot convenience: hash `data` in a single call. Equivalent to
    /// `new` + `update` + `finalize`, returning the 16-byte digest.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    /// RFC 1321 §3.1 and §3.2 padding and the final §3.4 compression(s), then
    /// the little-endian registers A, B, C, D into `out` (§3.5). The
    /// state is left holding the final chaining value; the callers decide
    /// whether it is dropped (`finalize`) or replaced (`finalize_reset`).
    fn finalize_in_place(&mut self, out: &mut [u8; 16]) {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u64) * 8);

        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 56 {
            self.block[self.pos..].fill(0);
            compress(&mut self.state, &self.block);
            self.block = [0u8; 64];
            self.pos = 0;
        }

        self.block[self.pos..56].fill(0);
        self.block[56..].copy_from_slice(&self.bit_len.to_le_bytes());
        compress(&mut self.state, &self.block);

        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }
}

// The bodies of `new` and `update` live here; the same-named inherent
// methods delegate through the trait path, so neither pair can turn into
// silent recursion if one half is removed.
impl Digest for Md5 {
    const BLOCK_LEN: usize = 64;
    const OUTPUT_LEN: usize = 16;

    /// The RFC 1321 §3.3 initial state (A, B, C, D) and an empty message.
    fn new() -> Self {
        Self {
            state: IV,
            block: [0u8; 64],
            pos: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (64 - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == 64 {
                compress(&mut self.state, &self.block);
                self.block = [0u8; 64];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(512);
            }
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        let out: &mut [u8; 16] = out.try_into().expect("wrong digest length");
        self.finalize_in_place(out);
    }

    fn finalize_reset(&mut self, out: &mut [u8]) {
        let out: &mut [u8; 16] = out.try_into().expect("wrong digest length");
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

impl Drop for Md5 {
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
        let mut h = Md5::new();
        h.update(msg);
        let mut out = [0u8; 16];
        crate::hash::Digest::finalize_reset(&mut h, &mut out);
        assert_eq!(out, Md5::digest(msg));
        assert_eq!(
            (h.state, h.block, h.pos, h.bit_len),
            (IV, [0u8; 64], 0, 0),
            "finalize_reset leaves a fresh instance"
        );

        let mut h = Md5::new();
        h.update(b"a partial block");
        crate::hash::Digest::zeroize(&mut h);
        assert_eq!(
            (h.state, h.block, h.pos, h.bit_len),
            ([0u32; 4], [0u8; 64], 0, 0)
        );
        assert!(core::mem::needs_drop::<Md5>());
    }

    #[test]
    fn md5_empty() {
        assert_eq!(
            encode_hex(&Md5::digest(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn md5_streaming_abc() {
        let mut h = Md5::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn md5_known_vector() {
        assert_eq!(
            encode_hex(&Md5::digest(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
    }

    #[test]
    fn md5_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-md5", "-binary"], msg)
            .or_skip("md5_matches_openssl")
        else {
            return;
        };
        assert_eq!(Md5::digest(msg).as_slice(), expected.as_slice());
    }

    /// RFC 1321 §3.4 defines T[i] as the integer part of 4294967296 times
    /// abs(sin(i)), i in radians; recompute all 64 words in `f64`. Only `sin`
    /// rounds: i converts exactly, and scaling by 4294967296 = 2^32 and the
    /// floor are exact. Every 4294967296 · |sin(i)| for i = 1 to 64 lies at
    /// least 0.015 from an integer (closest at i = 31; checked in 60-digit
    /// decimal arithmetic), while one ulp of error in sin(i) moves the product
    /// by at most 2^32 · 2^-53 ≈ 4.8e-7. The smallest margin, measured in ulps
    /// of sin(i), is about 39,000, so any sin short of that error recovers
    /// the table exactly.
    #[test]
    fn t_is_the_integer_part_of_4294967296_abs_sin_i() {
        for i in 1..=64u32 {
            let expected = (4_294_967_296.0 * f64::from(i).sin().abs()).floor();
            assert_eq!(f64::from(T[i as usize - 1]), expected, "T[{i}]");
        }
    }
}
