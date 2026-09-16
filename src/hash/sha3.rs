//! SHA-3 (Keccak-f\[1600\]) from FIPS 202.
//!
//! This module implements the fixed-output SHA-3 family:
//!
//! - `Sha3_224`
//! - `Sha3_256`
//! - `Sha3_384`
//! - `Sha3_512`
//!
//! The core is the Keccak sponge over the 1600-bit permutation with the SHA-3
//! domain-separation suffix `0x06`.
//!
//! `Shake128` and `Shake256` are built on the same permutation, but use the
//! SHAKE domain suffix (`0x1f`) and expose the sponge's natural
//! absorb-then-squeeze interface through the `Xof` trait. One `Keccak`
//! state serves both phases and is padded and permuted in place, so the
//! absorbing state is never copied when output begins.

use super::{Digest, Xof};

// Keccak-f[1600] rho-step rotation offsets for lanes A[x,y] (FIPS 202,
// Keccak-p permutation definition).
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

// Keccak-f[1600] pi-step lane permutation, flattened as index x + 5*y where
// (x, y) -> (y, (2x + 3y) mod 5).
const PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

// Keccak-f[1600] iota-step round constants for rounds 0..23.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

// Runtime-dispatching entry point: hardware on aarch64 + FEAT_SHA3 when the
// opt-in `arm-sha3` cargo feature is enabled, else the portable soft path.
#[inline]
fn keccak_f1600(state: &mut [u64; 25]) {
    #[cfg(all(target_arch = "aarch64", feature = "arm-sha3"))]
    {
        if std::arch::is_aarch64_feature_detected!("sha3") {
            // SAFETY: feature detection confirms FEAT_SHA3 is present.
            #[allow(unsafe_code)]
            unsafe {
                return keccak_f1600_sha3(state);
            }
        }
    }
    keccak_f1600_soft(state);
}

// Pure-Rust fallback — 24 rounds of theta → rho → pi → chi → iota.
fn keccak_f1600_soft(state: &mut [u64; 25]) {
    // Round scratch lives outside the loop so one wipe clears the last round:
    // `b` is the state just before chi, which determines the output state,
    // capacity included.
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];
    let mut b = [0u64; 25];
    for &rc in &RC {
        // theta: parity of each column.
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        // theta: mix neighboring column parities.
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        // theta: xor D[x] into each lane of column x.
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // rho + pi: per-lane rotate, then permute lane positions.
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(RHO[i]);
        }

        // chi: nonlinear row step.
        for y in 0..5 {
            let row = 5 * y;
            for x in 0..5 {
                state[row + x] = b[row + x] ^ ((!b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)]);
            }
        }

        // iota: inject round constant.
        state[0] ^= rc;
    }
    crate::ct::zeroize_slice(c.as_mut_slice());
    crate::ct::zeroize_slice(d.as_mut_slice());
    crate::ct::zeroize_slice(b.as_mut_slice());
}

// FEAT_SHA3 hardware path: uses EOR3 (3-way XOR), RAX1 (rotate-and-XOR),
// and BCAX (bit-clear-and-XOR) intrinsics.  Theta column parities and D
// vectors are computed with EOR3/RAX1; chi replaces the scalar NOT+AND+XOR
// triple with a single BCAX per lane pair.  Rho+Pi remain scalar (each of
// the 24 non-zero lanes has a distinct rotation, so XAR offers no advantage
// when lanes are processed sequentially).
#[cfg(all(target_arch = "aarch64", feature = "arm-sha3"))]
#[target_feature(enable = "sha3")]
#[allow(unsafe_code)]
unsafe fn keccak_f1600_sha3(state: &mut [u64; 25]) {
    use core::arch::aarch64::*;

    // Pack two scalars into a 128-bit SIMD register [a, b].
    #[inline(always)]
    unsafe fn u64x2(a: u64, b: u64) -> uint64x2_t {
        vcombine_u64(vdup_n_u64(a), vdup_n_u64(b))
    }

    // Round scratch outside the loop, wiped once after the last round, as in
    // the soft path: `c` holds the column parities, `d` the theta offsets,
    // and `b` the state just before chi. The packed `uint64x2_t` values
    // below (`c01`, `c23`, `d01`, `d23`, `chi01`, `chi23`) carry the same
    // words through the intrinsics; they live in vector registers, have no
    // address to wipe, and are overwritten by the next round's values.
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];
    let mut b = [0u64; 25];
    for &rc in &RC {
        // === Theta ===
        // Column parities: c[x] = XOR of 5 lanes in column x.
        // EOR3(a,b,c) = a^b^c; chaining two EOR3s gives a 5-way XOR.

        // c[0] and c[1] in one SIMD register.
        let c01 = {
            let t = veor3q_u64(
                u64x2(state[0], state[1]),
                u64x2(state[5], state[6]),
                u64x2(state[10], state[11]),
            );
            veor3q_u64(t, u64x2(state[15], state[16]), u64x2(state[20], state[21]))
        };
        // c[2] and c[3].
        let c23 = {
            let t = veor3q_u64(
                u64x2(state[2], state[3]),
                u64x2(state[7], state[8]),
                u64x2(state[12], state[13]),
            );
            veor3q_u64(t, u64x2(state[17], state[18]), u64x2(state[22], state[23]))
        };
        // c[4] is the odd column; compute it scalar.
        let c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        c = [
            vgetq_lane_u64::<0>(c01),
            vgetq_lane_u64::<1>(c01),
            vgetq_lane_u64::<0>(c23),
            vgetq_lane_u64::<1>(c23),
            c4,
        ];

        // D[x] = C[(x+4)%5] ^ rotate_left(C[(x+1)%5], 1).
        // vrax1q_u64(a, b) = a ^ rotate_left(b, 1), elementwise.
        //   D[0] = c4 ^ rotl(c1, 1)    D[1] = c0 ^ rotl(c2, 1)
        //   D[2] = c1 ^ rotl(c3, 1)    D[3] = c2 ^ rotl(c4, 1)
        let d01 = vrax1q_u64(u64x2(c[4], c[0]), u64x2(c[1], c[2]));
        let d23 = vrax1q_u64(u64x2(c[1], c[2]), u64x2(c[3], c[4]));
        let d4 = c[3] ^ c[0].rotate_left(1); // scalar

        d = [
            vgetq_lane_u64::<0>(d01),
            vgetq_lane_u64::<1>(d01),
            vgetq_lane_u64::<0>(d23),
            vgetq_lane_u64::<1>(d23),
            d4,
        ];

        // Apply D[x] to every lane in column x.
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // === Rho + Pi (scalar) ===
        // Each of the 24 non-zero-rotation lanes has a unique RHO value, so
        // XAR (which applies the same rotation to both elements of a pair)
        // gives no advantage.  Keep the existing scalar loop.
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(RHO[i]);
        }

        // === Chi using BCAX ===
        // chi[x] = b[x] ^ (!b[(x+1)%5] & b[(x+2)%5])
        //        = BCAX(b[x], b[(x+2)%5], b[(x+1)%5])
        // vbcaxq_u64(a, b, c) = a ^ (b & !c), elementwise.
        // Process each row of 5 lanes as two SIMD pairs + one scalar.
        for y in 0..5 {
            let r = y * 5;
            // x=0: BCAX(b[0], b[2], b[1])    x=1: BCAX(b[1], b[3], b[2])
            let chi01 = vbcaxq_u64(
                u64x2(b[r], b[r + 1]),
                u64x2(b[r + 2], b[r + 3]),
                u64x2(b[r + 1], b[r + 2]),
            );
            // x=2: BCAX(b[2], b[4], b[3])    x=3: BCAX(b[3], b[0], b[4])
            let chi23 = vbcaxq_u64(
                u64x2(b[r + 2], b[r + 3]),
                u64x2(b[r + 4], b[r]),
                u64x2(b[r + 3], b[r + 4]),
            );
            state[r] = vgetq_lane_u64::<0>(chi01);
            state[r + 1] = vgetq_lane_u64::<1>(chi01);
            state[r + 2] = vgetq_lane_u64::<0>(chi23);
            state[r + 3] = vgetq_lane_u64::<1>(chi23);
            // x=4: BCAX(b[4], b[1], b[0]) = b[4] ^ (b[1] & !b[0])
            state[r + 4] = b[r + 4] ^ (b[r + 1] & !b[r]);
        }

        // === Iota ===
        state[0] ^= rc;
    }
    crate::ct::zeroize_slice(c.as_mut_slice());
    crate::ct::zeroize_slice(d.as_mut_slice());
    crate::ct::zeroize_slice(b.as_mut_slice());
}

#[inline]
fn absorb_block<const RATE: usize>(state: &mut [u64; 25], block: &[u8; RATE]) {
    debug_assert_eq!(RATE % 8, 0, "Keccak rate must be lane-aligned");
    let lanes = RATE / 8;
    let mut i = 0usize;
    while i < lanes {
        let lane = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        state[i] ^= lane;
        i += 1;
    }
    keccak_f1600(state);
}

/// Serialize the rate lanes of `state` into `out` (little-endian), writing in
/// place so no temporary copy of the output block is left behind.
#[inline]
fn load_rate_bytes<const RATE: usize>(state: &[u64; 25], out: &mut [u8; RATE]) {
    let lanes = RATE / 8;
    let mut i = 0usize;
    while i < lanes {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        i += 1;
    }
}

/// One Keccak sponge (FIPS 202 §4, Algorithm 8) over Keccak-f\[1600\] with a
/// rate of `RATE` bytes, in either of its two phases, and finalized in place
/// so the state is never copied between phases.
///
/// While absorbing, `block` buffers the not-yet-absorbed tail of the input
/// and `pos` counts it. Once [`Keccak::pad_and_permute`] has applied the
/// domain suffix and `pad10*1` (§5.1) the sponge is squeezing: `block` holds
/// the rate bytes of the current state and `pos` counts how many of them
/// have been emitted. Every value wipes itself on drop.
#[derive(Clone)]
struct Keccak<const RATE: usize> {
    state: [u64; 25],
    block: [u8; RATE],
    pos: usize,
    squeezing: bool,
}

impl<const RATE: usize> Drop for Keccak<RATE> {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl<const RATE: usize> Keccak<RATE> {
    /// A fresh absorbing sponge: Keccak starts from the all-zero state
    /// (Algorithm 8, step 5).
    fn new() -> Self {
        Self {
            state: [0u64; 25],
            block: [0u8; RATE],
            pos: 0,
            squeezing: false,
        }
    }

    /// Wipe the state and block buffer. Because the initial state is zero,
    /// a wiped sponge is also a fresh one.
    fn wipe(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.squeezing = false;
    }

    /// Absorb `data`: XOR each completed rate block into the state and
    /// permute (Algorithm 8, step 6); buffer any partial block.
    ///
    /// # Panics
    ///
    /// Panics once the sponge is squeezing: a sponge cannot absorb more
    /// input after its output has begun.
    fn update(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "cannot absorb after squeezing");
        while !data.is_empty() {
            let take = (RATE - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == RATE {
                absorb_block(&mut self.state, &self.block);
                self.block = [0u8; RATE];
                self.pos = 0;
            }
        }
    }

    /// Finish absorbing in place and enter the squeezing phase.
    ///
    /// `suffix` is the domain-separation bits followed by the first `1` of
    /// `pad10*1` (§5.1), as one byte in the little-endian bit order of
    /// Appendix B.2: `0x06` for the SHA-3 hash functions (M || 01, §6.1) and
    /// `0x1f` for SHAKE (M || 1111, §6.2). It is XORed into the byte after
    /// the buffered input, the closing `1` bit into the last rate byte; when
    /// the buffered input stops one byte short of the rate the two land in
    /// the same byte (`0x86` or `0x9f`). The padded block is absorbed and
    /// the rate bytes of the resulting state are exposed for squeezing.
    fn pad_and_permute(&mut self, suffix: u8) {
        debug_assert!(!self.squeezing, "the sponge is already squeezing");
        self.block[self.pos] ^= suffix;
        self.block[RATE - 1] ^= 0x80;
        absorb_block(&mut self.state, &self.block);
        load_rate_bytes(&self.state, &mut self.block);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Squeeze (Algorithm 8, steps 8 to 10): copy from the rate bytes,
    /// permuting for a fresh block whenever they are exhausted.
    fn squeeze(&mut self, out: &mut [u8]) {
        debug_assert!(self.squeezing, "pad_and_permute comes first");
        let mut produced = 0usize;
        while produced < out.len() {
            if self.pos == RATE {
                keccak_f1600(&mut self.state);
                load_rate_bytes(&self.state, &mut self.block);
                self.pos = 0;
            }

            let take = (out.len() - produced).min(RATE - self.pos);
            out[produced..produced + take].copy_from_slice(&self.block[self.pos..self.pos + take]);
            produced += take;
            self.pos += take;
        }
    }

    /// Fixed-output finalization: pad with `suffix`, then fill `out` from
    /// the leading rate bytes. The sponge is left in the squeezing phase;
    /// the callers decide whether it is dropped (`finalize`) or replaced
    /// (`finalize_reset`).
    fn finalize_in_place(&mut self, suffix: u8, out: &mut [u8]) {
        self.pad_and_permute(suffix);
        self.squeeze(out);
    }
}

macro_rules! define_sha3 {
    ($name:ident, $rate:expr, $out_len:expr) => {
        /// Fixed-output SHA-3 hasher from FIPS 202: a sponge over the
        /// 1600-bit (200-byte) Keccak-f\[1600\] permutation with the SHA-3
        /// domain-separation suffix `0x06`.
        ///
        #[doc = concat!("`", stringify!($name), "` absorbs input at a rate of")]
        #[doc = concat!(stringify!($rate), " bytes per permutation call and emits a")]
        #[doc = concat!(stringify!($out_len), "-byte digest; the remaining state")]
        /// bytes form the capacity, twice the digest length. As a sponge, the
        /// digest is not subject to length-extension attacks.
        #[derive(Clone)]
        pub struct $name {
            inner: Keccak<$rate>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Keccak sponge rate in bytes (200 minus twice the digest
            /// length); this is also the block size HMAC uses with the SHA-3
            /// family.
            pub const BLOCK_LEN: usize = $rate;
            /// Digest length in bytes; the sponge capacity is twice this, so
            /// collision resistance is half the digest length in bits.
            pub const OUTPUT_LEN: usize = $out_len;

            /// Begin hashing from the all-zero 1600-bit Keccak state with an
            /// empty rate buffer.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    inner: Keccak::new(),
                }
            }

            /// Absorb `data`, XORing each completed rate-sized block into the
            /// state (little-endian lanes) and permuting; partial blocks are
            /// buffered, so a message may be split across calls arbitrarily.
            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            /// Consume the hasher: XOR in the `0x06` domain suffix and the
            /// closing bit of the `pad10*1` rule, permute once more, and
            /// return the digest read from the leading state lanes in
            /// little-endian byte order.
            #[must_use]
            pub fn finalize(mut self) -> [u8; $out_len] {
                let mut out = [0u8; $out_len];
                self.inner.finalize_in_place(0x06, &mut out);
                // `self` drops here, and `Drop` wipes the final state.
                out
            }

            /// One-shot hash of `data`, equivalent to `new` + `update` +
            /// `finalize`; returns a fixed-size array rather than the `Vec`
            /// of the `Digest::digest` trait helper.
            #[must_use]
            pub fn digest(data: &[u8]) -> [u8; $out_len] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Digest for $name {
            const BLOCK_LEN: usize = $rate;
            const OUTPUT_LEN: usize = $out_len;

            fn new() -> Self {
                $name {
                    inner: Keccak::new(),
                }
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(mut self, out: &mut [u8]) {
                assert_eq!(out.len(), $out_len, "wrong digest length");
                self.inner.finalize_in_place(0x06, out);
            }

            fn finalize_reset(&mut self, out: &mut [u8]) {
                assert_eq!(out.len(), $out_len, "wrong digest length");
                self.inner.finalize_in_place(0x06, out);
                // Assigning a fresh sponge drops the consumed one, and `Drop`
                // wipes its state.
                self.inner = Keccak::new();
            }

            fn zeroize(&mut self) {
                self.inner.wipe();
            }
        }
    };
}

define_sha3!(Sha3_224, 144, 28);
define_sha3!(Sha3_256, 136, 32);
define_sha3!(Sha3_384, 104, 48);
define_sha3!(Sha3_512, 72, 64);

macro_rules! define_shake {
    ($name:ident, $rate:expr) => {
        /// Extendable-output function from FIPS 202: a sponge over the
        /// 1600-bit (200-byte) Keccak-f\[1600\] permutation with the SHAKE
        /// domain-separation suffix `0x1f`.
        ///
        #[doc = concat!("`", stringify!($name), "` absorbs and squeezes at a rate of")]
        #[doc = concat!(stringify!($rate), " bytes per permutation call; the")]
        /// remaining state bytes form the capacity, twice the security
        /// strength the variant is named for.
        ///
        /// Absorb with [`Xof::update`], then draw any number of output bytes
        /// with [`Xof::squeeze`]; the first squeeze finalizes the sponge in
        /// place, and updating after that panics. The state is zeroized on
        /// drop.
        #[derive(Clone)]
        pub struct $name {
            inner: Keccak<$rate>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Keccak sponge rate in bytes: input is absorbed and output
            /// squeezed in blocks of this size, one permutation call per
            /// block.
            pub const BLOCK_LEN: usize = $rate;

            /// Begin a fresh absorb-phase sponge with an all-zero 1600-bit
            /// Keccak state.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    inner: Keccak::new(),
                }
            }

            /// One-shot XOF: absorb `data`, then fill all of `out` with
            /// squeezed output. `out.len()` selects the output length, and a
            /// longer output begins with the bytes of a shorter one.
            pub fn digest(data: &[u8], out: &mut [u8]) {
                let mut xof = Self::new();
                xof.update(data);
                xof.squeeze(out);
            }
        }

        impl Xof for $name {
            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn squeeze(&mut self, out: &mut [u8]) {
                if !self.inner.squeezing {
                    self.inner.pad_and_permute(0x1f);
                }
                self.inner.squeeze(out);
            }
        }
    };
}

define_shake!(Shake128, 168);
define_shake!(Shake256, 136);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::encode_hex;

    /// `finalize_reset` leaves a fresh sponge (for Keccak the zero state),
    /// `zeroize` scrubs it, and every SHA-3 and SHAKE type wipes itself on
    /// drop.
    #[test]
    fn finalize_reset_and_zeroize_scrub_the_state() {
        let msg = b"HMAC feeds key material through this state";
        let mut h = Sha3_256::new();
        h.update(msg);
        let mut out = [0u8; 32];
        crate::hash::Digest::finalize_reset(&mut h, &mut out);
        assert_eq!(out, Sha3_256::digest(msg));
        assert_eq!(h.inner.state, [0u64; 25]);
        assert!(h.inner.block.iter().all(|&b| b == 0));
        assert_eq!((h.inner.pos, h.inner.squeezing), (0, false));

        let mut h = Sha3_512::new();
        h.update(b"a partial block");
        crate::hash::Digest::zeroize(&mut h);
        assert_eq!((h.inner.state, h.inner.pos), ([0u64; 25], 0));

        let mut xof = Shake128::new();
        xof.update(msg);
        xof.squeeze(&mut out);
        assert!(xof.inner.squeezing);
        drop(xof);

        assert!(core::mem::needs_drop::<Sha3_224>());
        assert!(core::mem::needs_drop::<Sha3_256>());
        assert!(core::mem::needs_drop::<Sha3_384>());
        assert!(core::mem::needs_drop::<Sha3_512>());
        assert!(core::mem::needs_drop::<Shake128>());
        assert!(core::mem::needs_drop::<Shake256>());
    }

    #[test]
    fn sha3_224_empty() {
        assert_eq!(
            encode_hex(&Sha3_224::digest(b"")),
            "6b4e03423667dbb73b6e15454f0eb1ab".to_owned() + "d4597f9a1b078e3f5b5a6bc7"
        );
    }

    #[test]
    fn sha3_256_empty() {
        assert_eq!(
            encode_hex(&Sha3_256::digest(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662".to_owned() + "f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn sha3_256_abc_streaming() {
        let mut h = Sha3_256::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            encode_hex(&h.finalize()),
            "3a985da74fe225b2045c172d6bd390bd".to_owned() + "855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_384_empty() {
        assert_eq!(
            encode_hex(&Sha3_384::digest(b"")),
            "0c63a75b845e4f7d01107d852e4c2485".to_owned()
                + "c51a50aaaa94fc61995e71bbee983a2a"
                + "c3713831264adb47fb6bd1e058d5f004"
        );
    }

    #[test]
    fn sha3_512_empty() {
        assert_eq!(
            encode_hex(&Sha3_512::digest(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e".to_owned()
                + "97c982164fe25859e0d1dcc1475c80a6"
                + "15b2123af1f5f94c11e3e9402c3ac558"
                + "f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn shake128_empty_32() {
        let mut out = [0u8; 32];
        Shake128::digest(b"", &mut out);
        assert_eq!(
            encode_hex(&out),
            "7f9c2ba4e88f827d616045507605853e".to_owned() + "d73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn shake128_abc_streaming_32() {
        let mut xof = Shake128::new();
        xof.update(b"a");
        xof.update(b"b");
        xof.update(b"c");
        let mut out = [0u8; 32];
        xof.squeeze(&mut out);
        assert_eq!(
            encode_hex(&out),
            "5881092dd818bf5cf8a3ddb793fbcba7".to_owned() + "4097d5c526a6d35f97b83351940f2cc8"
        );
    }

    #[test]
    fn shake128_chunked_squeeze_matches_one_shot() {
        let mut one_shot = Shake128::new();
        one_shot.update(b"abc");
        let mut full = [0u8; 64];
        one_shot.squeeze(&mut full);

        let mut chunked = Shake128::new();
        chunked.update(b"abc");
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        chunked.squeeze(&mut left);
        chunked.squeeze(&mut right);

        assert_eq!([left.as_slice(), right.as_slice()].concat(), full);
    }

    #[test]
    fn shake256_empty_64() {
        let mut out = [0u8; 64];
        Shake256::digest(b"", &mut out);
        assert_eq!(
            encode_hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb24".to_owned()
                + "3fcd52ea62b81b82b50c27646ed5762f"
                + "d75dc4ddd8c0f200cb05019d67b592f6"
                + "fc821c49479ab48640292eacb3b7c4be"
        );
    }

    #[test]
    fn sha3_224_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha3-224", "-binary"], msg)
            .or_skip("sha3_224_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha3_224::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha3_256_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha3-256", "-binary"], msg)
            .or_skip("sha3_256_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha3_256::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha3_384_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha3-384", "-binary"], msg)
            .or_skip("sha3_384_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha3_384::digest(msg).as_slice(), expected.as_slice());
    }

    #[test]
    fn sha3_512_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(&["dgst", "-sha3-512", "-binary"], msg)
            .or_skip("sha3_512_matches_openssl")
        else {
            return;
        };
        assert_eq!(Sha3_512::digest(msg).as_slice(), expected.as_slice());
    }

    /// `Xof::update` after the first squeeze panics: the sponge is in output
    /// mode and cannot absorb.
    #[test]
    #[should_panic(expected = "cannot absorb after squeezing")]
    fn shake128_update_after_squeeze_panics() {
        let mut xof = Shake128::new();
        xof.update(b"absorbed");
        let mut out = [0u8; 16];
        xof.squeeze(&mut out);
        xof.update(b"too late");
    }

    /// The same for SHAKE256.
    #[test]
    #[should_panic(expected = "cannot absorb after squeezing")]
    fn shake256_update_after_squeeze_panics() {
        let mut xof = Shake256::new();
        xof.update(b"absorbed");
        let mut out = [0u8; 16];
        xof.squeeze(&mut out);
        xof.update(b"too late");
    }

    /// The message of `len` bytes the pad-edge cross-checks hash: a fixed
    /// non-constant pattern.
    fn message(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(13) ^ (i >> 2)) as u8)
            .collect()
    }

    /// Message lengths at which `pad10*1` changes shape for a rate of `rate`
    /// bytes (FIPS 202 §5.1 and Appendix B.2): at `rate - 2` the suffix and
    /// the closing bit occupy separate bytes; at `rate - 1` they share the
    /// last rate byte (`0x86` / `0x9f`); at `rate` the message fills a block
    /// and the padding is a whole block of its own. The same three lengths
    /// one block later, and `rate + 1`, cover the multi-block absorb.
    fn pad_edge_lengths(rate: usize) -> [usize; 7] {
        [
            rate - 2,
            rate - 1,
            rate,
            rate + 1,
            2 * rate - 2,
            2 * rate - 1,
            2 * rate,
        ]
    }

    /// Cross-check a SHA-3 hash against `openssl dgst <flag>` at the
    /// pad-edge lengths, hashing in one call and byte by byte.
    fn sha3_pad_edges_match_openssl<H: Digest>(flag: &str, test: &str) {
        for len in pad_edge_lengths(H::BLOCK_LEN) {
            let msg = message(len);
            let Some(expected) =
                crate::test_utils::openssl(&["dgst", flag, "-binary"], &msg).or_skip(test)
            else {
                return;
            };
            assert_eq!(H::digest(&msg), expected, "{test}: {len}-byte message");
            let mut h = H::new();
            for byte in &msg {
                h.update(core::slice::from_ref(byte));
            }
            let mut out = vec![0u8; H::OUTPUT_LEN];
            h.finalize_into(&mut out);
            assert_eq!(out, expected, "{test}: {len}-byte message, byte by byte");
        }
    }

    #[test]
    fn sha3_224_pad_edges_match_openssl() {
        sha3_pad_edges_match_openssl::<Sha3_224>("-sha3-224", "sha3_224_pad_edges_match_openssl");
    }

    #[test]
    fn sha3_256_pad_edges_match_openssl() {
        sha3_pad_edges_match_openssl::<Sha3_256>("-sha3-256", "sha3_256_pad_edges_match_openssl");
    }

    #[test]
    fn sha3_384_pad_edges_match_openssl() {
        sha3_pad_edges_match_openssl::<Sha3_384>("-sha3-384", "sha3_384_pad_edges_match_openssl");
    }

    #[test]
    fn sha3_512_pad_edges_match_openssl() {
        sha3_pad_edges_match_openssl::<Sha3_512>("-sha3-512", "sha3_512_pad_edges_match_openssl");
    }

    /// Cross-check a SHAKE XOF against `openssl dgst <flag> -xoflen N` at the
    /// pad-edge lengths, with `N = rate + 9` so the output crosses one
    /// squeeze boundary; the output is also drawn in two uneven pieces.
    fn shake_pad_edges_match_openssl<X: Xof>(new: fn() -> X, rate: usize, flag: &str, test: &str) {
        let xoflen = rate + 9;
        let xoflen_arg = xoflen.to_string();
        for len in pad_edge_lengths(rate) {
            let msg = message(len);
            let Some(expected) = crate::test_utils::openssl(
                &["dgst", flag, "-xoflen", &xoflen_arg, "-binary"],
                &msg,
            )
            .or_skip(test) else {
                return;
            };
            assert_eq!(expected.len(), xoflen, "{test}: openssl output length");

            let mut xof = new();
            xof.update(&msg);
            let mut out = vec![0u8; xoflen];
            xof.squeeze(&mut out);
            assert_eq!(out, expected, "{test}: {len}-byte message");

            let mut xof = new();
            for byte in &msg {
                xof.update(core::slice::from_ref(byte));
            }
            let (head, tail) = out.split_at_mut(rate - 3);
            xof.squeeze(head);
            xof.squeeze(tail);
            assert_eq!(out, expected, "{test}: {len}-byte message, piecewise");
        }
    }

    #[test]
    fn shake128_pad_edges_match_openssl() {
        shake_pad_edges_match_openssl(
            Shake128::new,
            Shake128::BLOCK_LEN,
            "-shake128",
            "shake128_pad_edges_match_openssl",
        );
    }

    #[test]
    fn shake256_pad_edges_match_openssl() {
        shake_pad_edges_match_openssl(
            Shake256::new,
            Shake256::BLOCK_LEN,
            "-shake256",
            "shake256_pad_edges_match_openssl",
        );
    }

    /// FIPS 202 §3.2.5, Algorithm 5, rc(t): the output bit of a linear
    /// feedback shift register over eight bits, written as the Standard does
    /// with R\[0\] the leftmost bit of the bit string R.
    fn rc(t: usize) -> u64 {
        // 1. If t mod 255 = 0, return 1.
        if t.is_multiple_of(255) {
            return 1;
        }
        // 2. Let R = 10000000.
        let mut r = [1u8, 0, 0, 0, 0, 0, 0, 0];
        // 3. For i from 1 to t mod 255, let:
        for _ in 1..=(t % 255) {
            // a. R = 0 || R;
            let mut r9 = [0u8; 9];
            r9[1..].copy_from_slice(&r);
            // b. R[0] = R[0] ⊕ R[8];  c. R[4] = R[4] ⊕ R[8];
            // d. R[5] = R[5] ⊕ R[8];  e. R[6] = R[6] ⊕ R[8];
            r9[0] ^= r9[8];
            r9[4] ^= r9[8];
            r9[5] ^= r9[8];
            r9[6] ^= r9[8];
            // f. R = Trunc8[R].
            r.copy_from_slice(&r9[..8]);
        }
        // 4. Return R[0].
        u64::from(r[0])
    }

    /// FIPS 202 §3.2.5, Algorithm 6, steps 2 and 3: for round index i_r the
    /// lane constant RC has RC\[2^j − 1\] = rc(j + 7 i_r) for 0 ≤ j ≤ l, with
    /// l = 6 for the 64-bit lanes of Keccak-f\[1600\] (§3.1, Table 1), every
    /// other bit zero. Bit z of a lane is the 2^z place of the `u64`
    /// (Appendix B.1). The 24 rounds of Keccak-f\[1600\] are i_r = 0 to 23
    /// (§3.4, with n_r = 24 rounds indexed 12 + 2l − n_r to 12 + 2l − 1).
    #[test]
    fn round_constants_come_from_the_algorithm_5_lfsr() {
        for (i_r, &constant) in RC.iter().enumerate() {
            let mut expected = 0u64;
            for j in 0..=6 {
                expected |= rc(j + 7 * i_r) << ((1usize << j) - 1);
            }
            assert_eq!(constant, expected, "RC[{i_r}]");
        }
    }

    /// FIPS 202 §3.2.2, Algorithm 2 (ρ): starting from (x, y) = (1, 0), the
    /// lane visited at step t (0 ≤ t ≤ 23) is rotated by (t + 1)(t + 2)/2
    /// mod w, and the walk continues to (y, (2x + 3y) mod 5); lane (0, 0) is
    /// not rotated. `RHO` is indexed x + 5y.
    #[test]
    fn rho_offsets_come_from_the_algorithm_2_walk() {
        let mut expected = [0u32; 25];
        let (mut x, mut y) = (1usize, 0usize);
        for t in 0..24u32 {
            expected[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        assert_eq!(RHO, expected);
    }

    /// FIPS 202 §3.2.3, Algorithm 3 (π): A′\[x, y\] = A\[(x + 3y) mod 5, x\].
    /// `PI` maps each source lane index x′ + 5y′ to the destination index it
    /// lands at, so for every destination (x, y) the source must be
    /// ((x + 3y) mod 5, x).
    #[test]
    fn pi_permutation_is_algorithm_3() {
        for y in 0..5 {
            for x in 0..5 {
                let source = (x + 3 * y) % 5 + 5 * x;
                assert_eq!(PI[source], x + 5 * y, "A'[{x}, {y}]");
            }
        }
    }
}
