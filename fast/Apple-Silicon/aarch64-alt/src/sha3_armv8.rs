//! Keccak-f[1600] backend using ARMv8.2 FEAT_SHA3 intrinsics.
//!
//! Uses EOR3 (3-way XOR), RAX1 (rotate-and-XOR), and BCAX (bit-clear-and-XOR)
//! to accelerate the theta column-parity and chi nonlinear steps.
//! Rho+Pi remain scalar: each of the 24 non-zero-rotation lanes has a unique
//! rotation offset, so XAR (same rotation for both SIMD lanes) cannot pair
//! them usefully.
//!
//! # Author
//! Darrell Long (Rust implementation).

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

/// Returns `true` when FEAT_SHA3 is available at runtime.
pub fn is_supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("sha3")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// SHA3-512 backed by hardware Keccak-f[1600].
///
/// Bit-compatible with `cryptography::Sha3_512`.  Use `is_supported()` before
/// calling; panics at runtime on hardware without FEAT_SHA3.
pub struct Sha3_512Armv8;

impl Sha3_512Armv8 {
    /// One-shot hash.  Panics if FEAT_SHA3 is not present.
    pub fn digest(data: &[u8]) -> [u8; 64] {
        assert!(is_supported(), "FEAT_SHA3 not available");
        // Rate for SHA3-512: 1600 - 2*512 = 576 bits = 72 bytes.
        const RATE: usize = 72;
        let mut state = [0u64; 25];
        let mut block = [0u8; RATE];
        let mut pos = 0usize;

        // Absorb.
        let mut rem = data;
        while !rem.is_empty() {
            let take = (RATE - pos).min(rem.len());
            block[pos..pos + take].copy_from_slice(&rem[..take]);
            pos += take;
            rem = &rem[take..];
            if pos == RATE {
                absorb_block(&mut state, &block);
                block = [0u8; RATE];
                pos = 0;
            }
        }

        // Padding (SHA3 domain suffix 0x06, then 0x80 at end of rate block).
        block[pos] ^= 0x06;
        block[RATE - 1] ^= 0x80;
        absorb_block(&mut state, &block);

        // Squeeze 64 bytes.
        let mut out = [0u8; 64];
        let lanes = 64 / 8;
        for i in 0..lanes {
            out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        out
    }
}

fn absorb_block(state: &mut [u64; 25], block: &[u8; 72]) {
    for i in 0..9 {
        let lane = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        state[i] ^= lane;
    }
    // SAFETY: is_supported() was checked before any call reaches here.
    unsafe { keccak_f1600_sha3(state); }
}

// Keccak-f[1600] rho rotation offsets (FIPS 202, lane A[x,y]).
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

// Keccak-f[1600] pi-step permutation: (x,y) -> (y, (2x+3y) mod 5).
const PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

// Round constants.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
    0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn keccak_f1600_sha3(state: &mut [u64; 25]) {
    #[inline(always)]
    unsafe fn u64x2(a: u64, b: u64) -> uint64x2_t {
        vcombine_u64(vdup_n_u64(a), vdup_n_u64(b))
    }

    for &rc in &RC {
        // === Theta: column parities via EOR3 ===
        let c01 = {
            let t = veor3q_u64(
                u64x2(state[0],  state[1]),
                u64x2(state[5],  state[6]),
                u64x2(state[10], state[11]),
            );
            veor3q_u64(t, u64x2(state[15], state[16]), u64x2(state[20], state[21]))
        };
        let c23 = {
            let t = veor3q_u64(
                u64x2(state[2],  state[3]),
                u64x2(state[7],  state[8]),
                u64x2(state[12], state[13]),
            );
            veor3q_u64(t, u64x2(state[17], state[18]), u64x2(state[22], state[23]))
        };
        let c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        let c0 = vgetq_lane_u64::<0>(c01);
        let c1 = vgetq_lane_u64::<1>(c01);
        let c2 = vgetq_lane_u64::<0>(c23);
        let c3 = vgetq_lane_u64::<1>(c23);

        // D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1)  via RAX1.
        // vrax1q_u64(a, b) = a ^ rotl(b, 1), elementwise.
        let d01 = vrax1q_u64(u64x2(c4, c0), u64x2(c1, c2)); // [D[0], D[1]]
        let d23 = vrax1q_u64(u64x2(c1, c2), u64x2(c3, c4)); // [D[2], D[3]]
        let d = [
            vgetq_lane_u64::<0>(d01),
            vgetq_lane_u64::<1>(d01),
            vgetq_lane_u64::<0>(d23),
            vgetq_lane_u64::<1>(d23),
            c3 ^ c0.rotate_left(1), // D[4]
        ];

        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // === Rho + Pi (scalar) ===
        let mut b = [0u64; 25];
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(RHO[i]);
        }

        // === Chi via BCAX ===
        // chi[x] = b[x] ^ (!b[(x+1)%5] & b[(x+2)%5])
        //        = vbcaxq_u64(b[x], b[(x+2)%5], b[(x+1)%5])
        for y in 0..5 {
            let r = y * 5;
            let chi01 = vbcaxq_u64(
                u64x2(b[r],   b[r+1]),
                u64x2(b[r+2], b[r+3]),
                u64x2(b[r+1], b[r+2]),
            );
            let chi23 = vbcaxq_u64(
                u64x2(b[r+2], b[r+3]),
                u64x2(b[r+4], b[r  ]),
                u64x2(b[r+3], b[r+4]),
            );
            state[r  ] = vgetq_lane_u64::<0>(chi01);
            state[r+1] = vgetq_lane_u64::<1>(chi01);
            state[r+2] = vgetq_lane_u64::<0>(chi23);
            state[r+3] = vgetq_lane_u64::<1>(chi23);
            state[r+4] = b[r+4] ^ (b[r+1] & !b[r]); // BCAX(b[4], b[1], b[0])
        }

        // === Iota ===
        state[0] ^= rc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::Sha3_512;

    #[test]
    fn sha3_512_empty() {
        if !is_supported() { return; }
        assert_eq!(Sha3_512Armv8::digest(b""), Sha3_512::digest(b""));
    }

    #[test]
    fn sha3_512_abc() {
        if !is_supported() { return; }
        assert_eq!(Sha3_512Armv8::digest(b"abc"), Sha3_512::digest(b"abc"));
    }

    fn xorshift64(s: &mut u64) -> u64 { *s ^= *s<<13; *s ^= *s>>7; *s ^= *s<<17; *s }

    #[test]
    fn matches_baseline_random_messages() {
        if !is_supported() { return; }
        let mut seed = 0xdeadbeefcafe1234u64;
        for _ in 0..500 {
            let len = (xorshift64(&mut seed) as usize) % 1024;
            let msg: Vec<u8> = (0..len).map(|_| xorshift64(&mut seed) as u8).collect();
            assert_eq!(
                Sha3_512Armv8::digest(&msg),
                Sha3_512::digest(&msg),
                "mismatch at len={len}"
            );
        }
    }
}
