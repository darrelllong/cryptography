//! SHA-256 backend for Apple Silicon (`aarch64` + FEAT_SHA2).
//!
//! Uses the ARM SHA2 round and schedule intrinsics (`vsha256*`) while keeping
//! digest semantics exactly aligned with the baseline `cryptography::Sha256`.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vld1q_u32, vld1q_u8, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32,
    vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256Armv8Error {
    MissingSha2Feature,
}

pub struct Sha256Armv8;

impl Sha256Armv8 {
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_arch = "aarch64")]
        {
            return std::arch::is_aarch64_feature_detected!("sha2");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            false
        }
    }

    pub fn digest(data: &[u8]) -> Result<[u8; 32], Sha256Armv8Error> {
        if !Self::is_supported() {
            return Err(Sha256Armv8Error::MissingSha2Feature);
        }

        // Standard SHA-256 IV.
        let mut state = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];

        let full = data.len() & !63;
        for chunk in data[..full].chunks_exact(64) {
            // Keep compression input as fixed-size blocks for the hw kernel.
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            compress(&mut state, &block);
        }

        // SHA-256 padding and 64-bit big-endian bit length.
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut tail = [0u8; 128];
        let rem = data.len() - full;
        tail[..rem].copy_from_slice(&data[full..]);
        tail[rem] = 0x80;

        if rem + 1 + 8 <= 64 {
            tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let mut block = [0u8; 64];
            block.copy_from_slice(&tail[..64]);
            compress(&mut state, &block);
        } else {
            tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
            let mut block0 = [0u8; 64];
            block0.copy_from_slice(&tail[..64]);
            compress(&mut state, &block0);
            let mut block1 = [0u8; 64];
            block1.copy_from_slice(&tail[64..128]);
            compress(&mut state, &block1);
        }

        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Ok(out)
    }
}

#[cfg(target_arch = "aarch64")]
// FIPS 180-4 round constants K[0..63], grouped as 16 vectors of 4 words.
const K32X4: [[u32; 4]; 16] = [
    [0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5],
    [0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5],
    [0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3],
    [0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174],
    [0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc],
    [0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da],
    [0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7],
    [0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967],
    [0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13],
    [0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85],
    [0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3],
    [0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070],
    [0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5],
    [0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3],
    [0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208],
    [0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2],
];

#[inline]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        compress_block_hw(state, block);
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn load_be(ptr: *const u8) -> uint32x4_t {
    // SHA-256 words are big-endian; NEON loads native-endian lanes.
    let bytes = vld1q_u8(ptr);
    let swapped = vrev32q_u8(bytes);
    vreinterpretq_u32_u8(swapped)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
unsafe fn compress_block_hw(state: &mut [u32; 8], block: &[u8; 64]) {
    // abcd/efgh hold the eight state words in two vectors.
    let mut abcd = vld1q_u32(state.as_ptr());
    let mut efgh = vld1q_u32(state.as_ptr().add(4));
    let abcd0 = abcd;
    let efgh0 = efgh;

    let mut w0 = load_be(block.as_ptr());
    let mut w1 = load_be(block.as_ptr().add(16));
    let mut w2 = load_be(block.as_ptr().add(32));
    let mut w3 = load_be(block.as_ptr().add(48));

    // SHA2 instructions process four rounds at a time. The macro keeps the
    // state update pattern explicit while minimizing call overhead.
    macro_rules! round4 {
        ($w:expr, $kidx:expr) => {{
            let wk = vaddq_u32($w, vld1q_u32(K32X4[$kidx].as_ptr()));
            let tmp = abcd;
            abcd = vsha256hq_u32(abcd, efgh, wk);
            efgh = vsha256h2q_u32(efgh, tmp, wk);
        }};
    }

    round4!(w0, 0);
    round4!(w1, 1);
    round4!(w2, 2);
    round4!(w3, 3);

    // Message schedule expansion is pipelined with round execution.
    w0 = vsha256su0q_u32(w0, w1);
    w0 = vsha256su1q_u32(w0, w2, w3);
    round4!(w0, 4);

    w1 = vsha256su0q_u32(w1, w2);
    w1 = vsha256su1q_u32(w1, w3, w0);
    round4!(w1, 5);

    w2 = vsha256su0q_u32(w2, w3);
    w2 = vsha256su1q_u32(w2, w0, w1);
    round4!(w2, 6);

    w3 = vsha256su0q_u32(w3, w0);
    w3 = vsha256su1q_u32(w3, w1, w2);
    round4!(w3, 7);

    w0 = vsha256su0q_u32(w0, w1);
    w0 = vsha256su1q_u32(w0, w2, w3);
    round4!(w0, 8);

    w1 = vsha256su0q_u32(w1, w2);
    w1 = vsha256su1q_u32(w1, w3, w0);
    round4!(w1, 9);

    w2 = vsha256su0q_u32(w2, w3);
    w2 = vsha256su1q_u32(w2, w0, w1);
    round4!(w2, 10);

    w3 = vsha256su0q_u32(w3, w0);
    w3 = vsha256su1q_u32(w3, w1, w2);
    round4!(w3, 11);

    w0 = vsha256su0q_u32(w0, w1);
    w0 = vsha256su1q_u32(w0, w2, w3);
    round4!(w0, 12);

    w1 = vsha256su0q_u32(w1, w2);
    w1 = vsha256su1q_u32(w1, w3, w0);
    round4!(w1, 13);

    w2 = vsha256su0q_u32(w2, w3);
    w2 = vsha256su1q_u32(w2, w0, w1);
    round4!(w2, 14);

    w3 = vsha256su0q_u32(w3, w0);
    w3 = vsha256su1q_u32(w3, w1, w2);
    round4!(w3, 15);

    abcd = vaddq_u32(abcd, abcd0);
    efgh = vaddq_u32(efgh, efgh0);

    vst1q_u32(state.as_mut_ptr(), abcd);
    vst1q_u32(state.as_mut_ptr().add(4), efgh);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::Sha256;

    #[test]
    fn sha256_known_vectors() {
        if !Sha256Armv8::is_supported() {
            return;
        }
        assert_eq!(
            Sha256Armv8::digest(b"").expect("digest"),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
        assert_eq!(
            Sha256Armv8::digest(b"abc").expect("digest"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
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

    #[test]
    fn matches_baseline_sha256_random_messages() {
        if !Sha256Armv8::is_supported() {
            return;
        }

        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..1000 {
            let len = (xorshift64(&mut seed) as usize) % 4096;
            let mut msg = vec![0u8; len];
            fill_bytes(&mut seed, &mut msg);

            let alt = Sha256Armv8::digest(&msg).expect("alt digest");
            let base = Sha256::digest(&msg);
            assert_eq!(alt, base);
        }
    }
}
