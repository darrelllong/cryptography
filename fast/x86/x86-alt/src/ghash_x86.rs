//! GHASH backend for x86/x86_64 (PCLMULQDQ carry-less multiply).
//!
//! Provides a hardware kernel for GCM GHASH multiplication plus a constant-time
//! scalar reference path used to cross-check correctness.

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhashX86Error {
    MissingPclmulFeature,
}

pub struct GhashX86;

impl GhashX86 {
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return std::arch::is_x86_feature_detected!("pclmulqdq");
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            false
        }
    }

    pub fn mul(x: u128, y: u128) -> Result<u128, GhashX86Error> {
        // Hot path avoids per-call CPUID checks; callers gate with is_supported().
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            return Ok(mul_hw(x, y));
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let _ = (x, y);
            Err(GhashX86Error::MissingPclmulFeature)
        }
    }

    #[must_use]
    pub fn mul_ref(x: u128, y: u128) -> u128 {
        ghash_mul_ct_ref(x, y)
    }
}

#[inline]
fn ghash_mul_ct_ref(x: u128, y: u128) -> u128 {
    // SP 800-38D field polynomial p(x)=x^128+x^7+x^2+x+1. GHASH's reflected
    // bit ordering encodes (x^7+x^2+x+1) as 0xe1 in the most-significant byte.
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        // Branch-free conditional xor via all-ones/all-zero mask.
        let bit = (x >> (127 - i)) & 1;
        let bit_mask = 0u128.wrapping_sub(bit);
        z ^= v & bit_mask;

        let lsb = v & 1;
        let lsb_mask = 0u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (R & lsb_mask);
    }
    z
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "pclmulqdq")]
unsafe fn clmul64_hw(a: u64, b: u64) -> u128 {
    // `_mm_clmulepi64_si128` computes carry-less 64x64 -> 128 polynomial products.
    let va = _mm_set_epi64x(0, a as i64);
    let vb = _mm_set_epi64x(0, b as i64);
    let prod = _mm_clmulepi64_si128(va, vb, 0x00);
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, prod);
    u128::from_le_bytes(out)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
fn reduce_mod_gcm(hi: u128, lo: u128) -> u128 {
    // Reduce modulo p(x) = x^128 + x^7 + x^2 + x + 1.
    //
    // Any high term x^(128+k) is congruent to x^(k+7) + x^(k+2) + x^(k+1) + x^k.
    // Folding `hi` into `lo` with shifts {0,1,2,7} applies that relation to all
    // upper terms at once; the small second fold handles overflow from bit 127.
    let x = hi;
    let mut z = lo ^ x ^ (x << 1) ^ (x << 2) ^ (x << 7);
    let x_hi = (x >> 127) ^ (x >> 126) ^ (x >> 121);
    z ^= x_hi ^ (x_hi << 1) ^ (x_hi << 2) ^ (x_hi << 7);
    z
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "pclmulqdq")]
unsafe fn mul_hw(x: u128, y: u128) -> u128 {
    // GHASH defines bit 0 as the coefficient of x^127 inside each byte string.
    // Reversing bits maps that representation to the natural CLMUL polynomial
    // layout; reverse again after reduction to return GHASH byte order.
    let a = x.reverse_bits();
    let b = y.reverse_bits();

    // Safety: AND with u64::MAX guarantees bits 64..127 are zero; shift by 64
    // guarantees bits 64..127 of the original value become bits 0..63.
    let a0 = (a & u128::from(u64::MAX)) as u64;
    let a1 = (a >> 64) as u64;
    let b0 = (b & u128::from(u64::MAX)) as u64;
    let b1 = (b >> 64) as u64;

    // Schoolbook over GF(2): four 64x64 carry-less products + cross-term combine.
    let p00 = clmul64_hw(a0, b0);
    let p01 = clmul64_hw(a0, b1);
    let p10 = clmul64_hw(a1, b0);
    let p11 = clmul64_hw(a1, b1);

    let middle = p01 ^ p10;
    let lo = p00 ^ (middle << 64);
    let hi = p11 ^ (middle >> 64);

    // Map back to GHASH representation.
    reduce_mod_gcm(hi, lo).reverse_bits()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn known_vector_against_reference() {
        let x = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78u128;
        let y = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2eu128;
        let expected = GhashX86::mul_ref(x, y);
        assert_eq!(expected, 0x5e2e_c746_9170_6288_2c85_b068_5353_deb7u128);
    }

    #[test]
    fn random_parity_with_reference() {
        if !GhashX86::is_supported() {
            return;
        }

        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..20_000 {
            let x = ((xorshift64(&mut seed) as u128) << 64) | (xorshift64(&mut seed) as u128);
            let y = ((xorshift64(&mut seed) as u128) << 64) | (xorshift64(&mut seed) as u128);

            let hw = GhashX86::mul(x, y).expect("hw");
            let sw = GhashX86::mul_ref(x, y);
            assert_eq!(hw, sw);
        }
    }
}
