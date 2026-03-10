//! GHASH alternative path for Apple Silicon (ARM carry-less multiply intrinsics).
//!
//! This module is intentionally isolated from the baseline crate implementation.
//! It is an opt-in acceleration path, and callers should validate output parity
//! with the baseline implementation.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::vmull_p64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhashArmv8Error {
    MissingAesFeature,
}

pub struct GhashArmv8;

impl GhashArmv8 {
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_arch = "aarch64")]
        {
            return std::arch::is_aarch64_feature_detected!("aes");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            false
        }
    }

    pub fn mul(x: u128, y: u128) -> Result<u128, GhashArmv8Error> {
        if !Self::is_supported() {
            return Err(GhashArmv8Error::MissingAesFeature);
        }
        // Feature check stays at API boundary; kernel below is branch-free math.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            return Ok(mul_hw(x, y));
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (x, y);
            Err(GhashArmv8Error::MissingAesFeature)
        }
    }

    #[must_use]
    pub fn mul_ref(x: u128, y: u128) -> u128 {
        ghash_mul_ct_ref(x, y)
    }
}

#[inline]
fn ghash_mul_ct_ref(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        let bit_mask = 0u128.wrapping_sub(bit);
        z ^= v & bit_mask;

        let lsb = v & 1;
        let lsb_mask = 0u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (R & lsb_mask);
    }
    z
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn clmul64_hw(a: u64, b: u64) -> u128 {
    // vmull_p64 computes carry-less 64x64 -> 128 polynomial products.
    vmull_p64(a, b)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn reduce_mod_gcm(hi: u128, lo: u128) -> u128 {
    // Reduce modulo x^128 + x^7 + x^2 + x + 1.
    // First fold the 128 high bits, then fold the small carry tail that
    // appears when the top term crosses x^128.
    let x = hi;
    let mut z = lo ^ x ^ (x << 1) ^ (x << 2) ^ (x << 7);
    let x_hi = (x >> 127) ^ (x >> 126) ^ (x >> 121);
    z ^= x_hi ^ (x_hi << 1) ^ (x_hi << 2) ^ (x_hi << 7);
    z
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn mul_hw(x: u128, y: u128) -> u128 {
    // Map GHASH's bit-reflected representation to canonical polynomial bits.
    let a = x.reverse_bits();
    let b = y.reverse_bits();

    let a0 = u64::try_from(a & u128::from(u64::MAX)).expect("masked low limb fits");
    let a1 = u64::try_from(a >> 64).expect("high limb fits");
    let b0 = u64::try_from(b & u128::from(u64::MAX)).expect("masked low limb fits");
    let b1 = u64::try_from(b >> 64).expect("high limb fits");

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
        let expected = GhashArmv8::mul_ref(x, y);
        assert_eq!(expected, 0x5e2e_c746_9170_6288_2c85_b068_5353_deb7u128);
    }

    #[test]
    fn random_parity_with_reference() {
        if !GhashArmv8::is_supported() {
            return;
        }

        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..20_000 {
            let x = ((xorshift64(&mut seed) as u128) << 64) | (xorshift64(&mut seed) as u128);
            let y = ((xorshift64(&mut seed) as u128) << 64) | (xorshift64(&mut seed) as u128);

            let hw = GhashArmv8::mul(x, y).expect("hw");
            let sw = GhashArmv8::mul_ref(x, y);
            assert_eq!(hw, sw);
        }
    }
}
