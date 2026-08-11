//! A small pure-Rust bigint foundation for public-key primitives.
//!
//! The representation uses little-endian `u64` limbs because the surrounding
//! algorithms are naturally word-oriented. The kernels come straight from the
//! literature so they are easy to audit against their sources: schoolbook and
//! Karatsuba multiplication, and Knuth's Algorithm D for division (*TAOCP*
//! vol. 2, §4.3.1), all fully in Rust with no external arithmetic backend.
//!
//! Local references for the multiplication kernels:
//! - `pubs/comba-1990-exponentiation-cryptosystems-on-the-ibm-pc.pdf`
//! - `pubs/karatsuba-ofman-1963-multiplication-of-multidigit-numbers-on-automata.pdf`

use core::cmp::Ordering;

// Heuristic crossover where the recursive split starts beating schoolbook in
// this pure-Rust implementation on our benchmark hardware.
const KARATSUBA_THRESHOLD_LIMBS: usize = 32;
// Limit highly lopsided splits; beyond this ratio the extra recursion/temporary
// cost usually outweighs Karatsuba's multiplication count reduction.
const KARATSUBA_MAX_IMBALANCE: usize = 2;

/// Sign of a [`BigInt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sign {
    /// Strictly positive value.
    Positive,
    /// Strictly negative value.
    Negative,
    /// Zero.
    Zero,
}

/// Unsigned multiprecision integer stored as little-endian `u64` limbs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigUint {
    limbs: Vec<u64>,
}

/// Signed multiprecision integer used by later public-key helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigInt {
    sign: Sign,
    magnitude: BigUint,
}

/// Montgomery arithmetic context for a fixed odd modulus.
///
/// Public-key schemes spend most of their time doing repeated modular
/// multiplication under one long-lived odd modulus. Precomputing the
/// Montgomery constants once avoids paying the setup cost on every multiply
/// while keeping the scheme code readable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MontgomeryCtx {
    modulus: BigUint,
    // n0_inv = -n^{-1} mod 2^64 (Montgomery reduction coefficient).
    n0_inv: u64,
    // R^2 mod n with R = 2^(64 * limbs(n)): conversion factor into Montgomery form.
    r2_mod: BigUint,
    // 1 encoded in Montgomery form, i.e. R mod n.
    one_mont: BigUint,
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Ordering assumes normalized limb vectors (no most-significant zero
        // limbs). All constructors/arithmetic paths call `normalize()`.
        debug_assert!(
            self.limbs.last().copied() != Some(0),
            "BigUint invariant: no leading zero limbs",
        );
        debug_assert!(
            other.limbs.last().copied() != Some(0),
            "BigUint invariant: no leading zero limbs",
        );
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        for (&lhs, &rhs) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match lhs.cmp(&rhs) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }

        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BigUint {
    /// Construct zero.
    #[must_use]
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    /// Construct one.
    #[must_use]
    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    /// Construct from a machine word.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![value] }
        }
    }

    /// Construct from a `u128`.
    ///
    /// # Panics
    ///
    /// Panics only if the internal limb split invariants fail unexpectedly.
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        if value == 0 {
            return Self::zero();
        }

        let lo =
            u64::try_from(value & u128::from(u64::MAX)).expect("low 64 bits always fit into u64");
        let hi = u64::try_from(value >> 64).expect("high 64 bits always fit into u64");
        if hi == 0 {
            Self { limbs: vec![lo] }
        } else {
            Self {
                limbs: vec![lo, hi],
            }
        }
    }

    /// Decode big-endian bytes.
    ///
    /// Internally, limb 0 always stores the least-significant 64 bits.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }

        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        let mut acc = 0u64;
        let mut shift = 0u32;

        // Walk bytes from least-significant (last byte of the big-endian input)
        // to most-significant, packing eight bytes at a time into a 64-bit limb.
        // When `shift` reaches 64, the current limb is full — push it and start
        // the next one.  Any remaining bytes at the end form a partial limb.
        for &byte in bytes.iter().rev() {
            acc |= u64::from(byte) << shift;
            shift += 8;
            if shift == 64 {
                limbs.push(acc);
                acc = 0;
                shift = 0;
            }
        }

        if shift != 0 {
            limbs.push(acc);
        }

        let mut out = Self { limbs };
        out.normalize();
        out
    }

    /// Encode as big-endian bytes without leading zero bytes.
    ///
    /// Internally, limb 0 stores the least-significant 64 bits, so encoding
    /// walks the limbs in reverse order and strips only the leading zero bytes
    /// introduced by the fixed-width `u64` representation.
    ///
    /// # Panics
    ///
    /// Panics only if the internal representation is corrupt and a non-zero
    /// value contains no non-zero bytes.
    #[must_use]
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for &limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }

        let first_nonzero = out
            .iter()
            .position(|&byte| byte != 0)
            .expect("non-zero bigint must encode to at least one non-zero byte");
        out.drain(0..first_nonzero);
        out
    }

    /// Return whether the value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Return whether the value is odd.
    #[must_use]
    pub fn is_odd(&self) -> bool {
        !self.is_zero() && (self.limbs[0] & 1) == 1
    }

    /// Return whether the value is exactly one.
    #[must_use]
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    /// Number of significant bits.
    ///
    /// # Panics
    ///
    /// Panics only if the internal representation is corrupt and a non-zero
    /// value contains no limbs.
    #[must_use]
    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let top = *self
            .limbs
            .last()
            .expect("non-zero bigint has at least one limb");
        let top_bits = (u64::BITS - top.leading_zeros()) as usize;
        (self.limbs.len() - 1) * 64 + top_bits
    }

    /// Integer square root: the largest `r` such that `r^2 <= self`.
    #[must_use]
    pub fn sqrt_floor(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        if self.is_one() {
            return Self::one();
        }

        let mut low = Self::one();
        let mut high = Self::zero();
        // Choose `high` so the search starts with `low^2 <= self < high^2`.
        // Setting bit `ceil(bits(self) / 2)` makes
        // `high = 2^ceil(bits(self)/2)`, so `high^2 >= 2^bits(self) > self`.
        // That gives the binary search a proved upper bound from the start.
        high.set_bit(self.bits().div_ceil(2));

        while {
            let next_low = low.add_ref(&Self::one());
            next_low < high
        } {
            let mut middle = low.add_ref(&high);
            middle.shr1();
            let square = middle.square_ref();
            if square <= *self {
                low = middle;
            } else {
                high = middle;
            }
        }

        low
    }

    /// Test bit `index`.
    #[must_use]
    pub fn bit(&self, index: usize) -> bool {
        let limb = index / 64;
        let shift = index % 64;
        if limb >= self.limbs.len() {
            false
        } else {
            ((self.limbs[limb] >> shift) & 1) == 1
        }
    }

    /// Set bit `index`.
    pub fn set_bit(&mut self, index: usize) {
        let limb = index / 64;
        let shift = index % 64;
        if self.limbs.len() <= limb {
            self.limbs.resize(limb + 1, 0);
        }
        self.limbs[limb] |= 1u64 << shift;
    }

    /// Add another bigint in place.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `u128` accumulator cannot be split back
    /// into `u64` limbs, which would indicate a logic error.
    pub fn add_assign_ref(&mut self, other: &Self) {
        if other.is_zero() {
            return;
        }

        if self.limbs.len() < other.limbs.len() {
            self.limbs.resize(other.limbs.len(), 0);
        }

        let mut carry = 0u128;
        for i in 0..other.limbs.len() {
            let sum = u128::from(self.limbs[i]) + u128::from(other.limbs[i]) + carry;
            self.limbs[i] = low_u64(sum);
            carry = sum >> 64;
        }

        let mut i = other.limbs.len();
        while carry != 0 && i < self.limbs.len() {
            let sum = u128::from(self.limbs[i]) + carry;
            self.limbs[i] = low_u64(sum);
            carry = sum >> 64;
            i += 1;
        }

        if carry != 0 {
            self.limbs
                .push(u64::try_from(carry).expect("final carry from u64 addition is at most 1"));
        }
    }

    /// Return `self + other`.
    #[must_use]
    pub fn add_ref(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.add_assign_ref(other);
        out
    }

    /// Subtract another bigint in place. Panics if `self < other`.
    ///
    /// # Panics
    ///
    /// Panics if `self < other`.
    pub fn sub_assign_ref(&mut self, other: &Self) {
        assert!((*self).cmp(other) != Ordering::Less, "BigUint underflow");
        if other.is_zero() {
            return;
        }

        let mut borrow = 0u128;
        for i in 0..self.limbs.len() {
            let lhs = u128::from(self.limbs[i]);
            let rhs = if i < other.limbs.len() {
                u128::from(other.limbs[i])
            } else {
                0
            };

            let subtrahend = rhs + borrow;
            if lhs >= subtrahend {
                self.limbs[i] = low_u64(lhs - subtrahend);
                borrow = 0;
            } else {
                self.limbs[i] = low_u64((1u128 << 64) + lhs - subtrahend);
                borrow = 1;
            }
        }

        self.normalize();
    }

    /// Return `self - other`. Panics if `self < other`.
    #[must_use]
    pub fn sub_ref(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.sub_assign_ref(other);
        out
    }

    /// Multiply two big integers.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `u128` accumulators cannot be split back
    /// into `u64` limbs, which would indicate a logic error.
    #[must_use]
    pub fn mul_ref(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        if Self::should_use_karatsuba(self, other) {
            return self.mul_karatsuba_ref(other);
        }

        Self::mul_schoolbook_ref(self, other)
    }

    /// Multiply a value by itself.
    #[must_use]
    pub fn square_ref(&self) -> Self {
        self.mul_ref(self)
    }

    fn split_at_limb(&self, split: usize) -> (Self, Self) {
        let low_end = split.min(self.limbs.len());
        let mut low = Self {
            limbs: self.limbs[..low_end].to_vec(),
        };
        low.normalize();

        if split >= self.limbs.len() {
            return (low, Self::zero());
        }

        let mut high = Self {
            limbs: self.limbs[split..].to_vec(),
        };
        high.normalize();
        (low, high)
    }

    fn should_use_karatsuba(lhs: &Self, rhs: &Self) -> bool {
        let short = lhs.limbs.len().min(rhs.limbs.len());
        let long = lhs.limbs.len().max(rhs.limbs.len());
        short >= KARATSUBA_THRESHOLD_LIMBS && long <= short * KARATSUBA_MAX_IMBALANCE
    }

    fn mul_karatsuba_ref(&self, other: &Self) -> Self {
        let split = self.limbs.len().max(other.limbs.len()) / 2;
        if split == 0 {
            return Self::mul_schoolbook_ref(self, other);
        }

        let (a0, a1) = self.split_at_limb(split);
        let (b0, b1) = other.split_at_limb(split);
        if a1.is_zero() || b1.is_zero() {
            return Self::mul_schoolbook_ref(self, other);
        }

        let z0 = a0.mul_ref(&b0);
        let z2 = a1.mul_ref(&b1);

        let a_sum = a0.add_ref(&a1);
        let b_sum = b0.add_ref(&b1);
        let mut z1 = a_sum.mul_ref(&b_sum);
        z1.sub_assign_ref(&z0);
        z1.sub_assign_ref(&z2);

        let mut out = z0;
        z1.shl_bits(split * 64);
        out.add_assign_ref(&z1);

        let mut z2_shifted = z2;
        z2_shifted.shl_bits(split * 128);
        out.add_assign_ref(&z2_shifted);
        out
    }

    fn mul_schoolbook_ref(lhs: &Self, rhs: &Self) -> Self {
        let mut out = vec![0u64; lhs.limbs.len() + rhs.limbs.len()];
        for (i, &lhs_limb) in lhs.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &rhs_limb) in rhs.limbs.iter().enumerate() {
                let idx = i + j;
                let acc =
                    u128::from(out[idx]) + u128::from(lhs_limb) * u128::from(rhs_limb) + carry;
                out[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + rhs.limbs.len();
            while carry != 0 {
                let acc = u128::from(out[idx]) + carry;
                out[idx] = low_u64(acc);
                carry = acc >> 64;
                idx += 1;
            }
        }

        let mut result = Self { limbs: out };
        // A normalized non-zero multiplicand and multiplier cannot produce a
        // spuriously zero high limb except through the carry chain itself, so
        // one post-pass normalization is enough.
        result.normalize();
        result
    }

    /// Shift left by one bit.
    pub fn shl1(&mut self) {
        if self.is_zero() {
            return;
        }

        let mut carry = 0u64;
        for limb in &mut self.limbs {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }

        if carry != 0 {
            self.limbs.push(carry);
        }
        // A left shift on an already-normalized value cannot introduce a
        // leading zero limb, so no normalize() pass is required here.
    }

    /// Shift right by one bit.
    pub fn shr1(&mut self) {
        if self.is_zero() {
            return;
        }

        let mut carry = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let next = (*limb & 1) << 63;
            *limb = (*limb >> 1) | carry;
            carry = next;
        }

        self.normalize();
    }

    /// XOR another bigint into `self` in place (GF(2^m) field addition).
    ///
    /// Extends `self.limbs` with zeros if shorter than `other.limbs`, then
    /// XORs each corresponding limb pair.  The result is normalized to strip
    /// any leading zero limbs produced by XOR cancellation.
    pub fn bitxor_assign(&mut self, other: &BigUint) {
        if self.limbs.len() < other.limbs.len() {
            self.limbs.resize(other.limbs.len(), 0);
        }
        for (s, &o) in self.limbs.iter_mut().zip(other.limbs.iter()) {
            *s ^= o;
        }
        self.normalize();
    }

    /// Left-shift by `n` bits.
    ///
    /// Implemented as `n / 64` full-limb shifts (inserting zero limbs at the
    /// low end) followed by up to 63 single-bit left shifts, which avoids
    /// undefined behaviour from shifting a `u64` by 64 or more positions.
    pub fn shl_bits(&mut self, n: usize) {
        if self.is_zero() || n == 0 {
            return;
        }
        let limb_shifts = n / 64;
        let bit_shifts = n % 64;
        // Full-limb shift: prepend zeros at the low (index 0) end.
        if limb_shifts > 0 {
            let mut new_limbs = vec![0u64; limb_shifts];
            new_limbs.extend_from_slice(&self.limbs);
            self.limbs = new_limbs;
        }
        // Remaining bit-level shift (0 < bit_shifts < 64, so 64 - bit_shifts is safe).
        if bit_shifts > 0 {
            let mut carry = 0u64;
            for limb in &mut self.limbs {
                let next_carry = *limb >> (64 - bit_shifts);
                *limb = (*limb << bit_shifts) | carry;
                carry = next_carry;
            }
            if carry != 0 {
                self.limbs.push(carry);
            }
        }
        // A left-shift on a normalized value cannot introduce a leading zero
        // limb, so no normalize() pass is needed here.
    }

    /// Compute `self mod modulus`.
    #[must_use]
    pub fn modulo(&self, modulus: &Self) -> Self {
        let (_, remainder) = self.div_rem(modulus);
        remainder
    }

    /// Compute the remainder modulo a machine word.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn rem_u64(&self, modulus: u64) -> u64 {
        assert!(modulus != 0, "division by zero");
        if self.is_zero() {
            return 0;
        }

        let mut remainder = 0u128;
        // Horner's method in base `2^64`: carry the remainder of the already
        // processed high limbs, then append the next limb as the next base
        // digit before reducing again.
        for &limb in self.limbs.iter().rev() {
            let acc = (remainder << 64) | u128::from(limb);
            remainder = acc % u128::from(modulus);
        }

        u64::try_from(remainder).expect("remainder modulo u64 fits into u64")
    }

    /// Compute `(lhs * rhs) mod modulus`.
    ///
    /// Multiply, then reduce once. This used to build a throwaway
    /// [`MontgomeryCtx`] for odd moduli and fall back to a double-and-add
    /// reducer for even ones, both to dodge a division. With Algorithm D doing
    /// the reduction that trade no longer pays: a Montgomery context costs two
    /// divisions to construct and then four Montgomery multiplies to encode,
    /// multiply, and decode, where this costs one multiply and one division —
    /// and it needs no odd-modulus special case.
    ///
    /// Callers that perform many multiplications under one modulus should still
    /// build a [`MontgomeryCtx`] once and reuse it; this is the one-shot path.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn mod_mul(lhs: &Self, rhs: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        if modulus.is_one() {
            return Self::zero();
        }
        lhs.mul_ref(rhs).modulo(modulus)
    }

    /// Return `(quotient, remainder)` for Euclidean division. Panics on zero divisor.
    ///
    /// # Panics
    ///
    /// Panics if `divisor == 0`.
    #[must_use]
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "division by zero");
        if self.cmp(divisor) == Ordering::Less {
            return (Self::zero(), self.clone());
        }

        // One limb of quotient at a time, not one bit: both paths below produce
        // 64 quotient bits per pass over the divisor.
        if divisor.limbs.len() == 1 {
            let (quotient, remainder) = Self::div_rem_limb(&self.limbs, divisor.limbs[0]);
            return (quotient, Self::from_u64(remainder));
        }

        Self::div_rem_knuth(&self.limbs, &divisor.limbs)
    }

    /// Divide by a single limb by Horner's method in base `2^64`, the same
    /// recurrence [`Self::rem_u64`] uses, keeping the quotient digits.
    fn div_rem_limb(dividend: &[u64], divisor: u64) -> (Self, u64) {
        let divisor = u128::from(divisor);
        let mut quotient = vec![0u64; dividend.len()];
        let mut remainder = 0u128;
        for (slot, &limb) in quotient.iter_mut().zip(dividend.iter()).rev() {
            let acc = (remainder << 64) | u128::from(limb);
            *slot = low_u64(acc / divisor);
            remainder = acc % divisor;
        }

        let mut quotient = Self { limbs: quotient };
        quotient.normalize();
        (quotient, low_u64(remainder))
    }

    /// Knuth's Algorithm D — long division in base `b = 2^64`.
    ///
    /// Reference: Knuth, *TAOCP* vol. 2, §4.3.1, Algorithm D; the borrow and
    /// add-back mechanics follow Warren, *Hacker's Delight*, §9-2 (`divmnu`).
    /// Step labels D1–D8 in the comments are Knuth's.
    ///
    /// Requires `dividend >= divisor` and at least two divisor limbs; both
    /// slices are normalized (non-zero top limb). Costs
    /// `O(quotient_limbs * divisor_limbs)` limb operations, against
    /// `O(bits * limbs)` for the bit-serial long division it replaced: one
    /// pass over the divisor now yields 64 quotient bits instead of one.
    ///
    /// Like the rest of the `vt::` lattice this is variable-time: the
    /// quotient-digit corrections below are data-dependent.
    fn div_rem_knuth(dividend: &[u64], divisor: &[u64]) -> (Self, Self) {
        /// Knuth's `b`, the digit base.
        const BASE: u128 = 1u128 << 64;

        let n = divisor.len();
        debug_assert!(n >= 2, "single-limb divisors take the Horner path");
        debug_assert!(dividend.len() >= n, "caller screens dividend < divisor");
        let m = dividend.len() - n;

        // D1. Scale both operands so the divisor's top limb has its high bit
        // set (the quotient is unchanged; the remainder is scaled back in D8).
        // Normalization is what bounds the D3 estimate to at most two over the
        // true digit, so a single conditional add-back in D6 suffices.
        let shift = divisor[n - 1].leading_zeros();
        let divisor = shl_into(divisor, shift, n);
        // One limb of headroom: the shift can carry out, and the estimate step
        // reads `rem[j + n]` for the top window.
        let mut rem = shl_into(dividend, shift, dividend.len() + 1);
        let divisor_hi = u128::from(divisor[n - 1]);
        let divisor_next = u128::from(divisor[n - 2]);

        let mut quotient = vec![0u64; m + 1];

        // D2/D7. One quotient digit per pass, most significant first. The
        // window `rem[j..=j + n]` always holds less than `divisor * b`, so
        // each true digit fits in one limb.
        for j in (0..=m).rev() {
            // D3. Estimate the digit from the window's top two limbs:
            // `q_hat = numerator / divisor_hi`, remainder `r_hat` (Knuth's
            // q-hat and r-hat). Normalization guarantees `q_hat <= q + 2`.
            //
            // The loop's second test rules the estimate against the divisor's
            // *third*-from-top limb; each firing lowers `q_hat` by one, and
            // when it stops `q_hat <= q + 1` (TAOCP §4.3.1, exercise 20),
            // leaving at most the one overshoot D6 can repair. Skipping this
            // correction is not an option: for divisors like
            // `[v0, d, d, ...]` with `d >= b/2` the raw estimate reaches
            // `b + 1` — two over the true digit `b - 1` — which no single
            // add-back can fix.
            //
            // The `q_hat >= BASE` arm is Knuth's `min(q_hat, b - 1)` clamp.
            // Because `q_hat` stays in `u128` all the way into D4, the clamp
            // is provably redundant here — an estimate of `b` or `b + 1` is
            // always caught by the second test or repaired by D6 — but it is
            // kept both to match the algorithm as published and to skip a
            // predictably doomed full-width subtraction.
            //
            // Termination: each round adds `divisor_hi >= b/2` to `r_hat`, so
            // the `r_hat >= BASE` break bounds the loop at two corrections
            // beyond the clamp.
            let numerator = (u128::from(rem[j + n]) << 64) | u128::from(rem[j + n - 1]);
            let mut q_hat = numerator / divisor_hi;
            let mut r_hat = numerator % divisor_hi;
            while q_hat >= BASE || q_hat * divisor_next > (r_hat << 64) | u128::from(rem[j + n - 2])
            {
                q_hat -= 1;
                r_hat += divisor_hi;
                if r_hat >= BASE {
                    break;
                }
            }

            // D4. Subtract `q_hat * divisor` from the window. Each step biases
            // the difference by `BASE` so it stays unsigned; bit 64 of the
            // biased result is 1 exactly when no borrow was needed.
            let mut borrow = 0u128;
            let mut carry = 0u128;
            for i in 0..n {
                let product = q_hat * u128::from(divisor[i]) + carry;
                carry = product >> 64;
                let diff = BASE + u128::from(rem[i + j]) - u128::from(low_u64(product)) - borrow;
                rem[i + j] = low_u64(diff);
                borrow = 1 - (diff >> 64);
            }
            let diff = BASE + u128::from(rem[j + n]) - carry - borrow;
            rem[j + n] = low_u64(diff);

            // D5/D6. A borrow out of the top means `q_hat` was one too large
            // (probability about `2/b` on random input); add the divisor back
            // once. The carry out of the add-back cancels the borrow D4 left
            // in the top limb, restoring the invariant checked below.
            if diff >> 64 == 0 {
                q_hat -= 1;
                let mut carry = 0u128;
                for i in 0..n {
                    let sum = u128::from(rem[i + j]) + u128::from(divisor[i]) + carry;
                    rem[i + j] = low_u64(sum);
                    carry = sum >> 64;
                }
                rem[j + n] = rem[j + n].wrapping_add(low_u64(carry));
            }

            // After a correct step the remaining value fits below `b^n`, so
            // the window's top limb must be clean. Release builds never read
            // `rem[j + n]` again (the next window sits one limb lower), but
            // the store above keeps this invariant true and checkable.
            debug_assert!(rem[j + n] == 0, "quotient digit left residue");

            quotient[j] = low_u64(q_hat);
        }

        let mut quotient = Self { limbs: quotient };
        quotient.normalize();

        // D8. The remainder is the final window, still scaled by `2^shift`
        // from D1; the true remainder's shifted-out low bits are zero.
        debug_assert!(
            shift == 0 || rem[0].trailing_zeros() >= shift,
            "denormalized remainder must be a multiple of 2^shift"
        );
        let mut remainder = Self {
            limbs: shr_limbs(&rem[..n], shift),
        };
        remainder.normalize();

        (quotient, remainder)
    }

    fn normalize(&mut self) {
        // Canonical representation invariant:
        // - zero has `limbs.is_empty()`
        // - non-zero values have a non-zero top limb
        while self.limbs.last().copied() == Some(0) {
            self.limbs.pop();
        }
    }

    fn limb_or_zero(&self, idx: usize) -> u64 {
        self.limbs.get(idx).copied().unwrap_or(0)
    }

    fn montgomery_mul_odd_with_workspace(
        lhs: &Self,
        rhs: &Self,
        modulus: &Self,
        n0_inv: u64,
        workspace: &mut Vec<u64>,
    ) -> Self {
        debug_assert!(modulus.is_odd(), "Montgomery path requires an odd modulus");
        let width = modulus.limbs.len();
        // `2 * width` limbs hold the schoolbook product. The extra two limbs
        // are carry headroom so neither pass can run off the end.
        let needed = width * 2 + 2;
        if workspace.len() != needed {
            workspace.resize(needed, 0);
        } else {
            workspace.fill(0);
        }

        // First pass: accumulate the ordinary product `lhs * rhs`.
        for i in 0..width {
            let lhs_limb = lhs.limb_or_zero(i);
            let mut carry = 0u128;
            for j in 0..width {
                let idx = i + j;
                let acc = u128::from(workspace[idx])
                    + u128::from(lhs_limb) * u128::from(rhs.limb_or_zero(j))
                    + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + width;
            while carry != 0 {
                let acc = u128::from(workspace[idx]) + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
                idx += 1;
            }
        }

        // Second pass: Montgomery reduction. Choose `m` so the current low
        // limb cancels modulo `2^64`, then add `m * modulus`. Each round
        // zeros one more low limb; after `width` rounds the discarded low half
        // accounts for the implicit division by `R = 2^(64w)`, so the high
        // half is `lhs * rhs * R^-1 mod n`. That is why copying out
        // `workspace[width..]` yields the Montgomery product.
        for i in 0..width {
            let m = workspace[i].wrapping_mul(n0_inv);
            let mut carry = 0u128;
            for j in 0..width {
                let idx = i + j;
                let acc = u128::from(workspace[idx])
                    + u128::from(m) * u128::from(modulus.limb_or_zero(j))
                    + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + width;
            while carry != 0 {
                let acc = u128::from(workspace[idx]) + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
                idx += 1;
            }
        }

        let mut out = Self {
            limbs: workspace[width..=(width * 2)].to_vec(),
        };
        out.normalize();
        // Montgomery reduction leaves a value in `[0, 2n)`, so at most one
        // subtraction is needed to return to the canonical residue range.
        if out >= *modulus {
            out.sub_assign_ref(modulus);
        }
        out
    }
}

impl MontgomeryCtx {
    fn encode_with_workspace(&self, value: &BigUint, workspace: &mut Vec<u64>) -> BigUint {
        if value.is_zero() {
            return BigUint::zero();
        }

        BigUint::montgomery_mul_odd_with_workspace(
            &value.modulo(&self.modulus),
            &self.r2_mod,
            &self.modulus,
            self.n0_inv,
            workspace,
        )
    }

    fn decode_with_workspace(&self, value: &BigUint, workspace: &mut Vec<u64>) -> BigUint {
        BigUint::montgomery_mul_odd_with_workspace(
            value,
            &BigUint::one(),
            &self.modulus,
            self.n0_inv,
            workspace,
        )
    }

    fn pow_encoded_with_workspace(
        &self,
        base_mont: &BigUint,
        exponent: &BigUint,
        workspace: &mut Vec<u64>,
    ) -> BigUint {
        if self.modulus == BigUint::one() {
            return BigUint::zero();
        }

        let bits = exponent.bits();

        // Short exponents (e.g. F4 public exponents): plain right-to-left
        // binary avoids the window table setup cost.
        if bits <= 64 {
            let mut result = self.one_mont.clone();
            let mut power = base_mont.clone();

            for bit in 0..bits {
                if exponent.bit(bit) {
                    result = BigUint::montgomery_mul_odd_with_workspace(
                        &result,
                        &power,
                        &self.modulus,
                        self.n0_inv,
                        workspace,
                    );
                }
                power = BigUint::montgomery_mul_odd_with_workspace(
                    &power,
                    &power,
                    &self.modulus,
                    self.n0_inv,
                    workspace,
                );
            }

            return self.decode_with_workspace(&result, workspace);
        }

        // Fixed 4-bit window, scanned left to right: per window 4 squarings
        // plus at most one multiply out of a 16-entry power table, versus one
        // multiply every other bit for the binary ladder (~1.23 vs ~1.5
        // multiplies per exponent bit; the 14-multiply table amortizes over
        // any exponent long enough to reach this path).
        //
        // Like the rest of the public-key stack this is variable-time: zero
        // windows skip their multiply, which is why the variable-time lattice
        // of callers lives under `vt::`.
        const WINDOW: usize = 4;
        let mut table = Vec::with_capacity(1 << WINDOW);
        table.push(self.one_mont.clone());
        table.push(base_mont.clone());
        for i in 2..(1 << WINDOW) {
            let next = BigUint::montgomery_mul_odd_with_workspace(
                &table[i - 1],
                base_mont,
                &self.modulus,
                self.n0_inv,
                workspace,
            );
            table.push(next);
        }

        let windows = bits.div_ceil(WINDOW);
        let mut result: Option<BigUint> = None;
        for w in (0..windows).rev() {
            if let Some(acc) = result.as_mut() {
                for _ in 0..WINDOW {
                    *acc = BigUint::montgomery_mul_odd_with_workspace(
                        acc,
                        acc,
                        &self.modulus,
                        self.n0_inv,
                        workspace,
                    );
                }
            }

            let mut idx = 0usize;
            for j in (0..WINDOW).rev() {
                idx = (idx << 1) | usize::from(exponent.bit(w * WINDOW + j));
            }

            match result.as_mut() {
                // Top window: seed the accumulator directly instead of
                // squaring up from one (the top window is non-zero because
                // `bits` counts up to the most significant set bit).
                None => result = Some(table[idx].clone()),
                Some(acc) => {
                    if idx != 0 {
                        *acc = BigUint::montgomery_mul_odd_with_workspace(
                            acc,
                            &table[idx],
                            &self.modulus,
                            self.n0_inv,
                            workspace,
                        );
                    }
                }
            }
        }

        let result = result.unwrap_or_else(|| self.one_mont.clone());
        self.decode_with_workspace(&result, workspace)
    }

    /// Build a Montgomery context for a non-zero odd modulus.
    #[must_use]
    pub fn new(modulus: &BigUint) -> Option<Self> {
        if modulus.is_zero() || !modulus.is_odd() {
            return None;
        }

        let n0_inv = montgomery_n0_inv(modulus.limbs[0]);

        // With `w` limbs, Montgomery arithmetic uses `R = 2^(64w)`. `R^2 mod
        // n` is the standard conversion factor for entering the Montgomery
        // domain because `montgomery_mul(a, R^2) = a * R^2 * R^-1 = aR`, the
        // Montgomery encoding of the ordinary residue `a`.
        let mut r2 = BigUint::zero();
        r2.set_bit(modulus.limbs.len() * 128);
        let r2_mod = r2.modulo(modulus);

        // `R mod n` is the Montgomery encoding of 1, stored so exponentiation
        // can start its accumulator in the correct domain.
        let mut r = BigUint::zero();
        r.set_bit(modulus.limbs.len() * 64);
        let one_mont = r.modulo(modulus);

        Some(Self {
            modulus: modulus.clone(),
            n0_inv,
            r2_mod,
            one_mont,
        })
    }

    /// Return the odd modulus this context was built for.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.modulus
    }

    /// Convert an ordinary residue into Montgomery form.
    #[must_use]
    pub fn encode(&self, value: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let result = self.encode_with_workspace(value, &mut workspace);
        crate::ct::zeroize_slice(workspace.as_mut_slice());
        result
    }

    /// Convert a Montgomery residue back to the ordinary representation.
    #[must_use]
    pub fn decode(&self, value: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let result = self.decode_with_workspace(value, &mut workspace);
        crate::ct::zeroize_slice(workspace.as_mut_slice());
        result
    }

    /// Multiply two ordinary residues modulo the context modulus.
    #[must_use]
    pub fn mul(&self, lhs: &BigUint, rhs: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let lhs_mont = self.encode_with_workspace(lhs, &mut workspace);
        let rhs_mont = self.encode_with_workspace(rhs, &mut workspace);
        let product_mont = BigUint::montgomery_mul_odd_with_workspace(
            &lhs_mont,
            &rhs_mont,
            &self.modulus,
            self.n0_inv,
            &mut workspace,
        );
        let result = self.decode_with_workspace(&product_mont, &mut workspace);
        crate::ct::zeroize_slice(workspace.as_mut_slice());
        result
    }

    /// Square one ordinary residue modulo the context modulus.
    #[must_use]
    pub fn square(&self, value: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let value_mont = self.encode_with_workspace(value, &mut workspace);
        let square_mont = BigUint::montgomery_mul_odd_with_workspace(
            &value_mont,
            &value_mont,
            &self.modulus,
            self.n0_inv,
            &mut workspace,
        );
        let result = self.decode_with_workspace(&square_mont, &mut workspace);
        crate::ct::zeroize_slice(workspace.as_mut_slice());
        result
    }

    /// Multiply two residues that are **already in Montgomery form**, staying
    /// in Montgomery form.
    ///
    /// One Montgomery reduction instead of the encode/multiply/decode round
    /// trip of [`Self::mul`]; the workhorse for callers (such as elliptic
    /// curve point arithmetic) that keep whole computations in the Montgomery
    /// domain and convert only at the boundaries.
    ///
    /// Unlike [`Self::mul`]/[`Self::pow`] this does not scrub its workspace:
    /// it is the innermost field-multiply, called in tight loops, so the
    /// per-call volatile wipe is omitted for speed. The product is returned as
    /// a `BigUint`, whose own `Drop` wipes it; the caller keeps the value.
    #[must_use]
    pub fn mul_mont(&self, lhs: &BigUint, rhs: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        BigUint::montgomery_mul_odd_with_workspace(
            lhs,
            rhs,
            &self.modulus,
            self.n0_inv,
            &mut workspace,
        )
    }

    /// Square a residue that is already in Montgomery form, staying in
    /// Montgomery form.
    #[must_use]
    pub fn square_mont(&self, value: &BigUint) -> BigUint {
        self.mul_mont(value, value)
    }

    /// The Montgomery encoding of one (`R mod n`).
    #[must_use]
    pub fn one_mont(&self) -> &BigUint {
        &self.one_mont
    }

    /// Compute `base^exponent mod modulus` inside the context.
    #[must_use]
    pub fn pow(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let base_mont = self.encode_with_workspace(&base.modulo(&self.modulus), &mut workspace);
        let result = self.pow_encoded_with_workspace(&base_mont, exponent, &mut workspace);
        // The workspace held Montgomery intermediates of a (possibly secret)
        // exponentiation; wipe it before the buffer is freed.
        crate::ct::zeroize_slice(workspace.as_mut_slice());
        result
    }

    /// Compute `base^exponent mod modulus` with `base` already in Montgomery form.
    ///
    /// This is useful when callers reuse the same base and can cache the
    /// encoded value once.
    #[must_use]
    pub fn pow_encoded(&self, base_mont: &BigUint, exponent: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let result = self.pow_encoded_with_workspace(base_mont, exponent, &mut workspace);
        crate::ct::zeroize_slice(workspace.as_mut_slice());
        result
    }
}

impl Drop for BigUint {
    fn drop(&mut self) {
        // BigUint backs private exponents, prime factors, and nonces in the
        // public-key layer. Clear the limb buffer on drop so those values do
        // not linger in freed heap memory.
        crate::ct::zeroize_slice(self.limbs.as_mut_slice());
    }
}

#[inline]
fn low_u64(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).expect("masked low 64 bits always fit into u64")
}

/// Copy `value` into a fresh `len`-limb buffer, shifted left by `shift` bits.
///
/// `shift` is below 64 and `len` is at least `value.len()`; this is the
/// Algorithm D normalization step, which never needs a whole-limb shift.
fn shl_into(value: &[u64], shift: u32, len: usize) -> Vec<u64> {
    debug_assert!(shift < 64, "normalization shift stays within one limb");
    debug_assert!(len >= value.len(), "destination must hold the source");

    let mut out = vec![0u64; len];
    if shift == 0 {
        out[..value.len()].copy_from_slice(value);
        return out;
    }

    // `shift` is in `1..64`, so `64 - shift` is also a defined shift amount.
    let mut carry = 0u64;
    for (slot, &limb) in out.iter_mut().zip(value.iter()) {
        *slot = (limb << shift) | carry;
        carry = limb >> (64 - shift);
    }
    if value.len() < len {
        out[value.len()] = carry;
    } else {
        debug_assert!(carry == 0, "shift carried out of the destination");
    }
    out
}

/// Return `value` shifted right by `shift` bits (below 64) in a fresh buffer.
fn shr_limbs(value: &[u64], shift: u32) -> Vec<u64> {
    debug_assert!(shift < 64, "normalization shift stays within one limb");
    if shift == 0 {
        return value.to_vec();
    }

    let mut out = vec![0u64; value.len()];
    for (i, slot) in out.iter_mut().enumerate() {
        let high = value.get(i + 1).map_or(0, |&next| next << (64 - shift));
        *slot = (value[i] >> shift) | high;
    }
    out
}

fn montgomery_n0_inv(n0: u64) -> u64 {
    debug_assert!(n0 & 1 == 1, "Montgomery path requires an odd modulus");
    // Newton iteration in Z_(2^64): each step doubles the number of correct
    // low bits in the inverse of `n0`. Six iterations are enough to converge
    // to the full 64-bit inverse, and Montgomery reduction wants `-n0^-1`.
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

impl BigInt {
    /// Construct zero.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            sign: Sign::Zero,
            magnitude: BigUint::zero(),
        }
    }

    /// Construct from an explicit sign and magnitude.
    #[must_use]
    pub fn from_parts(sign: Sign, magnitude: BigUint) -> Self {
        if magnitude.is_zero() {
            return Self::zero();
        }

        let canonical_sign = match sign {
            Sign::Zero => Sign::Positive,
            other => other,
        };

        Self {
            sign: canonical_sign,
            magnitude,
        }
    }

    /// Construct a non-negative signed integer from an unsigned value.
    #[must_use]
    pub fn from_biguint(magnitude: BigUint) -> Self {
        Self::from_parts(Sign::Positive, magnitude)
    }

    /// Return the sign.
    #[must_use]
    pub fn sign(&self) -> Sign {
        self.sign
    }

    /// Return the absolute value.
    #[must_use]
    pub fn magnitude(&self) -> &BigUint {
        &self.magnitude
    }

    /// Negate the integer.
    #[must_use]
    pub fn negated(&self) -> Self {
        let sign = match self.sign {
            Sign::Positive => Sign::Negative,
            Sign::Negative => Sign::Positive,
            Sign::Zero => Sign::Zero,
        };
        Self {
            sign,
            magnitude: self.magnitude.clone(),
        }
    }

    /// Return `self + other`.
    #[must_use]
    pub fn add_ref(&self, other: &Self) -> Self {
        match (self.sign, other.sign) {
            (Sign::Zero, _) => other.clone(),
            (_, Sign::Zero) => self.clone(),
            (Sign::Positive, Sign::Positive) => {
                Self::from_parts(Sign::Positive, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Negative, Sign::Negative) => {
                Self::from_parts(Sign::Negative, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Positive, Sign::Negative) => self.sub_ref(&other.negated()),
            (Sign::Negative, Sign::Positive) => other.sub_ref(&self.negated()),
        }
    }

    /// Return `self - other`.
    #[must_use]
    pub fn sub_ref(&self, other: &Self) -> Self {
        match (self.sign, other.sign) {
            (_, Sign::Zero) => self.clone(),
            (Sign::Zero, _) => other.negated(),
            (Sign::Positive, Sign::Negative) => {
                Self::from_parts(Sign::Positive, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Negative, Sign::Positive) => {
                Self::from_parts(Sign::Negative, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Positive, Sign::Positive) => match self.magnitude.cmp(&other.magnitude) {
                Ordering::Greater => {
                    Self::from_parts(Sign::Positive, self.magnitude.sub_ref(&other.magnitude))
                }
                Ordering::Less => {
                    Self::from_parts(Sign::Negative, other.magnitude.sub_ref(&self.magnitude))
                }
                Ordering::Equal => Self::zero(),
            },
            (Sign::Negative, Sign::Negative) => match self.magnitude.cmp(&other.magnitude) {
                Ordering::Greater => {
                    Self::from_parts(Sign::Negative, self.magnitude.sub_ref(&other.magnitude))
                }
                Ordering::Less => {
                    Self::from_parts(Sign::Positive, other.magnitude.sub_ref(&self.magnitude))
                }
                Ordering::Equal => Self::zero(),
            },
        }
    }

    /// Return `self * factor` for a non-negative factor.
    #[must_use]
    pub fn mul_biguint_ref(&self, factor: &BigUint) -> Self {
        if factor.is_zero() || self.sign == Sign::Zero {
            return Self::zero();
        }

        Self::from_parts(self.sign, self.magnitude.mul_ref(factor))
    }

    /// Reduce modulo a positive modulus and return the least non-negative residue.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn modulo_positive(&self, modulus: &BigUint) -> BigUint {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        match self.sign {
            Sign::Zero => BigUint::zero(),
            Sign::Positive => self.magnitude.modulo(modulus),
            Sign::Negative => {
                let rem = self.magnitude.modulo(modulus);
                if rem.is_zero() {
                    BigUint::zero()
                } else {
                    modulus.sub_ref(&rem)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BigInt, BigUint, MontgomeryCtx, Sign};

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *state
    }

    fn seeded_biguint(words: usize, state: &mut u64) -> BigUint {
        let mut limbs = Vec::with_capacity(words);
        for _ in 0..words {
            limbs.push(lcg_next(state));
        }
        if words > 0 && limbs[words - 1] == 0 {
            limbs[words - 1] = 1;
        }
        BigUint { limbs }
    }

    #[test]
    fn bytes_roundtrip() {
        let value =
            BigUint::from_be_bytes(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22]);
        assert_eq!(
            value.to_be_bytes(),
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22]
        );
    }

    #[test]
    fn add_sub_mul_small_values() {
        let a = BigUint::from_u128(1_000_000_000_000);
        let b = BigUint::from_u128(777_777_777_777);
        assert_eq!(a.add_ref(&b), BigUint::from_u128(1_777_777_777_777));
        assert_eq!(
            a.sub_ref(&BigUint::from_u64(1)),
            BigUint::from_u128(999_999_999_999)
        );
        assert_eq!(
            a.mul_ref(&b),
            BigUint::from_u128(777_777_777_777_000_000_000_000)
        );
    }

    #[test]
    fn square_ref_matches_mul_ref() {
        let mut seed = 0x9e37_79b9_7f4a_7c15;
        for words in [1usize, 2, 8, 32, 48] {
            for _ in 0..8 {
                let value = seeded_biguint(words, &mut seed);
                assert_eq!(value.square_ref(), value.mul_ref(&value));
            }
        }
    }

    #[test]
    fn karatsuba_dispatch_matches_schoolbook() {
        let mut seed = 0x243f_6a88_85a3_08d3;
        for words in [32usize, 40, 64] {
            for _ in 0..6 {
                let lhs = seeded_biguint(words, &mut seed);
                let rhs = seeded_biguint(words, &mut seed);
                let dispatched = lhs.mul_ref(&rhs);
                let schoolbook = BigUint::mul_schoolbook_ref(&lhs, &rhs);
                assert_eq!(dispatched, schoolbook);
            }
        }
    }

    #[test]
    fn division_roundtrip() {
        let dividend = BigUint::from_u128(1_234_567_890_123_456_789);
        let divisor = BigUint::from_u64(37);
        let (q, r) = dividend.div_rem(&divisor);
        assert_eq!(q, BigUint::from_u128(33_366_699_733_066_399));
        assert_eq!(r, BigUint::from_u64(26));
        assert_eq!(q.mul_ref(&divisor).add_ref(&r), dividend);
    }

    /// `(q, r)` with `dividend = q * divisor + r` and `r < divisor` is unique,
    /// so checking the pair is a complete correctness statement for
    /// [`BigUint::div_rem`] and needs no separately computed expected value.
    fn assert_div_rem_invariant(dividend: &BigUint, divisor: &BigUint) {
        let (quotient, remainder) = dividend.div_rem(divisor);
        assert!(
            remainder < *divisor,
            "remainder {remainder:?} not reduced modulo {divisor:?}"
        );
        assert_eq!(
            quotient.mul_ref(divisor).add_ref(&remainder),
            *dividend,
            "q * d + r != n for {dividend:?} / {divisor:?}"
        );
    }

    #[test]
    fn div_rem_invariant_over_limb_shapes() {
        let mut seed = 0x243f_6a88_85a3_08d3;
        // Cover both division paths (one-limb Horner and multi-limb Knuth),
        // every quotient length from one limb up, and — because the leading
        // limb is random — a spread of D1 normalization shifts.
        for dividend_words in 1..=9usize {
            for divisor_words in 1..=dividend_words {
                for _ in 0..12 {
                    let dividend = seeded_biguint(dividend_words, &mut seed);
                    let divisor = seeded_biguint(divisor_words, &mut seed);
                    assert_div_rem_invariant(&dividend, &divisor);
                }
            }
        }
    }

    #[test]
    fn div_rem_handles_quotient_estimate_corrections() {
        // Knuth's D6 add-back runs with probability about 2^-63 on random
        // input, so it needs inputs built to force it. These are the base-2^64
        // analogues of the classic add-back cases from Warren, *Hacker's
        // Delight*, §9-2, plus a divisor whose top limb is already normalized
        // (D1 shift of zero) and one that needs the maximum shift.
        let cases: [(&[u64], &[u64]); 5] = [
            (&[0, 0, 0x8000_0000_0000_0000], &[1, 0x8000_0000_0000_0000]),
            (
                &[0, 0xFFFF_FFFF_FFFF_FFFE, 0x8000_0000_0000_0000],
                &[0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000],
            ),
            (
                &[0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF],
                &[0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_FFFF_FFFF],
            ),
            (&[0, 0, 0, 1], &[1, 1]),
            (&[u64::MAX, u64::MAX, u64::MAX], &[u64::MAX, 1]),
        ];

        for (dividend, divisor) in cases {
            assert_div_rem_invariant(
                &BigUint {
                    limbs: dividend.to_vec(),
                },
                &BigUint {
                    limbs: divisor.to_vec(),
                },
            );
        }
    }

    #[test]
    fn div_rem_exercises_the_add_back_path() {
        // Knuth's D6 add-back cannot happen for a two-limb divisor — there the
        // `v[n-2]` test in D3 is exact — and on random longer input it runs
        // with probability about `2 / 2^64`, so reaching it needs constructed
        // inputs. `dividend = (q + 1) * divisor - 1` is that construction: D3
        // accepts `q + 1` because it cannot see the divisor's low limbs, while
        // the true quotient is `q`, which is precisely what D6 repairs.
        let mut seed = 0xb504_f333_f9de_6484;
        for divisor_words in 3..=6usize {
            for q in [1u64, 2, 12_345, u64::MAX - 1] {
                let mut divisor = seeded_biguint(divisor_words, &mut seed);
                // A D1 shift of zero keeps the construction exact.
                divisor.limbs[divisor_words - 1] |= 1 << 63;

                let scale = BigUint::from_u64(q).add_ref(&BigUint::one());
                let dividend = scale.mul_ref(&divisor).sub_ref(&BigUint::one());

                assert_div_rem_invariant(&dividend, &divisor);
                // `(q + 1) * d - 1 = q * d + (d - 1)`, so the answer is exact.
                let (quotient, remainder) = dividend.div_rem(&divisor);
                assert_eq!(quotient, BigUint::from_u64(q));
                assert_eq!(remainder, divisor.sub_ref(&BigUint::one()));
            }
        }
    }

    #[test]
    fn div_rem_edge_cases() {
        let big = BigUint::from_be_bytes(&[0xFF; 40]);
        assert_div_rem_invariant(&big, &BigUint::one());
        assert_div_rem_invariant(&big, &big);
        assert_eq!(big.div_rem(&big).0, BigUint::one());
        assert!(big.div_rem(&big).1.is_zero());

        // Divisor above the dividend takes the early exit.
        let (quotient, remainder) = BigUint::from_u64(5).div_rem(&BigUint::from_u64(9));
        assert!(quotient.is_zero());
        assert_eq!(remainder, BigUint::from_u64(5));

        assert!(BigUint::zero().div_rem(&BigUint::from_u64(7)).0.is_zero());
    }

    #[test]
    fn sqrt_floor_small_values() {
        assert_eq!(BigUint::from_u64(0).sqrt_floor(), BigUint::from_u64(0));
        assert_eq!(BigUint::from_u64(1).sqrt_floor(), BigUint::from_u64(1));
        assert_eq!(BigUint::from_u64(2).sqrt_floor(), BigUint::from_u64(1));
        assert_eq!(BigUint::from_u64(15).sqrt_floor(), BigUint::from_u64(3));
        assert_eq!(BigUint::from_u64(16).sqrt_floor(), BigUint::from_u64(4));
        assert_eq!(BigUint::from_u64(17).sqrt_floor(), BigUint::from_u64(4));
        assert_eq!(
            BigUint::from_u128(17_184_849_881).sqrt_floor(),
            BigUint::from_u64(131_090)
        );
    }

    #[test]
    fn mod_mul_matches_small_arithmetic() {
        let a = BigUint::from_u64(123_456_789);
        let b = BigUint::from_u64(987_654_321);
        let m = BigUint::from_u64(1_000_000_007);
        assert_eq!(BigUint::mod_mul(&a, &b, &m), BigUint::from_u64(259_106_859));
    }

    #[test]
    fn montgomery_mod_pow_matches_small_arithmetic() {
        let ctx = MontgomeryCtx::new(&BigUint::from_u64(1_000_000_007))
            .expect("odd modulus builds a context");
        let base = BigUint::from_u64(123_456_789);
        let exponent = BigUint::from_u64(65_537);
        assert_eq!(ctx.pow(&base, &exponent), BigUint::from_u64(560_583_526));
    }

    #[test]
    fn montgomery_ctx_mul_matches_small_arithmetic() {
        let ctx = MontgomeryCtx::new(&BigUint::from_u64(1_000_000_007))
            .expect("odd modulus builds a context");
        let a = BigUint::from_u64(123_456_789);
        let b = BigUint::from_u64(987_654_321);
        assert_eq!(ctx.mul(&a, &b), BigUint::from_u64(259_106_859));
    }

    #[test]
    fn mod_mul_handles_even_modulus() {
        // Even moduli have no Montgomery representation, so this used to take a
        // separate double-and-add path; multiply-then-reduce covers both.
        let a = BigUint::from_u64(37);
        let b = BigUint::from_u64(19);
        let modulus = BigUint::from_u64(100);
        assert_eq!(BigUint::mod_mul(&a, &b, &modulus), BigUint::from_u64(3));
    }

    #[test]
    fn mod_mul_matches_montgomery_context() {
        // The one-shot path and the reusable-context path must agree.
        let mut seed = 0x0123_4567_89ab_cdef;
        for words in [1usize, 2, 4, 8, 16] {
            for _ in 0..8 {
                let lhs = seeded_biguint(words, &mut seed);
                let rhs = seeded_biguint(words, &mut seed);
                let mut modulus = seeded_biguint(words, &mut seed);
                modulus.limbs[0] |= 1; // Montgomery needs an odd modulus.

                let ctx = MontgomeryCtx::new(&modulus).expect("odd modulus builds a context");
                assert_eq!(BigUint::mod_mul(&lhs, &rhs, &modulus), ctx.mul(&lhs, &rhs));
            }
        }
    }

    #[test]
    fn bigint_sign_normalization() {
        let zero = BigInt::from_parts(Sign::Negative, BigUint::zero());
        assert_eq!(zero.sign(), Sign::Zero);

        let value = BigInt::from_parts(Sign::Positive, BigUint::from_u64(7));
        assert_eq!(value.negated().sign(), Sign::Negative);
        assert_eq!(value.magnitude(), &BigUint::from_u64(7));
    }

    #[test]
    fn bigint_add_sub_and_modulo() {
        let a = BigInt::from_biguint(BigUint::from_u64(10));
        let b = BigInt::from_parts(Sign::Negative, BigUint::from_u64(3));
        assert_eq!(a.add_ref(&b), BigInt::from_biguint(BigUint::from_u64(7)));
        assert_eq!(
            b.sub_ref(&a),
            BigInt::from_parts(Sign::Negative, BigUint::from_u64(13))
        );
        assert_eq!(
            BigInt::from_parts(Sign::Negative, BigUint::from_u64(3))
                .modulo_positive(&BigUint::from_u64(11)),
            BigUint::from_u64(8)
        );
    }
}
