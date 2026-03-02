//! A small pure-Rust bigint foundation for public-key primitives.
//!
//! The representation uses little-endian `u64` limbs because the surrounding
//! algorithms are naturally word-oriented. This is intentionally simple:
//! schoolbook multiplication and bitwise long division are easy to audit and
//! match the structure used in the teaching-oriented Python code.

use core::cmp::Ordering;

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
    n0_inv: u64,
    r2_mod: BigUint,
    one_mont: BigUint,
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
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
        high.set_bit(self.bits().div_ceil(2));

        while {
            let next_low = low.add_ref(&Self::one());
            next_low < high
        } {
            let mut middle = low.add_ref(&high);
            middle.shr1();
            let square = middle.mul_ref(&middle);
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

    /// Multiply using schoolbook limb multiplication.
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

        let mut out = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &lhs) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &rhs) in other.limbs.iter().enumerate() {
                let idx = i + j;
                let acc = u128::from(out[idx]) + u128::from(lhs) * u128::from(rhs) + carry;
                out[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + other.limbs.len();
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
        for &limb in self.limbs.iter().rev() {
            let acc = (remainder << 64) | u128::from(limb);
            remainder = acc % u128::from(modulus);
        }

        u64::try_from(remainder).expect("remainder modulo u64 fits into u64")
    }

    /// Compute `(lhs * rhs) mod modulus`.
    ///
    /// Odd moduli use a fresh Montgomery context so the common public-key path
    /// avoids the division-heavy teaching fallback. Even moduli keep the old
    /// double-and-add reducer because Montgomery requires an odd modulus.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn mod_mul(lhs: &Self, rhs: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        if modulus == &Self::one() {
            return Self::zero();
        }
        if let Some(ctx) = MontgomeryCtx::new(modulus) {
            return ctx.mul(lhs, rhs);
        }
        Self::mod_mul_plain(lhs, rhs, modulus)
    }

    /// Compute `(lhs * rhs) mod modulus` using the simple double-and-add
    /// teaching implementation.
    ///
    /// The result is mathematically correct, but repeated division-based
    /// reduction makes it much slower than Montgomery multiplication for the
    /// odd moduli that dominate public-key code.
    #[must_use]
    pub(crate) fn mod_mul_plain(lhs: &Self, rhs: &Self, modulus: &Self) -> Self {
        if lhs.is_zero() || rhs.is_zero() {
            return Self::zero();
        }

        let mut a = lhs.modulo(modulus);
        let mut b = rhs.clone();
        let mut out = Self::zero();
        while !b.is_zero() {
            if b.is_odd() {
                out = out.add_ref(&a).modulo(modulus);
            }
            a = a.add_ref(&a).modulo(modulus);
            b.shr1();
        }
        out
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

        let mut quotient = Self::zero();
        let mut remainder = Self::zero();

        for bit in (0..self.bits()).rev() {
            remainder.shl1();
            if self.bit(bit) {
                if remainder.is_zero() {
                    remainder.limbs.push(1);
                } else {
                    remainder.limbs[0] |= 1;
                }
            }

            if remainder.cmp(divisor) != Ordering::Less {
                remainder.sub_assign_ref(divisor);
                quotient.set_bit(bit);
            }
        }

        (quotient, remainder)
    }

    fn normalize(&mut self) {
        while self.limbs.last().copied() == Some(0) {
            self.limbs.pop();
        }
    }

    fn limb_or_zero(&self, idx: usize) -> u64 {
        self.limbs.get(idx).copied().unwrap_or(0)
    }

    fn montgomery_mul_odd(lhs: &Self, rhs: &Self, modulus: &Self, n0_inv: u64) -> Self {
        debug_assert!(modulus.is_odd(), "Montgomery path requires an odd modulus");
        let width = modulus.limbs.len();
        let mut workspace = vec![0u64; width * 2 + 2];

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
        if out >= *modulus {
            out.sub_assign_ref(modulus);
        }
        out
    }
}

impl MontgomeryCtx {
    /// Build a Montgomery context for a non-zero odd modulus.
    #[must_use]
    pub fn new(modulus: &BigUint) -> Option<Self> {
        if modulus.is_zero() || !modulus.is_odd() {
            return None;
        }

        let n0_inv = montgomery_n0_inv(modulus.limbs[0]);

        let mut r2 = BigUint::zero();
        r2.set_bit(modulus.limbs.len() * 128);
        let r2_mod = r2.modulo(modulus);

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
        if value.is_zero() {
            return BigUint::zero();
        }

        BigUint::montgomery_mul_odd(
            &value.modulo(&self.modulus),
            &self.r2_mod,
            &self.modulus,
            self.n0_inv,
        )
    }

    /// Convert a Montgomery residue back to the ordinary representation.
    #[must_use]
    pub fn decode(&self, value: &BigUint) -> BigUint {
        BigUint::montgomery_mul_odd(value, &BigUint::one(), &self.modulus, self.n0_inv)
    }

    /// Multiply two ordinary residues modulo the context modulus.
    #[must_use]
    pub fn mul(&self, lhs: &BigUint, rhs: &BigUint) -> BigUint {
        let lhs_mont = self.encode(lhs);
        let rhs_mont = self.encode(rhs);
        let product_mont =
            BigUint::montgomery_mul_odd(&lhs_mont, &rhs_mont, &self.modulus, self.n0_inv);
        self.decode(&product_mont)
    }

    /// Square one ordinary residue modulo the context modulus.
    #[must_use]
    pub fn square(&self, value: &BigUint) -> BigUint {
        self.mul(value, value)
    }

    /// Compute `base^exponent mod modulus` inside the context.
    #[must_use]
    pub fn pow(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        if self.modulus == BigUint::one() {
            return BigUint::zero();
        }

        let one = BigUint::one();
        let mut result = self.one_mont.clone();
        let mut power = self.encode(&base.modulo(&self.modulus));

        for bit in 0..exponent.bits() {
            if exponent.bit(bit) {
                result = BigUint::montgomery_mul_odd(&result, &power, &self.modulus, self.n0_inv);
            }
            power = BigUint::montgomery_mul_odd(&power, &power, &self.modulus, self.n0_inv);
        }

        BigUint::montgomery_mul_odd(&result, &one, &self.modulus, self.n0_inv)
    }
}

impl Drop for BigUint {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.limbs.as_mut_slice());
    }
}

#[inline]
fn low_u64(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).expect("masked low 64 bits always fit into u64")
}

fn montgomery_n0_inv(n0: u64) -> u64 {
    debug_assert!(n0 & 1 == 1, "Montgomery path requires an odd modulus");
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
    fn division_roundtrip() {
        let dividend = BigUint::from_u128(1_234_567_890_123_456_789);
        let divisor = BigUint::from_u64(37);
        let (q, r) = dividend.div_rem(&divisor);
        assert_eq!(q, BigUint::from_u128(33_366_699_733_066_399));
        assert_eq!(r, BigUint::from_u64(26));
        assert_eq!(q.mul_ref(&divisor).add_ref(&r), dividend);
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
