//! GHASH's block multiplication (NIST SP 800-38D §6.3, Algorithm 1) and POLYVAL
//! (RFC 8452 §3), constant-time in their operands.
//!
//! # Representation
//!
//! A 16-byte block is held as `u128::from_be_bytes(block)`, the convention of
//! the GCM code in the parent module. SP 800-38D §6.3 names a block's bits
//! `x0 x1 … x127` from the left and reads them as the polynomial
//! `x0 + x1·u + … + x127·u^127`, so the coefficient of `u^i` is bit `127 − i`
//! of the integer: the lowest power sits in the top bit.
//!
//! # Multiplication by u
//!
//! Multiplying by `u` moves the coefficient of `u^i` to `u^(i+1)`, one bit to
//! the right in this layout: `v >> 1`. The coefficient of `u^127` (bit 0) moves
//! to `u^128`. The field is taken modulo `u^128 + u^7 + u^2 + u + 1`, the
//! polynomial of `R || 1` (§6.3), so `u^128 = u^7 + u^2 + u + 1`. Those four
//! coefficients sit at bits `127 − 7`, `127 − 2`, `127 − 1`, `127 − 0`, that is
//! bits 120, 125, 126, 127: the integer `0xE1 << 120`, which is §6.3's
//! `R = 11100001 || 0^120`. So `v·u = (v >> 1) ⊕ (R if bit 0 of v is set)`,
//! Algorithm 1's update of `V`.
//!
//! # The product
//!
//! Algorithm 1 walks `x0 … x127` and adds `V_i = Y·u^i` into `Z` whenever
//! `x_i = 1`, so `Z_128 = Σ x_i·Y·u^i = X·Y`. GHASH (§6.4 step 3) and POLYVAL
//! always multiply by the same hash subkey `H`, so the blocks `V_i = H·u^i` are
//! the same for every block of a message. `SubkeyTable` computes the 128 of
//! them once, by repeated multiplication by `u`, and each product is then 128
//! masked XORs. The bit `x_i` becomes an all-zeros or all-ones mask instead of
//! a branch, and the table is read in index order, so neither the instructions
//! executed nor the memory touched depend on `X` or `H`.
//!
//! `VariableTimeSubkey` is Algorithm 1 exactly as printed, branching on `x_i`
//! and on `LSB1(V_i)`. It backs the variable-time `GcmVt` and `GmacVt`
//! comparison paths and serves as a second, independently shaped product in
//! the tests.
//!
//! # Barrier discipline
//!
//! The constant-time claim is made at source level: the mask derived from
//! `x_i` is arithmetic, not a condition. An optimizer that could see the mask
//! is all-zeros or all-ones would be free to lower the masked XOR back into a
//! branch, so every mask passes through `core::hint::black_box` before it is
//! used, the same discipline as `crate::ct::constant_time_eq_mask`. `black_box`
//! is a hint rather than a guarantee; it removes the optimizer's knowledge of
//! the mask's value, which is what the branch conversion needs.
//!
//! # POLYVAL
//!
//! RFC 8452 Appendix A shows that reversing the bytes of a 16-byte string
//! carries POLYVAL's field and bit order onto GHASH's, and that
//! `POLYVAL(H, X_1, …, X_n) = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//! ByteReverse(X_1), …, ByteReverse(X_n)))`. In the representation above,
//! `u128::from_be_bytes(ByteReverse(s))` is `u128::from_le_bytes(s)`, and
//! `mulX_GHASH` is multiplication by `u`.

use core::hint::black_box;

/// `R = 11100001 || 0^120` (SP 800-38D §6.3): `u^128` reduced modulo
/// `u^128 + u^7 + u^2 + u + 1`, in the block layout.
const R: u128 = 0xE1 << 120;

/// `v·u`: RFC 8452 Appendix A's `mulX_GHASH`, constant-time in `v`.
#[inline]
pub(super) const fn times_u(v: u128) -> u128 {
    (v >> 1) ^ (R & 0u128.wrapping_sub(v & 1))
}

/// A GHASH hash subkey `H` prepared for SP 800-38D §6.4 step 3,
/// `Y_i = (Y_{i-1} ⊕ X_i) • H`: every product in a message is by the same `H`.
pub(super) trait HashSubkey {
    /// Prepare the hash subkey `h` (a block in the layout described above).
    fn new(h: u128) -> Self;

    /// The block product `x • H` (SP 800-38D §6.3).
    fn multiply(&self, x: u128) -> u128;
}

/// Bits in a GHASH field element, and so entries in the table of multiples
/// (SP 800-38D §6.3: the field is GF(2^128)).
const FIELD_BITS: usize = 128;

/// Bytes in a field element.
const BLOCK_BYTES: usize = FIELD_BITS / 8;

/// Bits in each half of the `u128` the table walks.
const HALF_BITS: usize = FIELD_BITS / 2;

/// A hash subkey `H` prepared for SP 800-38D §6.3 products `X • H`: Algorithm
/// 1's blocks `V_i = H·u^i` for `i = 0..128`, each as `[high, low]` halves.
///
/// The table is key material and is wiped on drop.
pub(super) struct SubkeyTable {
    multiples: [[u64; 2]; FIELD_BITS],
}

impl HashSubkey for SubkeyTable {
    /// Algorithm 1 step 2 and the `V` half of step 3: `V_0 = H` and
    /// `V_{i+1} = V_i·u`.
    ///
    /// The table is filled inside the value that is returned, so no second,
    /// unwiped copy of the multiples is left in a constructor local.
    fn new(h: u128) -> Self {
        let mut table = Self {
            multiples: [[0u64; 2]; FIELD_BITS],
        };
        let mut v = h;
        for entry in &mut table.multiples {
            *entry = [(v >> 64) as u64, v as u64];
            v = times_u(v);
        }
        super::wipe_u128(&mut v);
        table
    }

    /// `X • H` (SP 800-38D §6.3): the XOR of the `V_i` whose bit `x_i` is 1.
    fn multiply(&self, x: u128) -> u128 {
        let (first_half, second_half) = self.multiples.split_at(HALF_BITS);
        let mut z_high = 0u64;
        let mut z_low = 0u64;
        // x0 … x63 are the high half of x from its top bit down; x64 … x127
        // are the low half.
        for (half, multiples) in [((x >> 64) as u64, first_half), (x as u64, second_half)] {
            let mut bits = half;
            for [v_high, v_low] in multiples {
                // All-ones iff x_i = 1; opaque to the optimizer (see the
                // module's "Barrier discipline").
                let take = black_box(0u64.wrapping_sub(bits >> 63));
                z_high ^= v_high & take;
                z_low ^= v_low & take;
                bits <<= 1;
            }
        }
        (u128::from(z_high) << 64) | u128::from(z_low)
    }
}

impl Drop for SubkeyTable {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.multiples.as_mut_slice());
    }
}

/// A hash subkey for the variable-time comparison path: SP 800-38D §6.3
/// Algorithm 1 as printed, with a branch on each `x_i` and each `LSB1(V_i)`.
///
/// Its timing depends on both operands, so it must never see data whose
/// timing matters; `SubkeyTable` is the constant-time path. Wiped on drop.
pub(super) struct VariableTimeSubkey {
    h: u128,
}

impl HashSubkey for VariableTimeSubkey {
    fn new(h: u128) -> Self {
        Self { h }
    }

    fn multiply(&self, x: u128) -> u128 {
        // Step 2: Z_0 = 0^128 and V_0 = Y.
        let mut z = 0u128;
        let mut v = self.h;
        // Step 3, for x0 (bit 127) down to x127 (bit 0).
        for i in 0..FIELD_BITS {
            if (x >> (127 - i)) & 1 == 1 {
                z ^= v;
            }
            v = if v & 1 == 0 { v >> 1 } else { (v >> 1) ^ R };
        }
        z
    }
}

impl Drop for VariableTimeSubkey {
    fn drop(&mut self) {
        super::wipe_u128(&mut self.h);
    }
}

/// POLYVAL (RFC 8452 §3) of `input` under the 16-byte key `h`, computed through
/// GHASH as RFC 8452 Appendix A describes.
///
/// `input` is read as consecutive 16-byte field elements. A shorter final chunk
/// is zero-padded, which GCM-SIV never relies on because it pads its input to a
/// multiple of 16 bytes (RFC 8452 §4) before calling POLYVAL.
pub(super) fn polyval(h: &[u8; BLOCK_BYTES], input: &[u8]) -> [u8; BLOCK_BYTES] {
    let mut ghash_key = times_u(u128::from_le_bytes(*h));
    let table = SubkeyTable::new(ghash_key);
    super::wipe_u128(&mut ghash_key);
    let mut acc = 0u128;
    let mut element = [0u8; BLOCK_BYTES];
    for chunk in input.chunks(BLOCK_BYTES) {
        element.fill(0);
        element[..chunk.len()].copy_from_slice(chunk);
        acc = table.multiply(acc ^ u128::from_le_bytes(element));
    }
    let out = acc.to_le_bytes();
    super::wipe_u128(&mut acc);
    crate::ct::zeroize_slice(element.as_mut_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::{polyval, times_u, HashSubkey, SubkeyTable, VariableTimeSubkey, R};
    use crate::test_utils::decode_hex_array;
    use core::mem::MaybeUninit;

    /// The count of non-zero bytes in `T`'s storage before and after it is
    /// dropped in place.
    #[allow(unsafe_code)] // observes the bytes a `Drop` leaves behind
    fn nonzero_bytes_before_and_after_drop<T>(value: T) -> (usize, usize) {
        let mut slot = MaybeUninit::new(value);
        let size = core::mem::size_of::<T>();
        // SAFETY: `slot` is initialised and the byte view covers exactly its
        // storage, which stays allocated (holding initialised bytes) until
        // `slot` goes out of scope; nothing uses the value after the drop
        // except this byte-level inspection.
        unsafe {
            let bytes = core::slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size);
            let before = bytes.iter().filter(|&&b| b != 0).count();
            core::ptr::drop_in_place(slot.as_mut_ptr());
            let after = bytes.iter().filter(|&&b| b != 0).count();
            (before, after)
        }
    }

    /// The 128 multiples of `H` are key material: none survives the drop.
    #[test]
    fn subkey_table_is_wiped_on_drop() {
        let h = element("b83b533708bf535d0aa6e52980d53b78");
        let (before, after) = nonzero_bytes_before_and_after_drop(SubkeyTable::new(h));
        assert!(before > 1024, "the live table is not all zero");
        assert_eq!(after, 0, "bytes left after drop");
    }

    #[test]
    fn variable_time_subkey_is_wiped_on_drop() {
        let h = element("b83b533708bf535d0aa6e52980d53b78");
        let (before, after) = nonzero_bytes_before_and_after_drop(VariableTimeSubkey::new(h));
        assert_eq!(before, 16);
        assert_eq!(after, 0, "bytes left after drop");
    }

    /// A GHASH field element written as its 16-byte string (SP 800-38D layout).
    fn element(hex: &str) -> u128 {
        u128::from_be_bytes(decode_hex_array::<16>(hex))
    }

    fn product(x: u128, y: u128) -> u128 {
        SubkeyTable::new(y).multiply(x)
    }

    /// An independent oracle: reverse the bits so bit i is the coefficient of
    /// u^i, multiply schoolbook into 256 bits, reduce by long division with
    /// u^128 + u^7 + u^2 + u + 1, and reverse back.
    fn schoolbook_product(x: u128, y: u128) -> u128 {
        let a = x.reverse_bits();
        let b = y.reverse_bits();
        let (mut high, mut low) = (0u128, 0u128);
        for i in 0..128 {
            if (a >> i) & 1 == 1 {
                low ^= b << i;
                if i > 0 {
                    high ^= b >> (128 - i);
                }
            }
        }
        // u^7 + u^2 + u + 1.
        const LOW_TERMS: u128 = 0x87;
        for degree in (128..256).rev() {
            let shift = degree - 128;
            if (high >> shift) & 1 == 1 {
                high ^= 1 << shift;
                low ^= LOW_TERMS << shift;
                if shift > 120 {
                    high ^= LOW_TERMS >> (128 - shift);
                }
            }
        }
        assert_eq!(high, 0);
        low.reverse_bits()
    }

    fn next(state: &mut u64) -> u128 {
        let mut half = || {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        };
        (u128::from(half()) << 64) | u128::from(half())
    }

    #[test]
    fn matches_schoolbook_oracle() {
        let mut state = 0x0123_4567_89ab_cdefu64;
        let corners = [0, 1, 2, 1 << 63, 1 << 64, 1 << 127, R, u128::MAX];
        for &a in &corners {
            for &b in &corners {
                assert_eq!(product(a, b), schoolbook_product(a, b), "{a:x} {b:x}");
            }
        }
        for _ in 0..5_000 {
            let h = next(&mut state);
            let table = SubkeyTable::new(h);
            for _ in 0..4 {
                let x = next(&mut state);
                assert_eq!(table.multiply(x), schoolbook_product(x, h), "{x:x} {h:x}");
            }
        }
    }

    #[test]
    fn constant_time_and_variable_time_paths_agree() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let corners = [0, 1, 1 << 127, R, u128::MAX];
        for &h in &corners {
            for &x in &corners {
                assert_eq!(
                    SubkeyTable::new(h).multiply(x),
                    VariableTimeSubkey::new(h).multiply(x)
                );
            }
        }
        for _ in 0..2_000 {
            let (h, x) = (next(&mut state), next(&mut state));
            assert_eq!(
                SubkeyTable::new(h).multiply(x),
                VariableTimeSubkey::new(h).multiply(x),
                "{x:x} {h:x}"
            );
        }
    }

    #[test]
    fn field_laws() {
        // The block for the polynomial 1 is x0 = 1: the top bit.
        let one = element("80000000000000000000000000000000");
        let u = element("40000000000000000000000000000000");
        let u127 = element("00000000000000000000000000000001");
        assert_eq!(product(u, u127), R, "u·u^127 = u^128 = R");
        assert_eq!(times_u(u127), R);

        let mut state = 0xfeed_beef_cafe_f00du64;
        for _ in 0..200 {
            let (a, b, c) = (next(&mut state), next(&mut state), next(&mut state));
            assert_eq!(product(a, one), a);
            assert_eq!(product(a, b), product(b, a));
            assert_eq!(product(product(a, b), c), product(a, product(b, c)));
            assert_eq!(product(a, b ^ c), product(a, b) ^ product(a, c));
            assert_eq!(product(a, u), times_u(a));
        }

        // a^(2^128 − 2) is a^-1: square-and-multiply over 127 ones then a 0.
        let a = next(&mut state) | 1;
        let a_table = SubkeyTable::new(a);
        let mut power = one;
        for bit in (0..128).rev() {
            power = product(power, power);
            if bit != 0 {
                power = a_table.multiply(power);
            }
        }
        assert_eq!(a_table.multiply(power), one);
    }

    /// RFC 8452 Appendix A: the `mulX_GHASH` examples.
    #[test]
    fn rfc8452_appendix_a_mulx_ghash() {
        assert_eq!(
            times_u(element("01000000000000000000000000000000")),
            element("00800000000000000000000000000000")
        );
        assert_eq!(
            times_u(element("9c98c04df9387ded828175a92ba652d8")),
            element("4e4c6026fc9c3ef6c140bad495d3296c")
        );
    }

    /// RFC 8452 Appendix A worked example: GHASH(H, X_1, X_2), the GHASH key
    /// POLYVAL derives, and POLYVAL(H, X_1, X_2).
    #[test]
    fn rfc8452_appendix_a_worked_example() {
        let h = decode_hex_array::<16>("25629347589242761d31f826ba4b757b");
        let x1 = decode_hex_array::<16>("4f4f95668c83dfb6401762bb2d01a262");
        let x2 = decode_hex_array::<16>("d1a24ddd2721d006bbe45f20d3c9f362");

        let table = SubkeyTable::new(u128::from_be_bytes(h));
        let y1 = table.multiply(u128::from_be_bytes(x1));
        let y2 = table.multiply(y1 ^ u128::from_be_bytes(x2));
        assert_eq!(y2, element("bd9b3997046731fb96251b91f9c99d7a"));

        assert_eq!(
            times_u(u128::from_le_bytes(h)),
            element("dcbaa5dd137c188ebb21492c23c9b112")
        );

        let mut input = [0u8; 32];
        input[..16].copy_from_slice(&x1);
        input[16..].copy_from_slice(&x2);
        assert_eq!(
            polyval(&h, &input),
            decode_hex_array::<16>("f7a3b47b846119fae5b7866cf5e5b77e")
        );
    }

    /// RFC 8452 §7: dot(a, b) = POLYVAL(b, a) for a single element.
    #[test]
    fn rfc8452_section_7_dot() {
        let a = decode_hex_array::<16>("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let b = decode_hex_array::<16>("ff000000000000000000000000000000");
        assert_eq!(
            polyval(&b, &a),
            decode_hex_array::<16>("ebe563401e7e91ea3ad6426b8140c394")
        );
    }
}
