//! Poly1305 one-time authenticator (RFC 8439 §2.5; RFC 7539 is the same profile).
//!
//! The 32-byte one-time key is split into `r || s`, `r` is clamped as §2.5.1
//! prescribes, and tags are computed modulo `p = 2^130 − 5`.
//!
//! The accumulator is three 64-bit words multiplied through 128-bit products.
//! The clamp makes the high half of `r` a multiple of four, so the product
//! folds back below 2^130 using only `2^130 ≡ 5 (mod p)`; the derivation and
//! the carry bounds are written out above `TagState`. The computation is
//! branch-free and allocation-free with respect to key and message contents:
//! only the message *length* shapes the schedule. The one data-dependent
//! selection, the final conditional subtraction of `p`, is a mask that passes
//! through `core::hint::black_box` before use, the discipline of
//! `crate::ct::constant_time_eq_mask`, so the optimizer cannot lower it to a
//! branch on the accumulator. The multiplier, the accumulator and every
//! stack copy of `r` and `s` are wiped.

// ─── Arithmetic modulo p = 2^130 − 5, derived from RFC 8439 §2.5 ───────────
//
// Multiplier. §2.5.1 clamps r with 0x0ffffffc_0ffffffc_0ffffffc_0fffffff.
// Split r = r_lo + 2^64·r_hi. The clamp clears the top nibble of octets 7
// and 15, so r_lo < 2^60 and r_hi < 2^60, and it clears the low two bits of
// octet 8, so 4 | r_hi. Hence 2^128·r_hi = 2^130·(r_hi/4) ≡ 5·(r_hi/4)
// (mod p), because 2^130 ≡ 5. Call that folded value f = r_hi + r_hi/4; it
// is exact (no rounding) since 4 | r_hi, and f ≤ 5·(2^58 − 1) < 2^61.
//
// Accumulator. Three words a = a0 + 2^64·a1 + 2^128·a2, only partially
// reduced: a0 and a1 are full 64-bit words and a2 ≤ 4 between blocks.
//
// Product. (a0 + 2^64·a1 + 2^128·a2)·(r_lo + 2^64·r_hi) expands to
//
//     a0·r_lo + 2^64·(a0·r_hi + a1·r_lo) + 2^128·(a1·r_hi + a2·r_lo)
//             + 2^192·a2·r_hi,
//
// and replacing 2^128·r_hi by f moves the two r_hi terms down 128 bits:
//
//     a·r ≡ (a0·r_lo + a1·f) + 2^64·(a0·r_hi + a1·r_lo + a2·f)
//           + 2^128·(a2·r_lo)                                     (mod p).
//
// Bounds, with a2 ≤ 6 on entry to the product (≤ 4 carried between blocks,
// + 1 for the 2^128 pad bit of a full block, + 1 carry out of a1 when the
// block is added):
//
//     c0 = a0·r_lo + a1·f                < 2^124 + 2^125         < 2^126
//     c1 = a0·r_hi + a1·r_lo + a2·f + ⌊c0/2^64⌋
//                                        < 2^125 + 30·2^58 + 2^62 < 2^126,
//          so ⌊c1/2^64⌋ < 2^61 + 1, i.e. ⌊c1/2^64⌋ ≤ 2^61
//     c2 = a2·r_lo + ⌊c1/2^64⌋           ≤ 6·(2^60 − 1) + 2^61   < 2^63.
//
// All three fit a u128 with room to spare. The value is now
// lo64(c0) + 2^64·lo64(c1) + 2^128·c2. Write c2 = 4q + (c2 mod 4); then
// 2^128·4q = 2^130·q ≡ 5q with 5q < 5·2^61 < 2^64. Adding 5q to the low
// 128 bits carries at most 1 into 2^128, so the new a2 = (c2 mod 4) + carry
// ≤ 4 and the invariant is restored.
//
// Finish. Between blocks a < 5·2^128 < 2·p, so a mod p is a or a − p, and
// a ≥ p exactly when a + 5 ≥ 2^130. The top word of a + 5 is at most 5, so
// its bit 2 is that comparison. When a ≥ p, a − p = (a + 5) − 2^130, whose
// low 128 bits equal those of a + 5. The tag is (a mod p) + s taken mod 2^128
// (§2.5: "the 128 least significant bits are serialized"), so a mask built
// from that bit selects the low 128 bits of a or of a + 5, and s is added
// with wrapping.

use core::hint::black_box;

/// §2.5.1 `clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff`.
const R_CLAMP: u128 = 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;

/// The low 64 bits of a `u128`.
const LOW64: u128 = u64::MAX as u128;

/// Wipe one `u64` that held key-derived data.
#[inline]
fn wipe_u64(word: &mut u64) {
    crate::ct::zeroize_slice(core::slice::from_mut(word));
}

/// Wipe one `u128` that held key-derived data.
#[inline]
fn wipe_u128(word: &mut u128) {
    crate::ct::zeroize_slice(core::slice::from_mut(word));
}

/// One Poly1305 computation in progress: the clamped multiplier and the
/// partially reduced accumulator. Both are key-derived and wiped on drop.
struct TagState {
    /// `[r_lo, r_hi, f]` with `r = r_lo + 2^64·r_hi` and `f = 5·(r_hi/4)`.
    multiplier: [u64; 3],
    /// `[a0, a1, a2]` for `a = a0 + 2^64·a1 + 2^128·a2`, with `a2 ≤ 4`.
    accumulator: [u64; 3],
}

impl TagState {
    /// Clamp the first key half into the multiplier and zero the accumulator.
    ///
    /// The clamped `r` and its halves exist only as locals of this function
    /// on the way into the multiplier, and are wiped before it returns.
    fn new(r_bytes: &[u8; 16]) -> Self {
        let mut r = u128::from_le_bytes(*r_bytes) & R_CLAMP;
        let mut r_lo = r as u64;
        let mut r_hi = (r >> 64) as u64;
        let state = Self {
            multiplier: [r_lo, r_hi, r_hi + (r_hi >> 2)],
            accumulator: [0; 3],
        };
        wipe_u128(&mut r);
        wipe_u64(&mut r_lo);
        wipe_u64(&mut r_hi);
        state
    }

    /// `Acc = ((Acc + block)·r) mod p`, where the block's value is
    /// `word + 2^128·pad_bit` and the result is only partially reduced.
    fn absorb(&mut self, word: u128, pad_bit: u64) {
        let [r_lo, r_hi, f] = self.multiplier.map(u128::from);
        let [acc0, acc1, acc2] = self.accumulator.map(u128::from);

        let sum0 = acc0 + (word & LOW64);
        let sum1 = acc1 + (word >> 64) + (sum0 >> 64);
        let a0 = sum0 & LOW64;
        let a1 = sum1 & LOW64;
        let a2 = acc2 + u128::from(pad_bit) + (sum1 >> 64);

        let c0 = a0 * r_lo + a1 * f;
        let c1 = a0 * r_hi + a1 * r_lo + a2 * f + (c0 >> 64);
        let c2 = a2 * r_lo + (c1 >> 64);

        let n0 = (c0 & LOW64) + 5 * (c2 >> 2);
        let n1 = (c1 & LOW64) + (n0 >> 64);
        self.accumulator = [n0 as u64, n1 as u64, ((c2 & 3) + (n1 >> 64)) as u64];
    }

    /// `(Acc mod p + s) mod 2^128`, serialized little-endian.
    ///
    /// The selection between `Acc` and `Acc − p` is a mask made opaque with
    /// `black_box` (see the module documentation). `s`, both candidates and
    /// the selected value `tag − s` are wiped before the tag is returned.
    fn finish(&self, s_bytes: &[u8; 16]) -> [u8; 16] {
        let [acc0, acc1, acc2] = self.accumulator.map(u128::from);
        let plus5_0 = acc0 + 5;
        let plus5_1 = acc1 + (plus5_0 >> 64);
        let plus5_top = acc2 + (plus5_1 >> 64);

        let at_least_p = black_box(0u128.wrapping_sub(plus5_top >> 2));
        let mut low = acc0 | (acc1 << 64);
        let mut low_minus_p = (plus5_0 & LOW64) | ((plus5_1 & LOW64) << 64);
        let mut reduced = (low_minus_p & at_least_p) | (low & !at_least_p);
        let mut s = u128::from_le_bytes(*s_bytes);
        let tag = reduced.wrapping_add(s).to_le_bytes();
        for word in [&mut low, &mut low_minus_p, &mut reduced, &mut s] {
            wipe_u128(word);
        }
        tag
    }
}

impl Drop for TagState {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.multiplier.as_mut_slice());
        crate::ct::zeroize_slice(self.accumulator.as_mut_slice());
    }
}

/// Compute a Poly1305 tag over `msg` with the given one-time `key`.
///
/// The key must be unique per message under a fixed long-term secret.
///
/// This is RFC 8439 §2.5.1 `poly1305_mac`: 16-byte blocks, each read
/// little-endian with a 1 appended one octet past its end, are absorbed in
/// order, then `s` is added. The schedule depends only on `msg.len()`.
#[must_use]
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut r_bytes = [0u8; 16];
    let mut s_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[..16]);
    s_bytes.copy_from_slice(&key[16..]);
    let mut state = TagState::new(&r_bytes);

    let mut blocks = msg.chunks_exact(16);
    for block in &mut blocks {
        let mut word = [0u8; 16];
        word.copy_from_slice(block);
        // A full block's appended 1 sits at 2^128, above the word.
        state.absorb(u128::from_le_bytes(word), 1);
    }

    let tail = blocks.remainder();
    let mut padded = [0u8; 16];
    if !tail.is_empty() {
        // A short block's appended 1 is the octet after its last one.
        padded[..tail.len()].copy_from_slice(tail);
        padded[tail.len()] = 1;
        state.absorb(u128::from_le_bytes(padded), 0);
    }

    let tag = state.finish(&s_bytes);
    crate::ct::zeroize_slice(r_bytes.as_mut_slice());
    crate::ct::zeroize_slice(s_bytes.as_mut_slice());
    crate::ct::zeroize_slice(padded.as_mut_slice());
    tag
}

/// Poly1305 authenticator holding a single one-time key.
///
/// A Poly1305 key `r || s` may tag exactly one message: tags for two
/// different messages under the same key let an attacker solve for the key
/// and forge. Derive a fresh key per message, as ChaCha20-Poly1305 does from
/// its nonce. Verifying candidate tags reveals only accept or reject and does
/// not use up the key. The key is wiped on drop.
pub struct Poly1305 {
    key: [u8; 32],
}

impl Poly1305 {
    /// Construct a Poly1305 context from a one-time key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Construct a Poly1305 context and wipe the caller-provided key bytes.
    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    /// Compute the Poly1305 tag over `msg`, the one message this key may tag.
    #[must_use]
    pub fn compute(&self, msg: &[u8]) -> [u8; 16] {
        poly1305_mac(msg, &self.key)
    }

    /// Verify a Poly1305 tag in constant time.
    #[must_use]
    pub fn verify(&self, msg: &[u8], tag: &[u8; 16]) -> bool {
        // The genuine tag is wiped: for an attacker-chosen `msg` it is a forgery.
        let mut expected = self.compute(msg);
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        crate::ct::zeroize_slice(expected.as_mut_slice());
        authentic
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.key.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::{poly1305_mac, Poly1305, TagState};
    use crate::test_utils::decode_hex;
    use core::mem::MaybeUninit;
    use rump::BigUint;

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

    /// The multiplier `r` and the accumulator are wiped when a computation in
    /// progress is dropped, mid-message included.
    #[test]
    fn tag_state_is_wiped_on_drop() {
        let mut state = TagState::new(&[0xa5; 16]);
        state.absorb(u128::MAX, 1);
        let (before, after) = nonzero_bytes_before_and_after_drop(state);
        assert!(before > 16, "the live state is not all zero");
        assert_eq!(after, 0, "bytes left after drop");
    }

    #[test]
    fn poly1305_key_is_wiped_on_drop() {
        let (before, after) = nonzero_bytes_before_and_after_drop(Poly1305::new(&[0x5a; 32]));
        assert_eq!(before, 32);
        assert_eq!(after, 0, "bytes left after drop");
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        let key = <[u8; 32]>::try_from(decode_hex(
            "85d6be7857556d337f4452fe42d506a8\
             0103808afb0db2fd4abff6af4149f51b",
        ))
        .expect("key");
        let msg = b"Cryptographic Forum Research Group";
        let expected =
            <[u8; 16]>::try_from(decode_hex("a8061dc1305136c6c22b8baf0c0127a9")).expect("tag");
        assert_eq!(poly1305_mac(msg, &key), expected);
    }

    #[test]
    fn wrapper_verify_roundtrip() {
        let key = [0x11u8; 32];
        let mac = Poly1305::new(&key);
        let msg = b"poly1305 message";
        let tag = mac.compute(msg);
        assert!(mac.verify(msg, &tag));

        let mut tampered = tag;
        tampered[0] ^= 0x80;
        assert!(!mac.verify(msg, &tampered));
    }

    /// RFC 8439 §2.5.1 read literally, over arbitrary-precision integers,
    /// with the clamp taken from §2.5's octet-wise description rather than
    /// the 128-bit mask the implementation uses.
    fn reference_tag(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
        let from_le = |bytes: &[u8]| {
            let mut big_endian = bytes.to_vec();
            big_endian.reverse();
            BigUint::from_be_bytes(&big_endian)
        };
        let mut r_bytes = key[..16].to_vec();
        for i in [3, 7, 11, 15] {
            r_bytes[i] &= 15;
        }
        for i in [4, 8, 12] {
            r_bytes[i] &= 252;
        }
        let r = from_le(&r_bytes);
        let s = from_le(&key[16..]);
        let mut p_bytes = [0xffu8; 17];
        p_bytes[0] = 0x03;
        p_bytes[16] = 0xfb;
        let p = BigUint::from_be_bytes(&p_bytes);

        let mut acc = BigUint::zero();
        for chunk in msg.chunks(16) {
            let mut block = chunk.to_vec();
            block.push(1);
            acc = acc.add(&from_le(&block)).mul(&r).rem(&p);
        }
        let mut tag = acc.add(&s).to_be_bytes();
        tag.reverse();
        tag.resize(16, 0);
        <[u8; 16]>::try_from(tag).expect("16 bytes")
    }

    #[test]
    fn matches_rfc8439_pseudocode() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next_byte = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed.to_le_bytes()[3]
        };
        for case in 0..240usize {
            let mut key = [0u8; 32];
            key.iter_mut().for_each(|b| *b = next_byte());
            let mut msg = vec![0u8; case % 83];
            msg.iter_mut().for_each(|b| *b = next_byte());
            // Every third case pushes the carry bounds: the largest clamped
            // r, all-ones blocks, and an s whose addition wraps 2^128.
            if case % 3 == 0 {
                key.fill(0xff);
                msg.fill(0xff);
            }
            assert_eq!(
                poly1305_mac(&msg, &key),
                reference_tag(&msg, &key),
                "case {case}"
            );
        }
    }

    #[test]
    fn absorb_holds_at_the_derived_bounds() {
        // The bound derivation allows a0 and a1 anything and a2 up to 4 before a
        // block is added. Start there, add the largest full block with the
        // largest clamped r: no u128 overflows (debug builds would panic), a2
        // comes back at most 4, and the value is right modulo p.
        let mut state = TagState::new(&[0xff; 16]);
        state.accumulator = [u64::MAX, u64::MAX, 4];
        state.absorb(u128::MAX, 1);
        assert!(state.accumulator[2] <= 4);

        let word = |value: u64| BigUint::from_be_bytes(&value.to_be_bytes());
        let two64 = word(1u64 << 63).add(&word(1u64 << 63));
        let two128 = two64.mul(&two64);
        let mut p_bytes = [0xffu8; 17];
        p_bytes[0] = 0x03;
        p_bytes[16] = 0xfb;
        let p = BigUint::from_be_bytes(&p_bytes);
        let r = BigUint::from_be_bytes(&super::R_CLAMP.to_be_bytes());
        let max_word = word(u64::MAX);
        let start = max_word
            .add(&max_word.mul(&two64))
            .add(&word(4).mul(&two128));
        let block = max_word.add(&max_word.mul(&two64)).add(&two128);
        let expected = start.add(&block).mul(&r).rem(&p);
        let [a0, a1, a2] = state.accumulator;
        let got = word(a0)
            .add(&word(a1).mul(&two64))
            .add(&word(a2).mul(&two128));
        assert_eq!(got.rem(&p), expected);
    }
}
