//! OCB authenticated encryption (RFC 7253, OCB3).
//!
//! RFC 7253 section 3 makes OCB a function of two global parameters: a block
//! cipher on 128-bit blocks and TAGLEN, the length of the authentication tag
//! in bits. [`Ocb<C, TAG_LEN>`](Ocb) takes the cipher as `C` and TAGLEN as the
//! const generic `TAG_LEN`, in bytes, restricted to the lengths of the
//! parameter sets named in section 3.1: 16, 12 and 8 bytes (TAGLEN 128, 96 and
//! 64).
//!
//! A shorter tag is not a truncated 128-bit tag. OCB-ENCRYPT (section 4.2)
//! begins with
//!
//! ```text
//! Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
//! ```
//!
//! so the tag length changes `Offset_0`, and with it every ciphertext block as
//! well as the tag.

use super::{dbl_block, xor_block16_in_place};
use crate::BlockCipher;

/// The key-only OCB offsets of RFC 7253 §4.1: `L_*`, `L_$`, and the lazily
/// extended `L_i = dbl(L_{i-1})` from `L_0 = dbl(L_$)`.
///
/// All of them derive from `E_K(0^128)`, and an attacker who learns them can
/// forge. `L_i` lives in a fixed array, so extending the table never
/// reallocates and abandons a copy on the heap, and the whole table is wiped
/// on drop.
struct OcbOffsets {
    l_star: [u8; 16],
    l_dollar: [u8; 16],
    // `L_i` for `i < filled`. A block index below 2^64 has at most 63 trailing
    // zeros, so 64 entries cover every addressable block.
    l: [[u8; 16]; 64],
    filled: usize,
}

impl OcbOffsets {
    /// An all-zero table. `derive` fills it in place, so the key-derived
    /// values are never moved out of a constructor's stack frame.
    const fn empty() -> Self {
        Self {
            l_star: [0; 16],
            l_dollar: [0; 16],
            l: [[0; 16]; 64],
            filled: 0,
        }
    }

    /// Fill `L_* = E_K(0^128)`, `L_$ = dbl(L_*)`, and `L_0 = dbl(L_$)`.
    fn derive<C: BlockCipher>(&mut self, cipher: &C) {
        self.l_star = [0u8; 16];
        cipher.encrypt(&mut self.l_star);
        self.l_dollar = dbl_block(self.l_star);
        self.l[0] = dbl_block(self.l_dollar);
        self.filled = 1;
    }

    /// `L_{ntz(i)}` for the 1-based block index `i`.
    fn for_block(&mut self, i: usize) -> &[u8; 16] {
        let tz = i.trailing_zeros() as usize;
        while self.filled <= tz {
            self.l[self.filled] = dbl_block(self.l[self.filled - 1]);
            self.filled += 1;
        }
        &self.l[tz]
    }
}

impl Drop for OcbOffsets {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.l_star.as_mut_slice());
        crate::ct::zeroize_slice(self.l_dollar.as_mut_slice());
        crate::ct::zeroize_slice(&mut self.l[..self.filled]);
    }
}

#[inline]
fn split_blocks(data: &[u8]) -> (&[u8], &[u8]) {
    let full = data.len() / 16 * 16;
    (&data[..full], &data[full..])
}

/// `Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N` of
/// RFC 7253 section 4.2, for a byte-string nonce `N` of at most 15 bytes.
fn nonce_block_from_bytes(tag_len_bits: usize, nonce: &[u8]) -> [u8; 16] {
    assert!(nonce.len() <= 15, "OCB nonce must be at most 120 bits");
    let n_bits = nonce.len() * 8;
    let tag_mod = tag_len_bits % 128;

    let mut n_aligned = [0u8; 16];
    n_aligned[16 - nonce.len()..].copy_from_slice(nonce);
    let n_val = u128::from_be_bytes(n_aligned);

    let nonce_val = ((tag_mod as u128) << 121) | (1u128 << n_bits) | n_val;
    nonce_val.to_be_bytes()
}

fn stretch_from_ktop(ktop: [u8; 16]) -> [u8; 24] {
    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }
    stretch
}

/// `Offset_0 = Stretch[1+bottom..128+bottom]` of RFC 7253 §4.2: the 128 bits
/// of the 192-bit `Stretch` starting `bottom` bits in.
///
/// `bottom` is the low six bits of the nonce block, so `bottom <= 63`: the
/// window starts at byte `bottom / 8 <= 7` and, when it is not byte-aligned,
/// its last bits come from byte `7 + 15 + 1 = 23`, the final byte of
/// `Stretch`. Every index below is therefore in bounds, and the `bit_off == 0`
/// case needs at most bytes `7..23`.
fn offset_from_stretch(stretch: &[u8; 24], bottom: u8) -> [u8; 16] {
    debug_assert!(bottom < 64, "bottom is a six-bit value");
    let byte_off = usize::from(bottom / 8);
    let bit_off = usize::from(bottom % 8);
    let mut out = [0u8; 16];

    if bit_off == 0 {
        out.copy_from_slice(&stretch[byte_off..byte_off + 16]);
        return out;
    }

    for (i, out_byte) in out.iter_mut().enumerate() {
        let b0 = stretch[byte_off + i];
        let b1 = stretch[byte_off + i + 1];
        *out_byte = (b0 << bit_off) | (b1 >> (8 - bit_off));
    }
    out
}

/// `HASH(K, A)` of RFC 7253 §4.1. The running offset and the cipher input are
/// wiped before the sum is returned; the caller wipes the sum.
fn hash_associated_data<C: BlockCipher>(
    cipher: &C,
    offsets: &mut OcbOffsets,
    aad: &[u8],
) -> [u8; 16] {
    let mut sum = [0u8; 16];
    let mut offset = [0u8; 16];
    let mut x = [0u8; 16];

    let (full, partial) = split_blocks(aad);
    for (idx, block) in full.chunks_exact(16).enumerate() {
        // RFC 7253 uses L_{ntz(i)} to advance offsets for full associated-data blocks.
        xor_block16_in_place(&mut offset, offsets.for_block(idx + 1));
        x.copy_from_slice(block);
        xor_block16_in_place(&mut x, &offset);
        cipher.encrypt(&mut x);
        xor_block16_in_place(&mut sum, &x);
    }

    if !partial.is_empty() {
        // Final partial AD block uses Offset xor L_* and 10* padding.
        xor_block16_in_place(&mut offset, &offsets.l_star);
        x = [0u8; 16];
        x[..partial.len()].copy_from_slice(partial);
        x[partial.len()] = 0x80;
        xor_block16_in_place(&mut x, &offset);
        cipher.encrypt(&mut x);
        xor_block16_in_place(&mut sum, &x);
    }

    crate::ct::zeroize_slice(offset.as_mut_slice());
    crate::ct::zeroize_slice(x.as_mut_slice());
    sum
}

/// OCB3 authenticated encryption (RFC 7253) with a detached `TAG_LEN`-byte
/// tag.
///
/// `TAG_LEN` is TAGLEN / 8 for one of the parameter sets of RFC 7253
/// section 3.1:
///
/// | `TAG_LEN`    | TAGLEN | Section 3.1 names                      |
/// |--------------|--------|----------------------------------------|
/// | 16 (default) | 128    | `AEAD_AES_{128,192,256}_OCB_TAGLEN128` |
/// | 12           | 96     | `AEAD_AES_{128,192,256}_OCB_TAGLEN96`  |
/// | 8            | 64     | `AEAD_AES_{128,192,256}_OCB_TAGLEN64`  |
///
/// `Ocb<C>` is the 128-bit-tag mode. The length is part of the type, so name
/// it wherever the compiler cannot infer it from how the tag is used:
///
/// ```
/// use cryptography::{Aes128, Ocb};
///
/// let ocb = Ocb::<_, 12>::new(Aes128::new(&[0u8; 16])); // AEAD_AES_128_OCB_TAGLEN96
/// let nonce = [1u8; 12];
/// let mut data = *b"attack at dawn";
/// let tag: [u8; 12] = ocb.encrypt(&nonce, b"header", &mut data);
/// assert!(ocb.decrypt(&nonce, b"header", &mut data, &tag));
/// assert_eq!(&data, b"attack at dawn");
/// ```
///
/// Any other length fails to compile:
///
/// ```compile_fail,E0080
/// use cryptography::{Aes128, Ocb};
///
/// let ocb = Ocb::<_, 10>::new(Aes128::new(&[0u8; 16]));
/// ```
///
/// # Tag length
///
/// An adversary forges with probability `2^-TAGLEN` by guessing, and RFC 7253
/// section 5 asks that a key be used with a single tag length, rejecting
/// ciphertexts that claim another length under the same key. `decrypt` takes
/// only a `TAG_LEN`-byte tag, so one mode value never verifies a tag of
/// another length; keep each key with one `TAG_LEN`.
///
/// # Nonce reuse
///
/// Reusing a nonce under the same key breaks both confidentiality and
/// authenticity. Never reuse a `(key, nonce)` pair. RFC 7253 additionally
/// caps the total data protected by one key at 2^48 blocks; rekey before
/// reaching that bound.
pub struct Ocb<C, const TAG_LEN: usize = 16> {
    cipher: C,
}

impl<C, const TAG_LEN: usize> Ocb<C, TAG_LEN> {
    /// Wrap a 128-bit block cipher in RFC 7253 OCB mode with a `TAG_LEN`-byte
    /// tag.
    ///
    /// A `TAG_LEN` other than 16, 12 or 8 is a compile-time error when the
    /// program is built.
    pub fn new(cipher: C) -> Self {
        const {
            assert!(
                matches!(TAG_LEN, 8 | 12 | 16),
                "RFC 7253 OCB tag length must be 16, 12 or 8 bytes (TAGLEN 128, 96 or 64)"
            );
        }
        Self { cipher }
    }

    /// Borrow the wrapped cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }

    /// Return the detached authentication tag length in bytes, TAGLEN / 8.
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

impl<C: BlockCipher, const TAG_LEN: usize> Ocb<C, TAG_LEN> {
    /// Nonce-dependent `Offset_0` (RFC 7253 §4.2) from `Ktop || Stretch` and
    /// the bottom six nonce bits. `Ktop` and `Stretch` are key-derived and are
    /// wiped here; the caller wipes the returned offset.
    fn initial_offset(&self, nonce: &[u8]) -> [u8; 16] {
        let nonce_block = nonce_block_from_bytes(TAG_LEN * 8, nonce);
        let bottom = nonce_block[15] & 0x3f;
        let mut ktop = nonce_block;
        ktop[15] &= 0xC0;
        self.cipher.encrypt(&mut ktop);
        let mut stretch = stretch_from_ktop(ktop);
        let offset0 = offset_from_stretch(&stretch, bottom);
        crate::ct::zeroize_slice(ktop.as_mut_slice());
        crate::ct::zeroize_slice(stretch.as_mut_slice());
        offset0
    }

    /// Encrypt `data` in place and return the detached tag, `Tag[1..TAGLEN]`
    /// of RFC 7253 section 4.2.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block is not 128 bits, or if `nonce` is longer
    /// than 15 bytes (section 4.2 allows at most 120 bits).
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        assert_eq!(C::BLOCK_LEN, 16, "OCB requires a 128-bit block cipher");
        let mut offsets = OcbOffsets::empty();
        offsets.derive(&self.cipher);
        let mut offset = self.initial_offset(nonce);
        let mut aad_hash = hash_associated_data(&self.cipher, &mut offsets, aad);

        let (full_len, partial_len) = (data.len() / 16 * 16, data.len() % 16);
        let mut checksum = [0u8; 16];
        let mut p = [0u8; 16];

        for (idx, block) in data[..full_len].chunks_exact_mut(16).enumerate() {
            // RFC 7253 §4.2: Offset_i = Offset_{i-1} xor L_{ntz(i)}.
            xor_block16_in_place(&mut offset, offsets.for_block(idx + 1));
            p.copy_from_slice(block);
            xor_block16_in_place(&mut checksum, &p);
            xor_block16_in_place(&mut p, &offset);
            self.cipher.encrypt(&mut p);
            xor_block16_in_place(&mut p, &offset);
            block.copy_from_slice(&p);
        }

        let mut pad = [0u8; 16];
        if partial_len != 0 {
            // RFC 7253 §4.2 final partial block: Offset_* = Offset_m xor L_*.
            xor_block16_in_place(&mut offset, &offsets.l_star);
            pad = offset;
            self.cipher.encrypt(&mut pad);

            let partial = &mut data[full_len..];
            p = [0u8; 16];
            p[..partial.len()].copy_from_slice(partial);
            p[partial.len()] = 0x80;
            xor_block16_in_place(&mut checksum, &p);
            for (byte, key) in partial.iter_mut().zip(pad.iter()) {
                *byte ^= key;
            }
        }

        // The 128-bit Tag of section 4.2; the ciphertext carries Tag[1..TAGLEN].
        let mut full_tag = checksum;
        xor_block16_in_place(&mut full_tag, &offset);
        xor_block16_in_place(&mut full_tag, &offsets.l_dollar);
        self.cipher.encrypt(&mut full_tag);
        xor_block16_in_place(&mut full_tag, &aad_hash);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full_tag[..TAG_LEN]);

        // The offset and pad are key-derived, the checksum and `p` carry
        // plaintext, the AD hash is half of the tag, and below 128 bits the
        // untransmitted tail of the full tag is secret.
        for block in [
            &mut offset,
            &mut aad_hash,
            &mut checksum,
            &mut p,
            &mut pad,
            &mut full_tag,
        ] {
            crate::ct::zeroize_slice(block.as_mut_slice());
        }
        tag
    }

    /// Verify `tag` and decrypt `data` in place on success (RFC 7253 section
    /// 4.3). Returns `false` and leaves `data` unchanged when the tag does not
    /// verify.
    ///
    /// The computed `Tag[1..TAGLEN]` is compared with `tag` in constant time:
    /// all `TAG_LEN` bytes are examined whatever their values, at every tag
    /// length.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block is not 128 bits, or if `nonce` is longer
    /// than 15 bytes (section 4.3 allows at most 120 bits).
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        assert_eq!(C::BLOCK_LEN, 16, "OCB requires a 128-bit block cipher");
        let mut offsets = OcbOffsets::empty();
        offsets.derive(&self.cipher);
        let mut offset = self.initial_offset(nonce);
        let mut aad_hash = hash_associated_data(&self.cipher, &mut offsets, aad);

        let (full_len, partial_len) = (data.len() / 16 * 16, data.len() % 16);
        let mut checksum = [0u8; 16];
        let mut c = [0u8; 16];

        // Decrypt into a heap copy and commit only if the tag verifies.
        let mut plaintext = data.to_vec();
        for (idx, block) in plaintext[..full_len].chunks_exact_mut(16).enumerate() {
            // RFC 7253 §4.3: Offset_i = Offset_{i-1} xor L_{ntz(i)}.
            xor_block16_in_place(&mut offset, offsets.for_block(idx + 1));
            c.copy_from_slice(block);
            xor_block16_in_place(&mut c, &offset);
            self.cipher.decrypt(&mut c);
            xor_block16_in_place(&mut c, &offset);
            xor_block16_in_place(&mut checksum, &c);
            block.copy_from_slice(&c);
        }

        let mut pad = [0u8; 16];
        if partial_len != 0 {
            // RFC 7253 §4.3 final partial block: Offset_* = Offset_m xor L_*.
            xor_block16_in_place(&mut offset, &offsets.l_star);
            pad = offset;
            self.cipher.encrypt(&mut pad);
            let partial = &mut plaintext[full_len..];
            for (byte, key) in partial.iter_mut().zip(pad.iter()) {
                *byte ^= key;
            }
            c = [0u8; 16];
            c[..partial.len()].copy_from_slice(partial);
            c[partial.len()] = 0x80;
            xor_block16_in_place(&mut checksum, &c);
        }

        let mut expected = checksum;
        xor_block16_in_place(&mut expected, &offset);
        xor_block16_in_place(&mut expected, &offsets.l_dollar);
        self.cipher.encrypt(&mut expected);
        xor_block16_in_place(&mut expected, &aad_hash);

        // Section 4.3: valid iff Tag[1..TAGLEN] == T. `constant_time_eq_mask`
        // reads every byte of both TAG_LEN-byte strings with no early exit.
        let authentic = crate::ct::constant_time_eq_mask(&expected[..TAG_LEN], tag) == u8::MAX;
        if authentic {
            data.copy_from_slice(&plaintext);
        }
        // The heap copy is unauthenticated plaintext on failure and a
        // duplicate on success; on failure `expected` is a valid tag for the
        // attacker's ciphertext, and below 128 bits its untransmitted tail is
        // secret on either path.
        crate::ct::zeroize_slice(&mut plaintext);
        for block in [
            &mut offset,
            &mut aad_hash,
            &mut checksum,
            &mut c,
            &mut pad,
            &mut expected,
        ] {
            crate::ct::zeroize_slice(block.as_mut_slice());
        }
        authentic
    }
}

#[cfg(test)]
mod tests {
    use super::{nonce_block_from_bytes, offset_from_stretch, Ocb, OcbOffsets};
    use crate::test_utils::decode_hex;
    use crate::Aes128;
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

    /// `L_*`, `L_$` and every `L_i` that was derived are wiped on drop; the
    /// only bytes left are the `filled` count, which is not secret.
    #[test]
    fn ocb_offsets_are_wiped_on_drop() {
        let mut offsets = OcbOffsets::empty();
        offsets.derive(&Aes128::new(&[0x5au8; 16]));
        // Extend the table to L_5 so more than the eager entries are live.
        let _ = offsets.for_block(32);
        assert_eq!(offsets.filled, 6);
        let filled_bytes = offsets
            .filled
            .to_ne_bytes()
            .iter()
            .filter(|&&b| b != 0)
            .count();
        let (before, after) = nonzero_bytes_before_and_after_drop(offsets);
        assert!(before > 6 * 16, "the live offsets are not all zero");
        assert_eq!(after, filled_bytes, "key-derived bytes left after drop");
    }

    /// Every `bottom` in `0..64` reads only bytes inside the 24-byte
    /// `Stretch`, and the window it returns is `Stretch` shifted left by
    /// `bottom` bits.
    #[test]
    fn offset_window_covers_every_bottom_value() {
        let stretch: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5c);
        let wide = u128::from_be_bytes(stretch[..16].try_into().expect("16 bytes"));
        let tail = u64::from_be_bytes(stretch[16..].try_into().expect("8 bytes"));
        for bottom in 0..64u8 {
            let shift = u32::from(bottom);
            let expected = if shift == 0 {
                wide
            } else {
                (wide << shift) | (u128::from(tail) >> (64 - shift))
            };
            assert_eq!(
                u128::from_be_bytes(offset_from_stretch(&stretch, bottom)),
                expected,
                "bottom {bottom}"
            );
        }
    }

    #[test]
    fn rfc7253_sample_vector_1_empty() {
        let key =
            <[u8; 16]>::try_from(decode_hex("000102030405060708090A0B0C0D0E0F")).expect("key");
        let nonce = decode_hex("BBAA99887766554433221100");
        let aad = [];
        let mut pt = vec![];
        let expected = decode_hex("785407BFFFC8AD9EDCC5520AC9111EE6");

        let ocb = Ocb::<_, 16>::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, &aad, &mut pt);
        assert_eq!(pt, Vec::<u8>::new());
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    #[test]
    fn rfc7253_sample_vector_2_short_aad_and_pt() {
        let key =
            <[u8; 16]>::try_from(decode_hex("000102030405060708090A0B0C0D0E0F")).expect("key");
        let nonce = decode_hex("BBAA99887766554433221101");
        let aad = decode_hex("0001020304050607");
        let mut pt = decode_hex("0001020304050607");
        let expected = decode_hex("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009");

        let ocb = Ocb::<_, 16>::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, &aad, &mut pt);
        let mut out = pt.clone();
        out.extend_from_slice(&tag);
        assert_eq!(out, expected);

        assert!(ocb.decrypt(&nonce, &aad, &mut pt, &tag));
        assert_eq!(pt, decode_hex("0001020304050607"));
    }

    #[test]
    fn rfc7253_sample_vector_4_short_pt_no_aad() {
        let key =
            <[u8; 16]>::try_from(decode_hex("000102030405060708090A0B0C0D0E0F")).expect("key");
        let nonce = decode_hex("BBAA99887766554433221103");
        let aad = [];
        let mut pt = decode_hex("0001020304050607");
        let expected = decode_hex("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9");

        let ocb = Ocb::<_, 16>::new(Aes128::new(&key));
        let tag = ocb.encrypt(&nonce, &aad, &mut pt);
        let mut out = pt.clone();
        out.extend_from_slice(&tag);
        assert_eq!(out, expected);
    }

    /// RFC 7253 §4.2: `Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N`.
    #[test]
    fn nonce_block_carries_taglen_mod_128() {
        let nonce: Vec<u8> = (1..=12).collect();
        // A 96-bit N: seven TAGLEN bits, 24 zero bits, then the 1 bit.
        for (taglen, first_byte) in [(128, 0x00), (96, 0xC0), (64, 0x80)] {
            let mut expected = [0u8; 16];
            expected[0] = first_byte;
            expected[3] = 0x01;
            expected[4..].copy_from_slice(&nonce);
            assert_eq!(
                nonce_block_from_bytes(taglen, &nonce),
                expected,
                "TAGLEN {taglen}"
            );
        }
        // A 120-bit N leaves no zero padding: the 1 bit is the eighth bit.
        let long = [0xA5u8; 15];
        let block = nonce_block_from_bytes(64, &long);
        assert_eq!(block[0], 0x81);
        assert_eq!(block[1..], long);
    }

    fn seal<const TAG_LEN: usize>(
        ocb: &Ocb<Aes128, TAG_LEN>,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; TAG_LEN]) {
        let mut data = plaintext.to_vec();
        let tag = ocb.encrypt(nonce, aad, &mut data);
        (data, tag)
    }

    /// TAGLEN enters the nonce block, so a shorter tag is not a prefix of a
    /// longer one and the ciphertext body changes with the tag length too.
    #[test]
    fn tag_length_is_not_a_truncation() {
        let key = [0x42u8; 16];
        let (nonce, aad, plaintext) = ([0x24u8; 12], b"header", [0x5Au8; 40]);
        let (c16, t16) = seal(
            &Ocb::<_, 16>::new(Aes128::new(&key)),
            &nonce,
            aad,
            &plaintext,
        );
        let (c12, t12) = seal(
            &Ocb::<_, 12>::new(Aes128::new(&key)),
            &nonce,
            aad,
            &plaintext,
        );
        let (c8, t8) = seal(
            &Ocb::<_, 8>::new(Aes128::new(&key)),
            &nonce,
            aad,
            &plaintext,
        );
        assert_ne!(c16, c12);
        assert_ne!(c16, c8);
        assert_ne!(c12, c8);
        assert_ne!(t16[..12], t12[..]);
        assert_ne!(t16[..8], t8[..]);
        assert_ne!(t12[..8], t8[..]);
    }

    /// A `TAG_LEN`-byte mode round-trips, and refuses a tag altered in any
    /// byte, an altered ciphertext, and altered associated data, leaving the
    /// buffer untouched each time.
    fn check_authentication<const TAG_LEN: usize>() {
        let ocb = Ocb::<_, TAG_LEN>::new(Aes128::new(&[0x11u8; 16]));
        assert_eq!(ocb.tag_len(), TAG_LEN);
        let (nonce, aad) = ([0x22u8; 12], b"aad");
        let plaintext = b"an OCB message spanning two blocks and a partial".to_vec();
        let (ciphertext, tag) = seal(&ocb, &nonce, aad, &plaintext);

        for i in 0..TAG_LEN {
            let mut forged = tag;
            forged[i] ^= 0x01;
            let mut data = ciphertext.clone();
            assert!(
                !ocb.decrypt(&nonce, aad, &mut data, &forged),
                "TAG_LEN {TAG_LEN}: tag byte {i} altered"
            );
            assert_eq!(data, ciphertext);
        }

        let mut altered = ciphertext.clone();
        altered[0] ^= 0x80;
        let mut data = altered.clone();
        assert!(!ocb.decrypt(&nonce, aad, &mut data, &tag));
        assert_eq!(data, altered);

        let mut data = ciphertext.clone();
        assert!(!ocb.decrypt(&nonce, b"aae", &mut data, &tag));
        assert_eq!(data, ciphertext);

        let mut data = ciphertext;
        assert!(ocb.decrypt(&nonce, aad, &mut data, &tag));
        assert_eq!(data, plaintext);
    }

    #[test]
    fn taglen_128_authenticates() {
        check_authentication::<16>();
    }

    #[test]
    fn taglen_96_authenticates() {
        check_authentication::<12>();
    }

    #[test]
    fn taglen_64_authenticates() {
        check_authentication::<8>();
    }
}
