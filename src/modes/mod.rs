//! Generic block-cipher modes of operation.
//!
//! Implemented in this layer:
//!
//! - SP 800-38A confidentiality modes: ECB, CBC, CFB (full-block), CFB8, OFB, CTR
//! - SP 800-38B authentication mode: CMAC
//! - SP 800-38C authenticated mode: CCM
//! - SP 800-38D authenticated mode: GCM / GMAC
//! - SP 800-38E storage mode: XTS (128-bit block ciphers only)
//! - RFC 3394 / SP 800-38F key wrap mode: AES Key Wrap (no padding)
//! - EAX authenticated mode
//! - OCB3 authenticated mode (RFC 7253)
//! - AES-GCM-SIV misuse-resistant mode (RFC 8452), generic over the AES
//!   implementation (T-table or constant-time)
//! - RFC 5297 misuse-resistant mode: SIV
//! - RFC 8439 AEAD: ChaCha20-Poly1305
//!
//! These adapters are generic over any `BlockCipher` in the crate, so the same
//! wrapper works with AES, DES, Camellia, PRESENT, and the other block
//! primitives exposed here.
//!
//! The point of this layer is to separate primitive choice from mode choice:
//! one block cipher implementation can be dropped into several standardized
//! operating modes without duplicating the mode logic in every cipher module.

use crate::BlockCipher;
use ghash::{HashSubkey, SubkeyTable, VariableTimeSubkey};

pub mod chacha20_poly1305;
pub mod eax;
pub mod gcm_siv;
mod ghash;
pub mod ocb;
pub mod poly1305;
pub mod siv;
pub use chacha20_poly1305::ChaCha20Poly1305;
pub use eax::Eax;
pub use gcm_siv::{
    Aes128GcmSiv, Aes128GcmSivCt, Aes256GcmSiv, Aes256GcmSivCt, AesGcmSiv, GcmSivBlockCipher,
};
pub use ocb::Ocb;
pub use poly1305::Poly1305;
pub use siv::Siv;

#[inline]
fn assert_block_multiple<C: BlockCipher>(buf: &[u8]) {
    assert_eq!(
        buf.len() % C::BLOCK_LEN,
        0,
        "buffer length must be a multiple of the block length"
    );
}

#[inline]
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Wipe a single `u128` local the same way a slice is wiped: GHASH keeps the
/// hash subkey `H` and the counter blocks as scalars, and those are key
/// material just as much as a round-key array is.
#[inline]
fn wipe_u128(value: &mut u128) {
    crate::ct::zeroize_slice(core::slice::from_mut(value));
}

#[inline]
fn increment_be(counter: &mut [u8]) {
    // CTR-style modes treat the IV/counter block as a single big-endian
    // integer so incrementing from the tail matches the NIST block-mode
    // specifications.
    for b in counter.iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

#[inline]
fn rb_for(block_len: usize) -> u8 {
    match block_len {
        8 => 0x1b,
        16 => 0x87,
        _ => panic!("CMAC only supports 64-bit or 128-bit block ciphers"),
    }
}

/// Double a big-endian value in GF(2^n) (`n = 8 * block.len()`) into `out`:
/// shift left one bit and, on overflow, fold in the block size's reduction
/// constant `Rb`. This is the CMAC subkey step; EAX and SIV reach it through
/// [`Cmac`]. The carry fold is branch-free so it does not condition on the
/// (secret) top bit, and the result lands in a caller-owned buffer so no
/// key-derived temporary is allocated.
fn dbl_into(block: &[u8], out: &mut [u8]) {
    debug_assert_eq!(block.len(), out.len());
    let mut carry = 0u8;
    for (o, &b) in out.iter_mut().rev().zip(block.iter().rev()) {
        *o = (b << 1) | carry;
        carry = b >> 7;
    }
    let mask = 0u8.wrapping_sub(carry);
    let last = out.len() - 1;
    out[last] ^= rb_for(block.len()) & mask;
}

/// The fixed-size 16-byte twin of [`dbl_into`]: double in GF(2^128) with the constant
/// reduction polynomial `0x87`. Used by the 128-bit-only SIV and OCB offsets.
fn dbl_block(block: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    let mask = 0u8.wrapping_sub(carry);
    out[15] ^= 0x87 & mask;
    out
}

#[inline]
fn assert_block_128<C: BlockCipher>() {
    assert_eq!(
        C::BLOCK_LEN,
        16,
        "this mode requires a 128-bit block cipher"
    );
}

#[inline]
fn xor_block16_in_place(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

#[inline]
fn increment_be32(counter: &mut [u8; 16]) {
    // GCM's fast path reserves the low 32 bits of the pre-counter block as the
    // incremented invocation field, so only the final four bytes advance here.
    for b in counter[12..].iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

const GCM_MAX_COUNTER_BLOCKS: u64 = (u32::MAX as u64) - 1;
const GCM_MAX_PAYLOAD_BYTES: u64 = GCM_MAX_COUNTER_BLOCKS * 16;

#[inline]
fn gcm_payload_len_allowed_u64(len_bytes: u64) -> bool {
    // SP 800-38D bounds GCTR to at most 2^32 - 2 block invocations per key/nonce.
    len_bytes.saturating_add(15) / 16 <= GCM_MAX_COUNTER_BLOCKS
}

#[inline]
fn gcm_payload_len_allowed(len_bytes: usize) -> bool {
    gcm_payload_len_allowed_u64(u64::try_from(len_bytes).unwrap_or(u64::MAX))
}

#[inline]
fn assert_gcm_payload_len(len_bytes: usize) {
    assert!(
        gcm_payload_len_allowed(len_bytes),
        "GCM payload too large: max {} bytes per key/nonce",
        GCM_MAX_PAYLOAD_BYTES
    );
}

/// SP 800-38D §5.2.1.1 bounds the AAD and the IV at `2^64 − 1` bits each, and
/// GHASH's length block (§6.4) carries the AAD length as a 64-bit bit count:
/// a byte length above `2^61 − 1` has no representation there.
#[inline]
fn gcm_bit_length_representable(len_bytes: usize) -> bool {
    u64::try_from(len_bytes).is_ok_and(|len| len <= u64::MAX >> 3)
}

#[inline]
fn assert_gcm_aad_and_iv_len(aad: &[u8], iv: &[u8]) {
    assert!(
        gcm_bit_length_representable(aad.len()),
        "GCM AAD too large: its bit length must fit 64 bits (SP 800-38D 5.2.1.1)"
    );
    assert!(
        gcm_bit_length_representable(iv.len()),
        "GCM IV too large: its bit length must fit 64 bits (SP 800-38D 5.2.1.1)"
    );
}

#[inline]
fn gf_mul_x_xts(tweak: &mut [u8; 16]) {
    // SP 800-38E treats tweaks as elements of GF(2^128) encoded little-endian.
    // Multiplication by x is a one-bit left shift across bytes; when a carry
    // leaves the top bit, reduce by x^128 + x^7 + x^2 + x + 1, which is `0x87`
    // in this byte order, so the xor lands in `tweak[0]`.
    let mut carry = 0u8;
    for b in tweak.iter_mut() {
        let next = *b >> 7;
        *b = (*b << 1) | carry;
        carry = next;
    }
    // Branch-free reduction: `mask` is 0xFF iff a carry left the top bit.
    let mask = 0u8.wrapping_sub(carry);
    tweak[0] ^= 0x87 & mask;
}

#[inline]
fn xex_encrypt_block<C: BlockCipher>(cipher: &C, tweak: &[u8; 16], block: &mut [u8; 16]) {
    xor_block16_in_place(block, tweak);
    cipher.encrypt(block);
    xor_block16_in_place(block, tweak);
}

#[inline]
fn xex_decrypt_block<C: BlockCipher>(cipher: &C, tweak: &[u8; 16], block: &mut [u8; 16]) {
    xor_block16_in_place(block, tweak);
    cipher.decrypt(block);
    xor_block16_in_place(block, tweak);
}

/// SP 800-38D §6.4 GHASH steps 1 and 3 over `data`, zero-padded to whole
/// blocks, continuing from the running value `y`.
fn ghash_update<K: HashSubkey>(y: &mut u128, key: &K, data: &[u8]) {
    let mut block = [0u8; 16];
    for chunk in data.chunks(16) {
        block.fill(0);
        block[..chunk.len()].copy_from_slice(chunk);
        *y ^= u128::from_be_bytes(block);
        *y = key.multiply(*y);
    }
}

fn ghash<K: HashSubkey>(key: &K, aad: &[u8], ciphertext: &[u8]) -> u128 {
    debug_assert!(gcm_bit_length_representable(aad.len()));
    debug_assert!(gcm_bit_length_representable(ciphertext.len()));
    let mut y = 0u128;
    ghash_update(&mut y, key, aad);
    ghash_update(&mut y, key, ciphertext);

    let mut len_block = [0u8; 16];
    // SP 800-38D GHASH appends bit lengths, not byte lengths.
    len_block[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) << 3).to_be_bytes());
    y ^= u128::from_be_bytes(len_block);
    key.multiply(y)
}

#[inline]
fn ghash_iv<K: HashSubkey>(key: &K, iv: &[u8]) -> [u8; 16] {
    // SP 800-38D requires 1 ≤ len(IV). An empty IV would take the GHASH path
    // below and reduce to J0 = 0^128 for every key, silently reusing the same
    // counter sequence and tag mask across all empty-IV messages under a key.
    // Reject it rather than emit an insecure, nonce-independent keystream.
    assert!(!iv.is_empty(), "GCM IV must be non-empty (SP 800-38D)");
    // SP 800-38D §7.1 fast path: for 96-bit IVs, J0 = IV || 0^31 || 1.
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        return j0;
    }
    // Non-96-bit IVs are GHASHed with the standard length block.
    ghash(key, &[], iv).to_be_bytes()
}

#[inline]
fn gcm_hash_subkey<C: BlockCipher>(cipher: &C) -> u128 {
    // GCM hash subkey H = E_K(0^128) per SP 800-38D.
    let mut h = [0u8; 16];
    cipher.encrypt(&mut h);
    let subkey = u128::from_be_bytes(h);
    crate::ct::zeroize_slice(h.as_mut_slice());
    subkey
}

#[inline]
fn counter_keystream<C: BlockCipher>(cipher: &C, counter: &[u8; 16]) -> [u8; 16] {
    let mut out = *counter;
    cipher.encrypt(&mut out);
    out
}

/// GCTR (SP 800-38D §6.5) over `data`, starting from `inc32(J0)`.
///
/// The counter and keystream blocks are wiped before returning: the keystream
/// is what turns the ciphertext back into plaintext.
fn gcm_ctr<C: BlockCipher>(cipher: &C, j0: &[u8; 16], data: &mut [u8]) {
    let mut counter = *j0;
    increment_be32(&mut counter);
    let mut stream = [0u8; 16];
    for chunk in data.chunks_mut(16) {
        stream = counter;
        cipher.encrypt(&mut stream);
        xor_in_place(chunk, &stream[..chunk.len()]);
        increment_be32(&mut counter);
    }
    crate::ct::zeroize_slice(stream.as_mut_slice());
    crate::ct::zeroize_slice(counter.as_mut_slice());
}

/// The GCM tag `GHASH_H(A, C) xor E_K(J0)` from an already derived `H`/`J0`.
///
/// The GHASH output `S` and the mask `E_K(J0)` are wiped before returning:
/// either one plus the public tag gives the other, and `S` over known data is
/// a polynomial in `H` whose roots an attacker can find.
fn gcm_tag<C: BlockCipher, K: HashSubkey>(
    cipher: &C,
    key: &K,
    j0: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut s = ghash(key, aad, ciphertext);
    let mut mask_block = counter_keystream(cipher, j0);
    let mut tag_mask = u128::from_be_bytes(mask_block);
    let tag = (s ^ tag_mask).to_be_bytes();
    wipe_u128(&mut s);
    wipe_u128(&mut tag_mask);
    crate::ct::zeroize_slice(mask_block.as_mut_slice());
    tag
}

/// The hash subkey `H = E_K(0^128)` prepared for GHASH as `K`. The raw subkey
/// is wiped here; the prepared form wipes itself on drop.
fn gcm_hash_key<C: BlockCipher, K: HashSubkey>(cipher: &C) -> K {
    let mut h = gcm_hash_subkey(cipher);
    let key = K::new(h);
    wipe_u128(&mut h);
    key
}

fn gcm_compute_tag<C: BlockCipher, K: HashSubkey>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    assert_block_128::<C>();
    assert_gcm_payload_len(ciphertext.len());
    assert_gcm_aad_and_iv_len(aad, nonce);
    let key: K = gcm_hash_key(cipher);
    // J0 is public for a 96-bit IV but is GHASH_H(IV) otherwise.
    let mut j0 = ghash_iv(&key, nonce);
    let tag = gcm_tag(cipher, &key, &j0, aad, ciphertext);
    crate::ct::zeroize_slice(j0.as_mut_slice());
    tag
}

/// Shared body of `Gcm::encrypt` and `GcmVt::encrypt`.
fn gcm_encrypt<C: BlockCipher, K: HashSubkey>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; 16] {
    assert_block_128::<C>();
    assert_gcm_payload_len(data.len());
    assert_gcm_aad_and_iv_len(aad, nonce);
    let key: K = gcm_hash_key(cipher);
    let mut j0 = ghash_iv(&key, nonce);
    gcm_ctr(cipher, &j0, data);
    let tag = gcm_tag(cipher, &key, &j0, aad, data);
    crate::ct::zeroize_slice(j0.as_mut_slice());
    tag
}

/// Shared body of `Gcm::decrypt` and `GcmVt::decrypt`: authenticate the
/// ciphertext, then decrypt in place only if the tag matched.
///
/// A ciphertext, AAD or IV longer than SP 800-38D allows is refused with
/// `false` rather than a panic: no valid GCM output has that shape, and the
/// lengths on this path are the sender's to choose.
fn gcm_decrypt<C: BlockCipher, K: HashSubkey>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> bool {
    assert_block_128::<C>();
    if !gcm_payload_len_allowed(data.len())
        || !gcm_bit_length_representable(aad.len())
        || !gcm_bit_length_representable(nonce.len())
    {
        return false;
    }
    let key: K = gcm_hash_key(cipher);
    let mut j0 = ghash_iv(&key, nonce);
    // The genuine tag for attacker-chosen ciphertext is a forgery if it
    // leaks, so it is wiped whether or not verification succeeds.
    let mut expected = gcm_tag(cipher, &key, &j0, aad, data);
    let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
    if authentic {
        gcm_ctr(cipher, &j0, data);
    }
    crate::ct::zeroize_slice(expected.as_mut_slice());
    crate::ct::zeroize_slice(j0.as_mut_slice());
    authentic
}

#[inline]
fn ccm_l_from_nonce(nonce: &[u8]) -> usize {
    assert!(
        (7..=13).contains(&nonce.len()),
        "CCM nonce length must be in 7..=13 bytes"
    );
    15 - nonce.len()
}

#[inline]
fn assert_ccm_tag_len(tag_len: usize) {
    assert!(
        (4..=16).contains(&tag_len) && tag_len.is_multiple_of(2),
        "CCM tag length must be one of {{4,6,8,10,12,14,16}}"
    );
}

#[inline]
fn ccm_pack_len(block: &mut [u8; 16], l: usize, value: u64) {
    let needed_bits = l * 8;
    assert!(
        needed_bits >= 64 || value < (1u64 << needed_bits),
        "CCM length/counter does not fit in L bytes"
    );
    for i in 0..l {
        block[15 - i] = u8::try_from((value >> (8 * i)) & 0xff).expect("single byte");
    }
}

#[inline]
fn ccm_b0(nonce: &[u8], msg_len: usize, aad_len: usize, tag_len: usize) -> [u8; 16] {
    let l = ccm_l_from_nonce(nonce);
    assert_ccm_tag_len(tag_len);
    let msg_len_u64 = u64::try_from(msg_len).expect("message length fits u64");

    let mut b0 = [0u8; 16];
    let aad_flag = u8::from(aad_len != 0) << 6;
    let t_field = u8::try_from((tag_len - 2) / 2).expect("CCM tag field fits u8") << 3;
    let l_field = u8::try_from(l - 1).expect("CCM L field fits u8");
    b0[0] = aad_flag | t_field | l_field;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    ccm_pack_len(&mut b0, l, msg_len_u64);
    b0
}

#[inline]
fn ccm_counter_block(nonce: &[u8], counter: u64) -> [u8; 16] {
    let l = ccm_l_from_nonce(nonce);
    let mut ctr = [0u8; 16];
    ctr[0] = u8::try_from(l - 1).expect("CCM L field fits u8");
    ctr[1..1 + nonce.len()].copy_from_slice(nonce);
    ccm_pack_len(&mut ctr, l, counter);
    ctr
}

fn ccm_encode_aad(aad: &[u8]) -> Vec<u8> {
    if aad.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(aad.len() + 16);
    let aad_len = aad.len() as u64;
    if aad_len < ((1u64 << 16) - (1u64 << 8)) {
        out.extend_from_slice(
            &u16::try_from(aad_len)
                .expect("length range checked")
                .to_be_bytes(),
        );
    } else if aad_len < (1u64 << 32) {
        out.extend_from_slice(&[0xff, 0xfe]);
        out.extend_from_slice(&(aad_len as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&[0xff, 0xff]);
        out.extend_from_slice(&aad_len.to_be_bytes());
    }
    out.extend_from_slice(aad);
    if !out.len().is_multiple_of(16) {
        out.resize(out.len().next_multiple_of(16), 0);
    }
    out
}

fn ccm_cbc_mac<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> [u8; 16] {
    assert_block_128::<C>();
    let mut y = [0u8; 16];

    let b0 = ccm_b0(nonce, plaintext.len(), aad.len(), tag_len);
    xor_block16_in_place(&mut y, &b0);
    cipher.encrypt(&mut y);

    let aad_encoded = ccm_encode_aad(aad);
    let mut block = [0u8; 16];
    for chunk in aad_encoded.chunks(16) {
        block.copy_from_slice(chunk);
        xor_block16_in_place(&mut y, &block);
        cipher.encrypt(&mut y);
    }

    // CBC-MAC runs over the plaintext, which on the decrypt path is not yet
    // authenticated: the block buffer is wiped once the chain is done.
    for chunk in plaintext.chunks(16) {
        block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        xor_block16_in_place(&mut y, &block);
        cipher.encrypt(&mut y);
    }
    crate::ct::zeroize_slice(block.as_mut_slice());

    y
}

fn ccm_apply_ctr<C: BlockCipher>(cipher: &C, nonce: &[u8], data: &mut [u8]) {
    let mut stream = [0u8; 16];
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        stream = ccm_counter_block(nonce, u64::try_from(i + 1).expect("counter fits u64"));
        cipher.encrypt(&mut stream);
        xor_in_place(chunk, &stream[..chunk.len()]);
    }
    crate::ct::zeroize_slice(stream.as_mut_slice());
}

const AES_KEY_WRAP_DEFAULT_IV: [u8; 8] = [0xA6; 8];

#[inline]
fn xor_aes_kw_t(a: &mut [u8; 8], t: u64) {
    let t_be = t.to_be_bytes();
    for i in 0..8 {
        a[i] ^= t_be[i];
    }
}

/// AES Key Wrap (RFC 3394) over 64-bit semiblocks with the default IV.
///
/// This is the no-padding variant standardized in RFC 3394 and SP 800-38F.
/// Inputs must be a multiple of 8 bytes and at least 16 bytes long.
pub struct AesKeyWrap<C> {
    cipher: C,
}

impl<C> AesKeyWrap<C> {
    /// Wrap an AES cipher instance for RFC 3394 key wrap operations.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped AES cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> AesKeyWrap<C> {
    /// Wrap key material with the RFC 3394 default IV (`A6A6A6A6A6A6A6A6`).
    ///
    /// Returns `None` when `key_data` is not a multiple of 8 bytes or is
    /// shorter than 16 bytes.
    pub fn wrap_key(&self, key_data: &[u8]) -> Option<Vec<u8>> {
        self.wrap_key_with_iv(key_data, &AES_KEY_WRAP_DEFAULT_IV)
    }

    /// Wrap key material with an explicit 64-bit initial register value.
    ///
    /// Returns `None` when `key_data` is not a multiple of 8 bytes or is
    /// shorter than 16 bytes.
    pub fn wrap_key_with_iv(&self, key_data: &[u8], iv: &[u8; 8]) -> Option<Vec<u8>> {
        assert_block_128::<C>();
        if !key_data.len().is_multiple_of(8) || key_data.len() < 16 {
            return None;
        }

        let n = key_data.len() / 8;
        // The register chain runs directly inside the output buffer: byte 0..8
        // is A, and the semiblocks R[1..=n] follow it. Working in place means
        // the plaintext key material exists in exactly one heap buffer, the
        // one that becomes ciphertext, instead of a second `Vec` of semiblocks
        // that would be freed still holding the key.
        let mut wrapped = vec![0u8; (n + 1) * 8];
        wrapped[..8].copy_from_slice(iv);
        wrapped[8..].copy_from_slice(key_data);

        let mut b = [0u8; 16];
        for j in 0..6usize {
            for i in 0..n {
                let (a, rest) = wrapped.split_at_mut(8);
                let ri = &mut rest[i * 8..i * 8 + 8];
                b[..8].copy_from_slice(a);
                b[8..].copy_from_slice(ri);
                self.cipher.encrypt(&mut b);

                a.copy_from_slice(&b[..8]);
                let t =
                    u64::try_from(j * n + i + 1).expect("AES-KW step index must fit in 64 bits");
                xor_aes_kw_t(a.try_into().expect("A is eight bytes"), t);
                ri.copy_from_slice(&b[8..]);
            }
        }
        // Every cipher input `A || R[i]` of the chain passed through `b`; the
        // final contents are public ciphertext, but the wipe keeps the block
        // from being the one temporary on this path that is left to chance.
        crate::ct::zeroize_slice(b.as_mut_slice());
        Some(wrapped)
    }

    /// Unwrap RFC 3394 key material and verify the default IV integrity check.
    ///
    /// Returns `None` when input length is invalid or the integrity check
    /// fails.
    pub fn unwrap_key(&self, wrapped: &[u8]) -> Option<Vec<u8>> {
        self.unwrap_key_with_iv(wrapped, &AES_KEY_WRAP_DEFAULT_IV)
    }

    /// Unwrap RFC 3394 key material and verify against an explicit IV value.
    ///
    /// Returns `None` when input length is invalid or the integrity check
    /// fails.
    pub fn unwrap_key_with_iv(&self, wrapped: &[u8], iv: &[u8; 8]) -> Option<Vec<u8>> {
        assert_block_128::<C>();
        if !wrapped.len().is_multiple_of(8) || wrapped.len() < 24 {
            return None;
        }

        let mut key_data = vec![0u8; wrapped.len() - 8];
        if self.unwrap_into(wrapped, iv, &mut key_data) {
            Some(key_data)
        } else {
            None
        }
    }

    /// RFC 3394 §2.2.2 unwrap of `wrapped` into `out`, which must be
    /// `wrapped.len() - 8` bytes long; returns whether the integrity check
    /// against `iv` passed.
    ///
    /// The semiblocks are recovered in place inside `out`, so the key exists
    /// in the caller's buffer only. On an integrity failure `out` is wiped
    /// before `false` is returned: the speculative key of a rejected unwrap
    /// must not survive it.
    fn unwrap_into(&self, wrapped: &[u8], iv: &[u8; 8], out: &mut [u8]) -> bool {
        debug_assert_eq!(out.len() + 8, wrapped.len());
        let n = out.len() / 8;
        let mut a = [0u8; 8];
        a.copy_from_slice(&wrapped[..8]);
        out.copy_from_slice(&wrapped[8..]);

        let mut b = [0u8; 16];
        for j in (0..6usize).rev() {
            for i in (0..n).rev() {
                let t =
                    u64::try_from(j * n + i + 1).expect("AES-KW step index must fit in 64 bits");
                b[..8].copy_from_slice(&a);
                xor_aes_kw_t((&mut b[..8]).try_into().expect("A is eight bytes"), t);
                b[8..].copy_from_slice(&out[i * 8..i * 8 + 8]);
                self.cipher.decrypt(&mut b);

                a.copy_from_slice(&b[..8]);
                out[i * 8..i * 8 + 8].copy_from_slice(&b[8..]);
            }
        }
        // `b` holds the last decrypted `A || R[1]`: plaintext key material.
        crate::ct::zeroize_slice(b.as_mut_slice());

        let authentic = crate::ct::constant_time_eq_mask(&a, iv) == u8::MAX;
        if !authentic {
            crate::ct::zeroize_slice(out);
        }
        authentic
    }
}

/// Electronic Codebook (ECB) mode.
///
/// This is included because SP 800-38A defines it, but it should only be used
/// for single-block operations or controlled test vectors. It leaks repeated
/// plaintext patterns.
pub struct Ecb<C> {
    cipher: C,
}

impl<C> Ecb<C> {
    /// Wrap a block cipher in SP 800-38A ECB mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ecb<C> {
    /// Encrypt block-aligned data in place without padding.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not an exact multiple of the block size.
    pub fn encrypt_nopad(&self, data: &mut [u8]) {
        assert_block_multiple::<C>(data);
        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            self.cipher.encrypt(block);
        }
    }

    /// Decrypt block-aligned data in place without padding.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not an exact multiple of the block size.
    pub fn decrypt_nopad(&self, data: &mut [u8]) {
        assert_block_multiple::<C>(data);
        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            self.cipher.decrypt(block);
        }
    }
}

/// Cipher Block Chaining (CBC) mode.
pub struct Cbc<C> {
    cipher: C,
}

impl<C> Cbc<C> {
    /// Wrap a block cipher in SP 800-38A CBC mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Cbc<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn encrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut prev = iv.to_vec();
        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            xor_in_place(block, &prev);
            self.cipher.encrypt(block);
            prev.copy_from_slice(block);
        }
    }

    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn decrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut prev = iv.to_vec();
        let mut tmp = vec![0u8; C::BLOCK_LEN];

        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            tmp.copy_from_slice(block);
            self.cipher.decrypt(block);
            xor_in_place(block, &prev);
            prev.copy_from_slice(&tmp);
        }
    }
}

/// Cipher Feedback (CFB) mode with a segment size equal to the full block.
pub struct Cfb<C> {
    cipher: C,
}

impl<C> Cfb<C> {
    /// Wrap a block cipher in SP 800-38A CFB mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Cfb<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn encrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut feedback = iv.to_vec();
        let mut keystream = feedback.clone();

        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            keystream.copy_from_slice(&feedback);
            self.cipher.encrypt(&mut keystream);
            xor_in_place(block, &keystream);
            feedback.copy_from_slice(block);
        }
        // The last keystream block XORs a ciphertext block back to plaintext.
        crate::ct::zeroize_slice(keystream.as_mut_slice());
    }

    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size, or if `data.len()`
    /// is not an exact multiple of the block size.
    pub fn decrypt_nopad(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        assert_block_multiple::<C>(data);

        let mut feedback = iv.to_vec();
        let mut keystream = feedback.clone();
        let mut tmp = vec![0u8; C::BLOCK_LEN];

        for block in data.chunks_exact_mut(C::BLOCK_LEN) {
            tmp.copy_from_slice(block);
            keystream.copy_from_slice(&feedback);
            self.cipher.encrypt(&mut keystream);
            xor_in_place(block, &keystream);
            feedback.copy_from_slice(&tmp);
        }
        // `feedback`/`tmp` only ever hold ciphertext; the keystream is what
        // turns it back into plaintext.
        crate::ct::zeroize_slice(keystream.as_mut_slice());
    }
}

/// Cipher Feedback (CFB) mode with an 8-bit segment size (CFB8).
pub struct Cfb8<C> {
    cipher: C,
}

impl<C> Cfb8<C> {
    /// Wrap a block cipher in CFB8 mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Cfb8<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size.
    pub fn encrypt(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        let mut state = iv.to_vec();
        let mut stream = vec![0u8; C::BLOCK_LEN];

        for byte in data.iter_mut() {
            stream.copy_from_slice(&state);
            self.cipher.encrypt(&mut stream);
            let ct = *byte ^ stream[0];
            state.rotate_left(1);
            state[C::BLOCK_LEN - 1] = ct;
            *byte = ct;
        }
        crate::ct::zeroize_slice(stream.as_mut_slice());
    }

    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size.
    pub fn decrypt(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");
        let mut state = iv.to_vec();
        let mut stream = vec![0u8; C::BLOCK_LEN];

        for byte in data.iter_mut() {
            let ct = *byte;
            stream.copy_from_slice(&state);
            self.cipher.encrypt(&mut stream);
            *byte = ct ^ stream[0];
            state.rotate_left(1);
            state[C::BLOCK_LEN - 1] = ct;
        }
        crate::ct::zeroize_slice(stream.as_mut_slice());
    }
}

/// Output Feedback (OFB) mode.
pub struct Ofb<C> {
    cipher: C,
}

impl<C> Ofb<C> {
    /// Wrap a block cipher in SP 800-38A OFB mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ofb<C> {
    /// # Panics
    ///
    /// Panics if `iv.len()` does not match the block size.
    pub fn apply_keystream(&self, iv: &[u8], data: &mut [u8]) {
        assert_eq!(iv.len(), C::BLOCK_LEN, "wrong IV length");

        let mut feedback = iv.to_vec();
        for chunk in data.chunks_mut(C::BLOCK_LEN) {
            self.cipher.encrypt(&mut feedback);
            xor_in_place(chunk, &feedback[..chunk.len()]);
        }
        // In OFB the feedback register *is* the keystream.
        crate::ct::zeroize_slice(feedback.as_mut_slice());
    }
}

/// Counter (CTR) mode with a big-endian incrementing counter block.
pub struct Ctr<C> {
    cipher: C,
}

impl<C> Ctr<C> {
    /// Wrap a block cipher in SP 800-38A CTR mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Ctr<C> {
    /// # Panics
    ///
    /// Panics if `counter.len()` does not match the block size.
    pub fn apply_keystream(&self, counter: &[u8], data: &mut [u8]) {
        assert_eq!(counter.len(), C::BLOCK_LEN, "wrong counter length");

        let mut ctr = counter.to_vec();
        let mut stream = ctr.clone();

        for chunk in data.chunks_mut(C::BLOCK_LEN) {
            stream.copy_from_slice(&ctr);
            self.cipher.encrypt(&mut stream);
            xor_in_place(chunk, &stream[..chunk.len()]);
            increment_be(&mut ctr);
        }
        crate::ct::zeroize_slice(stream.as_mut_slice());
    }
}

/// The longest data unit SP 800-38E permits, in blocks: `2^20`.
///
/// SP 800-38E §4: "The length of the data unit for any instance of an
/// implementation of XTS-AES shall not exceed 2^20 AES blocks."
pub const XTS_MAX_DATA_UNIT_BLOCKS: usize = 1 << 20;

#[inline]
fn xts_data_unit_len_allowed(len_bytes: usize) -> bool {
    len_bytes <= XTS_MAX_DATA_UNIT_BLOCKS * 16
}

#[inline]
fn assert_xts_data_unit_len(len_bytes: usize) {
    assert!(
        len_bytes >= 16,
        "XTS requires at least one complete block in each data unit"
    );
    assert!(
        xts_data_unit_len_allowed(len_bytes),
        "XTS data unit too long: at most {XTS_MAX_DATA_UNIT_BLOCKS} blocks (SP 800-38E section 4)"
    );
}

/// XEX-based Tweaked `CodeBook` mode with ciphertext Stealing (XTS).
///
/// This implementation supports 128-bit block ciphers, which is the case
/// covered by SP 800-38E / XTS-AES.
///
/// # Data unit length
///
/// A data unit is at least one block and, per SP 800-38E §4, at most
/// [`XTS_MAX_DATA_UNIT_BLOCKS`] (`2^20`) blocks, 16 MiB. Both sector
/// operations panic outside that range, before touching the buffer.
pub struct Xts<C> {
    data_cipher: C,
    tweak_cipher: C,
}

impl<C> Xts<C> {
    /// Wrap a pair of block ciphers in SP 800-38E XTS mode.
    ///
    /// `data_cipher` encrypts the sector payload blocks. `tweak_cipher`
    /// derives the per-sector tweak stream from the caller-supplied tweak.
    pub fn new(data_cipher: C, tweak_cipher: C) -> Self {
        Self {
            data_cipher,
            tweak_cipher,
        }
    }

    /// Borrow the data-encryption cipher.
    pub fn data_cipher(&self) -> &C {
        &self.data_cipher
    }

    /// Borrow the tweak-derivation cipher.
    pub fn tweak_cipher(&self) -> &C {
        &self.tweak_cipher
    }
}

impl<C: BlockCipher> Xts<C> {
    /// # Panics
    ///
    /// Panics if the wrapped cipher does not have a 128-bit block size, if
    /// `data` is shorter than one complete block, or if it is longer than
    /// [`XTS_MAX_DATA_UNIT_BLOCKS`] blocks (SP 800-38E §4).
    pub fn encrypt_sector(&self, tweak_value: &[u8; 16], data: &mut [u8]) {
        assert_block_128::<C>();
        assert_xts_data_unit_len(data.len());

        let full_blocks = data.len() / 16;
        let rem = data.len() % 16;

        // `tweak` is the key-derived XEX mask `E_K2(i)·α^j` and `tmp` carries
        // each block through the cipher; both are wiped before returning.
        let mut tweak = *tweak_value;
        self.tweak_cipher.encrypt(&mut tweak);
        let mut tmp = [0u8; 16];

        let whole_blocks = if rem == 0 {
            full_blocks
        } else {
            full_blocks - 1
        };
        for block in data[..whole_blocks * 16].chunks_exact_mut(16) {
            tmp.copy_from_slice(block);
            xex_encrypt_block(&self.data_cipher, &tweak, &mut tmp);
            block.copy_from_slice(&tmp);
            gf_mul_x_xts(&mut tweak);
        }

        if rem != 0 {
            // Ciphertext stealing over the last full block and the tail.
            let last_full_start = whole_blocks * 16;
            let mut cc = [0u8; 16];
            cc.copy_from_slice(&data[last_full_start..last_full_start + 16]);
            xex_encrypt_block(&self.data_cipher, &tweak, &mut cc);

            // `tmp` becomes PP: the plaintext tail padded with CC's tail.
            tmp[..rem].copy_from_slice(&data[last_full_start + 16..]);
            tmp[rem..].copy_from_slice(&cc[rem..]);
            data[last_full_start + 16..].copy_from_slice(&cc[..rem]);

            gf_mul_x_xts(&mut tweak);
            xex_encrypt_block(&self.data_cipher, &tweak, &mut tmp);
            data[last_full_start..last_full_start + 16].copy_from_slice(&tmp);
            crate::ct::zeroize_slice(cc.as_mut_slice());
        }
        crate::ct::zeroize_slice(tmp.as_mut_slice());
        crate::ct::zeroize_slice(tweak.as_mut_slice());
    }

    /// # Panics
    ///
    /// Panics if the wrapped cipher does not have a 128-bit block size, if
    /// `data` is shorter than one complete block, or if it is longer than
    /// [`XTS_MAX_DATA_UNIT_BLOCKS`] blocks (SP 800-38E §4).
    pub fn decrypt_sector(&self, tweak_value: &[u8; 16], data: &mut [u8]) {
        assert_block_128::<C>();
        assert_xts_data_unit_len(data.len());

        let full_blocks = data.len() / 16;
        let rem = data.len() % 16;

        // `tweak` is the key-derived XEX mask and `tmp` carries each block
        // (plaintext on the way out) through the cipher; both are wiped.
        let mut tweak = *tweak_value;
        self.tweak_cipher.encrypt(&mut tweak);
        let mut tmp = [0u8; 16];

        let whole_blocks = if rem == 0 {
            full_blocks
        } else {
            full_blocks - 1
        };
        for block in data[..whole_blocks * 16].chunks_exact_mut(16) {
            tmp.copy_from_slice(block);
            xex_decrypt_block(&self.data_cipher, &tweak, &mut tmp);
            block.copy_from_slice(&tmp);
            gf_mul_x_xts(&mut tweak);
        }

        if rem != 0 {
            let last_full_start = whole_blocks * 16;
            let mut next_tweak = tweak;
            gf_mul_x_xts(&mut next_tweak);

            // PP: the last full ciphertext block decrypted under the next tweak.
            let mut pp = [0u8; 16];
            pp.copy_from_slice(&data[last_full_start..last_full_start + 16]);
            xex_decrypt_block(&self.data_cipher, &next_tweak, &mut pp);

            // `tmp` becomes CC: the ciphertext tail padded with PP's tail.
            tmp[..rem].copy_from_slice(&data[last_full_start + 16..]);
            tmp[rem..].copy_from_slice(&pp[rem..]);
            xex_decrypt_block(&self.data_cipher, &tweak, &mut tmp);

            data[last_full_start..last_full_start + 16].copy_from_slice(&tmp);
            data[last_full_start + 16..].copy_from_slice(&pp[..rem]);
            crate::ct::zeroize_slice(pp.as_mut_slice());
            crate::ct::zeroize_slice(next_tweak.as_mut_slice());
        }
        crate::ct::zeroize_slice(tmp.as_mut_slice());
        crate::ct::zeroize_slice(tweak.as_mut_slice());
    }
}

/// Cipher-based Message Authentication Code (CMAC).
///
/// The SP 800-38B subkeys `K1`/`K2` are derived once, in [`Cmac::new`], and
/// wiped when the value is dropped. EAX and SIV compute their OMAC and S2V
/// values through this type, so every CMAC in the crate uses one subkey
/// schedule per key instead of re-deriving `E_K(0)` per call.
pub struct Cmac<C> {
    cipher: C,
    // One block each; only the first `C::BLOCK_LEN` bytes (8 or 16) are live.
    k1: [u8; 16],
    k2: [u8; 16],
}

impl<C: BlockCipher> Cmac<C> {
    /// Wrap a block cipher in SP 800-38B CMAC mode.
    ///
    /// The two SP 800-38B subkeys `K1`/`K2` are derived once here rather
    /// than on every tag computation.
    ///
    /// # Panics
    ///
    /// Panics if the cipher's block size is not 8 or 16 bytes; CMAC only
    /// supports 64-bit or 128-bit block ciphers.
    pub fn new(cipher: C) -> Self {
        let blk = C::BLOCK_LEN;
        assert!(
            matches!(blk, 8 | 16),
            "CMAC only supports 64-bit or 128-bit block ciphers"
        );
        let mut mac = Self {
            cipher,
            k1: [0u8; 16],
            k2: [0u8; 16],
        };
        // L = E_K(0^b) is the root of both subkeys.
        let mut l = [0u8; 16];
        mac.cipher.encrypt(&mut l[..blk]);
        dbl_into(&l[..blk], &mut mac.k1[..blk]);
        dbl_into(&mac.k1[..blk], &mut mac.k2[..blk]);
        crate::ct::zeroize_slice(l.as_mut_slice());
        mac
    }
}

impl<C> Cmac<C> {
    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C> Drop for Cmac<C> {
    fn drop(&mut self) {
        // The subkeys are key material derived from E_K(0); scrub them like
        // the wrapped cipher scrubs its round keys.
        crate::ct::zeroize_slice(self.k1.as_mut_slice());
        crate::ct::zeroize_slice(self.k2.as_mut_slice());
    }
}

/// Counter with CBC-MAC (CCM) with compile-time detached tag length.
///
/// `TAG_LEN` must be one of RFC 3610's valid lengths:
/// `{4, 6, 8, 10, 12, 14, 16}`.
///
/// # Nonce reuse
///
/// Reusing a nonce under the same key breaks both confidentiality and
/// authenticity: the CTR keystream repeats and the CBC-MAC values become
/// related. Never reuse a `(key, nonce)` pair.
pub struct Ccm<C, const TAG_LEN: usize = 16> {
    cipher: C,
}

impl<C, const TAG_LEN: usize> Ccm<C, TAG_LEN> {
    /// Wrap a 128-bit block cipher in SP 800-38C CCM mode.
    ///
    /// # Panics
    ///
    /// Panics if `TAG_LEN` is not one of `{4, 6, 8, 10, 12, 14, 16}`.
    pub fn new(cipher: C) -> Self {
        assert_ccm_tag_len(TAG_LEN);
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }

    /// Return the detached authentication tag length in bytes.
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

impl<C: BlockCipher, const TAG_LEN: usize> Ccm<C, TAG_LEN> {
    /// Compute a detached CCM tag over `plaintext` and associated data.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, if `nonce.len()` is
    /// outside `7..=13`, or if `plaintext.len()` does not fit in the
    /// `L = 15 - nonce.len()` byte length field.
    #[must_use]
    pub fn compute_tag(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> [u8; TAG_LEN] {
        let mut t = ccm_cbc_mac(&self.cipher, nonce, aad, plaintext, TAG_LEN);
        let mut s0 = counter_keystream(&self.cipher, &ccm_counter_block(nonce, 0));
        let mut tag = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            tag[i] = t[i] ^ s0[i];
        }
        // `T` and `S_0` are each the other half of the tag, and with a
        // truncated tag the untransmitted bytes of both are secret.
        crate::ct::zeroize_slice(t.as_mut_slice());
        crate::ct::zeroize_slice(s0.as_mut_slice());
        tag
    }

    /// Encrypt `data` in place and return the detached CCM authentication tag.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, if `nonce.len()` is
    /// outside `7..=13`, or if `data.len()` does not fit in the
    /// `L = 15 - nonce.len()` byte length field.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        assert_block_128::<C>();
        let tag = self.compute_tag(nonce, aad, data);
        ccm_apply_ctr(&self.cipher, nonce, data);
        tag
    }

    /// Verify `tag` and decrypt in place on success.
    ///
    /// Returns `false` and leaves `data` unchanged when verification fails,
    /// or when `data.len()` does not fit in the `L = 15 - nonce.len()` byte
    /// length field (no valid ciphertext of that length exists under this
    /// nonce, and the length is attacker-controlled on a decrypt path).
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits or if `nonce.len()` is
    /// outside `7..=13`.
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        assert_block_128::<C>();
        let l = ccm_l_from_nonce(nonce);
        if l < 8 && (data.len() as u64) >= (1u64 << (8 * l)) {
            return false;
        }

        // In CCM, authentication is over plaintext, so decrypt to a temporary
        // buffer first and only commit if tag verification succeeds.
        let mut plaintext = data.to_vec();
        ccm_apply_ctr(&self.cipher, nonce, &mut plaintext);

        let mut expected = self.compute_tag(nonce, aad, &plaintext);
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        if authentic {
            data.copy_from_slice(&plaintext);
        }
        // CCM must decrypt before authenticating (the MAC is over plaintext),
        // so the heap buffer holds unauthenticated plaintext on failure and a
        // second copy of it on success, and the expected tag is a forgery for
        // this ciphertext. All of it is wiped on both paths.
        crate::ct::zeroize_slice(&mut plaintext);
        crate::ct::zeroize_slice(&mut expected);
        authentic
    }
}

/// Galois/Counter Mode (GCM) with a full 128-bit authentication tag.
///
/// Per NIST SP 800-38D, this implementation enforces a per-call payload limit
/// of `(2^32 - 2)` counter blocks (`68_719_476_704` bytes) so the 32-bit
/// counter field cannot wrap.
///
/// Callers must still ensure nonce uniqueness per key; this API is stateless and
/// cannot enforce global `(key, nonce)` uniqueness.
///
/// # Nonce reuse
///
/// Reusing a nonce under the same key is catastrophic: it leaks the XOR of
/// the plaintexts and exposes the GHASH authentication key `H`, enabling
/// forgeries. Never reuse a `(key, nonce)` pair.
///
/// # Examples
///
/// ```rust
/// use cryptography::{Aes256, Gcm};
///
/// let key = [0x11u8; 32];
/// let nonce = [0x22u8; 12];
/// let aad = b"hdr";
/// let mut ciphertext = *b"payload";
///
/// let aead = Gcm::new(Aes256::new(&key));
/// let tag = aead.encrypt(&nonce, aad, &mut ciphertext);
///
/// let mut recovered = ciphertext;
/// assert!(aead.decrypt(&nonce, aad, &mut recovered, &tag));
/// assert_eq!(recovered, *b"payload");
/// ```
pub struct Gcm<C> {
    cipher: C,
}

/// Variable-time Galois/Counter Mode (GCM) reference path.
///
/// # Timing
///
/// **This type's GHASH is variable-time in both of its operands.** Its block
/// multiplication is SP 800-38D §6.3 Algorithm 1 exactly as printed: it
/// branches on every bit of the block being hashed (the AAD, the ciphertext
/// and the length block) and on the low bit of each running multiple of the
/// hash subkey `H`, so its running time is a function of the secret `H` as
/// well as of the data. An observer who can time GHASH learns bits of `H`,
/// and `H` is all a forger needs. It exists for comparison against [`Gcm`]
/// and for profiling; it must not process data whose timing an adversary
/// can observe. [`Gcm`] is the constant-time path and the default.
///
/// It enforces the same SP 800-38D payload bound as [`Gcm`]:
/// `(2^32 - 2)` counter blocks (`68_719_476_704` bytes) per call.
/// The nonce-reuse caveats documented on [`Gcm`] apply equally here.
pub struct GcmVt<C> {
    cipher: C,
}

impl<C> Gcm<C> {
    /// Wrap a 128-bit block cipher in SP 800-38D GCM mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C> GcmVt<C> {
    /// Wrap a 128-bit block cipher in variable-time SP 800-38D GCM mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Gcm<C> {
    /// Compute the GCM authentication tag over `aad` and `ciphertext`.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, if `nonce` is empty,
    /// if `ciphertext.len()` exceeds the SP 800-38D per-call bound of
    /// `68_719_476_704` bytes, or if the bit length of `aad` or `nonce` does
    /// not fit 64 bits (§5.2.1.1).
    #[must_use]
    pub fn compute_tag(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        gcm_compute_tag::<_, SubkeyTable>(&self.cipher, nonce, aad, ciphertext)
    }

    /// Encrypt in place and return the 128-bit authentication tag.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, if `nonce` is empty,
    /// if `data.len()` exceeds the SP 800-38D per-call bound of
    /// `68_719_476_704` bytes, or if the bit length of `aad` or `nonce` does
    /// not fit 64 bits (§5.2.1.1).
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        gcm_encrypt::<_, SubkeyTable>(&self.cipher, nonce, aad, data)
    }

    /// Verify the tag and, if valid, decrypt in place.
    ///
    /// `tag` must be the full 128-bit tag: a slice of any other length is
    /// rejected outright, in the same constant-time comparison. This type
    /// never produces the truncated tags of SP 800-38D §5.2.1.2, so it never
    /// accepts one as a prefix match.
    ///
    /// Returns `false` and leaves `data` unchanged if tag verification fails,
    /// and also when `data.len()` exceeds the SP 800-38D per-call bound of
    /// `68_719_476_704` bytes or the bit length of `aad` or `nonce` does not
    /// fit 64 bits (§5.2.1.1): no valid ciphertext has those shapes.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, or if `nonce` is
    /// empty.
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        gcm_decrypt::<_, SubkeyTable>(&self.cipher, nonce, aad, data, tag)
    }
}

impl<C: BlockCipher> GcmVt<C> {
    /// Compute the GCM authentication tag over `aad` and `ciphertext`.
    ///
    /// # Panics
    ///
    /// Panics as [`Gcm::compute_tag`] does: non-128-bit block, empty
    /// `nonce`, or an over-long `ciphertext`, `aad` or `nonce`.
    #[must_use]
    pub fn compute_tag(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        gcm_compute_tag::<_, VariableTimeSubkey>(&self.cipher, nonce, aad, ciphertext)
    }

    /// Encrypt in place and return the 128-bit authentication tag.
    ///
    /// # Panics
    ///
    /// Panics as [`Gcm::encrypt`] does: non-128-bit block, empty `nonce`, or
    /// an over-long `data`, `aad` or `nonce`.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        gcm_encrypt::<_, VariableTimeSubkey>(&self.cipher, nonce, aad, data)
    }

    /// Verify the tag and, if valid, decrypt in place, with the tag-length
    /// and length-bound contract of [`Gcm::decrypt`]: `tag` must be the full
    /// 16 bytes, and an over-long `data`, `aad` or `nonce` returns `false`.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, or if `nonce` is
    /// empty.
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        gcm_decrypt::<_, VariableTimeSubkey>(&self.cipher, nonce, aad, data, tag)
    }
}

/// Galois Message Authentication Code (GMAC).
pub struct Gmac<C> {
    cipher: C,
}

/// Variable-time Galois Message Authentication Code (GMAC) reference path.
///
/// # Timing
///
/// **This type's GHASH is variable-time in both of its operands**, exactly as
/// [`GcmVt`]'s is: SP 800-38D §6.3 Algorithm 1 as printed, branching on the
/// bits of the authenticated data and on the running multiples of the hash
/// subkey `H`. A timing observer learns bits of `H`, which is the forgery key.
/// It exists for comparison against [`Gmac`]; it must not authenticate data
/// whose timing an adversary can observe. [`Gmac`] is the constant-time
/// default.
pub struct GmacVt<C> {
    cipher: C,
}

impl<C> Gmac<C> {
    /// Wrap a 128-bit block cipher in SP 800-38D GMAC mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C> GmacVt<C> {
    /// Wrap a 128-bit block cipher in variable-time SP 800-38D GMAC mode.
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Borrow the wrapped block cipher.
    pub fn cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: BlockCipher> Gmac<C> {
    /// Compute a GMAC tag over associated data only.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block size is not 128 bits, if `nonce` is empty,
    /// or if the bit length of `aad` or `nonce` does not fit 64 bits
    /// (SP 800-38D §5.2.1.1).
    #[must_use]
    pub fn compute(&self, nonce: &[u8], aad: &[u8]) -> [u8; 16] {
        gcm_compute_tag::<_, SubkeyTable>(&self.cipher, nonce, aad, &[])
    }

    /// Verify a GMAC tag in constant time.
    ///
    /// `tag` must be the full 128-bit tag: a slice of any other length is
    /// rejected outright, in the same constant-time comparison; a truncated
    /// tag (SP 800-38D §5.2.1.2) is never accepted as a prefix match.
    ///
    /// # Panics
    ///
    /// Panics as [`Gmac::compute`] does: non-128-bit block, empty `nonce`,
    /// or an over-long `aad` or `nonce`.
    pub fn verify(&self, nonce: &[u8], aad: &[u8], tag: &[u8]) -> bool {
        // The genuine tag is wiped: for attacker-chosen `aad` it is a forgery.
        let mut expected = self.compute(nonce, aad);
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        crate::ct::zeroize_slice(expected.as_mut_slice());
        authentic
    }
}

impl<C: BlockCipher> GmacVt<C> {
    /// Compute a GMAC tag over associated data only.
    #[must_use]
    pub fn compute(&self, nonce: &[u8], aad: &[u8]) -> [u8; 16] {
        gcm_compute_tag::<_, VariableTimeSubkey>(&self.cipher, nonce, aad, &[])
    }

    /// Verify a GMAC tag in constant time, with the tag-length contract of
    /// [`Gmac::verify`]: `tag` must be the full 16 bytes.
    pub fn verify(&self, nonce: &[u8], aad: &[u8], tag: &[u8]) -> bool {
        let mut expected = self.compute(nonce, aad);
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        crate::ct::zeroize_slice(expected.as_mut_slice());
        authentic
    }
}

impl<C: BlockCipher> Cmac<C> {
    /// Compute a CMAC tag over arbitrary-length input.
    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut tag = vec![0u8; C::BLOCK_LEN];
        self.compute_into(data, &mut tag);
        tag
    }

    /// Compute the tag into `out`, which must be exactly one block long.
    ///
    /// The CBC chaining value lives in a stack block that is wiped before
    /// returning, so no MAC-internal state outlives the call.
    pub(crate) fn compute_into(&self, data: &[u8], out: &mut [u8]) {
        let blk = C::BLOCK_LEN;
        assert_eq!(out.len(), blk, "CMAC output buffer must be one block");

        let n = if data.is_empty() {
            1
        } else {
            data.len().div_ceil(blk)
        };
        let last_complete = !data.is_empty() && data.len().is_multiple_of(blk);

        let mut chain = [0u8; 16];
        let x = &mut chain[..blk];
        for block in data.chunks(blk).take(n - 1) {
            xor_in_place(x, block);
            self.cipher.encrypt(x);
        }

        let start = (n - 1) * blk;
        if last_complete {
            out.copy_from_slice(&data[start..start + blk]);
            xor_in_place(out, &self.k1[..blk]);
        } else {
            let rem = data.len() - start;
            out.fill(0);
            out[..rem].copy_from_slice(&data[start..]);
            out[rem] = 0x80;
            xor_in_place(out, &self.k2[..blk]);
        }
        xor_in_place(out, x);
        self.cipher.encrypt(out);
        crate::ct::zeroize_slice(chain.as_mut_slice());
    }

    /// Verify a CMAC tag in constant time.
    ///
    /// `tag` must be the full block-length tag (16 bytes for a 128-bit block
    /// cipher, 8 for a 64-bit one): a slice of any other length is rejected
    /// outright, in the same constant-time comparison. SP 800-38B §5.5 allows
    /// a MAC to be the leftmost `Tlen` bits of the block, but [`Cmac::compute`]
    /// emits only full blocks, so a truncated tag is never accepted as a
    /// prefix match.
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        let blk = C::BLOCK_LEN;
        let mut expected = [0u8; 16];
        self.compute_into(data, &mut expected[..blk]);
        let authentic = crate::ct::constant_time_eq_mask(&expected[..blk], tag) == u8::MAX;
        crate::ct::zeroize_slice(expected.as_mut_slice());
        authentic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{decode_hex, decode_hex_array};
    use crate::{Aes128, Aes192, Aes256};

    #[test]
    fn ecb_aes128_sp800_38a() {
        // NIST SP 800-38A, F.1.1 ECB-AES128.Encrypt and F.1.2 ECB-AES128.Decrypt.
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("3ad77bb40d7a3660a89ecaf32466ef97"),
            decode_hex_array::<16>("f5d3d58503b9699de785895a96fdbaaf"),
            decode_hex_array::<16>("43b1cd7f598ece23881b00e3ed030688"),
            decode_hex_array::<16>("7b0c785e27e8ad3f8223207104725dd4"),
        ]
        .concat();

        Ecb::new(Aes128::new(&key)).encrypt_nopad(&mut data);
        assert_eq!(data, expected);
        Ecb::new(Aes128::new(&key)).decrypt_nopad(&mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn ecb_aes256_sp800_38a() {
        // NIST SP 800-38A, F.1.5 ECB-AES256.Encrypt and F.1.6 ECB-AES256.Decrypt.
        let key = decode_hex_array::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("f3eed1bdb5d2a03c064b5a7e3db181f8"),
            decode_hex_array::<16>("591ccb10d410ed26dc5ba74a31362870"),
            decode_hex_array::<16>("b6ed21b99ca6f4f9f153e7b1beafed1d"),
            decode_hex_array::<16>("23304b7a39f9f3ff067d8d8f9e24ecc7"),
        ]
        .concat();

        Ecb::new(Aes256::new(&key)).encrypt_nopad(&mut data);
        assert_eq!(data, expected);
        Ecb::new(Aes256::new(&key)).decrypt_nopad(&mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cbc_aes128_sp800_38a() {
        // NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt and F.2.2 CBC-AES128.Decrypt.
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("7649abac8119b246cee98e9b12e9197d"),
            decode_hex_array::<16>("5086cb9b507219ee95db113a917678b2"),
            decode_hex_array::<16>("73bed6b8e3c1743b7116e69e22229516"),
            decode_hex_array::<16>("3ff1caa1681fac09120eca307586e1a7"),
        ]
        .concat();

        let mode = Cbc::new(Aes128::new(&key));
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cbc_aes256_sp800_38a() {
        // NIST SP 800-38A, F.2.5 CBC-AES256.Encrypt and F.2.6 CBC-AES256.Decrypt.
        let key = decode_hex_array::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
            decode_hex_array::<16>("9cfc4e967edb808d679f777bc6702c7d"),
            decode_hex_array::<16>("39f23369a9d9bacfa530e26304231461"),
            decode_hex_array::<16>("b2eb05e2c39be9fcda6c19078c6a9d1b"),
        ]
        .concat();

        let mode = Cbc::new(Aes256::new(&key));
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cfb_aes128_sp800_38a() {
        // NIST SP 800-38A, F.3.13 CFB128-AES128.Encrypt and F.3.14 CFB128-AES128.Decrypt.
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("3b3fd92eb72dad20333449f8e83cfb4a"),
            decode_hex_array::<16>("c8a64537a0b3a93fcde3cdad9f1ce58b"),
            decode_hex_array::<16>("26751f67a3cbb140b1808cf187a4f4df"),
            decode_hex_array::<16>("c04b05357c5d1c0eeac4c66f9ff7f2e6"),
        ]
        .concat();

        let mode = Cfb::new(Aes128::new(&key));
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cfb_aes256_sp800_38a() {
        // NIST SP 800-38A, F.3.17 CFB128-AES256.Encrypt and F.3.18 CFB128-AES256.Decrypt.
        let key = decode_hex_array::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("dc7e84bfda79164b7ecd8486985d3860"),
            decode_hex_array::<16>("39ffed143b28b1c832113c6331e5407b"),
            decode_hex_array::<16>("df10132415e54b92a13ed0a8267ae2f9"),
            decode_hex_array::<16>("75a385741ab9cef82031623d55b1e471"),
        ]
        .concat();

        let mode = Cfb::new(Aes256::new(&key));
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cfb8_aes128_roundtrip() {
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let plaintext = *b"cfb8 mode roundtrip check";
        let mut data = plaintext;

        let mode = Cfb8::new(Aes128::new(&key));
        mode.encrypt(&iv, &mut data);
        assert_ne!(data, plaintext);
        mode.decrypt(&iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn cfb8_aes128_sp800_38a_prefix_vector() {
        // NIST SP 800-38A, F.3.7 CFB8-AES128.Encrypt and F.3.8 CFB8-AES128.Decrypt
        // (the standard prints 18 segments).
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = decode_hex("6bc1bee22e409f96e93d7e117393172aae2d");
        let expected = decode_hex("3b79424c9c0dd436bace9e0ed4586a4f32b9");

        let mode = Cfb8::new(Aes128::new(&key));
        mode.encrypt(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt(&iv, &mut data);
        assert_eq!(data, decode_hex("6bc1bee22e409f96e93d7e117393172aae2d"));
    }

    #[test]
    fn ofb_aes128_sp800_38a() {
        // NIST SP 800-38A, F.4.1 OFB-AES128.Encrypt and F.4.2 OFB-AES128.Decrypt.
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("3b3fd92eb72dad20333449f8e83cfb4a"),
            decode_hex_array::<16>("7789508d16918f03f53c52dac54ed825"),
            decode_hex_array::<16>("9740051e9c5fecf64344f7a82260edcc"),
            decode_hex_array::<16>("304c6528f659c77866a510d9c1d6ae5e"),
        ]
        .concat();

        let mode = Ofb::new(Aes128::new(&key));
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn ofb_aes256_sp800_38a() {
        // NIST SP 800-38A, F.4.5 OFB-AES256.Encrypt and F.4.6 OFB-AES256.Decrypt.
        let key = decode_hex_array::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let iv = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("dc7e84bfda79164b7ecd8486985d3860"),
            decode_hex_array::<16>("4febdc6740d20b3ac88f6ad82a4fb08d"),
            decode_hex_array::<16>("71ab47a086e86eedf39d1c5bba97c408"),
            decode_hex_array::<16>("0126141d67f37be8538f5a8be740e484"),
        ]
        .concat();

        let mode = Ofb::new(Aes256::new(&key));
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn ctr_aes128_sp800_38a() {
        // NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt and F.5.2 CTR-AES128.Decrypt.
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let ctr = decode_hex_array::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("874d6191b620e3261bef6864990db6ce"),
            decode_hex_array::<16>("9806f66b7970fdff8617187bb9fffdff"),
            decode_hex_array::<16>("5ae4df3edbd5d35e5b4f09020db03eab"),
            decode_hex_array::<16>("1e031dda2fbe03d1792170a0f3009cee"),
        ]
        .concat();

        let mode = Ctr::new(Aes128::new(&key));
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn ctr_aes256_sp800_38a() {
        // NIST SP 800-38A, F.5.5 CTR-AES256.Encrypt and F.5.6 CTR-AES256.Decrypt.
        let key = decode_hex_array::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let ctr = decode_hex_array::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = [
            decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
            decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
            decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
            decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
        ]
        .concat();
        let expected = [
            decode_hex_array::<16>("601ec313775789a5b7a7f504bbf3d228"),
            decode_hex_array::<16>("f443e3ca4d62b59aca84e990cacaf5c5"),
            decode_hex_array::<16>("2b0930daa23de94ce87017ba2d84988d"),
            decode_hex_array::<16>("dfc9c58db67aada613c2dd08457941a6"),
        ]
        .concat();

        let mode = Ctr::new(Aes256::new(&key));
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(
            data,
            [
                decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"),
                decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"),
                decode_hex_array::<16>("30c81c46a35ce411e5fbc1191a0a52ef"),
                decode_hex_array::<16>("f69f2445df4f9b17ad2b417be66c3710"),
            ]
            .concat()
        );
    }

    #[test]
    fn cmac_aes128_sp800_38b() {
        let key = decode_hex_array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let mode = Cmac::new(Aes128::new(&key));

        assert_eq!(
            mode.compute(&[]),
            decode_hex_array::<16>("bb1d6929e95937287fa37d129b756746").to_vec()
        );
        assert_eq!(
            mode.compute(&decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a")),
            decode_hex_array::<16>("070a16b46b4d4144f79bdd9dd04a287c").to_vec()
        );
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&decode_hex_array::<16>("6bc1bee22e409f96e93d7e117393172a"));
        msg.extend_from_slice(&decode_hex_array::<16>("ae2d8a571e03ac9c9eb76fac45af8e51"));
        msg.extend_from_slice(&decode_hex_array::<8>("30c81c46a35ce411"));
        assert_eq!(
            mode.compute(&msg),
            decode_hex_array::<16>("dfa66747de9ae63030ca32611497c827").to_vec()
        );
        assert!(mode.verify(
            &msg,
            &decode_hex_array::<16>("dfa66747de9ae63030ca32611497c827")
        ));
    }

    // The three `xts_aes128_*_openssl` tests below are cross-checks: their
    // expected bytes were produced by OpenSSL's `aes-128-xts`, not taken from
    // a standard. The known answers are `xts_aes128_ieee1619_annex_b_vectors`
    // and `xts_aes128_nist_cavp_vector`.
    #[test]
    fn xts_aes128_two_block_matches_openssl() {
        let key1 = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let key2 = decode_hex_array::<16>("101112131415161718191a1b1c1d1e1f");
        let tweak = [0u8; 16];
        let mut data = decode_hex_array::<32>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let expected = decode_hex_array::<32>(
            "74a109aabf1937c022d19da4b96cbc40b8ddc9c0653a7fb0dc8425c7ef276dea",
        );

        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_sector(&tweak, &mut data);
        assert_eq!(
            data,
            decode_hex_array::<32>(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
        );
    }

    #[test]
    fn xts_aes128_ciphertext_stealing_matches_openssl() {
        let key1 = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let key2 = decode_hex_array::<16>("101112131415161718191a1b1c1d1e1f");
        let tweak = [0u8; 16];
        let mut data = decode_hex_array::<31>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        );
        let expected = decode_hex_array::<31>(
            "03ab02ee0037b6327b1110429d562a8674a109aabf1937c022d19da4b96cbc",
        );

        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_sector(&tweak, &mut data);
        assert_eq!(
            data,
            decode_hex_array::<31>(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
            )
        );
    }

    #[test]
    fn xts_aes128_runtime_cross_check_with_openssl() {
        let key1 = decode_hex_array::<16>("000102030405060708090a0b0c0d0e0f");
        let key2 = decode_hex_array::<16>("101112131415161718191a1b1c1d1e1f");
        let tweak = [0u8; 16];
        let plaintext = decode_hex_array::<31>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        );

        let Some(expected) = crate::test_utils::openssl(
            &[
                "enc",
                "-aes-128-xts",
                "-e",
                "-nopad",
                "-K",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "-iv",
                "00000000000000000000000000000000",
            ],
            &plaintext,
        )
        .or_skip("xts_aes128_runtime_cross_check_with_openssl") else {
            return;
        };

        let mut data = plaintext;
        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data.as_slice(), expected.as_slice());
    }

    #[test]
    fn xts_aes128_nist_cavp_vector() {
        // NIST CAVP XTSGenAES128.rsp, "format tweak value input - 128 hex str",
        // ENCRYPT, COUNT = 1.
        let key1 = decode_hex_array::<16>("a1b90cba3f06ac353b2c343876081762");
        let key2 = decode_hex_array::<16>("090923026e91771815f29dab01932f2f");
        let tweak = decode_hex_array::<16>("4faef7117cda59c66e4b92013e768ad5");
        let mut data = decode_hex_array::<16>("ebabce95b14d3c8d6fb350390790311c");
        let expected = decode_hex_array::<16>("778ae8b43cb98d5a825081d5be471c63");

        let mode = Xts::new(Aes128::new(&key1), Aes128::new(&key2));
        mode.encrypt_sector(&tweak, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_sector(&tweak, &mut data);
        assert_eq!(
            data,
            decode_hex_array::<16>("ebabce95b14d3c8d6fb350390790311c")
        );
    }

    /// XTS-AES-128 known answers from IEEE P1619/D16 (May 2007, unapproved
    /// draft), Annex B: Vectors 1–3 (32-byte data units) and Vectors 15–18
    /// (17- to 20-byte data units, exercising ciphertext stealing). Checked
    /// field by field against the draft as published by IEEE at
    /// grouper.ieee.org/groups/1619/email/pdf00086.pdf (SHA-256
    /// c312d3930e22be1218b25a3bff73ed09b08e0b73cc91ec7ed9fefd12dce72460).
    /// Annex B prints each data unit sequence number as the byte array of
    /// §5.1, which converts the tweak to little-endian bytes before AES
    /// encryption, so the printed `9a78563412` is the integer `0x123456789a`.
    #[test]
    fn xts_aes128_ieee1619_annex_b_vectors() {
        fn tweak(data_unit_sequence_number: u64) -> [u8; 16] {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&data_unit_sequence_number.to_le_bytes());
            t
        }

        // (vector, Key1, Key2, data unit sequence number, PTX, CTX)
        let vectors: [(u32, &str, &str, u64, &str, &str); 7] = [
            (
                1,
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                0,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
            ),
            (
                2,
                "11111111111111111111111111111111",
                "22222222222222222222222222222222",
                0x33_3333_3333,
                "4444444444444444444444444444444444444444444444444444444444444444",
                "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
            ),
            (
                3,
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "22222222222222222222222222222222",
                0x33_3333_3333,
                "4444444444444444444444444444444444444444444444444444444444444444",
                "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
            ),
            (
                15,
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                0x12_3456_789a,
                "000102030405060708090a0b0c0d0e0f10",
                "6c1625db4671522d3d7599601de7ca09ed",
            ),
            (
                16,
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                0x12_3456_789a,
                "000102030405060708090a0b0c0d0e0f1011",
                "d069444b7a7e0cab09e24447d24deb1fedbf",
            ),
            (
                17,
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                0x12_3456_789a,
                "000102030405060708090a0b0c0d0e0f101112",
                "e5df1351c0544ba1350b3363cd8ef4beedbf9d",
            ),
            (
                18,
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                0x12_3456_789a,
                "000102030405060708090a0b0c0d0e0f10111213",
                "9d84c813f719aa2c7be3f66171c7c5c2edbf9dac",
            ),
        ];

        for (vector, key1, key2, dsn, ptx, ctx) in vectors {
            let mode = Xts::new(
                Aes128::new(&decode_hex_array::<16>(key1)),
                Aes128::new(&decode_hex_array::<16>(key2)),
            );
            let mut data = decode_hex(ptx);
            mode.encrypt_sector(&tweak(dsn), &mut data);
            assert_eq!(data, decode_hex(ctx), "IEEE 1619 Annex B vector {vector}");
            mode.decrypt_sector(&tweak(dsn), &mut data);
            assert_eq!(data, decode_hex(ptx), "IEEE 1619 Annex B vector {vector}");
        }
    }

    #[test]
    fn ctr_des_roundtrip_generic() {
        let key = decode_hex_array::<8>("133457799bbcdff1");
        let counter = decode_hex_array::<8>("0123456789abcdef");
        let original = *b"generic DES mode path!";
        let mut data = original;

        let mode = Ctr::new(crate::Des::new(&key).expect("non-weak DES test key"));
        mode.apply_keystream(&counter, &mut data);
        assert_ne!(data, original);
        mode.apply_keystream(&counter, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn gcm_aes128_test_case_1_empty() {
        // D. McGrew and J. Viega, "The Galois/Counter Mode of Operation
        // (GCM)", revised May 31, 2005 (pubs/mcgrew-viega-2005-gcm-revised-
        // spec.pdf), Appendix B, Test Case 1: all-zero key and 96-bit IV,
        // empty plaintext and AAD.
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut data = Vec::new();
        let mode = Gcm::new(Aes128::new(&key));

        let tag = mode.encrypt(&iv, &[], &mut data);
        assert_eq!(data, Vec::<u8>::new());
        assert_eq!(
            tag,
            decode_hex_array::<16>("58e2fccefa7e3061367f1d57a4e7455a")
        );
        assert!(mode.decrypt(&iv, &[], &mut data, &tag));
    }

    #[test]
    #[should_panic(expected = "GCM IV must be non-empty")]
    fn gcm_empty_iv_is_rejected() {
        // An empty IV would yield J0 = 0^128 for every key, silently reusing
        // the keystream and tag mask across messages. It must be rejected.
        let key = [0u8; 16];
        let mut data = [0u8; 16];
        let mode = Gcm::new(Aes128::new(&key));
        let _ = mode.encrypt(&[], &[], &mut data);
    }

    #[test]
    fn gcm_aes128_test_case_2_single_block() {
        // McGrew and Viega (pubs/mcgrew-viega-2005-gcm-revised-spec.pdf),
        // Appendix B, Test Case 2: all-zero key and 96-bit IV, one all-zero
        // plaintext block.
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut data = [0u8; 16];
        let expected_ct = decode_hex_array::<16>("0388dace60b6a392f328c2b971b2fe78");
        let expected_tag = decode_hex_array::<16>("ab6e47d42cec13bdf53a67b21257bddf");
        let mode = Gcm::new(Aes128::new(&key));

        let tag = mode.encrypt(&iv, &[], &mut data);
        assert_eq!(data, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&iv, &[], &mut data, &tag));
        assert_eq!(data, [0u8; 16]);
    }

    #[test]
    fn gcm_aes128_test_case_4_with_aad() {
        // McGrew and Viega (pubs/mcgrew-viega-2005-gcm-revised-spec.pdf),
        // Appendix B, Test Case 4: a 60-byte plaintext under 20 bytes of
        // associated data. Checked field by field against the PDF; the
        // integration test `tests/kat_gcm.rs` covers Test Cases 3-18.
        let key = decode_hex_array::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = decode_hex_array::<12>("cafebabefacedbaddecaf888");
        let aad = decode_hex_array::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = decode_hex_array::<60>(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let expected_ct = decode_hex_array::<60>(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );
        let expected_tag = decode_hex_array::<16>("5bc94fbc3221a5db94fae95ae7121a47");
        let mode = Gcm::new(Aes128::new(&key));

        let mut data = plaintext;
        let tag = mode.encrypt(&iv, &aad, &mut data);
        assert_eq!(data, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&iv, &aad, &mut data, &tag));
        assert_eq!(data, plaintext);
    }

    #[test]
    fn gcm_aes256_single_block_cavp() {
        // NIST CAVP gcmEncryptExtIV256.rsp
        // [Keylen=256, IVlen=96, PTlen=128, AADlen=0, Taglen=128], Count=0.
        let key = decode_hex_array::<32>(
            "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
        );
        let iv = decode_hex_array::<12>("0d18e06c7c725ac9e362e1ce");
        let mut data = decode_hex_array::<16>("2db5168e932556f8089a0622981d017d");
        let expected_ct = decode_hex_array::<16>("fa4362189661d163fcd6a56d8bf0405a");
        let expected_tag = decode_hex_array::<16>("d636ac1bbedd5cc3ee727dc2ab4a9489");

        let mode = Gcm::new(Aes256::new(&key));
        let tag = mode.encrypt(&iv, &[], &mut data);
        assert_eq!(data, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&iv, &[], &mut data, &tag));
        assert_eq!(
            data,
            decode_hex_array::<16>("2db5168e932556f8089a0622981d017d")
        );
    }

    #[test]
    fn gcm_aes256_non_96bit_iv_auth_only_cavp() {
        // NIST CAVP gcmEncryptExtIV256.rsp
        // [Keylen=256, IVlen=8, PTlen=0, AADlen=128, Taglen=128], Count=0.
        let key = decode_hex_array::<32>(
            "c639f716597a86afd12319199e21a62b1fc0277a70e3ca120bd3ff745be88604",
        );
        let iv = decode_hex_array::<1>("29");
        let aad = decode_hex_array::<16>("20fda1db6911d160121dc3c48e5f19b2");
        let mut data: [u8; 0] = [];
        let expected_tag = decode_hex_array::<16>("221a3398f20d0d9fe913f33a6cd413d3");

        let mode = Gcm::new(Aes256::new(&key));
        let tag = mode.encrypt(&iv, &aad, &mut data);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&iv, &aad, &mut data, &tag));
    }

    #[test]
    fn gcm_rejects_wrong_tag_without_decrypting() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut data = [0u8; 16];
        let mode = Gcm::new(Aes128::new(&key));
        let tag = mode.encrypt(&iv, &[], &mut data);
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let ciphertext = data;

        assert!(!mode.decrypt(&iv, &[], &mut data, &bad_tag));
        assert_eq!(data, ciphertext);
    }

    #[test]
    fn gcm_ct_and_vt_backends_match() {
        let key = decode_hex_array::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = decode_hex_array::<12>("cafebabefacedbaddecaf888");
        let aad = decode_hex_array::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = decode_hex_array::<64>(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b391aafd255",
        );

        let gcm_ct = Gcm::new(Aes128::new(&key));
        let gcm_vt = GcmVt::new(Aes128::new(&key));

        let mut ct_data = plaintext;
        let mut vt_data = plaintext;
        let ct_tag = gcm_ct.encrypt(&iv, &aad, &mut ct_data);
        let vt_tag = gcm_vt.encrypt(&iv, &aad, &mut vt_data);

        assert_eq!(ct_data, vt_data);
        assert_eq!(ct_tag, vt_tag);
        assert!(gcm_ct.decrypt(&iv, &aad, &mut ct_data, &ct_tag));
        assert!(gcm_vt.decrypt(&iv, &aad, &mut vt_data, &vt_tag));
        assert_eq!(ct_data, plaintext);
        assert_eq!(vt_data, plaintext);
    }

    #[test]
    fn gcm_payload_limit_matches_sp800_38d_bound() {
        assert!(gcm_payload_len_allowed_u64(0));
        assert!(gcm_payload_len_allowed_u64(1));
        assert!(gcm_payload_len_allowed_u64(16));
        assert!(gcm_payload_len_allowed_u64(GCM_MAX_PAYLOAD_BYTES));
        assert!(!gcm_payload_len_allowed_u64(GCM_MAX_PAYLOAD_BYTES + 1));
    }

    #[test]
    fn gmac_matches_gcm_on_empty_plaintext() {
        let key = decode_hex_array::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = decode_hex_array::<12>("cafebabefacedbaddecaf888");
        let aad = decode_hex_array::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let gcm = Gcm::new(Aes128::new(&key));
        let gmac = Gmac::new(Aes128::new(&key));
        let tag = gmac.compute(&iv, &aad);

        assert_eq!(tag, gcm.compute_tag(&iv, &aad, &[]));
        assert!(gmac.verify(&iv, &aad, &tag));
    }

    #[test]
    fn gmac_ct_and_vt_backends_match() {
        let key = decode_hex_array::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = decode_hex_array::<12>("cafebabefacedbaddecaf888");
        let aad = decode_hex_array::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let gmac_ct = Gmac::new(Aes128::new(&key));
        let gmac_vt = GmacVt::new(Aes128::new(&key));

        let tag_ct = gmac_ct.compute(&iv, &aad);
        let tag_vt = gmac_vt.compute(&iv, &aad);

        assert_eq!(tag_ct, tag_vt);
        assert!(gmac_ct.verify(&iv, &aad, &tag_ct));
        assert!(gmac_vt.verify(&iv, &aad, &tag_vt));
    }

    /// A 13-byte nonce leaves a 2-byte length field: a 65 536-byte
    /// ciphertext cannot be valid under it, and a decrypt path must say so
    /// rather than panic on attacker-chosen length.
    #[test]
    fn ccm_decrypt_rejects_length_that_does_not_fit_l() {
        let ccm = Ccm::<Aes128, 16>::new(Aes128::new(&[0u8; 16]));
        let nonce = [0u8; 13];
        let mut data = vec![0u8; 1 << 16];
        assert!(!ccm.decrypt(&nonce, &[], &mut data, &[0u8; 16]));
    }

    #[test]
    fn ccm_aes128_rfc3610_packet_vector_1() {
        // RFC 3610, section 8, Packet Vector #1.
        let key = decode_hex_array::<16>("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce = decode_hex_array::<13>("00000003020100a0a1a2a3a4a5");
        let aad = decode_hex_array::<8>("0001020304050607");
        let mut msg = decode_hex_array::<23>("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let expected_ct = decode_hex_array::<23>("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
        let expected_tag = decode_hex_array::<8>("17e8d12cfdf926e0");

        let mode = Ccm::<_, 8>::new(Aes128::new(&key));
        let tag = mode.encrypt(&nonce, &aad, &mut msg);
        assert_eq!(msg, expected_ct);
        assert_eq!(tag, expected_tag);

        assert!(mode.decrypt(&nonce, &aad, &mut msg, &tag));
        assert_eq!(
            msg,
            decode_hex_array::<23>("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        );
    }

    #[test]
    fn ccm_aes128_rfc3610_packet_vector_2() {
        // RFC 3610, section 8, Packet Vector #2.
        let key = decode_hex_array::<16>("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce = decode_hex_array::<13>("00000004030201a0a1a2a3a4a5");
        let aad = decode_hex_array::<8>("0001020304050607");
        let mut msg = decode_hex_array::<24>("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let expected_ct =
            decode_hex_array::<24>("72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b");
        let expected_tag = decode_hex_array::<8>("a091d56e10400916");

        let mode = Ccm::<_, 8>::new(Aes128::new(&key));
        let tag = mode.encrypt(&nonce, &aad, &mut msg);
        assert_eq!(msg, expected_ct);
        assert_eq!(tag, expected_tag);

        assert!(mode.decrypt(&nonce, &aad, &mut msg, &tag));
        assert_eq!(
            msg,
            decode_hex_array::<24>("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[test]
    fn ccm_tag_mismatch_rejected() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 13];
        let aad = b"header";
        let mode = Ccm::<_, 12>::new(Aes128::new(&key));
        let mut data = *b"ccm plaintext data";
        let tag = mode.encrypt(&nonce, aad, &mut data);
        let ciphertext = data;

        let mut bad_tag = tag;
        bad_tag[0] ^= 0x80;
        assert!(!mode.decrypt(&nonce, aad, &mut data, &bad_tag));
        assert_eq!(data, ciphertext);

        assert!(mode.decrypt(&nonce, aad, &mut data, &tag));
        assert_eq!(data, *b"ccm plaintext data");
    }

    #[test]
    fn ccm_aes128_cavp_tlen_4_vector() {
        // NIST CAVP VTT128.rsp, [Tlen = 4], Count = 0.
        let key = decode_hex_array::<16>("43b1a6bc8d0d22d6d1ca95c18593cca5");
        let nonce = decode_hex_array::<13>("9882578e750b9682c6ca7f8f86");
        let aad = decode_hex_array::<32>(
            "2084f3861c9ad0ccee7c63a7e05aece5db8b34bd8724cc06b4ca99a7f9c4914f",
        );
        let mut msg = decode_hex_array::<24>("a2b381c7d1545c408fe29817a21dc435a154c87256346b05");
        let expected_ct =
            decode_hex_array::<24>("cc69ed76985e0ed4c8365a72775e5a19bfccc71aeb116c85");
        let expected_tag = decode_hex_array::<4>("a8c74677");

        let mode = Ccm::<_, 4>::new(Aes128::new(&key));
        let tag = mode.encrypt(&nonce, &aad, &mut msg);
        assert_eq!(msg, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&nonce, &aad, &mut msg, &tag));
        assert_eq!(
            msg,
            decode_hex_array::<24>("a2b381c7d1545c408fe29817a21dc435a154c87256346b05")
        );
    }

    #[test]
    fn ccm_aes128_cavp_tlen_16_vector() {
        // NIST CAVP VTT128.rsp, [Tlen = 16], Count = 0.
        let key = decode_hex_array::<16>("4189351b5caea375a0299e81c621bf43");
        let nonce = decode_hex_array::<13>("48c0906930561e0ab0ef4cd972");
        let aad = decode_hex_array::<32>(
            "40a27c1d1e23ea3dbe8056b2774861a4a201cce49f19997d19206d8c8a343951",
        );
        let mut msg = decode_hex_array::<24>("4535d12b4377928a7c0a61c9f825a48671ea05910748c8ef");
        let expected_ct =
            decode_hex_array::<24>("26c56961c035a7e452cce61bc6ee220d77b3f94d18fd10b6");
        let expected_tag = decode_hex_array::<16>("d80e8bf80f4a46cab06d4313f0db9be9");

        let mode = Ccm::<_, 16>::new(Aes128::new(&key));
        let tag = mode.encrypt(&nonce, &aad, &mut msg);
        assert_eq!(msg, expected_ct);
        assert_eq!(tag, expected_tag);
        assert!(mode.decrypt(&nonce, &aad, &mut msg, &tag));
        assert_eq!(
            msg,
            decode_hex_array::<24>("4535d12b4377928a7c0a61c9f825a48671ea05910748c8ef")
        );
    }

    #[test]
    fn aes_key_wrap_rfc3394_4_1() {
        let kek = decode_hex_array::<16>("000102030405060708090A0B0C0D0E0F");
        let key_data = decode_hex_array::<16>("00112233445566778899AABBCCDDEEFF");
        let expected = decode_hex_array::<24>("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        let kw = AesKeyWrap::new(Aes128::new(&kek));

        assert_eq!(kw.wrap_key(&key_data), Some(expected.to_vec()));
        assert_eq!(kw.unwrap_key(&expected), Some(key_data.to_vec()));
    }

    #[test]
    fn aes_key_wrap_rfc3394_4_2() {
        let kek = decode_hex_array::<24>("000102030405060708090A0B0C0D0E0F1011121314151617");
        let key_data = decode_hex_array::<16>("00112233445566778899AABBCCDDEEFF");
        let expected = decode_hex_array::<24>("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");
        let kw = AesKeyWrap::new(Aes192::new(&kek));

        assert_eq!(kw.wrap_key(&key_data), Some(expected.to_vec()));
        assert_eq!(kw.unwrap_key(&expected), Some(key_data.to_vec()));
    }

    #[test]
    fn aes_key_wrap_rfc3394_4_3() {
        let kek = decode_hex_array::<32>(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        );
        let key_data = decode_hex_array::<16>("00112233445566778899AABBCCDDEEFF");
        let expected = decode_hex_array::<24>("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");
        let kw = AesKeyWrap::new(Aes256::new(&kek));

        assert_eq!(kw.wrap_key(&key_data), Some(expected.to_vec()));
        assert_eq!(kw.unwrap_key(&expected), Some(key_data.to_vec()));
    }

    #[test]
    fn aes_key_wrap_rfc3394_4_4() {
        let kek = decode_hex_array::<24>("000102030405060708090A0B0C0D0E0F1011121314151617");
        let key_data = decode_hex_array::<24>("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected = decode_hex_array::<32>(
            "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
        );
        let kw = AesKeyWrap::new(Aes192::new(&kek));

        assert_eq!(kw.wrap_key(&key_data), Some(expected.to_vec()));
        assert_eq!(kw.unwrap_key(&expected), Some(key_data.to_vec()));
    }

    #[test]
    fn aes_key_wrap_rfc3394_4_5() {
        let kek = decode_hex_array::<32>(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        );
        let key_data = decode_hex_array::<24>("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected = decode_hex_array::<32>(
            "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        );
        let kw = AesKeyWrap::new(Aes256::new(&kek));

        assert_eq!(kw.wrap_key(&key_data), Some(expected.to_vec()));
        assert_eq!(kw.unwrap_key(&expected), Some(key_data.to_vec()));
    }

    #[test]
    fn aes_key_wrap_rfc3394_4_6() {
        let kek = decode_hex_array::<32>(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        );
        let key_data = decode_hex_array::<32>(
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        );
        let expected = decode_hex_array::<40>(
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        );
        let kw = AesKeyWrap::new(Aes256::new(&kek));

        assert_eq!(kw.wrap_key(&key_data), Some(expected.to_vec()));
        assert_eq!(kw.unwrap_key(&expected), Some(key_data.to_vec()));
    }

    #[test]
    fn aes_key_wrap_rejects_bad_lengths_and_tampering() {
        let kw = AesKeyWrap::new(Aes128::new(&[0u8; 16]));

        assert!(kw.wrap_key(&[]).is_none());
        assert!(kw.wrap_key(&[0u8; 8]).is_none());
        assert!(kw.wrap_key(&[0u8; 15]).is_none());
        assert!(kw.unwrap_key(&[]).is_none());
        assert!(kw.unwrap_key(&[0u8; 16]).is_none());

        let mut wrapped = kw.wrap_key(&[0u8; 16]).expect("wrap");
        wrapped[0] ^= 1;
        assert!(kw.unwrap_key(&wrapped).is_none());
    }

    /// A rejected unwrap must not leave the speculatively recovered key in
    /// the output buffer; an accepted one fills the same buffer with the key.
    #[test]
    fn aes_key_wrap_failed_unwrap_wipes_the_output() {
        let kw = AesKeyWrap::new(Aes128::new(&[0x5au8; 16]));
        let key_data = [0x11u8; 24];
        let good = kw.wrap_key(&key_data).expect("wrap");

        let mut tampered = good.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let mut out = [0xffu8; 24];
        assert!(!kw.unwrap_into(&tampered, &AES_KEY_WRAP_DEFAULT_IV, &mut out));
        assert_eq!(out, [0u8; 24]);

        // Right ciphertext, wrong expected IV: still rejected, still wiped.
        let mut out = [0xffu8; 24];
        assert!(!kw.unwrap_into(&good, &[0x5b; 8], &mut out));
        assert_eq!(out, [0u8; 24]);

        assert!(kw.unwrap_into(&good, &AES_KEY_WRAP_DEFAULT_IV, &mut out));
        assert_eq!(out, key_data);
    }

    /// SP 800-38A Appendix F: the four-block plaintext shared by every
    /// example, and the AES-192 key of F.1.3, F.2.3, F.3.9, F.3.15, F.4.3 and
    /// F.5.3.
    const SP800_38A_PLAINTEXT: [&str; 4] = [
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ];
    const SP800_38A_AES192_KEY: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    const SP800_38A_AES256_KEY: &str =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const SP800_38A_IV: &str = "000102030405060708090a0b0c0d0e0f";

    fn sp800_38a_blocks(blocks: &[&str]) -> Vec<u8> {
        blocks.iter().flat_map(|b| decode_hex(b)).collect()
    }

    /// NIST SP 800-38A, F.1.3 ECB-AES192.Encrypt and F.1.4 ECB-AES192.Decrypt.
    #[test]
    fn ecb_aes192_sp800_38a() {
        let plaintext = sp800_38a_blocks(&SP800_38A_PLAINTEXT);
        let expected = sp800_38a_blocks(&[
            "bd334f1d6e45f25ff712a214571fa5cc",
            "974104846d0ad3ad7734ecb3ecee4eef",
            "ef7afd2270e2e60adce0ba2face6444e",
            "9a4b41ba738d6c72fb16691603c18e0e",
        ]);
        let mode = Ecb::new(Aes192::new(&decode_hex_array::<24>(SP800_38A_AES192_KEY)));
        let mut data = plaintext.clone();
        mode.encrypt_nopad(&mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&mut data);
        assert_eq!(data, plaintext);
    }

    /// NIST SP 800-38A, F.2.3 CBC-AES192.Encrypt and F.2.4 CBC-AES192.Decrypt.
    #[test]
    fn cbc_aes192_sp800_38a() {
        let plaintext = sp800_38a_blocks(&SP800_38A_PLAINTEXT);
        let expected = sp800_38a_blocks(&[
            "4f021db243bc633d7178183a9fa071e8",
            "b4d9ada9ad7dedf4e5e738763f69145a",
            "571b242012fb7ae07fa9baac3df102e0",
            "08b0e27988598881d920a9e64f5615cd",
        ]);
        let iv = decode_hex_array::<16>(SP800_38A_IV);
        let mode = Cbc::new(Aes192::new(&decode_hex_array::<24>(SP800_38A_AES192_KEY)));
        let mut data = plaintext.clone();
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(data, plaintext);
    }

    /// NIST SP 800-38A, F.3.15 CFB128-AES192.Encrypt and F.3.16
    /// CFB128-AES192.Decrypt.
    #[test]
    fn cfb_aes192_sp800_38a() {
        let plaintext = sp800_38a_blocks(&SP800_38A_PLAINTEXT);
        let expected = sp800_38a_blocks(&[
            "cdc80d6fddf18cab34c25909c99a4174",
            "67ce7f7f81173621961a2b70171d3d7a",
            "2e1e8a1dd59b88b1c8e60fed1efac4c9",
            "c05f9f9ca9834fa042ae8fba584b09ff",
        ]);
        let iv = decode_hex_array::<16>(SP800_38A_IV);
        let mode = Cfb::new(Aes192::new(&decode_hex_array::<24>(SP800_38A_AES192_KEY)));
        let mut data = plaintext.clone();
        mode.encrypt_nopad(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt_nopad(&iv, &mut data);
        assert_eq!(data, plaintext);
    }

    /// NIST SP 800-38A, F.4.3 OFB-AES192.Encrypt and F.4.4 OFB-AES192.Decrypt.
    #[test]
    fn ofb_aes192_sp800_38a() {
        let plaintext = sp800_38a_blocks(&SP800_38A_PLAINTEXT);
        let expected = sp800_38a_blocks(&[
            "cdc80d6fddf18cab34c25909c99a4174",
            "fcc28b8d4c63837c09e81700c1100401",
            "8d9a9aeac0f6596f559c6d4daf59a5f2",
            "6d9f200857ca6c3e9cac524bd9acc92a",
        ]);
        let iv = decode_hex_array::<16>(SP800_38A_IV);
        let mode = Ofb::new(Aes192::new(&decode_hex_array::<24>(SP800_38A_AES192_KEY)));
        let mut data = plaintext.clone();
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&iv, &mut data);
        assert_eq!(data, plaintext);
    }

    /// NIST SP 800-38A, F.5.3 CTR-AES192.Encrypt and F.5.4 CTR-AES192.Decrypt.
    #[test]
    fn ctr_aes192_sp800_38a() {
        let plaintext = sp800_38a_blocks(&SP800_38A_PLAINTEXT);
        let expected = sp800_38a_blocks(&[
            "1abc932417521ca24f2b0459fe7e6e0b",
            "090339ec0aa6faefd5ccc2c6f4ce8e94",
            "1e36b26bd1ebc670d1bd1d665620abf7",
            "4f78a7f6d29809585a97daec58c6b050",
        ]);
        let ctr = decode_hex_array::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mode = Ctr::new(Aes192::new(&decode_hex_array::<24>(SP800_38A_AES192_KEY)));
        let mut data = plaintext.clone();
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(data, expected);
        mode.apply_keystream(&ctr, &mut data);
        assert_eq!(data, plaintext);
    }

    /// NIST SP 800-38A, F.3.9 CFB8-AES192.Encrypt and F.3.10 CFB8-AES192.Decrypt
    /// (the standard prints 18 segments).
    #[test]
    fn cfb8_aes192_sp800_38a() {
        let plaintext = decode_hex("6bc1bee22e409f96e93d7e117393172aae2d");
        let expected = decode_hex("cda2521ef0a905ca44cd057cbf0d47a0678a");
        let iv = decode_hex_array::<16>(SP800_38A_IV);
        let mode = Cfb8::new(Aes192::new(&decode_hex_array::<24>(SP800_38A_AES192_KEY)));
        let mut data = plaintext.clone();
        mode.encrypt(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt(&iv, &mut data);
        assert_eq!(data, plaintext);
    }

    /// NIST SP 800-38A, F.3.11 CFB8-AES256.Encrypt and F.3.12 CFB8-AES256.Decrypt
    /// (the standard prints 18 segments).
    #[test]
    fn cfb8_aes256_sp800_38a() {
        let plaintext = decode_hex("6bc1bee22e409f96e93d7e117393172aae2d");
        let expected = decode_hex("dc1f1a8520a64db55fcc8ac554844e889700");
        let iv = decode_hex_array::<16>(SP800_38A_IV);
        let mode = Cfb8::new(Aes256::new(&decode_hex_array::<32>(SP800_38A_AES256_KEY)));
        let mut data = plaintext.clone();
        mode.encrypt(&iv, &mut data);
        assert_eq!(data, expected);
        mode.decrypt(&iv, &mut data);
        assert_eq!(data, plaintext);
    }

    /// SP 800-38E §4: a data unit is at most 2^20 blocks.
    #[test]
    fn xts_data_unit_bound_is_2_20_blocks() {
        assert_eq!(XTS_MAX_DATA_UNIT_BLOCKS, 1 << 20);
        assert!(xts_data_unit_len_allowed(16));
        assert!(xts_data_unit_len_allowed(XTS_MAX_DATA_UNIT_BLOCKS * 16));
        assert!(!xts_data_unit_len_allowed(
            XTS_MAX_DATA_UNIT_BLOCKS * 16 + 1
        ));
    }

    #[test]
    #[should_panic(expected = "XTS data unit too long")]
    fn xts_encrypt_refuses_data_unit_longer_than_2_20_blocks() {
        let mode = Xts::new(Aes128::new(&[0u8; 16]), Aes128::new(&[1u8; 16]));
        let mut data = vec![0u8; XTS_MAX_DATA_UNIT_BLOCKS * 16 + 1];
        mode.encrypt_sector(&[0u8; 16], &mut data);
    }

    #[test]
    #[should_panic(expected = "XTS data unit too long")]
    fn xts_decrypt_refuses_data_unit_longer_than_2_20_blocks() {
        let mode = Xts::new(Aes128::new(&[0u8; 16]), Aes128::new(&[1u8; 16]));
        let mut data = vec![0u8; XTS_MAX_DATA_UNIT_BLOCKS * 16 + 1];
        mode.decrypt_sector(&[0u8; 16], &mut data);
    }

    /// SP 800-38C Appendix C prints `B` (whose first block is B0) and `Ctr0`
    /// for nonces of 7, 8, 12 and 13 bytes, that is L = 8, 7, 3 and 2, with
    /// Tlen 32, 48, 64 and 112 bits and the associated-data flag set.
    #[test]
    fn ccm_b0_and_ctr0_match_sp800_38c_appendix_c() {
        // (nonce, payload length, AAD length, tag length, B0, Ctr0)
        let examples = [
            (
                "10111213141516",
                4,
                8,
                4,
                "4f101112131415160000000000000004",
                "07101112131415160000000000000000",
            ),
            (
                "1011121314151617",
                16,
                16,
                6,
                "56101112131415161700000000000010",
                "06101112131415161700000000000000",
            ),
            (
                "101112131415161718191a1b",
                24,
                20,
                8,
                "5a101112131415161718191a1b000018",
                "02101112131415161718191a1b000000",
            ),
            (
                "101112131415161718191a1b1c",
                32,
                65536,
                14,
                "71101112131415161718191a1b1c0020",
                "01101112131415161718191a1b1c0000",
            ),
        ];
        for (nonce, plen, alen, tlen, b0, ctr0) in examples {
            let nonce = decode_hex(nonce);
            assert_eq!(
                ccm_b0(&nonce, plen, alen, tlen).to_vec(),
                decode_hex(b0),
                "B0 for a {}-byte nonce",
                nonce.len()
            );
            assert_eq!(
                ccm_counter_block(&nonce, 0).to_vec(),
                decode_hex(ctr0),
                "Ctr0 for a {}-byte nonce",
                nonce.len()
            );
        }
    }

    /// SP 800-38C Appendix A.2.1 formatting for every L from 2 to 8: the
    /// flags octet, the nonce placement, and the payload length in the last
    /// L octets, at the largest length L octets can hold.
    #[test]
    fn ccm_formatting_for_every_l() {
        for nonce_len in 7..=13usize {
            let l = 15 - nonce_len;
            let nonce: Vec<u8> = (1..=nonce_len).map(|i| i as u8).collect();
            let max_len = if l >= 8 {
                u64::MAX
            } else {
                (1u64 << (8 * l)) - 1
            };
            let max_len_usize = usize::try_from(max_len).unwrap_or(usize::MAX);

            let b0 = ccm_b0(&nonce, max_len_usize, 0, 16);
            // Flags: Reserved(0) || Adata(0) || [(t-2)/2]_3 || [q-1]_3.
            assert_eq!(b0[0], (7 << 3) | (l as u8 - 1), "L = {l} flags");
            assert_eq!(&b0[1..1 + nonce_len], nonce.as_slice(), "L = {l} nonce");
            let mut q_field = [0u8; 8];
            q_field[8 - l..].copy_from_slice(&b0[16 - l..]);
            assert_eq!(
                u64::from_be_bytes(q_field),
                u64::try_from(max_len_usize).expect("usize")
            );

            let ctr = ccm_counter_block(&nonce, 1);
            assert_eq!(ctr[0], l as u8 - 1, "L = {l} counter flags");
            assert_eq!(&ctr[1..1 + nonce_len], nonce.as_slice());
            assert!(ctr[1 + nonce_len..15].iter().all(|&b| b == 0));
            assert_eq!(ctr[15], 1);
        }
    }

    /// The length field holds `2^(8L) − 1` and refuses `2^(8L)` for every
    /// L below 8; at L = 8 every `u64` fits and the shift guard must not be
    /// evaluated (a shift by 64 would overflow).
    #[test]
    fn ccm_pack_len_guard_at_every_l() {
        for l in 2..8usize {
            let mut block = [0u8; 16];
            ccm_pack_len(&mut block, l, (1u64 << (8 * l)) - 1);
            assert!(block[16 - l..].iter().all(|&b| b == 0xff), "L = {l}");
            assert!(block[..16 - l].iter().all(|&b| b == 0), "L = {l}");
            let overflow = std::panic::catch_unwind(|| {
                let mut block = [0u8; 16];
                ccm_pack_len(&mut block, l, 1u64 << (8 * l));
            });
            assert!(overflow.is_err(), "L = {l} accepted 2^(8L)");
        }
        let mut block = [0u8; 16];
        ccm_pack_len(&mut block, 8, u64::MAX);
        assert_eq!(block.to_vec(), [[0u8; 8], [0xffu8; 8]].concat());
    }

    /// SP 800-38C A.2.2: an AAD of fewer than 2^16 − 2^8 octets is prefixed
    /// with its 2-octet length; from 2^16 − 2^8 up to 2^32 − 1 with
    /// `0xff 0xfe` and a 4-octet length.
    #[test]
    fn ccm_aad_length_encoding_thresholds() {
        let short = vec![0x5au8; (1 << 16) - (1 << 8) - 1];
        let encoded = ccm_encode_aad(&short);
        assert_eq!(&encoded[..2], &[0xfe, 0xff]);
        assert_eq!(&encoded[2..2 + short.len()], short.as_slice());
        assert!(encoded.len().is_multiple_of(16));

        let long = vec![0xa5u8; (1 << 16) - (1 << 8)];
        let encoded = ccm_encode_aad(&long);
        assert_eq!(&encoded[..6], &[0xff, 0xfe, 0x00, 0x00, 0xff, 0x00]);
        assert_eq!(&encoded[6..6 + long.len()], long.as_slice());
        assert!(encoded.len().is_multiple_of(16));
    }
}
