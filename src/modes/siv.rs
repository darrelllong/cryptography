//! Synthetic IV (SIV) authenticated encryption (RFC 5297).
//!
//! This module implements the AES-SIV construction with CMAC-based S2V and
//! CTR encryption. The caller supplies separate block-cipher instances for the
//! CMAC key half and CTR key half.
//!
//! # Limits
//!
//! The CTR counter is advanced by 32-bit addition (RFC 5297 §2.5 and §5), so a
//! plaintext or ciphertext may be at most [`MAX_PLAINTEXT_BYTES`] bytes, and
//! S2V accepts at most [`MAX_AD_COMPONENTS`] associated-data components. The
//! encrypt methods panic outside these limits; the decrypt methods return
//! `false`, since the lengths on that path are attacker-controlled.

use super::{
    assert_block_128, dbl_block, increment_be32, xor_block16_in_place, xor_in_place, Cmac,
};
use crate::BlockCipher;

/// Block length of the 128-bit block ciphers SIV uses, in bytes
/// (RFC 5297 §1: AES with 128-bit blocks).
const BLOCK_BYTES: usize = 16;

/// The longest plaintext SIV-AES protects when the counter is advanced by
/// 32-bit addition, in bytes: 2^36 − 16 (`68_719_476_720`).
///
/// RFC 5297 §2.5: "Performing 32-bit or 64-bit addition on the counter will
/// limit the amount of plaintext that can be safely protected by SIV-AES to
/// 2^39 - 128 bits or 2^71 - 128 bits, respectively." This module's CTR increments
/// the rightmost 32 bits of the counter, so the 2^39 − 128 bit figure applies
/// to every message this module encrypts or decrypts.
pub const MAX_PLAINTEXT_BYTES: u64 = ((1u64 << 39) - 128) / 8;

/// The most associated-data components one SIV call accepts.
///
/// RFC 5297 §2.6 and §2.7 take "a vector of associated data AD[ ] where the
/// number of components in the vector is not greater than 126 (see Section
/// 7)": §7 limits S2V to 127 components because its security proof needs
/// fewer components than the 128-bit block size, and the plaintext is the
/// last of them.
pub const MAX_AD_COMPONENTS: usize = 126;

#[inline]
fn plaintext_len_allowed(len: usize) -> bool {
    u64::try_from(len).is_ok_and(|len| len <= MAX_PLAINTEXT_BYTES)
}

/// RFC 5297 §2.4 S2V with `plaintext` as the final component.
///
/// On the decrypt path `plaintext` is not authenticated yet, so the padded or
/// xor-ended copy S2V builds from it is wiped, together with the chaining value
/// `D` and the per-component MAC block.
fn s2v<C: BlockCipher>(mac: &Cmac<C>, components: &[&[u8]], plaintext: &[u8]) -> [u8; BLOCK_BYTES] {
    assert_block_128::<C>();
    debug_assert!(components.len() <= MAX_AD_COMPONENTS);
    let mut d = [0u8; BLOCK_BYTES];
    mac.compute_into(&[0u8; BLOCK_BYTES], &mut d);
    let mut component_mac = [0u8; BLOCK_BYTES];
    for component in components {
        mac.compute_into(component, &mut component_mac);
        d = dbl_block(d);
        xor_block16_in_place(&mut d, &component_mac);
    }

    let mut v = [0u8; BLOCK_BYTES];
    if plaintext.len() >= BLOCK_BYTES {
        // T = S_n xorend D.
        let mut t = plaintext.to_vec();
        let start = t.len() - BLOCK_BYTES;
        xor_in_place(&mut t[start..], &d);
        mac.compute_into(&t, &mut v);
        crate::ct::zeroize_slice(t.as_mut_slice());
    } else {
        // T = dbl(D) xor pad(S_n).
        let mut t = [0u8; BLOCK_BYTES];
        t[..plaintext.len()].copy_from_slice(plaintext);
        t[plaintext.len()] = 0x80;
        xor_block16_in_place(&mut t, &dbl_block(d));
        mac.compute_into(&t, &mut v);
        crate::ct::zeroize_slice(t.as_mut_slice());
    }
    crate::ct::zeroize_slice(d.as_mut_slice());
    crate::ct::zeroize_slice(component_mac.as_mut_slice());
    v
}

#[inline]
fn clear_siv_ctr_bits(counter: &mut [u8; BLOCK_BYTES]) {
    // RFC 5297 §2.6: Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31), that
    // is bits 63 and 31 (the rightmost bit being bit 0) are cleared.
    counter[8] &= 0x7f;
    counter[12] &= 0x7f;
}

/// CTR over `data` from the S2V-derived counter, incrementing its rightmost
/// 32 bits (RFC 5297 §2.5, "X+i = SALT || (n + i mod 2^32)"). The keystream
/// and counter blocks are wiped afterwards.
fn ctr_apply<C: BlockCipher>(cipher: &C, initial_counter: &[u8; BLOCK_BYTES], data: &mut [u8]) {
    debug_assert!(plaintext_len_allowed(data.len()));
    let mut counter = *initial_counter;
    let mut stream = [0u8; BLOCK_BYTES];
    for chunk in data.chunks_mut(BLOCK_BYTES) {
        stream = counter;
        cipher.encrypt(&mut stream);
        xor_in_place(chunk, &stream[..chunk.len()]);
        increment_be32(&mut counter);
    }
    crate::ct::zeroize_slice(stream.as_mut_slice());
    crate::ct::zeroize_slice(counter.as_mut_slice());
}

/// RFC 5297 SIV construction parameterized by two block-cipher instances.
///
/// # Nonce reuse
///
/// SIV is misuse-resistant: encryption is deterministic, so repeating a nonce
/// (or omitting one) only reveals whether two messages are identical. It does
/// not leak plaintext contents or authentication keys. Unique nonces are
/// still preferred.
///
/// # Limits
///
/// A message is at most [`MAX_PLAINTEXT_BYTES`] bytes (RFC 5297 §2.5, 32-bit
/// counter addition) and carries at most [`MAX_AD_COMPONENTS`] associated-data
/// components (§2.6, §2.7, §7). Encryption panics beyond either limit;
/// decryption returns `false`.
pub struct Siv<C> {
    // S2V is a chain of CMACs under one key: the `Cmac` derives its subkeys once.
    mac: Cmac<C>,
    ctr_cipher: C,
}

impl<C> Siv<C> {
    /// Borrow the CMAC-side cipher.
    pub fn mac_cipher(&self) -> &C {
        self.mac.cipher()
    }

    /// Borrow the CTR-side cipher.
    pub fn ctr_cipher(&self) -> &C {
        &self.ctr_cipher
    }
}

impl<C: BlockCipher> Siv<C> {
    /// Construct from separate CMAC and CTR ciphers.
    ///
    /// The CMAC subkeys every S2V computation uses are derived here, once,
    /// and wiped when the `Siv` is dropped.
    pub fn new(mac_cipher: C, ctr_cipher: C) -> Self {
        Self {
            mac: Cmac::new(mac_cipher),
            ctr_cipher,
        }
    }

    /// Encrypt using an explicit ordered vector of associated-data components
    /// (RFC 5297 §2.6, `SIV-ENCRYPT(K, P, AD1, ..., ADn)`).
    ///
    /// # Panics
    ///
    /// Panics if the cipher block is not 128 bits, if `components` holds more
    /// than [`MAX_AD_COMPONENTS`] entries, or if `plaintext` is longer than
    /// [`MAX_PLAINTEXT_BYTES`].
    pub fn encrypt_with_components(
        &self,
        components: &[&[u8]],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; BLOCK_BYTES]) {
        assert!(
            components.len() <= MAX_AD_COMPONENTS,
            "SIV accepts at most {MAX_AD_COMPONENTS} associated-data components (RFC 5297 section 7)"
        );
        assert!(
            plaintext_len_allowed(plaintext.len()),
            "SIV plaintext too large: at most {MAX_PLAINTEXT_BYTES} bytes with 32-bit counter addition (RFC 5297 section 2.5)"
        );
        let tag = s2v(&self.mac, components, plaintext);
        let mut counter = tag;
        clear_siv_ctr_bits(&mut counter);

        let mut ciphertext = plaintext.to_vec();
        ctr_apply(&self.ctr_cipher, &counter, &mut ciphertext);
        (ciphertext, tag)
    }

    /// Decrypt/authenticate using an explicit vector of associated-data
    /// components (RFC 5297 §2.7, `SIV-DECRYPT(K, Z, AD1, ..., ADn)`).
    ///
    /// Returns `false` and leaves `ciphertext` unchanged when the tag does not
    /// verify, when `components` holds more than [`MAX_AD_COMPONENTS`]
    /// entries, or when `ciphertext` is longer than [`MAX_PLAINTEXT_BYTES`]:
    /// no valid SIV output has either shape, and both counts are under the
    /// sender's control on this path.
    ///
    /// # Panics
    ///
    /// Panics if the cipher block is not 128 bits.
    pub fn decrypt_with_components(
        &self,
        components: &[&[u8]],
        ciphertext: &mut [u8],
        tag: &[u8; BLOCK_BYTES],
    ) -> bool {
        if components.len() > MAX_AD_COMPONENTS || !plaintext_len_allowed(ciphertext.len()) {
            return false;
        }
        let mut counter = *tag;
        clear_siv_ctr_bits(&mut counter);

        let mut plaintext = ciphertext.to_vec();
        ctr_apply(&self.ctr_cipher, &counter, &mut plaintext);
        let mut expected = s2v(&self.mac, components, &plaintext);
        let authentic = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        if authentic {
            ciphertext.copy_from_slice(&plaintext);
        }
        // SIV must decrypt before authenticating (S2V is over plaintext): the
        // heap copy is unauthenticated plaintext on failure and a duplicate on
        // success, and on failure `expected` is a valid tag for attacker input.
        crate::ct::zeroize_slice(&mut plaintext);
        crate::ct::zeroize_slice(&mut expected);
        authentic
    }

    /// Encrypt and return `(ciphertext, detached_tag)`.
    ///
    /// The S2V vector is `[aad, nonce]` when `nonce` is non-empty and `[aad]`
    /// when it is empty. RFC 5297 §3 places the nonce in "the final component
    /// -- i.e., the string immediately preceding the plaintext in the vector
    /// input to S2V", and §4 defines deterministic authenticated encryption
    /// with no nonce component at all; an empty `nonce` selects that mode.
    /// The two arguments are therefore not interchangeable: an empty `aad` is
    /// still a component (S2V folds in the CMAC of the empty string, so
    /// `[b"", nonce]` and `[nonce]` give different tags), while an empty
    /// `nonce` is no component. Other vectors go through
    /// [`Siv::encrypt_with_components`].
    ///
    /// # Panics
    ///
    /// Panics if the cipher block is not 128 bits or if `plaintext` is longer
    /// than [`MAX_PLAINTEXT_BYTES`].
    pub fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; BLOCK_BYTES]) {
        if nonce.is_empty() {
            self.encrypt_with_components(&[aad], plaintext)
        } else {
            self.encrypt_with_components(&[aad, nonce], plaintext)
        }
    }

    /// Authenticate and decrypt in place, with the S2V vector of
    /// [`Siv::encrypt`].
    ///
    /// Returns `false` and leaves `ciphertext` unchanged when the tag does not
    /// verify or when `ciphertext` is longer than [`MAX_PLAINTEXT_BYTES`].
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; BLOCK_BYTES],
    ) -> bool {
        if nonce.is_empty() {
            self.decrypt_with_components(&[aad], ciphertext, tag)
        } else {
            self.decrypt_with_components(&[aad, nonce], ciphertext, tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{plaintext_len_allowed, Siv, MAX_AD_COMPONENTS, MAX_PLAINTEXT_BYTES};
    use crate::test_utils::decode_hex;
    use crate::Aes128;

    #[test]
    fn rfc5297_a1_deterministic_vector() {
        // RFC 5297 Appendix A.1.
        let key = <[u8; 32]>::try_from(decode_hex(
            "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
             f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
        ))
        .expect("key");
        let k1: [u8; 16] = key[..16].try_into().expect("k1");
        let k2: [u8; 16] = key[16..].try_into().expect("k2");
        let aad = decode_hex("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");
        let nonce: [u8; 0] = [];
        let plaintext = decode_hex("11223344 55667788 99aabbcc ddee");
        let expected_tag =
            <[u8; 16]>::try_from(decode_hex("85632d07 c6e8f37f 950acd32 0a2ecc93")).expect("tag");
        let expected_ct = decode_hex("40c02b96 90c4dc04 daef7f6a fe5c");

        let siv = Siv::new(Aes128::new(&k1), Aes128::new(&k2));
        let (ct, tag) = siv.encrypt(&nonce, &aad, &plaintext);
        assert_eq!(tag, expected_tag);
        assert_eq!(ct, expected_ct);

        let mut roundtrip = ct.clone();
        assert!(siv.decrypt(&nonce, &aad, &mut roundtrip, &tag));
        assert_eq!(roundtrip, plaintext);
    }

    #[test]
    fn rfc5297_a2_nonce_based_vector() {
        // RFC 5297 Appendix A.2.
        let key = <[u8; 32]>::try_from(decode_hex(
            "7f7e7d7c 7b7a7978 77767574 73727170
             40414243 44454647 48494a4b 4c4d4e4f",
        ))
        .expect("key");
        let k1: [u8; 16] = key[..16].try_into().expect("k1");
        let k2: [u8; 16] = key[16..].try_into().expect("k2");
        let ad1 = decode_hex(
            "00112233 44556677 8899aabb ccddeeff
             deaddada deaddada ffeeddcc bbaa9988
             77665544 33221100",
        );
        let ad2 = decode_hex("10203040 50607080 90a0");
        let nonce = decode_hex("09f91102 9d74e35b d84156c5 635688c0");
        let plaintext = decode_hex(
            "74686973 20697320 736f6d65 20706c61
             696e7465 78742074 6f20656e 63727970
             74207573 696e6720 5349562d 414553",
        );
        let expected_tag =
            <[u8; 16]>::try_from(decode_hex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f")).expect("tag");
        let expected_ct = decode_hex(
            "cb900f2f ddbe4043 26601965 c889bf17
             dba77ceb 094fa663 b7a3f748 ba8af829
             ea64ad54 4a272e9c 485b62a3 fd5c0d",
        );

        let siv = Siv::new(Aes128::new(&k1), Aes128::new(&k2));
        let (ct, tag) = siv.encrypt_with_components(&[&ad1, &ad2, &nonce], &plaintext);
        assert_eq!(tag, expected_tag);
        assert_eq!(ct, expected_ct);

        let mut roundtrip = ct.clone();
        assert!(siv.decrypt_with_components(&[&ad1, &ad2, &nonce], &mut roundtrip, &tag));
        assert_eq!(roundtrip, plaintext);
    }

    #[test]
    fn tamper_rejected_without_plaintext_commit() {
        let k1 = [0x11u8; 16];
        let k2 = [0x22u8; 16];
        let nonce = [0x33u8; 16];
        let aad = b"aad";
        let plaintext = b"siv plaintext".to_vec();
        let siv = Siv::new(Aes128::new(&k1), Aes128::new(&k2));
        let (mut ct, tag) = siv.encrypt(&nonce, aad, &plaintext);

        ct[0] ^= 1;
        let snapshot = ct.clone();
        assert!(!siv.decrypt(&nonce, aad, &mut ct, &tag));
        assert_eq!(ct, snapshot);
    }

    /// RFC 5297 §2.5: 32-bit counter addition protects at most 2^39 − 128
    /// bits, which is 2^36 − 16 bytes: 2^32 − 1 counter blocks.
    #[test]
    fn plaintext_bound_is_2_39_minus_128_bits() {
        assert_eq!(MAX_PLAINTEXT_BYTES, (1u64 << 36) - 16);
        assert_eq!(MAX_PLAINTEXT_BYTES, ((1u64 << 32) - 1) * 16);
        assert!(plaintext_len_allowed(0));
        if let Ok(max) = usize::try_from(MAX_PLAINTEXT_BYTES) {
            assert!(plaintext_len_allowed(max));
            assert!(!plaintext_len_allowed(max + 1));
        }
    }

    /// RFC 5297 §2.6/§2.7: 126 associated-data components are accepted, and
    /// with the plaintext they make the 127 components §7 allows S2V.
    #[test]
    fn accepts_126_associated_data_components() {
        let siv = Siv::new(Aes128::new(&[0x11u8; 16]), Aes128::new(&[0x22u8; 16]));
        let component = [0xabu8; 3];
        let components = vec![component.as_slice(); MAX_AD_COMPONENTS];
        let plaintext = b"one hundred and twenty-six".to_vec();
        let (mut ct, tag) = siv.encrypt_with_components(&components, &plaintext);
        assert!(siv.decrypt_with_components(&components, &mut ct, &tag));
        assert_eq!(ct, plaintext);
    }

    #[test]
    #[should_panic(expected = "at most 126 associated-data components")]
    fn encrypt_refuses_127_associated_data_components() {
        let siv = Siv::new(Aes128::new(&[0x11u8; 16]), Aes128::new(&[0x22u8; 16]));
        let component = [0xabu8; 3];
        let components = vec![component.as_slice(); MAX_AD_COMPONENTS + 1];
        let _ = siv.encrypt_with_components(&components, b"too many");
    }

    /// The decrypt path answers `false`, not a panic, to a component count
    /// the standard forbids, and leaves the buffer alone.
    #[test]
    fn decrypt_refuses_127_associated_data_components_without_panicking() {
        let siv = Siv::new(Aes128::new(&[0x11u8; 16]), Aes128::new(&[0x22u8; 16]));
        let component = [0xabu8; 3];
        let components = vec![component.as_slice(); MAX_AD_COMPONENTS + 1];
        let mut data = *b"never decrypted";
        let snapshot = data;
        assert!(!siv.decrypt_with_components(&components, &mut data, &[0u8; 16]));
        assert_eq!(data, snapshot);
    }

    /// `encrypt(nonce, aad, p)`: an empty nonce is no S2V component (RFC 5297
    /// §4 deterministic mode), an empty AAD still is one.
    #[test]
    fn empty_nonce_is_absent_but_empty_aad_is_a_component() {
        let siv = Siv::new(Aes128::new(&[0x11u8; 16]), Aes128::new(&[0x22u8; 16]));
        let (nonce, aad, plaintext) = ([0x33u8; 16], b"aad", b"siv plaintext");

        assert_eq!(
            siv.encrypt(&[], aad, plaintext),
            siv.encrypt_with_components(&[aad], plaintext)
        );
        assert_eq!(
            siv.encrypt(&nonce, &[], plaintext),
            siv.encrypt_with_components(&[&[], &nonce], plaintext)
        );
        assert_ne!(
            siv.encrypt(&nonce, &[], plaintext),
            siv.encrypt_with_components(&[&nonce], plaintext)
        );
    }
}
