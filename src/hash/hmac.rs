//! Hash-based Message Authentication Code (HMAC).
//!
//! This is the standard HMAC construction from FIPS 198-1 / RFC 2104, layered
//! over any fixed-output hash that implements [`crate::hash::Digest`].

use super::Digest;

/// Streaming HMAC state over an arbitrary in-tree digest.
///
/// `Clone` captures the keyed inner/outer states after ipad/opad absorption, so
/// callers that authenticate many messages under one key (e.g. HKDF-Expand) can
/// derive the key schedule once and clone it per message instead of rebuilding
/// it every time.
#[derive(Clone)]
pub struct Hmac<H: Digest> {
    inner: H,
    outer: H,
}

impl<H: Digest> Hmac<H> {
    /// Build the RFC 2104 / FIPS 198-1 keyed inner and outer hash states.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = vec![0u8; H::BLOCK_LEN];
        if key.len() > H::BLOCK_LEN {
            // HMAC hashes oversize keys down to one digest-width block first so
            // the actual ipad/opad processing always starts from exactly one
            // block of key material, regardless of caller input length.
            //
            // Use an explicit hasher and `finalize_reset` rather than the
            // consuming `H::digest`: the `Digest` contract is that
            // `finalize_reset` scrubs the key-derived state as it produces
            // the digest, whether or not the implementation also wipes on
            // drop, and the digest lands in a buffer this code wipes.
            let mut h = H::new();
            h.update(key);
            let mut digest = vec![0u8; H::OUTPUT_LEN];
            h.finalize_reset(&mut digest);
            key_block[..H::OUTPUT_LEN].copy_from_slice(&digest);
            crate::ct::zeroize_slice(digest.as_mut_slice());
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = key_block.clone();
        let mut opad = key_block;
        for b in &mut ipad {
            *b ^= 0x36;
        }
        for b in &mut opad {
            *b ^= 0x5c;
        }

        let mut inner = H::new();
        inner.update(&ipad);
        let mut outer = H::new();
        outer.update(&opad);

        crate::ct::zeroize_slice(ipad.as_mut_slice());
        crate::ct::zeroize_slice(opad.as_mut_slice());

        Self { inner, outer }
    }

    /// Absorb more message bytes into the keyed inner hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[must_use]
    /// Finalize the MAC and return the authentication tag.
    pub fn finalize(self) -> Vec<u8> {
        let mut out = vec![0u8; H::OUTPUT_LEN];
        self.finalize_into(&mut out);
        out
    }

    /// Finalize the MAC into a caller-provided buffer of `H::OUTPUT_LEN`
    /// bytes, avoiding the return-value allocation of [`Self::finalize`].
    ///
    /// # Panics
    ///
    /// Panics if `out.len() != H::OUTPUT_LEN`.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), H::OUTPUT_LEN, "HMAC output buffer length");
        let mut inner_digest = vec![0u8; H::OUTPUT_LEN];
        // `finalize_reset` produces the standard inner digest and scrubs the
        // keyed hash state as it does so, instead of leaving the ipad-derived
        // chaining value behind until drop.
        self.inner.finalize_reset(&mut inner_digest);
        self.outer.update(&inner_digest);
        self.outer.finalize_reset(out);
        crate::ct::zeroize_slice(inner_digest.as_mut_slice());
    }

    #[must_use]
    /// Compute an HMAC tag in one shot.
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Self::new(key);
        mac.update(data);
        mac.finalize()
    }

    #[must_use]
    /// Compute and compare the tag in constant time.
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        // Compute the genuine tag into a local so it can be wiped: otherwise the
        // valid tag for an attacker-chosen message would be freed unscrubbed.
        let mut expected = Self::compute(key, data);
        let ok = crate::ct::constant_time_eq_mask(&expected, tag) == u8::MAX;
        crate::ct::zeroize_slice(expected.as_mut_slice());
        ok
    }
}

impl<H: Digest> Drop for Hmac<H> {
    fn drop(&mut self) {
        self.inner.zeroize();
        self.outer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::encode_hex;
    use crate::{Sha256, Sha3_256, Sha3_512, Sha512};

    /// HMAC-SHA3-256 of "The quick brown fox jumps over the lazy dog" under the
    /// key "key". This is a regression value, not a published known answer:
    /// NIST's HMAC-SHA3 example values use other keys and messages, and no
    /// primary publication of this pair was found. The same input is
    /// cross-checked against OpenSSL by `hmac_sha3_256_matches_openssl`.
    #[test]
    fn hmac_sha3_256_regression_vector() {
        let tag = Hmac::<Sha3_256>::compute(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            encode_hex(&tag),
            "8c6e0683409427f8931711b10ca92a50".to_owned() + "6eb1fafa48fadd66d76126f47ac2c333"
        );
    }

    /// HMAC-SHA3-512 over the same key and message. A regression value
    /// produced by this implementation; no published source was found, and no
    /// OpenSSL cross-check covers SHA3-512 here.
    #[test]
    fn hmac_sha3_512_regression_vector() {
        let tag = Hmac::<Sha3_512>::compute(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            encode_hex(&tag),
            "237a35049c40b3ef5ddd960b3dc893d8".to_owned()
                + "284953b9a4756611b1b61bffcf53edd9"
                + "79f93547db714b06ef0a692062c609b7"
                + "0208ab8d4a280ceee40ed8100f293063"
        );
    }

    #[test]
    fn hmac_sha3_256_streaming_matches_one_shot() {
        let key = (0u8..32).collect::<Vec<_>>();
        let expected = Hmac::<Sha3_256>::compute(&key, b"abc");

        let mut mac = Hmac::<Sha3_256>::new(&key);
        mac.update(b"a");
        mac.update(b"b");
        mac.update(b"c");
        let got = mac.finalize();

        assert_eq!(got, expected);
        assert_eq!(
            encode_hex(&got),
            "632f618ac17ba24355d9ee1fd187cf75".to_owned() + "bb5b68e6948804bf6674bf5ee7f1c345"
        );
        assert!(Hmac::<Sha3_256>::verify(&key, b"abc", &got));
    }

    #[test]
    fn hmac_sha3_256_matches_openssl() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(
            &[
                "dgst",
                "-sha3-256",
                "-mac",
                "HMAC",
                "-macopt",
                "hexkey:6b6579",
                "-binary",
            ],
            msg,
        )
        .or_skip("hmac_sha3_256_matches_openssl") else {
            return;
        };

        let tag = Hmac::<Sha3_256>::compute(key, msg);
        assert_eq!(tag, expected);
    }

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let tag = Hmac::<Sha256>::compute(&key, b"Hi There");
        assert_eq!(
            encode_hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b".to_owned() + "881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let tag = Hmac::<Sha256>::compute(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            encode_hex(&tag),
            "5bdcc146bf60754e6a042426089575c7".to_owned() + "5a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let tag = Hmac::<Sha256>::compute(&key, &data);
        assert_eq!(
            encode_hex(&tag),
            "773ea91e36800e46854db8ebd09181a7".to_owned() + "2959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case4() {
        let key = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let data = [0xcdu8; 50];
        let tag = Hmac::<Sha256>::compute(&key, &data);
        assert_eq!(
            encode_hex(&tag),
            "82558a389a443c0ea4cc819899f2083a".to_owned() + "85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    /// RFC 4231 §4.6, Test Case 5, publishes only the leftmost 128 bits of
    /// the output. `verify` compares full-length tags only, so the published
    /// truncation is refused rather than matched as a prefix; this crate
    /// offers no truncated-tag comparison.
    #[test]
    fn hmac_sha256_rfc4231_case5_truncated() {
        let key = [0x0cu8; 20];
        let tag = Hmac::<Sha256>::compute(&key, b"Test With Truncation");
        assert_eq!(encode_hex(&tag[..16]), "a3b6167473100ee06e0c796c2955552b");
        assert!(!Hmac::<Sha256>::verify(
            &key,
            b"Test With Truncation",
            &tag[..16]
        ));
        assert!(Hmac::<Sha256>::verify(&key, b"Test With Truncation", &tag));
    }

    /// `verify` accepts exactly one byte string per key and message: the
    /// full tag. Every single-bit corruption, every proper prefix (the empty
    /// tag included), an over-long tag, and the genuine tag under another key
    /// or for another message are refused.
    fn verify_refuses_every_wrong_tag<H: Digest>(label: &str) {
        let key = b"an HMAC key shorter than one block";
        let msg = b"the message being authenticated";
        let tag = Hmac::<H>::compute(key, msg);
        assert_eq!(tag.len(), H::OUTPUT_LEN, "{label}: tag length");
        assert!(
            Hmac::<H>::verify(key, msg, &tag),
            "{label}: the genuine tag"
        );

        for bit in 0..tag.len() * 8 {
            let mut flipped = tag.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(
                !Hmac::<H>::verify(key, msg, &flipped),
                "{label}: bit {bit} flipped"
            );
        }
        for len in 0..tag.len() {
            assert!(
                !Hmac::<H>::verify(key, msg, &tag[..len]),
                "{label}: {len}-byte prefix of the tag"
            );
        }
        let mut long = tag.clone();
        long.push(0);
        assert!(
            !Hmac::<H>::verify(key, msg, &long),
            "{label}: tag with a trailing byte"
        );
        let doubled = [tag.as_slice(), tag.as_slice()].concat();
        assert!(
            !Hmac::<H>::verify(key, msg, &doubled),
            "{label}: doubled tag"
        );
        assert!(!Hmac::<H>::verify(key, msg, &[]), "{label}: empty tag");
        assert!(
            !Hmac::<H>::verify(b"another key", msg, &tag),
            "{label}: another key"
        );
        assert!(
            !Hmac::<H>::verify(key, b"another message", &tag),
            "{label}: another message"
        );
    }

    #[test]
    fn hmac_sha256_verify_refuses_every_wrong_tag() {
        verify_refuses_every_wrong_tag::<Sha256>("HMAC-SHA-256");
    }

    #[test]
    fn hmac_sha512_verify_refuses_every_wrong_tag() {
        verify_refuses_every_wrong_tag::<Sha512>("HMAC-SHA-512");
    }

    #[test]
    fn hmac_sha3_256_verify_refuses_every_wrong_tag() {
        verify_refuses_every_wrong_tag::<Sha3_256>("HMAC-SHA3-256");
    }

    #[test]
    fn hmac_sha256_rfc4231_case6() {
        let key = [0xaau8; 131];
        let tag = Hmac::<Sha256>::compute(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            encode_hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f".to_owned() + "8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case7() {
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let tag = Hmac::<Sha256>::compute(&key, data);
        assert_eq!(
            encode_hex(&tag),
            "9b09ffa71b942fcb27635fbcd5b0e944".to_owned() + "bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn hmac_sha256_matches_openssl() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::test_utils::openssl(
            &[
                "dgst",
                "-sha256",
                "-mac",
                "HMAC",
                "-macopt",
                "hexkey:6b6579",
                "-binary",
            ],
            msg,
        )
        .or_skip("hmac_sha256_matches_openssl") else {
            return;
        };

        let tag = Hmac::<Sha256>::compute(key, msg);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }
}
