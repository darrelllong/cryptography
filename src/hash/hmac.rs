//! Hash-based Message Authentication Code (HMAC).
//!
//! This is the standard HMAC construction from FIPS 198-1 / RFC 2104, layered
//! over any fixed-output hash that implements [`crate::hash::Digest`].

use super::Digest;

/// Streaming HMAC state over an arbitrary in-tree digest.
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
            let mut digest = H::digest(key);
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
    pub fn finalize(mut self) -> Vec<u8> {
        let mut inner_digest = vec![0u8; H::OUTPUT_LEN];
        // `finalize_reset` is used here for two reasons: it produces the
        // standard inner digest and it actively wipes the live keyed hash state
        // instead of leaving the ipad-derived chaining value behind until drop.
        self.inner.finalize_reset(&mut inner_digest);
        self.outer.update(&inner_digest);
        let mut out = vec![0u8; H::OUTPUT_LEN];
        self.outer.finalize_reset(&mut out);
        crate::ct::zeroize_slice(inner_digest.as_mut_slice());
        out
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
        crate::ct::constant_time_eq_mask(&Self::compute(key, data), tag) == u8::MAX
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
    use crate::{Sha256, Sha3_256, Sha3_512};
    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    #[test]
    fn hmac_sha3_256_known_vector() {
        let tag = Hmac::<Sha3_256>::compute(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex(&tag),
            "8c6e0683409427f8931711b10ca92a50".to_owned() + "6eb1fafa48fadd66d76126f47ac2c333"
        );
    }

    #[test]
    fn hmac_sha3_512_known_vector() {
        let tag = Hmac::<Sha3_512>::compute(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex(&tag),
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
            hex(&got),
            "632f618ac17ba24355d9ee1fd187cf75".to_owned() + "bb5b68e6948804bf6674bf5ee7f1c345"
        );
        assert!(Hmac::<Sha3_256>::verify(&key, b"abc", &got));
    }

    #[test]
    fn hmac_sha3_256_matches_openssl() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::ct::run_openssl(
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
        ) else {
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
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b".to_owned() + "881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_matches_openssl() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let Some(expected) = crate::ct::run_openssl(
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
        ) else {
            return;
        };

        let tag = Hmac::<Sha256>::compute(key, msg);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }
}
