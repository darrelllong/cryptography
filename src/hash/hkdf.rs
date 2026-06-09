//! HKDF (RFC 5869) over the crate's digest/HMAC traits.
//!
//! This module exposes the two standard stages:
//! - extract: `PRK = HMAC(salt, IKM)`
//! - expand: `OKM = T(1) || T(2) || ...`
//!
//! The implementation is generic over any fixed-output digest `H` that
//! implements [`crate::hash::Digest`].

use core::marker::PhantomData;

use super::hmac::Hmac;
use super::Digest;

/// HKDF key schedule state holding one pseudorandom key (PRK).
pub struct Hkdf<H: Digest> {
    prk: Vec<u8>,
    marker: PhantomData<H>,
}

impl<H: Digest> Hkdf<H> {
    /// Extract one pseudorandom key from input keying material.
    ///
    /// If `salt` is `None`, RFC 5869 uses a digest-length all-zero salt.
    #[must_use]
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let zero_salt;
        let salt = match salt {
            Some(salt) => salt,
            None => {
                zero_salt = vec![0u8; H::OUTPUT_LEN];
                &zero_salt
            }
        };
        let prk = Hmac::<H>::compute(salt, ikm);
        Self {
            prk,
            marker: PhantomData,
        }
    }

    /// Build an HKDF state from a previously extracted PRK.
    ///
    /// RFC 5869 defines PRK as one digest-width string.
    #[must_use]
    pub fn from_prk(prk: &[u8]) -> Option<Self> {
        if prk.len() != H::OUTPUT_LEN {
            return None;
        }
        Some(Self {
            prk: prk.to_vec(),
            marker: PhantomData,
        })
    }

    /// Return the extracted pseudorandom key.
    #[must_use]
    pub fn prk(&self) -> &[u8] {
        &self.prk
    }

    /// Expand into `out` with caller-supplied context `info`.
    ///
    /// Returns `false` if `out` exceeds `255 * H::OUTPUT_LEN`, as required by
    /// RFC 5869.
    #[must_use]
    pub fn expand(&self, info: &[u8], out: &mut [u8]) -> bool {
        let max = 255usize
            .checked_mul(H::OUTPUT_LEN)
            .expect("digest output length should keep HKDF max bounded");
        if out.len() > max {
            return false;
        }

        // T(i) is streamed directly into the keyed HMAC and written into one
        // reused buffer — no per-round concatenation or allocation churn.
        let mut t = vec![0u8; H::OUTPUT_LEN];
        let mut generated = 0usize;
        let mut counter = 1u8;

        while generated < out.len() {
            let mut mac = Hmac::<H>::new(&self.prk);
            if counter > 1 {
                mac.update(&t);
            }
            mac.update(info);
            mac.update(&[counter]);
            mac.finalize_into(&mut t);

            let take = core::cmp::min(out.len() - generated, t.len());
            out[generated..generated + take].copy_from_slice(&t[..take]);
            generated += take;
            counter = counter.wrapping_add(1);
        }

        crate::ct::zeroize_slice(t.as_mut_slice());
        true
    }

    /// Convenience one-shot HKDF (extract + expand).
    #[must_use]
    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
        let hkdf = Self::extract(salt, ikm);
        let mut out = vec![0u8; len];
        if !hkdf.expand(info, &mut out) {
            return None;
        }
        Some(out)
    }
}

impl<H: Digest> Drop for Hkdf<H> {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.prk.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::Hkdf;
    use crate::{Sha1, Sha256};

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    fn unhex(input: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    #[test]
    fn rfc5869_case_1_sha256() {
        let ikm = vec![0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");

        let hkdf = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            hex(hkdf.prk()),
            "077709362c2e32df0ddc3f0dc47bba63".to_owned() + "90b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let mut okm = vec![0u8; 42];
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a".to_owned()
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865"
        );
    }

    #[test]
    fn rfc5869_case_2_sha256_long_inputs() {
        let ikm = unhex(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = unhex(
            "606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = unhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );

        let hkdf = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            hex(hkdf.prk()),
            "06a6b88c5853361a06104c9ceb35b45c".to_owned() + "ef760014904671014a193f40c15fc244"
        );

        let mut okm = vec![0u8; 82];
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "b11e398dc80327a1c8e7f78c596a4934".to_owned()
                + "4f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09"
                + "da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f"
                + "1d87"
        );
    }

    #[test]
    fn rfc5869_case_3_sha256_zero_salt() {
        let ikm = vec![0x0b; 22];
        let info = [];
        let mut okm = vec![0u8; 42];
        let hkdf = Hkdf::<Sha256>::extract(None, &ikm);
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31".to_owned()
                + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                + "9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn rfc5869_case_4_sha1() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b");
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");

        let hkdf = Hkdf::<Sha1>::extract(Some(&salt), &ikm);
        assert_eq!(hex(hkdf.prk()), "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243");

        let mut okm = vec![0u8; 42];
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "085a01ea1b10f36933068b56efa5ad81".to_owned()
                + "a4f14b822f5b091568a9cdd4f155fda2"
                + "c22e422478d305f3f896"
        );
    }

    #[test]
    fn rfc5869_case_5_sha1_long_inputs() {
        let ikm = unhex(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = unhex(
            "606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = unhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );

        let hkdf = Hkdf::<Sha1>::extract(Some(&salt), &ikm);
        assert_eq!(hex(hkdf.prk()), "8adae09a2a307059478d309b26c4115a224cfaf6");

        let mut okm = vec![0u8; 82];
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "0bd770a74d1160f7c9f12cd5912a06eb".to_owned()
                + "ff6adcae899d92191fe4305673ba2ffe"
                + "8fa3f1a4e5ad79f3f334b3b202b2173c"
                + "486ea37ce3d397ed034c7f9dfeb15c5e"
                + "927336d0441f4c4300e2cff0d0900b52"
                + "d3b4"
        );
    }

    #[test]
    fn rfc5869_case_6_sha1_zero_salt_info() {
        let ikm = vec![0x0b; 22];
        let info = [];

        let hkdf = Hkdf::<Sha1>::extract(Some(&[]), &ikm);
        assert_eq!(hex(hkdf.prk()), "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01");

        let mut okm = vec![0u8; 42];
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "0ac1af7002b3d761d1e55298da9d0506".to_owned()
                + "b9ae52057220a306e07b6b87e8df21d0"
                + "ea00033de03984d34918"
        );
    }

    #[test]
    fn rfc5869_case_7_sha1_no_salt() {
        let ikm = vec![0x0c; 22];
        let info = [];

        let hkdf = Hkdf::<Sha1>::extract(None, &ikm);
        assert_eq!(hex(hkdf.prk()), "2adccada18779e7c2077ad2eb19d3f3e731385dd");

        let mut okm = vec![0u8; 42];
        assert!(hkdf.expand(&info, &mut okm));
        assert_eq!(
            hex(&okm),
            "2c91117204d745f3500d636a62f64f0a".to_owned()
                + "b3bae548aa53d423b0d1f27ebba6f5e5"
                + "673a081d70cce7acfc48"
        );
    }

    #[test]
    fn expand_rejects_overlong_output() {
        let hkdf = Hkdf::<Sha256>::extract(Some(&[0x01, 0x02]), b"ikm");
        let mut out = vec![0u8; 255 * 32 + 1];
        assert!(!hkdf.expand(b"info", &mut out));
    }

    #[test]
    fn derive_matches_extract_expand() {
        let salt = b"salt";
        let ikm = b"ikm";
        let info = b"context";
        let direct = Hkdf::<Sha256>::derive(Some(salt), ikm, info, 48).expect("derive");

        let hkdf = Hkdf::<Sha256>::extract(Some(salt), ikm);
        let mut manual = vec![0u8; 48];
        assert!(hkdf.expand(info, &mut manual));
        assert_eq!(direct, manual);
    }
}
