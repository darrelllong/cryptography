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

        let mut t = Vec::<u8>::new();
        let mut generated = 0usize;
        let mut counter = 1u8;

        while generated < out.len() {
            let mut data = Vec::with_capacity(t.len() + info.len() + 1);
            data.extend_from_slice(&t);
            data.extend_from_slice(info);
            data.push(counter);

            t = Hmac::<H>::compute(&self.prk, &data);
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
    use crate::Sha256;

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
