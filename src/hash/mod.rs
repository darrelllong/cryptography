//! Hash functions, XOFs, and message-authentication helpers.
//!
//! The in-tree hash families currently cover:
//!
//! - RFC 1321 (`Md5`)
//! - FIPS 180-4 (`Sha1`, SHA-2)
//! - FIPS 202 (`Sha3_*`, `Shake*`)
//! - RIPEMD-160 (`Ripemd160`)
//! - FIPS 198-1 / RFC 2104 (`Hmac<H>`)
//! - RFC 5869 (`Hkdf<H>`)
//!
//! The shared traits in this module are the glue that lets one keyed
//! construction (`Hmac<H>`) work across multiple named hash families without
//! reimplementing the HMAC state machine for each one.

/// Minimal trait for fixed-output hash functions that can back HMAC.
///
/// MD5, RIPEMD-160, SHA-1 and SHA-2 are Merkle-Damgard hashes, so their raw
/// outputs inherit the usual length-extension caveat: whoever knows
/// `H(secret || msg)` and the length of `secret` can compute
/// `H(secret || msg || padding || extra)` without knowing `secret`. Use
/// `Hmac<H>` for keyed authentication, or prefer SHA-3 / SHAKE when you
/// specifically want sponge-based hashing semantics.
pub trait Digest: Clone {
    /// Byte-oriented block size used by the Merkle-Damgard or sponge API.
    ///
    /// For SHA-3, this is the Keccak rate in bytes, which is the block size
    /// used by HMAC with the SHA-3 family.
    const BLOCK_LEN: usize;
    /// Digest size in bytes.
    const OUTPUT_LEN: usize;

    /// Create a fresh hashing state.
    fn new() -> Self;

    /// Absorb more input bytes.
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash into `out`.
    ///
    /// The default one-shot `digest(...)` helper below allocates. Prefer the
    /// concrete types' inherent `digest(...)` methods when you know the hash at
    /// compile time and want a fixed-size array.
    ///
    /// # Panics
    ///
    /// Panics if `out.len() != Self::OUTPUT_LEN`.
    fn finalize_into(self, out: &mut [u8]);

    /// Finalize the hash into `out`, scrub the consumed state, and
    /// re-initialize the hasher.
    ///
    /// Afterwards the hasher is indistinguishable from `Self::new()`: the
    /// chaining value is back at the initial value, the block buffer is empty
    /// and the length counter is zero, so it can absorb a second message. The
    /// state that produced the digest is wiped, not merely superseded, which
    /// is what keyed constructions such as `Hmac<H>` rely on: the key-derived
    /// chaining value is gone as soon as the tag is produced rather than
    /// lingering until drop.
    ///
    /// # Panics
    ///
    /// Panics if `out.len() != Self::OUTPUT_LEN`.
    fn finalize_reset(&mut self, out: &mut [u8]);

    /// Zeroize the internal state (chaining value, buffered block, and length
    /// counters). Every digest in this crate also does this when dropped.
    fn zeroize(&mut self);

    /// Convenience helper for one-shot hashing.
    #[must_use]
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        let mut out = vec![0u8; Self::OUTPUT_LEN];
        h.finalize_into(&mut out);
        out
    }
}

/// Minimal trait for extendable-output functions.
///
/// The caller absorbs input incrementally and then squeezes as many output
/// bytes as needed. The first `squeeze(...)` call transitions the XOF into
/// output mode; later calls continue the same output stream.
pub trait Xof {
    /// Absorb more input bytes.
    ///
    /// # Panics
    ///
    /// Panics if called after [`Self::squeeze`]: a sponge cannot absorb more
    /// input once it is in output mode.
    fn update(&mut self, data: &[u8]);

    /// Finalize if needed and squeeze more output.
    ///
    /// The first call transitions the XOF from absorb mode to squeeze mode.
    /// Subsequent calls continue producing output from the same stream. This
    /// models sponge-based XOFs such as SHAKE, where the caller may not know
    /// the required output length up front.
    fn squeeze(&mut self, out: &mut [u8]);
}

pub mod hkdf;
pub mod hmac;
pub mod md5;
pub mod ripemd160;
pub mod sha1;
pub mod sha2;
pub mod sha3;

#[cfg(test)]
mod tests {
    use super::Digest;
    use crate::test_utils::openssl;
    use crate::{
        Md5, Ripemd160, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
        Sha512, Sha512_224, Sha512_256,
    };

    /// The message of `len` bytes every cross-check below hashes: a fixed
    /// non-constant byte pattern, so a block absorbed in the wrong order or
    /// endianness changes the digest.
    fn message(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(7) ^ (i >> 3)) as u8)
            .collect()
    }

    /// Cross-check `H` against `openssl dgst <flag>` at every message length
    /// where the Merkle-Damgard padding changes shape (FIPS 180-4 §5.1, RFC
    /// 1321 §3.1 and §3.2, and RIPEMD-160's identical rule). With a block of
    /// `B` bytes and a length field of `B/8` bytes: at `B - B/8 - 1` the
    /// `0x80` byte and the length both fit in the last message block; at
    /// `B - B/8` the `0x80` byte fits but the length spills into a new
    /// block; at `B - 1` and `B` the `0x80` byte itself lands in the last
    /// byte of the block, and in a fresh block. The same four lengths one
    /// block later exercise the multi-block path. The loud skip when no
    /// `openssl` is available comes from `or_skip`.
    fn matches_openssl_at_padding_boundaries<H: Digest>(flag: &str, test: &str) {
        let block = H::BLOCK_LEN;
        let length_field = block / 8;
        let lengths = [
            block - length_field - 1,
            block - length_field,
            block - 1,
            block,
            2 * block - length_field - 1,
            2 * block - length_field,
            2 * block - 1,
            2 * block,
        ];
        for len in lengths {
            let msg = message(len);
            let Some(expected) = openssl(&["dgst", flag, "-binary"], &msg).or_skip(test) else {
                return;
            };
            assert_eq!(H::digest(&msg), expected, "{test}: {len}-byte message");
            let mut incremental = H::new();
            for byte in &msg {
                incremental.update(core::slice::from_ref(byte));
            }
            let mut out = vec![0u8; H::OUTPUT_LEN];
            incremental.finalize_into(&mut out);
            assert_eq!(out, expected, "{test}: {len}-byte message, byte by byte");
        }
    }

    #[test]
    fn md5_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Md5>(
            "-md5",
            "md5_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn ripemd160_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Ripemd160>(
            "-ripemd160",
            "ripemd160_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha1_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha1>(
            "-sha1",
            "sha1_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha224_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha224>(
            "-sha224",
            "sha224_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha256_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha256>(
            "-sha256",
            "sha256_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha384_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha384>(
            "-sha384",
            "sha384_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha512_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha512>(
            "-sha512",
            "sha512_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha512_224_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha512_224>(
            "-sha512-224",
            "sha512_224_padding_boundaries_match_openssl",
        );
    }

    #[test]
    fn sha512_256_padding_boundaries_match_openssl() {
        matches_openssl_at_padding_boundaries::<Sha512_256>(
            "-sha512-256",
            "sha512_256_padding_boundaries_match_openssl",
        );
    }

    /// `finalize_reset` leaves every digest type a fresh instance: a second
    /// message hashed through the same value equals a fresh one-shot digest,
    /// and the value equals `new()` in every observable way (`Clone` of a
    /// reset hasher and of a fresh one agree on any continuation).
    fn finalize_reset_yields_a_fresh_hasher<H: Digest>(label: &str) {
        let first =
            b"the first message, long enough to cross a block boundary in every family here";
        let second = b"a second message hashed through the same value";
        let mut h = H::new();
        h.update(first);
        let mut out = vec![0u8; H::OUTPUT_LEN];
        h.finalize_reset(&mut out);
        assert_eq!(out, H::digest(first), "{label}: digest before the reset");

        let reset_clone = h.clone();
        h.update(second);
        h.finalize_into(&mut out);
        assert_eq!(out, H::digest(second), "{label}: digest after the reset");

        // A reset hasher continues exactly as a fresh one does, including
        // across a block boundary and a second reset.
        let mut fresh = H::new();
        let mut reset = reset_clone;
        let long = message(3 * H::BLOCK_LEN + 5);
        fresh.update(&long);
        reset.update(&long);
        let mut from_fresh = vec![0u8; H::OUTPUT_LEN];
        let mut from_reset = vec![0u8; H::OUTPUT_LEN];
        fresh.finalize_reset(&mut from_fresh);
        reset.finalize_reset(&mut from_reset);
        assert_eq!(from_fresh, from_reset, "{label}: continuation after reset");
        fresh.update(second);
        reset.update(second);
        fresh.finalize_into(&mut from_fresh);
        reset.finalize_into(&mut from_reset);
        assert_eq!(from_fresh, from_reset, "{label}: after a second reset");
    }

    macro_rules! finalize_reset_tests {
        ($($test:ident: $hash:ty, $label:literal;)*) => {$(
            #[test]
            fn $test() {
                finalize_reset_yields_a_fresh_hasher::<$hash>($label);
            }
        )*};
    }

    finalize_reset_tests! {
        md5_finalize_reset_yields_a_fresh_hasher: Md5, "MD5";
        ripemd160_finalize_reset_yields_a_fresh_hasher: Ripemd160, "RIPEMD-160";
        sha1_finalize_reset_yields_a_fresh_hasher: Sha1, "SHA-1";
        sha224_finalize_reset_yields_a_fresh_hasher: Sha224, "SHA-224";
        sha256_finalize_reset_yields_a_fresh_hasher: Sha256, "SHA-256";
        sha384_finalize_reset_yields_a_fresh_hasher: Sha384, "SHA-384";
        sha512_finalize_reset_yields_a_fresh_hasher: Sha512, "SHA-512";
        sha512_224_finalize_reset_yields_a_fresh_hasher: Sha512_224, "SHA-512/224";
        sha512_256_finalize_reset_yields_a_fresh_hasher: Sha512_256, "SHA-512/256";
        sha3_224_finalize_reset_yields_a_fresh_hasher: Sha3_224, "SHA3-224";
        sha3_256_finalize_reset_yields_a_fresh_hasher: Sha3_256, "SHA3-256";
        sha3_384_finalize_reset_yields_a_fresh_hasher: Sha3_384, "SHA3-384";
        sha3_512_finalize_reset_yields_a_fresh_hasher: Sha3_512, "SHA3-512";
    }
}
