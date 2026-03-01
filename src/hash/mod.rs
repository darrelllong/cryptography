//! Hash functions, XOFs, and message-authentication helpers.
//!
//! The in-tree hash families currently cover:
//!
//! - FIPS 180-4 (`Sha1`, SHA-2)
//! - FIPS 202 (`Sha3_*`, `Shake*`)
//! - FIPS 198-1 / RFC 2104 (`Hmac<H>`)
//!
//! The shared traits in this module are the glue that lets one keyed
//! construction (`Hmac<H>`) work across multiple named hash families without
//! reimplementing the HMAC state machine for each one.

/// Minimal trait for fixed-output hash functions that can back HMAC.
///
/// SHA-1 and SHA-2 implementations behind this trait are Merkle-Damgard style
/// hashes, so their raw outputs inherit the usual length-extension caveat.
/// Use `Hmac<H>` for keyed authentication, or prefer SHA-3 / SHAKE when you
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
    fn finalize_into(self, out: &mut [u8]);

    /// Finalize in place and wipe the internal state.
    ///
    /// This exists primarily so keyed constructions such as `Hmac<H>` can
    /// consume intermediate hash state without leaving key-derived chaining
    /// values behind in memory.
    fn finalize_reset(&mut self, out: &mut [u8]);

    /// Best-effort zeroization of the internal state.
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
    fn update(&mut self, data: &[u8]);

    /// Finalize if needed and squeeze more output.
    ///
    /// The first call transitions the XOF from absorb mode to squeeze mode.
    /// Subsequent calls continue producing output from the same stream. This
    /// models sponge-based XOFs such as SHAKE, where the caller may not know
    /// the required output length up front.
    fn squeeze(&mut self, out: &mut [u8]);
}

pub mod hmac;
pub mod sha1;
pub mod sha2;
pub mod sha3;
