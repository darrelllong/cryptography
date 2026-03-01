//! Hash functions and sponge constructions.

/// Minimal trait for extendable-output functions.
///
/// The caller absorbs input incrementally and then consumes as many output
/// bytes as needed in one final squeeze step.
///
/// This is intentionally a single-shot squeeze API: `squeeze(...)` consumes the
/// XOF state. Callers that need output in multiple chunks should either request
/// the full output in one buffer or instantiate a fresh XOF and absorb the same
/// prefix again.
pub trait Xof {
    /// Absorb more input bytes.
    fn update(&mut self, data: &[u8]);

    /// Finalize if needed and squeeze more output.
    ///
    /// The first call transitions the XOF from absorb mode to squeeze mode.
    /// Subsequent calls continue producing output from the same stream.
    fn squeeze(&mut self, out: &mut [u8]);
}

pub mod sha3;
