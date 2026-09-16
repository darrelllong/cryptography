//! Decoding of known answers: hexadecimal text and the crate's `KEY=VALUE`
//! vector files.
//!
//! The unit tests reach these helpers through `crate::test_utils`. The
//! integration tests under `tests/` are separate crates that cannot see the
//! library's `#[cfg(test)]` code, so `tests/common/mod.rs` compiles this same
//! file into each of them: a vector decodes to the same bytes on both sides
//! because there is one decoder, not two copies kept in step.
//!
//! Malformed input is a broken test, never a value to guess at, so every
//! helper panics on it and quotes the text it was given.

use std::collections::HashMap;
use std::fmt::Write as _;

/// Decode hexadecimal digits into bytes, the first digit of each pair being
/// the high nibble.
///
/// Digits may be upper or lower case. ASCII whitespace anywhere in the text
/// is skipped, so a value can keep the digit groups and line breaks of the
/// document it was copied from.
///
/// # Panics
///
/// Panics on any other character, and on an odd number of digits, quoting
/// the input.
pub(crate) fn decode_hex(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut high_nibble = None;
    for (at, ch) in text.char_indices() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let Some(digit) = ch.to_digit(16) else {
            panic!("{ch:?} at byte {at} is not a hex digit in {text:?}");
        };
        let nibble = u8::try_from(digit).expect("a hex digit is below 16");
        match high_nibble.take() {
            None => high_nibble = Some(nibble),
            Some(high) => bytes.push((high << 4) | nibble),
        }
    }
    assert!(
        high_nibble.is_none(),
        "odd number of hex digits in {text:?}"
    );
    bytes
}

/// Decode hexadecimal digits into exactly `N` bytes, by the rules of
/// [`decode_hex`].
///
/// # Panics
///
/// Panics as [`decode_hex`] does, and when the digits decode to any length
/// other than `N`, quoting the input.
pub(crate) fn decode_hex_array<const N: usize>(text: &str) -> [u8; N] {
    let bytes = decode_hex(text);
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{text:?} decodes to {len} bytes, not {N}"))
}

/// Lower-case hexadecimal digits of `bytes`, two per byte, unseparated.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

/// The `(key, value)` fields of a `KEY=VALUE` vector file, in file order.
///
/// Each line is trimmed; blank lines and lines starting with `#` (the
/// provenance header) are skipped. Every other line splits at its first `=`,
/// and the key and value are trimmed again; a later `=` stays in the value.
///
/// # Panics
///
/// The iterator panics, quoting the line, on a line that is neither blank, a
/// comment, nor `KEY=VALUE`.
pub(crate) fn vector_fields(contents: &str) -> impl Iterator<Item = (&str, &str)> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("vector line {line:?} is not KEY=VALUE"));
            (key.trim(), value.trim())
        })
}

/// The fields of a `KEY=VALUE` vector file whose keys are all distinct,
/// looked up by key; the line format is that of [`vector_fields`].
///
/// # Panics
///
/// Panics on a malformed line, and on a key that appears twice, whose later
/// value would otherwise silently replace the earlier one.
pub(crate) fn parse_vector_map(contents: &str) -> HashMap<&str, &str> {
    let mut fields = HashMap::new();
    for (key, value) in vector_fields(contents) {
        let earlier = fields.insert(key, value);
        assert!(earlier.is_none(), "vector key {key} appears twice");
    }
    fields
}
