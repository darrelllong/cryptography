//! Internal helpers for crate-defined public-key serialization.
//!
//! RSA uses standards-based containers in `rsa_io`. The other public-key
//! schemes do not have an equally universal interchange format for the exact
//! primitive forms exposed here, so they use two deliberately simple
//! crate-defined formats:
//! - a binary DER `SEQUENCE` of positive `INTEGER`s
//! - a flat XML document whose root tag is the Rust type name and whose child
//!   elements are fixed-schema big integers rendered as uppercase hexadecimal
//!   with no `0x` prefix
//!
//! PEM text armor for the non-RSA schemes wraps the DER body, not the XML
//! form. The XML form is a convenience export that mirrors the in-memory
//! structs closely enough to audit side-by-side with the binary encoding.
//!
//! The payload is intentionally "RSA-like" in shape: just the key components
//! encoded in a fixed field order, without pretending that these schemes have
//! PKCS / X.509 object identifiers. The current field layouts are:
//!
//! - `CocksPublicKey`: `[n]`
//! - `CocksPrivateKey`: `[pi, q]`
//! - `DsaPublicKey`: `[p, q, g, y]`
//! - `DsaPrivateKey`: `[p, q, g, x]`
//! - `ElGamalPublicKey`: `[p, exponent_bound, g, b]`
//! - `ElGamalPrivateKey`: `[p, exponent_modulus, a]`
//! - `PaillierPublicKey`: `[n, zeta]`
//! - `PaillierPrivateKey`: `[n, lambda, u]`
//! - `RabinPublicKey`: `[n]`
//! - `RabinPrivateKey`: `[n, p, q]`
//! - `SchmidtSamoaPublicKey`: `[n]`
//! - `SchmidtSamoaPrivateKey`: `[d, gamma]`
//!
//! The PEM label selects the scheme and key role. The DER body is shared.
//! Bare DER blobs are intentionally schema-shaped rather than self-describing:
//! types with the same field count can therefore share identical binary
//! encodings. The PEM labels and XML root tags are the type discriminants when
//! callers need a tagged interchange format.

use rump::BigUint;

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn encode_biguints(fields: &[&BigUint]) -> Vec<u8> {
    let mut body = Vec::new();
    for field in fields {
        body.push(0x02);
        let bytes = der_integer_bytes(field);
        encode_der_len(bytes.len(), &mut body);
        body.extend_from_slice(&bytes);
    }

    let mut out = Vec::new();
    out.push(0x30);
    encode_der_len(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

pub(crate) fn decode_biguints(input: &[u8]) -> Option<Vec<BigUint>> {
    let (seq_tag, rest) = input.split_first()?;
    if *seq_tag != 0x30 {
        return None;
    }

    let (seq_len, mut pos) = decode_der_len(rest)?;
    // Use checked_add: seq_len can be usize::MAX with crafted input (eight
    // 0xff length bytes), and adding pos to it would otherwise overflow.
    if pos.checked_add(seq_len) != Some(rest.len()) {
        return None;
    }

    let mut out = Vec::new();
    while pos < rest.len() {
        let int_tag = *rest.get(pos)?;
        pos += 1;
        if int_tag != 0x02 {
            return None;
        }

        let (len, len_len) = decode_der_len(rest.get(pos..)?)?;
        pos += len_len;
        // pos + len can overflow when len ≈ usize::MAX; use checked_add.
        let end = pos.checked_add(len)?;
        let field = rest.get(pos..end)?;
        pos = end;
        out.push(decode_der_biguint(field)?);
    }

    Some(out)
}

fn der_integer_bytes(value: &BigUint) -> Vec<u8> {
    let mut bytes = value.to_be_bytes();
    // DER INTEGER uses signed two's-complement, so a leading 1 bit would make
    // the value look negative. Prepend a zero byte to mark the encoding as a
    // positive integer.
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

fn decode_der_biguint(field: &[u8]) -> Option<BigUint> {
    if field.is_empty() {
        return None;
    }
    // Negative DER INTEGER encodings are not valid for these key fields.
    if field[0] & 0x80 != 0 {
        return None;
    }

    let body = if field.len() > 1 && field[0] == 0 {
        // DER requires the shortest positive encoding: a leading zero is
        // allowed only when it prevents the next byte from being interpreted
        // as a sign bit.
        if field[1] & 0x80 == 0 {
            return None;
        }
        &field[1..]
    } else {
        field
    };

    Some(BigUint::from_be_bytes(body))
}

fn encode_der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        // Short-form DER length.
        out.push(u8::try_from(len).expect("short DER length fits in u8"));
        return;
    }

    // Long-form DER length: high bit set, remaining bits = number of length
    // octets that follow.
    let be = len.to_be_bytes();
    let first_nonzero = be
        .iter()
        .position(|&byte| byte != 0)
        .expect("non-zero length has at least one non-zero byte");
    let len_bytes = &be[first_nonzero..];
    out.push(0x80 | u8::try_from(len_bytes.len()).expect("DER length-of-length fits in u8"));
    out.extend_from_slice(len_bytes);
}

fn decode_der_len(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first & 0x80 == 0 {
        // Short-form DER length.
        return Some((usize::from(first), 1));
    }

    // Long-form DER length. The low 7 bits say how many big-endian length
    // octets follow.
    let count = usize::from(first & 0x7f);
    if count == 0 {
        return None;
    }
    let len_bytes = input.get(1..1 + count)?;
    let mut len = 0usize;
    for &byte in len_bytes {
        len = len.checked_shl(8)?.checked_add(usize::from(byte))?;
    }
    Some((len, 1 + count))
}

pub(crate) fn pem_wrap(label: &str, blob: &[u8]) -> String {
    let b64 = base64_encode(blob);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");

    let mut idx = 0usize;
    while idx < b64.len() {
        let end = (idx + 64).min(b64.len());
        out.push_str(&b64[idx..end]);
        out.push('\n');
        idx = end;
    }

    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

pub(crate) fn pem_unwrap(label: &str, pem: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut lines = pem.lines();
    if lines.next()? != begin {
        return None;
    }

    let mut b64 = String::new();
    for line in lines {
        if line == end {
            return base64_decode(&b64);
        }
        if !line.is_empty() {
            b64.push_str(line.trim());
        }
    }
    None
}

/// Emit `to_xml` / `from_xml` for a key or ciphertext type from its schema.
///
/// The type must provide two inherent methods that own the scheme-specific
/// logic exactly once:
///
/// - `fn serial_fields(&self) -> Vec<BigUint>` — the schema fields in order
///   (owned values, so synthesized fields like cofactors are fine);
/// - `fn from_serial_fields(fields: Vec<BigUint>) -> Option<Self>` — validate
///   the fields and rebuild the type (including any derived state). It is
///   always called with exactly the schema's field count.
///
/// Usage: `impl_xml_serialization!(DsaPublicKey, "DsaPublicKey", ["p", "q", "g", "y"]);`
macro_rules! impl_xml_serialization {
    ($ty:ident, $root:literal, [$($field:literal),+ $(,)?]) => {
        impl $ty {
            /// Encode as the crate's flat XML form (fixed field order,
            /// uppercase hexadecimal values; see `public_key::io`).
            #[must_use]
            pub fn to_xml(&self) -> String {
                let values = self.serial_fields();
                let pairs: ::std::vec::Vec<(&str, &crate::vt::BigUint)> =
                    [$($field),+].iter().copied().zip(values.iter()).collect();
                crate::public_key::io::xml_wrap($root, &pairs)
            }

            /// Decode from the crate's flat XML form, validating the fields.
            #[must_use]
            pub fn from_xml(xml: &str) -> Option<Self> {
                let fields = crate::public_key::io::xml_unwrap($root, &[$($field),+], xml)?;
                Self::from_serial_fields(fields)
            }
        }
    };
}
pub(crate) use impl_xml_serialization;

/// Emit `to_key_blob` / `from_key_blob` / `to_pem` / `from_pem` for a key
/// type from its schema. Requires the same `serial_fields` /
/// `from_serial_fields` pair as [`impl_xml_serialization`]; the field list is
/// only used for its length (DER bodies are positional).
macro_rules! impl_blob_pem_serialization {
    ($ty:ident, $label:expr, [$($field:literal),+ $(,)?]) => {
        impl $ty {
            /// Encode as the crate's bare DER `SEQUENCE` of positive `INTEGER`s.
            #[must_use]
            pub fn to_key_blob(&self) -> ::std::vec::Vec<u8> {
                let values = self.serial_fields();
                let refs: ::std::vec::Vec<&crate::vt::BigUint> =
                    values.iter().collect();
                crate::public_key::io::encode_biguints(&refs)
            }

            /// Decode from the crate's bare DER form, validating the fields.
            #[must_use]
            pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
                let fields = crate::public_key::io::decode_biguints(blob)?;
                if fields.len() != [$($field),+].len() {
                    return None;
                }
                Self::from_serial_fields(fields)
            }

            /// Encode as PEM text armor over the DER body, using the
            /// crate-defined label.
            #[must_use]
            pub fn to_pem(&self) -> String {
                crate::public_key::io::pem_wrap($label, &self.to_key_blob())
            }

            /// Decode from the crate-defined PEM label.
            #[must_use]
            pub fn from_pem(pem: &str) -> Option<Self> {
                let blob = crate::public_key::io::pem_unwrap($label, pem)?;
                Self::from_key_blob(&blob)
            }
        }
    };
}
pub(crate) use impl_blob_pem_serialization;

/// Encode the crate's flat XML representation for one key or ciphertext.
///
/// `root` is the outer element name and `fields` supplies the fixed child
/// elements in order.
pub(crate) fn xml_wrap(root: &str, fields: &[(&str, &BigUint)]) -> String {
    // Tag names are crate-controlled identifiers and the field values are
    // uppercase hexadecimal, so no XML escaping is ever required and the
    // document can be emitted by simple concatenation.
    let mut out = String::new();
    out.push('<');
    out.push_str(root);
    out.push('>');
    for (name, value) in fields {
        out.push('<');
        out.push_str(name);
        out.push('>');
        out.push_str(&hex_encode_upper(value));
        out.push_str("</");
        out.push_str(name);
        out.push('>');
    }
    out.push_str("</");
    out.push_str(root);
    out.push('>');
    out
}

/// Parse the crate's flat XML representation for one key or ciphertext.
///
/// The parser is intentionally strict: the root tag must match, the field
/// names must appear in the expected order, and extra trailing content is
/// rejected.
pub(crate) fn xml_unwrap(root: &str, field_names: &[&str], xml: &str) -> Option<Vec<BigUint>> {
    let mut scanner = XmlScanner::new(xml);

    scanner.skip_whitespace();
    scanner.expect_start_tag(root)?;

    let mut out = Vec::with_capacity(field_names.len());
    for &field_name in field_names {
        scanner.skip_whitespace();
        scanner.expect_start_tag(field_name)?;
        let text = scanner.take_text()?;
        out.push(hex_decode_biguint(text.trim())?);
        scanner.expect_end_tag(field_name)?;
    }

    scanner.skip_whitespace();
    scanner.expect_end_tag(root)?;
    scanner.skip_whitespace();
    if scanner.at_end() {
        Some(out)
    } else {
        None
    }
}

/// Strict cursor over the crate's flat XML key documents.
///
/// The format has no attributes, comments, declarations, CDATA, or escaped
/// text, so tags are matched literally (`<name>` / `</name>`) and anything
/// else is a parse failure. This deliberately accepts only what `xml_wrap`
/// emits, modulo whitespace between elements and around field values.
struct XmlScanner<'a> {
    rest: &'a str,
}

impl<'a> XmlScanner<'a> {
    fn new(input: &'a str) -> Self {
        Self { rest: input }
    }

    fn skip_whitespace(&mut self) {
        self.rest = self.rest.trim_start();
    }

    /// Consume an exact `<name>` start tag with no attributes.
    fn expect_start_tag(&mut self, name: &str) -> Option<()> {
        self.rest = self
            .rest
            .strip_prefix('<')?
            .strip_prefix(name)?
            .strip_prefix('>')?;
        Some(())
    }

    /// Consume an exact `</name>` end tag.
    fn expect_end_tag(&mut self, name: &str) -> Option<()> {
        self.rest = self
            .rest
            .strip_prefix("</")?
            .strip_prefix(name)?
            .strip_prefix('>')?;
        Some(())
    }

    /// Take the raw text up to (not including) the next `<`.
    fn take_text(&mut self) -> Option<&'a str> {
        let end = self.rest.find('<')?;
        let (text, rest) = self.rest.split_at(end);
        self.rest = rest;
        Some(text)
    }

    fn at_end(&self) -> bool {
        self.rest.is_empty()
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut idx = 0usize;
    while idx < input.len() {
        let a = input[idx];
        let b = if idx + 1 < input.len() {
            input[idx + 1]
        } else {
            0
        };
        let c = if idx + 2 < input.len() {
            input[idx + 2]
        } else {
            0
        };

        let triple = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        let i0 = usize::try_from((triple >> 18) & 0x3f).expect("base64 sextet fits usize");
        let i1 = usize::try_from((triple >> 12) & 0x3f).expect("base64 sextet fits usize");
        let i2 = usize::try_from((triple >> 6) & 0x3f).expect("base64 sextet fits usize");
        let i3 = usize::try_from(triple & 0x3f).expect("base64 sextet fits usize");

        out.push(char::from(TABLE[i0]));
        out.push(char::from(TABLE[i1]));
        if idx + 1 < input.len() {
            out.push(char::from(TABLE[i2]));
        } else {
            out.push('=');
        }
        if idx + 2 < input.len() {
            out.push(char::from(TABLE[i3]));
        } else {
            out.push('=');
        }

        idx += 3;
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let mut idx = 0usize;
    while idx < bytes.len() {
        let a = decode_base64_char(bytes[idx])?;
        let b = decode_base64_char(bytes[idx + 1])?;
        let c = if bytes[idx + 2] == b'=' {
            64
        } else {
            decode_base64_char(bytes[idx + 2])?
        };
        let d = if bytes[idx + 3] == b'=' {
            64
        } else {
            decode_base64_char(bytes[idx + 3])?
        };

        let triple = (u32::from(a) << 18)
            | (u32::from(b) << 12)
            | (u32::from(c & 0x3f) << 6)
            | u32::from(d & 0x3f);

        out.push(u8::try_from((triple >> 16) & 0xff).expect("decoded base64 byte fits"));
        if c != 64 {
            out.push(u8::try_from((triple >> 8) & 0xff).expect("decoded base64 byte fits"));
        }
        if d != 64 {
            out.push(u8::try_from(triple & 0xff).expect("decoded base64 byte fits"));
        }

        idx += 4;
    }
    Some(out)
}

fn decode_base64_char(ch: u8) -> Option<u8> {
    match ch {
        b'A'..=b'Z' => Some(ch - b'A'),
        b'a'..=b'z' => Some(ch - b'a' + 26),
        b'0'..=b'9' => Some(ch - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn hex_encode_upper(value: &BigUint) -> String {
    let bytes = value.to_be_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(UPPER_HEX[usize::from(byte >> 4)]));
        out.push(char::from(UPPER_HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode_biguint(input: &str) -> Option<BigUint> {
    if input.is_empty() {
        return None;
    }
    // Accept the one-digit zero shorthand for hand-written XML, even though
    // `hex_encode_upper` emits the canonical `00` form.
    if input == "0" {
        return Some(BigUint::zero());
    }
    if !input.len().is_multiple_of(2) {
        return None;
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = decode_hex_char(bytes[idx])?;
        let lo = decode_hex_char(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Some(BigUint::from_be_bytes(&out))
}

fn decode_hex_char(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_biguints, encode_biguints, pem_unwrap, pem_wrap, xml_unwrap, xml_wrap};
    use rump::BigUint;

    #[test]
    fn binary_roundtrip() {
        let a = BigUint::from_u64(0x1234);
        let b = BigUint::from_u64(0x5678);
        let blob = encode_biguints(&[&a, &b]);
        let parsed = decode_biguints(&blob).expect("parse");
        assert_eq!(parsed, vec![a, b]);
    }

    #[test]
    fn pem_roundtrip() {
        let blob = vec![0, 1, 2, 3, 4, 5];
        let pem = pem_wrap("CRYPTOGRAPHY TEST KEY", &blob);
        let parsed = pem_unwrap("CRYPTOGRAPHY TEST KEY", &pem).expect("pem");
        assert_eq!(parsed, blob);
    }

    #[test]
    fn xml_roundtrip() {
        let a = BigUint::from_u64(0x1234);
        let b = BigUint::from_u64(0xabcd);
        let xml = xml_wrap("TestKey", &[("first", &a), ("second", &b)]);
        let parsed = xml_unwrap("TestKey", &["first", "second"], &xml).expect("xml");
        assert_eq!(parsed, vec![a, b]);
    }

    #[test]
    fn xml_rejects_wrong_root() {
        let xml = "<Wrong><n>BB</n></Wrong>";
        assert!(xml_unwrap("TestKey", &["n"], xml).is_none());
    }

    #[test]
    fn xml_rejects_wrong_field_name() {
        let xml = "<TestKey><wrong>BB</wrong></TestKey>";
        assert!(xml_unwrap("TestKey", &["n"], xml).is_none());
    }

    #[test]
    fn xml_rejects_trailing_content() {
        let xml = "<TestKey><n>BB</n></TestKey>junk";
        assert!(xml_unwrap("TestKey", &["n"], xml).is_none());
    }

    #[test]
    fn xml_rejects_truncated_input() {
        let xml = "<TestKey><n>BB</n>";
        assert!(xml_unwrap("TestKey", &["n"], xml).is_none());
    }
}
