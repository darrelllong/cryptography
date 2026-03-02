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
//! - `ElGamalPublicKey`: `[p, exponent_bound, r, b]`
//! - `ElGamalPrivateKey`: `[p, exponent_modulus, a]`
//! - `PaillierPublicKey`: `[n, zeta]`
//! - `PaillierPrivateKey`: `[n, lambda, u]`
//! - `RabinPublicKey`: `[n]`
//! - `RabinPrivateKey`: `[n, p, q]`
//! - `SchmidtSamoaPublicKey`: `[n]`
//! - `SchmidtSamoaPrivateKey`: `[d, gamma]`
//!
//! The PEM label selects the scheme and key role. The DER body is shared.

use crate::public_key::bigint::BigUint;

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
    if pos + seq_len != rest.len() {
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
        let field = rest.get(pos..pos + len)?;
        pos += len;
        out.push(decode_der_biguint(field)?);
    }

    Some(out)
}

fn der_integer_bytes(value: &BigUint) -> Vec<u8> {
    let mut bytes = value.to_be_bytes();
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

fn decode_der_biguint(field: &[u8]) -> Option<BigUint> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        return None;
    }

    let body = if field.len() > 1 && field[0] == 0 {
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
        out.push(u8::try_from(len).expect("short DER length fits in u8"));
        return;
    }

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
        return Some((usize::from(first), 1));
    }

    let count = usize::from(first & 0x7f);
    if count == 0 {
        return None;
    }
    let len_bytes = input.get(1..1 + count)?;
    let mut len = 0usize;
    for &byte in len_bytes {
        len = len.checked_shl(8)? | usize::from(byte);
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

pub(crate) fn xml_wrap(root: &str, fields: &[(&str, &BigUint)]) -> String {
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

pub(crate) fn xml_unwrap(root: &str, field_names: &[&str], xml: &str) -> Option<Vec<BigUint>> {
    let bytes = xml.as_bytes();
    let mut pos = 0usize;

    skip_ws(bytes, &mut pos);
    expect_open_tag(bytes, &mut pos, root)?;

    let mut out = Vec::with_capacity(field_names.len());
    for &field_name in field_names {
        skip_ws(bytes, &mut pos);
        expect_open_tag(bytes, &mut pos, field_name)?;
        let start = pos;
        while pos < bytes.len() && bytes[pos] != b'<' {
            pos += 1;
        }
        let body = core::str::from_utf8(bytes.get(start..pos)?).ok()?;
        out.push(hex_decode_biguint(body.trim())?);
        expect_close_tag(bytes, &mut pos, field_name)?;
    }

    skip_ws(bytes, &mut pos);
    expect_close_tag(bytes, &mut pos, root)?;
    skip_ws(bytes, &mut pos);
    if pos != bytes.len() {
        return None;
    }

    Some(out)
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

fn expect_open_tag(input: &[u8], pos: &mut usize, name: &str) -> Option<()> {
    let mut tag = String::with_capacity(name.len() + 2);
    tag.push('<');
    tag.push_str(name);
    tag.push('>');
    let tag_bytes = tag.as_bytes();
    if input.get(*pos..(*pos + tag_bytes.len()))? != tag_bytes {
        return None;
    }
    *pos += tag_bytes.len();
    Some(())
}

fn expect_close_tag(input: &[u8], pos: &mut usize, name: &str) -> Option<()> {
    let mut tag = String::with_capacity(name.len() + 3);
    tag.push_str("</");
    tag.push_str(name);
    tag.push('>');
    let tag_bytes = tag.as_bytes();
    if input.get(*pos..(*pos + tag_bytes.len()))? != tag_bytes {
        return None;
    }
    *pos += tag_bytes.len();
    Some(())
}

fn skip_ws(input: &[u8], pos: &mut usize) {
    while *pos < input.len() && input[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn hex_encode_upper(value: &BigUint) -> String {
    let bytes = value.to_be_bytes();
    if bytes.is_empty() {
        return String::from("0");
    }

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
    use crate::public_key::bigint::BigUint;

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
}
