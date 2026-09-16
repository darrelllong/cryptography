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
//! - `DhParams`: `[p, q, g]`
//! - `DhPublicKey`: `[p, q, g, y]`
//! - `DhPrivateKey`: `[p, q, g, x]`
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
//! - `RsaPublicKey` (XML form only; DER uses PKCS #1): `[e, n]`
//! - `RsaPrivateKey` (XML form only; DER uses PKCS #1): `[e, d, n, p, q]`
//!
//! The PEM label selects the scheme and key role. The DER body is shared.
//! Bare DER blobs are intentionally schema-shaped rather than self-describing:
//! types with the same field count can therefore share identical binary
//! encodings. The PEM labels and XML root tags are the type discriminants when
//! callers need a tagged interchange format.
//!
//! ## DER, BER and the textual encoding
//!
//! Every decoder named for DER — the integer-sequence blobs here, the `pkix`
//! containers (`SubjectPublicKeyInfo`, `OneAsymmetricKey`) and the key
//! structures inside them — goes through the one [`DerReader`] below, which
//! enforces the Distinguished Encoding Rules of X.690 §10: definite lengths
//! only, each length in the fewest octets (no long form below 128, no leading
//! zero length octets), strings in the primitive form, and each `INTEGER` in
//! the fewest octets (X.690 §8.3.2: no redundant leading `0x00`), non-negative
//! and non-empty. A component typed `ANY`, such as algorithm parameters or an
//! attribute value, is read with [`DerReader::read_element`], which checks it
//! and everything nested in it against the DER rules a reader can apply
//! without the schema. A byte string is accepted only if re-encoding what it
//! decodes to reproduces it exactly, so a key has one encoding and a signature
//! has one encoding.
//!
//! Where a specification requires a receiver to accept BER — RFC 5958 §2 for
//! a `OneAsymmetricKey`, RFC 7468 §10 and §13 for the contents of `PRIVATE KEY`
//! and `PUBLIC KEY` text — the input is first read by [`BerReader`], which
//! checks the rules X.690 clause 8 sets and brings the value to its DER
//! encoding (clauses 10 and 11). The strict DER decoder then reads that
//! encoding, so BER support is one conversion in front of the DER decoders and
//! relaxes nothing inside them. The containers' schemas, and which key
//! contents an algorithm's specification requires in DER, are `pkix`'s.
//!
//! [`pem_contents`] reads the textual encoding as RFC 7468 §2 directs a
//! parser, for the crate-defined labels as for the standard ones.
//!
//! ## What parsing validates
//!
//! Decoding a blob, PEM document, or XML document yields a key only after the
//! scheme's `from_serial_fields` has applied the crate's parse-time validation
//! policy, stated in full in the [`public_key`](crate::public_key) module docs:
//! private keys are validated completely (hardened primality on every prime
//! they carry, the scheme's algebraic relations, derived values recomputed
//! rather than trusted); public keys are validated structurally (ranges,
//! parity, subgroup membership, and one fixed-base primality test per public
//! prime).

use crate::zeroize_slice;
use rump::BigUint;

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

// ─── Strict X.690 DER ─────────────────────────────────────────────────────────

/// ASN.1 universal class tags (X.690 §8.1.2) used by the crate's containers.
pub(crate) mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
}

/// Encode one tag-length-value triple with a minimal definite length
/// (X.690 §8.1.3 and §10.1), allocated at its exact size so that encoding a
/// secret never strands a copy of it in a reallocation.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let (length, count) = der_length(content.len());
    let mut out = Vec::with_capacity(1 + count + content.len());
    out.push(tag);
    out.extend_from_slice(&length[..count]);
    out.extend_from_slice(content);
    out
}

/// Length octets of the longest definite length a `usize` holds: the initial
/// octet and one octet per byte of the value.
const MAX_LENGTH_OCTETS: usize = 1 + core::mem::size_of::<usize>();

/// The definite length `len` in the fewest octets (X.690 §8.1.3.4, §8.1.3.5
/// and §10.1), and how many of the returned octets it takes.
fn der_length(len: usize) -> ([u8; MAX_LENGTH_OCTETS], usize) {
    let mut octets = [0u8; MAX_LENGTH_OCTETS];
    match u8::try_from(len) {
        // Short form: the single octet is the length itself.
        Ok(short) if short < 0x80 => {
            octets[0] = short;
            (octets, 1)
        }
        // Long form: the first octet has its high bit set and counts the
        // big-endian length octets that follow, with no leading zero octet.
        _ => {
            let be = len.to_be_bytes();
            let leading_zeros = be.iter().take_while(|&&byte| byte == 0).count();
            let count = be.len() - leading_zeros;
            octets[0] = 0x80 | u8::try_from(count).expect("a usize has at most 8 bytes");
            octets[1..=count].copy_from_slice(&be[leading_zeros..]);
            (octets, 1 + count)
        }
    }
}

/// DER `SEQUENCE` over already-encoded `content`.
pub(crate) fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tlv(tag::SEQUENCE, content)
}

/// DER `OCTET STRING`.
pub(crate) fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(tag::OCTET_STRING, content)
}

/// DER `BIT STRING` whose payload ends on a byte boundary (zero unused bits).
pub(crate) fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + content.len());
    // X.690 §8.6.2: the first content octet counts the unused bits in the
    // final octet. Every payload this crate wraps is a whole number of bytes.
    body.push(0);
    body.extend_from_slice(content);
    der_tlv(tag::BIT_STRING, &body)
}

/// DER `OBJECT IDENTIFIER` over pre-encoded sub-identifier content.
pub(crate) fn der_oid(content: &[u8]) -> Vec<u8> {
    der_tlv(tag::OBJECT_IDENTIFIER, content)
}

/// The single identifier octet of the context-specific tag `[number]`
/// (X.690 §8.1.2.2 and Table 1), in primitive or constructed form.
///
/// # Panics
///
/// Panics if `number` exceeds 30: larger numbers need the multi-octet
/// identifier of §8.1.2.4, which no structure this crate encodes uses.
pub(crate) const fn context_tag(number: u8, constructed: bool) -> u8 {
    assert!(
        number <= 30,
        "context-specific tag number needs the high-tag-number form"
    );
    let form = if constructed { 0x20 } else { 0x00 };
    0x80 | form | number
}

/// `[number] IMPLICIT` over a primitive base type (X.690 §8.14.4): the base
/// encoding's contents octets under a context-specific primitive tag. For an
/// `OCTET STRING` the contents are the octets themselves.
pub(crate) fn der_implicit_primitive(number: u8, content: &[u8]) -> Vec<u8> {
    der_tlv(context_tag(number, false), content)
}

/// `[number] IMPLICIT BIT STRING` over a payload that ends on a byte boundary
/// (zero unused bits, X.690 §8.6.2).
pub(crate) fn der_implicit_bit_string(number: u8, payload: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(1 + payload.len());
    contents.push(0);
    contents.extend_from_slice(payload);
    der_implicit_primitive(number, &contents)
}

/// `[number] EXPLICIT` tagging (X.690 §8.14.3): a constructed
/// context-specific value whose contents are `inner`, the complete encoding
/// of the tagged value.
pub(crate) fn der_explicit(number: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(context_tag(number, true), inner)
}

/// DER `INTEGER` holding one small non-negative value.
pub(crate) fn der_integer_u8(value: u8) -> Vec<u8> {
    der_integer_biguint(&BigUint::from_u64(u64::from(value)))
}

/// DER `INTEGER` holding a non-negative big integer in the fewest octets,
/// allocated at its exact size. The transient byte image of the value is
/// wiped; the returned encoding is the caller's to wipe.
pub(crate) fn der_integer_biguint(value: &BigUint) -> Vec<u8> {
    // `to_be_bytes` already has no redundant leading zeros (zero itself is
    // the single octet `00`). X.690 §8.3.3 reads the content as two's
    // complement, so a set high bit needs one `00` octet to keep the value
    // positive; §8.3.2 forbids any further leading zero octet.
    let mut magnitude = value.to_be_bytes();
    let sign = usize::from(magnitude.first().is_some_and(|byte| byte & 0x80 != 0));
    let (length, count) = der_length(sign + magnitude.len());
    let mut out = Vec::with_capacity(1 + count + sign + magnitude.len());
    out.push(tag::INTEGER);
    out.extend_from_slice(&length[..count]);
    if sign == 1 {
        out.push(0);
    }
    out.extend_from_slice(&magnitude);
    zeroize_slice(magnitude.as_mut_slice());
    out
}

/// Append `piece` to `out`, then wipe `piece` before it is freed.
///
/// `Vec::extend` would move the bytes and free the source buffer unwiped;
/// the private-key encoders build their bodies through this instead. `out`
/// must already have room for `piece`: growing it would strand a copy of
/// what it holds.
pub(crate) fn extend_wiped(out: &mut Vec<u8>, mut piece: Vec<u8>) {
    debug_assert!(
        out.len() + piece.len() <= out.capacity(),
        "a secret-bearing buffer is sized before it is filled"
    );
    out.extend_from_slice(&piece);
    zeroize_slice(piece.as_mut_slice());
}

/// DER `SEQUENCE` whose contents are the complete encodings `parts`, in
/// order. The encoding is allocated at its exact size and each part is wiped
/// once copied, so a private key's components leave no copy behind.
pub(crate) fn der_sequence_of(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let len = parts.iter().map(Vec::len).sum();
    let (length, count) = der_length(len);
    let mut out = Vec::with_capacity(1 + count + len);
    out.push(tag::SEQUENCE);
    out.extend_from_slice(&length[..count]);
    for part in parts {
        extend_wiped(&mut out, part);
    }
    out
}

/// Cursor over one DER byte string, enforcing X.690 §10 as it reads.
pub(crate) struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// True once every byte has been consumed; callers check this to reject
    /// trailing garbage after a top-level value.
    pub(crate) fn is_finished(&self) -> bool {
        self.pos == self.data.len()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    /// Read a definite length in the fewest octets (X.690 §8.1.3, §10.1).
    fn read_len(&mut self) -> Option<usize> {
        let first = self.next_byte()?;
        if first & 0x80 == 0 {
            return Some(usize::from(first));
        }

        // Long form. `0x80` is the indefinite form, which DER forbids; more
        // length octets than a `usize` holds can never describe a slice this
        // process holds, so that is rejected rather than truncated.
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return None;
        }
        let mut len = 0usize;
        for index in 0..count {
            let byte = self.next_byte()?;
            // Fewest octets: no leading zero length octet.
            if index == 0 && byte == 0 {
                return None;
            }
            len = (len << 8) | usize::from(byte);
        }
        // Fewest octets: a length below 128 must use the short form.
        if len < 0x80 {
            return None;
        }
        Some(len)
    }

    /// Read one value with the expected tag and return its content octets.
    fn read_tlv(&mut self, expected_tag: u8) -> Option<&'a [u8]> {
        if self.next_byte()? != expected_tag {
            return None;
        }
        let len = self.read_len()?;
        let end = self.pos.checked_add(len)?;
        let content = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(content)
    }

    /// Content of a `SEQUENCE`; parse it with a nested reader.
    pub(crate) fn read_sequence(&mut self) -> Option<&'a [u8]> {
        self.read_tlv(tag::SEQUENCE)
    }

    /// Content of an `OCTET STRING`.
    pub(crate) fn read_octet_string(&mut self) -> Option<&'a [u8]> {
        self.read_tlv(tag::OCTET_STRING)
    }

    /// Payload of a `BIT STRING` that ends on a byte boundary (X.690 §8.6.2:
    /// the leading unused-bits octet must be zero).
    pub(crate) fn read_bit_string(&mut self) -> Option<&'a [u8]> {
        octet_aligned_bit_string(self.read_tlv(tag::BIT_STRING)?)
    }

    /// Content of an `OBJECT IDENTIFIER`, for comparison against a known
    /// pre-encoded value.
    pub(crate) fn read_oid(&mut self) -> Option<&'a [u8]> {
        let content = self.read_tlv(tag::OBJECT_IDENTIFIER)?;
        if content.is_empty() {
            return None;
        }
        Some(content)
    }

    /// A non-negative `INTEGER` in the fewest octets (X.690 §8.3).
    pub(crate) fn read_integer_biguint(&mut self) -> Option<BigUint> {
        let content = self.read_tlv(tag::INTEGER)?;
        // §8.3.1: at least one content octet. §8.3.3: two's complement, so a
        // set high bit means negative, which no field here can be.
        let (&first, rest) = content.split_first()?;
        if first & 0x80 != 0 {
            return None;
        }
        // §8.3.2: a leading `00` is allowed only to keep a set high bit in
        // the next octet from reading as a sign bit.
        let body = if first == 0 {
            match rest.first() {
                None => rest,
                Some(next) if next & 0x80 != 0 => rest,
                Some(_) => return None,
            }
        } else {
            content
        };
        Some(BigUint::from_be_bytes(body))
    }

    /// An `INTEGER` whose value fits one byte, for version fields.
    pub(crate) fn read_integer_small(&mut self) -> Option<u8> {
        let value = self.read_integer_biguint()?;
        value.to_u64().and_then(|value| u8::try_from(value).ok())
    }

    /// The identifier octet of the next value, without consuming it; `None`
    /// at the end of the input. Compare it against a tag to decide whether an
    /// `OPTIONAL` component is present or which `CHOICE` alternative follows.
    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Content of a `SET` or `SET OF`.
    pub(crate) fn read_set(&mut self) -> Option<&'a [u8]> {
        self.read_tlv(tag::SET)
    }

    /// Contents of a `[number] IMPLICIT` value over a primitive base type
    /// (X.690 §8.14.4): what the base type's own contents octets would be,
    /// the octets themselves for an `OCTET STRING`.
    pub(crate) fn read_implicit_primitive(&mut self, number: u8) -> Option<&'a [u8]> {
        self.read_tlv(context_tag(number, false))
    }

    /// Contents of a `[number] IMPLICIT` value over a constructed base type
    /// such as `SEQUENCE` or `SET OF` (X.690 §8.14.4); parse them with a
    /// nested reader.
    pub(crate) fn read_implicit_constructed(&mut self, number: u8) -> Option<&'a [u8]> {
        self.read_tlv(context_tag(number, true))
    }

    /// Payload of a `[number] IMPLICIT BIT STRING` that ends on a byte
    /// boundary.
    pub(crate) fn read_implicit_bit_string(&mut self, number: u8) -> Option<&'a [u8]> {
        octet_aligned_bit_string(self.read_implicit_primitive(number)?)
    }

    /// Contents of a `[number] EXPLICIT` value (X.690 §8.14.3): the complete
    /// encoding of the one value it tags, and nothing else, that encoding
    /// already checked as [`Self::read_element`] checks it. The caller
    /// decodes it with a nested reader, whose type checks are its own.
    pub(crate) fn read_explicit(&mut self, number: u8) -> Option<&'a [u8]> {
        let contents = self.read_tlv(context_tag(number, true))?;
        let mut inner = DerReader::new(contents);
        inner.read_element()?;
        inner.is_finished().then_some(contents)
    }

    /// The complete encoding of the next value, whatever its type, once it
    /// and everything nested in it has passed the DER checks a reader can make
    /// without the schema (identifier and length octets in their fewest
    /// octets, the primitive or constructed form each universal type allows,
    /// the content rules of `BOOLEAN`, `INTEGER`, `BIT STRING`, `NULL` and
    /// `OBJECT IDENTIFIER`, and `SET` ordering). This is how a parser accepts
    /// a component typed `ANY` without admitting a BER-only encoding.
    pub(crate) fn read_element(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        self.skip_der_element(0)?;
        self.data.get(start..self.pos)
    }

    /// Identifier octets (X.690 §8.1.2), with the tag number in its one
    /// permitted form.
    fn read_identifier(&mut self) -> Option<Identifier> {
        parse_identifier(|| self.next_byte())
    }

    /// Consume one value, checking it as [`Self::read_element`] describes.
    fn skip_der_element(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_ELEMENT_DEPTH {
            return None;
        }
        let identifier = self.read_identifier()?;
        let len = self.read_len()?;
        let end = self.pos.checked_add(len)?;
        let contents = self.data.get(self.pos..end)?;
        self.pos = end;
        if identifier.constructed {
            constructed_contents_are_der(identifier, contents, depth)
        } else {
            primitive_contents_are_der(identifier, contents).then_some(())
        }
    }
}

/// Deepest nesting [`DerReader::read_element`] follows. The values a key
/// container holds nest a few levels; the bound keeps a hostile encoding from
/// exhausting the stack.
const MAX_ELEMENT_DEPTH: usize = 32;

/// Most values one constructed BER encoding may hold, and most segments one
/// constructed string may be cut into, on the way to DER ([`BerReader`]). The
/// converter keeps each value in its own buffer until the enclosing value is
/// written, so a run of two-octet values would otherwise cost some twenty
/// times its length; no `SEQUENCE`, `SET OF` or segmented string in a key
/// container comes near this many. Input past the bound fails.
const MAX_CONSTRUCTED_VALUES: usize = 4096;

/// A tag as identifier octets carry it (X.690 §8.1.2).
#[derive(Clone, Copy)]
struct Identifier {
    /// Bits 8 and 7 of the leading octet (Table 1); 0 is the universal class.
    class: u8,
    /// Bit 6 of the leading octet (§8.1.2.5).
    constructed: bool,
    /// The tag number.
    number: u32,
}

impl Identifier {
    fn is_universal(self) -> bool {
        self.class == class::UNIVERSAL
    }

    /// Whether this is the universal tag `number`.
    fn is(self, number: u32) -> bool {
        self.is_universal() && self.number == number
    }
}

/// Tag classes (X.690 §8.1.2.2, Table 1).
pub(crate) mod class {
    /// The universal class.
    pub const UNIVERSAL: u8 = 0;
    /// The context-specific class.
    pub const CONTEXT_SPECIFIC: u8 = 2;
}

/// Identifier octets (X.690 §8.1.2) drawn one at a time from `next`, with
/// the tag number in its one permitted form; BER and DER share these rules.
fn parse_identifier(mut next: impl FnMut() -> Option<u8>) -> Option<Identifier> {
    let leading = next()?;
    let class = leading >> 6;
    let constructed = leading & 0x20 != 0;
    if leading & 0x1f != 0x1f {
        return Some(Identifier {
            class,
            constructed,
            number: u32::from(leading & 0x1f),
        });
    }
    // §8.1.2.4.2: base-128 subsequent octets, bit 8 set on all but the
    // last, and bits 7 to 1 of the first not all zero.
    let mut number = 0u32;
    let mut first = true;
    loop {
        let octet = next()?;
        if first && octet & 0x7f == 0 {
            return None;
        }
        first = false;
        number = number
            .checked_mul(0x80)?
            .checked_add(u32::from(octet & 0x7f))?;
        if octet & 0x80 == 0 {
            break;
        }
    }
    // §8.1.2.2: tag numbers up to 30 take the single-octet form only.
    if number <= 30 {
        return None;
    }
    Some(Identifier {
        class,
        constructed,
        number,
    })
}

/// The payload of a `BIT STRING` with contents octets `contents`, if it ends
/// on a byte boundary (X.690 §8.6.2: the initial octet, which counts the
/// unused bits, is zero). Every bit string in this crate's key containers is a
/// whole number of octets.
fn octet_aligned_bit_string(contents: &[u8]) -> Option<&[u8]> {
    match contents.split_first() {
        Some((0, payload)) => Some(payload),
        _ => None,
    }
}

/// The form X.690 clause 8 gives the encoding of a universal type: the one
/// table both the DER checker ([`DerReader::read_element`]) and the BER
/// converter ([`BerReader::read_any`]) read, so that every encoding the
/// checker accepts as DER the converter maps to itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Form {
    /// Always primitive: `BOOLEAN` (§8.2.1), `INTEGER` (§8.3.1), `NULL`
    /// (§8.8.1), `OBJECT IDENTIFIER` (§8.19.1), `REAL` (§8.5.1),
    /// `ENUMERATED` (§8.4), `RELATIVE-OID` (§8.20.1), the `TIME` types
    /// (§8.26), `OID-IRI` and `RELATIVE-OID-IRI` (§8.21.1, §8.22.1), and the
    /// tag numbers X.680 Table 1 leaves unassigned, whose contents carry no
    /// rule a reader can check.
    Primitive,
    /// Primitive or constructed in BER, primitive in DER (§10.2): `BIT
    /// STRING` (§8.6.1), `OCTET STRING` (§8.7.1), the restricted character
    /// strings (§8.23.3) and the types encoded as octet strings (§8.25).
    Either,
    /// Always constructed: `SEQUENCE` and `SEQUENCE OF` (§8.9.1, §8.10.1),
    /// `SET` and `SET OF` (§8.11.1, §8.12.1), and the types encoded as
    /// sequences, `EXTERNAL`, `EMBEDDED PDV` and `CHARACTER STRING` (§8.17.1,
    /// §8.18.1, §8.24.1).
    Constructed,
}

/// The form of the universal type numbered `number`, or `None` for 0:
/// end-of-contents is not a value (§8.1.5). An unassigned number is
/// [`Form::Primitive`], so a primitive encoding under it passes both readers
/// unchanged and a constructed one, whose DER form would need the type,
/// fails both.
fn universal_form(number: u32) -> Option<Form> {
    use universal::{
        BIT_STRING, BMP_STRING, CHARACTER_STRING, EMBEDDED_PDV, EXTERNAL, GENERALIZED_TIME,
        GRAPHIC_STRING, IA5_STRING, NUMERIC_STRING, OBJECT_DESCRIPTOR, OCTET_STRING, SEQUENCE, SET,
        UNIVERSAL_STRING, UTC_TIME, UTF8_STRING,
    };
    match number {
        0 => None,
        EXTERNAL | EMBEDDED_PDV | SEQUENCE | SET | CHARACTER_STRING => Some(Form::Constructed),
        BIT_STRING
        | OCTET_STRING
        | OBJECT_DESCRIPTOR
        | UTF8_STRING
        | NUMERIC_STRING..=IA5_STRING
        | UTC_TIME
        | GENERALIZED_TIME
        | GRAPHIC_STRING..=UNIVERSAL_STRING
        | BMP_STRING => Some(Form::Either),
        _ => Some(Form::Primitive),
    }
}

/// The DER rules a schema-free reader can check on a constructed value: only
/// the types [`universal_form`] marks [`Form::Constructed`] take that form,
/// since §10.2 forbids it for bit, octet and restricted character strings and
/// every other universal type is primitive; each nested value passes the same
/// checks; and the values of a `SET` appear in the §11.6 order of a `SET OF`.
/// Without the schema a `SET` and a `SET OF` look alike, and §10.3's tag order
/// for a `SET` can disagree with §11.6 only when its components mix primitive
/// and constructed encodings, which no structure this crate parses does.
fn constructed_contents_are_der(
    identifier: Identifier,
    contents: &[u8],
    depth: usize,
) -> Option<()> {
    if identifier.is_universal() && universal_form(identifier.number) != Some(Form::Constructed) {
        return None;
    }
    let is_set = identifier.is(universal::SET);
    let mut inner = DerReader::new(contents);
    let mut previous: Option<&[u8]> = None;
    while !inner.is_finished() {
        let start = inner.pos;
        inner.skip_der_element(depth + 1)?;
        let encoding = contents.get(start..inner.pos)?;
        if is_set {
            if previous.is_some_and(|prior| set_of_order(prior, encoding).is_gt()) {
                return None;
            }
            previous = Some(encoding);
        }
    }
    Some(())
}

/// The DER content rules of the primitive universal types a key container
/// can hold: `BOOLEAN` is one octet with `TRUE` as all ones (X.690 §8.2.1,
/// §11.1); `INTEGER` and `ENUMERATED` take the fewest octets (§8.3.1, §8.3.2,
/// §8.4); a `BIT STRING` has at most seven unused bits, none when it is
/// empty, all zero (§8.6.2, §11.2.1); `NULL` is empty (§8.8.2); an
/// `OBJECT IDENTIFIER`'s subidentifiers take the fewest octets (§8.19.2).
/// End-of-contents never appears, since it closes the indefinite form §10.1
/// forbids, and the types [`universal_form`] marks [`Form::Constructed`] are
/// never primitive. The contents of any other primitive value, including
/// every non-universal one, carry no rule a reader can check without the
/// schema.
fn primitive_contents_are_der(identifier: Identifier, contents: &[u8]) -> bool {
    use universal::{BIT_STRING, BOOLEAN, ENUMERATED, INTEGER, NULL, OBJECT_IDENTIFIER};
    if !identifier.is_universal() {
        return true;
    }
    match universal_form(identifier.number) {
        None | Some(Form::Constructed) => return false,
        Some(Form::Primitive | Form::Either) => {}
    }
    match identifier.number {
        BOOLEAN => matches!(contents, [0x00] | [0xff]),
        INTEGER | ENUMERATED => integer_contents_are_minimal(contents),
        BIT_STRING => bit_string_contents_are_der(contents),
        NULL => contents.is_empty(),
        OBJECT_IDENTIFIER => subidentifiers_are_minimal(contents),
        _ => true,
    }
}

/// X.690 §8.3.1 and §8.3.2: at least one octet, and the first nine bits
/// neither all zero nor all one.
fn integer_contents_are_minimal(contents: &[u8]) -> bool {
    match contents {
        [] => false,
        [0x00, next, ..] => next & 0x80 != 0,
        [0xff, next, ..] => next & 0x80 == 0,
        _ => true,
    }
}

/// X.690 §8.6.2 and §11.2.1: the initial octet counts at most seven unused
/// bits, is zero when no octets follow, and the unused bits are zero.
fn bit_string_contents_are_der(contents: &[u8]) -> bool {
    match contents {
        [] => false,
        [unused] => *unused == 0,
        [unused, .., last] => *unused <= 7 && last & ((1u8 << *unused) - 1) == 0,
    }
}

/// X.690 §8.19.2: one or more subidentifiers, each ending at an octet with
/// bit 8 clear and none beginning with the octet `80`.
fn subidentifiers_are_minimal(contents: &[u8]) -> bool {
    let mut at_subidentifier_start = true;
    for &octet in contents {
        if at_subidentifier_start && octet == 0x80 {
            return false;
        }
        at_subidentifier_start = octet & 0x80 == 0;
    }
    !contents.is_empty() && at_subidentifier_start
}

/// X.690 §11.6: the order of two component encodings of a `SET OF`, compared
/// as octet strings with the shorter padded at its trailing end with zero
/// octets.
pub(crate) fn set_of_order(left: &[u8], right: &[u8]) -> core::cmp::Ordering {
    let len = left.len().max(right.len());
    (0..len)
        .map(|index| {
            (
                left.get(index).copied().unwrap_or(0),
                right.get(index).copied().unwrap_or(0),
            )
        })
        .find(|(a, b)| a != b)
        .map_or(core::cmp::Ordering::Equal, |(a, b)| a.cmp(&b))
}

// ─── X.690 BER, brought to DER ───────────────────────────────────────────────

/// Bytes that hold, or may hold, key material: allocated at their final
/// length, never grown, and wiped when dropped.
pub(crate) struct WipedBytes {
    bytes: Vec<u8>,
    /// The length the buffer was sized for, which is all it will hold.
    sized: usize,
}

impl WipedBytes {
    /// An empty buffer with room for exactly `len` bytes.
    fn with_len(len: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(len),
            sized: len,
        }
    }

    /// Append `bytes`, within the length the buffer was sized for. Should a
    /// miscount ever make one grow, the old allocation is wiped before it is
    /// released, so no copy survives either way.
    fn extend(&mut self, bytes: &[u8]) {
        let needed = self.bytes.len() + bytes.len();
        debug_assert!(
            needed <= self.sized,
            "a WipedBytes is sized before it is filled"
        );
        if needed > self.bytes.capacity() {
            let mut grown = Vec::with_capacity(needed);
            grown.extend_from_slice(&self.bytes);
            zeroize_slice(self.bytes.as_mut_slice());
            self.bytes = grown;
        }
        self.bytes.extend_from_slice(bytes);
    }

    /// The buffer's capacity, for the tests that check it equals the length.
    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Zero the low `unused` bits of the final octet: the unused bits of a
    /// bit string, which DER sets to zero (X.690 §11.2.1).
    fn clear_unused_bits(&mut self, unused: u8) {
        if let Some(last) = self.bytes.last_mut() {
            *last &= 0xffu8.checked_shl(u32::from(unused)).unwrap_or(0);
        }
    }

    /// The bytes as a vector, which the caller then owns and wipes.
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl core::ops::Deref for WipedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        zeroize_slice(self.bytes.as_mut_slice());
    }
}

/// The DER encoding of a value whose identifier octets are `leading` then
/// `subsequent` and whose contents are `parts` concatenated, in a buffer of
/// its exact size.
fn der_encoding(leading: u8, subsequent: &[u8], parts: &[&[u8]]) -> WipedBytes {
    let len = parts.iter().map(|part| part.len()).sum();
    let (length, count) = der_length(len);
    let mut out = WipedBytes::with_len(1 + subsequent.len() + count + len);
    out.extend(&[leading]);
    out.extend(subsequent);
    out.extend(&length[..count]);
    for part in parts {
        out.extend(part);
    }
    out
}

/// The DER encoding of a value under the single identifier octet `tag` whose
/// contents are `parts` concatenated, in a wiped buffer of its exact size.
pub(crate) fn wiped_tlv(tag: u8, parts: &[&[u8]]) -> WipedBytes {
    der_encoding(tag, &[], parts)
}

/// The DER encoding of a constructed value with the tag `tag` whose contents
/// are the DER encodings `values`, put in X.690 §11.6 order when `sort`.
fn constructed_der(tag: Tag<'_>, mut values: Vec<WipedBytes>, sort: bool) -> WipedBytes {
    if sort {
        values.sort_by(|left, right| set_of_order(left, right));
    }
    let parts: Vec<&[u8]> = values.iter().map(|value| &value[..]).collect();
    der_encoding(tag.leading(true), tag.subsequent(), &parts)
}

/// A bit string's value as DER writes it: how many bits of its final octet
/// are unused, and its octets with those bits zero (X.690 §11.2.1).
pub(crate) struct BitString {
    unused: u8,
    octets: WipedBytes,
}

impl BitString {
    /// The bit string of the whole octets `octets`.
    pub(crate) fn whole_octets(octets: WipedBytes) -> Self {
        Self { unused: 0, octets }
    }

    /// How many bits of the final octet are unused.
    pub(crate) fn unused(&self) -> u8 {
        self.unused
    }

    /// The octets, unused bits zero.
    pub(crate) fn octets(&self) -> &[u8] {
        &self.octets
    }

    /// The DER encoding under the single identifier octet `tag`, the universal
    /// BIT STRING's or an implicit tag's (§8.14.4), in the primitive form.
    pub(crate) fn to_der(&self, tag: u8) -> WipedBytes {
        wiped_tlv(tag, &[&[self.unused][..], &self.octets[..]])
    }
}

/// Universal class tag numbers (X.680 Table 1) the BER reader tells apart.
mod universal {
    pub const BOOLEAN: u32 = 1;
    pub const INTEGER: u32 = 2;
    pub const BIT_STRING: u32 = 3;
    pub const OCTET_STRING: u32 = 4;
    pub const NULL: u32 = 5;
    pub const OBJECT_IDENTIFIER: u32 = 6;
    pub const OBJECT_DESCRIPTOR: u32 = 7;
    pub const EXTERNAL: u32 = 8;
    pub const ENUMERATED: u32 = 10;
    pub const EMBEDDED_PDV: u32 = 11;
    pub const UTF8_STRING: u32 = 12;
    pub const RELATIVE_OID: u32 = 13;
    pub const SEQUENCE: u32 = 16;
    pub const SET: u32 = 17;
    pub const NUMERIC_STRING: u32 = 18;
    pub const IA5_STRING: u32 = 22;
    pub const UTC_TIME: u32 = 23;
    pub const GENERALIZED_TIME: u32 = 24;
    pub const GRAPHIC_STRING: u32 = 25;
    pub const UNIVERSAL_STRING: u32 = 28;
    pub const CHARACTER_STRING: u32 = 29;
    pub const BMP_STRING: u32 = 30;
}

/// A tag as a BER reader met it: the identifier octets (X.690 §8.1.2) and
/// what they encode.
#[derive(Clone, Copy)]
struct Tag<'a> {
    octets: &'a [u8],
    identifier: Identifier,
}

impl<'a> Tag<'a> {
    /// The leading identifier octet in the primitive or the `constructed`
    /// form (§8.1.2.5), with the class and number as read.
    fn leading(self, constructed: bool) -> u8 {
        let leading = self.octets.first().copied().unwrap_or(0);
        if constructed {
            leading | 0x20
        } else {
            leading & !0x20
        }
    }

    /// The identifier octets after the leading one, which a tag number above
    /// 30 takes (§8.1.2.4).
    fn subsequent(self) -> &'a [u8] {
        self.octets.get(1..).unwrap_or(&[])
    }
}

/// The identifier and length octets of one BER value.
struct Header<'a> {
    tag: Tag<'a>,
    /// The definite length (§8.1.3.3), or `None` for the indefinite form
    /// (§8.1.3.6).
    length: Option<usize>,
}

/// Cursor over the BER encoding (X.690 clause 8) of a value whose
/// specification requires receivers to accept BER. It checks each rule of
/// clause 8 for the forms it meets and hands back the value's DER encoding
/// (clauses 10 and 11) for a [`DerReader`] to decode, so the strict decoders
/// read every BER form without relaxing anything themselves.
///
/// What it accepts, as clause 8 does: lengths in the short form, in the long
/// form with any number of length octets and leading zeros (§8.1.3.5 NOTE 2),
/// or indefinite for a constructed encoding (§8.1.3.6); bit strings, octet
/// strings and the types encoded as octet strings in either form (§8.6.1,
/// §8.7.1, §8.23.3, §8.25); `BOOLEAN` true as any non-zero octet (§8.2.2); the
/// values of a `SET` or `SET OF` in any order (§8.11.2, §8.12.3); and bit
/// strings with unused bits of any value. What it rejects, as clause 8 does: a
/// tag number up to 30 in the long identifier form (§8.1.2.2) or a long form
/// with a redundant leading octet (§8.1.2.4.2 c), the length octet `FF`
/// (§8.1.3.5 c), an indefinite primitive (§8.1.3.2 a), end-of-contents where a
/// value belongs (§8.1.5), a constructed encoding of a type §8 makes
/// primitive, an `INTEGER` or `ENUMERATED` not in the fewest octets (§8.3.2),
/// an `OBJECT IDENTIFIER` subidentifier not in the fewest octets (§8.19.2), a
/// `NULL` with contents (§8.8.2), more than seven unused bits or unused bits
/// in an empty bit string (§8.6.2.2, §8.6.2.3), a segment of the wrong type
/// or, but for the last, a bit-string segment with unused bits (§8.6.4,
/// §8.7.3.2), and a tag X.680 leaves unassigned.
///
/// Totality and cost: every length is checked against the octets left before
/// anything is read past it; constructed encodings nest at most
/// [`MAX_ELEMENT_DEPTH`] deep, and deeper input fails; each input octet is
/// read once, and each nesting level copies what it holds once into its DER
/// encoding, so the work is proportional to the input times the depth, plus
/// the sort of each `SET`.
#[derive(Clone, Copy)]
pub(crate) struct BerReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// No octet at or past this offset belongs to the contents being read.
    limit: usize,
    /// Whether the contents close with end-of-contents octets (§8.1.3.6)
    /// rather than at `limit`.
    indefinite: bool,
    /// Constructed encodings open around the contents.
    depth: usize,
}

impl<'a> BerReader<'a> {
    /// A reader over `data`, which must hold one value and nothing after it
    /// once the caller checks [`Self::is_finished`].
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            limit: data.len(),
            indefinite: false,
            depth: 0,
        }
    }

    /// Whether the contents are exhausted: at their definite end, or at the
    /// end-of-contents octets that close the indefinite form (§8.1.5).
    pub(crate) fn is_finished(&self) -> bool {
        let rest = self.data.get(self.pos..self.limit).unwrap_or(&[]);
        if self.indefinite {
            rest.starts_with(&[0, 0])
        } else {
            rest.is_empty()
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        if self.pos >= self.limit {
            return None;
        }
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    /// The identifier and length octets of the next value (§8.1.2, §8.1.3),
    /// its length checked against what the contents have left.
    fn read_header(&mut self) -> Option<Header<'a>> {
        if self.is_finished() {
            return None;
        }
        let start = self.pos;
        let identifier = parse_identifier(|| self.next_byte())?;
        let octets = self.data.get(start..self.pos)?;
        let length = match self.next_byte()? {
            // §8.1.3.6.1: the indefinite form.
            0x80 => None,
            // §8.1.3.5 c): reserved.
            0xff => return None,
            short @ 0x00..=0x7f => Some(usize::from(short)),
            // §8.1.3.5: the long form, in as many octets as the sender chose.
            long => {
                let mut len = 0usize;
                for _ in 0..(long & 0x7f) {
                    len = len
                        .checked_mul(0x100)?
                        .checked_add(usize::from(self.next_byte()?))?;
                }
                Some(len)
            }
        };
        match length {
            // §8.1.3.2 a): a primitive encoding takes the definite form.
            None if !identifier.constructed => return None,
            Some(len) if len > self.limit - self.pos => return None,
            _ => {}
        }
        Some(Header {
            tag: Tag { octets, identifier },
            length,
        })
    }

    /// Run `body` over the contents of the constructed value `header`
    /// introduces, then move past them: to their definite end, or past the
    /// end-of-contents octets that close them.
    fn enter<T>(
        &mut self,
        header: &Header<'a>,
        body: impl FnOnce(&mut Self) -> Option<T>,
    ) -> Option<T> {
        if !header.tag.identifier.constructed || self.depth >= MAX_ELEMENT_DEPTH {
            return None;
        }
        let mut contents = Self {
            data: self.data,
            pos: self.pos,
            limit: header.length.map_or(self.limit, |len| self.pos + len),
            indefinite: header.length.is_none(),
            depth: self.depth + 1,
        };
        let value = body(&mut contents)?;
        if !contents.is_finished() {
            return None;
        }
        self.pos = if contents.indefinite {
            contents.pos + 2
        } else {
            contents.pos
        };
        Some(value)
    }

    /// The contents octets of the primitive value `header` introduces.
    fn primitive(&mut self, header: &Header<'a>) -> Option<&'a [u8]> {
        if header.tag.identifier.constructed {
            return None;
        }
        let end = self.pos + header.length?;
        let contents = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(contents)
    }

    /// The DER encoding of the next value, whatever its type, once it has
    /// passed the rules of clause 8 that hold without the ASN.1 type (see the
    /// type's documentation). Clauses 10 and 11 are applied as far as they
    /// follow from the encoding alone: definite lengths in the fewest octets,
    /// strings primitive, `BOOLEAN` true as `FF`, unused bits zero, and the
    /// values of a `SET` in §11.6 order. The contents of a value of another
    /// class, of `REAL` and the time types, and of a primitive value under a
    /// tag number X.680 leaves unassigned are kept as they are.
    ///
    /// The forms come from [`universal_form`], the table
    /// [`DerReader::read_element`] checks against, so an encoding that reader
    /// accepts converts to itself.
    pub(crate) fn read_any(&mut self) -> Option<WipedBytes> {
        use universal::{
            BIT_STRING, BOOLEAN, ENUMERATED, INTEGER, NULL, OBJECT_IDENTIFIER, RELATIVE_OID, SET,
        };
        let header = self.read_header()?;
        let tag = header.tag;
        let identifier = tag.identifier;
        if !identifier.is_universal() {
            // Without the type, a value of another class carries no rule of
            // its own: primitive contents are kept, and constructed contents
            // are read as a series of values (§8.14.3, §8.14.4).
            return if identifier.constructed {
                let values = self.enter(&header, Self::read_values)?;
                Some(constructed_der(tag, values, false))
            } else {
                let contents = self.primitive(&header)?;
                Some(der_encoding(
                    tag.leading(false),
                    tag.subsequent(),
                    &[contents],
                ))
            };
        }
        let primitive = tag.leading(false);
        let subsequent = tag.subsequent();
        match universal_form(identifier.number)? {
            // §8.9.1, and §8.17.1, §8.18.1 and §8.24.1 for the types encoded
            // as a sequence: constructed, the values in order. §8.11.1,
            // §8.12.1: a SET is constructed too; without the type a SET and a
            // SET OF look alike, and the values take §11.6's order for a SET
            // OF, which §10.3's order for a SET matches unless its components
            // mix primitive and constructed encodings, as none in a key does.
            Form::Constructed => {
                let values = self.enter(&header, Self::read_values)?;
                Some(constructed_der(tag, values, identifier.is(SET)))
            }
            // §8.6.1: either form, primitive in DER (§10.2).
            Form::Either if identifier.is(BIT_STRING) => {
                Some(self.bit_string_value(&header)?.to_der(primitive))
            }
            // §8.7.1, and §8.23.3 and §8.25 for the types encoded as an OCTET
            // STRING: either form, primitive in DER (§10.2).
            Form::Either => {
                let octets = self.octet_string_value(&header)?;
                Some(der_encoding(primitive, subsequent, &[&octets[..]]))
            }
            Form::Primitive => {
                let contents = self.primitive(&header)?;
                match identifier.number {
                    // §8.2.1, §8.2.2: one octet, true when non-zero, which DER
                    // writes as all ones (§11.1).
                    BOOLEAN => {
                        let [octet] = contents else {
                            return None;
                        };
                        let value = if *octet == 0 { 0x00 } else { 0xff };
                        Some(der_encoding(primitive, subsequent, &[&[value][..]]))
                    }
                    // §8.3.1, §8.3.2, §8.4: one or more octets, the first nine
                    // bits neither all zero nor all one.
                    INTEGER | ENUMERATED => integer_contents_are_minimal(contents)
                        .then(|| der_encoding(primitive, subsequent, &[contents])),
                    // §8.8.1, §8.8.2: primitive and empty.
                    NULL => contents
                        .is_empty()
                        .then(|| der_encoding(primitive, subsequent, &[])),
                    // §8.19.1, §8.19.2, §8.20.1, §8.20.2: each subidentifier
                    // in the fewest octets.
                    OBJECT_IDENTIFIER | RELATIVE_OID => subidentifiers_are_minimal(contents)
                        .then(|| der_encoding(primitive, subsequent, &[contents])),
                    // §8.5.1, §8.21.1, §8.22.1, §8.26: primitive. The normal
                    // forms DER gives REAL and the time types (§11.3, §11.9)
                    // come from reading them, which no key container needs,
                    // so the contents are kept; so are those of a tag number
                    // X.680 Table 1 leaves unassigned, which carry no rule.
                    _ => Some(der_encoding(primitive, subsequent, &[contents])),
                }
            }
        }
    }

    /// The DER encodings of the values left in the contents, in order: at
    /// most [`MAX_CONSTRUCTED_VALUES`] of them.
    fn read_values(&mut self) -> Option<Vec<WipedBytes>> {
        let mut values = Vec::new();
        while !self.is_finished() {
            if values.len() == MAX_CONSTRUCTED_VALUES {
                return None;
            }
            values.push(self.read_any()?);
        }
        Some(values)
    }

    /// The value of an OCTET STRING, or of a type encoded as one, from either
    /// form: the contents octets (§8.7.2), or the values of the segments the
    /// constructed form holds, each an OCTET STRING encoding (§8.7.3),
    /// concatenated.
    fn octet_string_value(&mut self, header: &Header<'a>) -> Option<WipedBytes> {
        let mut segments = Vec::new();
        self.octet_string_segments(header, &mut segments)?;
        let mut octets = WipedBytes::with_len(segments.iter().map(|segment| segment.len()).sum());
        for segment in segments {
            octets.extend(segment);
        }
        Some(octets)
    }

    fn octet_string_segments(
        &mut self,
        header: &Header<'a>,
        segments: &mut Vec<&'a [u8]>,
    ) -> Option<()> {
        if !header.tag.identifier.constructed {
            if segments.len() == MAX_CONSTRUCTED_VALUES {
                return None;
            }
            segments.push(self.primitive(header)?);
            return Some(());
        }
        self.enter(header, |contents| {
            while !contents.is_finished() {
                let segment = contents.read_header()?;
                // §8.7.3.2 NOTE 2: "the tags in the contents octets are always
                // universal class, number 4".
                if !segment.tag.identifier.is(universal::OCTET_STRING) {
                    return None;
                }
                contents.octet_string_segments(&segment, segments)?;
            }
            Some(())
        })
    }

    /// The value of a BIT STRING from either form. A primitive encoding's
    /// initial octet counts the unused bits of its final octet, at most seven
    /// and none when no octet follows (§8.6.2.2, §8.6.2.3); the constructed
    /// form holds BIT STRING segments, each a whole number of octets but the
    /// last (§8.6.3, §8.6.4).
    fn bit_string_value(&mut self, header: &Header<'a>) -> Option<BitString> {
        let mut segments = Vec::new();
        self.bit_string_segments(header, &mut segments)?;
        let unused = match segments.split_last() {
            Some((&(unused, _), earlier)) => {
                if earlier.iter().any(|&(unused, _)| unused != 0) {
                    return None;
                }
                unused
            }
            None => 0,
        };
        let mut octets =
            WipedBytes::with_len(segments.iter().map(|(_, segment)| segment.len()).sum());
        for (_, segment) in segments {
            octets.extend(segment);
        }
        octets.clear_unused_bits(unused);
        Some(BitString { unused, octets })
    }

    fn bit_string_segments(
        &mut self,
        header: &Header<'a>,
        segments: &mut Vec<(u8, &'a [u8])>,
    ) -> Option<()> {
        if !header.tag.identifier.constructed {
            let (&unused, octets) = self.primitive(header)?.split_first()?;
            if unused > 7
                || (octets.is_empty() && unused != 0)
                || segments.len() == MAX_CONSTRUCTED_VALUES
            {
                return None;
            }
            segments.push((unused, octets));
            return Some(());
        }
        self.enter(header, |contents| {
            while !contents.is_finished() {
                let segment = contents.read_header()?;
                // §8.6.4.1 NOTE 2: "the tags in the contents octets are always
                // universal class, number 3".
                if !segment.tag.identifier.is(universal::BIT_STRING) {
                    return None;
                }
                contents.bit_string_segments(&segment, segments)?;
            }
            Some(())
        })
    }

    /// Whether the next value's tag is `class` `number`, in either form.
    pub(crate) fn next_is(&self, class: u8, number: u32) -> bool {
        let mut probe = *self;
        probe.read_header().is_some_and(|header| {
            header.tag.identifier.class == class && header.tag.identifier.number == number
        })
    }

    /// Run `body` over the contents of the next value, a SEQUENCE.
    pub(crate) fn read_sequence<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Option<T>,
    ) -> Option<T> {
        let header = self.read_header()?;
        if !header.tag.identifier.is(universal::SEQUENCE) {
            return None;
        }
        self.enter(&header, body)
    }

    /// The contents octets of the next value, an OBJECT IDENTIFIER (§8.19).
    pub(crate) fn read_oid(&mut self) -> Option<&'a [u8]> {
        let header = self.read_header()?;
        if !header.tag.identifier.is(universal::OBJECT_IDENTIFIER) {
            return None;
        }
        let contents = self.primitive(&header)?;
        subidentifiers_are_minimal(contents).then_some(contents)
    }

    /// The DER encoding of the next value, an INTEGER (§8.3).
    pub(crate) fn read_integer(&mut self) -> Option<WipedBytes> {
        if !self.next_is(class::UNIVERSAL, universal::INTEGER) {
            return None;
        }
        self.read_any()
    }

    /// The value of the next value, an OCTET STRING in either form (§8.7).
    pub(crate) fn read_octet_string(&mut self) -> Option<WipedBytes> {
        let header = self.read_header()?;
        if !header.tag.identifier.is(universal::OCTET_STRING) {
            return None;
        }
        self.octet_string_value(&header)
    }

    /// The value of the next value, a BIT STRING in either form under the tag
    /// `class` `number`: the universal one, or an implicit tag (§8.14.4).
    pub(crate) fn read_bit_string(&mut self, class: u8, number: u32) -> Option<BitString> {
        let header = self.read_header()?;
        let identifier = header.tag.identifier;
        if identifier.class != class || identifier.number != number {
            return None;
        }
        self.bit_string_value(&header)
    }

    /// The DER encoding of the next value, a SET OF under the tag `class`
    /// `number`, its elements read as by [`Self::read_any`] and put in §11.6
    /// order.
    pub(crate) fn read_set_of(&mut self, class: u8, number: u32) -> Option<WipedBytes> {
        let header = self.read_header()?;
        let identifier = header.tag.identifier;
        if identifier.class != class || identifier.number != number {
            return None;
        }
        let values = self.enter(&header, Self::read_values)?;
        Some(constructed_der(header.tag, values, true))
    }
}

/// The DER encoding of the one value `ber` holds in BER, all of `ber`, as
/// [`BerReader::read_any`] converts it. Exact wherever the value's type
/// follows from its encoding: universal types, and explicit tags around
/// them, as in the PKCS #1 and SEC 1 key structures.
pub(crate) fn ber_to_der(ber: &[u8]) -> Option<WipedBytes> {
    let mut reader = BerReader::new(ber);
    let der = reader.read_any()?;
    reader.is_finished().then_some(der)
}

/// The crate's integer-sequence blob: a DER `SEQUENCE` of non-negative
/// `INTEGER`s in schema order. The fields may be private-key components, so
/// the blob is sized exactly and no intermediate copy survives.
pub(crate) fn encode_biguints(fields: &[&BigUint]) -> Vec<u8> {
    der_sequence_of(
        fields
            .iter()
            .map(|field| der_integer_biguint(field))
            .collect(),
    )
}

/// Inverse of [`encode_biguints`] for a schema of at most `max_fields`
/// integers: a blob holding more fails before its excess is decoded, so an
/// input can cost no more than `max_fields` values. The caller still checks
/// that the count is its schema's, since fewer fields also decode.
pub(crate) fn decode_biguints_at_most(input: &[u8], max_fields: usize) -> Option<Vec<BigUint>> {
    let mut outer = DerReader::new(input);
    let body = outer.read_sequence()?;
    if !outer.is_finished() {
        return None;
    }

    let mut reader = DerReader::new(body);
    let mut out = Vec::new();
    while !reader.is_finished() {
        if out.len() == max_fields {
            return None;
        }
        out.push(reader.read_integer_biguint()?);
    }
    Some(out)
}

/// Most fields [`decode_biguints`] reads: every schema in the crate has at
/// most nine, and a hand-rolled decoder that takes the blob's own count is
/// bounded here.
pub(crate) const DEFAULT_MAX_BIGUINT_FIELDS: usize = 16;

/// [`decode_biguints_at_most`] with [`DEFAULT_MAX_BIGUINT_FIELDS`], for a
/// decoder that reads the fields one by one and counts them itself.
pub(crate) fn decode_biguints(input: &[u8]) -> Option<Vec<BigUint>> {
    decode_biguints_at_most(input, DEFAULT_MAX_BIGUINT_FIELDS)
}

// ─── RFC 7468 textual encoding ───────────────────────────────────────────────

/// The pre-encapsulation boundary up to its label (RFC 7468 §2).
const PREEB_START: &str = "-----BEGIN ";

/// The post-encapsulation boundary up to its label.
const POSTEB_START: &str = "-----END ";

/// What follows the label on either boundary: "exactly five hyphen-minus".
const BOUNDARY_END: &str = "-----";

/// Base64 characters on each line of the strict form but the last (RFC 7468
/// §2: "exactly 64 characters except for the final line").
const PEM_LINE_SYMBOLS: usize = 64;

/// Most bytes [`pem_contents`] reads between the encapsulation boundaries.
/// RFC 7468 sets no bound; this one is far above any key container the crate
/// decodes (the largest, an ML-DSA-87 private key, is under 7 KiB of base64)
/// yet keeps the two buffers the decoder allocates proportionate to a key,
/// not to whatever text arrives under the label.
pub(crate) const MAX_PEM_ENCAPSULATED_TEXT: usize = 1 << 20;

/// Armor `blob` under `label` in RFC 7468's strict textual encoding (§3,
/// Figure 3): each boundary on a line of its own, the base64 (RFC 4648 §4) in
/// lines of exactly 64 characters but the last, LF line ends and no other
/// whitespace. The text is written straight into a string allocated at its
/// exact length, so armoring a private key leaves no copy of its base64 in
/// freed memory.
pub(crate) fn pem_wrap(label: &str, blob: &[u8]) -> String {
    let symbols = blob.len().div_ceil(3) * 4;
    let boundaries =
        PREEB_START.len() + POSTEB_START.len() + 2 * (label.len() + BOUNDARY_END.len() + 1);
    let mut out = String::with_capacity(boundaries + symbols + symbols.div_ceil(PEM_LINE_SYMBOLS));
    out.push_str(PREEB_START);
    out.push_str(label);
    out.push_str(BOUNDARY_END);
    out.push('\n');
    let mut quantum = [0u8; 4];
    let mut column = 0;
    for chunk in blob.chunks(3) {
        base64_quantum(chunk, &mut quantum);
        for &symbol in &quantum {
            out.push(char::from(symbol));
            column += 1;
            if column == PEM_LINE_SYMBOLS {
                out.push('\n');
                column = 0;
            }
        }
    }
    if column != 0 {
        out.push('\n');
    }
    zeroize_slice(quantum.as_mut_slice());
    out.push_str(POSTEB_START);
    out.push_str(label);
    out.push_str(BOUNDARY_END);
    out.push('\n');
    out
}

/// [`pem_contents`] as a vector, which the caller then owns and wipes.
pub(crate) fn pem_unwrap(label: &str, text: &str) -> Option<Vec<u8>> {
    pem_contents(label, text).map(WipedBytes::into_vec)
}

/// The contents of the first textual encoding labelled `label` in `text`,
/// read as RFC 7468 §2 directs a parser:
///
/// - Data before the pre-encapsulation boundary is skipped, whatever it holds
///   ("parsers MUST NOT malfunction when processing such data").
/// - Lines end at CRLF, CR or LF ("MUST handle different newline
///   conventions").
/// - Each encapsulation boundary is "a line comprising '-----BEGIN ', a
///   label, and '-----'" (`END` for the post-encapsulation boundary): exactly
///   one space after the keyword, exactly five hyphen-minus at each end, and
///   the label as written, labels being case-sensitive. Whitespace around a
///   boundary on its line is ignored. The end boundary must carry the same
///   label: the RFC lets a parser disregard a mismatch "instead of signaling
///   an error", and this one signals it.
/// - Between the boundaries, whitespace (HT, VT, FF, SP, CR and LF) and every
///   other character outside the base64 alphabet are ignored ("parsers SHOULD
///   ignore whitespace and other non-base64 characters"). The empty space the
///   RFC permits before the base64, blank lines and indentation are therefore
///   all read. A line that begins with five hyphen-minus is a boundary, not
///   base64, and anything there but the matching end boundary fails.
/// - Line length binds generators, not parsers: "Generators MUST wrap the
///   base64-encoded lines so that each line consists of exactly 64 characters
///   except for the final line, which will encode the remainder of the data
///   (within the 64-character line boundary), and they MUST NOT emit
///   extraneous whitespace.  Parsers MAY handle other line sizes.  These
///   requirements are consistent with PEM [RFC1421]." Lines of any length
///   are read. The text between the boundaries is bounded instead, at
///   [`MAX_PEM_ENCAPSULATED_TEXT`] bytes.
/// - What follows the end boundary's line is not part of the message: another
///   instance, or any other text.
/// - The base64 is RFC 4648 §4's with its padding: a whole number of
///   four-character quanta, `=` only as the final quantum's last one or two
///   characters, and the pad bits zero, which RFC 4648 §3.5 lets a decoder
///   require.
///
/// The base64 characters and the decoded octets are held in buffers allocated
/// at their final size and wiped when dropped.
pub(crate) fn pem_contents(label: &str, text: &str) -> Option<WipedBytes> {
    let text = text.as_bytes();
    let (start, end) = base64_region(label.as_bytes(), text)?;
    let region = text.get(start..end)?;
    if region.len() > MAX_PEM_ENCAPSULATED_TEXT {
        return None;
    }
    let base64 = || {
        region
            .iter()
            .copied()
            .filter(|&symbol| is_base64_symbol(symbol))
    };
    let mut symbols = WipedBytes::with_len(base64().count());
    for symbol in base64() {
        symbols.extend(&[symbol]);
    }
    base64_decode_canonical(&symbols)
}

/// Where the base64 of the first textual encoding labelled `label` lies in
/// `text`: from the end of its pre-encapsulation boundary's line to the start
/// of its post-encapsulation boundary's line.
fn base64_region(label: &[u8], text: &[u8]) -> Option<(usize, usize)> {
    let mut lines = LineSpans { text, next: 0 };
    let (_, start) = lines.find(|&(from, to)| is_boundary(&text[from..to], PREEB_START, label))?;
    for (from, to) in lines {
        if trim_whitespace(&text[from..to]).starts_with(BOUNDARY_END.as_bytes()) {
            return is_boundary(&text[from..to], POSTEB_START, label).then_some((start, from));
        }
    }
    None
}

/// Whether `line` is the encapsulation boundary that begins with `start` and
/// carries `label`, whitespace around it ignored (RFC 7468 §2).
fn is_boundary(line: &[u8], start: &str, label: &[u8]) -> bool {
    trim_whitespace(line)
        .strip_prefix(start.as_bytes())
        .and_then(|rest| rest.strip_prefix(label))
        .is_some_and(|rest| rest == BOUNDARY_END.as_bytes())
}

/// The lines of a text as byte ranges, divided at each CR and each LF, so that
/// CRLF, CR and LF all end a line (RFC 7468 §2). CRLF leaves an empty line
/// between its two characters, which is neither a boundary nor base64.
struct LineSpans<'t> {
    text: &'t [u8],
    next: usize,
}

impl Iterator for LineSpans<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let from = self.next;
        let rest = self.text.get(from..)?;
        let to = rest
            .iter()
            .position(|&character| character == b'\r' || character == b'\n')
            .map_or(self.text.len(), |at| from + at);
        self.next = to + 1;
        Some((from, to))
    }
}

/// `line` without the whitespace RFC 7468 §2 names at either end: HT, VT, FF
/// and SP, the line dividers CR and LF being gone already.
fn trim_whitespace(line: &[u8]) -> &[u8] {
    let blank = |character: &u8| matches!(character, b'\t' | 0x0b | 0x0c | b' ');
    let start = line
        .iter()
        .position(|character| !blank(character))
        .unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|character| !blank(character))
        .map_or(start, |at| at + 1);
    &line[start..end]
}

/// Whether `character` is base64: one of the 64-character alphabet or the pad
/// `=` (RFC 4648 §4, Table 1).
fn is_base64_symbol(character: u8) -> bool {
    character == b'=' || decode_base64_char(character).is_some()
}

/// The base64 of one to three octets `chunk` (RFC 4648 §4), padded to a whole
/// quantum, written into `quantum`.
fn base64_quantum(chunk: &[u8], quantum: &mut [u8; 4]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let octet = |index: usize| u32::from(chunk.get(index).copied().unwrap_or(0));
    let group = (octet(0) << 16) | (octet(1) << 8) | octet(2);
    for (index, symbol) in quantum.iter_mut().enumerate() {
        // A quantum of n octets takes n + 1 characters; the rest are padding.
        *symbol = if index <= chunk.len() {
            let sextet = (group >> (18 - 6 * index)) & 0x3f;
            ALPHABET[usize::try_from(sextet).expect("a sextet fits in usize")]
        } else {
            b'='
        };
    }
}

/// Decode the base64 characters `symbols` (RFC 4648 §4): a whole number of
/// four-character quanta, `=` only as the final quantum's last one or two
/// characters, and the pad bits zero (§3.5). No characters decode to no
/// octets (§10).
fn base64_decode_canonical(symbols: &[u8]) -> Option<WipedBytes> {
    if !symbols.len().is_multiple_of(4) {
        return None;
    }
    let padding = symbols
        .iter()
        .rev()
        .take_while(|&&symbol| symbol == b'=')
        .count();
    if padding > 2 {
        return None;
    }
    let data = &symbols[..symbols.len() - padding];
    let mut out = WipedBytes::with_len(data.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &symbol in data {
        accumulator = (accumulator << 6) | u32::from(decode_base64_char(symbol)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.extend(&[(accumulator >> bits).to_be_bytes()[3]]);
            accumulator &= (1 << bits) - 1;
        }
    }
    // §3.5: the bits left after the last whole octet are pad bits.
    (accumulator == 0).then_some(out)
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
                const FIELDS: usize = [$($field),+].len();
                let fields = crate::public_key::io::decode_biguints_at_most(blob, FIELDS)?;
                if fields.len() != FIELDS {
                    return None;
                }
                Self::from_serial_fields(fields)
            }

            /// Encode as PEM text armor over the DER body, using the
            /// crate-defined label.
            #[must_use]
            pub fn to_pem(&self) -> String {
                let mut blob = self.to_key_blob();
                let pem = crate::public_key::io::pem_wrap($label, &blob);
                crate::zeroize_slice(blob.as_mut_slice());
                pem
            }

            /// Decode from the crate-defined PEM label.
            #[must_use]
            pub fn from_pem(pem: &str) -> Option<Self> {
                let mut blob = crate::public_key::io::pem_unwrap($label, pem)?;
                let parsed = Self::from_key_blob(&blob);
                crate::zeroize_slice(blob.as_mut_slice());
                parsed
            }
        }
    };
}
pub(crate) use impl_blob_pem_serialization;

/// Encode the crate's flat XML representation for one key or ciphertext.
///
/// `root` is the outer element name and `fields` supplies the fixed child
/// elements in order. The fields may be private-key components, so the
/// document is written into a string allocated at its exact length and each
/// value's transient byte image is wiped.
pub(crate) fn xml_wrap(root: &str, fields: &[(&str, &BigUint)]) -> String {
    // Tag names are crate-controlled identifiers and the field values are
    // uppercase hexadecimal, so no XML escaping is ever required and the
    // document can be emitted by simple concatenation.
    let mut images: Vec<Vec<u8>> = fields
        .iter()
        .map(|(_, value)| value.to_be_bytes())
        .collect();
    // `<name>` and `</name>` take twice the name and five characters more.
    let element = |name: &str, contents: usize| 2 * name.len() + 5 + contents;
    let contents = fields
        .iter()
        .zip(&images)
        .map(|((name, _), image)| element(name, 2 * image.len()))
        .sum();
    let mut out = String::with_capacity(element(root, contents));
    out.push('<');
    out.push_str(root);
    out.push('>');
    for ((name, _), image) in fields.iter().zip(&mut images) {
        out.push('<');
        out.push_str(name);
        out.push('>');
        for &byte in image.iter() {
            out.push(char::from(UPPER_HEX[usize::from(byte >> 4)]));
            out.push(char::from(UPPER_HEX[usize::from(byte & 0x0f)]));
        }
        zeroize_slice(image.as_mut_slice());
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

/// The value of one character of the base64 alphabet (RFC 4648 §4, Table 1).
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
    let value = BigUint::from_be_bytes(&out);
    zeroize_slice(out.as_mut_slice());
    Some(value)
}

fn decode_hex_char(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        _ => None,
    }
}

/// BER forms a DER encoder never writes, built for tests from DER encodings.
#[cfg(test)]
pub(crate) mod ber_forms {
    /// How [`reencode`] rewrites each value.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Style {
        /// Length octets after the initial one in every definite length, or 0
        /// for the fewest (X.690 §8.1.3.5 NOTE 2).
        pub(crate) length_octets: usize,
        /// Whether constructed values take the indefinite form (§8.1.3.6).
        pub(crate) indefinite: bool,
        /// Octets per segment when OCTET STRING and BIT STRING values, and the
        /// implicitly tagged `[1]` bit string, take the constructed form
        /// (§8.6.4, §8.7.3), or 0 to keep them primitive.
        pub(crate) segment: usize,
    }

    /// The styles the tests apply: indefinite lengths, long-form lengths,
    /// segmented strings, and all three at once.
    pub(crate) const STYLES: [Style; 4] = [
        Style {
            length_octets: 0,
            indefinite: true,
            segment: 0,
        },
        Style {
            length_octets: 3,
            indefinite: false,
            segment: 0,
        },
        Style {
            length_octets: 0,
            indefinite: false,
            segment: 5,
        },
        Style {
            length_octets: 1,
            indefinite: true,
            segment: 7,
        },
    ];

    /// The DER value at the front of `der`, which has a single-octet
    /// identifier: the identifier, the contents, and what follows.
    fn split(der: &[u8]) -> (u8, &[u8], &[u8]) {
        let (len, header) = match der[1] {
            short if short < 0x80 => (usize::from(short), 2),
            long => {
                let count = usize::from(long & 0x7f);
                let len = der[2..2 + count]
                    .iter()
                    .fold(0, |len, &octet| (len << 8) | usize::from(octet));
                (len, 2 + count)
            }
        };
        (der[0], &der[header..header + len], &der[header + len..])
    }

    /// `tag` over `contents` with the length in at least `length_octets`
    /// long-form octets, or in the fewest octets when that is 0.
    pub(crate) fn tlv(tag: u8, contents: &[u8], length_octets: usize) -> Vec<u8> {
        if length_octets == 0 {
            return super::der_tlv(tag, contents);
        }
        let be = contents.len().to_be_bytes();
        let significant = &be[be.iter().take_while(|&&octet| octet == 0).count()..];
        let count = length_octets.max(significant.len());
        let mut out = vec![tag, 0x80 | u8::try_from(count).expect("length octet count")];
        out.resize(out.len() + count - significant.len(), 0);
        out.extend_from_slice(significant);
        out.extend_from_slice(contents);
        out
    }

    /// `der`, a series of DER values with single-octet identifiers, rewritten
    /// in `style`, including every value nested in a constructed one but not
    /// what an OCTET STRING or BIT STRING holds.
    pub(crate) fn reencode(der: &[u8], style: Style) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = der;
        while !rest.is_empty() {
            let (tag, contents, after) = split(rest);
            if tag & 0x20 != 0 {
                out.extend(wrap_constructed(tag, &reencode(contents, style), style));
            } else if matches!(tag, 0x03 | 0x04 | 0x81) && style.segment > 0 {
                out.extend(segmented(tag, contents, style));
            } else {
                out.extend(tlv(tag, contents, style.length_octets));
            }
            rest = after;
        }
        out
    }

    fn wrap_constructed(tag: u8, contents: &[u8], style: Style) -> Vec<u8> {
        if style.indefinite {
            [&[tag, 0x80][..], contents, &[0x00, 0x00]].concat()
        } else {
            tlv(tag, contents, style.length_octets)
        }
    }

    /// The string `tag` `contents` in the constructed form, in segments of
    /// `style.segment` octets: OCTET STRING segments for an octet string, and
    /// for a bit string BIT STRING segments of which only the last carries the
    /// unused bits (§8.6.4).
    fn segmented(tag: u8, contents: &[u8], style: Style) -> Vec<u8> {
        let mut inner = Vec::new();
        if tag == 0x04 {
            for piece in contents.chunks(style.segment) {
                inner.extend(tlv(0x04, piece, style.length_octets));
            }
        } else {
            let (&unused, octets) = contents.split_first().expect("initial octet");
            let pieces: Vec<&[u8]> = octets.chunks(style.segment).collect();
            for (index, piece) in pieces.iter().enumerate() {
                let initial = if index + 1 == pieces.len() { unused } else { 0 };
                inner.extend(tlv(
                    0x03,
                    &[&[initial][..], piece].concat(),
                    style.length_octets,
                ));
            }
        }
        wrap_constructed(tag | 0x20, &inner, style)
    }
}

#[cfg(test)]
mod tests {
    use super::ber_forms::{reencode, STYLES};
    use super::{
        base64_decode_canonical, ber_to_der, decode_biguints, decode_biguints_at_most,
        der_bit_string, der_encoding, der_explicit, der_integer_biguint, der_octet_string, der_oid,
        der_sequence, encode_biguints, pem_contents, pem_unwrap, pem_wrap, wiped_tlv, xml_unwrap,
        xml_wrap, DerReader, DEFAULT_MAX_BIGUINT_FIELDS, MAX_CONSTRUCTED_VALUES, MAX_ELEMENT_DEPTH,
        MAX_PEM_ENCAPSULATED_TEXT,
    };
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
    fn integer_encoding_is_minimal_and_sign_safe() {
        // Zero is the single octet 00; a set high bit gets exactly one 00.
        assert_eq!(der_integer_biguint(&BigUint::zero()), [0x02, 0x01, 0x00]);
        assert_eq!(
            der_integer_biguint(&BigUint::from_u64(0x7f)),
            [0x02, 0x01, 0x7f]
        );
        assert_eq!(
            der_integer_biguint(&BigUint::from_u64(0x80)),
            [0x02, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn long_form_length_roundtrip() {
        let big = BigUint::from_be_bytes(&[0x5a; 300]);
        let blob = encode_biguints(&[&big]);
        // 300-byte content: SEQUENCE length is long form with two octets.
        assert_eq!(blob[1], 0x82);
        assert_eq!(decode_biguints(&blob).expect("parse"), vec![big]);
    }

    // ── X.690 §10 rejections: every BER-only shape must fail ──────────────

    #[test]
    fn rejects_long_form_length_below_128() {
        // SEQUENCE { INTEGER 5 } with the outer length as `81 03` instead of `03`.
        let blob = [0x30, 0x81, 0x03, 0x02, 0x01, 0x05];
        assert!(decode_biguints(&blob).is_none());
        assert!(decode_biguints(&[0x30, 0x03, 0x02, 0x01, 0x05]).is_some());
    }

    #[test]
    fn rejects_leading_zero_length_octet() {
        let mut blob = encode_biguints(&[&BigUint::from_be_bytes(&[0x5a; 200])]);
        // Rewrite `81 C9` as `82 00 C9`.
        assert_eq!(blob[1], 0x81);
        blob.splice(1..2, [0x82, 0x00]);
        assert!(decode_biguints(&blob).is_none());
    }

    #[test]
    fn rejects_indefinite_length() {
        let blob = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
        assert!(decode_biguints(&blob).is_none());
    }

    #[test]
    fn rejects_length_octets_wider_than_usize() {
        let mut blob = vec![0x30, 0x89];
        blob.extend_from_slice(&[0x01; 9]);
        assert!(decode_biguints(&blob).is_none());
    }

    #[test]
    fn rejects_non_minimal_integer() {
        // INTEGER 5 encoded with a redundant leading zero.
        let blob = [0x30, 0x04, 0x02, 0x02, 0x00, 0x05];
        assert!(decode_biguints(&blob).is_none());
    }

    #[test]
    fn rejects_negative_and_empty_integer() {
        assert!(decode_biguints(&[0x30, 0x03, 0x02, 0x01, 0x85]).is_none());
        assert!(decode_biguints(&[0x30, 0x02, 0x02, 0x00]).is_none());
    }

    #[test]
    fn rejects_trailing_bytes_and_truncation() {
        let mut blob = encode_biguints(&[&BigUint::from_u64(5)]);
        blob.push(0x00);
        assert!(decode_biguints(&blob).is_none());
        let blob = encode_biguints(&[&BigUint::from_u64(0x1234)]);
        assert!(decode_biguints(&blob[..blob.len() - 1]).is_none());
    }

    #[test]
    fn rejects_wrong_tags() {
        // OCTET STRING where a SEQUENCE is required; SEQUENCE holding a NULL.
        assert!(decode_biguints(&[0x04, 0x03, 0x02, 0x01, 0x05]).is_none());
        assert!(decode_biguints(&[0x30, 0x02, 0x05, 0x00]).is_none());
    }

    #[test]
    fn bit_string_requires_zero_unused_bits() {
        let good = der_bit_string(&[0xaa]);
        let mut reader = DerReader::new(&good);
        assert_eq!(reader.read_bit_string().expect("bit string"), [0xaa]);
        assert!(reader.is_finished());

        let bad = [0x03, 0x02, 0x01, 0xaa];
        assert!(DerReader::new(&bad).read_bit_string().is_none());
    }

    #[test]
    fn small_integer_reader_bounds_the_value() {
        let version = der_sequence(&der_integer_biguint(&BigUint::from_u64(0)));
        let mut outer = DerReader::new(&version);
        let body = outer.read_sequence().expect("sequence");
        assert_eq!(DerReader::new(body).read_integer_small(), Some(0));

        let wide = der_integer_biguint(&BigUint::from_u64(0x100));
        assert!(DerReader::new(&wide).read_integer_small().is_none());
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

    // ── Exact allocation: no reallocation strands a copy of a secret ──────

    #[test]
    fn der_encoders_allocate_exactly_their_length() {
        for value in [
            BigUint::zero(),
            BigUint::from_u64(0x7f),
            BigUint::from_u64(0x80),
            BigUint::from_be_bytes(&[0xff; 200]),
            BigUint::from_be_bytes(&[0x5a; 70_000]),
        ] {
            let integer = der_integer_biguint(&value);
            assert_eq!(integer.capacity(), integer.len());
            let blob = encode_biguints(&[&value, &value]);
            assert_eq!(blob.capacity(), blob.len());
            assert_eq!(decode_biguints(&blob), Some(vec![value.clone(), value]));
        }
        for len in [0, 1, 127, 128, 255, 256, 65_535, 65_536] {
            let string = der_octet_string(&vec![0xa5; len]);
            assert_eq!(string.capacity(), string.len(), "{len}");
        }
    }

    #[test]
    fn pem_and_xml_armor_allocate_exactly_their_length() {
        for len in 0..200usize {
            let blob: Vec<u8> = (0..len)
                .map(|index| u8::try_from((index * 37 + 11) % 256).expect("byte"))
                .collect();
            let pem = pem_wrap("CRYPTOGRAPHY TEST KEY", &blob);
            assert_eq!(pem.capacity(), pem.len(), "{len}");
            // RFC 7468 §3 Figure 3: every base64 line but the last is 64
            // characters, and the last is 1 to 64.
            let lines: Vec<&str> = pem.lines().collect();
            let base64 = &lines[1..lines.len() - 1];
            if let Some((last, full)) = base64.split_last() {
                assert!(full.iter().all(|line| line.len() == 64));
                assert!((1..=64).contains(&last.len()));
            }
            assert_eq!(pem_unwrap("CRYPTOGRAPHY TEST KEY", &pem), Some(blob));
        }
        let values = [
            BigUint::zero(),
            BigUint::from_u64(0x00ab_cdef),
            BigUint::from_be_bytes(&[0x81; 97]),
        ];
        let xml = xml_wrap(
            "TestKey",
            &[("a", &values[0]), ("bb", &values[1]), ("ccc", &values[2])],
        );
        assert_eq!(xml.capacity(), xml.len());
        assert_eq!(
            xml_unwrap("TestKey", &["a", "bb", "ccc"], &xml),
            Some(values.to_vec())
        );
    }

    #[test]
    fn base64_must_be_canonical() {
        // RFC 4648 §10 vectors, the empty string among them.
        for (text, bytes) in [
            ("", &b""[..]),
            ("Zg==", b"f"),
            ("Zm8=", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg==", b"foob"),
            ("Zm9vYmE=", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
        ] {
            assert_eq!(
                base64_decode_canonical(text.as_bytes()).as_deref(),
                Some(bytes),
                "{text}"
            );
        }
        // Non-zero pad bits (RFC 4648 §3.5), padding inside the data, three
        // pads, and a partial quantum.
        for text in ["Zh==", "Zm9=", "Zg==Zg==", "Z===", "Zm9", "Z=g="] {
            assert!(base64_decode_canonical(text.as_bytes()).is_none(), "{text}");
        }
    }

    #[test]
    fn crate_labels_are_read_by_the_rfc7468_parser_rules() {
        let pem = pem_wrap("CRYPTOGRAPHY TEST KEY", b"foobar");
        assert_eq!(pem, "-----BEGIN CRYPTOGRAPHY TEST KEY-----\nZm9vYmFy\n-----END CRYPTOGRAPHY TEST KEY-----\n");
        // RFC 7468 §2: data before the boundary, CRLF line ends, and ignored
        // whitespace and non-base64 characters.
        let lax = "note\r\n-----BEGIN CRYPTOGRAPHY TEST KEY-----\r\n Zm9v\r\n\r\n*YmFy \r\n-----END CRYPTOGRAPHY TEST KEY-----\r\n";
        assert_eq!(
            pem_contents("CRYPTOGRAPHY TEST KEY", lax).as_deref(),
            Some(&b"foobar"[..])
        );
        assert!(pem_contents("CRYPTOGRAPHY OTHER KEY", &pem).is_none());
    }

    // ── X.690 BER, brought to DER ─────────────────────────────────────────

    fn der_of(ber: &[u8]) -> Option<Vec<u8>> {
        ber_to_der(ber).map(|der| der.to_vec())
    }

    #[test]
    fn ber_examples_of_x690_convert_to_their_der() {
        // §8.6.4.2: the bit string '0A3B5F291CD'H, primitive and constructed.
        let bits = [0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0];
        let constructed_bits = [
            0x23, 0x80, 0x03, 0x03, 0x00, 0x0A, 0x3B, 0x03, 0x05, 0x04, 0x5F, 0x29, 0x1C, 0xD0,
            0x00, 0x00,
        ];
        for ber in [&bits[..], &constructed_bits] {
            assert_eq!(der_of(ber).as_deref(), Some(&bits[..]));
        }
        // §8.23.5: the VisibleString "Jones" in the three forms it prints,
        // which §8.23.6 says "Receivers are required to handle".
        let jones = [0x1A, 0x05, 0x4A, 0x6F, 0x6E, 0x65, 0x73];
        for ber in [
            &jones[..],
            &[
                0x3A, 0x09, 0x04, 0x03, 0x4A, 0x6F, 0x6E, 0x04, 0x02, 0x65, 0x73,
            ],
            &[
                0x3A, 0x80, 0x04, 0x03, 0x4A, 0x6F, 0x6E, 0x04, 0x02, 0x65, 0x73, 0x00, 0x00,
            ],
        ] {
            assert_eq!(der_of(ber).as_deref(), Some(&jones[..]));
        }
        // §8.9.3: SEQUENCE {name "Smith", ok TRUE}, and with the sequence
        // indefinite and TRUE as another non-zero octet (§8.2.2).
        let smith = [
            0x30, 0x0A, 0x16, 0x05, 0x53, 0x6D, 0x69, 0x74, 0x68, 0x01, 0x01, 0xFF,
        ];
        let smith_ber = [
            0x30, 0x80, 0x16, 0x05, 0x53, 0x6D, 0x69, 0x74, 0x68, 0x01, 0x01, 0x01, 0x00, 0x00,
        ];
        for ber in [&smith[..], &smith_ber] {
            assert_eq!(der_of(ber).as_deref(), Some(&smith[..]));
        }
        // §8.19.5: {2 999 3}.
        let oid = [0x06, 0x03, 0x88, 0x37, 0x03];
        assert_eq!(der_of(&oid).as_deref(), Some(&oid[..]));
    }

    #[test]
    fn ber_length_forms_follow_clause_8_1_3() {
        let der = [0x04, 0x01, 0xaa];
        let mut widest = vec![0x04, 0xfe];
        widest.extend([0u8; 125]);
        widest.extend([0x01, 0xaa]);
        for ber in [
            // §8.1.3.5 NOTE 2: more length octets than needed, below 128 and
            // with leading zeros, up to the 126 that §8.1.3.5 c) leaves.
            &[0x04, 0x81, 0x01, 0xaa][..],
            &[0x04, 0x82, 0x00, 0x01, 0xaa],
            &widest,
            // §8.1.3.6: the indefinite form, for a constructed encoding.
            &[0x24, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x00],
        ] {
            assert_eq!(der_of(ber).as_deref(), Some(&der[..]), "{ber:02x?}");
        }
        // §8.1.3.5 EXAMPLE: L = 201 as 81 C9, which DER also writes.
        let long = [&[0x04, 0x81, 0xc9][..], &[0x5a; 201]].concat();
        assert_eq!(der_of(&long).as_deref(), Some(&long[..]));
        for ber in [
            // §8.1.3.5 c): the initial octet FF.
            &[0x04, 0xff, 0x01, 0xaa][..],
            // §8.1.3.2 a): an indefinite primitive.
            &[0x04, 0x80, 0xaa, 0x00, 0x00],
            // Lengths past the input, one wider than any `usize`, and length
            // octets cut short.
            &[0x04, 0x02, 0xaa],
            &[0x04, 0x84, 0x7f, 0xff, 0xff, 0xff, 0xaa],
            &[0x04, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
            &[0x04],
            &[0x04, 0x82, 0x00],
            // §8.1.3.6.2: end-of-contents missing, or half of it.
            &[0x30, 0x80, 0x05, 0x00],
            &[0x30, 0x80, 0x05, 0x00, 0x00],
            // An indefinite value that runs past its definite parent.
            &[0x30, 0x04, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00],
        ] {
            assert!(der_of(ber).is_none(), "{ber:02x?}");
        }
    }

    #[test]
    fn ber_rejects_what_clause_8_forbids() {
        for ber in [
            // §8.3.1, §8.3.2: INTEGER contents empty or not in the fewest
            // octets, and a constructed INTEGER.
            &[0x02, 0x02, 0x00, 0x05][..],
            &[0x02, 0x02, 0xff, 0x80],
            &[0x02, 0x00],
            &[0x22, 0x03, 0x02, 0x01, 0x05],
            // §8.19.2: a subidentifier led by 80, and no subidentifier.
            &[0x06, 0x02, 0x80, 0x01],
            &[0x06, 0x00],
            // §8.8.2 NULL with contents; §8.2.1 BOOLEAN of other than one octet.
            &[0x05, 0x01, 0x00],
            &[0x01, 0x02, 0x00, 0x00],
            &[0x01, 0x00],
            // §8.6.2: no initial octet, eight unused bits, unused bits in an
            // empty bit string, and unused bits before the last segment
            // (§8.6.4).
            &[0x03, 0x00],
            &[0x03, 0x02, 0x08, 0xff],
            &[0x03, 0x01, 0x03],
            &[0x23, 0x08, 0x03, 0x02, 0x04, 0xf0, 0x03, 0x02, 0x00, 0xaa],
            // §8.6.4.1, §8.7.3.2: segments of the wrong type.
            &[0x24, 0x03, 0x02, 0x01, 0x05],
            &[0x23, 0x04, 0x04, 0x02, 0x00, 0xaa],
            // §8.9.1, §8.11.1: primitive SEQUENCE and SET.
            &[0x10, 0x00],
            &[0x11, 0x00],
            // §8.1.5: end-of-contents where a value belongs.
            &[0x00, 0x00],
            &[0x30, 0x02, 0x00, 0x00],
            // §8.1.2.2, §8.1.2.4.2 c): a low tag number in the long form, and
            // a long form led by 80.
            &[0x1f, 0x05, 0x00],
            &[0x5f, 0x80, 0x1f, 0x00],
            // X.680 Table 1: universal 15 and 37 are unassigned, so nothing
            // says what a constructed encoding under them would hold; the
            // primitive forms pass (`der_accepted_by_the_der_reader_converts_to_itself`).
            &[0x2f, 0x00],
            &[0x3f, 0x25, 0x00],
            // Anything after the value.
            &[0x05, 0x00, 0x00],
        ] {
            assert!(der_of(ber).is_none(), "{ber:02x?}");
        }
    }

    #[test]
    fn ber_values_take_their_der_forms() {
        // §11.1: TRUE as all ones. §11.2.1: unused bits zero.
        assert_eq!(
            der_of(&[0x01, 0x01, 0x5a]).as_deref(),
            Some(&[0x01, 0x01, 0xff][..])
        );
        assert_eq!(
            der_of(&[0x03, 0x02, 0x04, 0xff]).as_deref(),
            Some(&[0x03, 0x02, 0x04, 0xf0][..])
        );
        // §11.6: the values of a SET OF in ascending order.
        assert_eq!(
            der_of(&[0x31, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x00, 0x00]).as_deref(),
            Some(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02][..])
        );
        // §8.7.3.1 NOTE and §8.6.4 NOTE: segments of size zero; nested
        // constructed segments (§8.7.3.2 NOTE 1); strings with no segments.
        assert_eq!(
            der_of(&[0x24, 0x80, 0x04, 0x00, 0x24, 0x00, 0x00, 0x00]).as_deref(),
            Some(&[0x04, 0x00][..])
        );
        assert_eq!(
            der_of(&[
                0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02, 0x00, 0x00
            ])
            .as_deref(),
            Some(&[0x04, 0x02, 0x01, 0x02][..])
        );
        assert_eq!(
            der_of(&[0x23, 0x80, 0x00, 0x00]).as_deref(),
            Some(&[0x03, 0x01, 0x00][..])
        );
        // A universal DATE (X.680 Table 1: 31) keeps its long identifier form
        // (§8.1.2.4); a constructed value of another class with a high tag
        // number keeps its identifier, and what it holds is converted.
        let date = [
            0x1f, 0x1f, 0x08, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x31, 0x31,
        ];
        assert_eq!(der_of(&date).as_deref(), Some(&date[..]));
        // Without the ASN.1 type an implicitly tagged value in the constructed
        // form (§8.14.4) cannot be told to be a string, so it stays
        // constructed and only what it holds is converted; the `pkix` readers
        // supply the type where a container has such a component.
        assert_eq!(
            der_of(&[0xa1, 0x80, 0x03, 0x81, 0x02, 0x00, 0x19, 0x00, 0x00]).as_deref(),
            Some(&[0xa1, 0x04, 0x03, 0x02, 0x00, 0x19][..])
        );
        assert_eq!(
            der_of(&[0xbf, 0x1f, 0x80, 0x02, 0x81, 0x01, 0x07, 0x00, 0x00]).as_deref(),
            Some(&[0xbf, 0x1f, 0x03, 0x02, 0x01, 0x07][..])
        );
    }

    /// DER encodings of assorted shapes: integers, strings of both kinds, an
    /// explicit tag, a SET and nesting. An implicitly tagged string is left
    /// out: without its type, its constructed form cannot be told from a
    /// constructed type's (see `ber_values_take_their_der_forms`).
    fn der_samples() -> Vec<Vec<u8>> {
        let integers = encode_biguints(&[
            &BigUint::from_be_bytes(&[0x80; 300]),
            &BigUint::zero(),
            &BigUint::from_u64(0x7f),
        ]);
        let set = [&[0x31, 0x06][..], &[0x02, 0x01, 0x01, 0x02, 0x01, 0x02]].concat();
        let nested = der_sequence(
            &[
                der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
                vec![0x05, 0x00],
                der_octet_string(&[0x5a; 40]),
                vec![0x03, 0x03, 0x03, 0xab, 0xc8],
                der_bit_string(&[0x77; 17]),
                der_explicit(0, &set),
                der_sequence(&der_sequence(&[0x01, 0x01, 0xff])),
            ]
            .concat(),
        );
        vec![integers, set, nested, der_octet_string(&[])]
    }

    #[test]
    fn ber_to_der_is_the_identity_on_der_and_undoes_every_ber_style() {
        for der in der_samples() {
            assert_eq!(der_of(&der).as_deref(), Some(&der[..]));
            for style in STYLES {
                let ber = reencode(&der, style);
                assert_eq!(der_of(&ber).as_deref(), Some(&der[..]), "{style:?}");
            }
        }
    }

    #[test]
    fn ber_nesting_is_bounded() {
        let nest = |depth: usize| {
            let mut ber = vec![0x05, 0x00];
            for _ in 0..depth {
                ber = [&[0x30, 0x80][..], &ber, &[0x00, 0x00]].concat();
            }
            ber
        };
        assert!(der_of(&nest(MAX_ELEMENT_DEPTH)).is_some());
        assert!(der_of(&nest(MAX_ELEMENT_DEPTH + 1)).is_none());
        // A hundred thousand open levels fail at the bound instead of
        // exhausting the stack.
        assert!(der_of(&[0x30, 0x80].repeat(100_000)).is_none());
        assert!(der_of(&[0x24, 0x80].repeat(100_000)).is_none());
    }

    #[test]
    fn ber_values_and_segments_are_bounded() {
        // As many one-octet segments, and as many equal SET values to sort,
        // as the bound allows convert; one more fails, whether the extra
        // value is a sibling or lies in a nested segment string.
        let segments = |count: usize| {
            [
                &[0x24, 0x80][..],
                &[0x04, 0x01, 0xaa].repeat(count),
                &[0x00, 0x00],
            ]
            .concat()
        };
        let set = |count: usize| {
            [
                &[0x31, 0x80][..],
                &[0x02, 0x01, 0x07].repeat(count),
                &[0x00, 0x00],
            ]
            .concat()
        };
        let at = MAX_CONSTRUCTED_VALUES;
        assert_eq!(ber_to_der(&segments(at)).map(|der| der.len()), Some(4 + at));
        assert_eq!(ber_to_der(&set(at)).map(|der| der.len()), Some(4 + 3 * at));
        assert!(ber_to_der(&segments(at + 1)).is_none());
        assert!(ber_to_der(&set(at + 1)).is_none());
        let nested = [
            &[0x24, 0x80][..],
            &[0x04, 0x01, 0xaa].repeat(at),
            &[0x24, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x00],
            &[0x00, 0x00],
        ]
        .concat();
        assert!(ber_to_der(&nested).is_none());
        // The bound counts the values of one constructed encoding, not of the
        // whole input: a sequence of sets each at the bound converts.
        let two_sets = [&[0x30, 0x80][..], &set(at), &set(at), &[0x00, 0x00]].concat();
        assert_eq!(
            ber_to_der(&two_sets).map(|der| der.len()),
            Some(4 + 2 * (4 + 3 * at))
        );
        // A bit string's segments are counted the same way.
        let bits = |count: usize| {
            [
                &[0x23, 0x80][..],
                &[0x03, 0x02, 0x00, 0xaa].repeat(count),
                &[0x00, 0x00],
            ]
            .concat()
        };
        assert_eq!(ber_to_der(&bits(at)).map(|der| der.len()), Some(5 + at));
        assert!(ber_to_der(&bits(at + 1)).is_none());
    }

    /// Whether the DER reader accepts all of `bytes` as one value.
    fn is_der_element(bytes: &[u8]) -> bool {
        let mut reader = DerReader::new(bytes);
        reader.read_element().is_some() && reader.is_finished()
    }

    /// Whatever `input` is, conversion returns, and what it returns is DER
    /// that converts to itself; and if `input` is DER already, conversion is
    /// the identity on it.
    fn assert_converts_to_der_or_fails(input: &[u8]) {
        if is_der_element(input) {
            assert_eq!(der_of(input).as_deref(), Some(input), "DER: {input:02x?}");
        }
        if let Some(der) = ber_to_der(input) {
            assert!(
                is_der_element(&der),
                "not DER: {:02x?} from {input:02x?}",
                &der[..]
            );
            assert_eq!(der_of(&der).as_deref(), Some(&der[..]), "{input:02x?}");
        }
    }

    #[test]
    fn ber_reader_is_total_on_random_truncated_and_mutated_input() {
        use crate::{Csprng, CtrDrbgAes256};
        // Octets BER gives meaning to, drawn often so that random input
        // reaches the reader's deeper paths.
        const MEANINGFUL: [u8; 16] = [
            0x00, 0x80, 0x81, 0x82, 0xff, 0x30, 0x31, 0x24, 0x23, 0x03, 0x04, 0x02, 0x06, 0x05,
            0x1f, 0xa1,
        ];
        let mut rng = CtrDrbgAes256::new(&[0x42; 48]);
        let mut buffer = [0u8; 65];
        for _ in 0..20_000 {
            rng.fill_bytes(&mut buffer);
            let len = usize::from(buffer[0] % 64);
            let input: Vec<u8> = buffer[1..=len]
                .iter()
                .map(|&octet| {
                    if octet & 1 == 0 {
                        MEANINGFUL[usize::from(octet >> 4)]
                    } else {
                        octet
                    }
                })
                .collect();
            assert_converts_to_der_or_fails(&input);
        }
        for der in der_samples() {
            for style in STYLES {
                let ber = reencode(&der, style);
                // A value's encoding is never a prefix of another's.
                for end in 0..ber.len() {
                    assert!(ber_to_der(&ber[..end]).is_none(), "{style:?} cut at {end}");
                }
                for at in 0..ber.len() {
                    for bit in 0..8 {
                        let mut mutated = ber.clone();
                        mutated[at] ^= 1 << bit;
                        assert_converts_to_der_or_fails(&mutated);
                    }
                }
            }
        }
    }

    #[test]
    fn der_accepted_by_the_der_reader_converts_to_itself() {
        // The two readers share one table of forms, so the BER receiver is a
        // superset of the DER reader: over the samples, the shapes the DER
        // reader's own test accepts, primitive values under the unassigned
        // universal numbers 15 and 37, and attribute-shaped nests of them.
        let mut corpus = der_samples();
        for shape in [
            &[0x01, 0x01, 0xff][..],
            &[0x02, 0x01, 0x80],
            &[0x03, 0x02, 0x04, 0xf0],
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            &[0x9f, 0x1f, 0x00],
            &[0x80, 0x02, 0x00, 0x00],
            &[0x0f, 0x00],
            &[0x1f, 0x25, 0x00],
            &[0x0f, 0x03, 0x01, 0x02, 0x03],
            &[0x31, 0x05, 0x0f, 0x00, 0x1f, 0x25, 0x00],
        ] {
            corpus.push(shape.to_vec());
        }
        let attribute = |values: &[u8]| {
            let set = [
                &[0x31, u8::try_from(values.len()).expect("short")][..],
                values,
            ]
            .concat();
            der_sequence(&[&[0x06, 0x02, 0x2a, 0x03][..], &set].concat())
        };
        corpus.push(attribute(&[0x0f, 0x00]));
        corpus.push(attribute(&[0x1f, 0x25, 0x00]));
        corpus.push(der_explicit(0, &attribute(&[0x0f, 0x00, 0x1f, 0x25, 0x00])));
        for der in &corpus {
            assert!(is_der_element(der), "{der:02x?}");
            assert_eq!(der_of(der).as_deref(), Some(&der[..]), "{der:02x?}");
        }
        // Neither reader takes a constructed value under an unassigned
        // number: its DER form would need the type.
        for bytes in [&[0x2f, 0x00][..], &[0x3f, 0x25, 0x00]] {
            assert!(!is_der_element(bytes), "{bytes:02x?}");
            assert!(der_of(bytes).is_none(), "{bytes:02x?}");
        }
    }

    #[test]
    fn integer_blobs_are_bounded_by_the_field_count() {
        let one = BigUint::from_u64(1);
        let blob = |count: usize| encode_biguints(&vec![&one; count]);
        // The schema's count decodes, fewer decode for the caller to count,
        // more fail.
        assert_eq!(
            decode_biguints_at_most(&blob(3), 3).map(|f| f.len()),
            Some(3)
        );
        assert_eq!(
            decode_biguints_at_most(&blob(2), 3).map(|f| f.len()),
            Some(2)
        );
        assert_eq!(
            decode_biguints_at_most(&blob(0), 3).map(|f| f.len()),
            Some(0)
        );
        assert!(decode_biguints_at_most(&blob(4), 3).is_none());
        assert!(decode_biguints_at_most(&blob(1), 0).is_none());
        // The default bound of the counting decoders.
        let at = DEFAULT_MAX_BIGUINT_FIELDS;
        assert_eq!(decode_biguints(&blob(at)).map(|f| f.len()), Some(at));
        assert!(decode_biguints(&blob(at + 1)).is_none());
        // A blob of a hundred thousand fields fails at the bound, not after
        // decoding them all.
        assert!(decode_biguints(&blob(100_000)).is_none());
    }

    #[test]
    fn wiped_buffers_allocate_exactly_their_length() {
        for len in [0, 1, 126, 127, 128, 255, 256, 65_535, 65_536, 70_000] {
            let contents = vec![0xa5; len];
            let (head, tail) = contents.split_at(len / 3);
            let whole = wiped_tlv(0x04, &[&contents]);
            let parts = wiped_tlv(0x04, &[head, tail, &[]]);
            assert_eq!(whole.capacity(), whole.len(), "{len}");
            assert_eq!(&whole[..], &parts[..], "{len}");
            assert_eq!(parts.capacity(), parts.len(), "{len}");
            assert_eq!(&whole[..], &der_octet_string(&contents)[..], "{len}");
            // A high tag number's subsequent identifier octets.
            let dated = der_encoding(0x1f, &[0x1f], &[head, tail]);
            assert_eq!(dated.capacity(), dated.len(), "{len}");
            assert_eq!(dated[..2], [0x1f, 0x1f]);
        }
        for der in der_samples() {
            for style in STYLES {
                let converted = ber_to_der(&reencode(&der, style)).expect("BER");
                assert_eq!(converted.capacity(), converted.len(), "{style:?}");
                assert_eq!(&converted[..], &der[..]);
            }
        }
        // Constructed strings and sets are gathered into exact buffers too.
        for ber in [
            &[
                0x24, 0x80, 0x04, 0x01, 0x01, 0x04, 0x02, 0x02, 0x03, 0x00, 0x00,
            ][..],
            &[
                0x23, 0x80, 0x03, 0x02, 0x00, 0xaa, 0x03, 0x02, 0x04, 0xf0, 0x00, 0x00,
            ],
            &[0x31, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x00, 0x00],
        ] {
            let converted = ber_to_der(ber).expect("BER");
            assert_eq!(converted.capacity(), converted.len(), "{ber:02x?}");
        }
        let symbols =
            pem_contents("X", "-----BEGIN X-----\nZm9vYmFy\n-----END X-----\n").expect("PEM");
        assert_eq!(symbols.capacity(), symbols.len());
    }

    #[test]
    fn explicit_tags_hold_exactly_one_der_value() {
        let read = |bytes: &[u8]| {
            let mut reader = DerReader::new(bytes);
            let inner = reader.read_explicit(0)?;
            reader.is_finished().then(|| inner.to_vec())
        };
        // One value, primitive or constructed.
        assert_eq!(
            read(&[0xa0, 0x02, 0x05, 0x00]).as_deref(),
            Some(&[0x05, 0x00][..])
        );
        assert_eq!(
            read(&[0xa0, 0x05, 0x30, 0x03, 0x02, 0x01, 0x07]).as_deref(),
            Some(&[0x30, 0x03, 0x02, 0x01, 0x07][..])
        );
        assert_eq!(
            read(&der_explicit(0, &[0x06, 0x03, 0x2b, 0x65, 0x70])).map(|v| v.len()),
            Some(5)
        );
        // Empty, two values, a value that is not DER, a value cut short, the
        // wrong tag number, and the primitive form (§8.14.3: explicit tags
        // are constructed).
        for bad in [
            &[0xa0, 0x00][..],
            &[0xa0, 0x04, 0x05, 0x00, 0x05, 0x00],
            &[0xa0, 0x04, 0x02, 0x02, 0x00, 0x01],
            &[0xa0, 0x03, 0x02, 0x02, 0x01],
            &[0xa1, 0x02, 0x05, 0x00],
            &[0x80, 0x02, 0x05, 0x00],
        ] {
            assert!(read(bad).is_none(), "{bad:02x?}");
        }
        // The implicit constructed reader hands back the contents as they
        // are, for a SET OF the caller checks itself.
        let mut reader = DerReader::new(&[0xa0, 0x04, 0x05, 0x00, 0x05, 0x00]);
        assert_eq!(
            reader.read_implicit_constructed(0),
            Some(&[0x05, 0x00, 0x05, 0x00][..])
        );
    }

    #[test]
    fn pem_encapsulated_text_is_bounded() {
        // The region between the boundary lines, line ends included, may
        // reach the bound exactly; one more byte fails, however many lines
        // or however few the text uses (RFC 7468 §2: "Parsers MAY handle
        // other line sizes").
        let base64_len = MAX_PEM_ENCAPSULATED_TEXT - 4;
        assert!(base64_len.is_multiple_of(4));
        let base64 = "A".repeat(base64_len);
        let at_bound = format!("-----BEGIN X-----\n{base64}  \n-----END X-----\n");
        let contents = pem_contents("X", &at_bound).expect("at the bound");
        assert_eq!(contents.len(), base64_len / 4 * 3);
        assert!(contents.iter().all(|&byte| byte == 0));
        let past = format!("-----BEGIN X-----\n{base64}   \n-----END X-----\n");
        assert!(pem_contents("X", &past).is_none());
        // One long line and many short ones read alike: the same base64 in
        // lines of seven characters decodes to the same octets.
        let short = &base64[..7 * 1200];
        let lines: String = short
            .as_bytes()
            .chunks(7)
            .map(|line| format!("{}\n", core::str::from_utf8(line).expect("ASCII")))
            .collect();
        let wrapped = format!("-----BEGIN X-----\n{lines}-----END X-----\n");
        let single = format!("-----BEGIN X-----\n{short}\n-----END X-----\n");
        assert_eq!(
            pem_contents("X", &wrapped).as_deref(),
            pem_contents("X", &single).as_deref()
        );
        assert_eq!(
            pem_contents("X", &single).map(|octets| octets.len()),
            Some(7 * 1200 / 4 * 3)
        );
        // Text before the boundaries is not counted against the bound.
        let preamble = "x".repeat(MAX_PEM_ENCAPSULATED_TEXT + 1);
        let text = format!("{preamble}\n-----BEGIN X-----\nZm9vYmFy\n-----END X-----\n");
        assert_eq!(pem_contents("X", &text).as_deref(), Some(&b"foobar"[..]));
    }
}
