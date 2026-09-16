//! CCM known answers.
//!
//! - NIST SP 800-38C, "Recommendation for Block Cipher Modes of Operation:
//!   The CCM Mode for Authentication and Confidentiality" (M. Dworkin, May
//!   2004, updated July 2007), Appendix C "Example Vectors", Examples 1-4:
//!   AES-128 under nonces of 7, 8, 12 and 13 bytes (L = 8, 7, 3 and 2) with
//!   tags of 4, 6, 8 and 14 bytes. Example 4 authenticates 2^16 bytes of
//!   associated data, the `0xff 0xfe` length encoding of Appendix A.2.2,
//!   and its formatted block `B` begins `71101112 13141516 1718191a 1b1c0020
//!   fffe0001 0000...`, so the whole formatting path from that appendix is
//!   pinned by the published tag.
//! - RFC 3610, "Counter with CBC-MAC (CCM)" (D. Whiting, R. Housley,
//!   N. Ferguson, September 2003), section 8, Packet Vectors #1-#24: 13-byte
//!   nonces (L = 2), 8- or 12-byte cleartext headers, 8- or 10-byte tags.
//!   The section is parsed from `vectors/rfc3610_section_8.txt`, the text of
//!   the RFC, so every digit checked is a digit of the RFC.
//!
//! Every vector is encrypted, its detached tag compared, decrypted, and
//! refused once its last tag byte is flipped.

mod common;

use common::decode_hex;
use cryptography::{Aes128, BlockCipher, Ccm};

/// Encrypt, compare, decrypt, and refuse a flipped tag, for one `TAG_LEN`.
fn check<C: BlockCipher, const TAG_LEN: usize>(
    ccm: &Ccm<C, TAG_LEN>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    label: &str,
) {
    let tag: [u8; TAG_LEN] = tag.try_into().expect("tag length matches TAG_LEN");
    let mut data = plaintext.to_vec();
    let sealed = ccm.encrypt(nonce, aad, &mut data);
    assert_eq!(data, ciphertext, "{label}: ciphertext");
    assert_eq!(sealed, tag, "{label}: tag");
    assert_eq!(
        ccm.compute_tag(nonce, aad, plaintext),
        tag,
        "{label}: compute_tag"
    );

    let mut forged = tag;
    forged[TAG_LEN - 1] ^= 0x01;
    assert!(
        !ccm.decrypt(nonce, aad, &mut data, &forged),
        "{label}: flipped tag accepted"
    );
    assert_eq!(data, ciphertext, "{label}: buffer changed on refusal");

    assert!(ccm.decrypt(nonce, aad, &mut data, &tag), "{label}: decrypt");
    assert_eq!(data, plaintext, "{label}: plaintext");
}

// ─── SP 800-38C Appendix C ──────────────────────────────────────────────────

/// SP 800-38C Appendix C: the key of all four examples.
const SP800_38C_KEY: &str = "404142434445464748494a4b4c4d4e4f";

fn aes128() -> Aes128 {
    Aes128::new(&decode_hex(SP800_38C_KEY).try_into().expect("128-bit key"))
}

/// SP 800-38C C.1 Example 1: Nlen = 56, Alen = 64, Plen = 32, Tlen = 32.
#[test]
fn sp800_38c_c1_example_1() {
    check(
        &Ccm::<_, 4>::new(aes128()),
        &decode_hex("10111213141516"),
        &decode_hex("0001020304050607"),
        &decode_hex("20212223"),
        &decode_hex("7162015b"),
        &decode_hex("4dac255d"),
        "SP 800-38C C.1",
    );
}

/// SP 800-38C C.2 Example 2: Nlen = 64, Alen = 128, Plen = 128, Tlen = 48.
#[test]
fn sp800_38c_c2_example_2() {
    check(
        &Ccm::<_, 6>::new(aes128()),
        &decode_hex("1011121314151617"),
        &decode_hex("000102030405060708090a0b0c0d0e0f"),
        &decode_hex("202122232425262728292a2b2c2d2e2f"),
        &decode_hex("d2a1f0e051ea5f62081a7792073d593d"),
        &decode_hex("1fc64fbfaccd"),
        "SP 800-38C C.2",
    );
}

/// SP 800-38C C.3 Example 3: Nlen = 96, Alen = 160, Plen = 192, Tlen = 64.
#[test]
fn sp800_38c_c3_example_3() {
    check(
        &Ccm::<_, 8>::new(aes128()),
        &decode_hex("101112131415161718191a1b"),
        &decode_hex("000102030405060708090a0b0c0d0e0f10111213"),
        &decode_hex("202122232425262728292a2b2c2d2e2f3031323334353637"),
        &decode_hex("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5"),
        &decode_hex("484392fbc1b09951"),
        "SP 800-38C C.3",
    );
}

/// SP 800-38C C.4 Example 4: Nlen = 104, Alen = 524288, Plen = 256, Tlen =
/// 112. The associated data is the 256-byte string `00 01 ... ff` repeated
/// 256 times; the formatted block `B` printed for it carries the `0xff 0xfe`
/// length prefix (Appendix A.2.2) followed by `00010000`.
#[test]
fn sp800_38c_c4_example_4_long_associated_data() {
    let aad: Vec<u8> = (0..(1usize << 16)).map(|i| i as u8).collect();
    assert_eq!(aad.len() * 8, 524_288);
    assert!(
        aad.len() >= (1 << 16) - (1 << 8),
        "reaches the 0xff 0xfe encoding"
    );
    check(
        &Ccm::<_, 14>::new(aes128()),
        &decode_hex("101112131415161718191a1b1c"),
        &aad,
        &decode_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
        &decode_hex("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72"),
        &decode_hex("b4ac6bec93e8598e7f0dadbcea5b"),
        "SP 800-38C C.4",
    );
}

// ─── RFC 3610 section 8 ─────────────────────────────────────────────────────

const RFC3610_SECTION_8: &str = include_str!("vectors/rfc3610_section_8.txt");

struct PacketVector {
    number: u32,
    key: Vec<u8>,
    nonce: Vec<u8>,
    header_len: usize,
    input: Vec<u8>,
    tag_len: usize,
    output: Vec<u8>,
}

/// Parse the space-separated hex bytes of one line.
fn hex_bytes(text: &str) -> Vec<u8> {
    decode_hex(&text.split_whitespace().collect::<String>())
}

/// Parse every "Packet Vector #N" record of section 8.
///
/// A record holds `AES Key =`, `Nonce =`, the input packet (`Total packet
/// length = L. [Input with H cleartext header octets]` followed by hex
/// lines), the CBC-MAC (whose printed length is the tag length), and the
/// output packet (`Total packet length = L. [Authenticated and Encrypted
/// Output]` followed by hex lines).
fn packet_vectors() -> Vec<PacketVector> {
    let mut vectors: Vec<PacketVector> = Vec::new();
    #[derive(PartialEq)]
    enum Reading {
        Nothing,
        Input,
        Output,
    }
    let mut reading = Reading::Nothing;
    for line in RFC3610_SECTION_8.lines() {
        let text = line.trim();
        if let Some(rest) = text.strip_prefix("=============== Packet Vector #") {
            let number = rest
                .trim_end_matches(['=', ' '])
                .parse()
                .expect("packet vector number");
            vectors.push(PacketVector {
                number,
                key: Vec::new(),
                nonce: Vec::new(),
                header_len: 0,
                input: Vec::new(),
                tag_len: 0,
                output: Vec::new(),
            });
            reading = Reading::Nothing;
            continue;
        }
        let Some(current) = vectors.last_mut() else {
            continue;
        };
        if let Some(rest) = text.strip_prefix("AES Key =") {
            current.key = hex_bytes(rest);
        } else if let Some(rest) = text.strip_prefix("Nonce =") {
            current.nonce = hex_bytes(rest);
        } else if let Some(rest) = text.strip_prefix("Total packet length =") {
            let (length, note) = rest.split_once('.').expect("length and note");
            let length: usize = length.trim().parse().expect("packet length");
            if let Some(header) = note.trim().strip_prefix("[Input with ") {
                current.header_len = header
                    .strip_suffix(" cleartext header octets]")
                    .expect("header note")
                    .parse()
                    .expect("header length");
                current.input.reserve(length);
                reading = Reading::Input;
            } else {
                assert_eq!(note.trim(), "[Authenticated and Encrypted Output]");
                current.output.reserve(length);
                reading = Reading::Output;
            }
        } else if let Some(rest) = text.strip_prefix("CBC-MAC  :") {
            current.tag_len = hex_bytes(rest).len();
            reading = Reading::Nothing;
        } else if text.is_empty() || text.contains(':') || text.starts_with("Whiting") {
            // A blank line, an intermediate value, or a page footer ends the
            // packet being read; the RFC's own page headers hold no hex.
            if !text.is_empty() {
                reading = Reading::Nothing;
            }
        } else if text.bytes().all(|b| b.is_ascii_hexdigit() || b == b' ') {
            match reading {
                Reading::Input => current.input.extend(hex_bytes(text)),
                Reading::Output => current.output.extend(hex_bytes(text)),
                Reading::Nothing => {}
            }
        }
    }
    vectors
}

/// The section holds 24 packet vectors, numbered in order, each with a
/// 16-byte key, a 13-byte nonce, and an output longer than its input by the
/// tag length.
#[test]
fn rfc3610_section_8_parses_into_24_packet_vectors() {
    let vectors = packet_vectors();
    assert_eq!(vectors.len(), 24);
    for (index, v) in vectors.iter().enumerate() {
        assert_eq!(v.number as usize, index + 1);
        assert_eq!(v.key.len(), 16, "#{}", v.number);
        assert_eq!(v.nonce.len(), 13, "#{}", v.number);
        assert!(matches!(v.header_len, 8 | 12), "#{}", v.number);
        assert!(matches!(v.tag_len, 8 | 10), "#{}", v.number);
        assert_eq!(v.output.len(), v.input.len() + v.tag_len, "#{}", v.number);
        assert!(v.input.len() > v.header_len, "#{}", v.number);
    }
}

fn check_packet_vector(v: &PacketVector) {
    let label = format!("RFC 3610 Packet Vector #{}", v.number);
    let key: [u8; 16] = v.key.as_slice().try_into().expect("128-bit key");
    let (aad, plaintext) = v.input.split_at(v.header_len);
    let (header, rest) = v.output.split_at(v.header_len);
    assert_eq!(header, aad, "{label}: the header is carried in clear");
    let (ciphertext, tag) = rest.split_at(rest.len() - v.tag_len);
    match v.tag_len {
        8 => check(
            &Ccm::<_, 8>::new(Aes128::new(&key)),
            &v.nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
            &label,
        ),
        10 => check(
            &Ccm::<_, 10>::new(Aes128::new(&key)),
            &v.nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
            &label,
        ),
        other => panic!("{label}: unexpected tag length {other}"),
    }
}

macro_rules! packet_vector_tests {
    ($($name:ident => $number:literal),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let vectors = packet_vectors();
                let v = vectors
                    .iter()
                    .find(|v| v.number == $number)
                    .expect("packet vector present");
                check_packet_vector(v);
            }
        )+
    };
}

packet_vector_tests!(
    rfc3610_packet_vector_01 => 1,
    rfc3610_packet_vector_02 => 2,
    rfc3610_packet_vector_03 => 3,
    rfc3610_packet_vector_04 => 4,
    rfc3610_packet_vector_05 => 5,
    rfc3610_packet_vector_06 => 6,
    rfc3610_packet_vector_07 => 7,
    rfc3610_packet_vector_08 => 8,
    rfc3610_packet_vector_09 => 9,
    rfc3610_packet_vector_10 => 10,
    rfc3610_packet_vector_11 => 11,
    rfc3610_packet_vector_12 => 12,
    rfc3610_packet_vector_13 => 13,
    rfc3610_packet_vector_14 => 14,
    rfc3610_packet_vector_15 => 15,
    rfc3610_packet_vector_16 => 16,
    rfc3610_packet_vector_17 => 17,
    rfc3610_packet_vector_18 => 18,
    rfc3610_packet_vector_19 => 19,
    rfc3610_packet_vector_20 => 20,
    rfc3610_packet_vector_21 => 21,
    rfc3610_packet_vector_22 => 22,
    rfc3610_packet_vector_23 => 23,
    rfc3610_packet_vector_24 => 24,
);
