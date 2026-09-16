//! RFC 8452, Appendix C: AES-GCM-SIV test vectors.
//!
//! The vectors live in `vectors/rfc8452_appendix_c.txt`, the text of Appendix
//! C of RFC 8452, "AES-GCM-SIV: Nonce Misuse-Resistant Authenticated
//! Encryption" (S. Gueron, A. Langley, Y. Lindell, April 2019), with only page
//! footers, page headers and blank-line runs removed. The file is parsed here
//! rather than retyped, so every digit checked is a digit of the RFC.
//!
//! Every record is driven through the public API: `encrypt` must produce the
//! record's `Result` (ciphertext followed by the 16-byte tag), `decrypt` must
//! accept that `Result` and return the plaintext, and `decrypt` must refuse
//! the `Result` once its tag, its AAD or its ciphertext is altered. The
//! intermediate values (record keys, POLYVAL input and result, initial
//! counter) are not observable through the API and are not checked.
//!
//! - C.1: 24 AEAD_AES_128_GCM_SIV records.
//! - C.2: 24 AEAD_AES_256_GCM_SIV records.
//! - C.3: 2 AEAD_AES_256_GCM_SIV counter-wrap records.
//!
//! Each section runs on both AES implementations: the T-table aliases
//! `Aes128GcmSiv`/`Aes256GcmSiv` and the constant-time
//! `Aes128GcmSivCt`/`Aes256GcmSivCt`.
//!
//! The first three records of C.1 and of C.2 (empty AAD) are also pinned by
//! the unit tests in `src/modes/gcm_siv.rs`; the other 44 records, which
//! include every record with non-empty AAD, are pinned only here.

mod common;

use common::{decode_hex, encode_hex};
use cryptography::modes::{Aes128GcmSiv, Aes128GcmSivCt, Aes256GcmSiv, Aes256GcmSivCt};

const APPENDIX_C: &str = include_str!("vectors/rfc8452_appendix_c.txt");

/// One record: its fields in order, each `(name, declared byte length, hex)`.
struct Record {
    section: String,
    fields: Vec<(String, Option<usize>, String)>,
}

impl Record {
    fn get(&self, name: &str) -> Vec<u8> {
        let found: Vec<_> = self.fields.iter().filter(|(n, _, _)| n == name).collect();
        assert_eq!(found.len(), 1, "{}: one `{name}` field", self.section);
        let (_, declared, digits) = found[0];
        let bytes = decode_hex(digits);
        if let Some(len) = declared {
            assert_eq!(bytes.len(), *len, "{}: `{name}` length label", self.section);
        }
        bytes
    }
}

fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse every record. A field is `Name = HEX` or `Name (N bytes) = HEX`, with
/// the digits possibly continued on following lines that hold nothing but hex
/// digits; `Plaintext` opens a new record. Blank lines never end a field (a
/// page break could fall inside one); any other line does.
fn parse() -> Vec<Record> {
    let mut records: Vec<Record> = Vec::new();
    let mut section = String::new();
    let mut open = false;
    for line in APPENDIX_C.lines() {
        if line.starts_with('#') {
            continue;
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        if line.starts_with("C.") {
            section = text
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_owned();
            open = false;
            continue;
        }
        if open && is_hex(text) {
            let record = records.last_mut().expect("continuation inside a record");
            record
                .fields
                .last_mut()
                .expect("continuation after a field")
                .2
                .push_str(text);
            continue;
        }
        open = false;
        let Some((label, value)) = text.split_once(" =") else {
            continue;
        };
        let value = value.trim();
        if !(value.is_empty() || is_hex(value)) {
            continue;
        }
        let (name, declared) = match label.split_once(" (") {
            Some((name, rest)) => {
                let count = rest
                    .strip_suffix(" bytes)")
                    .and_then(|n| n.parse().ok())
                    .expect("`(N bytes)` label");
                (name, Some(count))
            }
            None => (label, None),
        };
        if name == "Plaintext" {
            records.push(Record {
                section: section.clone(),
                fields: Vec::new(),
            });
        }
        records
            .last_mut()
            .expect("field before the first Plaintext")
            .fields
            .push((name.to_owned(), declared, value.to_owned()));
        open = true;
    }
    records
}

fn section(name: &str) -> Vec<Record> {
    parse().into_iter().filter(|r| r.section == name).collect()
}

/// Seal and open one record with `$aead`, pushing any mismatch onto `$failures`.
macro_rules! check_record {
    ($aead:ty, $record:expr, $index:expr, $failures:expr) => {{
        let record: &Record = $record;
        let label = format!("{} record {}", record.section, $index + 1);
        let key = record.get("Key");
        let nonce: [u8; 12] = record.get("Nonce").try_into().expect("96-bit nonce");
        let aad = record.get("AAD");
        let plaintext = record.get("Plaintext");
        let result = record.get("Result");
        let aead = <$aead>::new(&key.as_slice().try_into().expect("key length"));

        let mut data = plaintext.clone();
        let tag = aead.encrypt(&nonce, &aad, &mut data);
        let mut sealed = data;
        sealed.extend_from_slice(&tag);
        if sealed != result {
            $failures.push(format!(
                "{label}: encrypt gave {}, Result = {}",
                encode_hex(&sealed),
                encode_hex(&result)
            ));
        }

        let (ciphertext, published_tag) = result.split_at(result.len() - 16);
        let published_tag: [u8; 16] = published_tag.try_into().expect("16-byte tag");
        let mut opened = ciphertext.to_vec();
        if !aead.decrypt(&nonce, &aad, &mut opened, &published_tag) {
            $failures.push(format!("{label}: decrypt rejected Result"));
        } else if opened != plaintext {
            $failures.push(format!(
                "{label}: decrypt gave {}, Plaintext = {}",
                encode_hex(&opened),
                encode_hex(&plaintext)
            ));
        }

        // Refusals: each alteration is rejected and the buffer left intact.
        let mut forged_tag = published_tag;
        forged_tag[0] ^= 0x01;
        let mut data = ciphertext.to_vec();
        if aead.decrypt(&nonce, &aad, &mut data, &forged_tag) || data != ciphertext {
            $failures.push(format!("{label}: altered tag accepted or buffer changed"));
        }

        let mut altered_aad = aad.clone();
        altered_aad.push(0x00);
        let mut data = ciphertext.to_vec();
        if aead.decrypt(&nonce, &altered_aad, &mut data, &published_tag) || data != ciphertext {
            $failures.push(format!("{label}: extended AAD accepted or buffer changed"));
        }
        if !aad.is_empty() {
            altered_aad.pop();
            altered_aad[0] ^= 0x80;
            let mut data = ciphertext.to_vec();
            if aead.decrypt(&nonce, &altered_aad, &mut data, &published_tag) || data != ciphertext {
                $failures.push(format!("{label}: altered AAD accepted or buffer changed"));
            }
        }

        if !ciphertext.is_empty() {
            let mut altered = ciphertext.to_vec();
            altered[ciphertext.len() - 1] ^= 0x01;
            let snapshot = altered.clone();
            if aead.decrypt(&nonce, &aad, &mut altered, &published_tag) || altered != snapshot {
                $failures.push(format!(
                    "{label}: altered ciphertext accepted or buffer changed"
                ));
            }
            let mut truncated = ciphertext[..ciphertext.len() - 1].to_vec();
            let snapshot = truncated.clone();
            if aead.decrypt(&nonce, &aad, &mut truncated, &published_tag) || truncated != snapshot {
                $failures.push(format!(
                    "{label}: truncated ciphertext accepted or buffer changed"
                ));
            }
        }
    }};
}

/// The data file holds 24 + 24 + 2 records.
#[test]
fn appendix_parses_into_fifty_records() {
    assert_eq!(section("C.1").len(), 24);
    assert_eq!(section("C.2").len(), 24);
    assert_eq!(section("C.3").len(), 2);
    assert_eq!(parse().len(), 50);
}

/// RFC 8452 C.1: AEAD_AES_128_GCM_SIV, all 24 records, on the T-table AES.
#[test]
fn c1_aead_aes_128_gcm_siv() {
    let records = section("C.1");
    assert_eq!(records.len(), 24);
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        check_record!(Aes128GcmSiv, record, index, failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// RFC 8452 C.1 on the constant-time AES.
#[test]
fn c1_aead_aes_128_gcm_siv_ct() {
    let records = section("C.1");
    assert_eq!(records.len(), 24);
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        check_record!(Aes128GcmSivCt, record, index, failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// RFC 8452 C.2: AEAD_AES_256_GCM_SIV, all 24 records, on the T-table AES.
#[test]
fn c2_aead_aes_256_gcm_siv() {
    let records = section("C.2");
    assert_eq!(records.len(), 24);
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        check_record!(Aes256GcmSiv, record, index, failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// RFC 8452 C.2 on the constant-time AES.
#[test]
fn c2_aead_aes_256_gcm_siv_ct() {
    let records = section("C.2");
    assert_eq!(records.len(), 24);
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        check_record!(Aes256GcmSivCt, record, index, failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// RFC 8452 C.3: the two AEAD_AES_256_GCM_SIV counter-wrap records, whose tag
/// makes the 32-bit block counter wrap during encryption, on both AES
/// implementations.
#[test]
fn c3_counter_wrap() {
    let records = section("C.3");
    assert_eq!(records.len(), 2);
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        check_record!(Aes256GcmSiv, record, index, failures);
        check_record!(Aes256GcmSivCt, record, index, failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
