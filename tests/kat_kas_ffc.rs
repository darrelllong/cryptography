//! NIST CAVP vectors for the SP 800-56A Rev. 3 finite-field Diffie-Hellman
//! primitive (§5.7.1.1): the KAS FFC dhEphem validity test with `Z` only.
//!
//! The vectors live in `vectors/cavp_kas_ffc_ephemeral_zz.txt`, the
//! initiator file of the "Test of 800-56A excluding KDF" set in NIST's
//! `KASTestVectorsFFC2016.zip`; the file's header records its provenance. It
//! is parsed here rather than retyped.
//!
//! For each of the parameter sets FB (`L = 2048`, `N = 224`) and FC
//! (`L = 2048`, `N = 256`) the domain goes through the hardened validation of
//! `DhParams::new` once, and every record then pins:
//!
//! - `YephemIUT = G^XephemIUT mod P`, through `Dh::with_secret_exponent`;
//! - the CAVS public key: accepted by `DhPublicKey::from_public_component`
//!   (§5.6.2.3.1 full public-key validation) exactly when the file does not
//!   mark it as failing public-key validation;
//! - `Z = YephemCAVS^XephemIUT mod P` from `agree_element`, equal to the
//!   file's `Z` exactly when `Result = P`, and the same value from the CAVS
//!   side (`YephemIUT^XephemCAVS`);
//! - the Appendix C.1 byte string of `Z`, as long as `P`, and `SHA-512` of it
//!   as `CAVSHashZZ`, for every `Result = P` record — including the ones
//!   whose first byte is below `0x10`, which C.1 keeps at full length.

mod common;

use cryptography::vt::{BigUint, Dh, DhParams, DhPublicKey};
use cryptography::Sha512;

const VECTORS: &str = include_str!("vectors/cavp_kas_ffc_ephemeral_zz.txt");

struct ParameterSet {
    name: &'static str,
    p: BigUint,
    q: BigUint,
    g: BigUint,
    records: Vec<Vec<(&'static str, &'static str)>>,
}

fn field<'r>(record: &[(&'r str, &'r str)], key: &str, context: &str) -> &'r str {
    record
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
        .unwrap_or_else(|| panic!("{context}: no {key}"))
}

fn integer(record: &[(&str, &str)], key: &str, context: &str) -> BigUint {
    BigUint::from_str_radix(field(record, key, context), 16)
        .unwrap_or_else(|| panic!("{context}: {key} is not hexadecimal"))
}

/// The `[FB - SHA512]` and `[FC - SHA512]` sets. The other bracketed lines
/// are the CAVS header and carry no records.
fn parameter_sets() -> Vec<ParameterSet> {
    let mut sets: Vec<ParameterSet> = Vec::new();
    let mut block: Vec<(&'static str, &'static str)> = Vec::new();
    let mut in_set = false;
    let flush = |block: &mut Vec<(&'static str, &'static str)>, sets: &mut Vec<ParameterSet>| {
        if block.is_empty() {
            return;
        }
        let fields = std::mem::take(block);
        let set = sets.last_mut().expect("records sit inside a parameter set");
        if fields.iter().any(|(name, _)| *name == "P") {
            let context = set.name;
            set.p = integer(&fields, "P", context);
            set.q = integer(&fields, "Q", context);
            set.g = integer(&fields, "G", context);
        } else {
            set.records.push(fields);
        }
    };
    for line in VECTORS.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() || line.starts_with('[') {
            if in_set {
                flush(&mut block, &mut sets);
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(" - SHA512]"))
            {
                in_set = true;
                sets.push(ParameterSet {
                    name,
                    p: BigUint::zero(),
                    q: BigUint::zero(),
                    g: BigUint::zero(),
                    records: Vec::new(),
                });
            }
            continue;
        }
        if !in_set {
            continue;
        }
        let (key, value) = line.split_once(" = ").expect("key = value");
        block.push((key, value));
    }
    assert_eq!(sets.len(), 2);
    sets
}

/// The CAVS reasons, so the test knows which failure each record expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    /// `Result = P`: `Z` is correct.
    Correct,
    /// `Result = F (2 - ...)`: the CAVS public key fails validation.
    PeerKeyInvalid,
    /// `Result = F (5 - ...)`: the file's `Z` is not the primitive's output.
    ZChanged,
}

fn expected(record: &[(&str, &str)], context: &str) -> Expected {
    let result = field(record, "Result", context);
    if result.starts_with("P (") {
        Expected::Correct
    } else if result.starts_with("F (2 ") {
        Expected::PeerKeyInvalid
    } else if result.starts_with("F (5 ") {
        Expected::ZChanged
    } else {
        panic!("{context}: unrecognized Result {result}")
    }
}

#[test]
fn dhephem_zz_only_initiator_fb_and_fc() {
    let sets = parameter_sets();
    let mut failures = Vec::new();
    for set in &sets {
        assert_eq!(set.p.bits(), 2048, "{}", set.name);
        assert_eq!(
            set.q.bits(),
            if set.name == "FB" { 224 } else { 256 },
            "{}",
            set.name
        );
        assert_eq!(set.records.len(), 24, "{}", set.name);
        let params = DhParams::new(set.p.clone(), set.q.clone(), set.g.clone())
            .unwrap_or_else(|| panic!("{}: the domain does not validate", set.name));
        let p_len = set.p.to_be_bytes().len();
        let mut counts = [0usize; 3];
        for record in &set.records {
            let context = format!("{} COUNT {}", set.name, field(record, "COUNT", set.name));
            let expected = expected(record, &context);
            counts[expected as usize] += 1;
            check_record(&params, p_len, record, expected, &context, &mut failures);
        }
        assert_eq!(counts, [20, 2, 2], "{}: P, F(2), F(5) records", set.name);
    }
    assert!(
        failures.is_empty(),
        "{} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn check_record(
    params: &DhParams,
    p_len: usize,
    record: &[(&str, &str)],
    expected: Expected,
    context: &str,
    failures: &mut Vec<String>,
) {
    let x_iut = integer(record, "XephemIUT", context);
    let y_iut = integer(record, "YephemIUT", context);
    let x_cavs = integer(record, "XephemCAVS", context);
    let y_cavs = integer(record, "YephemCAVS", context);
    let z_file = integer(record, "Z", context);

    let (public_iut, private_iut) = Dh::with_secret_exponent(params, &x_iut)
        .unwrap_or_else(|| panic!("{context}: XephemIUT is not in [1, q)"));
    if public_iut.public_component() != &y_iut {
        failures.push(format!("{context}: YephemIUT != G^XephemIUT"));
    }

    let Some(public_cavs) = DhPublicKey::from_public_component(params, y_cavs) else {
        if expected != Expected::PeerKeyInvalid {
            failures.push(format!(
                "{context}: YephemCAVS refused by public-key validation, Result says {expected:?}"
            ));
        }
        return;
    };
    if expected == Expected::PeerKeyInvalid {
        failures.push(format!(
            "{context}: YephemCAVS accepted, but the file says it fails public-key validation"
        ));
        return;
    }

    let Some(z) = private_iut.agree_element(&public_cavs) else {
        failures.push(format!("{context}: agree_element returned None"));
        return;
    };
    // The CAVS side reaches the same element.
    let (_, private_cavs) = Dh::with_secret_exponent(params, &x_cavs)
        .unwrap_or_else(|| panic!("{context}: XephemCAVS is not in [1, q)"));
    if private_cavs.agree_element(&public_iut).as_ref() != Some(&z) {
        failures.push(format!("{context}: the two sides disagree"));
    }

    match expected {
        Expected::Correct => {
            if z != z_file {
                failures.push(format!("{context}: Z differs from the file"));
                return;
            }
            // SP 800-56A Appendix C.1: Z is as long as p, leading zeros kept.
            let z_bytes = common::decode_hex(field(record, "Z", context));
            if z_bytes.len() != p_len || z.to_be_bytes_padded(p_len) != z_bytes {
                failures.push(format!("{context}: Z is not the C.1 byte string of z"));
            }
            let hash = common::decode_hex(field(record, "CAVSHashZZ", context));
            if Sha512::digest(&z_bytes)[..] != hash[..] {
                failures.push(format!("{context}: SHA-512(Z) != CAVSHashZZ"));
            }
        }
        Expected::ZChanged => {
            if z == z_file {
                failures.push(format!("{context}: the changed Z was reproduced"));
            }
        }
        Expected::PeerKeyInvalid => unreachable!("handled above"),
    }
}
