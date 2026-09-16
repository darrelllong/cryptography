//! RFC 6979, Appendix A.2: deterministic DSA and ECDSA test vectors.
//!
//! The vectors live in `vectors/rfc6979_appendix_a2.txt`, the text of
//! Appendix A.2 (subsections A.2.1 through A.2.17) of RFC 6979, "Deterministic
//! Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital
//! Signature Algorithm (ECDSA)" (T. Pornin, August 2013), with only page
//! footers, page headers and blank-line runs removed. The file is parsed here
//! rather than retyped, so every digit checked is a digit of the RFC.
//!
//! For each of the seventeen keys this pins:
//!
//! - the key pair: `x -> y` for DSA, `x -> (Ux, Uy)` for ECDSA, and for ECDSA
//!   that the crate's named curve has the RFC's subgroup order `q` and `qlen`;
//! - for each of the ten signatures (messages "sample" and "test" under
//!   SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512):
//!   1. `sign_message`, whose nonce comes from the RFC 6979 section 3.2
//!      derivation, reproduces the RFC's signature;
//!   2. `sign_digest_with_nonce` with the RFC's `k` reproduces it too;
//!   3. the RFC's `(r, s)`, exactly as printed, verifies.
//!
//! Both signers emit `s` as the standards compute it, so every signature is
//! pinned digit for digit; for ECDSA the low-`s` form is a separate
//! conversion (`EcdsaSignature::to_low_s`) and is not applied here.

use cryptography::vt::{
    b163, b233, b283, b409, b571, k163, k233, k283, k409, k571, p192, p224, p256, p384, p521,
    BigUint, CurveParams, Dsa, DsaPrivateKey, DsaPublicKey, DsaSignature, Ecdsa, EcdsaPrivateKey,
    EcdsaPublicKey, EcdsaSignature,
};
use cryptography::{Digest, Sha1, Sha224, Sha256, Sha384, Sha512};

const APPENDIX_A2: &str = include_str!("vectors/rfc6979_appendix_a2.txt");

/// One `With SHA-xxx, message = "yyy":` block: its `k`, `r` and `s`.
struct SignatureVector {
    hash: String,
    message: String,
    values: Vec<(String, BigUint)>,
}

/// One subsection A.2.N: a key and its ten signatures.
struct KeyVector {
    /// Subsection heading, e.g. `A.2.5.  ECDSA, 256 Bits (Prime Field)`.
    heading: String,
    /// The `curve:` line, e.g. `NIST P-256` (ECDSA subsections only).
    curve: Option<String>,
    /// The `(qlen = N bits)` line (ECDSA subsections only).
    qlen: Option<usize>,
    /// Key values in order of appearance: `p`, `q`, `g`, `x`, `y`, `Ux`, `Uy`.
    values: Vec<(String, BigUint)>,
    signatures: Vec<SignatureVector>,
}

fn lookup<'a>(values: &'a [(String, BigUint)], name: &str, context: &str) -> &'a BigUint {
    let mut found = values.iter().filter(|(n, _)| n == name);
    let value = found
        .next()
        .unwrap_or_else(|| panic!("{context}: no `{name}` in the appendix"));
    assert!(found.next().is_none(), "{context}: `{name}` appears twice");
    &value.1
}

impl KeyVector {
    fn value(&self, name: &str) -> &BigUint {
        lookup(&self.values, name, &self.heading)
    }
}

impl SignatureVector {
    fn value(&self, name: &str) -> &BigUint {
        lookup(&self.values, name, &self.hash)
    }
}

fn is_hex_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn hex_upper(value: &BigUint) -> String {
    value.to_str_radix(16).to_uppercase()
}

fn current(keys: &mut [KeyVector]) -> &mut KeyVector {
    keys.last_mut()
        .expect("appendix content before the first A.2.N subsection")
}

/// File one completed `name = digits` assignment under the current key, or
/// under its most recent signature block for `k`, `r` and `s`.
fn store(keys: &mut [KeyVector], name: String, digits: &str) {
    let value = BigUint::from_str_radix(digits, 16).expect("hexadecimal value");
    let key = current(keys);
    if matches!(name.as_str(), "k" | "r" | "s") {
        key.signatures
            .last_mut()
            .expect("k, r or s outside a signature block")
            .values
            .push((name, value));
    } else {
        assert!(
            key.signatures.is_empty(),
            "{}: key value `{name}` after the signatures",
            key.heading
        );
        key.values.push((name, value));
    }
}

/// Parse the appendix into its seventeen keys.
///
/// A value is `name = HEX` with the digits possibly continued on following
/// lines that hold nothing but hex digits. Blank lines never end a value (a
/// page break could fall inside one); any other line does.
fn parse_appendix() -> Vec<KeyVector> {
    let mut keys: Vec<KeyVector> = Vec::new();
    let mut pending: Option<(String, String)> = None;

    for line in APPENDIX_A2.lines() {
        if line.starts_with('#') {
            continue;
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        if let Some((_, digits)) = pending.as_mut() {
            if is_hex_digits(text) {
                digits.push_str(text);
                continue;
            }
        }
        if let Some((name, digits)) = pending.take() {
            store(&mut keys, name, &digits);
        }

        if line.starts_with("A.2.") {
            // `A.2.  Test Vectors` introduces the appendix; `A.2.N.` opens a key.
            if !line.starts_with("A.2.  ") {
                keys.push(KeyVector {
                    heading: line.to_owned(),
                    curve: None,
                    qlen: None,
                    values: Vec::new(),
                    signatures: Vec::new(),
                });
            }
        } else if let Some(name) = text.strip_prefix("curve: ") {
            current(&mut keys).curve = Some(name.to_owned());
        } else if let Some(bits) = text
            .strip_prefix("(qlen = ")
            .and_then(|rest| rest.strip_suffix(" bits)"))
        {
            current(&mut keys).qlen = Some(bits.parse().expect("qlen is decimal"));
        } else if let Some(rest) = text.strip_prefix("With ") {
            let (hash, message) = rest
                .split_once(", message = ")
                .expect("`With HASH, message = \"...\":`");
            let message = message
                .strip_prefix('"')
                .and_then(|m| m.strip_suffix("\":"))
                .expect("quoted message");
            current(&mut keys).signatures.push(SignatureVector {
                hash: hash.to_owned(),
                message: message.to_owned(),
                values: Vec::new(),
            });
        } else if let Some((name, digits)) = text.split_once(" = ") {
            if is_identifier(name) && is_hex_digits(digits) {
                pending = Some((name.to_owned(), digits.to_owned()));
            }
        }
    }
    if let Some((name, digits)) = pending.take() {
        store(&mut keys, name, &digits);
    }
    keys
}

/// Subsection A.2.`number`, checked to hold exactly the ten signatures the
/// appendix promises: both messages under each of the five hashes, each with
/// one `k`, one `r` and one `s`.
fn key_vector(number: u32) -> KeyVector {
    let prefix = format!("A.2.{number}.");
    let key = parse_appendix()
        .into_iter()
        .find(|k| k.heading.starts_with(&prefix))
        .unwrap_or_else(|| panic!("subsection {prefix} not found"));
    assert_eq!(key.signatures.len(), 10, "{}", key.heading);
    for hash in ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"] {
        for message in ["sample", "test"] {
            let count = key
                .signatures
                .iter()
                .filter(|s| s.hash == hash && s.message == message)
                .count();
            assert_eq!(count, 1, "{}: {hash} / {message}", key.heading);
        }
    }
    for signature in &key.signatures {
        let mut names: Vec<&str> = signature.values.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["k", "r", "s"], "{}", key.heading);
    }
    key
}

// ─── DER framing for the RFC's (r, s) ───────────────────────────────────────

fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(u8::try_from(len).expect("short-form length"));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).expect("length of length"));
        out.extend_from_slice(&bytes);
    }
}

fn der_integer(value: &BigUint) -> Vec<u8> {
    let mut content = value.to_be_bytes();
    if content.first().is_none_or(|&b| b & 0x80 != 0) {
        content.insert(0, 0);
    }
    let mut out = vec![0x02];
    push_der_length(&mut out, content.len());
    out.extend_from_slice(&content);
    out
}

/// `SEQUENCE { r INTEGER, s INTEGER }`, the X9.62 / RFC 3279 signature value,
/// which is the only public way to hand an exact `(r, s)` to a verifier.
fn der_signature(r: &BigUint, s: &BigUint) -> Vec<u8> {
    let mut body = der_integer(r);
    body.extend_from_slice(&der_integer(s));
    let mut out = vec![0x30];
    push_der_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

// ─── ECDSA ──────────────────────────────────────────────────────────────────

fn check_ecdsa<H: Digest>(
    public: &EcdsaPublicKey,
    private: &EcdsaPrivateKey,
    q: &BigUint,
    vector: &SignatureVector,
    label: &str,
    failures: &mut Vec<String>,
) {
    let message = vector.message.as_bytes();
    let (k, r, s) = (vector.value("k"), vector.value("r"), vector.value("s"));
    let describe = |what: &str, got: Option<&EcdsaSignature>| match got {
        Some(sig) => format!(
            "{label}: {what} gave r = {}, s = {}; RFC r = {}, s = {}",
            hex_upper(sig.r()),
            hex_upper(sig.s()),
            hex_upper(r),
            hex_upper(s)
        ),
        None => format!("{label}: {what} returned None"),
    };
    let matches = |sig: &EcdsaSignature| sig.r() == r && sig.s() == s;

    let deterministic = private.sign_message::<H>(message);
    if !deterministic.as_ref().is_some_and(matches) {
        failures.push(describe(
            "sign_message (RFC 6979 nonce)",
            deterministic.as_ref(),
        ));
    }

    let from_k = private.sign_digest_with_nonce(&H::digest(message), k);
    if !from_k.as_ref().is_some_and(matches) {
        failures.push(describe("sign_digest_with_nonce(k)", from_k.as_ref()));
    }

    let published = EcdsaSignature::from_der(&der_signature(r, s)).expect("RFC (r, s) frames");
    if !public.verify_message::<H>(message, &published) {
        failures.push(format!("{label}: the RFC's (r, s) does not verify"));
    }
    // The other representative of {s, q − s} verifies as well, and `to_low_s`
    // picks the one at or below (q − 1)/2.
    let low = published.to_low_s(public.curve());
    let mut half = q.clone();
    half.shr1();
    if low.r() != r || *low.s() > half || !public.verify_message::<H>(message, &low) {
        failures.push(format!("{label}: to_low_s gave s = {}", hex_upper(low.s())));
    }
    if *low.s() != *s && low.s().add(s) != *q {
        failures.push(format!(
            "{label}: to_low_s changed s to something other than q − s"
        ));
    }
}

fn run_ecdsa(number: u32, curve_name: &str, curve: CurveParams) {
    let key = key_vector(number);
    let heading = key.heading.as_str();
    assert_eq!(key.curve.as_deref(), Some(curve_name), "{heading}: curve");
    let q = key.value("q");
    assert_eq!(
        Some(q.bits()),
        key.qlen,
        "{heading}: the RFC's q against its qlen"
    );

    let mut failures = Vec::new();
    if &curve.n != q {
        failures.push(format!(
            "{heading}: the named curve's order n = {} is not the RFC's q = {}",
            hex_upper(&curve.n),
            hex_upper(q)
        ));
    }
    let Some((public, private)) = Ecdsa::from_secret_scalar(curve, key.value("x")) else {
        failures.push(format!(
            "{heading}: from_secret_scalar rejected the RFC's x"
        ));
        panic!("{}", failures.join("\n"));
    };
    let point = public.public_point();
    if point.infinity || &point.x != key.value("Ux") || &point.y != key.value("Uy") {
        failures.push(format!(
            "{heading}: U = xG gave ({}, {}), RFC Ux = {}, Uy = {}",
            hex_upper(&point.x),
            hex_upper(&point.y),
            hex_upper(key.value("Ux")),
            hex_upper(key.value("Uy"))
        ));
    }

    for vector in &key.signatures {
        let label = format!("{heading} / {} / \"{}\"", vector.hash, vector.message);
        let args = (&public, &private, q, vector, label.as_str(), &mut failures);
        match vector.hash.as_str() {
            "SHA-1" => check_ecdsa::<Sha1>(args.0, args.1, args.2, args.3, args.4, args.5),
            "SHA-224" => check_ecdsa::<Sha224>(args.0, args.1, args.2, args.3, args.4, args.5),
            "SHA-256" => check_ecdsa::<Sha256>(args.0, args.1, args.2, args.3, args.4, args.5),
            "SHA-384" => check_ecdsa::<Sha384>(args.0, args.1, args.2, args.3, args.4, args.5),
            "SHA-512" => check_ecdsa::<Sha512>(args.0, args.1, args.2, args.3, args.4, args.5),
            other => panic!("{label}: unexpected hash {other}"),
        }
    }
    assert!(
        failures.is_empty(),
        "{} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ─── DSA ────────────────────────────────────────────────────────────────────

fn check_dsa<H: Digest>(
    public: &DsaPublicKey,
    private: &DsaPrivateKey,
    vector: &SignatureVector,
    label: &str,
    failures: &mut Vec<String>,
) {
    let message = vector.message.as_bytes();
    let (k, r, s) = (vector.value("k"), vector.value("r"), vector.value("s"));
    let describe = |what: &str, got: Option<&DsaSignature>| match got {
        Some(sig) => format!(
            "{label}: {what} gave r = {}, s = {}; RFC r = {}, s = {}",
            hex_upper(sig.r()),
            hex_upper(sig.s()),
            hex_upper(r),
            hex_upper(s)
        ),
        None => format!("{label}: {what} returned None"),
    };
    let matches = |sig: &DsaSignature| sig.r() == r && sig.s() == s;

    let deterministic = private.sign_message::<H>(message);
    if !deterministic.as_ref().is_some_and(matches) {
        failures.push(describe(
            "sign_message (RFC 6979 nonce)",
            deterministic.as_ref(),
        ));
    }

    let from_k = private.sign_digest_with_nonce(&H::digest(message), k);
    if !from_k.as_ref().is_some_and(matches) {
        failures.push(describe("sign_digest_with_nonce(k)", from_k.as_ref()));
    }

    let published = DsaSignature::from_der(&der_signature(r, s)).expect("RFC (r, s) frames");
    if !public.verify_message::<H>(message, &published) {
        failures.push(format!("{label}: the RFC's (r, s) does not verify"));
    }
}

fn run_dsa(number: u32) {
    let key = key_vector(number);
    let heading = key.heading.as_str();
    let (public, private) = Dsa::from_secret_exponent(
        key.value("p"),
        key.value("q"),
        key.value("g"),
        key.value("x"),
    )
    .expect("RFC group and private key validate");

    let mut failures = Vec::new();
    if public.public_component() != key.value("y") {
        failures.push(format!(
            "{heading}: y = g^x gave {}, RFC y = {}",
            hex_upper(public.public_component()),
            hex_upper(key.value("y"))
        ));
    }
    for vector in &key.signatures {
        let label = format!("{heading} / {} / \"{}\"", vector.hash, vector.message);
        let (pb, pr, l, f) = (&public, &private, label.as_str(), &mut failures);
        match vector.hash.as_str() {
            "SHA-1" => check_dsa::<Sha1>(pb, pr, vector, l, f),
            "SHA-224" => check_dsa::<Sha224>(pb, pr, vector, l, f),
            "SHA-256" => check_dsa::<Sha256>(pb, pr, vector, l, f),
            "SHA-384" => check_dsa::<Sha384>(pb, pr, vector, l, f),
            "SHA-512" => check_dsa::<Sha512>(pb, pr, vector, l, f),
            other => panic!("{label}: unexpected hash {other}"),
        }
    }
    assert!(
        failures.is_empty(),
        "{} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// The data file holds all seventeen subsections, 170 signatures in total.
#[test]
fn appendix_parses_into_seventeen_keys() {
    let keys = parse_appendix();
    let headings: Vec<&str> = keys.iter().map(|k| k.heading.as_str()).collect();
    assert_eq!(
        headings,
        [
            "A.2.1.  DSA, 1024 Bits",
            "A.2.2.  DSA, 2048 Bits",
            "A.2.3.  ECDSA, 192 Bits (Prime Field)",
            "A.2.4.  ECDSA, 224 Bits (Prime Field)",
            "A.2.5.  ECDSA, 256 Bits (Prime Field)",
            "A.2.6.  ECDSA, 384 Bits (Prime Field)",
            "A.2.7.  ECDSA, 521 Bits (Prime Field)",
            "A.2.8.  ECDSA, 163 Bits (Binary Field, Koblitz Curve)",
            "A.2.9.  ECDSA, 233 Bits (Binary Field, Koblitz Curve)",
            "A.2.10.  ECDSA, 283 Bits (Binary Field, Koblitz Curve)",
            "A.2.11.  ECDSA, 409 Bits (Binary Field, Koblitz Curve)",
            "A.2.12.  ECDSA, 571 Bits (Binary Field, Koblitz Curve)",
            "A.2.13.  ECDSA, 163 Bits (Binary Field, Pseudorandom Curve)",
            "A.2.14.  ECDSA, 233 Bits (Binary Field, Pseudorandom Curve)",
            "A.2.15.  ECDSA, 283 Bits (Binary Field, Pseudorandom Curve)",
            "A.2.16.  ECDSA, 409 Bits (Binary Field, Pseudorandom Curve)",
            "A.2.17.  ECDSA, 571 Bits (Binary Field, Pseudorandom Curve)",
        ]
    );
    let signatures: usize = keys.iter().map(|k| k.signatures.len()).sum();
    assert_eq!(signatures, 170);
}

/// RFC 6979 A.2.1: DSA, 1024-bit p, 160-bit q.
#[test]
fn a2_1_dsa_1024() {
    run_dsa(1);
}

/// RFC 6979 A.2.2: DSA, 2048-bit p, 256-bit q.
#[test]
fn a2_2_dsa_2048() {
    run_dsa(2);
}

/// RFC 6979 A.2.3: ECDSA over NIST P-192.
#[test]
fn a2_3_ecdsa_p192() {
    run_ecdsa(3, "NIST P-192", p192());
}

/// RFC 6979 A.2.4: ECDSA over NIST P-224.
#[test]
fn a2_4_ecdsa_p224() {
    run_ecdsa(4, "NIST P-224", p224());
}

/// RFC 6979 A.2.5: ECDSA over NIST P-256.
#[test]
fn a2_5_ecdsa_p256() {
    run_ecdsa(5, "NIST P-256", p256());
}

/// RFC 6979 A.2.6: ECDSA over NIST P-384.
#[test]
fn a2_6_ecdsa_p384() {
    run_ecdsa(6, "NIST P-384", p384());
}

/// RFC 6979 A.2.7: ECDSA over NIST P-521.
#[test]
fn a2_7_ecdsa_p521() {
    run_ecdsa(7, "NIST P-521", p521());
}

/// RFC 6979 A.2.8: ECDSA over NIST K-163.
#[test]
fn a2_8_ecdsa_k163() {
    run_ecdsa(8, "NIST K-163", k163());
}

/// RFC 6979 A.2.9: ECDSA over NIST K-233.
#[test]
fn a2_9_ecdsa_k233() {
    run_ecdsa(9, "NIST K-233", k233());
}

/// RFC 6979 A.2.10: ECDSA over NIST K-283.
#[test]
fn a2_10_ecdsa_k283() {
    run_ecdsa(10, "NIST K-283", k283());
}

/// RFC 6979 A.2.11: ECDSA over NIST K-409.
#[test]
fn a2_11_ecdsa_k409() {
    run_ecdsa(11, "NIST K-409", k409());
}

/// RFC 6979 A.2.12: ECDSA over NIST K-571.
#[test]
fn a2_12_ecdsa_k571() {
    run_ecdsa(12, "NIST K-571", k571());
}

/// RFC 6979 A.2.13: ECDSA over NIST B-163.
#[test]
fn a2_13_ecdsa_b163() {
    run_ecdsa(13, "NIST B-163", b163());
}

/// RFC 6979 A.2.14: ECDSA over NIST B-233.
#[test]
fn a2_14_ecdsa_b233() {
    run_ecdsa(14, "NIST B-233", b233());
}

/// RFC 6979 A.2.15: ECDSA over NIST B-283.
#[test]
fn a2_15_ecdsa_b283() {
    run_ecdsa(15, "NIST B-283", b283());
}

/// RFC 6979 A.2.16: ECDSA over NIST B-409.
#[test]
fn a2_16_ecdsa_b409() {
    run_ecdsa(16, "NIST B-409", b409());
}

/// RFC 6979 A.2.17: ECDSA over NIST B-571.
#[test]
fn a2_17_ecdsa_b571() {
    run_ecdsa(17, "NIST B-571", b571());
}
