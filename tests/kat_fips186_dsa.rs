//! NIST CAVP vectors for FIPS 186-4 DSA: key pairs, signature generation with
//! the per-message secret given, and signature verification.
//!
//! The vectors live in `vectors/fips186_4_dsa_keypair_siggen_sigver.txt`:
//! `KeyPair.rsp`, `SigGen.txt` and `SigVer.rsp` from NIST's
//! `186-3dsatestvectors.zip`, whose provenance the file's header records. The
//! file is parsed here rather than retyped, so every digit checked is a digit
//! of the CAVP file.
//!
//! What each part pins:
//!
//! - KeyPair: `Y = G^X mod P` for every key pair, through
//!   `Dsa::with_secret_exponent`, and that `DsaPublicKey::from_public_component`
//!   accepts the same `Y`.
//! - SigGen: `sign_digest_with_nonce(SHA(Msg), K)` reproduces `(R, S)` exactly
//!   (FIPS 186-4 §4.6 with the file's `K`), `Y` matches `X`, and the signature
//!   verifies under `Y` (§4.7).
//! - SigVer: the verdict of §4.7 on every record equals the file's `Result`,
//!   a changed `Y` that leaves the subgroup being refused by
//!   `DsaPublicKey::from_public_component` (SP 800-56A Rev. 3 §5.6.2.3.1) and
//!   every other change by verification.
//!
//! Every `[mod = ...]` group has its own domain parameters, and each group's
//! parameters go through the hardened validation of `DsaParams::new` once.
//! That validation costs seconds per group at 2048 and 3072 bits in a debug
//! build, so the default run covers every `L = 1024` group and the ignored
//! tests cover every group; run those with `--release -- --ignored`.

mod common;

use cryptography::vt::{BigUint, Dsa, DsaParams, DsaPrivateKey, DsaPublicKey, DsaSignature};
use cryptography::{Digest, Sha1, Sha224, Sha256, Sha384, Sha512};

const VECTORS: &str = include_str!("vectors/fips186_4_dsa_keypair_siggen_sigver.txt");

/// One `[mod = ...]` group of one CAVP file: its domain and its records.
struct Group {
    file: &'static str,
    l: usize,
    n: usize,
    /// `SHA-1`, `SHA-224`, ... for SigGen and SigVer; none for KeyPair.
    hash: Option<&'static str>,
    p: BigUint,
    q: BigUint,
    g: BigUint,
    records: Vec<Vec<(&'static str, &'static str)>>,
}

impl Group {
    fn describe(&self) -> String {
        match self.hash {
            Some(hash) => format!("{} L={} N={} {hash}", self.file, self.l, self.n),
            None => format!("{} L={} N={}", self.file, self.l, self.n),
        }
    }
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

fn bytes(record: &[(&str, &str)], key: &str, context: &str) -> Vec<u8> {
    common::decode_hex(field(record, key, context))
}

/// `[mod = L=1024, N=160, SHA-256]` or `[mod = L=1024, N=160]`.
fn parse_mod(spec: &'static str) -> (usize, usize, Option<&'static str>) {
    let mut parts = spec.split(", ");
    let mut length = |prefix: &str| -> usize {
        parts
            .next()
            .and_then(|part| part.strip_prefix(prefix))
            .and_then(|digits| digits.trim().parse().ok())
            .unwrap_or_else(|| panic!("group {spec} lacks {prefix}"))
    };
    let l = length("L=");
    let n = length("N=");
    (l, n, parts.next().map(str::trim))
}

/// Every group of every file, in file order. Blocks are separated by blank
/// lines; a group's first block holds `P`, `Q`, `G` and the rest are records.
fn groups() -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut file = "";
    let mut current: Option<(usize, usize, Option<&'static str>)> = None;
    let mut block: Vec<(&'static str, &'static str)> = Vec::new();
    for line in VECTORS.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if let Some(name) = line
            .strip_prefix("# ---- ")
            .and_then(|rest| rest.strip_suffix(" ----"))
        {
            flush(&mut block, &mut groups, file, current);
            file = name;
            current = None;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() || line.starts_with('[') {
            flush(&mut block, &mut groups, file, current);
            if let Some(spec) = line
                .strip_prefix("[mod = ")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                current = Some(parse_mod(spec));
            }
            continue;
        }
        let (key, value) = line.split_once(" = ").expect("key = value");
        block.push((key, value));
    }
    assert!(!groups.is_empty());
    groups
}

/// File one finished block: a domain starts a new group, anything else is a
/// record of the last one.
fn flush(
    block: &mut Vec<(&'static str, &'static str)>,
    groups: &mut Vec<Group>,
    file: &'static str,
    current: Option<(usize, usize, Option<&'static str>)>,
) {
    if block.is_empty() {
        return;
    }
    let (l, n, hash) = current.expect("records sit inside a [mod = ...] group");
    let fields = std::mem::take(block);
    if fields.iter().any(|(name, _)| *name == "P") {
        let context = format!("{file} L={l} N={n}");
        groups.push(Group {
            file,
            l,
            n,
            hash,
            p: integer(&fields, "P", &context),
            q: integer(&fields, "Q", &context),
            g: integer(&fields, "G", &context),
            records: Vec::new(),
        });
    } else {
        groups
            .last_mut()
            .expect("a record follows its group's domain")
            .records
            .push(fields);
    }
}

fn groups_of(file: &str, l: Option<usize>) -> Vec<Group> {
    let selected: Vec<Group> = groups()
        .into_iter()
        .filter(|group| group.file == file && l.is_none_or(|l| group.l == l))
        .collect();
    assert!(!selected.is_empty(), "no {file} groups with L = {l:?}");
    selected
}

/// The group's domain under the hardened validation of `DsaParams::new`.
fn params(group: &Group) -> DsaParams {
    DsaParams::new(group.p.clone(), group.q.clone(), group.g.clone())
        .unwrap_or_else(|| panic!("{}: domain parameters do not validate", group.describe()))
}

// ── KeyPair.rsp ─────────────────────────────────────────────────────────────

fn check_keypair_group(group: &Group) {
    let context = group.describe();
    let params = params(group);
    assert_eq!(group.records.len(), 10, "{context}");
    for record in &group.records {
        let x = integer(record, "X", &context);
        let y = integer(record, "Y", &context);
        let (public, private) = Dsa::with_secret_exponent(&params, &x)
            .unwrap_or_else(|| panic!("{context}: X is not in [1, q)"));
        assert_eq!(public.public_component(), &y, "{context}: Y = G^X");
        assert_eq!(private.exponent(), &x);
        assert_eq!(
            DsaPublicKey::from_public_component(&params, y),
            Some(public),
            "{context}: Y passes full public-key validation"
        );
    }
}

#[test]
fn keypair_1024_160() {
    for group in &groups_of("KeyPair.rsp", Some(1024)) {
        check_keypair_group(group);
    }
}

#[test]
#[ignore = "hardened validation of the 2048- and 3072-bit domains is slow in debug; run with --release --ignored"]
fn keypair_every_size() {
    let groups = groups_of("KeyPair.rsp", None);
    assert_eq!(groups.len(), 4);
    for group in &groups {
        check_keypair_group(group);
    }
}

// ── SigGen.txt ──────────────────────────────────────────────────────────────

/// One SigGen record under hash `H`: `Y` from `X`, `(R, S)` from `K`, and
/// verification of the result.
fn check_siggen_record<H: Digest>(
    params: &DsaParams,
    record: &[(&str, &str)],
    context: &str,
    failures: &mut Vec<String>,
) {
    let message = bytes(record, "Msg", context);
    let x = integer(record, "X", context);
    let y = integer(record, "Y", context);
    let k = integer(record, "K", context);
    let r = integer(record, "R", context);
    let s = integer(record, "S", context);
    let (public, private): (DsaPublicKey, DsaPrivateKey) = Dsa::with_secret_exponent(params, &x)
        .unwrap_or_else(|| panic!("{context}: X is not in [1, q)"));
    if public.public_component() != &y {
        failures.push(format!("{context}: Y != G^X"));
    }
    let digest = H::digest(&message);
    match private.sign_digest_with_nonce(&digest, &k) {
        Some(signature) if signature.r() == &r && signature.s() == &s => {
            if !public.verify_message::<H>(&message, &signature) {
                failures.push(format!("{context}: the signature does not verify"));
            }
        }
        Some(signature) => failures.push(format!(
            "{context}: got (R, S) = ({:X?}, {:X?})",
            signature.r().to_be_bytes(),
            signature.s().to_be_bytes()
        )),
        None => failures.push(format!("{context}: sign_digest_with_nonce returned None")),
    }
}

fn check_siggen_group(group: &Group, records: usize, failures: &mut Vec<String>) {
    let params = params(group);
    assert_eq!(group.records.len(), 15, "{}", group.describe());
    let hash = group.hash.expect("SigGen groups name a hash");
    for (index, record) in group.records.iter().take(records).enumerate() {
        let context = format!("{} record {index}", group.describe());
        let (p, r, c, f) = (&params, record.as_slice(), context.as_str(), &mut *failures);
        match hash {
            "SHA-1" => check_siggen_record::<Sha1>(p, r, c, f),
            "SHA-224" => check_siggen_record::<Sha224>(p, r, c, f),
            "SHA-256" => check_siggen_record::<Sha256>(p, r, c, f),
            "SHA-384" => check_siggen_record::<Sha384>(p, r, c, f),
            "SHA-512" => check_siggen_record::<Sha512>(p, r, c, f),
            other => panic!("{context}: unexpected hash {other}"),
        }
    }
}

fn report(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Three records of each `L = 1024` group, one group per hash.
#[test]
fn siggen_1024_160_every_hash() {
    let groups = groups_of("SigGen.txt", Some(1024));
    assert_eq!(groups.len(), 5);
    let mut failures = Vec::new();
    for group in &groups {
        check_siggen_group(group, 3, &mut failures);
    }
    report(failures);
}

#[test]
#[ignore = "every record of every (L, N, hash) group; run with --release --ignored"]
fn siggen_every_group_every_record() {
    let groups = groups_of("SigGen.txt", None);
    assert_eq!(groups.len(), 20);
    let mut failures = Vec::new();
    for group in &groups {
        check_siggen_group(group, usize::MAX, &mut failures);
    }
    report(failures);
}

// ── SigVer.rsp ──────────────────────────────────────────────────────────────

/// The §4.7 verdict on one record: a `Y` outside the subgroup is refused
/// before verification, everything else is verified.
fn verdict<H: Digest>(params: &DsaParams, record: &[(&str, &str)], context: &str) -> bool {
    let message = bytes(record, "Msg", context);
    let y = integer(record, "Y", context);
    let signature = DsaSignature::from_der(&der_signature(
        &integer(record, "R", context),
        &integer(record, "S", context),
    ))
    .expect("the file's R and S are non-zero");
    match DsaPublicKey::from_public_component(params, y) {
        Some(public) => public.verify_message::<H>(&message, &signature),
        None => false,
    }
}

/// `Dss-Sig-Value` of `(r, s)`, so the record's integers reach the verifier
/// through the same decoder a wire signature would.
fn der_signature(r: &BigUint, s: &BigUint) -> Vec<u8> {
    fn integer(value: &BigUint) -> Vec<u8> {
        let mut magnitude = value.to_be_bytes();
        if magnitude.first().is_some_and(|byte| byte & 0x80 != 0) {
            magnitude.insert(0, 0);
        }
        let mut out = vec![0x02];
        out.extend(length(magnitude.len()));
        out.extend(magnitude);
        out
    }
    fn length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            let mut out = vec![0x80 | bytes.len() as u8];
            out.extend(bytes);
            out
        }
    }
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![0x30];
    out.extend(length(body.len()));
    out.extend(body);
    out
}

fn check_sigver_group(group: &Group, failures: &mut Vec<String>) {
    let params = params(group);
    assert_eq!(group.records.len(), 15, "{}", group.describe());
    let hash = group.hash.expect("SigVer groups name a hash");
    let mut verdicts = [0usize; 2];
    for (index, record) in group.records.iter().enumerate() {
        let context = format!("{} record {index}", group.describe());
        let result = field(record, "Result", &context);
        let expected = match result.as_bytes().first() {
            Some(b'P') => true,
            Some(b'F') => false,
            _ => panic!("{context}: unrecognized Result {result}"),
        };
        verdicts[usize::from(expected)] += 1;
        let (p, r, c) = (&params, record.as_slice(), context.as_str());
        let actual = match hash {
            "SHA-1" => verdict::<Sha1>(p, r, c),
            "SHA-224" => verdict::<Sha224>(p, r, c),
            "SHA-256" => verdict::<Sha256>(p, r, c),
            "SHA-384" => verdict::<Sha384>(p, r, c),
            "SHA-512" => verdict::<Sha512>(p, r, c),
            other => panic!("{context}: unexpected hash {other}"),
        };
        if actual != expected {
            failures.push(format!("{context}: verdict {actual}, Result = {result}"));
        }
    }
    // Every group carries at least five P and five F records.
    assert!(
        verdicts[0] >= 5 && verdicts[1] >= 5,
        "{}: {} F and {} P records",
        group.describe(),
        verdicts[0],
        verdicts[1]
    );
}

/// Every record of every `L = 1024` group, one group per hash.
#[test]
fn sigver_1024_160_every_hash_every_record() {
    let groups = groups_of("SigVer.rsp", Some(1024));
    assert_eq!(groups.len(), 5);
    let mut failures = Vec::new();
    for group in &groups {
        check_sigver_group(group, &mut failures);
    }
    report(failures);
}

#[test]
#[ignore = "every (L, N, hash) group; run with --release --ignored"]
fn sigver_every_group_every_record() {
    let groups = groups_of("SigVer.rsp", None);
    assert_eq!(groups.len(), 20);
    let mut failures = Vec::new();
    for group in &groups {
        check_sigver_group(group, &mut failures);
    }
    report(failures);
}
