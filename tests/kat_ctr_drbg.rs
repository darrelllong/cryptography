//! NIST CAVP known answers for `CtrDrbgAes256` and `CtrDrbgAes256Ct`:
//! SP 800-90A Rev. 1 `CTR_DRBG` with AES-256 and no derivation function, on
//! the T-table and the constant-time AES-256. Every group runs through both.
//!
//! The vectors live in `vectors/ctr_drbg_aes256_no_df.txt`, transcribed
//! verbatim from the CAVP archive `drbgtestvectors.zip` (CAVS 14.3): from each
//! of `drbgvectors_no_reseed/CTR_DRBG.rsp` and
//! `drbgvectors_pr_false/CTR_DRBG.rsp`, the first `[AES-256 no df]` group for
//! each personalization-string length (0, 384) and additional-input length
//! (0, 384): eight groups of fifteen trials, 120 trials in all.
//!
//! The call sequence is the one fixed by NIST's DRBG Validation System
//! document ("The NIST SP 800-90A Deterministic Random Bit Generator
//! Validation System (DRBGVS)", section 6.2):
//!
//! - reseed not tested (`drbgvectors_no_reseed`): instantiate, generate
//!   (output discarded), generate (output compared with `ReturnedBits`);
//! - prediction resistance false (`drbgvectors_pr_false`): instantiate,
//!   reseed, generate (discarded), generate (compared).
//!
//! Each vector field goes to the DRBG as the standard names it:
//! `EntropyInput` and `PersonalizationString` to `CtrDrbg::instantiate`,
//! `EntropyInputReseed` and `AdditionalInputReseed` to
//! `reseed_with_additional_input`, and each `AdditionalInput` to `generate`
//! (384 bits, or `None` when the vector's field is empty).

mod common;

use common::{decode_hex, encode_hex};
use cryptography::cprng::ctr_drbg::{CtrDrbg, CtrDrbgCipher};
use cryptography::{Aes256, Aes256Ct};

const VECTORS: &str = include_str!("vectors/ctr_drbg_aes256_no_df.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    /// `drbgvectors_no_reseed`: instantiate, generate, generate.
    NoReseed,
    /// `drbgvectors_pr_false`: instantiate, reseed, generate, generate.
    ReseedFirst,
}

struct Trial {
    count: u32,
    fields: Vec<(String, Vec<u8>)>,
}

struct Group {
    flow: Flow,
    parameters: Vec<String>,
    trials: Vec<Trial>,
}

impl Trial {
    fn all(&self, name: &str) -> Vec<&[u8]> {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    fn one(&self, name: &str) -> &[u8] {
        let found = self.all(name);
        assert_eq!(found.len(), 1, "COUNT = {}: one `{name}`", self.count);
        found[0]
    }
}

fn parse() -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut flow = None;
    let mut in_header = false;
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            match line {
                "# ---- drbgvectors_no_reseed/CTR_DRBG.rsp ----" => flow = Some(Flow::NoReseed),
                "# ---- drbgvectors_pr_false/CTR_DRBG.rsp ----" => flow = Some(Flow::ReseedFirst),
                _ => {}
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !in_header {
                groups.push(Group {
                    flow: flow.expect("group header before a file marker"),
                    parameters: Vec::new(),
                    trials: Vec::new(),
                });
                in_header = true;
            }
            groups
                .last_mut()
                .expect("group just pushed")
                .parameters
                .push(line.to_owned());
            continue;
        }
        in_header = false;
        let (name, value) = line.split_once(" =").expect("`NAME = value` record line");
        let value = value.trim();
        let group = groups.last_mut().expect("record before a group header");
        if name == "COUNT" {
            group.trials.push(Trial {
                count: value.parse().expect("decimal COUNT"),
                fields: Vec::new(),
            });
        } else {
            group
                .trials
                .last_mut()
                .expect("field before COUNT")
                .fields
                .push((name.to_owned(), decode_hex(value)));
        }
    }
    groups
}

fn group(flow: Flow, personalization_bits: u32, additional_bits: u32) -> Group {
    let wanted = [
        "[AES-256 no df]".to_owned(),
        "[PredictionResistance = False]".to_owned(),
        "[EntropyInputLen = 384]".to_owned(),
        "[NonceLen = 0]".to_owned(),
        format!("[PersonalizationStringLen = {personalization_bits}]"),
        format!("[AdditionalInputLen = {additional_bits}]"),
        "[ReturnedBitsLen = 512]".to_owned(),
    ];
    let mut found: Vec<Group> = parse()
        .into_iter()
        .filter(|g| g.flow == flow && g.parameters == wanted)
        .collect();
    assert_eq!(found.len(), 1, "{flow:?} {wanted:?}");
    let group = found.pop().expect("one group");
    let counts: Vec<u32> = group.trials.iter().map(|t| t.count).collect();
    assert_eq!(counts, (0..15).collect::<Vec<u32>>(), "{flow:?} {wanted:?}");
    group
}

fn entropy_input(bytes: &[u8]) -> [u8; 48] {
    bytes.try_into().expect("EntropyInputLen = 384 bits")
}

fn additional_input(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() {
        None
    } else {
        assert_eq!(bytes.len(), 48, "AdditionalInputLen = 384 bits");
        Some(bytes)
    }
}

fn run_trial<C: CtrDrbgCipher>(flow: Flow, trial: &Trial) -> Vec<u8> {
    assert!(trial.one("Nonce").is_empty(), "no-df trials carry no nonce");
    let mut drbg = CtrDrbg::<C>::instantiate(
        &entropy_input(trial.one("EntropyInput")),
        trial.one("PersonalizationString"),
    );
    match flow {
        Flow::NoReseed => assert!(trial.all("EntropyInputReseed").is_empty()),
        Flow::ReseedFirst => drbg.reseed_with_additional_input(
            &entropy_input(trial.one("EntropyInputReseed")),
            trial.one("AdditionalInputReseed"),
        ),
    }
    let additional = trial.all("AdditionalInput");
    assert_eq!(additional.len(), 2, "COUNT = {}", trial.count);
    let mut out = vec![0u8; trial.one("ReturnedBits").len()];
    drbg.generate(&mut out, additional_input(additional[0]));
    drbg.generate(&mut out, additional_input(additional[1]));
    out
}

/// Run one group through the DRBG on `C`, naming the implementation in any
/// failure.
fn run_group_on<C: CtrDrbgCipher>(
    which: &str,
    flow: Flow,
    personalization_bits: u32,
    additional_bits: u32,
) {
    let group = group(flow, personalization_bits, additional_bits);
    let failures: Vec<String> = group
        .trials
        .iter()
        .filter_map(|trial| {
            let got = run_trial::<C>(flow, trial);
            let expected = trial.one("ReturnedBits");
            (got != expected).then(|| {
                format!(
                    "COUNT = {}: ReturnedBits = {}, got {}",
                    trial.count,
                    encode_hex(expected),
                    encode_hex(&got)
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{which}: {flow:?}, PersonalizationStringLen = {personalization_bits}, \
         AdditionalInputLen = {additional_bits}: {} of 15 trials failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every group is a known answer for both instantiations: `CtrDrbgAes256`
/// (`CtrDrbg<Aes256>`) and `CtrDrbgAes256Ct` (`CtrDrbg<Aes256Ct>`).
fn run_group(flow: Flow, personalization_bits: u32, additional_bits: u32) {
    run_group_on::<Aes256>("CtrDrbgAes256", flow, personalization_bits, additional_bits);
    run_group_on::<Aes256Ct>(
        "CtrDrbgAes256Ct",
        flow,
        personalization_bits,
        additional_bits,
    );
}

/// The data file holds four groups of fifteen trials for each call sequence.
#[test]
fn vector_file_holds_eight_groups() {
    let groups = parse();
    assert_eq!(groups.len(), 8);
    for flow in [Flow::NoReseed, Flow::ReseedFirst] {
        assert_eq!(groups.iter().filter(|g| g.flow == flow).count(), 4);
    }
    assert!(groups.iter().all(|g| g.trials.len() == 15));
}

/// drbgvectors_no_reseed, `[PersonalizationStringLen = 0]`, `[AdditionalInputLen = 0]`.
#[test]
fn no_reseed_personalization_0_additional_input_0() {
    run_group(Flow::NoReseed, 0, 0);
}

/// drbgvectors_no_reseed, `[PersonalizationStringLen = 0]`, `[AdditionalInputLen = 384]`.
#[test]
fn no_reseed_personalization_0_additional_input_384() {
    run_group(Flow::NoReseed, 0, 384);
}

/// drbgvectors_no_reseed, `[PersonalizationStringLen = 384]`, `[AdditionalInputLen = 0]`.
#[test]
fn no_reseed_personalization_384_additional_input_0() {
    run_group(Flow::NoReseed, 384, 0);
}

/// drbgvectors_no_reseed, `[PersonalizationStringLen = 384]`, `[AdditionalInputLen = 384]`.
#[test]
fn no_reseed_personalization_384_additional_input_384() {
    run_group(Flow::NoReseed, 384, 384);
}

/// drbgvectors_pr_false, `[PersonalizationStringLen = 0]`, `[AdditionalInputLen = 0]`.
#[test]
fn reseed_personalization_0_additional_input_0() {
    run_group(Flow::ReseedFirst, 0, 0);
}

/// drbgvectors_pr_false, `[PersonalizationStringLen = 0]`, `[AdditionalInputLen = 384]`.
#[test]
fn reseed_personalization_0_additional_input_384() {
    run_group(Flow::ReseedFirst, 0, 384);
}

/// drbgvectors_pr_false, `[PersonalizationStringLen = 384]`, `[AdditionalInputLen = 0]`.
#[test]
fn reseed_personalization_384_additional_input_0() {
    run_group(Flow::ReseedFirst, 384, 0);
}

/// drbgvectors_pr_false, `[PersonalizationStringLen = 384]`, `[AdditionalInputLen = 384]`.
#[test]
fn reseed_personalization_384_additional_input_384() {
    run_group(Flow::ReseedFirst, 384, 384);
}
