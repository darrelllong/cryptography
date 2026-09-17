//! NIST CAVP known answers for `HashDrbg` and `HmacDrbg`: SP 800-90A Rev. 1
//! `Hash_DRBG` and `HMAC_DRBG` with SHA-256.
//!
//! The vectors live in `vectors/hash_drbg_sha256.txt` and
//! `vectors/hmac_drbg_sha256.txt`, transcribed verbatim from the CAVP archive
//! `drbgtestvectors.zip` (CAVS 14.3): from each of `drbgvectors_no_reseed` and
//! `drbgvectors_pr_false`, the first `[SHA-256]` group for each
//! personalization-string length (0, 256) and additional-input length (0, 256):
//! eight groups of fifteen trials, 120 trials per mechanism.
//!
//! The call sequence is the one fixed by NIST's DRBG Validation System
//! document (DRBGVS, section 6.2):
//!
//! - reseed not tested (`drbgvectors_no_reseed`): instantiate, generate
//!   (output discarded), generate (output compared with `ReturnedBits`);
//! - prediction resistance false (`drbgvectors_pr_false`): instantiate,
//!   reseed, generate (discarded), generate (compared).
//!
//! Each field goes to the DRBG as the standard names it: `EntropyInput`,
//! `Nonce` and `PersonalizationString` to `instantiate`,
//! `EntropyInputReseed` and `AdditionalInputReseed` to `reseed`, and each
//! `AdditionalInput` to `generate` (an empty field is the standard's Null).

mod common;

use common::{decode_hex, encode_hex};
use cryptography::cprng::hash_drbg::HashDrbg;
use cryptography::cprng::hmac_drbg::HmacDrbg;
use cryptography::cprng::DrbgError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    NoReseed,
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

fn parse(text: &str, rsp: &str) -> Vec<Group> {
    let no_reseed = format!("# ---- drbgvectors_no_reseed/{rsp} ----");
    let pr_false = format!("# ---- drbgvectors_pr_false/{rsp} ----");
    let mut groups: Vec<Group> = Vec::new();
    let mut flow = None;
    let mut in_header = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            if line == no_reseed {
                flow = Some(Flow::NoReseed);
            } else if line == pr_false {
                flow = Some(Flow::ReseedFirst);
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

/// The one mechanism under test, driven through the DRBGVS sequence.
trait Mechanism: Sized {
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: &[u8])
        -> Result<Self, DrbgError>;
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), DrbgError>;
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), DrbgError>;
}

impl Mechanism for HashDrbg {
    fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        HashDrbg::instantiate(entropy, nonce, personalization)
    }
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), DrbgError> {
        HashDrbg::reseed(self, entropy, additional)
    }
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), DrbgError> {
        HashDrbg::generate(self, out, additional)
    }
}

impl Mechanism for HmacDrbg {
    fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        HmacDrbg::instantiate(entropy, nonce, personalization)
    }
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), DrbgError> {
        HmacDrbg::reseed(self, entropy, additional)
    }
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), DrbgError> {
        HmacDrbg::generate(self, out, additional)
    }
}

fn run_trial<M: Mechanism>(flow: Flow, trial: &Trial) -> Vec<u8> {
    let mut drbg = M::instantiate(
        trial.one("EntropyInput"),
        trial.one("Nonce"),
        trial.one("PersonalizationString"),
    )
    .expect("CAVP inputs meet the length minimums");
    match flow {
        Flow::NoReseed => assert!(trial.all("EntropyInputReseed").is_empty()),
        Flow::ReseedFirst => drbg
            .reseed(
                trial.one("EntropyInputReseed"),
                trial.one("AdditionalInputReseed"),
            )
            .expect("CAVP reseed input meets the length minimum"),
    }
    let additional = trial.all("AdditionalInput");
    assert_eq!(additional.len(), 2, "COUNT = {}", trial.count);
    let mut out = vec![0u8; trial.one("ReturnedBits").len()];
    drbg.generate(&mut out, additional[0])
        .expect("first request");
    drbg.generate(&mut out, additional[1])
        .expect("second request");
    out
}

fn run_all<M: Mechanism>(which: &str, text: &str, rsp: &str) {
    let groups = parse(text, rsp);
    let mut checked = 0;
    for flow in [Flow::NoReseed, Flow::ReseedFirst] {
        for personalization in [0, 256] {
            for additional in [0, 256] {
                let wanted = [
                    "[SHA-256]".to_owned(),
                    "[PredictionResistance = False]".to_owned(),
                    "[EntropyInputLen = 256]".to_owned(),
                    "[NonceLen = 128]".to_owned(),
                    format!("[PersonalizationStringLen = {personalization}]"),
                    format!("[AdditionalInputLen = {additional}]"),
                    "[ReturnedBitsLen = 1024]".to_owned(),
                ];
                let found: Vec<&Group> = groups
                    .iter()
                    .filter(|g| g.flow == flow && g.parameters == wanted)
                    .collect();
                assert_eq!(found.len(), 1, "{which} {flow:?} {wanted:?}");
                let group = found[0];
                let counts: Vec<u32> = group.trials.iter().map(|t| t.count).collect();
                assert_eq!(counts, (0..15).collect::<Vec<u32>>());
                let failures: Vec<String> = group
                    .trials
                    .iter()
                    .filter_map(|trial| {
                        let got = run_trial::<M>(flow, trial);
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
                    "{which} {flow:?} pers {personalization} add {additional}:\n{}",
                    failures.join("\n")
                );
                checked += group.trials.len();
            }
        }
    }
    assert_eq!(checked, 120, "{which}");
}

#[test]
fn hash_drbg_sha256_cavp() {
    run_all::<HashDrbg>(
        "Hash_DRBG",
        include_str!("vectors/hash_drbg_sha256.txt"),
        "Hash_DRBG.rsp",
    );
}

#[test]
fn hmac_drbg_sha256_cavp() {
    run_all::<HmacDrbg>(
        "HMAC_DRBG",
        include_str!("vectors/hmac_drbg_sha256.txt"),
        "HMAC_DRBG.rsp",
    );
}
