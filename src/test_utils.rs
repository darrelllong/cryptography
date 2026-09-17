//! Helpers shared by the crate's unit tests.
//!
//! [`vectors`] decodes known answers from hexadecimal text and from the
//! crate's `KEY=VALUE` vector files; its helpers are re-exported here.
//!
//! The rest of the module cross-validates implementations against the
//! installed `openssl` command-line tool. The helpers spawn `openssl` as a
//! subprocess and hand back its output for the caller to compare against the
//! native implementation. Every call ends in one of the [`OpenSslOutcome`]
//! states, and a cross-check test must react to each of them explicitly:
//!
//! - no `openssl` found — the test skips (nothing to compare against);
//! - the installed tool says it lacks the algorithm (OpenSSL 3 `enc` and
//!   `dgst` name the cipher or digest they do not know; a cipher living in an
//!   unloaded provider fetches as `unsupported`; `enc` refuses XTS with "not
//!   supported") — the test skips, and says so on stderr naming the test and
//!   the reason, so `cargo test -- --nocapture` shows what was not exercised;
//! - the tool ran — the caller compares the bytes and a mismatch **fails**.
//!
//! A diagnostic about the invocation rather than the algorithm — usage text,
//! an unknown or unrecognized option, an invalid command — is an error in the
//! test itself and panics, as does any other non-zero exit (a bad key length,
//! say): neither may turn into a silent pass. LibreSSL answers an algorithm
//! it lacks with the same usage text it prints for a mistyped flag, so under
//! LibreSSL such a cross-check panics and the message says to install OpenSSL
//! 3 or name one through `CRYPTOGRAPHY_OPENSSL`.
//!
//! Setting `CRYPTOGRAPHY_OPENSSL_REQUIRED=1` turns the two skips into
//! failures as well, for a CI runner that has installed OpenSSL and means the
//! cross-checks to run: a missing tool or an algorithm it lacks then fails
//! the test. The one skip that survives is `enc` refusing a mode it has never
//! driven (XTS: "XTS ciphers not supported"), because no installation can
//! change that.
//!
//! The tool is chosen once per test binary. `CRYPTOGRAPHY_OPENSSL`, when set,
//! names the binary and nothing else is tried. Otherwise the candidates are
//! every `openssl` on `PATH`, in order, then Homebrew's `openssl@3` prefixes;
//! the first OpenSSL 3 or later among them wins, then the first older OpenSSL,
//! then LibreSSL. macOS puts LibreSSL in `/usr/bin` ahead of Homebrew, and
//! LibreSSL lacks algorithms the cross-checks exercise, so the first
//! `openssl` on `PATH` is not simply taken. The choice is printed to stderr,
//! which `cargo test -- --nocapture` shows.
//!
//! OpenSSL 3 moved single DES, CAST5, SEED, Blowfish, RC2/RC4/RC5 and IDEA into
//! its `legacy` provider. [`openssl_enc`] detects that flavor once and asks for
//! `-provider legacy -provider default` for those ciphers, so an OpenSSL 3 CI
//! runner really exercises them instead of skipping.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

mod vectors;

pub(crate) use vectors::{
    decode_hex, decode_hex_array, encode_hex, parse_vector_map, vector_fields,
};

/// Which `openssl` tool is installed, from the first two words of
/// `openssl version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenSslFlavor {
    /// LibreSSL (the macOS system binary).
    LibreSsl,
    /// OpenSSL proper, with its major version (1 or 3 in practice).
    OpenSsl {
        /// Leading component of the version string.
        major: u32,
    },
}

impl OpenSslFlavor {
    fn parse(version_line: &str) -> Option<Self> {
        let mut words = version_line.split_whitespace();
        let name = words.next()?;
        let version = words.next().unwrap_or("");
        let major = version
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(0);
        match name {
            "LibreSSL" => Some(Self::LibreSsl),
            "OpenSSL" => Some(Self::OpenSsl { major }),
            _ => None,
        }
    }

    /// OpenSSL 3 and later load algorithms from providers; earlier versions
    /// and LibreSSL reject the `-provider` option outright.
    fn uses_providers(self) -> bool {
        matches!(self, Self::OpenSsl { major } if major >= 3)
    }
}

/// Result of asking the installed `openssl` for a reference value.
#[derive(Debug)]
pub(crate) enum OpenSslOutcome {
    /// No `openssl` binary was found, or it could not be spawned.
    Absent,
    /// The tool runs but rejects this algorithm or option; the payload is the
    /// diagnostic it printed.
    Unsupported(String),
    /// The tool accepted the invocation and this is its standard output.
    Output(Vec<u8>),
}

impl OpenSslOutcome {
    /// Hand back the reference bytes, or report why `test` is being skipped
    /// on stderr and return `None` so the caller can `return`.
    ///
    /// Skips are deliberately loud: a cross-check that does not run should be
    /// visible in `cargo test -- --nocapture`, never mistaken for a pass.
    ///
    /// # Panics
    ///
    /// With `CRYPTOGRAPHY_OPENSSL_REQUIRED=1` in the environment a skip is a
    /// failure: panics when no tool was found or the tool lacks the
    /// algorithm. `enc` refusing a mode it never drives (XTS) still skips,
    /// since installing another OpenSSL cannot change that answer.
    pub(crate) fn or_skip(self, test: &str) -> Option<Vec<u8>> {
        match self {
            Self::Output(bytes) => Some(bytes),
            Self::Absent => {
                let message = format!(
                    "no `openssl` binary found (PATH, Homebrew openssl@3, {TOOL_OVERRIDE})"
                );
                assert!(
                    !openssl_required(),
                    "{test}: {message}, and {REQUIRED_OVERRIDE}=1 forbids skipping"
                );
                eprintln!("skipping {test}: {message}");
                None
            }
            Self::Unsupported(reason) => {
                let flavor = flavor()
                    .map(|f| format!("{f:?}"))
                    .unwrap_or_else(|| "unknown".to_owned());
                let message =
                    format!("installed openssl ({flavor}) rejects the algorithm: {reason}");
                assert!(
                    !openssl_required() || refused_by_enc_command(&reason),
                    "{test}: {message}, and {REQUIRED_OVERRIDE}=1 forbids skipping"
                );
                eprintln!("skipping {test}: {message}");
                None
            }
        }
    }
}

/// One runnable `openssl` binary and what it reported itself to be.
#[derive(Debug)]
struct Tool {
    path: PathBuf,
    flavor: OpenSslFlavor,
}

/// Environment variable naming the one binary to cross-check against.
const TOOL_OVERRIDE: &str = "CRYPTOGRAPHY_OPENSSL";

/// Environment variable that, set to `1`, makes a skipped cross-check fail.
const REQUIRED_OVERRIDE: &str = "CRYPTOGRAPHY_OPENSSL_REQUIRED";

/// Is skipping forbidden by [`REQUIRED_OVERRIDE`]?
fn openssl_required() -> bool {
    std::env::var_os(REQUIRED_OVERRIDE).is_some_and(|value| value == "1")
}

/// Does the tool's rejection come from the `enc` command refusing to drive a
/// mode at all? `enc` has never accepted XTS (or AEAD and key-wrap) ciphers
/// and says "<mode> ciphers not supported"; the library has the algorithm, so
/// no other installation would answer differently.
fn refused_by_enc_command(reason: &str) -> bool {
    reason
        .to_ascii_lowercase()
        .contains("ciphers not supported")
}

/// Where Homebrew installs OpenSSL 3, on Apple silicon and on Intel.
const HOMEBREW_OPENSSL3: [&str; 2] = [
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
];

/// The tool the cross-checks run, chosen once per test binary as the module
/// docs describe; `None` means absent.
fn tool() -> Option<&'static Tool> {
    static TOOL: OnceLock<Option<Tool>> = OnceLock::new();
    TOOL.get_or_init(|| {
        let chosen = choose_tool();
        match &chosen {
            Some(tool) => eprintln!(
                "openssl cross-checks run {} ({:?})",
                tool.path.display(),
                tool.flavor
            ),
            None => eprintln!("openssl cross-checks: no openssl binary found"),
        }
        chosen
    })
    .as_ref()
}

fn choose_tool() -> Option<Tool> {
    if let Some(path) = std::env::var_os(TOOL_OVERRIDE) {
        return probe(PathBuf::from(path));
    }
    let on_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join("openssl"))
                .collect()
        })
        .unwrap_or_default();
    on_path
        .into_iter()
        .chain(HOMEBREW_OPENSSL3.iter().map(PathBuf::from))
        .filter(|path| path.is_file())
        .filter_map(probe)
        // `min_by_key` keeps the first of equal ranks, so `PATH` order breaks
        // ties.
        .min_by_key(|tool| match tool.flavor {
            OpenSslFlavor::OpenSsl { major } if major >= 3 => 0,
            OpenSslFlavor::OpenSsl { .. } => 1,
            OpenSslFlavor::LibreSsl => 2,
        })
}

/// Run `path version` and identify the tool.
fn probe(path: PathBuf) -> Option<Tool> {
    let out = Command::new(&path)
        .arg("version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let flavor = OpenSslFlavor::parse(&String::from_utf8_lossy(&out.stdout))?;
    Some(Tool { path, flavor })
}

/// The flavor of the chosen tool; `None` means absent.
pub(crate) fn flavor() -> Option<OpenSslFlavor> {
    tool().map(|tool| tool.flavor)
}

/// What the tool's diagnostic says went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Diagnostic {
    /// The tool does not have the algorithm: OpenSSL 3 `enc` and `dgst` name
    /// the cipher or message digest they do not know, a cipher in an
    /// unloaded provider fetches as `unsupported`, `enc` refuses a mode as
    /// "not supported", and a provider module can fail to load.
    LacksAlgorithm,
    /// The invocation is wrong: usage text, an unknown or unrecognized
    /// option, an invalid command. A test bug, never a reason to skip.
    BadInvocation,
    /// Anything else (a bad key length, a short hex string).
    Other,
}

/// Diagnostics that say the tool lacks the algorithm. Checked before the
/// invocation markers because OpenSSL 3's "Unknown option or cipher" contains
/// one of them.
const LACKS_ALGORITHM: [&str; 13] = [
    "unknown option or cipher",
    "unknown option or message digest",
    "unknown cipher",
    "unknown digest",
    "unknown message digest",
    "no such cipher",
    "unsupported",
    "not supported",
    "error setting cipher",
    "could not load",
    "failed to load",
    "unable to load",
    "init fail",
];

/// Diagnostics that say the invocation itself is wrong.
const BAD_INVOCATION: [&str; 5] = [
    "usage:",
    "unknown option",
    "unrecognized flag",
    "invalid command",
    "multiple cipher or unknown options",
];

fn classify(stderr: &str) -> Diagnostic {
    let lower = stderr.to_ascii_lowercase();
    if LACKS_ALGORITHM.iter().any(|needle| lower.contains(needle)) {
        Diagnostic::LacksAlgorithm
    } else if BAD_INVOCATION.iter().any(|needle| lower.contains(needle)) {
        Diagnostic::BadInvocation
    } else {
        Diagnostic::Other
    }
}

/// Run `openssl` with the given arguments, piping `stdin` to its standard
/// input.
///
/// # Panics
///
/// Panics when the tool exits non-zero for any reason other than lacking the
/// algorithm (see the module docs): a wrong invocation or any other error is
/// a broken test, and hiding it behind a skip would defeat the cross-check.
pub(crate) fn openssl(args: &[&str], stdin: &[u8]) -> OpenSslOutcome {
    let Some(tool) = tool() else {
        return OpenSslOutcome::Absent;
    };
    let Ok(mut child) = Command::new(&tool.path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return OpenSslOutcome::Absent;
    };
    // A rejected invocation may exit before reading stdin; a failed write is
    // then just the pipe closing, and the exit status tells the real story.
    if let Some(mut pipe) = child.stdin.take() {
        let _ = pipe.write_all(stdin);
    }
    let out = child
        .wait_with_output()
        .expect("openssl child process was spawned and must be waitable");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let diagnostic = classify(&stderr);
    // `openssl <unknown-command>` prints "invalid command" and still exits 0.
    if out.status.success() && diagnostic != Diagnostic::BadInvocation {
        return OpenSslOutcome::Output(out.stdout);
    }
    let invocation = args.join(" ");
    match diagnostic {
        Diagnostic::LacksAlgorithm => {
            let first_line = stderr.lines().next().unwrap_or("").trim().to_owned();
            OpenSslOutcome::Unsupported(format!("`openssl {invocation}`: {first_line}"))
        }
        Diagnostic::BadInvocation => {
            let libressl_note = if tool.flavor == OpenSslFlavor::LibreSsl {
                format!(
                    "\nLibreSSL prints this same text for an algorithm it lacks; install \
                     OpenSSL 3 (Homebrew openssl@3) or name one through {TOOL_OVERRIDE}."
                )
            } else {
                String::new()
            };
            panic!(
                "`openssl {invocation}` rejected the invocation itself ({}); that is a \
                 mistyped flag or command in the test, not an algorithm the tool lacks:\n\
                 {stderr}{libressl_note}",
                out.status
            );
        }
        Diagnostic::Other => panic!(
            "`openssl {invocation}` failed ({}) for a reason that is not an algorithm \
             rejection:\n{stderr}",
            out.status
        ),
    }
}

/// [`openssl`] for cross-checks that compare against what OpenSSL 3 writes.
///
/// Older tools write other key containers for the same command — LibreSSL
/// and OpenSSL 1.1 answer `pkey -outform DER` with a key type's traditional
/// structure rather than PKCS #8, and LibreSSL has no X9.42 Diffie-Hellman
/// keys — so under any other tool the check reports itself unsupported and
/// skips loudly instead of failing on a difference in the tool.
pub(crate) fn openssl3(args: &[&str], stdin: &[u8]) -> OpenSslOutcome {
    match flavor() {
        None => OpenSslOutcome::Absent,
        Some(OpenSslFlavor::OpenSsl { major }) if major >= 3 => openssl(args, stdin),
        Some(other) => OpenSslOutcome::Unsupported(format!(
            "`openssl {}` needs OpenSSL 3 or later, found {other:?}",
            args.join(" ")
        )),
    }
}

/// Bound on a refusal that must come before any arithmetic on its oversized
/// input. The arithmetic it rules out (a primality test, a Montgomery
/// context or an irreducibility test at thousands of bits) takes seconds or
/// more in a debug build, so the bound separates the two by an order of
/// magnitude while leaving room for a shared, loaded host.
pub(crate) const REFUSAL_BOUND: std::time::Duration = std::time::Duration::from_millis(500);

/// The fastest of three wall-clock timings of `f`. Other load on the host
/// only lengthens a run, so the fastest is the one closest to the work
/// itself.
pub(crate) fn fastest_of_three(mut f: impl FnMut()) -> std::time::Duration {
    (0..3)
        .map(|_| {
            let started = std::time::Instant::now();
            f();
            started.elapsed()
        })
        .min()
        .expect("three runs")
}

/// A private key read by OpenSSL 3 from `stdin` in the form `inform` (`DER`
/// or `PEM`) and written back as PKCS #8 DER. `pkey -outform DER` is not
/// used for this: OpenSSL 3.0 writes an EC, DSA or RSA key's traditional
/// structure there, and later releases write PKCS #8. `pkcs8 -topk8
/// -nocrypt` writes PKCS #8 on every OpenSSL 3 release.
pub(crate) fn openssl3_pkcs8_der(inform: &str, stdin: &[u8]) -> OpenSslOutcome {
    openssl3(
        &[
            "pkcs8", "-topk8", "-nocrypt", "-inform", inform, "-outform", "DER",
        ],
        stdin,
    )
}

/// Ciphers OpenSSL 3 serves only from its `legacy` provider.
fn needs_legacy_provider(cipher_flag: &str) -> bool {
    let name = cipher_flag.trim_start_matches('-');
    let single_des = name == "des" || (name.starts_with("des-") && !name.starts_with("des-ede"));
    single_des
        || ["desx", "cast", "seed", "bf", "rc2", "rc4", "rc5", "idea"]
            .iter()
            .any(|family| name.starts_with(family))
}

/// Encrypt `input` with `openssl enc`. Flags `-nopad -nosalt -e` are always
/// set; on OpenSSL 3 the legacy provider is requested for ciphers that need it.
pub(crate) fn openssl_enc(
    cipher_name: &str,
    key_hex: &str,
    iv_hex: Option<&str>,
    input: &[u8],
) -> OpenSslOutcome {
    let mut args = vec!["enc"];
    if flavor().is_some_and(OpenSslFlavor::uses_providers) && needs_legacy_provider(cipher_name) {
        args.extend(["-provider", "legacy", "-provider", "default"]);
    }
    args.extend([cipher_name, "-nopad", "-nosalt", "-K", key_hex]);
    if let Some(iv) = iv_hex {
        args.extend(["-iv", iv]);
    }
    args.push("-e");
    openssl(&args, input)
}

/// A file the `openssl` tool reads or writes during a cross-check, for the
/// options that take a path rather than standard input (`pkeyutl -inkey`,
/// `-peerkey`, `-sigfile`, `-secret`, and `-in` with `-rawin`). It lives in
/// the system temporary directory under a name unique to the test, the file
/// and this process, and is removed when dropped.
pub(crate) struct ScratchFile {
    path: PathBuf,
}

impl ScratchFile {
    /// Create the file `name` for the test `test`, holding `contents`. The
    /// file must not exist yet, so a file or link planted at the name is
    /// refused rather than followed; on Unix only its owner may read it.
    ///
    /// # Panics
    ///
    /// Panics if the file exists already or cannot be written.
    pub(crate) fn new(test: &str, name: &str, contents: &[u8]) -> Self {
        let path =
            std::env::temp_dir().join(format!("cryptography-{test}-{}-{name}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .and_then(|mut file| file.write_all(contents))
            .unwrap_or_else(|err| panic!("cannot create {}: {err}", path.display()));
        Self { path }
    }

    /// The path, as `openssl` takes it.
    ///
    /// # Panics
    ///
    /// Panics if the temporary directory's path is not UTF-8.
    pub(crate) fn arg(&self) -> &str {
        self.path.to_str().expect("temporary path is UTF-8")
    }

    /// The contents now, after `openssl` has written the file.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be read.
    pub(crate) fn read(&self) -> Vec<u8> {
        std::fs::read(&self.path)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", self.path.display()))
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        // Best effort. A file left behind holds only a test key, readable on
        // Unix by its owner alone.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Re-encode one constructed DER value with BER's indefinite length (X.690
/// §8.1.3.6): still valid BER, no longer DER. For testing BER receivers.
pub(crate) fn der_to_indefinite_length(der: &[u8]) -> Vec<u8> {
    assert!(
        der.len() >= 2 && der[0] & 0x20 != 0,
        "one constructed DER value"
    );
    let (length, header) = if der[1] < 0x80 {
        (usize::from(der[1]), 2)
    } else {
        let octets = usize::from(der[1] & 0x7f);
        let length = der[2..2 + octets]
            .iter()
            .fold(0usize, |acc, &octet| (acc << 8) | usize::from(octet));
        (length, 2 + octets)
    };
    assert_eq!(header + length, der.len(), "exactly one DER value");
    let mut ber = Vec::with_capacity(der.len() + 2);
    ber.extend_from_slice(&[der[0], 0x80]);
    ber.extend_from_slice(&der[header..]);
    ber.extend_from_slice(&[0x00, 0x00]);
    ber
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavor_parses_version_lines() {
        assert_eq!(
            OpenSslFlavor::parse("LibreSSL 3.3.6"),
            Some(OpenSslFlavor::LibreSsl)
        );
        assert_eq!(
            OpenSslFlavor::parse("OpenSSL 3.0.2 15 Mar 2022"),
            Some(OpenSslFlavor::OpenSsl { major: 3 })
        );
        assert_eq!(
            OpenSslFlavor::parse("OpenSSL 1.1.1w  11 Sep 2023"),
            Some(OpenSslFlavor::OpenSsl { major: 1 })
        );
        assert_eq!(OpenSslFlavor::parse("BoringSSL"), None);
        assert!(OpenSslFlavor::OpenSsl { major: 3 }.uses_providers());
        assert!(!OpenSslFlavor::OpenSsl { major: 1 }.uses_providers());
        assert!(!OpenSslFlavor::LibreSsl.uses_providers());
    }

    #[test]
    fn legacy_provider_set_is_single_des_and_friends() {
        for flag in [
            "-des-ecb",
            "-des-cbc",
            "-des",
            "-desx-cbc",
            "-cast5-ecb",
            "-seed-ecb",
            "-bf-ecb",
            "-rc2-ecb",
            "-rc4",
            "-idea-ecb",
        ] {
            assert!(needs_legacy_provider(flag), "{flag} should need legacy");
        }
        for flag in [
            "-des-ede3-ecb",
            "-des-ede-cbc",
            "-aes-128-ecb",
            "-camellia-128-ecb",
            "-sm4-ecb",
            "-chacha20",
        ] {
            assert!(
                !needs_legacy_provider(flag),
                "{flag} should not need legacy"
            );
        }
    }

    #[test]
    fn diagnostics_naming_a_missing_algorithm_are_lacks_algorithm() {
        for stderr in [
            "enc: Unknown option or cipher: seed-ecb",
            "dgst: Unknown option or message digest: sha3-999",
            "Error setting cipher DES-ECB\nerror:0308010C:digital envelope routines::unsupported",
            "enc XTS ciphers not supported",
            "enc: unable to load provider legacy",
            "unknown cipher no-such-cipher",
        ] {
            assert_eq!(classify(stderr), Diagnostic::LacksAlgorithm, "{stderr}");
        }
    }

    #[test]
    fn diagnostics_about_the_invocation_are_bad_invocation() {
        for stderr in [
            "usage: dgst [-cdr] [-binary]",
            "pkeyutl: Unknown option: -bogus",
            "unknown option '-bogus'\nusage: pkeyutl [-asn1parse]",
            "enc: Unrecognized flag no-such-cipher",
            "Invalid command 'nosuchcmd'; type \"help\" for a list.",
            "openssl:Error: 'nosuchcmd' is an invalid command.",
            "enc: Multiple cipher or unknown options: -aes-128-ecb and -bogus",
        ] {
            assert_eq!(classify(stderr), Diagnostic::BadInvocation, "{stderr}");
        }
    }

    #[test]
    fn other_failures_are_neither() {
        assert_eq!(
            classify("hex string is too short, padding with zero bytes to length"),
            Diagnostic::Other
        );
        assert_eq!(classify(""), Diagnostic::Other);
    }

    #[test]
    fn only_enc_refusing_a_mode_survives_required() {
        assert!(refused_by_enc_command(
            "`openssl enc -aes-128-xts`: enc XTS ciphers not supported"
        ));
        assert!(!refused_by_enc_command(
            "`openssl dgst -sha3-256`: dgst: Unknown option or message digest: sha3-256"
        ));
        assert!(!refused_by_enc_command(
            "`openssl enc -seed-ecb`: Error setting cipher SEED-ECB"
        ));
    }

    #[test]
    fn a_known_good_invocation_yields_output_when_openssl_is_present() {
        // SHA-256("abc") is universally supported; whichever tool is present
        // must either be absent or produce exactly 32 bytes.
        match openssl(&["dgst", "-sha256", "-binary"], b"abc") {
            OpenSslOutcome::Absent => eprintln!("no openssl on PATH"),
            OpenSslOutcome::Output(bytes) => assert_eq!(bytes.len(), 32),
            OpenSslOutcome::Unsupported(reason) => panic!("sha256 rejected: {reason}"),
        }
    }

    #[test]
    fn a_nonsense_digest_is_reported_as_unsupported_not_output() {
        // LibreSSL answers with usage text alone, which is a bad invocation
        // by contract, so only an OpenSSL can take part in this experiment.
        if flavor() == Some(OpenSslFlavor::LibreSsl) {
            eprintln!("LibreSSL does not name the digest it lacks");
            return;
        }
        match openssl(&["dgst", "-no-such-digest-xyz", "-binary"], b"abc") {
            OpenSslOutcome::Absent => eprintln!("no openssl on PATH"),
            OpenSslOutcome::Unsupported(_) => {}
            OpenSslOutcome::Output(bytes) => {
                panic!("nonsense digest produced {} bytes", bytes.len())
            }
        }
    }
}
