# Cryptography audit

> **Motto:** better that, better algorithms
>
> **Creed:** Experiment is asking God for peer review.

## Reviewed state and method

2026-09-16 PDT / 2026-09-17 UTC. Frozen sibling checkouts on
`aarch64-apple-darwin`, rustc/Cargo 1.93.1; separate Rust 1.87 checks.

| Repository | HEAD at capture |
|---|---|
| cryptography | `aa865da77502306f544b7031f65eaf3f7b7960b2` |
| entropy | `de1bd2d061eea43fe1fca291edae346315b85983` |
| rump | `66651ab0c82a21929c52da92823fad930766fef9` |
| factoring | `d594060dc824a4f2c3a0800fdeb86c739dce7e71` |

This repository's reviewed-file manifest SHA-256 is
`0e1c714db3d0e27250ffb05340a6ef29462e0d5aa2de9b897b535620ab6fee42` (572 files).
The manifest covers tracked and nonignored untracked regular files, excluding
AUDIT.md and SUGGESTIONS.md: sort relative paths, emit `SHA256(file)`, two
spaces, path and newline, then SHA-256 the UTF-8 manifest. It identifies working
contents as well as commits. Tests used fresh build directories in the frozen
copies. Later edits require checking which evidence still applies.

This review combines source inspection, mathematical identities, the release
suites, and focused boundary experiments. Reproduced failures, inspected risks,
retained measurements and proposed experiments are distinguished below. Coverage
is stated explicitly; passing suites do not establish every input domain,
platform, timing property or statistical null law. This review changes the two
review documents only. Diagnostic code ran in separate scratch copies.

## Assessment

The default and all-feature release suites pass, including the required
OpenSSL cross-checks. This pass concentrated on the changed ElGamal group
validation, the reporting path, sibling composition, and the boundary between
functional correctness and security claims. The reproduced report defects can
produce a PASS without valid complete measurements. Raw ElGamal's message-space
limitation is demonstrated separately; it is not a failed round-trip equation.

## Findings

### C1 — High: the randomness report can declare PASS with no valid p-values

**Reproduced from the current function.**
[scripts/cipher_randomness.R](scripts/cipher_randomness.R), `verdict`, first
removes missing values and then applies `all(p >= ALPHA_BONF)`.

| Supplied seven-test vector | Returned pass | Returned minimum |
|---|---|---|
| Seven NA values | TRUE | +Inf |
| One 0.5 and six NA values | TRUE | 0.5 |
| Seven values of 2 | TRUE | 2 |
| Seven +Inf values | TRUE | +Inf |

The first case follows from `all(logical(0))` being true. These are fresh helper
probes, not a claim that every retained report row had this condition. The
report uses the returned Boolean to print both per-cipher PASS and “All ciphers
pass” statements, so result validation must precede that decision.

Require the exact expected set of seven named, scalar, finite probabilities in
[0,1]. Missing, duplicate, nonfinite or out-of-range results must remain explicit
errors through caching, the summary and process exit. A statistical rejection
and an incomplete measurement are distinct outcomes. Entropy's R report has the
same class of gap ([E2](../entropy/AUDIT.md)), although its Rust result
constructors already validate probabilities.

### C2 — Medium: retained ciphertext and analysis caches do not identify the implementation tested

**Source inspection.** The same script's `encrypt` accepts any nonempty
`cipher_outputs/<name>.bin` without invoking `cipher_encrypt`. `run_battery`
accepts an analysis cache when its modification time is at least the
ciphertext's and its stored battery version is current. Neither condition
identifies the executable, sibling sources, feature selection, input digest,
key/nonce experiment identity or analysis-script contents. The report is dated
when rendered, and no build is performed by this script.

A changed cipher can therefore receive a newly rendered report based entirely
on retained output from a different executable. Cached data is useful when
presented as a retained experiment with its own identity; it cannot establish
current-tree behavior without that identity. Build the requested executable,
record its digest and the source graph, and key or label the retained experiment
accordingly. A changed plaintext must also invalidate a current-input claim.

### C3 — Medium: raw ElGamal byte encryption discloses message-class information

**Derived and reproduced; security contract.**
[src/public_key/elgamal.rs](src/public_key/elgamal.rs) accepts every integer
`1 <= m < p`. In an order-q subgroup, `delta = m*b^k` implies
`delta^q = m^q mod p`, which publicly identifies the message's subgroup coset.
Rejecting zero and small-order ciphertext elements does not hide that class.

For the safe-prime primitive-root profile, write `chi(x)=x^((p-1)/2) mod p`.
The public key b reveals the parity of a through chi(b), and gamma reveals
that of k. Thus:

```text
if chi(b) = 1:  chi(m) = chi(delta)
otherwise:     chi(m) = chi(delta) * chi(gamma) mod p
```

A public-API experiment with `p=23, g=5, a=7`, all 22 nonzero messages and all
20 accepted nonces recovered the correct character in **440/440 cases**.
Only public key/ciphertext values were used for recovery. This is an exact
algebraic witness; it does not depend on solving a small discrete logarithm or
on timing. Arbitrary large safe primes have the same identity.

The module already labels this as textbook/raw encryption and asks callers to
supply a hybrid construction or padding. Keep that scope prominent on the byte
entry points and supply a precisely specified authenticated hybrid path if the
library intends to offer message confidentiality. Raw multiplicative ElGamal
also remains malleable. The group algorithm and semantic-security distinction
are discussed in [HAC §§8.4 and 8.7](https://cacr.uwaterloo.ca/hac/about/chap8.pdf).
No new primitive arithmetic failure is asserted by this finding.

### C4 — Medium: timing evidence supports a narrower claim than end-to-end constant time

**Source inspection; no new timing campaign.** [src/lib.rs](src/lib.rs)
correctly labels the generic public-key operations variable-time and distinguishes
table-driven symmetric types from their `Ct` variants. Rump wiping is enabled
through the dependency graph; normalization, allocation and generic arithmetic
remain value dependent.

[src/ct.rs](src/ct.rs)'s ignored equality timing test compares the fastest of
101 samples from two mismatch positions. That is a useful check for a gross
early-exit regression; it cannot rule out smaller distributional differences,
other secret classes, compiler changes or complete-operation leakage. Its name
and a passing result must not become a certification of every API. Preserve
source-level discipline, then qualify generated code and measured operations on
the actual targets separately.

### C5 — Medium: statistical and performance claims need matching evidence domains

**Retained statistical evidence; inspected performance limits.**
[R-REPORT.md](R-REPORT.md) now describes the family threshold as nominal unless
each marginal tail is valid. A fresh recount of the retained 400,000 null rows
at 5,638,480 bytes gives the following counts below `0.001/7`:

| byte chi-square | KS | serial | gap | permutation | Bartlett | runs | any |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 46 | 60 | 58 | 79 | 55 | 65 | 61 | 419 |

The family rate 0.0010475 is compatible with ordinary sampling uncertainty
around 0.001; these rows do not prove an excess family error. The gap marginal
and any new stream length or tuned pooling rule require held-out validation at
the deciding threshold. No new null streams were generated in this review.

The comparison tables in [SYMMETRIC.md](SYMMETRIC.md),
[ASYMMETRIC.md](ASYMMETRIC.md) and [POSTQUANTUM.md](POSTQUANTUM.md) identify stale
performance data. Current correctness-suite durations are not replacement
benchmarks. GHASH's 128 masked selections per block are an operation count;
they do not establish which phase dominates a complete AEAD call.

## Mathematical and implementation boundaries checked

| Boundary | Evidence and remaining limit |
|---|---|
| ElGamal group validation | Safe-prime primitive-root and prime-order-subgroup profiles are explicit; degenerate secret/nonce and ciphertext membership checks are covered by the current suite. Message-space secrecy is a separate contract, C3. |
| AEAD | Known answers, tag/AAD/ciphertext perturbations and wipe regressions pass; nonce and per-key usage requirements remain scheme-specific. |
| EC and signature imports | The exercised invalid-point, identity-key and private/public consistency regressions pass. RFC 8032 cofactored verification is a chosen profile, not every application's key-registration policy. |
| ML-KEM, ML-DSA and NTRU | Included known-answer, malformed-input and key-validation regressions pass. This is not a fresh clause-by-clause standards review or the entire ignored campaign. |
| Randomness | CSPRNG/DRBG state is deterministic after seeding. Ciphertext uniformity cannot establish seed entropy, unpredictability, confidentiality or authenticity. |
| Dependency graph | Cryptography enables rump wipe; both this crate and entropy default pass with the captured rump. |

## Fresh verification

OpenSSL 3.6.4 was discovered through the Homebrew path.
`CRYPTOGRAPHY_OPENSSL_REQUIRED=1` was set on both release runs. The helper's
explicit exception for modes unavailable through `openssl enc` remains part of
that test contract.

| Check | Result |
|---|---|
| `cargo test --offline --locked --release --all-targets` | 1,620 passed, 19 ignored |
| Same `--all-features` | 1,620 passed, 19 ignored |
| `cargo test --offline --locked --release --doc` | 57 passed |
| `cargo +1.87 check --offline --locked --all-targets` | Passed |
| Current R `verdict` with incomplete/invalid vectors | C1 reproduced |
| Public ElGamal character-recovery experiment | 440/440 exact matches |
| Recount of retained null CSV | C5 table reproduced |

All features means `ct_profile` and `arm-sha3` on this ARM64 host. These runs
are functional evidence, not a new assembly/timing review. No fresh full fuzz
campaign, ignored-test campaign, x86/Linux build or companion-fast-crate benchmark
was run. Existing campaign and remote-host reports remain separately dated
records; their results are not added to the fresh counts above.

## Cross-repository contracts

| Owner | Obligation at the boundary |
|---|---|
| [rump](../rump/AUDIT.md) | Exact arithmetic and matrix identities; numerical domains, error and convergence; explicit search completion. |
| [cryptography](../cryptography/AUDIT.md) | Scheme-specific validation, randomness requirements, confidentiality/authentication profiles, timing and secret handling. |
| [entropy](../entropy/AUDIT.md) | Explicit input view, statistic, null law, calibrated decision and complete report; a statistical pass is not a security claim. |
| [factoring](../factoring/AUDIT.md) | Exact relation identities and dependency expansion, verified proper divisors, measured selection cost; probable-prime leaves are not proofs. |

The links assume sibling checkouts. Cryptography enables rump's additive `wipe`
feature. Entropy default inherits it; entropy minimal and factoring alone do
not. The same rump version string can therefore describe different timing and
allocation costs. Record the resolved dependency revisions, lockfiles,
features, compiler and target alongside results.

Implementations start from papers, specifications and mathematical derivations.
State the equation, representation, hypotheses and invariant. Derive numerical
tables reproducibly and separate approximation error from floating evaluation.
Use published answer files and independently constructed oracles for checks;
another implementation's source is not an implementation reference. A round
trip alone cannot detect a shared error in its two halves.
