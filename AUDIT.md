# Cryptography audit

> **Motto:** better that, better algorithms
>
> **Creed:** Experiment is asking God for peer review.

## Reviewed state

Reviewed 2026-09-16 on `aarch64-apple-darwin`, rustc/Cargo 1.93.1.
HEAD: `601c97bbd9049a4a2ba02e3b37d113f00d063e66`. The reviewed cryptography tree includes the uncommitted source and CI changes present at capture.
Tests ran against frozen sibling copies, with fresh build directories.
This is a targeted mathematical and cross-repository review, supported by the
runs below; it is not an assertion that every line or parameter regime was examined.
Only AUDIT.md and SUGGESTIONS.md are changed by this review.

| Sibling | Reviewed HEAD |
|---|---|
| entropy | `b52a72ddc63dc5ae2a41df0deb6c780fc990079d` |
| rump | `70d12839933c32569fdee5cb2bc1d5b4f3964f1a` |
| factoring | `5271af623135efbf7116d6e32e38ab8ac3d48eed` |

Reviewed-file manifest SHA-256: `59a8f526a3b3abed5613231a75e45076467078df6ff8b5935fbc86f9a62ae3e1` (567 files).
The manifest includes tracked files and nonignored untracked regular files,
except AUDIT.md and SUGGESTIONS.md. Sort repository-relative paths; emit
`SHA256(file)`, two spaces, path and newline; hash that UTF-8 manifest.
Hashes identify the captured working contents, including dirty files, rather
than treating HEAD alone as their identity. A later source change requires
revalidation of the affected findings and results.

## Assessment

The default and all-feature release suites pass against the reviewed rump.
The checked encoding, identity-key, key-pair, nonce-retry, authentication and
wiping regressions are exercised by those runs. No new primitive-level failure
was reproduced in this bounded pass. Current work concerns timing evidence,
statistical interpretation, reproducible companion builds and performance
measurement. These are separate questions from known-answer correctness.

## Findings and limits

### C1 — High: source-level timing discipline is not an end-to-end timing guarantee

**Source inspection.** [src/lib.rs](src/lib.rs) explicitly places public-key
operations in the variable-time category. Bare table-driven cipher types and
their `Ct` alternatives have different timing contracts. Rump wiping is enabled,
but generic multiprecision arithmetic still normalizes, allocates, divides and
branches according to values. A fixed scalar schedule cannot repair that layer.

[src/modes/ghash.rs](src/modes/ghash.rs) reads its 128 precomputed multiples in
public index order and masks each contribution. Its `black_box` barrier is
explicitly a compiler hint. Functional agreement and source inspection do not
establish the generated code's timing behavior on each supported target.

**Required evidence for a stronger claim:** fixed-width secret arithmetic;
generated-code inspection for the actual compiler and target; separate input-
class timing experiments; and a record of which complete operations satisfy
which contract. Continue to name the existing variable-time paths accurately.
No timing campaign or assembly audit was performed here.

### C2 — Medium: the statistical report's rare-tail claim needs qualification

**Fresh recount of retained data, not a new calibration campaign.**
[scripts/null_calibration/pvalues.csv.gz](scripts/null_calibration/pvalues.csv.gz)
has 400,000 rows, all at **5,638,480 bytes**. At the report's decision threshold
`0.001/7`, the counts are:

| Test | Rejections |
|---|---:|
| byte χ² | 46 |
| KS | 60 |
| serial | 58 |
| gap | 79 |
| permutation | 55 |
| Bartlett | 65 |
| runs | 61 |
| Any of the seven | 419 |

The marginal expectation at that threshold is 57.14. The gap count is about
2.9 binomial standard deviations above it. The family rate is 419/400,000
= 0.0010475, consistent with ordinary sampling uncertainty around 0.001;
this recount alone does not prove that the family target is violated.

The Bonferroni inequality remains valid under arbitrary dependence **if each
input p-value has the required null tail bound**. It does not confer that bound
on an approximate statistic. [R-REPORT.md](R-REPORT.md)'s unconditional bound
language is therefore stronger than the numerical evidence warrants. Calibrate
the gap statistic at the deciding threshold on held-out data and at each
supported stream length. A PASS from this battery is not evidence of key
secrecy, authentication security or unpredictability.

### C3 — Medium: evidence must name a complete sibling and feature combination

**Source inspection.** [Cargo.toml](Cargo.toml) takes rump by path and enables
`wipe`. [.github/workflows/ci.yml](.github/workflows/ci.yml) follows rump's main
in the cryptography jobs; entropy's own workflow pins specific companion
commits. Therefore identical cryptography HEADs need not mean identical builds,
and entropy's pinned green result is not automatically a result for this tree.

Keep the advancing integration jobs, and record the resolved sibling hashes,
features, toolchain and lockfile for every release/test report. Check the
consumer graph after changing a dependency's defaults. Entropy E6 shows why a
fresh no-default build is a distinct obligation even when the default suite is
green. The initial `--locked` command in the fresh cryptography copy required
`cargo generate-lockfile --offline`: the library does not track Cargo.lock.
That is a reproducibility detail, not a primitive failure.

### C4 — Medium: current speed comparisons lack a current matched baseline

**Source inspection.** [ASYMMETRIC.md](ASYMMETRIC.md),
[SYMMETRIC.md](SYMMETRIC.md) and [POSTQUANTUM.md](POSTQUANTUM.md) explicitly
mark performance figures stale. The source shows a concrete GHASH cost:
128 masked selections, reading 2,048 bytes of prepared multiples per 16-byte
input block. That is an operation count, not a measured bottleneck or a claimed
speedup for an alternative.

Re-measure the current implementation before choosing an optimization. Charge
key setup, allocations, wiping, authentication and short-message overhead.
Keep benchmark units, operand lengths, parameter sets and feature combinations
with each result. All suites here ran as correctness checks; their elapsed
times are not benchmark evidence.

## Mathematical and interface boundaries checked

| Boundary | Current implementation and evidence |
|---|---|
| GHASH/POLYVAL | Field `F2[u]/(u^128+u^7+u^2+u+1)` with GHASH bit i at integer bit 127−i; reduction mask `0xE1<<120` follows from that representation. GCM and GCM-SIV known-answer tests pass. |
| EC import and verification | Invalid points, identity keys, private/public consistency and explicit-domain validation have regressions in the passing suite. Apply each scheme's own validation rules. |
| Ed25519 | The implementation specifies RFC 8032's cofactored verification equation. Small-order acceptance is part of that chosen profile; it must not be confused with ECDSA's identity-key rule or a stricter application key-registration policy. |
| ML-KEM / ML-DSA | Tests cover external FIPS answer subsets, malformed encodings and expanded-key validation. A successful pair-wise test is not proof that arbitrary input keys were generated with the prescribed distribution. |
| NTRU | Release-mode `nist_kat` exercises all 100 entries in each of four committed submission answer files. Encoding/sampling conventions are explicit in the shared modules; a sampler optimization must preserve the prescribed coin-to-output map and distribution. |
| AEAD failure and wiping | Tag/ciphertext/AAD perturbation and wipe-behavior suites pass. Wiping is best effort over the buffers actually covered; this does not establish erasure of registers or every allocation copy. |

The GHASH equations and representation were checked against
[SP 800-38D §§6.3–6.4](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
The scheme rows above describe the reviewed source and executed regressions,
not a fresh clause-by-clause standards certification. Preserve precise
specification versions, sections, parameter sets and accepted-input profiles
in any future change.

## Verification

OpenSSL 3.6.4 was available through the configured Homebrew discovery path;
`CRYPTOGRAPHY_OPENSSL_REQUIRED=1` was set, so missing supported cross-checks
could not silently count as success. The helper's explicit exception for modes
unavailable through `openssl enc` remains part of that test contract.

```bash
cargo generate-lockfile --offline
CRYPTOGRAPHY_OPENSSL_REQUIRED=1 cargo test --offline --locked --release --all-targets
CRYPTOGRAPHY_OPENSSL_REQUIRED=1 cargo test --offline --locked --release --all-features --all-targets
cargo test --offline --locked --release --doc
```

Both all-target runs: **1,619 passed, 19 ignored**. Doctests: **57 passed**.
All features here means `ct_profile` and `arm-sha3` on this ARM64 host;
compilation alone does not show that a runtime-dispatched hardware branch was
taken. No ignored-test campaign, fuzz campaign, x86 build, MSRV run, companion
fast-crate build or timing certification was repeated in this pass.

The calibration recount is reproducible without regenerating random streams:

```python
import csv, gzip
names = ['byte_chisq', 'ks', 'serial', 'gap', 'permutation', 'bartlett', 'runs']
counts = dict.fromkeys(names + ['any'], 0)
rows = 0
with gzip.open('scripts/null_calibration/pvalues.csv.gz', 'rt') as stream:
    for row in csv.DictReader(stream):
        rows += 1
        values = [float(row[name]) for name in names]
        for name, value in zip(names, values):
            counts[name] += value < 0.001 / 7
        counts['any'] += min(values) < 0.001 / 7
print(rows, counts)
```

## Cross-repository contracts

| Owner | Contract and consumers |
|---|---|
| [rump](../rump/AUDIT.md) | Exact integer/field arithmetic and matrix identities; numerical approximations identify their domain and error. Used by all three companions. |
| [cryptography](../cryptography/AUDIT.md) | Scheme validation, entropy requirements, secret handling and timing properties. Enables rump's `wipe`; that feature does not make arithmetic constant-time. |
| [entropy](../entropy/AUDIT.md) | The statistic, input projection, null distribution and calibrated decision rule. A statistical PASS is not a security claim. |
| [factoring](../factoring/AUDIT.md) | Relation identities, matrix expansion and verified divisors. Uses entropy without default features; probable-prime leaves remain distinguished from proved primes. |

The links assume the repositories are sibling checkouts. Mathematical kernels
belong with their owner; consumers add their own preconditions and verify
results at the boundary. With cryptography enabled, Cargo unifies rump's
`wipe` feature across the dependency graph. Factoring alone was checked with
`cargo tree --offline --locked -e features -i rust-mp`: no `wipe` and no active
cryptography dependency.

Implementation work starts from papers, specifications and mathematical
derivations. A citation identifies the exact equation or algorithm, and the
implementation states its representation, hypotheses and invariants. Numerical
tables need a derivation or a precisely identified standard table. Published
answer files are test data; another implementation's source is not an
implementation reference. A passing round trip alone cannot validate two
functions that share the same mistake.
