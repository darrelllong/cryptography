# Cryptography audit — 2026-09-17

> **Motto:** better that, better algorithms
>
> **Creed:** Experiment is asking God for peer review.

## Scope and evidence

This review covers the captured sibling combination below on Apple M4 Pro,
`aarch64-apple-darwin`, rustc/Cargo 1.93.1, with separate Rust 1.87 checks.

| Repository | Captured HEAD |
|---|---|
| cryptography | `0242a217f1d79ab01bd43d4e5b79fc2a7be7a88f` |
| entropy | `63592e02ab50a494499a87c3abe0ab406ab01bf5` |
| rump | `ae7566b1b100239e1b511a9b05ff8229ea6613bd` |
| factoring | `732801274f7a27640b3616995b7503855a870e99` |

The reviewed-file manifest for this repository has SHA-256
`8f6afba1a69537ba101491e9fcebe03ff5defc6a15564a92334a9d0883815c63` (574 files).
[The manifest](review/2026-09-17/reviewed-files.sha256) contains sorted
`SHA256(file)  relative/path` lines; its own digest identifies the capture.
It covers tracked and nonignored regular files, excluding these two review
documents and the review artifacts added afterward. Entropy's final capture includes its new
seeding, sampling, thread-local and `CryptoRng` APIs through `63592e0`.

The review distinguishes reproduced results, source inspection, retained
measurements and proposed experiments. The files record current findings and
acceptance criteria; they do not implement the proposed changes. Implementation
references are papers, standards and mathematics. External libraries were called
through public APIs for comparison; their implementation source was not used.

## Assessment

The exercised primitive, encoding, malformed-input, wipe and cross-implementation
checks pass. The report validates complete probability vectors and identifies
its executable, input and analysis. The main remaining work is the placement and
contract of cryptographic RNG state, measured ChaCha throughput, and qualification
of security claims at complete-operation boundaries. This pass found no new
primitive arithmetic counterexample in cryptography; that is limited evidence,
not a claim that every construction or target is certified.

## Findings

### C1 — Medium: cryptographic RNG mechanisms have two owners

**Source inspection.** [src/cprng](src/cprng) owns CTR_DRBG, while entropy owns
Hash_DRBG, HMAC_DRBG and fast-key-erasure key evolution. Those mechanisms specify
cryptographic state transitions, request/reseed limits and erasure. Their core
algorithms belong beside the other cryptographic mechanisms. OS acquisition,
thread-local lifecycle, application sampling and battery adapters belong in
entropy.

Cryptography already has `Csprng`; RSA and ElGamal key generation require it.
Rump deliberately accepts quality-neutral bytes. Entropy now also has
`CryptoRng`, including a documented distinction between a secure construction
and a public test seed. The remaining issue is interoperable contracts and
ownership, not the absence of any cryptographic RNG type boundary.

Hash_DRBG's 440-bit modular additions currently pass through generic BigUint.
That is exact arithmetic, but its fixed width permits an independently derived
55-byte carry loop with bounded storage. Price that operation before changing it;
retain NIST request semantics separately from a buffered stream adapter.
[SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) specifies the
mechanisms and their state transitions.

### C2 — Medium: matched ChaCha20 throughput leaves substantial room

**Fresh black-box measurement through entropy's adapter.** The comparison at
[entropy's retained experiment](../entropy/review/2026-09-17/README.md) uses the
same zero key/nonce/counter and verifies 100,000 matching 64-bit outputs before
timing. Median process-CPU throughput over seven measured rounds:

| Path | Bulk MiB/s | Scalar u64 MiB/s |
|---|---:|---:|
| This crate through entropy `ChaCha20Rng` | 719.4 | 753.0 |
| `chacha20` 0.10.2, 20-round RNG public API | 1,564.3 | 1,359.9 |
| `rand_chacha` 0.10.0, 20-round public API | 869.4 | 809.0 |

The first matched bulk ratio is 2.17×. This compares complete generator paths;
it does not isolate the permutation, prove a particular vector backend executed,
or equalize erasure policy. The host was heavily loaded; both wall and process
CPU times are retained, and these are exploratory single-host results.

The current ChaCha implementation computes blocks from scalar state and its
entropy adapter serves buffered words. Prioritize a direct bulk path and batched
independent counters. Derive any vector kernel from the quarter-round equations
and test it against independently constructed vectors. The IETF counter/nonce
layout and counter-exhaustion behavior must remain explicit.
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) supplies the specification and
known answers. Reduced rounds would change the security/performance comparison;
they are not a transparent optimization of ChaCha20.

### C3 — Medium: timing and state-erasure claims require target-specific evidence

**Source inspection; no fresh timing campaign.** The crate correctly distinguishes
variable-time public-key primitives, table-driven symmetric implementations and
`Ct` variants. Rump's erasure feature does not make generic multiprecision
arithmetic constant-time. The ignored equality probe's fastest samples from two
mismatch positions can detect a gross early exit but do not qualify all secret
classes or complete operations.

The new fast-key-erasure state in entropy wipes served bytes and replaces the
key on refill. It warrants review of compiler-produced copies, caller seed
copies, panic/error paths, actual child-process reseeding and concurrent use.
The exercised unit tests simulate PID changes; this review did not run a real
fork campaign or establish physical-memory erasure of every compiler temporary.
Keep the construction's mathematical claim distinct from what a volatile write
and a functional test establish on a particular build.

### C4 — Medium: statistical reports have a bounded interpretation

**Source inspection and retained evidence.**
[scripts/cipher_randomness.R](scripts/cipher_randomness.R) now requires the
expected named, finite [0,1] results, rejects invalid/incomplete rows, builds the
executable, fingerprints output/input/analysis and tests cache acceptance.
Its fresh self-test passes. These checks make a retained experiment identifiable;
they do not supply the null law of every statistic or establish confidentiality.

The retained 400,000-stream campaign at 5,638,480 bytes records 419 family
rejections, a rate of 0.0010475 at nominal family alpha 0.001. That rate is
compatible with sampling uncertainty. It applies to its recorded length, pooling
and decision rule, not arbitrary future inputs or tuned thresholds. No new full
ciphertext battery or null calibration was generated in this pass.

### C5 — Contract boundary: raw ElGamal is a primitive

The [ElGamal API](src/public_key/elgamal.rs) explicitly states its raw message
contract and malleability. For an order-q subgroup, `delta = m*b^k` gives
`delta^q = m^q mod p`, revealing the message's coset for unrestricted nonzero m.
This is an algebraic limitation of that interface, not a round-trip failure.
Keep byte encoding separate from a specified authenticated hybrid construction;
changing comments or rejecting zero cannot create semantic security.

### C6 — Medium: dense NTRU profile parameters have incomplete documentary support

**Source inspection.** [src/public_key/ntru_ees_core.rs](src/public_key/ntru_ees_core.rs)
distinguishes the public EESS specification, the parameter paper and measured
interoperability. It explicitly leaves the dense sets' `minCallsR` and
`minCallsMask` values unconfirmed. Those precomputation choices do not change the
known-answer outputs, so passing vectors cannot identify or validate them.
Several other profile fields are pinned by interoperability data rather than a
retrieved complete normative parameter table.

Keep algorithm correctness, interoperability and conformance to a named parameter
profile separate. Establish a primary-document or mathematical derivation for
each field; where that evidence is unavailable, state the implemented profile
precisely without claiming complete standards conformance. The wire framing is
also an interoperability choice where the specification leaves format open.
This review did not retrieve the complete IEEE/ANSI parameter tables or reproduce
a wrong NTRU ciphertext from these choices.

## Fresh verification

| Check | Result |
|---|---|
| Release, locked/offline, all targets | 1,621 passed; 19 ignored |
| Same, all features (`ct_profile`, `arm-sha3`) | 1,621 passed; 19 ignored |
| Release doctests | 57 passed |
| Rust 1.87, locked/offline, all-target check | Passed |
| `Rscript scripts/cipher_randomness.R --self-test` | Passed |
| Matched ChaCha20 output comparison | 100,000 u64 outputs identical across three paths |

Both release suites set `CRYPTOGRAPHY_OPENSSL_REQUIRED=1`; the test helper's
specified exceptions for modes unavailable through `openssl enc` still apply.
These are functional checks on ARM64. No new full fuzz campaign, ignored-test
campaign, assembly/timing campaign, Linux/x86 run or PQ standards certification
was performed. [Retained validation](review/2026-09-17/validation.json) records
commands and log digests; test durations are not performance measurements.

## Cross-repository ownership

Keep the four repositories, with a focused boundary refactor. The desired graph
is `cryptography → rump`, `entropy → cryptography` when crypto generators are
enabled, and `factoring → rump + entropy` with only the RNG/statistics features
it needs. Rump must not depend on either consumer.

| Owner | Keep here | Boundary change |
|---|---|---|
| rump | BigInt, modular arithmetic, primality, exact polynomial/finite-field/GF(2)/lattice support, caller-driven BigInt sampling | Move floating probability kernels out; retain reusable arithmetic without factoring policy or OS entropy |
| cryptography | Ciphers, hashes, authenticated schemes, DRBG mechanisms, cryptographic state evolution and erasure | Own Hash_DRBG, HMAC_DRBG and fast-key-erasure cores; entropy supplies their adapters |
| entropy | Noncryptographic PRNGs, OS seeding, sampling, stream views, thread-local access, probability functions and test batteries | Separate application RNG, statistics and batteries by features; make FFT/battery dependencies optional |
| factoring | Rho/ECM/QS/GNFS orchestration, relation/cofactor policy, polynomial selection and size/cost dispatch | Reuse native modular arithmetic; keep schedule, graph forecasting and algorithm selection here |

Generic exact algebra in rump is supporting mathematics, not a reason to move
QS/GNFS policy there. `ln_gamma`, incomplete beta and Student quantiles are
floating statistical functions; entropy already owns most probability kernels
and factoring already depends on entropy. Move them in a coordinated API release
with reference fixtures. A rump forwarding wrapper that calls entropy would
create a dependency cycle and is unsuitable.

Preserve the distinction between rump's quality-neutral `RandomSource`,
cryptography's byte-oriented `Csprng`, and entropy's generator/`CryptoRng`
interfaces. Add explicit adapters with documented security and byte-stream
contracts; never blanket-implement a cryptographic contract for every test RNG.
A marker describes a construction, not the entropy in a caller-supplied seed.

Cryptography enables rump's additive `wipe` feature. Entropy default inherits it;
entropy minimal and standalone factoring do not. Record the resolved graph in
benchmarks: compiling factoring alongside a consumer that enables wipe can change
its arithmetic costs. Separate processes/packages may be needed when measuring
that configuration. Optional features should remove unwanted dependencies, not
silently weaken a cryptographic build's erasure contract.

## Standard for accepting changes

Derive the formula and state its domain, representation and invariant. Retain
published known answers, independent mathematical identities and reproducible
coefficient/table generation. Test boundary strata and algorithm switches as
well as ordinary inputs. Source comments should explain the invariant, assumption
or non-obvious choice and cite the relevant paper section when useful.

Use paired measurements with fixed inputs, seeds, compiler, target, features and
sibling revisions. Record wall time, total process-tree CPU, memory and work
counters. Separate the cost of setup, steady-state work and teardown, then report
the complete operation too. Statistical acceptance, semantic security, exact
factorization and performance are separate claims with separate evidence.
