# Cryptography suggestions — 2026-09-17

> **Motto:** better that, better algorithms
>
> **Creed:** Experiment is asking God for peer review.

Current evidence and limitations are in [AUDIT.md](AUDIT.md). Each proposal below
has an acceptance experiment. Predicted improvements are not measured speedups.

## Priorities

| Order | Work | Acceptance evidence |
|---|---|---|
| 1 | Consolidate cryptographic generator cores | Unchanged NIST vectors and stream contracts; no dependency cycle |
| 2 | Bulk and batched ChaCha20 | Matched outputs at every block/tail boundary; paired complete-path gains |
| 3 | Review fast-key erasure and fallible seeding together | Explicit compromise model; tested seed/read/reseed/fork failures |
| 4 | Qualify complete operations on each target | Functional vectors, generated-code review and adequate timing distributions |
| 5 | Retain identifiable statistical/performance experiments | Exact build/input/decision identity and honest scope |

## Own mechanisms; let entropy own access

Move Hash_DRBG, HMAC_DRBG and the deterministic fast-key-erasure core from entropy
into cryptography. Keep entropy's wrappers, OS source and thread-local policy in
entropy. Preserve published `Generate` request boundaries: fetching 1 byte twice
through a buffer is not automatically the same state transition as two NIST
Generate requests. Test instantiation, reseeding, request limits, additional
input, partial fills and complete state updates against the specification.

Use the existing `Csprng` interface and named adapters from entropy's secure
generators. Give fallible OS access an explicit error path. A caller should be
able to distinguish a seeded deterministic generator from an OS operation that
can fail. Do not let blanket adapters from `Rng` admit constant/test generators
into security-sensitive APIs.

`Seedable::seed_from_u64` expands at most 64 bits of seed uncertainty even when
the resulting state/key is 256 bits. Label it for deterministic experiments;
cryptographic examples should use successful OS seeding or sufficiently entropic
secret seed material. Neither a marker nor SplitMix expansion manufactures
entropy. Include compile-fail examples for weak-generator substitution and
runtime tests for unsuccessful OS seeding/reseeding.

Replace Hash_DRBG's fixed-width BigUint additions only after a measurement shows
useful savings. Derive addition modulo 2^440 directly, test carry chains across
all 55 bytes and preserve wiping of every state and scratch buffer. Keep this
specialized cryptographic state operation here; it does not belong in factoring.

## Improve the shared ChaCha engine

Expose a bulk keystream path that consumes entire blocks without repeated
per-word adapter work. Batch independent counter blocks, then evaluate scalar
interleaving and target-specific vector arithmetic derived from
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439). Retain a simple specification
oracle and known answers; inspect generated code for the supported targets.

Measure one word, 16/64/480/512 bytes, 4 KiB and long streams. Include unaligned
buffers, every short tail, mixed access widths, counter exhaustion, construction
and erasure. Price ordinary ChaCha20 and fast-key-erasure separately, since
reserved rekey bytes and wiping are real work. Require gains in the consumers,
not just a permutation-only loop. Compare 20 rounds with 20 rounds; offer a
reduced-round RNG only as a separately specified construction with an explicit
security rationale.

## Qualify security claims at the operation boundary

Keep known-answer, malformed-input and import consistency checks. Add a targeted
matrix for the actual supported compiler/CPU paths before extending constant-time
claims. Timing experiments should compare distributions across relevant secret
classes and include whole AEAD/signature/key operations, with setup separated
and then included. A nonsignificant timing test is evidence at its sensitivity,
not proof of constant time. The methodology in
[Reparaz, Balasch and Verbauwhede](https://eprint.iacr.org/2016/1123) is a useful
experimental reference.

For fast-key erasure, state when compromise occurs and what survives: current
key, unserved output, caller copies, forks and reseeding failures. Test real fork
behavior on supported Unix systems as well as injected PID changes. Measure the
PID/TLS check cost and add a bulk access path that amortizes it without serving
bytes before the reseed decision.

A higher-level ElGamal interface requires a specified authenticated construction,
encoding, KDF/domain separation and rejection behavior. Retain the raw primitive
for callers who explicitly need it. A ciphertext randomness report is not the
acceptance test for message confidentiality or authentication.

## Make every parameter profile reviewable from documents and equations

For dense NTRU, retain a per-field table with value, meaning, exact source section
or derivation, and validating experiment. Resolve `minCallsR`/`minCallsMask`
against authoritative parameter material or define the chosen precomputation
policy explicitly. Output agreement cannot determine a parameter that leaves
outputs unchanged. Mark custom wire-format choices and validation strengthenings
as part of the implemented profile, with interoperability tests and a mathematical
reason for each rejection rule.

Across algorithms, known-answer files may be published data or outputs from an
independent executable. Keep that role distinct from the implementation's source
of equations and constants. A traceability review should inspect those records;
a keyword scan or a passing round trip cannot certify independent derivation of
every line.

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
