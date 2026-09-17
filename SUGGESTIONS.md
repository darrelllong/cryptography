# Cryptography suggestions

> **Motto:** better that, better algorithms
>
> **Creed:** Experiment is asking God for peer review.

2026-09-16 PDT / 2026-09-17 UTC. Current findings, scope and measured evidence:
[AUDIT.md](AUDIT.md). These are proposals, with their acceptance experiments;
no implementation or speedup is claimed by this document. Work from the named
papers, specifications and independently derived mathematics.

## Priorities

| Order | Work | Required outcome |
|---|---|---|
| 1 | Report completeness and probability validation | Missing/invalid measurements cannot become PASS |
| 2 | Identified, reproducible retained experiments | A report states exactly which executable, input and analysis it describes |
| 3 | Explicit raw-versus-hybrid encryption contracts | Message-security claims match a specified construction and message space |
| 4 | Timing qualification and targeted fuzzing | Evidence tied to the complete operation, compiler, target and accepted-input profile |
| 5 | Matched algorithm experiments | Exact answers preserved; lower complete cost on held-out workloads |

## Make measurement results dependable

For **C1**, validate all seven expected names and scalar probabilities before
constructing a decision. Carry complete/invalid/unsupported status through RDS,
markdown and exit codes. Preserve failure reasons instead of dropping NA values.
Use the same boundary fixtures as entropy: no results, a missing result, a
nonfinite value, values outside [0,1], duplicated names and a failed producer.
A statistical failure is a scored result; a broken measurement is not.

For **C2**, create an experiment manifest containing source and sibling hashes,
features, compiler, executable digest, input digest/length, output digest,
analysis-script digest and the statistical rule/table identity. Retained
ciphertext remains tied to the manifest that produced it. A re-render can have
its own rendering date while keeping the measurement date and identity.

Build before producing a current-tree report. Test invalidation with a changed
executable, changed input, changed analysis and interrupted output write. Write
artifacts atomically, and check expected lengths. Preserve useful retained
experiments without presenting their cached outputs as new execution evidence.

For **C5**, run held-out rare-tail validation at the actual Bonferroni threshold
and supported lengths. Freeze tuning before that run. Report uncertainty for
marginal and whole-battery rates and distinguish it from a theorem conditional
on valid input p-values. Coordinate statistical kernels and fixtures with entropy.

## A secure message API needs a specified composition

For **C3**, keep raw group operations explicitly low-level. Arbitrary-byte
messages multiplied into a subgroup reveal their coset; adding unspecified
padding does not establish semantic or chosen-ciphertext security.

If a message API is desired, select a complete published KEM/KDF/AEAD composition
with domain separation, context binding, key/nonce schedules, validation rules
and published vectors. [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
is one precise hybrid specification to evaluate; adopting it is a separate
implementation task, not a claim that the current raw ElGamal type implements it.

Preserve an algebraic regression demonstrating the raw API's message-class
behavior so documentation cannot accidentally promise more. For a chosen hybrid
construction, test corrupted encapsulations, ciphertext, AAD/context, invalid
public keys, secret-dependent failure behavior and exact byte framing. Review
its full threat model and randomness requirements from the specification.

## Timing and secret handling

For **C4**, start at fixed-width field arithmetic if adding constant-time public-key
operations. A fixed scalar loop over normalized BigUint values cannot establish
the property. Keep the existing variable-time APIs accurately named while
qualifying any new path at the field, group and complete-operation levels.

Inspect generated code for the supported compiler/target pairs. Use independent
input-class timing experiments with a predeclared measurement rule, matched
lengths, randomized/interleaved classes and reported uncertainty. A minimum-time
ratio detects some gross regressions but does not replace distributional tests.
Keep wiping, functional equality and timing as separate claims.

Focus fresh fuzz campaigns on accepted-input boundaries and composition: all
parser length/count fields, explicit domain parameters, key-pair consistency,
nonce/counter exhaustion, authentication failure and failure-buffer contents.
Use independent standard vectors and mathematical identities in addition to
round trips. Record the exact corpus, target, duration, features and revisions.

## Algorithm experiments worth pricing

GHASH/POLYVAL: derive folded field accumulation and carryless Karatsuba from the
specified bit representation and reduction polynomial. Check multiplication
against an independently written bit-polynomial oracle before measuring GCM and
GCM-SIV. Include short messages, AAD, key setup, allocation and authentication.
Do not infer a speedup from removing a table scan alone.

Prime-field curves: measure fixed-width arithmetic and prepared contexts at
complete scalar-multiplication/signature/KEM boundaries. NTT-based schemes:
measure transforms, reductions and sampling separately, preserving exact
coin-to-output maps and prescribed distributions. An implementation matching
known answers must still enforce the required input and key-distribution rules.

Use paired interleaved trials on an idle host, with fresh held-out inputs and
both setup-inclusive and steady-state numbers. Retain negative results. Replace
stale tables only with measurements of the exact qualified implementation.
