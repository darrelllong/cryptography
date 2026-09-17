# Cryptography suggestions

> **Motto:** better that, better algorithms
>
> **Creed:** Experiment is asking God for peer review.

2026-09-16. Evidence and reviewed source identity: [AUDIT.md](AUDIT.md).
These are proposed changes; no implementation or speedup is claimed here.
Implement from papers, specifications and independently derived mathematics.
Preserve the exact hypotheses, representation and invariants beside the algorithm.
An experiment records its source/dependency identities, features, input, seed,
measurement rule and acceptance criterion before its validation run.

## 1. Fold GHASH from its field recurrence

The existing baseline prepares H*u^i and performs 128 masked selections per
block. Expanding `Y_i=(Y_(i−1) XOR X_i)*H` over b blocks gives

```text
Y_(i+b) = Y_i*H^b XOR sum_(j=1..b) X_(i+j)*H^(b-j+1).
```

Precompute a small number of H powers. Form the independent carryless
products, XOR their unreduced polynomials, then reduce once modulo
`u^128+u^7+u^2+u+1`. For 64-bit halves, Karatsuba needs three half-products:
`a0*b0`, `a1*b1`, and `(a0 XOR a1)*(b0 XOR b1)`, with the cross term recovered
by XOR. Derive the representation conversion and reduction from the polynomial.
The recurrence is [SP 800-38D §6.4](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf);
the batching identity above is its direct expansion.

**Experiment:** compare b=1,2,4,8 against an independently written bit-polynomial
oracle. Cover single basis bits, all-one values, reduction boundaries, partial
blocks and GHASH/POLYVAL conversion. Replay the GCM/GMAC/GCM-SIV answer files
and reject altered tags/AAD/ciphertexts. Compare total authenticated-operation
time over short and long messages, charging H-power setup, storage and wiping.
Keep a portable path and place any documented carryless-multiply intrinsics
behind the appropriate optional acceleration boundary. Reject a variant that
changes secret-dependent access or costs more on the intended workload.

## 2. Build constant-time curves from the field upward

Addresses **C1**. Choose one named prime curve and an explicit threat model.
Derive fixed-width field arithmetic, bounded carries, modular reduction and
constant-time selection. Keep operation counts and addresses independent of
secret values. Derive inversion with a fixed exponentiation chain or a
published constant-time inversion algorithm.

Then use complete point formulas only under their stated hypotheses;
[Renes–Costello–Batina](https://eprint.iacr.org/2015/1060) addresses prime-order
short-Weierstrass curves over fields of characteristic other than two or three.
Those hypotheses are not a general license to reuse the formulas for arbitrary
Edwards or binary curves. Preserve subgroup/key validation and scalar-range
checks independently of the formulas.

**Acceptance has three parts:** mathematical equivalence on exceptional and
ordinary inputs; functional agreement with published vectors; and generated-
code plus timing evidence for each supported compiler/target. Measure complete
key agreement and signing, including conversions and inversion. A negative
timing experiment bounds what that experiment detected; it is not a proof of
all execution paths. Keep variable-time APIs labeled until the whole path has
the stronger contract. General variable-time rump arithmetic remains useful
for public data and independent mathematical checks.

## 3. Make specification-to-test coverage inspectable

For each scheme maintain a compact mapping from specification/version/section
to the implementing operation, its input conditions and a meaningful test.
Separate valid-vector conformance from refusal of malformed inputs. An accepted
encoding needs canonical round-trip checks; a key import needs the mathematical
validation its profile requires, not merely a length check.

Prioritize these adversarial boundaries:

- Identity and invalid points, wrong subgroups where the scheme forbids them,
  explicit-domain limits and private/public disagreement.
- Zero, maximum and out-of-range scalars; broken or repeating randomness;
  retry limits that bound both random draws and expensive work.
- ML-KEM modulus/key-pair checks and implicit rejection; ML-DSA expanded-key
  consistency; NTRU prescribed sampling, zero cases and exact byte encodings.
- Authentication failure at every supported tag/nonce/message boundary;
  streaming splits, counter exhaustion and the returned buffer's contents.
- DER/BER/PEM length arithmetic, malformed nesting and allocations constrained
  before expensive arithmetic.

Retain answer-file source, parameter set, count and digest. Generate mathematical
constants and tables from their definitions where possible. A disagreement
between specification text and published vectors needs an explicit interpretation
and a discriminating test, never an unexplained numerical adjustment.
These rules apply equally to benchmark and fuzz harnesses.

**Experiment:** run the existing ignored cases and longer fuzz campaigns with
coverage/iteration records and minimized failing inputs. Fuzz targets must
assert the actual API contract: arbitrary corruption does not always imply
rejection for a non-authenticating primitive. Do not replace an independent
expected answer with an output freshly generated by the code under test.

## 4. Resolve the battery's statistical boundary with entropy

Addresses **C2**. Preserve the retained calibration corpus and reproduce the
counts before changing a statistic. Predeclare the target tail precision,
stream lengths, null sources, weak alternatives and a held-out validation set.
Decide whether the gap test needs different pooling, a better tail law or an
explicit simulated null. At threshold 0.001/7, 400,000 samples supply only
57.14 expected marginal rejections; uncertainty is material.

Keep Bonferroni only with individually valid null tail bounds, and report the
measured family rejection rate with an interval. A battery change must improve
calibration without silently losing power. Use entropy's finite-corpus interface
when available, with exact byte identity and projection. Repair its discrete-
null and error-result findings before using it as an independent verdict.
The scientific question is whether the statistic sees a specified deviation;
cryptographic security requires the scheme's own analysis.

## 5. Profile complete operations before rewriting arithmetic

Addresses **C4**. Establish fresh baselines for symmetric, RSA/EC and
post-quantum operations under recorded features. Profile stages separately:
setup, sampling, polynomial transforms/multiplication, reduction, hashing,
encoding, allocation and wiping. Preserve sampler distributions and deterministic
coin mapping: replacing either changes the algorithm, not just its speed.

Use paired, interleaved trials on an idle host, fixed message/parameter grids,
and an input corpus chosen before optimization. Report dispersion, CPU, memory
and complete-operation time. Stage wins that disappear after conversions or
setup do not establish a useful improvement. Regenerate tables and plots from
identified raw observations; do not use stale ratios as current targets.

Publish the dependency combination with every result. Rump's improvements
must run with `wipe` enabled here, even if factoring selects the opposite mode.
Check entropy's default adapters on the same bytes after cipher/DRBG changes.

## 6. Add standards by precise profiles, not by names alone

Potential extensions include Ed448, SLH-DSA, CTR_DRBG derivation-function and
prediction-resistance support, bit-oriented SHA-3, named finite-field groups,
and a specified ECIES KDF profile. Rank these by actual use after the audit
priorities. Pin a final specification, define accepted inputs and failure
behavior, and obtain published answer data before implementation. A FIPS
algorithm implementation is not by itself a validated cryptographic module.

| Boundary | Owner |
|---|---|
| Integer/field identities and generic arithmetic performance | [rump](../rump/SUGGESTIONS.md) |
| Scheme validation, timing, secret buffers and wire profiles | cryptography |
| Calibrated statistics and finite-corpus observations | [entropy](../entropy/SUGGESTIONS.md) |
| Shared performance methodology, with different feature profiles | all four repositories |
