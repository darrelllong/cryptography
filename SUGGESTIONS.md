# Suggestions for cryptography

Revalidated 2026-09-11 against the paused `342989a` working tree and frozen
rump `d30a7bcc`; source fingerprints and checks are in AUDIT.md. This is a
current work queue. The standard-format implementations, plain Lucas adoption,
EES canonical-bit check and resolved rump API gaps have been removed from it.
Keep implementations derived from published algorithms and specifications;
reference code is not a source of replacement code.

## Owner rulings, 2026-09-11 afternoon

The owner ruled on this queue after it was written. EC public keys refuse the
identity; cryptography turns wiping on; encapsulation never creates zero
polynomials; decoders do what each RFC says, with `_der` methods strict and BER
receivers beside them; Ed25519 follows RFC 8032 exactly; and ML-KEM's pair-wise
test is not skipped. Items 1, 2, 3, 5 and 6 below are done in the working tree
under those rulings. Where an item recommends otherwise, such as opt-in wiping,
a strict Ed25519 profile or an optional pair-wise test, the ruling governs.
Item 4, fuzz entry points for the standard parsers, is still open.

## First: make the contracts agree

1. **Reject identity public keys in legacy wire import (C5).** Use the existing
   `is_valid_public_point` at ECDSA/ECDH public-key boundaries. Preserve identity
   support in low-level group arithmetic. Add the audit's public-data ECDSA
   forgery as a negative regression, valid-key controls and cross-entry-point
   tests. The SPKI validator already enforces the required invariant.
2. **Honor opt-in automatic wiping (C1).** Gate crate-owned automatic state
   and temporary scrubbing through the explicit cryptography feature and keep
   rump forwarding there. Update the live-buffer helper tests, automatic-call
   audit and feature documentation together. Specify explicit-erasure API
   behavior separately. Compare outputs with and without the feature; do not
   attempt to validate erasure by reading freed memory. Measure costs only
   after recording the actual feature graph.
3. **Keep the recorded NTRU rejection policy and repair the sender (C2).**
   Add a checked deterministic coin-to-encapsulation boundary that can refuse
   excluded r/m values before returning a ciphertext/key pair. Define how the
   public random-source API reports failure or retries, including exhaustion
   on a broken source. A conditioned sampler is a change to the specified
   procedure and needs explicit distribution/interoperability analysis.
   An unbounded secret-dependent retry loop is not a free constant-time fix.
   Pin r=0 independently in all four sets, and m=0 independently for HRSS,
   alongside normal KATs and unchanged invalid-ciphertext implicit rejection.
4. **Exercise the implemented standard parsers (C4).** Add fuzz entry points
   for SPKI/PKCS #8 DER and PEM with the existing RFC vectors as corpus seeds.
   Include all supported parameter sets, optional public keys and attributes,
   absent versus NULL parameters, seed/expanded mismatches, truncation and
   trailing bytes. Check accepted encodings round-trip semantically and enforce
   each import profile's consistency guarantees. Expanded-only ML-KEM currently
   lacks the optional pairwise test; do not silently assume structural decoding
   certifies an operational key pair. Keep crate formats as the recorded default.
5. **Specify import profiles (C6 and audit import limits).** Keep DER entry
   points strict; add a bounded BER-aware receiver if claiming the full RFC 5958
   receiver profile. Preserve each algorithm's inner encoding requirements.
   Name Ed25519's strict subgroup policy and test its boundary separately from
   RFC 8032 decoding. A broader profile needs a complete equation/point review.
   For ML-KEM, distinguish ordinary structural import from optional validated
   import with pairwise checking, preserving existing seed/hash consistency
   checks. Published malformed-key vectors already demonstrate the difference.
6. **Account for PEM output growth when erasure is enabled (C7).** Compute the
   exact required capacity before placing secret text in the output, or write
   base64 directly to a single final allocation. For this encoder, if b is
   `4*ceil(blob_bytes/3)` and L is the label length, the output length is
   `32+2*L+b+ceil(b/64)`. Use checked integer arithmetic and verify empty input,
   64-column boundaries and large keys. Measure allocations with controlled
   test material; do not inspect freed secret memory. This reduces copies and
   respects the opt-in wiping policy rather than mandating default scrubbing.

## Arithmetic direction: folded GHASH with independently derived multiplication

The current `src/modes/ghash.rs` precomputes the 128 values `H*u^i`, then
performs 128 masked-XOR selections per input block. That is a clear constant-
operation baseline, but it still reads about 2 KiB of key-dependent table
contents per 16-byte block. The table addresses are sequential, not secret-
indexed. The previous 0.31× throughput report is historical; establish a new
baseline before attributing current costs to it.

Exploit the polynomial recurrence, not another implementation's layout. From
[NIST SP 800-38D §6.4](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),
expanding b steps gives the exact identity

```text
Y_(i+b) = Y_i*H^b XOR sum_(j=1..b) X_(i+j)*H^(b-j+1).
```

Precompute a small set of H powers, perform the independent carryless
products, XOR their unreduced polynomials, and reduce the aggregate once
modulo `u^128+u^7+u^2+u+1`. For 64-bit polynomial halves, Karatsuba replaces
four carryless half-products with three. Derive the bit order and reduction
from the displayed polynomial; the GHASH/POLYVAL byte reversal is already
specified in RFC 8452. This identity opens parallel work and shared reduction;
it does not establish a speedup with the existing bit-serial multiply.

Compare b=1,2,4,8, short messages and long streams, charging precomputation,
partial blocks and register/memory pressure. Use documented processor
carryless-multiply operations in the appropriate optional fast path, with an
independently derived portable baseline. Hardware support is not itself a
mathematical contribution. Validate all products against the simple field
oracle, then GCM/GMAC/GCM-SIV vectors and chunk boundaries. Preserve tag
verification and do not emit unauthenticated plaintext. Reject the change
if setup dominates the workloads that matter or timing behavior depends on
secret indices. No acceleration was implemented or benchmarked in this pass.

## Constant-time curves require a constant-time field representation

The old suggestion stopped too early at complete addition formulas and a
fixed scalar schedule. The current prime-field path uses rump Montgomery
objects; generic multiprecision operations, normalization and inversion also
need a secret-independent execution contract. Replacing point formulas while
leaving variable-width arithmetic underneath would not establish constant time.

Start with one named prime curve. Derive fixed-width modular arithmetic with
bounded carries, branchless reduction/selection and fixed memory access. Use
[Renes, Costello and Batina's complete formulas](https://eprint.iacr.org/2015/1060.pdf)
only where their field and group hypotheses hold; they are not a universal
replacement for binary curves or arbitrary Edwards parameters. Fix the scalar
schedule and table selection, then derive a fixed addition chain for inversion
or another published constant-time inversion method. Keep formula equivalence
checks separate from generated-code/timing checks.

Measure end-to-end key agreement/signing, not just point addition. Test scalar
edge values, exceptional points allowed by the API and malformed inputs.
Timing experiments can find leaks; a negative result is evidence under that
experiment, not proof. Publish compiler, target, feature and input classes.
Keep the current honest `vt` labeling until the complete path warrants more.
Generic rump algorithm work belongs in rump's own recommendations.

## Calibrate the cipher battery to a stated statistical decision

At alpha=0.001, 300 p-values do not tightly establish the rejection rate.
For an approximate 95% half-width of 20% of that rate, an independent binomial
calibration needs roughly 96,000 trials. That calculation is a planning scale,
not a demand to run every expensive cipher/FFT configuration 96,000 times.
Use exact or justified finite-sample null calculations where available, then
calibrate the actual finite byte/chunk construction at representative sizes.

Predeclare the precision target, acceptance threshold and treatment of skipped
tests. Replicate independent streams; handle several widths of the same stream
as a cluster. Measure power against specified bit bias, short periods and
repeated blocks, not only false rejection under the null. Keep calibration
streams separate from the ciphertext panel. Do not tune until those ciphers
pass, or equate a randomness verdict with cryptographic security.

Cryptography owns ciphertext generation, its R script and a harness that
replays exactly the same saved bytes through entropy's maintained battery.
Record corpus hashes, modes/nonces, sampled variants and insufficient-input
results. Reusable finite-input support and DIEHARD preservation belong in
[entropy/SUGGESTIONS.md](../entropy/SUGGESTIONS.md); do not duplicate them here.

## Remaining standards and performance work

These are feature choices, not audit failures. After the contracts and boundary
coverage above, consider SLH-DSA, Ed448, CTR_DRBG's derivation function and
prediction resistance, bit-oriented SHA-3, named finite-field key-agreement
groups, and a specified ECIES concatenation-KDF profile. Pin the exact published
specification, accepted inputs and external vectors before implementation.
Keep draft constructions labeled as drafts. Standard key containers for the
currently supported named families are already implemented.

For ML-KEM and NTRU, obtain current stage profiles before selecting an arithmetic
rewrite. Preserve prescribed distributions and deterministic coin mapping;
optimizing a sampler by changing either is a different algorithm. Compare
mathematical kernels and complete operations under the same parameters,
compiler and features. Historical rewrite ratios do not describe the newest
working tree or identify its current bottleneck.

The provenance/publication record remains in AUDIT.md. On 2026-09-16 the
remote still held the original history and tags and crates.io still served
0.5.0–0.6.2 unyanked; `TODO.md` carries both as owner actions. This review
neither publishes nor changes history.
