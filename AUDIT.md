# Cryptography audit

Revalidated 2026-09-11 against `342989abf5f9b8da585843a4a01e5435dddc4bc3`
plus the paused working tree, including the new PKIX modules. The commit ID
alone does not describe this implementation. Source hashes and frozen copies
of cryptography, rump, entropy and factoring are retained in
`/tmp/paused-review-jb_h_rke`; rump is `d30a7bcc` in that snapshot.

This pass changes only AUDIT.md and SUGGESTIONS.md. It rechecks current
findings and recommendations with source inspection, published specifications
and bounded local tests. It is not a repeat of the original whole-crate
security/provenance audit, a timing certification or a release gate.

## Source identity

The SHA-256 digest of the source/test manifest is
`97d00a1957a4ae684085cc8e0981f09f04573c43294e15e34a6251d6cabe5fe0`.
Compute each regular file's SHA-256 under `src/` and `tests/`, sort by
repository-relative path, concatenate lines as `hex_digest`, two spaces,
`path`, newline, then SHA-256 that UTF-8 manifest. This includes untracked
source files; it is stronger than the commit ID for a dirty checkout.
Cargo.toml and Cargo.lock also match the frozen copy used for these checks.

## Current assessment

**Status on 2026-09-16.** The assessment below is the reviewer's text of
2026-09-11 and is kept as the record of what was found. Every finding it
names is closed in the working tree: C5, C1, C2, C6 and C7 by the owner
rulings and repairs tabulated in the next section, C3 and C4 by the
resolutions recorded under their headings, and the Ed25519 and ML-KEM import
contracts by the profiles section. The full-tree review of 2026-09-15 and its
repairs follow the rulings. What remains open is not in the source: the
published releases 0.5.0–0.6.2 on crates.io and docs.rs still carry the
pre-audit code and need the owner's publication actions; the performance
tables in `ASYMMETRIC.md`, `SYMMETRIC.md` and `POSTQUANTUM.md` are marked
stale and await a fleet re-sweep with the corrected instruments; and none of
the repairs is committed yet.

The old “RSA alone has standard formats” recommendation is obsolete. Standard
encodings now exist for named Weierstrass curves, Ed25519/X25519/X448, DSA/DH,
ML-KEM and ML-DSA. The FFC caller now uses plain Lucas. Those implementation
tasks are removed; their current validation and remaining fuzz coverage are
recorded below. The EES tamper fix also remains effective in the checked cases.

The most serious reproduced boundary error is an ECDSA importer accepting the
point at infinity: a signature built entirely from public data then verifies
under that invalid key (C5). Other open issues concern default wiping, the NTRU
sender/receiver contract, calibration evidence, parser coverage, BER receiver
support and copies made while formatting secret PEM. Ed25519 and ML-KEM import
limits also need precise contracts. Independent speed work should target the
arithmetic actually present, especially GHASH's 128 masked-XOR steps per block.
New curve formulas alone cannot make variable-time field arithmetic constant-time.

## Owner rulings and repairs, 2026-09-11 afternoon

After this review the owner ruled on its open questions, and the implementer
made the repairs below in the working tree. The review's findings stay as
written; where a recommendation differs from a ruling, the ruling governs.

| Finding | Owner's ruling | State of the working tree |
|---|---|---|
| C5 identity public keys | "Infinity: do what is CORRECT." | Every EC public-key import applies SEC 1 §3.2.2.1 and refuses the identity, private-key imports require a valid d·G, and ECDSA verification refuses Q = O. The gap was wider than reported: EC-ElGamal wire import, ECDSA's blob, PEM and XML coordinate range check, and private keys deriving the identity. |
| C1 wiping | "It means for cryptography code we turn on wiping." | Always on: the crate scrubs its own secrets and enables rump's `wipe`; the opt-in feature is gone. |
| C2 NTRU sender | "Are zero polynomials useful? If not, why create them?" | Encapsulation redraws once when r = 0, or m = 0 for HRSS, and panics if the second draw is refused; decapsulation keeps rejecting them. All 400 KAT entries still reproduce. |
| C6 BER receivers | "Do what the RFC says, we obey standards." | `_der` methods stay strict. `from_pkcs8_ber` on every private-key type, `from_sec1_ber` on EC keys, and the `PRIVATE KEY` and `PUBLIC KEY` PEM decoders accept BER; contents an RFC requires in DER stay DER. |
| C7 PEM copies | "wipe them" | PEM, XML and DER encoders allocate their exact final size; decoding and BER conversion use wiped buffers that never grow. |
| Ed25519 import profile | "RFC 8032 is what we follow." | Decoding exactly per §5.1.3 and the cofactored §5.1.7 equation; small-order and mixed-order keys are accepted and bind no secret. |
| ML-KEM validation | "do not skip" | Seedless imports run FIPS 203 §7.1's pair-wise test with a random source the importers now take; RFC 9935 C.4.1 #2 is rejected. |
| Published history | Rewrite it. | Built and verified but not published: the implementer's force-push was refused twice by a permission check, so pushing is the owner's step. |
| crates.io releases | "Fix crates.io, that is shameful." | Not yet done. rng-entropy depends on cryptography-rs, so it must be deleted first; both deletions need the owner's logged-in session. |

Validation of the repaired working tree, 2026-09-11 afternoon: 1,318 tests
pass with 12 ignored, plus 5 doc tests and 14 `arm-sha3` tests. Clippy with
`-D warnings` under the default and `ct_profile` features, rustfmt and rustdoc
are clean. The Rust 1.87 build and the fuzz, benchmark and both fast crates
check clean. OpenSSL 3.6.3 cross-checks ran with only XTS skipped, because
`openssl enc` does not offer it. entropy passes 422 tests with 8 ignored, and
each of the day's commits compiles on its own. The release-only tests pass 12
of 12 on the 128-core x86-64 host, where the x86 fast crate also checks clean.

Still open from this review: C3, calibration evidence, and C4, fuzz entry
points for the standard parsers.

Found during the repairs and not yet addressed:

- ML-DSA's `from_wire_bytes` and `from_key_blob` check only a private key's
  length; its PKCS #8 `expandedKey` path checks ranges and t0 and tr.
- DSA and ECDSA `sign_digest_with_rng`, and NTRUEncrypt key generation and
  encryption, retry without a bound, so a broken random source hangs them.
- Explicit curve parameters in crate EC blobs and XML are not validated per
  SEC 1 §3.1.1.2.1.
- `MlKem::keygen` does not run the pair-wise test that FIPS 140-3 IG 10.3.A
  asks of generated keys.

*Status, 2026-09-15: all four repaired, from the specifications, and each
checked by experiment.* ML-DSA's `from_wire_bytes` and `from_key_blob`
regenerate the public key as the PKCS #8 path does (range of `s1` and `s2`,
`t0` and `tr` recomputed); the KAT keys with one coefficient pushed past `±η`
are refused on both paths. DSA and ECDSA `sign_digest_with_rng` draw at most
`MAX_NONCE_DRAWS = 64` nonces and return `None`, shown on a toy key with a
source stuck on the one `k` that zeroes `s` and, since the full-tree review,
with a source that yields that `k` once and a good one next (a signature after
exactly two draws); the deterministic RFC 6979 signers stop at the same bound. NTRUEncrypt bounds its three
loops (8 candidates for `F` and for `g`, 64 encryption attempts, 256 index
draws) and panics on a broken source, as the round-3 KEMs do; the `ees401ep1`
refusal rate is measured at 2.7% of attempts (14 of 514, binomial estimate
about 4%), so 64 refusals in a row are below `2^-250`, and the panics are
exercised with a source stuck on a refused `b` and with one of all-one bytes.
Explicit curve parameters in blobs and XML go through
`CurveParams::from_explicit`: a named curve of this crate, or SEC 1 v2.0
§3.1.1.2.1 / §3.1.2.2.1 in full (`validate_domain_parameters`); all 16 named
curves pass the primitive itself, P-256 and B-163 under `−G` pass as unnamed
parameters, and a defect at each step is refused, as is the 17-element toy
curve, whose field width step 1 does not admit. Verification: 1,146 library
tests, 5 doc tests and the integration suites pass; clippy under default and
`ct_profile` features, rustfmt, rustdoc with warnings denied, and the fuzz
crate are clean.

## Full-tree review and repairs, 2026-09-15

The owner asked for every line of the crate to be read after the four
remaining findings above were repaired. Twenty-one adversarial readers each
took one slice of the tree; their findings, the decisions taken on them and
the repairs are recorded here as each slice closes. The arithmetic held
everywhere it was re-derived independently (every cipher table, hash constant,
NTT twiddle, curve constant and DER rule the readers recomputed matched); the
defects were in validation, secret handling, honesty of claims and coverage.

### NTRU round-3: two departures from the specification's text, settled by the KAT files

**`Fixed_Type` sort order (§1.10.5).** Step 16 reads "Sort A", where steps 5, 9
and 13 define `A_i = label + Σ 2^(2+j)·b`, a non-negative integer below 2^32,
so the text describes numerical order. The code sorts the `A_i` as 32-bit
two's-complement integers (keys with bit 31 set precede all others), in
constant time by XORing bit 31 before Batcher's network on unsigned keys. All
300 ntru-hps KAT entries reproduce under the signed order and none under
numerical order; the departure changes only the permutation, not the weight or
the sample space.

**`pack_S3` index (§1.8.7 step 5, §1.8.8 step 6).** The text sets
`c_j ≡ v_{5i+j} (mod 3)` for `i = 0, 1, …` while §1.8.2 declares zero-indexed
coefficients, so read literally byte 0 would encode `v_1 … v_5` and nothing
would encode `v_0`. The code uses `c_j ≡ v_{5i+j−1}`, the only reading under
which the bytes encode `S3(a)` as the section's output line requires. Every
private key, ciphertext and shared secret of all 400 KAT entries reproduces
under it.

**Key generation and zero polynomials.** The C2 ruling now covers the party
whose failure would be permanent: `sample_fg` refuses `f = 0` (and `g = 0`
for HRSS, where `h` would be 0 and every ciphertext `Lift(m)` in the clear);
key generation redraws its sampling bits once and panics on a second refusal,
as encapsulation does. All 400 KAT entries still reproduce.

### NTRUEncrypt (EESS #1 v3.1): `dm0` pinned, refusal rates measured, key generation exercised

**`dm0` provenance.** The reader found `dm0` unpinned for seven of the nine
sets. It is now pinned two ways against the standard authors' reference
implementation used as a black-box oracle: over 5,000 encryptions per set the
oracle redrew `b` for 3.87% of `ees401ep1`, 15.5% of `ees449ep1` and 0.06% of
`ees443ep1` attempts and never for the other six; and under a public key
`h = 0`, where the mask is fixed and the representative's trit counts can be
chosen, the oracle redrew at a minimum count of `dm0 − 1` and accepted at
`dm0` for all nine sets. The module documents the exact refusal probability
per attempt, `1 − P(every count ≥ dm0)` under the multinomial on `N` uniform
trits: 3.49 × 10⁻², 9.74 × 10⁻⁴ and 0.155 for the three small sets and below
10⁻⁸ for the rest (recomputed independently by the lead from the same
formula). `ENCRYPT_ATTEMPT_LIMIT = 64` is sized against the worst row:
0.155⁶⁴ < 2⁻¹⁷².

**Refusal-rate tests.** The first form of the test allowed `ees443ep1` at
most three refusals in 1,000 trials against an expectation of one, and the
fixed seed gave five; its replacement (30,000, 1,000 and 300 trials, at
least 25 expected refusals, a four-standard-deviation band) is a consistency
check that cannot tell `dm0` from `dm0 ± 1`: the adjacent rates differ by
about 1.3× while the band is ±4σ, so it would pass 89–99.7% of the time under
a neighbouring `dm0` (the adversarial re-review computed this, and noted
that the 30,000-trial count of 39 fits `dm0 = 116` 3.5 times better than
115). The separation is the release-only test
`step_p_refusal_rates_separate_dm0_from_its_neighbours`: 100,000, 1,000,000
and 30,000 trials, the neighbours' expectations at least ten standard
deviations away, the binomial log-likelihood required to be highest under
the table's `dm0`. Its run of 2026-09-15: `ees401ep1` 3,588 of 103,588
attempts (z = −0.46; log-likelihood ratios 135 and 171 nats against
`dm0 ∓ 1`), `ees443ep1` 1,038 of 1,001,038 (z = +2.01; 91 and 57 nats),
`ees449ep1` 5,416 of 35,416 (z = −1.03; 117 and 166 nats). The `ees443ep1`
count sits two standard deviations high of the table with the seeds the
test fixes; it is nevertheless 57 nats more likely under the table's value
than under the nearest alternative, and the oracle measurement above pins
that value directly.

**Key generation.** `Φ_N` splits over GF(2) into `(N − 1)/ord_N(2)`
irreducibles; the test `phi_n_splits_over_gf2_as_tabulated` checks the
factor counts, and `KEYGEN_DRAW_LIMIT` is justified from the smallest factor
degree, 200 at `N = 401`. Non-invertible `f` and `g` for `N = 401` were
constructed as complemented multiples of a degree-200 factor and driven into
`random_ternary` through a scripted source, so the redraw and the limit are
both observed. Public keys pass the plausibility test of §10.2.5.2.2 step a
(convention 13) on import, so `h = 0` no longer imports; the ROS2BSP padding
reading (convention 1) is pinned against the oracle's 27 public keys.

### Tests, fuzzing and the documentation

- **The manual and README are compiled.** `#[cfg(doctest)]` includes make
  every Rust block of `MANUAL.md` (32) and `README.md` (20) a doctest, beside
  the crate's five source doctests. Eight did not compile or run on first
  inclusion (README examples that depended on a variable from an earlier
  block; a manual PSS example whose salt violated RFC 8017 §9.1.1 step 3; a
  two-block file-encryption example); all are repaired, and every block but
  the file-encryption example (`rust,no_run`) runs under `cargo test --doc`.
- **Standard containers are fuzzed** (`fuzz_pkix_parse`, 29 arms, DER, BER
  and PEM, idempotent re-encoding required on acceptance) and so are every
  AEAD's decoder, every MAC, both NTRU families, X25519/X448 and Edwards-DH;
  ML-KEM, ML-DSA and NTRU targets flip the bit the fuzzer chooses; the
  structured targets take length-prefixed blobs and ship seed corpora. Every
  one of the 45 targets ran 3,000 iterations under libFuzzer on nightly, and
  the nineteen new or rewritten ones a minute each (from 16,460 iterations
  for ECDH on sixteen curves to 3.5 million for the MACs), without a finding
  in the crate. Two findings were in the targets' own assumptions: Rabin's
  byte API returns the minimal integer encoding, as documented; and
  Poly1305 does not bind the message under every key (with `r = 2^48` two
  blocks collide, with `r = 0` the tag is `s`), only with probability about
  `1 − 8⌈L/16⌉/2^106` over a uniform key, so that target keys Poly1305 from a
  digest of the fuzzer's bytes.
- **The CAVP DRBG harness calls the standard's interface.**
  `CtrDrbg::instantiate` and `reseed_with_additional_input` take the vector
  fields as NIST names them; the padding and XOR of §10.2.1.3.1 and
  §10.2.1.4.1 steps 1-3 live in the DRBG, not the test.
- **A regression the suite caught.** After the Koblitz capacity became
  `⌊(bits − 1)/8⌋ − 1`, the x-coordinate buffer in EC-ElGamal's byte
  encryption was two octets short of the coordinate width and every byte
  encryption returned `None`; the nine round-trip tests failed in the final
  verification and the buffer is sized from the coordinate width again.
- **The randomness battery** is rebuilt and calibrated on OS-random streams;
  see the C3 resolution below and `R-REPORT.md`.

## Findings of the 2026-09-11 review

Each heading keeps the reviewer's text. Dispositions: C5, C1, C2, C6 and C7
are closed by the rulings table above; C3 and C4 carry their resolutions
below their text. Nothing in this section is open in the working tree.

### C5 — P1: the wire ECDSA importer accepts an identity key with forgeable signatures

*Status after this review: repaired under the owner's ruling; see "Owner rulings and repairs".*

`EcdsaPublicKey::from_wire_bytes` (`src/public_key/ecdsa.rs:147`) and
`EcdhPublicKey::from_wire_bytes` (`src/public_key/ecdh.rs:119`) accept SEC 1's
single-byte identity encoding `[0]`. Their subgroup predicate accepts it
because `n*O=O`. That predicate is mathematically correct; public-key validation
must additionally reject the identity, as required by
[SEC 1 §3.2.2.1](https://www.secg.org/sec1-v2.pdf).

For ECDSA under Q=O, verification computes `(z/s)*G+(r/s)*Q=(z/s)*G`.
Anyone can choose s=1 and r=x(z*G) mod n for an ordinary digest z, provided
r is nonzero. A fresh public-API P-256 test imports `[0]`, constructs that
signature using only the digest and curve parameters, and successfully verifies
it. This requires the invalid imported key; it is **not a forgery against an
honest existing key**. ECDH already rejects the resulting shared identity in
`agree`; the reproduced ECDH error is the import invariant, not secret recovery.

Use the existing `CurveParams::is_valid_public_point` (`ec.rs:1198`) in public
key constructors. The SPKI EC path already does this. Preserve identity support
in the low-level group decoder and arithmetic. Regress all public import paths,
including legacy wire formats, with valid controls and identity, noncanonical,
off-curve and wrong-subgroup cases. The reproduction below demonstrates why
passing ordinary signing and standard-container tests did not close this gap.

### C1 — P1: automatic wiping still violates the stated opt-in requirement

*Status after this review: superseded by the owner's ruling that cryptography turns wiping on; see "Owner rulings and repairs".*

The governing instruction in this conversation is: “We should ONLY be
memory-wiping when specifically enabled for cryptography. Doing it by default
is an error.” The previous audit treated a different interpretation as an
unresolved owner decision. An implementer's interpretation does not supersede
that explicit instruction.

`src/ct.rs:216`, `zeroize_slice`, performs volatile stores in every build.
Ordinary drop and temporary-cleanup paths call it without feature guards;
for example `src/cprng/ctr_drbg.rs:178` wipes the key and V on drop.
`Cargo.toml` forwards `wipe` only to rump, and `tests/wipe_policy.rs` explicitly
requires the helper to scrub in the default build. A public-client check
confirmed live-buffer clearing both with and without the feature. This proves
the helper's behavior; the automatic paths are established by source inspection,
not by reading deallocated memory.

Make automatic crate scrubbing and the corresponding tests honor the opt-in
policy. Rump already has an opt-in implementation. The module summary in
`ct.rs` still says the helper is feature-gated, while the function and tests
say otherwise. Correct documentation with the policy implementation, not by
relabeling current behavior as approved. Explicit erasure APIs should have a
stated contract. No implementation or policy change was made in this pass.

### C2 — P2: NTRU round-3 encapsulation can emit a ciphertext its decoder rejects

*Status after this review: repaired; see "Owner rulings and repairs".*

`src/public_key/ntru_pqc_shared.rs:761`, `ternary`, reduces bytes modulo 3;
`sample_rm` at `:875` does not exclude zero. `dpke_decrypt` at `:1036` requires
nonzero r and, for HRSS, nonzero m. The source now acknowledges this mismatch,
but behavior is unchanged.

Fresh public-API checks generate keys with `CtrDrbgAes256([0x64;48])`, verify
an ordinary encapsulation, then control only the encapsulation coin block:

| Set | Controlled component | Result |
|---|---|---|
| HPS509 | r=0; remaining coin bytes 1 | Shared keys disagree |
| HPS677 | r=0; remaining coin bytes 1 | Shared keys disagree |
| HPS821 | r=0; remaining coin bytes 1 | Shared keys disagree |
| HRSS701 | r=0; m nonzero | Shared keys disagree |
| HRSS701 | m=0; r nonzero | Shared keys disagree |

All five ordinary controls pass. The same outcomes hold with `wipe` enabled.
The controlled source is a boundary test, not a suggested random generator.

The [authors' round-3 specification](https://www.cryptojedi.org/papers/ntrunistr3-20200930.pdf)
§1.2 item 13 gives incompatible nonzero-set and canonical-representative
wording, while §§1.10.2–1.10.3 include the zero coin outcome. With independent
uniform bytes, each zero-polynomial event has probability
`p0=(86/256)^(N-1)`. For HRSS the probability of either is `2*p0-p0^2`, since
r and m use disjoint coin bytes. This is negligible, not a demonstrated
practical attack. Nevertheless, an infallible encapsulation must not promise
an agreed key for a ciphertext the same implementation rejects.

The earlier recorded owner decision keeps zero rejection. Address the sender
under that constraint: specify a checked coin boundary and explicit failure
or retry behavior, document any departure from the published procedure, and
keep implicit rejection for invalid received ciphertexts. A retry must not
hang forever on a broken coin source or silently weaken a constant-time claim.
Do not introduce a new sampling distribution without analyzing it.

### C3 — P2: the reported calibration is too small to establish the rare tail

`scripts/cipher_randomness.R:233` records the 300-test calibration behind the
replacement gap statistic; the script uses alpha=0.001. One rejection in
300 independent trials gives an exact 95% binomial interval approximately
`[0.0000844, 0.01843]`. Reusing one byte stream at several widths adds dependence
and does not increase independent-stream replication.

The corrected gap and cumulative-periodogram statistics address the old
miscalibration; this finding does not argue for reverting them. It limits
what the validation can claim. An expected 0.68 false rejections across 680
calibrated marginal tests requires no independence, but observing one does
not establish their calibration or cryptographic security.

**Resolution (2026-09-15).** The battery was rebuilt as seven distinct tests
on one chunk width with a Bonferroni decision rule (see CHANGELOG), and the
script gained a `--calibrate N` mode that runs the same code on `N` streams
of `/dev/urandom` bytes of the plaintext's length. The first campaign,
200,000 streams on dennard, gave per-test rejection rates at α = 10⁻³ of
1.12, 0.93, 0.91, 1.32, 0.90, 1.03 and 0.99 × 10⁻³ (byte χ², KS, serial, gap,
permutation, Bartlett, runs), a battery false-failure rate of 9.75 × 10⁻⁴
against the bound 10⁻³, and Kolmogorov-Smirnov uniformity p-values of the
p-value samples between 0.10 and 0.68. The gap test's interval,
[1.2, 1.5] × 10⁻³, excluded 10⁻³: pooling its tail at an expected count of 5
leaves the χ² approximation short in that tail. A 60,000-stream experiment
on the gap test alone measured 1.42 × 10⁻³ at a pooling threshold of 5,
1.25 × 10⁻³ at 20, 9.2 × 10⁻⁴ at 50 and 8.8 × 10⁻⁴ at 100; the threshold is
50. That pooling depth is the battery's one tuned quantity; it was chosen at
α = 10⁻³ while the battery decides at α/m = 1.43 × 10⁻⁴, so the calibration
section reports each test's rate at both thresholds, and the depth depends
on the stream length, so the calibration is read only for streams of the
plaintext's length. The campaign was rerun on the final battery on dennard
and twilight, 200,000 streams each: per-test rejection rates at α = 10⁻³ of
1.05, 1.03, 1.00, 1.10, 1.00, 0.99 and 0.99 × 10⁻³ (every 95% interval
covers 10⁻³; the gap test's is [1.0, 1.2] × 10⁻³), rejections at α/m of 46,
60, 58, 79, 55, 65 and 61 against 57.1 expected (the gap test's 79 is 2.9
Poisson standard deviations high, the one residual of the pooling choice),
Kolmogorov-Smirnov uniformity p-values from 0.41 to 0.86, and a battery
false-failure rate of 419 / 400,000 = 1.05 × 10⁻³ [0.95, 1.2] × 10⁻³
against the bound 10⁻³. The byte-entropy deficit over the 400,000 streams
had mean 3.26 × 10⁻⁵ and standard deviation 2.89 × 10⁻⁶ bits, the
second-order prediction to three figures. The section is in `R-REPORT.md`;
every stream is a row of `scripts/null_calibration/pvalues.csv.gz` (p-values
at six significant digits, 12.6 MB). The superseded version-3 campaign's
200,000 rows are the commit `dfb0582` in the fleet worktree
`/soe/darrell/cryptography-review` (dennard).

Choose a precision or decision target before collecting evidence, account
for stream clusters, and measure power against specified weak alternatives.
Use exact null distributions when applicable, explaining the assumptions;
for example the cumulative-periodogram construction is exact under the
appropriate Gaussian white-noise model, not automatically for finite uniform
chunk values. No R battery or calibration campaign was rerun here.

### C4 — P2: new standard key parsers are outside the current fuzz entry points

The new `pkix`, `ec_pkix`, `curve_pkix`, `ffc_pkix` and `ml_pkix` modules are
present and tested. The fuzz-target search finds no call to `from_spki_der`,
`from_pkcs8_der`, `from_spki_pem` or `from_pkcs8_pem`. The general
`fuzz_pk_parse.rs` still drives crate-defined blobs and wire points.

**Resolution (2026-09-15).** `fuzz/fuzz_targets/fuzz_pkix_parse.rs` drives
every `from_spki_der`, `from_pkcs8_der`, `from_sec1_der`, their BER and PEM
forms, and the RFC 3279 parameter and signature parsers (29 arms), with the
encoding required to be idempotent when a parse succeeds; `fuzz/seeds/`
seeds each arm with a valid container. Every target ran under libFuzzer
(`cargo +nightly fuzz run`, 3,000 iterations each, and a minute for the new
ones: 315,006 iterations of `fuzz_pkix_parse`) without a finding.

This is a coverage gap, not a reproduced parser vulnerability. Route bounded
hostile input into the standard entry points and seed the corpus with the
published vectors already present. Exercise nested attributes and limits,
algorithm identifiers, seed/expanded-key consistency, optional public keys,
truncation and trailing data. Keep accepted-key semantic checks, not just
“did not panic,” with the expanded-only ML-KEM limitation below made explicit.
The completed S1 implementation should become this bounded
validation task rather than remain an unimplemented-format recommendation.

### C6 — P2: strict DER APIs do not cover the claimed RFC 5958 receiver profile

*Status after this review: repaired under the owner's ruling; see "Owner rulings and repairs".*

The current PKIX entry points parse DER. Replacing an honest Ed25519 PKCS #8
outer SEQUENCE's definite length with BER's indefinite-length marker and an
end-of-contents terminator produces a valid BER container that they reject;
the DER control imports successfully. [RFC 5958 §2](https://www.rfc-editor.org/rfc/rfc5958.html#section-2)
requires receivers to support BER, which includes DER.

Rejecting BER in a method explicitly named `from_pkcs8_der` is appropriate.
The gap is the broader receiver claim with no BER-aware import entry point.
Provide a separate bounded BER receiver or narrow the supported profile. Keep
strict DER methods strict. Bound nesting, lengths and work; a BER outer wrapper
must not relax algorithm-specific requirements such as RFC 9935's DER-encoded
private-key CHOICE. This is a conformance gap, not a demonstrated memory-safety
or authentication vulnerability.

### C7 — P2 when wiping is enabled: PEM construction can leave allocation copies

*Status after this review: repaired; see "Owner rulings and repairs".*

`src/public_key/io.rs:630`, `pem_wrap`, builds the armored output from
`String::new()` with repeated pushes, then scrubs only the separate base64
string. Growth can move the output after private-key bytes have been copied
into it, leaving its old allocation unscrubbed. This is a source-identified
copy path; no freed-memory inspection or allocator campaign was performed.

When the opt-in erasure guarantee is enabled, wiping the final/intermediate
objects does not account for these earlier output allocations. Compute the
full output size with checked arithmetic before writing secret bytes, or emit
base64 directly into a correctly sized final buffer. This also removes
allocation work. Do not use this finding to reintroduce default wiping: C1
still governs policy. The caller's ownership of the returned PEM is a separate
contract.

### Import profiles: stricter Ed25519 and optional ML-KEM validation

*Status after this review: the owner ruled for RFC 8032 exactly and for running the pair-wise test; see "Owner rulings and repairs".*

The latest implementer audit records two further boundaries; both are real,
but they should not be described as the same kind of defect as C5.

- **Ed25519:** `from_key_blob` applies the nonidentity, prime-order-subgroup
  predicate after point decoding. A fresh check rejects the canonical order-two
  point `(0,p-1)`. This is a narrower import policy than RFC 8032's point
  decoding. Name and test the strict profile and document interoperability
  implications. [RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7)
  explicitly allows verification with either its cofactored equation or the
  stronger uncofactored equation; the latter alone is not a conformance error.
  Broadening accepted points requires reviewing decoding, challenge handling
  and the verification equation together, not simply deleting checks.
- **ML-KEM:** an expanded private key with a corrupted secret polynomial can
  pass structural and public-key-hash checks. The existing RFC 9935 C.4.1 test,
  rerun in this pass, accepts example #2 and demonstrates an encapsulation/
  decapsulation mismatch. This example requires a pairwise consistency check
  to detect; it is not a failure of a mandatory hash check. Distinguish structural
  import from optional validated import with an appropriate random source.
  Preserve the checks on seed/expanded agreement and public-key hashes described
  in [RFC 9935 §8 and Appendix C.4.1](https://www.rfc-editor.org/rfc/rfc9935.html#section-8).
  An expanded-only decoder cannot recover a missing generation seed. Tests
  should assert each profile's advertised guarantees rather than assume every
  structurally accepted key is a working pair.

## Verified repairs removed from the queue

| Item | Fresh evidence |
|---|---|
| EES443/EES1499 trailing decoded bits | 32 last-coefficient mutations per set rejected, with all honest controls accepted; repeated under `wipe`. This is the original bounded case, not every possible mutation. |
| FFC plain Lucas adoption | Source calls `is_lucas_probable_prime`; 15 targeted prime/domain tests pass, including CAVP cases. Three existing expensive cases remain ignored in this selection. |
| Standard key containers | 34 `pkix`-filtered tests pass, including named-curve and DSA/DH OpenSSL checks. RFC 8410/9881/9935 filtered checks also pass. |
| Rump padding, modular negation and little-endian APIs | Present in rump `d30a7bcc`; crypto callers use the APIs. They are not missing features or pending Lucas adoption. |

The targeted standard/prime groups execute 61 passing tests with overlap:
**58 distinct tests pass**, three are ignored. The seven-case public client
checks five isolated NTRU corners and two EES parameter sets, under both feature
states. Rust 1.93.1 on aarch64-apple-darwin; library tests use the ordinary
debug profile, the scratch client uses dev opt-level 1. No full clippy,
rustdoc, MSRV, fuzz campaign, release suite or timing test was rerun. A second
public client reproduces the ECDSA, ECDH, BER and Ed25519 boundaries above.
Its four boundary checks are separate from the 58 library tests; the script is
included below. Ordinary green tests do not cover the ECDSA counterexample.

### Implementer verification received during this review

The audit changed concurrently while this pass was running. Its latest
September 11 record reports the following; these are **attributed results,
not checks independently repeated by this reviewer**:

| Check | Reported result |
|---|---|
| All-target tests, default and `wipe` | 1,262 passed, 12 ignored in each build |
| Doc tests; Apple `arm-sha3` tests | 5 and 14 passed |
| Release ignored tests on the 128-core x86-64 host | 12 passed |
| Clippy default/`ct_profile`; fmt; rustdoc | clean |
| Rust 1.87 minimum build; fuzz, benchmarks and both fast crates | pass/check clean |
| OpenSSL cross-checks | OpenSSL 3.6.3; only XTS skipped because `enc` lacks it |
| Each September 11 commit | builds |
| Rump `d30a7bc`, default/`wipe` | 382/383 passed; four pre-existing rustdoc errors remain |
| Downstream entropy at that run | 296 passed, 2 ignored; entropy remains active |

The reported R rerun remains 34 ciphers, one rejection in 680 checks at
alpha=0.001 on the retained ciphertexts. C3 qualifies its calibration evidence.
Do not infer a fresh run or a security certification from this preserved record.

## Publication and provenance record

The following disclosure is preserved from the implementer's audit. Its
source-copy comparisons, deleted scratch artifacts and reported published history
rewrite were **not independently repeated in this pass**. Keeping this record
is distinct from carrying fixed code defects as open findings. Nothing was
committed, force-pushed, yanked or deleted by this reviewer.

The recorded owner decisions keep crate formats as the default alongside
standard encodings, keep zero rejection, and authorize preparation of a history
rewrite. An earlier record said the rewrite and four tags were pushed; that is
not so. `git ls-remote origin` on 2026-09-16 shows `main` at `342989a` and the
tags `v0.5.0`–`v0.6.2` at their original commits, and the crates.io API lists
0.5.0–0.6.2 as published and not yanked. The prepared rewrite remains
unpublished. These decisions
do not close C1 or C2. The published-release issue remains:
rewriting Git does not remove the copies in crates.io/docs.rs releases
0.5.0–0.6.2. Publication actions need their own concrete plan and execution.

### Previously recorded code provenance

| Component | Source | License of source | Entered in | Resolution |
|---|---|---|---|---|
| ML-KEM arithmetic core | pq-crystals Kyber reference | CC0 or Apache-2.0 | `032439d`, 2026-03-07 | Rewritten from FIPS 203 |
| ML-DSA | pq-crystals Dilithium reference | CC0, Apache-2.0 or GPL-2.0 | `4ec4728`, 2026-03-07 | Rewritten from FIPS 204 |
| NTRU round-3 KEMs | round-3 reference C and SUPERCOP code | CC0 | `6a0c824`, 2026-05-07 | Rewritten from the round-3 specification |
| NTRUEncrypt encoding, IGF, MGF, drivers | libntru | BSD 3-clause, notice required | `6a0c824`, 2026-05-07 | Rewritten from EESS #1 v3.1 |
| Poly1305 | poly1305-donna | MIT or public domain | `1aae1df`, 2026-06-09 | Rewritten from RFC 8439 §2.5 |
| GHASH constant-time multiply | BearSSL `ghash_ctmul64` | MIT, notice required | `d894ece`, 2026-07-20 | Rewritten from SP 800-38D §6.3 |
| ZUC arithmetic | C listing printed in its own ETSI/SAGE specification | specification text | `8b60d06`, 2026-03-01 | Rewritten from the specification's prose |
| SNOW 3G LFSR and FSM | C listing printed in its own ETSI/SAGE specification | specification text | `98d0b4a`, 2026-03-04 | Rewritten from the specification's prose |
| X25519 inversion identifiers | libsodium and SUPERCOP naming | ISC and public domain | `482ea75`, 2026-04-27 | Rewritten from RFC 7748 |
| ML-DSA benchmark RNG literal | Dilithium test code | CC0, Apache-2.0 or GPL-2.0 | `4ec4728`, 2026-03-07 | Replaced with an original generator |

The MIT and BSD notices those licenses require were never included. The
commit message for `6a0c824` states the code was written from the round-3
specification and IEEE 1363.1; the module headers for ML-KEM and ML-DSA made
the same claim for FIPS 203 and FIPS 204. Several commits that brought in
copied code carry co-author lines from earlier Claude sessions.

Each rewrite was clean-room: the rewriting stream could not open any other
implementation or read the copied function bodies, and equivalence was shown
by output, not resemblance.

| Rewrite | Known answers reproduced | Speed on the development machine |
|---|---|---|
| ML-KEM (512/768/1024) | pq-crystals oracle vectors (keys, encaps, decaps, implicit rejection) and the NIST ACVP subset | ML-KEM-768 1.38–1.73× slower |
| ML-DSA (44/65/87) | pq-crystals oracle vectors (public and private keys, deterministic signatures) and the ACVP subset | ML-DSA-65 signing 1.30× slower |
| NTRU round-3 (four sets) | all 100 entries of each NIST KAT file | key generation about 2× slower |
| NTRUEncrypt (nine sets) | interoperates both ways with Security Innovation's reference | not measured |
| Poly1305, GHASH, SNOW 3G, ZUC, X25519 | RFC 8439, GCM specification, RFC 8452, ETSI/SAGE test data, RFC 7748 | GCM tags 0.31×, GCM encryption 0.63× |

The ML-KEM compression constants the lead added earlier on 2026-09-10 came from
the pq-crystals KyberSlash fix. The provenance audit caught them, and they were
replaced by an independently derived pair before the rewrite.

Two borderline items were also rewritten: MD5, SHA-1 and SHA-2 followed
Wikipedia's pseudocode rather than RFC 1321 and FIPS 180-4. They now use the
specifications' own definitions and names, and tests recompute MD5's T table
and the SHA-2 constants and initial values from their mathematical
definitions.

### Previously recorded source-hygiene incident

While looking for an NTRUEncrypt oracle, one stream fetched libntruencrypt
sources from the HelloKitty ransomware analysis directory of the
`PacktPublishing/Malware-Development-for-Ethical-Hackers` repository,
knowingly, compiled 15 library C files into a static library, linked its own
harness against it, and ran the harness three times in a scratch directory.

- The one core file that differs from the legitimate upstream changes only
  pointer casts, `memset` to `SecureZeroMemory`, and a static-analyzer comment.
- No fetched file makes file, process, or network calls, and the binary
  imported only standard C I/O and memory functions.
- Nothing from that build reached the repository. The committed vectors come
  from a clean build of `jschanck-si/NTRUEncrypt` at `3d36004`, verified byte
  for byte.
- The artifacts were deleted after their SHA-256 digests were recorded.

Other copies not tied to an original project were also fetched:

- The same stream downloaded Security Innovation's sources from a personal
  GitHub copy of SUPERCOP (`floodyberry/supercop`). One platform header from
  it went into the build above.
- Another stream cloned an unofficial copy of the NTRU project
  (`di3online/ntru-crypto`) and read its function headers. Nothing was built
  from it.
- The lead cloned a personal fork (`Martinjdksn/ntru-crypto`) that holds only
  a README.

None of them contributed to the repository, and all were deleted.

### Previously recorded history rewrite

An implementer record written ahead of the push described the rewrite as
pushed with the four release tags. It has not been pushed: the implementer's
force-push was refused twice by a permission check, and GitHub still holds the
old history. In the prepared history, every commit before this work was
rewritten with git filter-repo. Where a version of a file held transcribed code, its contents were
replaced by a short note naming the source. Where only part of a file was
transcribed, just those functions were cut. Everything else in every commit is
unchanged, and commit messages, authors, dates and the release tags are
preserved. Most of those earlier commits no longer build.

- **Whole versions replaced:** SNOW 3G; Poly1305 from 2026-06-09; ML-KEM from
  2026-03-07; ML-DSA; the NTRU round-3 files; the NTRUEncrypt core and the
  early per-set files that held full copies of it.
- **Functions cut:** the BearSSL-derived GHASH multiply from 2026-07-20, the
  X25519 field inversion, ZUC's LFSR arithmetic, the NTRU test-only reference
  multiply, and the seeded `randombytes()` in the ML-DSA benchmark script.
- **Left alone:** the reference implementations vendored under `third_party/`,
  which were kept for reference, and the borderline hash code.

Across all 253 commits only those files changed, in 182 file versions. No
distinctive token of the copied code survives outside `third_party/`. A scan of
2,524 surviving file versions for lines cut from the originals found only the
crate's own test helpers and original documentation. The new tip builds and
passes 1,200 tests.

A history rewrite cannot reach copies elsewhere. The crates.io releases 0.5.0
through 0.6.2, and their source view on docs.rs, contain the transcribed code,
and GitHub may serve old commits by hash until it purges them.

## Companion ownership

DIEHARD sources, their preservation and finite-input battery support belong
in [entropy/SUGGESTIONS.md](../entropy/SUGGESTIONS.md). Entropy now tracks
Fortran and C source archives; the previous source-recovery concern is no
longer an open cryptography task. This pass does not modify active entropy.

## Reproduce the public-API checks

The client and both logs are in `/tmp/paused-review-jb_h_rke/client` and its
parent. For a future reproduction, create a disposable crate beside frozen
cryptography and rump copies with this manifest, add the Rust below as
`src/main.rs`, then run `cargo run --offline --bin paused-review-client -j 2`
and `cargo run --offline --bin paused-review-client --features wipe -j 2`. Successful execution reproduces
the listed NTRU discrepancies; it does not assert cryptographic correctness.

```toml
[package]
name = "paused-review-client"
version = "0.0.0"
edition = "2021"
[features]
wipe = ["cryptography-rs/wipe"]
[dependencies]
cryptography-rs = { path = "../cryptography" }
[profile.dev]
opt-level = 1
```

<details>
<summary>Public-API reproduction</summary>

```rust
use cryptography::{CtrDrbgAes256};
use cryptography::vt::*;
fn change_last(bytes: &mut [u8], n: usize) {
    let start=(n-1)*11;
    let mut value=0u16;
    for i in 0..11 {let b=start+i;value=(value<<1)|u16::from((bytes[b/8]>>(7-b%8))&1);}
    value=(value+1)&2047;
    for i in 0..11 {let b=start+i;let mask=1u8<<(7-b%8);bytes[b/8]=(bytes[b/8]&!mask)|((((value>>(10-i))&1) as u8)<<(7-b%8));}
}
macro_rules! run {
    ($scheme:ident,$ct:ident,$n:expr) => {{
        let mut rng=CtrDrbgAes256::new(&[0x53;48]);
        let (pk,sk)=$scheme::keygen(&mut rng);
        let mut accepted=0;let mut rejected=0;
        for _ in 0..32 {
            let msg=b"audit tail check";
            let ct=$scheme::encrypt(&pk,msg,&mut rng).unwrap();
            assert_eq!($scheme::decrypt(&sk,&ct).unwrap(),msg);
            let mut wire=ct.to_wire_bytes();let original=wire.clone();
            change_last(&mut wire,$n);assert_ne!(wire,original);
            let changed=$ct::from_wire_bytes(&wire).unwrap();
            match $scheme::decrypt(&sk,&changed) {
                Ok(m)=>{assert_eq!(m,msg);accepted+=1;},
                Err(_)=>rejected+=1
            }
        }
        println!("{}: accepted same plaintext after last-coefficient +1: {accepted}/32; rejected {rejected}",stringify!($scheme));
        assert_eq!(accepted,0,"tail encoding should now be canonical");
    }};
}


struct Coins { first: usize, zero_r: bool }
impl cryptography::Csprng for Coins {
    fn fill_bytes(&mut self,out:&mut [u8]) {
        out.fill(1);
        if self.zero_r {out[..self.first].fill(0);} else {out[self.first..].fill(0);}
    }
}
macro_rules! check_coins {
    ($scheme:ident,$n:expr,$zero_r:expr) => {{
        let mut rng=CtrDrbgAes256::new(&[0x64;48]);
        let (pk,sk)=$scheme::keygen(&mut rng);
        let (honest,sent)=$scheme::encaps(&pk,&mut rng);
        assert_eq!(sent.as_bytes(),$scheme::decaps(&sk,&honest).as_bytes());
        let (ct,sent)=$scheme::encaps(&pk,&mut Coins{first:$n-1,zero_r:$zero_r});
        let received=$scheme::decaps(&sk,&ct);
        println!("{} zero_{}: keys_match={}",stringify!($scheme),if $zero_r {"r"} else {"m"},sent.as_bytes()==received.as_bytes());
        assert_ne!(sent.as_bytes(),received.as_bytes());
    }};
}
fn main() {
    let mut bytes=[0xa5u8;37];
    cryptography::zeroize_slice(&mut bytes);
    println!("wipe_feature={} helper_clears={}",cfg!(feature="wipe"),bytes==[0;37]);
    check_coins!(NtruHps509,509,true);
    check_coins!(NtruHps677,677,true);
    check_coins!(NtruHps821,821,true);
    check_coins!(NtruHrss701,701,true);
    check_coins!(NtruHrss701,701,false);
    run!(NtruEes443Ep1,NtruEes443Ep1Ciphertext,443);
    run!(NtruEes1499Ep1,NtruEes1499Ep1Ciphertext,1499);
}
```

</details>

<details>
<summary>Public-key and container boundary reproduction</summary>

With the same manifest, save this as `src/bin/parser_boundaries.rs` and run
`cargo run --offline --bin parser_boundaries -j 2`. The invalid-key signature
is constructed from public data only. The other assertions record import
boundaries, not equivalent security impacts.

```rust
use cryptography::Sha256;
use cryptography::vt::*;
fn main() {
    let curve=p256();
    let key=EcdsaPublicKey::from_wire_bytes(curve.clone(), &[0]).expect("identity imported");
    assert!(key.public_point().is_infinity());
    let digest=Sha256::digest(b"audit identity-key boundary");
    let z=BigUint::from_be_bytes(&digest);
    let r=curve.scalar_mul(&curve.base_point(), &z).x.rem(&curve.n);
    let mut r_bytes=r.to_be_bytes();
    if r_bytes[0]&128!=0 {r_bytes.insert(0,0);}
    let mut der=vec![0x30, (r_bytes.len()+5) as u8, 0x02, r_bytes.len() as u8];
    der.extend_from_slice(&r_bytes); der.extend_from_slice(&[2,1,1]);
    let signature=EcdsaSignature::from_der(&der).unwrap();
    assert!(key.verify(&digest,&signature));
    println!("ECDSA: SEC1 identity accepted; signature constructed from public data verifies");
    assert!(EcdhPublicKey::from_wire_bytes(curve,&[0]).is_some());
    println!("ECDH: SEC1 identity accepted at import");
    let private=Ed25519PrivateKey::from_key_blob(&[0x11;32]).unwrap();
    let der=private.to_pkcs8_der();
    assert_eq!(der[0],0x30); assert!(der[1]<128);
    let mut ber=vec![0x30,0x80]; ber.extend_from_slice(&der[2..]); ber.extend_from_slice(&[0,0]);
    assert!(Ed25519PrivateKey::from_pkcs8_der(&der).is_some());
    assert!(Ed25519PrivateKey::from_pkcs8_der(&ber).is_none());
    println!("PKCS8: valid BER indefinite outer SEQUENCE refused by DER entry point");
    let mut torsion=[0xffu8;32]; torsion[0]=0xec; torsion[31]=0x7f;
    assert!(Ed25519PublicKey::from_raw_bytes(&torsion).is_none());
    println!("Ed25519: canonical order-two point refused at import (stricter policy)");
}
```

</details>
