# Interleaved input-class timing runs

Each row is one run of `scripts/ct_timing` at the protocol its source fixes:
800,000 measurements per experiment, the first 10,000 discarded, classes drawn
by a seeded coin and interleaved, tails cropped at ten percentiles, and the
statistic the largest `|t|` over those crops — computed on the first quarter of
the measurements and on all of them — against dudect's threshold of 4.5.

Two controls bracket every run. The positive control is a comparison that stops
at the first differing byte and must be flagged; a run that does not flag it has
not shown the apparatus can see a leak, and its other results say nothing. The
negative control is a pair of identical classes and must not be flagged; if it
is, the apparatus separates equal inputs and the run says nothing either.

Every pair is two *fixed* values. A class of fresh random inputs leaves the
machine in a different state from one that repeats a single input, and for an
operation as large as a scalar multiplication that difference alone was enough:
a fixed scalar against random scalars gave `|t| = 10.4` on an idle host where
two fixed scalars gave 0.9.

A statistic below the threshold is not proof of constant time. It says this
experiment, at this sample size, on this machine, found no difference.

## 2026-09-17

| Experiment | Classes | dmz (Intel, idle) | dyson (Apple M4 Pro, shared) |
|---|---|---|---|
| control: early-exit compare | differs at byte 0 / byte 31 | 1386–1617 **flagged** | 53 **flagged** |
| control: identical classes | differs at byte 31, both | 1.7–2.7 | 1.0 |
| `Hmac::<Sha256>::verify` | differs at byte 0 / byte 31 | 1.9–2.0 | 3.0 |
| `Hmac::<Sha256>::verify` | differs at byte 15 / byte 31 | 4.2–4.3 | 2.0 |
| `Aes128Ct::encrypt_block` | all-zero / dense key and block | 1.3–1.6 | 0.5 |
| `X25519::scalar_mult` | all-zero / dense scalar | 0.9–1.7 | 44–51 **flagged** |
| `X25519::scalar_mult` | two ordinary fixed scalars | 1.4–2.3 | 2.1–2.6 |
| `X25519::scalar_mult` | low-order point / base point | 1.0–1.5 | 1.3–1.7 |
| `MlKem::decaps` | well-formed / tampered ciphertext | 1.8–3.4 | 1.0–2.4 |

Both hosts ran rustc 1.93.1. dmz is an idle Intel machine with the run pinned to
four cores; dyson is an Apple M4 Pro (macOS 27.0) that was running other work,
which is why its marginal statistics move more between runs. The dmz figures
span two consecutive runs, the dyson ones three.

## The scalar that never swaps

On the Apple host, and only there, an all-zero scalar is distinguishable from a
dense one: `|t|` of 44, 47 and 51 across three runs, each with the quarter
statistic already past the threshold. That host separates neither two ordinary
scalars nor a low-order point from the base point, its negative control is
quiet, and the idle Intel host separates nothing at all.

What differs between those two classes is the conditional swap. RFC 7748's
ladder swaps on `k_t ⊕ k_{t-1}`, and clamping turns an all-zero scalar into
exactly `2^254`: one swap at the top bit and none in the remaining 254 rounds,
against about 127 for a dense scalar. `fe_cswap` is branch-free and touches
every limb either way, and the machine-code evidence in `scripts/ct_budgets/`
shows no branch and no secret-dependent index anywhere in the ladder, so what
the measurement sees is not the code taking a different path. It is the same
instructions writing values that do not change, which a processor may complete
differently from ones that do.

Two things follow. An all-zero scalar is not a key, and the comparison that
bears on key recovery — two ordinary scalars — separates nothing on either
host. And a constant-time claim of this kind is a claim about the code, which
the machine-code evidence supports; what a particular processor does with the
data is a separate question, which only measurement on that processor answers.
