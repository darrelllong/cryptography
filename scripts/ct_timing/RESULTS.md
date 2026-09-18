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

Every pair is two *fixed* values, each fixture built once and copied whole. Two
earlier versions of this program measured themselves instead of the crate: one
drew random bytes for one class and not the other, and one flipped a tag byte at
a different offset per class immediately before the comparison read it. Both
produced flags that went away when the classes were made to do identical work.

A statistic below the threshold is not proof of constant time. It says this
experiment, at this sample size, on this machine, found no difference.

## 2026-09-17

| Experiment | Classes | dmz (Intel Xeon, idle) | dyson (Apple M4 Pro) | darby (Cortex-A76) | baase (Cortex-X925) |
|---|---|---|---|---|---|
| control: early-exit compare | differs at byte 0 / byte 31 | 1707 **flagged** | 49 **flagged** | 662 **flagged** | 247 **flagged** |
| control: identical classes | differs at byte 31, both | 2.2 | 1.4 | 1.7 | 1.6 |
| `Hmac::<Sha256>::verify` | differs at byte 0 / byte 31 | 1.8 | 1.1 | 2.6 | 1.9 |
| `Hmac::<Sha256>::verify` | differs at byte 15 / byte 31 | 2.1 | 2.1 | 3.3 | 0.8 |
| `Aes128Ct::encrypt_block` | all-zero / dense key and block | 2.1 | 2.0 | 1.2 | 1.3 |
| `X25519::scalar_mult` | all-zero / dense scalar | 1.3 | 46 **flagged** | 2.1 | 1.8 |
| `X25519::scalar_mult` | two ordinary fixed scalars | 1.6 | 2.2 | 2.2 | 2.5 |
| `X25519::scalar_mult` | alternating bits / long runs | 1.3 | 11–13 **flagged** | 1.8 | 2.8 |
| `X25519::scalar_mult` | low-order point / base point | 1.0 | 1.8 | 28 **flagged** | 1.3 |
| `MlKem::decaps` | well-formed / tampered ciphertext | 1.6 | 1.3 | 1.7 | 0.5 |

Each column is one run: dmz is an idle Intel machine with the run pinned to four
cores, dyson an Apple M4 Pro under macOS 27.0, darby a Raspberry Pi 5 under
Linux 6.18, all three under rustc 1.93.1; baase is an idle heterogeneous ARM
machine under Linux 7.0 and rustc 1.95.0, with the run pinned to five Cortex-X925
cores of one cluster so it cannot migrate to the Cortex-A725 cores beside them,
which run at a different frequency. The dyson scalar figure reproduced at 44, 46,
47, 51 and 52 across five runs; the darby column is the larger of two runs,
whose point figures were 28 and 16.5.

## Degenerate inputs, and only on two hosts

Two pairs are flagged, each on one host and each contrasting a degenerate input
with an ordinary one:

- On the Apple host, an all-zero scalar. Clamping turns it into exactly `2^254`,
  so RFC 7748's conditional swap fires once and then never again through 254
  rounds, against about 127 times for a dense scalar.
- On the Raspberry Pi, `u = 1` as the peer's point, which keeps the ladder's
  field elements small and structured where an ordinary point makes them look
  random.

Neither host flags the other's pair, neither the idle Intel host nor the
Cortex-X925 flags either, and no host separates two ordinary scalars of similar
swap count — the section below takes up the pair that does. The machine-code evidence in
`scripts/ct_budgets/` shows no branch and no secret-dependent index anywhere in
the ladder, and `fe_cswap` touches every limb whatever the mask says, so this is
not the code taking a different path for one class. It is the same instructions
over different data, finishing at different speeds on those processors.

## The swap count is what the Apple host sees

The experiment the all-zero scalar asked for has now been run: two *ordinary*
scalars, one of alternating bits (the swap fires on almost every round) and one
of long runs (about a sixth of them). On the Apple host they separate at `|t|`
of 11.0 and 13.2 over two runs, each growing from a quarter statistic near 4;
on the idle Intel host the same pair gives 1.3, on the Cortex-X925 2.8 and on
the Raspberry Pi 1.8. Two ordinary scalars whose swap counts are alike stay
quiet on every host.

So what that processor resolves is not a degenerate input but how often the
ladder's conditional swap fires, which is a property of the secret scalar: the
number of positions where consecutive bits differ. It is an aggregate over the
whole scalar, the same for every call with that key, so what it can give an
attacker who times many agreements is a few bits about the key, not the key.

**A countermeasure was tried and not kept.** `fe_cswap` writes each limb twice,
and with `swap == 0` the plain form stores the value the limb already holds. An
alternative that XORs a nonzero constant in and out — so no store is ever a
no-op, with a compiler fence between the passes to keep them apart — halved the
statistic (46 to 10 for the degenerate pair, 11–13 to 7.5 for the ordinary one)
without removing it, at a measured cost of 11% on the ladder (20.8 s against
18.7 s for a million scalar multiplications). A store that leaves the value
unchanged is therefore part of what is observable, but not all of it, and an
11% cost for a distinguisher that remains is not a trade worth making. The
emitted code was checked: the two passes survived, the constant appears sixty
times in the ladder.

What the measurement is worth knowing for:

- The comparison that bears on key recovery is two ordinary scalars of similar
  swap count, and no host separates them.
- A low-order peer point is chosen by whoever sends it, and the agreement
  refuses the all-zero shared secret it produces, so a timing difference there
  tells an attacker only what they already know.
- The machine code holds no branch and no secret-dependent index, on either
  architecture, which `scripts/ct_budgets/` records. What remains is what a
  processor does with the data, and the answer differs between processors:
  four hosts, two of them ARM, and each flagged pair belongs to exactly one of
  them. A newer ARM core than the Pi's, the Cortex-X925, separates none of the
  pairs at all.
