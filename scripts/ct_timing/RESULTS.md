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

| Experiment | Classes | dmz (Intel Xeon, idle) | dyson (Apple M4 Pro) | darby (Cortex-A76) |
|---|---|---|---|---|
| control: early-exit compare | differs at byte 0 / byte 31 | 1707 **flagged** | 49 **flagged** | 662 **flagged** |
| control: identical classes | differs at byte 31, both | 2.2 | 1.4 | 1.7 |
| `Hmac::<Sha256>::verify` | differs at byte 0 / byte 31 | 1.8 | 1.1 | 2.6 |
| `Hmac::<Sha256>::verify` | differs at byte 15 / byte 31 | 2.1 | 2.1 | 3.3 |
| `Aes128Ct::encrypt_block` | all-zero / dense key and block | 2.1 | 2.0 | 1.2 |
| `X25519::scalar_mult` | all-zero / dense scalar | 1.3 | 46 **flagged** | 2.1 |
| `X25519::scalar_mult` | two ordinary fixed scalars | 1.6 | 2.2 | 2.2 |
| `X25519::scalar_mult` | low-order point / base point | 1.0 | 1.8 | 28 **flagged** |
| `MlKem::decaps` | well-formed / tampered ciphertext | 1.6 | 1.3 | 1.7 |

Each column is one run under rustc 1.93.1: dmz is an idle Intel machine with the
run pinned to four cores, dyson an Apple M4 Pro under macOS 27.0, darby a
Raspberry Pi 5 under Linux 6.18. The dyson scalar figure reproduced at 44, 46,
47, 51 and 52 across five runs; the darby point figure is from its one run with
this harness.

## Degenerate inputs, and only on the ARM hosts

Two pairs are flagged, each on one host and each contrasting a degenerate input
with an ordinary one:

- On the Apple host, an all-zero scalar. Clamping turns it into exactly `2^254`,
  so RFC 7748's conditional swap fires once and then never again through 254
  rounds, against about 127 times for a dense scalar.
- On the Raspberry Pi, `u = 1` as the peer's point, which keeps the ladder's
  field elements small and structured where an ordinary point makes them look
  random.

Neither host flags the other's pair, the idle Intel host flags neither, and no
host separates two ordinary scalars. The machine-code evidence in
`scripts/ct_budgets/` shows no branch and no secret-dependent index anywhere in
the ladder, and `fe_cswap` touches every limb whatever the mask says, so this is
not the code taking a different path for one class. It is the same instructions
over different data, finishing at different speeds on those processors.

What that is worth knowing for:

- The comparison that bears on key recovery is two ordinary scalars, and no host
  separates them.
- An all-zero scalar is not a key, but the *reason* it separates — how often the
  swap fires — is a property of the secret scalar. This experiment compared the
  extreme (one swap) against a typical scalar (about 127); it did not ask
  whether two ordinary scalars whose swap counts differ by a few are
  distinguishable, and that is the experiment to run next.
- A low-order peer point is chosen by whoever sends it, and the agreement
  refuses the all-zero shared secret it produces, so a timing difference there
  tells an attacker only what they already know.
