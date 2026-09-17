# Interleaved input-class timing runs

Each row is one run of `scripts/ct_timing` at the protocol its source fixes:
200,000 measurements per experiment, the first 10,000 discarded, classes drawn
by a seeded coin and interleaved, tails cropped at ten percentiles, and the
statistic the largest `|t|` over those crops against dudect's threshold of 4.5.

A run counts only if its positive control — a comparison that stops at the
first differing byte — is flagged. A statistic below the threshold is not proof
of constant time; it says this experiment, at this sample size, on this machine,
found no difference.

## 2026-09-17

| Experiment | Classes | Wigner, aarch64-apple-darwin | dmz, x86_64-unknown-linux-gnu |
|---|---|---|---|
| control: early-exit compare | differs at byte 0 / byte 31 | 29.6 **flagged** | 378.9 **flagged** |
| `Hmac::<Sha256>::verify` | differs at byte 0 / byte 31 | 4.2 | 2.1 |
| `Aes128Ct::encrypt_block` | fixed / random key and block | 1.6 | 1.4 |
| `X25519::scalar_mult` | fixed / random scalar | 1.2 | 3.3 |
| `X25519::scalar_mult` (point) | low-order / random point | 1.5 | 1.3 |
| `Hmac::<Sha256>::verify` (middle) | differs at byte 15 / byte 31 | 1.0 | 1.2 |

Both hosts ran rustc 1.93.1; Wigner is an Apple M1 Max, dmz an idle Intel
machine with the run pinned to four cores. Every class pair draws the same
bytes and copies the same buffers before the timed span, and a key schedule is
built outside it, so what differs between two classes is the value the
operation is given.

The tag comparison's statistic moves between 2 and 4.2 across runs on Wigner,
near the threshold: a one-microsecond operation is at this apparatus's
resolution there, and a run that wanted to separate a smaller difference would
need more measurements than the protocol takes.

The control's statistic differs by two orders of magnitude between the hosts,
which is what one should expect: it measures how well that machine resolves a
difference of a few hundred nanoseconds, not how large the leak is.
