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

| Host | Target | Compiler | Control | `Hmac::<Sha256>::verify` | `Aes128Ct::encrypt_block` | `X25519::scalar_mult` |
|---|---|---|---|---|---|---|
| Wigner (Apple M1 Max) | aarch64-apple-darwin | rustc 1.93.1 | 39.4 **flagged** | 2.8 | 3.0 | 1.4 |
| dmz (Intel, idle, 4 cores pinned) | x86_64-unknown-linux-gnu | rustc 1.93.1 | 817.6 **flagged** | 1.9 | 1.3 | 2.3 |

The classes are, for the tag comparison, a tag that differs in its first byte
against one that differs in its last; for AES-128 and the ladder, a fixed key
or scalar against random ones, with both classes drawing the same bytes and
building their key schedule outside the timed span.

The control's statistic differs by two orders of magnitude between the hosts,
which is what one should expect: it measures how well that machine resolves a
difference of a few hundred nanoseconds, not how large the leak is.
