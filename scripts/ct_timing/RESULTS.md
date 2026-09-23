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

Every pair is two *fixed* values, each fixture built once and copied whole into
the slot the timed span reads. Four versions of this program have measured
themselves instead of the crate, and each flag went away when the classes were
made to differ only in the secret:

- one drew random bytes for one class and not the other;
- one flipped a tag byte at a different offset per class, immediately before
  the comparison read it;
- one let the two classes share two long-lived AEAD ciphers, one of which the
  previous experiment had just run 800,000 times, so the classes differed in
  cache state as well as in key: 1589 on one host, 5.1 on another, 1.8 once
  each class built its own;
- one handed the timed span a reference to one of two message fixtures rather
  than copying the chosen one into a single buffer, so the classes differed in
  where their message sat: 12.2 on an idle Intel host, 1.9 once they shared a
  slot.

Two fixtures at two addresses is the subtlest of these, and the reason the rule
is *copy into one slot* rather than *point at one of two*.

A statistic below the threshold is not proof of constant time. It says this
experiment, at this sample size, on this machine, found no difference.

## 2026-09-17

Every column is one run of the whole battery at `e312ab3`, so the rows compare.

| Experiment | Classes | dmz (i5-8259U) | dyson (Apple M4 Pro) | darby (Cortex-A76) | baase (Cortex-X925) |
|---|---|---|---|---|---|
| control: early-exit compare | differs at byte 0 / byte 31 | 1119 **flagged** | 50 **flagged** | 651 **flagged** | 268 **flagged** |
| control: identical classes | differs at byte 31, both | 1.7 | 2.3 | 1.4 | 1.9 |
| `Hmac::<Sha256>::verify` | differs at byte 0 / byte 31 | 2.4 | 1.3 | 2.0 | 2.6 |
| `Hmac::<Sha256>::verify` | differs at byte 15 / byte 31 | 1.1 | 2.0 | 2.2 | 1.8 |
| `Aes128Ct::encrypt_block` | all-zero / dense key and block | 1.4 | 0.6 | 2.2 | 0.4 |
| `X25519::scalar_mult` | all-zero / dense scalar | 1.1 | 14.2 **flagged** | 2.6 | 1.4 |
| `X25519::scalar_mult` | two ordinary fixed scalars | 1.4 | 1.4 | 1.2 | 0.8 |
| `X25519::scalar_mult` | alternating bits / long runs | 1.0 | 15.1 **flagged** | 1.2 | 1.5 |
| `X25519::scalar_mult` | low-order point / base point | 2.6 | 1.3 | 6.9 **flagged** | 1.3 |
| `ChaCha20Poly1305::open` | tag differs at byte 0 / byte 7, both reject | 1.1 | 1.6 | 1.8 | 0.7 |
| `ChaCha20Poly1305::open` | two keys, both accept | 3.2 | 1.1 | 3.9 | 2.4 |
| `Ed25519::sign_message` | dense seed / one-bit seed | 66 **flagged** | 19 **flagged** | 426 **flagged** | 5.3 **flagged** |
| `Ed25519::sign_message` | one key, nonce of 97 / 157 set bits | 7.9 **flagged** | 7.2 **flagged** | 244 **flagged** | 35 **flagged** |
| `MlKem::decaps` | well-formed / tampered ciphertext | 1.1 | 0.7 | 1.2 | 1.4 |

The hosts: dmz an idle Intel Core i5-8259U under Linux, pinned to four cores;
dyson an Apple M4 Pro under macOS 27.0, this session's own machine, which was
doing nothing else during its run but is not a quiet benchmark host; darby a
Raspberry Pi 5 under Linux 6.18; baase an idle heterogeneous ARM machine under
Linux 7.0, pinned to five Cortex-X925 cores of one cluster so the run cannot
migrate to the Cortex-A725 cores beside them, which run at a different
frequency.

The dyson column's magnitudes are lower than earlier runs of the same
experiments — 14.2 where five earlier runs gave 44 to 52 — and its control is
lower too, which is what a less quiet machine looks like; which pairs separate
is unchanged. The `ChaCha20Poly1305::open` pair on two accepting keys reached
5.0 on the Raspberry Pi in an earlier run, over the threshold but growing only
1.18× from its quarter statistic, which by this file's rule is not a flag; it
is 3.9 here and quiet on the other three hosts.

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

## Ed25519 signing publishes its nonce

Signing separates two secret keys on every host — 66, 19, 426 and 5.3 — which
the crate's policy allows: public-key code here is variable-time by design,
X25519 and X448 excepted, and the module says so. What the policy does not say,
and what the second experiment measures, is *which* secret the timing follows.

One key signs two messages. Everything is fixed but the nonce `r`, which
RFC 8032 derives as `H(prefix ‖ M) mod L`; the two messages were searched for
beforehand, over twenty thousand candidates, as the ones whose reduced nonces
have the fewest and the most set bits — 97 against 157. They separate on every
host: 7.9, 7.2, 244 and 35.

The code says why. `scalar_mul_with_table` runs one window per
`ED25519_BASE_WINDOW_BITS` bits of the scalar, so the loop count follows `r`'s
bit length, and each window reads `table[value]` from 256 precomputed extended
points with 8 bits of `r` as the index, so the memory pattern follows `r`'s
value. A sparse nonce reads a few entries many times and a dense one reads
many; that difference is what the statistic sees.

This is the leak a signature scheme can least afford. A key is used for many
signatures and an attacker sees the timing of each, while partial knowledge of
many nonces recovers the private key by lattice reduction — the attack that
`k`-bias and `k`-leak papers have been building since the first ECDSA nonce
results. The private key's own scalar `a` is multiplied by the same code, so
`A = a·B` at key generation leaks in the same way, once.

Closing it means a fixed-base multiplication whose loop count and memory
pattern do not depend on the scalar: a fixed number of windows over the full
scalar length, and a table read that touches every entry under a mask, as
`fe_cswap` does in the X25519 ladder. That is the research-grade
constant-time public-key work this crate's README puts out of scope, and it is
the owner's call whether Ed25519 should be the exception beside X25519 and
X448. Until then the honest statement is the one the module now carries: this
signing implementation is unsuitable where an attacker can time it, and the
quantity it publishes is the nonce.

## What scalar blinding would cost, and why it is not here

The channel is the swap count, a property of the secret scalar, so the
countermeasure that would close it is one that makes the scalar's bit pattern
differ from call to call: replace `k` by `k + rM` for a random `r` and a
modulus `M` that leaves every result unchanged. What `M` has to be decides the
price.

RFC 7748 §5 defines `X25519(k, u)` for every 32-byte `u`, which includes the
points of the quadratic twist; §6.1's warning is about the shared secret, not
about which `u` the function accepts. So `M` must annihilate every point the
function may be handed:

- Curve25519's group order is `8ℓ`, `ℓ = 2^252 + 27742317777372353535851937790883648493`.
- Its twist's is `4ℓ'`, `ℓ' = 2^253 - 55484635554744707071703875581767296995`,
  from `#E + #E_twist = 2p + 2`. Both `ℓ` and `ℓ'` are prime.
- Any point on either curve has order dividing one of them, so
  `M = lcm(8ℓ, 4ℓ') = 8ℓℓ'`, which is 508 bits.

The ladder's cost is linear in the scalar's length, so with a 64-bit `r` the
scalar is 572 bits and the ladder takes 2.24 times as long. Blinding by the
curve order alone — 320 bits, 1.25 times as long — changes the result for
twist inputs, which is not X25519 as the RFC defines it, and this crate obeys
the standard it names.

Against that: what the measurement found is an aggregate over the whole
scalar, the same for every call with that key, on one of four processors, in
the pair that contrasts alternating bits with long runs. Two ordinary scalars
of similar swap count are not separated on any host. A 2.24-fold cost on every
agreement is not a trade this crate makes for that, and a 1.25-fold one is not
available at all. The door stays open: if a caller's threat model puts the
few bits of aggregate at issue, blinding by `8ℓℓ'` is what it would take, and
the measurement above is what it would have to be re-run against.

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
