# Sweep — 2026-09-17

Pilot-driven sweep of the symmetric, hash and public-key surfaces at
`23bd845`, taken after the audit round that renamed the tree's constants and
after the timing work in `scripts/ct_timing`.

## Instruments

```
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 PILOT_SESSION_LIMIT=300 \
  bash scripts/bench_all.sh        > <host>/symmetric.md
  bash scripts/bench_all_hash.sh   > <host>/hash.md
  bash scripts/bench_all_pk_full.sh > <host>/pk.md
```

`PILOT_SESSION_LIMIT` is new and is why this sweep finished: a key-generation
case searches for primes, so its timing has a long tail and its confidence
interval need never reach the preset's 10% target. Such a case now stops after
five minutes and is marked `(limit)`, which means the mean is of what was
measured and the interval is as wide as the tail made it. Three cases hit it
here — `elgamal_keygen_1024`, `dsa_keygen_1024` and `rsa_keygen_2048` — and
their intervals show why: ±31%, ±21% and ±22% of the mean after thousands of
rounds.

## Hosts

| Tag | Host | CPU | OS | Cores |
|---|---|---|---|---|
| `baase` | `baase` | Arm Cortex-X925 | Linux 7.0 (Ubuntu 24.04) | 20 (single-core slice) |

Each host was idle: its own benchmark was the only load.

## What is not here yet

An x86-64 column and an Apple-silicon column. Both EPYC hosts and the Apple
machine were running other people's work when this sweep ran; `twilight`'s
first attempt was discarded when another user's job took it to load 118 partway
through, and a benchmark taken under that is not worth keeping. `darby`
(Raspberry Pi 5) was still running when this was written.

Until those columns exist, the merged tables and the radar plots in
`ASYMMETRIC.md`, `SYMMETRIC.md` and `POSTQUANTUM.md` keep their earlier
figures, and their staleness notes stand.
