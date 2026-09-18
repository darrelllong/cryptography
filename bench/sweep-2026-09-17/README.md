# Sweep — 2026-09-17

Pilot-driven sweep of the symmetric, hash and public-key surfaces, taken
after the audit round that renamed the tree's constants and after the timing
work in `scripts/ct_timing`.

`baase` and `darby` ran at `23bd845`, `tolkien` and `dmz` at `c804c50`. The
only library difference between those commits is the new HPKE module and the
two lines that register it; no code any of these cases measures changed, so
the columns compare.

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

| Tag | CPU | OS | Cores | Toolchain |
|---|---|---|---|---|
| `dmz` | Intel Core i5-8259U | Linux 7.0 (Ubuntu) | 8 (single-core slice) | rustc 1.93.1 |
| `tolkien` | Apple M1 | macOS 26.5 | 8 (single-core slice) | rustc 1.98.0 |
| `baase` | Arm Cortex-X925 | Linux 7.0 (Ubuntu 24.04) | 20 (single-core slice) | rustc 1.95.0 |
| `darby` | Arm Cortex-A76 (Raspberry Pi 5) | Linux 6.18 (Debian) | 4 (single-core slice) | rustc 1.93.1 |

The compilers differ with the hosts, which is part of what each column
measures: a figure here is this crate, on this machine, through that
compiler.

Each Linux host was idle: its own benchmark was the only load. No Mac is ever
idle, so `tolkien`'s notes record what its background daemons were using at
the start and end of its run — 138% and 154% of one core, out of eight — in
place of a claim it was quiet.

## The merge

```
python3 scripts/merge_pilot_tables.py --mode {sym,hash,pk} \
  --input "i5-8259U=<sweep>/dmz/<file>.md" \
  --input "Apple M1=<sweep>/tolkien/<file>.md" \
  --input "Cortex-X925=<sweep>/baase/<file>.md" \
  --input "Cortex-A76=<sweep>/darby/<file>.md" \
  --out <sweep>/merged/<file>.md
python3 scripts/build_radar_csvs.py --sweep sweep-2026-09-17 \
  --platforms "i5-8259U,Apple M1,Cortex-X925,Cortex-A76" \
  --columns   "i5-8259U,Apple M1,Cortex-X925,Cortex-A76"
python3 scripts/generate_platform_radar.py --csv <sweep>/csv/<set>.csv \
  --out assets/sweep-2026-09-17-<set>-radar.svg --title "…" --units "…"
```

The three scripts took exactly three platforms until this sweep; they take any
number now, which is why the column order is the order of the `--input` flags.

## What is not here

No EPYC column. Both EPYC hosts were running other users' work throughout;
`twilight`'s first attempt was discarded when another user's job took it to
load 118 partway through, and a benchmark taken under that is not worth
keeping. The x86-64 column here is a mobile part, which is what was idle.
