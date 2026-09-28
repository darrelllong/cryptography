# Sweep — 2026-09-28

The Cortex-X925 column of the symmetric, hash and public-key surfaces, taken
again after two corrections to Pilot
([pilot-bench](https://github.com/darrelllong/pilot-bench), `doc/changelog.rst`):

- `f01eec4` replaced the change-point detection and corrected several of
  Pilot's statistics.
- `475063f` averages a performance index of type 1 (a rate) by its harmonic
  mean and finds its interval from the reciprocals of the readings. Before it,
  every index was averaged arithmetically, whatever its declared type.

Only `baase` was available, so the other three columns of the published tables
are still those of the [2026-09-23 sweep](../sweep-2026-09-23/README.md),
produced with Pilot before `f01eec4`.

## Instruments

```
# public key: Pilot f01eec4 (baase/run-pk.sh)
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 PILOT_SESSION_LIMIT=300 \
  taskset -c 9 bash scripts/bench_all_pk_full.sh > baase/pk.md
# symmetric and hash: Pilot 475063f (baase/run-rates.sh)
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 PILOT_SESSION_LIMIT=300 \
  taskset -c 9 bash scripts/bench_all.sh      > baase/symmetric.md
  taskset -c 9 bash scripts/bench_all_hash.sh > baase/hash.md
```

The same preset, confidence level and session limit as the 2026-09-17 and
2026-09-23 sweeps. Pilot and every workload process ran on CPU 9, one of the
ten Cortex-X925 cores (the other ten are Cortex-A725), with the `performance`
governor. `baase/run-rates.sh` also ran the Delta-Compression benchmarks after
these; they are recorded in that repository.

The public-key sessions were run with `f01eec4` and with `ms/op` declared as
type 1, as the script then declared it. `f01eec4` averaged type 1
arithmetically, exactly as type 0, so these are the type-0 results; a time per
operation is not a rate, and the scripts now declare it as type 0. They were
not run again with `475063f`, which changes nothing for type 0 at this
confidence level. The symmetric and hash sessions measure rates (MB/s, type 1)
and were first run with `f01eec4`; those results were arithmetic means of
rates and were discarded, and the sessions were run again with `475063f`.

## Host

| Tag | CPU | OS | Toolchain | Code |
|---|---|---|---|---|
| `baase` | Arm Cortex-X925 (NVIDIA GB10), 3.9 GHz, pinned to CPU 9 | Linux 7.0 (Ubuntu 24.04.5) | rustc 1.95.0 | cryptography `a2b6ddf`, rump `686cfcd` |

`baase` was idle apart from a resident vLLM/Ray inference service that was
serving nothing (GPU 0%, CPUs 99.4% idle before each run). The load average,
sampled at the start and end of each run, was between 0.07 and 1.26; the
benchmark itself keeps one core busy.

The public-key sessions took 384 s (13:26–13:34 PDT), the symmetric 82 s and
the hash 1 s (14:25–14:27 PDT).

## The CI column

Pilot prints the full width of the confidence interval, and the `normal`
preset stops when that width is at most 10% of the mean. For a time (type 0)
the interval is the mean plus or minus half of the width. For a rate (type 1)
under `475063f` it is found from the reciprocals and is not symmetric about the
harmonic mean; the table gives its width. Tables before this one printed the
width as `±CI` and the documentation called it a half-width, which was wrong by
a factor of two. The scripts now print it under `CI width`, without the sign,
and `merge_pilot_tables.py` reads both forms and writes `CI width`. The older
columns in the merged tables are the numbers they always were.

## The merge

```
python3 scripts/merge_pilot_tables.py --mode {sym,hash,pk} \
  --input "EPYC 7452=bench/sweep-2026-09-23/twilight/<file>.md" \
  --input "i5-8259U=bench/sweep-2026-09-23/dmz/<file>.md" \
  --input "Cortex-A76=bench/sweep-2026-09-23/darby/<file>.md" \
  --input "Cortex-X925=bench/sweep-2026-09-28/baase/<file>.md" \
  --out bench/sweep-2026-09-28/merged/<file>.md
python3 scripts/build_radar_csvs.py --sweep sweep-2026-09-28 \
  --platforms "EPYC 7452,i5-8259U,Cortex-A76,Cortex-X925" \
  --columns   "EPYC 7452,i5-8259U,Cortex-A76,Cortex-X925"
python3 scripts/generate_platform_radar.py --csv bench/sweep-2026-09-28/csv/<set>.csv \
  --out assets/sweep-2026-09-28-<set>-radar.svg --title "…" --units "…" \
  --legend "EPYC 7452 (2026-09-23, Pilot before f01eec4);…;Cortex-X925 (2026-09-28, Pilot <commit>)"
```

The legend names `475063f` on the symmetric and hash radars and `f01eec4` on
the public-key radars.

## What changed from the Cortex-X925 column of 2026-09-17

That column was taken on the same machine with a Pilot from before `f01eec4`,
at cryptography `23bd845`.

- **Every session converged.** `elgamal_keygen_1024`, `dsa_keygen_1024` and
  `rsa_keygen_2048` stopped at the five-minute limit in 2026-09-17, after
  4,245, 2,868 and 1,626 rounds with interval widths of 31%, 21% and 22% of
  the mean. Here they reached the 10% target after 590, 400 and 318 rounds,
  at 8.4%, 8.3% and 8.4%. Pilot's changelog describes the cause: the old
  change-point detection always accepted a first change-point and used only
  the readings after the last one, so a session that needed more than about
  60 readings worked from the last 30 to 60 of them.
- **Intervals are narrower and sessions shorter.** The median interval width
  fell from 3.7% to 0.24% of the mean for the symmetric cases, 3.4% to 1.8%
  for the hashes, and 5.6% to 0.41% for the public-key cases; the rounds run
  fell from 11,001 to 5,731, 2,259 to 1,024, and 24,384 to 10,205.
- **Most means agree.** The median ratio of new to old mean is 1.02
  (symmetric), 1.01 (hash) and 0.98 (public key). Thirteen symmetric cases
  measure 8–21% higher than before, six of them constant-time variants; their
  2026-09-17 intervals were 3.5–8.3% of the mean.
- **Changes in the code, not in Pilot.** `ed25519_keygen` and `ed25519_sign`
  are 11–14 times faster (the fixed-base comb of 0.8.0), and the four X25519
  cases 1.28–1.32 times slower. X25519 moved onto the shared `fe25519` field
  arithmetic between the two commits, and the i5-8259U and Cortex-A76 show a
  similar slowdown (1.27 and 1.25 times for `x25519_agree`) between the
  2026-09-17 and 2026-09-23 sweeps, both taken with the old Pilot.
