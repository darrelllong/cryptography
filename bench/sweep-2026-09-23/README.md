# Sweep — 2026-09-23

Pilot-driven sweep of the symmetric, hash and public-key surfaces for 0.8.0,
taken after Ed25519 signing and key generation moved onto the constant-time
fixed-base comb. `dmz` and `darby` ran at `7bbcab2`, `twilight` at
`ad7655c`; the only difference between those commits is a codegen budget file
and a harness change, so no code any case measures differs and the columns
compare.

## Instruments

```
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 PILOT_SESSION_LIMIT=300 \
  bash scripts/bench_all.sh        > <host>/symmetric.md
  bash scripts/bench_all_hash.sh   > <host>/hash.md
  bash scripts/bench_all_pk_full.sh > <host>/pk.md
```

The same instrument as the 2026-09-17 sweep. Three key-generation cases hit
the five-minute session limit on every host and are marked `(limit)`:
`elgamal_keygen_1024`, `dsa_keygen_1024` and `rsa_keygen_2048`, whose prime
searches have tails the 10% confidence target need never reach.

## Hosts

| Tag | CPU | OS | Cores | Toolchain |
|---|---|---|---|---|
| `twilight` | AMD EPYC 7452 | Linux (Ubuntu) | 64 (single-core slice) | rustc 1.95.0 |
| `dmz` | Intel Core i5-8259U | Linux 7.0 (Ubuntu) | 8 (single-core slice) | rustc 1.93.1 |
| `darby` | Arm Cortex-A76 (Raspberry Pi 5) | Linux 6.18 (Debian) | 4 (single-core slice) | rustc 1.93.1 |

Each host was idle: its own benchmark was the only load. `twilight` is the
EPYC column the 2026-09-17 sweep could not get, that machine having carried
other users' work throughout; this time its load average was 0.00 at the
start.

## The merge

```
python3 scripts/merge_pilot_tables.py --mode {sym,hash,pk} \
  --input "EPYC 7452=<sweep>/twilight/<file>.md" \
  --input "i5-8259U=<sweep>/dmz/<file>.md" \
  --input "Cortex-A76=<sweep>/darby/<file>.md" \
  --out <sweep>/merged/<file>.md
python3 scripts/build_radar_csvs.py --sweep sweep-2026-09-23 \
  --platforms "EPYC 7452,i5-8259U,Cortex-A76" \
  --columns   "EPYC 7452,i5-8259U,Cortex-A76"
python3 scripts/generate_platform_radar.py --csv <sweep>/csv/<set>.csv \
  --out assets/sweep-2026-09-23-<set>-radar.svg --title "…" --units "…"
```

## What is not here

No Apple-silicon column. `dyson` (Apple M4 Pro) was carrying another
session's test binaries at three full cores throughout, and `tolkien`'s
checkout was no longer present. The 2026-09-17 sweep's Apple M1 column stands
for everything but Ed25519 key generation and signing, which changed between
the two sweeps.

No Cortex-X925 column, by decision: `baase` was running another user's
inference job at 87% of a core for two and a half days, and a column taken
under that is noise. Its 2026-09-17 column stands on the same terms as the
Apple one.

## What changed since 2026-09-17

Ed25519 signing and key generation. On the i5-8259U, present in both sweeps,
`ed25519_sign` went from 0.4889 ms to 0.0385 ms and `ed25519_keygen` from
0.4932 ms to 0.0465 ms; on the Cortex-A76, from 0.8282 ms to 0.1134 ms and
0.8327 ms to 0.1437 ms. `ed25519_verify` is unchanged on both, as it should
be: verification still uses the generic arithmetic, since it reads only
public data.
