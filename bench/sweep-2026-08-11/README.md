# Public-key Pilot sweep — 2026-08-11

Pilot-bench sweep of the full public-key surface (finite-field, elliptic-curve,
and post-quantum) on the current tree, taken after two changes that move
public-key timing:

1. the multiprecision layer moved to the sibling
   [rump](https://github.com/darrelllong/rump) crate (crates.io `rust-mp`), and
2. prime-curve scalar multiplication moved fully into the Montgomery domain,
   recovering a regression that a windowed-scalar-mult change had left sitting
   on top of encode/decode-bound field arithmetic.

**Scope: public-key only.** Symmetric-cipher and hash throughput are untouched
by the multiprecision work, so they were not re-swept; their radars and tables
remain the 2026-06-11 numbers. The merged tables here feed the public-key
sections of [`ASYMMETRIC.md`](../../ASYMMETRIC.md) and
[`POSTQUANTUM.md`](../../POSTQUANTUM.md).

## Hosts

| Tag | Host | CPU | OS | Cores |
|---|---|---|---|---|
| `tolkien`  | `tolkien`               | Apple M1                     | Darwin 25.5.0 (macOS)         | 8 |
| `twilight` | `twilight.soe.ucsc.edu` | AMD EPYC 7452                | Linux 6.2.0 (Ubuntu 22.04)    | 128 (single-core slice) |
| `heinlein` | `heinlein`              | NVIDIA Jetson (Tegra, ARMv8) | Linux 5.15.185-tegra (Ubuntu) | 8 |

**Host substitution.** The 2026-06-11 sweep's EPYC host, `dennard`, lost its
Boost 1.74 runtime to an OS upgrade (the pilot-bench binary would no longer
load), so this sweep uses `twilight` — the same EPYC 7452 silicon on the same
`/soe` NFS home — as the x86 platform. That shared home is also why the
pilot-bench binary is per-host: it links a machine's system Boost, so only the
host that last built it can run it. Each host here rebuilt pilot-bench against
its own Boost.

## Commit set

Crate and rump commits are identical across all three hosts:

- cryptography: `e7e4825`
- rump (crates.io `rust-mp` 0.1.1): `01e1c1e`
- pilot-bench: `0f3cb4f` on `tolkien`/`twilight`, `097624d` on `heinlein`
  (the same harness used for the 2026-06-11 sweep; the version gap is in the
  measurement tool, not the crate under test, and does not change the
  operation latencies it records)

## Pilot configuration

Identical to the 2026-06-11 sweep:

- `PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90` — 90% CI, 10% half-width
  target, autocorrelation tolerance ≤ 0.2, ≥ 50 rounds minimum sample size
- `PILOT_PK_ITERS_PERCENT=25` for `pilot_pk`

## vs the 2026-06-11 v0.7.0 baseline

Same-host is not available (dennard is down), but on `tolkien` (M1) versus the
June `tolkien` capture at v0.7.0 (`1aae1df`):

- **RSA / finite-field** and **ML-KEM / ML-DSA** throughput reflect the
  optimization work that landed between the two sweeps (Algorithm D division,
  the Montgomery-kernel rewrite, the ML-KEM matrix cache). These are large —
  RSA encrypt/verify ~3.7×, ML-KEM encaps ~2.9× — and are *not* attributable
  to the rump extraction, which is arithmetic-preserving.
- **Prime-curve ECDSA / ECDH** are ~1.2–1.3× faster than the June baseline.
  The Montgomery-domain scalar-multiplication rewrite (commit `e7e4825`)
  recovered a ~1.9× M1 regression that commit `a63c781` had introduced by
  layering a windowed ladder over field arithmetic that still paid an
  encode/decode round trip on every multiply.

ML-KEM/ML-DSA serve as a control for the rump extraction specifically: they
share no code with the extracted bigint layer, and a pre-extraction vs
post-extraction A/B on the same host showed them unchanged within CI.

## Layout

```
sweep-2026-08-11/
├── README.md                  ← this file
├── tolkien/  {host.txt, pk.md, pk.stderr}
├── twilight/ {host.txt, pk.md, pk.stderr}
├── heinlein/ {host.txt, pk.md, pk.stderr}
├── merged/   {pk.md}          ← three platforms side by side
└── csv/                       ← per-radar ops/sec extracts
```

## Reproduce

```bash
# Per host (after a fresh pull + rebuild of both cryptography and ../rump):
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 \
  bash scripts/bench_all_pk_full.sh > <host>/pk.md

# Merge:
python3 scripts/merge_three_pilot_tables.py \
  --a tolkien/pk.md --b twilight/pk.md --c heinlein/pk.md \
  --a-label "Tolkien (M1)" --b-label "Twilight (EPYC 7452)" \
  --c-label "Heinlein (Jetson)" \
  --mode pk --confidence-pct 90 --out merged/pk.md

# Radars (symmetric.md/hash.md from the 2026-06-11 merge are reused as
# inputs, since only the public-key surface was re-swept):
python3 scripts/build_radar_csvs.py --sweep sweep-2026-08-11 \
  --platforms "Tolkien (M1),Twilight (EPYC 7452),Heinlein (Jetson)" \
  --columns "tolkien,twilight,heinlein"
python3 scripts/generate_three_platform_radar.py \
  --csv bench/sweep-2026-08-11/csv/pk_rsa_ec.csv \
  --out assets/sweep-2026-08-11-pk-rsa-ec-radar.svg \
  --title "RSA / DSA / EC ops/sec (Tolkien / Twilight / Heinlein)" \
  --units "ops/sec" \
  --legend "Tolkien (M1, macOS);Twilight (EPYC 7452, single-core);Heinlein (Jetson, aarch64)"
```
