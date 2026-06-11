# Three-platform Pilot sweep — 2026-06-11

Pilot-bench sweep across three platforms covering the full symmetric, hash,
and public-key (incl. post-quantum) surface of the cryptography crate, taken
immediately after the 0.7.0 audit/optimization pass (commit `1aae1df`).

## Hosts

| Tag | Host | CPU | OS | Cores |
|---|---|---|---|---|
| `tolkien`  | `tolkien` | Apple M1 | Darwin 25.5.0 (macOS 26.5.1) | 8 |
| `dennard`  | `dennard.soe.ucsc.edu` | AMD EPYC 7452 | Linux 5.15.0 (Ubuntu 22.04) | 128 (single-core slice) |
| `heinlein` | `heinlein.local` | NVIDIA Jetson (Tegra, ARMv8) | Linux 5.15.185-tegra (Ubuntu) | 8 |

All hosts pinned to the same commit set:

- cryptography: `1aae1df` (v0.7.0)
- pilot-bench: `097624d` (+ locally reconstructed `cmake/patch_twitter_bd.sh`,
  which is referenced by `lib/CMakeLists.txt` but untracked at that commit;
  on GCC hosts pilot-bench additionally needs
  `-DCMAKE_CXX_FLAGS=-Wno-unknown-pragmas` for the clang-only pragmas in
  `libpilot.cc`)

`dennard` carries the same EPYC 7452 silicon as the 2026-05-08 sweep's
`moore`, giving a like-for-like before/after across the 0.7.0 changes (see
below). `tolkien` (M1) and `heinlein` (Jetson) are new hosts; their numbers
are not directly comparable to `wigner` (M1 Max) or `darby` (RPi5).

## Pilot configuration

Run with `PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90`, identical to the
2026-05-08 sweep:

- 90% confidence interval, 10% CI half-width target
- autocorrelation tolerance ≤ 0.2, ≥ 50 rounds minimum sample size
- 256 KiB per `pilot_cipher`/`pilot_hash` invocation,
  `PILOT_PK_ITERS_PERCENT=25` for `pilot_pk`

## 0.7.0 before/after on identical silicon (EPYC 7452)

`moore` (2026-05-08, v0.6.2 at `eac8df0`) vs `dennard` (this sweep, v0.7.0):

| Operation | moore ms/op | dennard ms/op | Speedup |
|---|---:|---:|---:|
| ecdsa_sign | 2.704 | 1.198 | 2.26× |
| ecdsa_verify | 4.977 | 2.124 | 2.34× |
| ed25519_sign | 1.264 | 0.499 | 2.53× |
| ed25519_verify | 4.126 | 1.649 | 2.50× |
| ecies_decrypt | 2.390 | 0.965 | 2.48× |
| rsa_sign_2048 | 2.546 | 2.130 | 1.20× |
| rsa_decrypt_2048 | 2.555 | 2.148 | 1.19× |

These track the 0.7.0 changes (Montgomery-domain EC/Edwards arithmetic,
windowed exponentiation). Symmetric-cipher throughput is unchanged within
machine-to-machine variance of identical silicon (e.g. chacha20 416.5 vs
409.2 MB/s), as expected — the cipher cores were not touched.

## Outputs

```
sweep-2026-06-11/
├── README.md                   ← this file
├── tolkien/                    ← raw stdout from each script per host
├── dennard/
├── heinlein/
├── merged/                     ← 3-way side-by-side Markdown tables
│   ├── symmetric.md
│   ├── hash.md
│   └── pk.md
└── csv/                        ← per-radar metric extracts
```

Kiviat radars (committed under `assets/`):

![Symmetric throughput (Kiviat)](../../assets/sweep-2026-06-11-symmetric-radar.svg)

![Hash throughput (Kiviat)](../../assets/sweep-2026-06-11-hash-radar.svg)

![RSA / DSA / EC ops/sec (Kiviat)](../../assets/sweep-2026-06-11-pk-rsa-ec-radar.svg)

![Post-quantum ops/sec (Kiviat)](../../assets/sweep-2026-06-11-pk-pq-radar.svg)

## How to reproduce / extend

```bash
# 1. Drive the sweeps on a fresh host (after a fresh pull + rebuild):
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 \
  bash scripts/bench_all.sh         > tolkien/symmetric.md
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 \
  bash scripts/bench_all_hash.sh    > tolkien/hash.md
PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 \
  bash scripts/bench_all_pk_full.sh > tolkien/pk.md

# 2. Merge three platforms' results side-by-side:
python3 scripts/merge_three_pilot_tables.py \
  --a tolkien/symmetric.md --b dennard/symmetric.md --c heinlein/symmetric.md \
  --a-label Tolkien --b-label Dennard --c-label Heinlein \
  --mode sym --confidence-pct 90 --out merged/symmetric.md

# 3. Extract per-radar CSVs and emit SVGs (both scripts are now
#    sweep/platform parameterized; defaults reproduce the 2026-05-08 set):
python3 scripts/build_radar_csvs.py --sweep sweep-2026-06-11 \
  --platforms "Tolkien,Dennard,Heinlein" --columns "tolkien,dennard,heinlein"
python3 scripts/generate_three_platform_radar.py \
  --csv bench/sweep-2026-06-11/csv/symmetric.csv \
  --out assets/sweep-2026-06-11-symmetric-radar.svg \
  --title "Symmetric throughput (Tolkien / Dennard / Heinlein)" --units "MB/s" \
  --legend "Tolkien (M1, macOS);Dennard (EPYC 7452, single-core);Heinlein (Jetson, aarch64)"
```
