# Apple-Silicon Hotspots (symmetric)

- Date: 2026-03-10 00:35:00 UTC
- Host: `Dyson`
- Pilot preset: `quick`
- Native tuning (`-C target-cpu=native`): `off`

## Ct Gap Pairs (MB/s)

| Pair | Fast MB/s | Fast ±CI | Fast Runs | Ct MB/s | Ct ±CI | Ct Runs | Fast/Ct |
|---|---:|---:|---:|---:|---:|---:|---:|
| `aes128` vs `aes128ct` | 460.2 | ±6.923 | 30 | 61.2 | ±0.4115 | 121 | 7.52x |
| `camellia128` vs `camellia128ct` | 139.4 | ±1.527 | 30 | 13.38 | ±0.07387 | 92 | 10.42x |
| `sm4` vs `sm4ct` | 185.6 | ±1.638 | 150 | 13.53 | ±0.04346 | 127 | 13.72x |
| `seed` vs `seedct` | 71.39 | ±0.2284 | 60 | 9.504 | ±0.01974 | 30 | 7.51x |
| `twofish256` vs `twofish256ct` | 13.94 | ±0.03303 | 70 | 2.034 | ±0.005795 | 60 | 6.85x |
| `present80` vs `present80ct` | 12.07 | ±0.1417 | 60 | 3.896 | ±0.02912 | 155 | 3.10x |
| `snow3g` vs `snow3gct` | 499.9 | ±5.939 | 45 | 59.22 | ±0.1654 | 47 | 8.44x |
| `zuc128` vs `zuc128ct` | 521.3 | ±5.939 | 127 | 61.53 | ±0.2327 | 48 | 8.47x |
