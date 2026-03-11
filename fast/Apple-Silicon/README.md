# Apple Silicon Optimization Workspace (No ASM, In-Repo Only)

This directory is the staging area for Apple Silicon performance work under
strict constraints:

- No assembly language.
- No external crypto crates or copied implementations.
- Improvements must be authored in this repository and maintain existing tests.

Baseline policy:

- `src/` is the canonical pure safe Rust baseline.
- Apple-Silicon acceleration work is an alternative path for macOS users and
  must not change baseline algorithm behavior or baseline API contracts.
- Any acceleration-specific code lives under `fast/Apple-Silicon/` (or a
  clearly isolated opt-in path), not as silent behavior changes in baseline
  implementations.

The initial focus is software-level throughput and latency wins on M-series CPUs
using algorithmic/layout improvements and compiler-friendly code structure.

## First Alternative Kernel

Implemented in:

- `fast/Apple-Silicon/aarch64-alt/src/aes128_armv8.rs`
- `fast/Apple-Silicon/aarch64-alt/src/aes256_armv8.rs`

It provides opt-in AES-128, AES-256, SHA-256, and GHASH acceleration using ARM
intrinsics on Apple-Silicon machines and includes parity checks against
baseline/reference outputs.

Run parity + microbench:

```bash
bash fast/Apple-Silicon/scripts/compare_aes128_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_aes256_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_sha256_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_ghash_alt.sh 5000
bash fast/Apple-Silicon/scripts/run_alt_suite.sh
```

## Scope

1. Constant-time symmetric hot paths with large `fast` vs `Ct` gaps.
2. Apple-Silicon alternative kernels (opt-in) with strict parity checks.
3. Measurement discipline tied to Pilot runs and operation IDs.

## Baseline

Current M4 Pro baseline snapshot:

- [BASELINE_M4_2026-03-09.md](BASELINE_M4_2026-03-09.md)

## Workflow

1. Pick one task from [TASKS.md](TASKS.md).
2. Record a hotspot baseline with the changed area only:

```bash
bash fast/Apple-Silicon/scripts/run_hotspots_symmetric.sh
bash fast/Apple-Silicon/scripts/run_hotspots_pk.sh
bash fast/Apple-Silicon/scripts/profile_ct_anf.sh
```

`run_hotspots.sh` runs both and is intended for full checkpoint snapshots.
Each split script only builds and benchmarks its own domain.

3. Implement one isolated change.
4. Re-run hotspots and full tests.
5. Only keep changes that improve median performance without widening CI in a
   suspicious way.
6. Promotion gate: only keep kernels in the go-fast published set if speedup is
   >=5x over baseline/reference.

## Build Modes

By default, the script uses the repository's normal release build.

To compare native tuning impact separately (still no asm), set:

```bash
FAST_NATIVE=1 bash fast/Apple-Silicon/scripts/run_hotspots_symmetric.sh
```

This adds `-C target-cpu=native` for the benchmark binaries only.
