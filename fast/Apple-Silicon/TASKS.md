# Apple Silicon No-ASM Task Board

Status legend: `[ ]` pending, `[~]` in progress, `[x]` done.

## Track A: Constant-Time Symmetric Paths

- [x] Remove panic-checked integer conversions from `src/ct.rs` tight loops.
- [x] Build first isolated Apple-Silicon alternative kernels outside baseline
      tree (`aarch64-alt` AES-128/AES-256 FEAT_AES paths + parity harnesses).
- [x] Add first non-AES acceleration paths in `aarch64-alt`:
      SHA-256, GHASH, and ChaCha20 (NEON) all implemented with parity harnesses.
- [x] Add Keccak/SHAKE acceleration path for PQ workloads:
      SHAKE128/SHAKE256 one-shot kernels are implemented with ML-KEM/ML-DSA
      workload wrapper entry points and parity/microbench coverage.
- [x] Profile `src/ct.rs` ANF evaluators (`subset_mask8`, `eval_byte_sbox`,
      `parity128`) on M-series and quantify cycle share by cipher.
- [~] Reduce repeated ANF evaluation overhead in high-gap Ct ciphers:
      major wins landed for `camellia.rs`, `sm4.rs`, `seed.rs`, `snow3g.rs`,
      `zuc.rs`; continue iterating on residual gaps.
- [ ] Audit Ct paths for avoidable allocations/copies and widen use of stack
      arrays in round functions where safe.
- [x] Add targeted regression tests that compare `fast` and `Ct` outputs for
      selected random vectors per cipher family (if missing in that module).

## Track B: BigUint / Public-Key (Paused)

- [x] Decision: pause BigUint optimization work unless there is an obvious,
      measured win.
- [ ] If revisited, only accept BigUint changes that show a clear isolated
      speedup and do not increase timing variability in Pilot PK runs.

## Track C: Measurement and Reporting

- [x] Create split local hotspot runners for Apple Silicon:
      [run_hotspots_symmetric.sh](scripts/run_hotspots_symmetric.sh),
      [run_hotspots_pk.sh](scripts/run_hotspots_pk.sh)
- [x] Store each optimization round as dated results under
      `fast/Apple-Silicon/results/` (see `run_alt_suite.sh` and generated
      `alt_suite_*.md` snapshots).
- [~] After each accepted optimization, propagate numbers to
      `SYMMETRIC.md` / `ASYMMETRIC.md` tables and associated Kiviat diagrams.
