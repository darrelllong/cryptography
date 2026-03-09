# Apple Silicon No-ASM Task Board

Status legend: `[ ]` pending, `[~]` in progress, `[x]` done.

## Track A: Constant-Time Symmetric Paths

- [x] Remove panic-checked integer conversions from `src/ct.rs` tight loops.
- [~] Build first isolated Apple-Silicon alternative kernel outside baseline
      tree (`aarch64-alt` AES-128 FEAT_AES path + parity harness).
- [ ] Profile `src/ct.rs` ANF evaluators (`subset_mask8`, `eval_byte_sbox`,
      `parity128`) on M-series and quantify cycle share by cipher.
- [ ] Reduce repeated ANF evaluation overhead in high-gap Ct ciphers:
      `camellia.rs`, `sm4.rs`, `seed.rs`, `snow3g.rs`, `zuc.rs`.
- [ ] Audit Ct paths for avoidable allocations/copies and widen use of stack
      arrays in round functions where safe.
- [ ] Add targeted regression tests that compare `fast` and `Ct` outputs for
      selected random vectors per cipher family (if missing in that module).

## Track B: BigUint / Public-Key

- [ ] Use profiling to rank BigUint hotspots by operation (`mul`, `mont_reduce`,
      modular exponentiation loops) in RSA/DSA/ElGamal keygen and decrypt/sign.
- [ ] Apply low-risk arithmetic improvements that preserve readability and
      correctness first (loop structure, carry propagation locality, temporary
      reuse).
- [ ] Re-run Pilot PK suite and compare CI behavior to verify we did not add
      timing variability.

## Track C: Measurement and Reporting

- [x] Create split local hotspot runners for Apple Silicon:
      [run_hotspots_symmetric.sh](scripts/run_hotspots_symmetric.sh),
      [run_hotspots_pk.sh](scripts/run_hotspots_pk.sh)
- [ ] Store each optimization round as dated results under
      `fast/Apple-Silicon/results/`.
- [ ] After each accepted optimization, propagate numbers to
      `SYMMETRIC.md` / `ASYMMETRIC.md` tables and associated Kiviat diagrams.
