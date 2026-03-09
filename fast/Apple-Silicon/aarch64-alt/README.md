# aarch64-alt

Opt-in Apple-Silicon alternative kernels for cryptography primitives.

This crate is intentionally separate from the baseline `src/` tree:

- Baseline (`src/`) stays pure safe Rust and is the canonical reference.
- `aarch64-alt` is for macOS/aarch64 users who want acceleration.

## Current kernel

- `aes128_armv8`: AES-128 encrypt/decrypt using ARM FEAT_AES intrinsics.

## Correctness check against baseline

```bash
bash fast/Apple-Silicon/scripts/compare_aes128_alt.sh 5000
```

This compares the alternative kernel output against `cryptography::Aes128` over
random vectors and prints a small throughput microbench.
