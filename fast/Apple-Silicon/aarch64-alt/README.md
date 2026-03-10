# aarch64-alt

Opt-in Apple-Silicon alternative kernels for cryptography primitives.

This crate is intentionally separate from the baseline `src/` tree:

- Baseline (`src/`) stays pure safe Rust and is the canonical reference.
- `aarch64-alt` is for macOS/aarch64 users who want acceleration.

## Current kernels

- `aes128_armv8`: AES-128 encrypt/decrypt using ARM FEAT_AES intrinsics.
- `aes256_armv8`: AES-256 encrypt/decrypt using ARM FEAT_AES intrinsics.
- `sha256_armv8`: SHA-256 one-shot digest using ARM FEAT_SHA2 intrinsics.
- `ghash_armv8`: GHASH multiply using ARM carry-less multiply intrinsics.
- `chacha20_armv8`: ChaCha20 stream kernel using ARM NEON (4-block path).
- `shake_armv8`: SHAKE128/SHAKE256 one-shot kernels for KEM-style workloads.

## Correctness check against baseline

```bash
bash fast/Apple-Silicon/scripts/compare_aes128_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_aes256_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_sha256_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_ghash_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_chacha20_alt.sh 5000
bash fast/Apple-Silicon/scripts/compare_shake_alt.sh 5000
```

Each command checks output parity against the corresponding baseline type in
`cryptography` over random vectors and then prints a small throughput
microbenchmark.
