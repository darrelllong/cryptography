# bin

Binary utilities for benchmarking, piloting, and dataset generation.

These are not part of the library API.  They exist to exercise the library
from the outside, produce benchmark data, and sanity-check implementations
interactively.

| File | Purpose |
|------|---------|
| `bench_bigint.rs` | Microbenchmarks for bigint and Montgomery arithmetic |
| `bench_public_key.rs` | Cross-platform latency benchmarks for all public-key schemes |
| `cipher_encrypt.rs` | CTR-mode (block) / native-stream (stream) encryption of stdin under a fresh OS-random key.  Drives the R randomness battery in `scripts/cipher_randomness.R`; not a general-purpose CLI: it does not emit the IV, supports a fixed cipher set, and is intended for statistical testing only |
| `pilot_cipher.rs` | Throughput benchmark driver for symmetric ciphers; called by `pilot-bench` to compute statistically tight MB/s figures |
| `pilot_pk.rs` | Interactive exercise of public-key keygen / sign / verify / encrypt / decrypt |
| `pilot_sm4.rs` | SM4-specific pilot; exercises both table-driven and constant-time paths |
| `profile_ct_anf.rs` | Profile Ct-ANF helper activity (build with `--features ct_profile`) |

## Running

```sh
# Run a specific binary
cargo run --bin pilot_cipher

# Run benchmarks (release mode for meaningful numbers)
cargo run --release --bin bench_public_key
```

Benchmark output is tab-separated and intended to be pasted directly into
`../../BENCHMARKING.md` or `../../ASYMMETRIC.md`.
