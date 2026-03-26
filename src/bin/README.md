# bin

Binary utilities for benchmarking, piloting, and dataset generation.

These are not part of the library API.  They exist to exercise the library
from the outside, produce benchmark data, and sanity-check implementations
interactively.

| File | Purpose |
|------|---------|
| `bench_bigint.rs` | Microbenchmarks for bigint and Montgomery arithmetic |
| `bench_public_key.rs` | Cross-platform latency benchmarks for all public-key schemes |
| `gen_ml_dataset.rs` | Generate training/test datasets for the ML side-channel analysis in `../../ml/` |
| `pilot_cipher.rs` | Quick encrypt/decrypt smoke test for symmetric ciphers |
| `pilot_pk.rs` | Interactive exercise of public-key keygen / sign / verify / encrypt / decrypt |
| `pilot_sm4.rs` | SM4-specific pilot; exercises both table-driven and constant-time paths |

## Running

```sh
# Run a specific binary
cargo run --bin pilot_cipher

# Run benchmarks (release mode for meaningful numbers)
cargo run --release --bin bench_public_key
```

Benchmark output is tab-separated and intended to be pasted directly into
`../../BENCHMARKING.md` or `../../ASYMMETRIC.md`.
