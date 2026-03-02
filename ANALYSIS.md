# ANALYSIS

This repository now has two focused technical analyses instead of one mixed
document:

- [SYMMETRIC.md](SYMMETRIC.md) covers block ciphers, stream ciphers, modes,
  hashes, MACs, CSPRNGs, and the symmetric benchmark story.
- [ASYMMETRIC.md](ASYMMETRIC.md) covers bigint arithmetic, public-key
  primitives, standards-based and crate-defined wrappers, serialization, and
  public-key latency.

This top-level file stays as the short overview so the repository has one place
to answer three questions quickly:

1. what is implemented,
2. how it is validated,
3. where the deeper write-ups live.

## Shared Structure

The crate is split into four major implementation areas:

- `src/ciphers/`: symmetric block and stream ciphers
- `src/modes/`: reusable block-cipher modes and AEAD-adjacent wrappers
- `src/hash/`: fixed-output hashes, XOFs, and HMAC support
- `src/public_key/`: bigint arithmetic, number theory, and public-key schemes

The public API keeps the same layering:

- primitive arithmetic / cipher cores
- reusable support layers (modes, hashes, DRBGs, Montgomery arithmetic)
- higher-level wrappers where the standards are clear

## Coverage

Validation is split into three lanes:

- correctness tests in `cargo test`
- focused interoperability checks against OpenSSL where real standards exist
- benchmark binaries for throughput or latency

Important entry points:

- `cargo test`
- `cargo test public_key::`
- `cargo run --release --bin bench_public_key -- 1024`
- `cargo bench --manifest-path benchmarks/Cargo.toml --bench cipher_bench`
- `cargo bench --manifest-path benchmarks/Cargo.toml --bench aes_bench`

## Machine-Learning Experiments

The `ml/` directory is a separate experiment harness for distinguisher tests.
It is intentionally treated as a research sidecar, not as evidence that any
implemented primitive is broken. The published runs so far remain effectively
at chance on held-out data.

For the current model families, commands, and result summaries, see:

- [README.md](README.md)
- [ml/README.md](ml/README.md)

## Reading Guide

- Start with [README.md](README.md) for usage.
- Read [SYMMETRIC.md](SYMMETRIC.md) when working with ciphers, modes, hashes,
  or DRBGs.
- Read [ASYMMETRIC.md](ASYMMETRIC.md) when working with key generation,
  serialization, encryption/signature wrappers, or the bigint backend.

