# ANALYSIS

- [SYMMETRIC.md](SYMMETRIC.md) covers block ciphers, stream ciphers, modes,
  hashes, MACs, CSPRNGs, and the symmetric benchmark story.
- [ASYMMETRIC.md](ASYMMETRIC.md) covers bigint arithmetic, public-key
  primitives, standards-based and crate-defined wrappers, serialization, and
  public-key latency.

## Shared Structure

The crate has four major implementation areas:

- `src/ciphers/`: symmetric block and stream ciphers
- `src/modes/`: reusable block-cipher modes and AEAD-adjacent wrappers
- `src/hash/`: fixed-output hashes, XOFs, and HMAC support
- `src/public_key/`: bigint arithmetic, number theory, and public-key schemes

The public API uses the same layering:

- primitive arithmetic / cipher cores
- reusable support layers (modes, hashes, DRBGs, Montgomery arithmetic)
- higher-level wrappers where the standards are clear

The implementation policy is intentionally uniform across the crate:

- pure idiomatic Rust
- no architecture intrinsics
- no C/FFI escape hatches
- minimal dependencies unless a standard format or external interop clearly
  justifies one

That is why the crate keeps its own cipher, hash, and DRBG code in-tree
and takes its bigint layer from the sibling
[rump](https://github.com/darrelllong/rump) crate (extracted from this tree;
same author, same policies, no third-party code), while still using standard
external formats such as DER/PEM where that materially improves
interoperability.

## Coverage

Validation has three main lanes:

- correctness tests in `cargo test`
- focused interoperability checks against OpenSSL where real standards exist
- benchmark binaries for throughput or latency

Important entry points:

- `cargo test`
- `cargo test public_key::`
- `bash scripts/bench_all.sh`
- `bash scripts/bench_all_pk_full.sh`

## Reading Guide

- Start with [README.md](README.md) for usage.
- Read [SYMMETRIC.md](SYMMETRIC.md) when working with ciphers, modes, hashes,
  or DRBGs.
- Read [ASYMMETRIC.md](ASYMMETRIC.md) when working with key generation,
  serialization, encryption/signature wrappers, or the bigint backend.
- Read [POSTQUANTUM.md](POSTQUANTUM.md) when working with ML-KEM or ML-DSA.
