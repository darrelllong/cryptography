//! Benchmark support crate.
//!
//! The actual benchmarks live in `benchmarks/benches/`; this empty library keeps
//! benchmark-only dependencies out of the main crate so `cargo test` there stays
//! usable without resolving Criterion or libsodium.
