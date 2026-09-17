//! DRBG generate throughput, at the request sizes a buffered caller uses.
//!
//! `rng-entropy` refills from one `generate` call per buffer: 256 bytes for
//! Hash_DRBG, 32 for HMAC_DRBG. Both sizes are measured here, along with a
//! single-block request, so a change in the per-call cost and a change in the
//! per-block cost can be told apart.
//!
//! Run:
//!   cargo bench --manifest-path benchmarks/Cargo.toml --bench drbg_bench

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cryptography::{HashDrbg, HmacDrbg};
use std::hint::black_box;

/// Entropy and nonce meeting the 256-bit security strength the DRBGs require.
const ENTROPY: [u8; 32] = [0x5a; 32];
const NONCE: [u8; 16] = [0xa5; 16];

/// Request sizes: one SHA-256 block, an HMAC_DRBG refill, a Hash_DRBG refill.
const SIZES: [usize; 3] = [32, 32, 256];

fn bench_hash_drbg(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash_DRBG-SHA-256");
    for size in [SIZES[0], SIZES[2]] {
        let mut drbg = HashDrbg::instantiate(&ENTROPY, &NONCE, &[]).expect("valid seed");
        let mut out = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                drbg.generate(black_box(&mut out), &[]).expect("fresh");
            });
        });
    }
    group.finish();
}

fn bench_hmac_drbg(c: &mut Criterion) {
    let mut group = c.benchmark_group("HMAC_DRBG-SHA-256");
    for size in [SIZES[1], SIZES[2]] {
        let mut drbg = HmacDrbg::instantiate(&ENTROPY, &NONCE, &[]).expect("valid seed");
        let mut out = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                drbg.generate(black_box(&mut out), &[]).expect("fresh");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hash_drbg, bench_hmac_drbg);
criterion_main!(benches);
