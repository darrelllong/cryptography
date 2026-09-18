//! What a ChaCha20 keystream costs at the sizes and shapes a caller asks for.
//!
//! The throughput figure in `cipher_bench` is one megabyte in one call, which
//! is the best case: whole blocks, an aligned buffer, one construction
//! amortised over sixteen thousand blocks. A caller that wants four bytes, or
//! a 480-byte record, or a buffer starting one byte into an allocation, pays
//! something else, and the difference is what decides whether a bulk path is
//! worth having.
//!
//! The sizes: one word; a 16-byte block of the AES sort; one ChaCha block; a
//! 480-byte record, which is seven blocks and a 32-byte tail; 512 bytes, which
//! is eight whole blocks; 4 KiB, a page; and a megabyte. The shapes: one call
//! for the whole buffer, a word at a time, and the whole buffer through a
//! slice that starts one byte into its allocation.
//!
//! Run:
//!   cargo bench --manifest-path benchmarks/Cargo.toml --bench keystream_sizes

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use cryptography::ChaCha20;
use std::hint::black_box;

/// Request sizes: a word, an AES block, a ChaCha block, a record with a tail,
/// whole blocks, a page, and a megabyte.
const SIZES: [usize; 7] = [4, 16, 64, 480, 512, 4096, 1 << 20];

/// The width of a word-at-a-time caller's request.
const WORD: usize = 4;

const KEY: [u8; 32] = [0x2bu8; 32];
const NONCE: [u8; 12] = [0x5au8; 12];

fn one_call(c: &mut Criterion) {
    let mut g = c.benchmark_group("ChaCha20/one call");
    for size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || vec![0u8; size],
                |mut buf| {
                    ChaCha20::new(&KEY, &NONCE).apply_keystream(&mut buf);
                    black_box(buf)
                },
                BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

/// The same bytes, asked for a word at a time: one cipher, many calls, so the
/// per-call cost shows against the per-byte one. The megabyte is left out —
/// its answer is the 4 KiB answer, a quarter of a million times over.
fn word_at_a_time(c: &mut Criterion) {
    let mut g = c.benchmark_group("ChaCha20/word at a time");
    for size in SIZES.into_iter().filter(|&s| s >= WORD && s <= 4096) {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || vec![0u8; size],
                |mut buf| {
                    let mut cipher = ChaCha20::new(&KEY, &NONCE);
                    for word in buf.chunks_mut(WORD) {
                        cipher.apply_keystream(word);
                    }
                    black_box(buf)
                },
                BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

/// One call over a slice that starts one byte into its allocation, which is
/// what a caller writing into the middle of a frame hands over.
fn unaligned(c: &mut Criterion) {
    let mut g = c.benchmark_group("ChaCha20/offset by one");
    for size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || vec![0u8; size + 1],
                |mut buf| {
                    ChaCha20::new(&KEY, &NONCE).apply_keystream(&mut buf[1..]);
                    black_box(buf)
                },
                BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

/// Construction alone, against construction plus one block: what a caller pays
/// for a fresh `(key, nonce)` before any keystream comes out.
fn construction(c: &mut Criterion) {
    let mut g = c.benchmark_group("ChaCha20/construction");
    g.bench_function("new", |b| {
        b.iter(|| black_box(ChaCha20::new(&KEY, &NONCE)));
    });
    g.throughput(Throughput::Bytes(64));
    g.bench_function("new and one block", |b| {
        b.iter_batched(
            || [0u8; 64],
            |mut block| {
                ChaCha20::new(&KEY, &NONCE).apply_keystream(&mut block);
                black_box(block)
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

criterion_group!(benches, one_call, word_at_a_time, unaligned, construction);
criterion_main!(benches);
