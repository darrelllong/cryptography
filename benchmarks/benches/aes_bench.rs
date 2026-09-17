//! AES throughput benchmarks.
//!
//! Two groups that are not like for like, printed side by side only as a
//! reference point:
//!
//!   * our-AES-software            — this crate's portable AES-128/192/256,
//!                                   raw block encryption with the key schedule
//!                                   hoisted out of the loop, no mode, no MAC
//!   * libsodium-XSalsa20-Poly1305 — NaCl secretbox through sodiumoxide: a
//!                                   different cipher (XSalsa20), plus a
//!                                   Poly1305 tag and an output allocation per
//!                                   call, built with libsodium's platform
//!                                   optimisations
//!
//! A ratio between the two groups compares a bare block permutation with an
//! authenticated encryption service; it is not an AES-versus-AES figure.
//!
//! Run:
//!   cargo bench --manifest-path benchmarks/Cargo.toml --bench aes_bench
//!
//! The libsodium group is behind the `libsodium` feature, which needs that
//! library installed (brew install libsodium on macOS):
//!   cargo bench --manifest-path benchmarks/Cargo.toml --bench aes_bench \
//!       --features libsodium
//! HTML reports land in target/criterion/.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use cryptography::{Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct};
use std::hint::black_box;

// ── Our AES implementation ────────────────────────────────────────────────────

fn bench_our_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("our-AES-software");

    // ── Single 16-byte block ──
    group.throughput(Throughput::Bytes(16));

    let aes128 = Aes128::new(&[0u8; 16]);
    group.bench_function("AES-128/block", |b| {
        let blk = black_box([0u8; 16]);
        b.iter(|| aes128.encrypt_block(&blk))
    });

    let aes192 = Aes192::new(&[0u8; 24]);
    group.bench_function("AES-192/block", |b| {
        let blk = black_box([0u8; 16]);
        b.iter(|| aes192.encrypt_block(&blk))
    });

    let aes256 = Aes256::new(&[0u8; 32]);
    group.bench_function("AES-256/block", |b| {
        let blk = black_box([0u8; 16]);
        b.iter(|| aes256.encrypt_block(&blk))
    });

    // ── 1 KiB (64 blocks) — shows amortised throughput ──
    let aes256 = Aes256::new(&[0u8; 32]);
    group.throughput(Throughput::Bytes(1024));
    group.bench_with_input(
        BenchmarkId::new("AES-256/1KiB", "64 blocks"),
        &[0u8; 1024usize],
        |b, msg| {
            b.iter(|| {
                msg.chunks_exact(16).fold([0u8; 16], |acc, chunk| {
                    let block = <&[u8; 16]>::try_from(chunk).unwrap();
                    let out = black_box(aes256.encrypt_block(block));
                    let mut next = acc;
                    for (n, o) in next.iter_mut().zip(out.iter()) {
                        *n ^= o;
                    }
                    next
                })
            })
        },
    );

    group.finish();

    let mut group = c.benchmark_group("our-AESCt-software");

    group.throughput(Throughput::Bytes(16));

    let aes128 = Aes128Ct::new(&[0u8; 16]);
    group.bench_function("AES-128/block", |b| {
        let blk = black_box([0u8; 16]);
        b.iter(|| aes128.encrypt_block(&blk))
    });

    let aes192 = Aes192Ct::new(&[0u8; 24]);
    group.bench_function("AES-192/block", |b| {
        let blk = black_box([0u8; 16]);
        b.iter(|| aes192.encrypt_block(&blk))
    });

    let aes256 = Aes256Ct::new(&[0u8; 32]);
    group.bench_function("AES-256/block", |b| {
        let blk = black_box([0u8; 16]);
        b.iter(|| aes256.encrypt_block(&blk))
    });

    let aes256 = Aes256Ct::new(&[0u8; 32]);
    group.throughput(Throughput::Bytes(1024));
    group.bench_with_input(
        BenchmarkId::new("AES-256/1KiB", "64 blocks"),
        &[0u8; 1024usize],
        |b, msg| {
            b.iter(|| {
                msg.chunks_exact(16).fold([0u8; 16], |acc, chunk| {
                    let block = <&[u8; 16]>::try_from(chunk).unwrap();
                    let out = black_box(aes256.encrypt_block(block));
                    let mut next = acc;
                    for (n, o) in next.iter_mut().zip(out.iter()) {
                        *n ^= o;
                    }
                    next
                })
            })
        },
    );

    group.finish();
}

// ── NaCl / libsodium ─────────────────────────────────────────────────────────
//
// secretbox = XSalsa20-Poly1305: NaCl's recommended authenticated cipher.
//
// secretbox's output carries a 16-byte Poly1305 tag and is freshly
// allocated per call; the AES groups above time the block permutation alone.

#[cfg(feature = "libsodium")]
fn bench_nacl(c: &mut Criterion) {
    sodiumoxide::init().expect("sodiumoxide init failed — is libsodium installed?");

    // ── XSalsa20-Poly1305 (NaCl secretbox) ──
    {
        use sodiumoxide::crypto::secretbox;
        let key   = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        let msg16 = [0u8; 16];
        let msg1k = [0u8; 1024];

        let mut group = c.benchmark_group("libsodium-XSalsa20-Poly1305");

        group.throughput(Throughput::Bytes(16));
        group.bench_function("16B", |b| {
            b.iter(|| secretbox::seal(black_box(&msg16), &nonce, &key))
        });

        group.throughput(Throughput::Bytes(1024));
        group.bench_function("1KiB", |b| {
            b.iter(|| secretbox::seal(black_box(&msg1k), &nonce, &key))
        });

        group.finish();
    }
}

/// Without the `libsodium` feature the comparison group is simply absent.
#[cfg(not(feature = "libsodium"))]
fn bench_nacl(_: &mut Criterion) {}

criterion_group!(benches, bench_our_aes, bench_nacl);
criterion_main!(benches);
