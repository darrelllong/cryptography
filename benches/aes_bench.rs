//! AES throughput benchmarks.
//!
//! Compares our pure-Rust T-table implementation against Bernstein's NaCl
//! library (via libsodium / sodiumoxide):
//!
//!   * our-AES-T-table          — AES-128/192/256 ECB, compile-time T-tables
//!   * libsodium-XSalsa20-Poly1305 — NaCl secretbox (stream cipher + MAC)
//!   * libsodium-AES256GCM      — AES-256-GCM via hardware AES (if available)
//!
//! Run:
//!   cargo bench
//!
//! Requires libsodium (brew install libsodium on macOS).
//! HTML reports land in target/criterion/.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use cryptography::{Aes128, Aes192, Aes256};
use std::hint::black_box;

// ── Our T-table AES ──────────────────────────────────────────────────────────

fn bench_our_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("our-AES-T-table");

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
                msg.chunks_exact(16).fold([0u8; 16], |_, chunk| {
                    aes256.encrypt_block(<&[u8; 16]>::try_from(chunk).unwrap())
                })
            })
        },
    );

    group.finish();
}

// ── NaCl / libsodium ─────────────────────────────────────────────────────────
//
// secretbox  = XSalsa20-Poly1305: NaCl's recommended authenticated cipher.
// aes256gcm  = AES-256-GCM: hardware-only (AES-NI / ARMv8 Crypto).
//
// Note: secretbox includes a 32-byte MAC tag in the output; the AES-ECB bench
// above has zero overhead.  The comparison shows the full "real-world" NaCl
// cost vs our raw cipher core.

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

    // ── AES-256-GCM (libsodium, hardware-accelerated) ──
    {
        use sodiumoxide::crypto::aead::aes256gcm;
        if aes256gcm::is_available() {
            let key   = aes256gcm::gen_key();
            let nonce = aes256gcm::gen_nonce();
            let msg16 = [0u8; 16];
            let msg1k = [0u8; 1024];

            let mut group = c.benchmark_group("libsodium-AES256GCM");

            group.throughput(Throughput::Bytes(16));
            group.bench_function("16B", |b| {
                b.iter(|| aes256gcm::seal(black_box(&msg16), None, &nonce, &key))
            });

            group.throughput(Throughput::Bytes(1024));
            group.bench_function("1KiB", |b| {
                b.iter(|| aes256gcm::seal(black_box(&msg1k), None, &nonce, &key))
            });

            group.finish();
        } else {
            eprintln!("note: AES-NI/ARMv8 not detected — skipping libsodium AES-256-GCM bench");
        }
    }
}

criterion_group!(benches, bench_our_aes, bench_nacl);
criterion_main!(benches);
