//! Throughput benchmarks for all cipher families.
//!
//! Each benchmark encrypts 1 MiB of data in ECB mode. The buffer is prepared by
//! `iter_batched` (setup not timed) so random data generation and allocation
//! never appear in the measurements.
//!
//! Run:
//!   cargo bench --manifest-path benchmarks/Cargo.toml --bench cipher_bench
//!
//! HTML reports land in target/criterion/.

use criterion::measurement::WallTime;
use criterion::{BatchSize, BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use cryptography::{
    Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct, BlockCipher, Camellia128,
    Camellia128Ct, Camellia192, Camellia192Ct, Camellia256, Camellia256Ct, Cast128, Cast128Ct,
    Des, DesCt, Grasshopper, GrasshopperCt, Magma, MagmaCt, Present128, Present128Ct, Present80,
    Present80Ct, Seed, SeedCt, Simon32_64, Simon48_72, Simon48_96, Simon64_96, Simon64_128,
    Simon96_96, Simon96_144, Simon128_128, Simon128_192, Simon128_256, Sm4, Sm4Ct, Speck32_64,
    Speck48_72, Speck48_96, Speck64_96, Speck64_128, Speck96_96, Speck96_144, Speck128_128,
    Speck128_192, Speck128_256, TripleDes, Twofish128, Twofish128Ct, Twofish192, Twofish192Ct,
    Twofish256, Twofish256Ct, Zuc128, Zuc128Ct,
};
use std::hint::black_box;

const MB: usize = 1 << 20; // 1 MiB

/// Deterministic pseudo-random fill — never timed.
fn fill(buf: &mut [u8]) {
    let mut s: u64 = 0x517cc1b727220a95;
    for b in buf.iter_mut() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }
}

// ── Generic benchmark helper ──────────────────────────────────────────────
//
// `iter_batched` keeps setup (buffer allocation + fill) outside the timed
// region. `BatchSize::LargeInput` tells Criterion to prepare one input per
// iteration, which is correct for a 1 MiB buffer.

fn bench_one<C: BlockCipher>(
    g: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    cipher: C,
    src: &[u8],
) {
    let blk = C::BLOCK_LEN;
    let n = (src.len() / blk) * blk;
    g.throughput(Throughput::Bytes(n as u64));
    g.bench_function(name, |b| {
        b.iter_batched(
            || {
                let mut buf = src[..n].to_vec();
                fill(&mut buf);
                buf
            },
            |mut buf| {
                buf.chunks_exact_mut(blk).for_each(|ch| cipher.encrypt(ch));
                black_box(buf)
            },
            BatchSize::LargeInput,
        );
    });
}

// ── Simon ─────────────────────────────────────────────────────────────────

fn bench_simon(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("Simon");

    bench_one(&mut g, "Simon32/64", Simon32_64::new(&[0u8; 8]), &src);
    bench_one(&mut g, "Simon48/72", Simon48_72::new(&[0u8; 9]), &src);
    bench_one(&mut g, "Simon48/96", Simon48_96::new(&[0u8; 12]), &src);
    bench_one(&mut g, "Simon64/96", Simon64_96::new(&[0u8; 12]), &src);
    bench_one(&mut g, "Simon64/128", Simon64_128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Simon96/96", Simon96_96::new(&[0u8; 12]), &src);
    bench_one(&mut g, "Simon96/144", Simon96_144::new(&[0u8; 18]), &src);
    bench_one(&mut g, "Simon128/128", Simon128_128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Simon128/192", Simon128_192::new(&[0u8; 24]), &src);
    bench_one(&mut g, "Simon128/256", Simon128_256::new(&[0u8; 32]), &src);

    g.finish();
}

// ── Speck ─────────────────────────────────────────────────────────────────

fn bench_speck(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("Speck");

    bench_one(&mut g, "Speck32/64", Speck32_64::new(&[0u8; 8]), &src);
    bench_one(&mut g, "Speck48/72", Speck48_72::new(&[0u8; 9]), &src);
    bench_one(&mut g, "Speck48/96", Speck48_96::new(&[0u8; 12]), &src);
    bench_one(&mut g, "Speck64/96", Speck64_96::new(&[0u8; 12]), &src);
    bench_one(&mut g, "Speck64/128", Speck64_128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Speck96/96", Speck96_96::new(&[0u8; 12]), &src);
    bench_one(&mut g, "Speck96/144", Speck96_144::new(&[0u8; 18]), &src);
    bench_one(&mut g, "Speck128/128", Speck128_128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Speck128/192", Speck128_192::new(&[0u8; 24]), &src);
    bench_one(&mut g, "Speck128/256", Speck128_256::new(&[0u8; 32]), &src);

    g.finish();
}

// ── AES ───────────────────────────────────────────────────────────────────

fn bench_aes(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("AES");

    bench_one(&mut g, "AES-128", Aes128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "AES-128-ct", Aes128Ct::new(&[0u8; 16]), &src);
    bench_one(&mut g, "AES-192", Aes192::new(&[0u8; 24]), &src);
    bench_one(&mut g, "AES-192-ct", Aes192Ct::new(&[0u8; 24]), &src);
    bench_one(&mut g, "AES-256", Aes256::new(&[0u8; 32]), &src);
    bench_one(&mut g, "AES-256-ct", Aes256Ct::new(&[0u8; 32]), &src);

    g.finish();
}

// ── DES / Triple-DES ──────────────────────────────────────────────────────

fn bench_des(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("DES");

    bench_one(&mut g, "DES", Des::new(&[0u8; 8]), &src);
    bench_one(&mut g, "DES-ct", DesCt::new(&[0u8; 8]), &src);
    bench_one(&mut g, "3DES-2key", TripleDes::new_2key(&[0u8; 16]), &src);
    bench_one(&mut g, "3DES-3key", TripleDes::new_3key(&[0u8; 24]), &src);

    g.finish();
}

// ── PRESENT ───────────────────────────────────────────────────────────────

fn bench_present(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("PRESENT");

    bench_one(&mut g, "PRESENT-80", Present80::new(&[0u8; 10]), &src);
    bench_one(&mut g, "PRESENT-80-ct", Present80Ct::new(&[0u8; 10]), &src);
    bench_one(&mut g, "PRESENT-128", Present128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "PRESENT-128-ct", Present128Ct::new(&[0u8; 16]), &src);

    g.finish();
}

// ── Camellia ──────────────────────────────────────────────────────────────

fn bench_camellia(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("Camellia");

    bench_one(&mut g, "Camellia-128", Camellia128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Camellia-128-ct", Camellia128Ct::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Camellia-192", Camellia192::new(&[0u8; 24]), &src);
    bench_one(&mut g, "Camellia-192-ct", Camellia192Ct::new(&[0u8; 24]), &src);
    bench_one(&mut g, "Camellia-256", Camellia256::new(&[0u8; 32]), &src);
    bench_one(&mut g, "Camellia-256-ct", Camellia256Ct::new(&[0u8; 32]), &src);

    g.finish();
}

// ── CAST-128 / CAST5 ──────────────────────────────────────────────────────

fn bench_cast128(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("CAST-128");

    bench_one(&mut g, "CAST-128", Cast128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "CAST-128-ct", Cast128Ct::new(&[0u8; 16]), &src);

    g.finish();
}

// ── Twofish ───────────────────────────────────────────────────────────────

fn bench_twofish(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("Twofish");

    bench_one(&mut g, "Twofish-128", Twofish128::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Twofish-128-ct", Twofish128Ct::new(&[0u8; 16]), &src);
    bench_one(&mut g, "Twofish-192", Twofish192::new(&[0u8; 24]), &src);
    bench_one(&mut g, "Twofish-192-ct", Twofish192Ct::new(&[0u8; 24]), &src);
    bench_one(&mut g, "Twofish-256", Twofish256::new(&[0u8; 32]), &src);
    bench_one(&mut g, "Twofish-256-ct", Twofish256Ct::new(&[0u8; 32]), &src);

    g.finish();
}

// ── Grasshopper (Kuznyechik) ──────────────────────────────────────────────

fn bench_grasshopper(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("Grasshopper");

    bench_one(&mut g, "Grasshopper-256", Grasshopper::new(&[0u8; 32]), &src);
    bench_one(&mut g, "Grasshopper-256-ct", GrasshopperCt::new(&[0u8; 32]), &src);

    g.finish();
}

// ── Magma ─────────────────────────────────────────────────────────────────

fn bench_magma(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("Magma");

    bench_one(&mut g, "Magma-256", Magma::new(&[0u8; 32]), &src);
    bench_one(&mut g, "Magma-256-ct", MagmaCt::new(&[0u8; 32]), &src);

    g.finish();
}

// ── SM4 ───────────────────────────────────────────────────────────────────

fn bench_sm4(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("SM4");

    bench_one(&mut g, "SM4-128", Sm4::new(&[0u8; 16]), &src);
    bench_one(&mut g, "SM4-128-ct", Sm4Ct::new(&[0u8; 16]), &src);

    g.finish();
}

// ── SEED ──────────────────────────────────────────────────────────────────

fn bench_seed(c: &mut Criterion) {
    let src = vec![0u8; MB];
    let mut g = c.benchmark_group("SEED");

    bench_one(&mut g, "SEED-128", Seed::new(&[0u8; 16]), &src);
    bench_one(&mut g, "SEED-128-ct", SeedCt::new(&[0u8; 16]), &src);

    g.finish();
}

// ── ZUC-128 ───────────────────────────────────────────────────────────────

fn bench_zuc(c: &mut Criterion) {
    let mut g = c.benchmark_group("ZUC");
    g.throughput(Throughput::Bytes(MB as u64));
    g.bench_function("ZUC-128", |b| {
        b.iter_batched(
            || vec![0u8; MB],
            |mut buf| {
                Zuc128::new(&[0u8; 16], &[0u8; 16]).fill(&mut buf);
                black_box(buf)
            },
            BatchSize::LargeInput,
        );
    });
    g.bench_function("ZUC-128-ct", |b| {
        b.iter_batched(
            || vec![0u8; MB],
            |mut buf| {
                Zuc128Ct::new(&[0u8; 16], &[0u8; 16]).fill(&mut buf);
                black_box(buf)
            },
            BatchSize::LargeInput,
        );
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_simon,
    bench_speck,
    bench_aes,
    bench_des,
    bench_present,
    bench_camellia,
    bench_cast128,
    bench_twofish,
    bench_grasshopper,
    bench_magma,
    bench_sm4,
    bench_seed,
    bench_zuc
);
criterion_main!(benches);
