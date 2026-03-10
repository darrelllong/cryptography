//! Compare Apple-Silicon SHAKE alternatives against baseline SHAKE outputs.
//!
//! Usage:
//!   cargo run --release --bin compare_shake --manifest-path fast/Apple-Silicon/aarch64-alt/Cargo.toml -- [vectors]

use std::hint::black_box;
use std::time::Instant;

use aarch64_alt::shake_armv8::ShakeArmv8;
use cryptography::{Shake128, Shake256, Xof};

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn fill_bytes(state: &mut u64, out: &mut [u8]) {
    for chunk in out.chunks_mut(8) {
        let bytes = xorshift64(state).to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&bytes[..n]);
    }
}

fn baseline_shake128(data: &[u8], out: &mut [u8]) {
    let mut xof = Shake128::new();
    xof.update(data);
    xof.squeeze(out);
}

fn baseline_shake256(data: &[u8], out: &mut [u8]) {
    let mut xof = Shake256::new();
    xof.update(data);
    xof.squeeze(out);
}

fn run_correctness(vectors: usize) -> Result<(), String> {
    if !ShakeArmv8::is_supported() {
        return Err("aarch64 path is not available on this machine".to_string());
    }

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..vectors {
        let in_len = (xorshift64(&mut seed) as usize) % 4096;
        let out_len = 32 + ((xorshift64(&mut seed) as usize) % 2048);

        let mut input = vec![0u8; in_len];
        fill_bytes(&mut seed, &mut input);

        let mut alt128 = vec![0u8; out_len];
        let mut base128 = vec![0u8; out_len];
        ShakeArmv8::shake128(&input, &mut alt128).map_err(|_| "alt shake128 failed".to_string())?;
        baseline_shake128(&input, &mut base128);
        if alt128 != base128 {
            return Err(format!("shake128 mismatch at vector {i}"));
        }

        let mut alt256 = vec![0u8; out_len];
        let mut base256 = vec![0u8; out_len];
        ShakeArmv8::shake256(&input, &mut alt256).map_err(|_| "alt shake256 failed".to_string())?;
        baseline_shake256(&input, &mut base256);
        if alt256 != base256 {
            return Err(format!("shake256 mismatch at vector {i}"));
        }
    }
    Ok(())
}

fn run_microbench() -> Result<(), String> {
    if !ShakeArmv8::is_supported() {
        return Err("aarch64 path is not available on this machine".to_string());
    }

    // ML-KEM-like sampling workload:
    // - SHAKE128(seed||x||y) with ~672 bytes output for rejection sampling
    // - SHAKE256(seed||nonce) with ~192 bytes output for CBD sampling
    const ITERS: usize = 80_000;

    let mut in128 = [0u8; 34];
    let mut in256 = [0u8; 33];
    let mut seed = 0x1234_5678_9abc_def0u64;
    fill_bytes(&mut seed, &mut in128);
    fill_bytes(&mut seed, &mut in256);

    let mut out128_alt = [0u8; 672];
    let mut out256_alt = [0u8; 192];
    let mut out128_base = [0u8; 672];
    let mut out256_base = [0u8; 192];

    let t0 = Instant::now();
    for _ in 0..ITERS {
        ShakeArmv8::shake128(&in128, &mut out128_alt)
            .map_err(|_| "alt shake128 failed".to_string())?;
        ShakeArmv8::shake256(&in256, &mut out256_alt)
            .map_err(|_| "alt shake256 failed".to_string())?;
        in128[0] = in128[0].wrapping_add(1);
        in256[0] = in256[0].wrapping_add(1);
    }
    let alt_elapsed = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    for _ in 0..ITERS {
        baseline_shake128(&in128, &mut out128_base);
        baseline_shake256(&in256, &mut out256_base);
        in128[1] = in128[1].wrapping_add(1);
        in256[1] = in256[1].wrapping_add(1);
    }
    let base_elapsed = t1.elapsed().as_secs_f64();

    black_box((&out128_alt, &out256_alt, &out128_base, &out256_base));

    let bytes_per_iter = (out128_alt.len() + out256_alt.len()) as f64;
    let alt_mibs = (ITERS as f64 * bytes_per_iter) / (1024.0 * 1024.0) / alt_elapsed;
    let base_mibs = (ITERS as f64 * bytes_per_iter) / (1024.0 * 1024.0) / base_elapsed;

    println!(
        "microbench SHAKE (ML-KEM-like): arm_alt={:.2} MiB/s baseline={:.2} MiB/s speedup={:.2}x",
        alt_mibs,
        base_mibs,
        if base_mibs == 0.0 {
            0.0
        } else {
            alt_mibs / base_mibs
        }
    );
    Ok(())
}

fn main() {
    let vectors = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2000);

    match run_correctness(vectors) {
        Ok(()) => println!("correctness OK for {vectors} vectors"),
        Err(e) => {
            eprintln!("correctness failed: {e}");
            std::process::exit(1);
        }
    }

    if let Err(e) = run_microbench() {
        eprintln!("microbench skipped: {e}");
    }
}
