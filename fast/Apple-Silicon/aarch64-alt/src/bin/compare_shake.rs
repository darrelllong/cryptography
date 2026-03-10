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

fn baseline_shake256_parts(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = Shake256::new();
    for part in parts {
        xof.update(part);
    }
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

    // ML-KEM + ML-DSA-like sampling/transcript workloads.
    const ITERS: usize = 80_000;

    let mut kem_uniform_in = [0u8; 34];
    let mut kem_eta_in = [0u8; 33];
    let mut dsa_uniform_in = [0u8; 34];
    let mut dsa_noise_in = [0u8; 66];
    let mut dsa_part_a = [0u8; 64];
    let mut dsa_part_b = [0u8; 48];
    let mut dsa_part_c = [0u8; 96];
    let mut seed = 0x1234_5678_9abc_def0u64;
    fill_bytes(&mut seed, &mut kem_uniform_in);
    fill_bytes(&mut seed, &mut kem_eta_in);
    fill_bytes(&mut seed, &mut dsa_uniform_in);
    fill_bytes(&mut seed, &mut dsa_noise_in);
    fill_bytes(&mut seed, &mut dsa_part_a);
    fill_bytes(&mut seed, &mut dsa_part_b);
    fill_bytes(&mut seed, &mut dsa_part_c);

    let mut kem_uniform_alt = [0u8; 840];
    let mut kem_eta_alt = [0u8; 192];
    let mut dsa_uniform_alt = [0u8; 840];
    let mut dsa_eta2_alt = [0u8; 136];
    let mut dsa_gamma1_alt = [0u8; 680];
    let mut dsa_tr_alt = [0u8; 64];

    let mut kem_uniform_base = [0u8; 840];
    let mut kem_eta_base = [0u8; 192];
    let mut dsa_uniform_base = [0u8; 840];
    let mut dsa_eta2_base = [0u8; 136];
    let mut dsa_gamma1_base = [0u8; 680];
    let mut dsa_tr_base = [0u8; 64];

    let t0 = Instant::now();
    for _ in 0..ITERS {
        ShakeArmv8::mlkem_poly_uniform(&kem_uniform_in, &mut kem_uniform_alt)
            .map_err(|_| "alt mlkem_poly_uniform failed".to_string())?;
        ShakeArmv8::mlkem_poly_eta(&kem_eta_in, &mut kem_eta_alt)
            .map_err(|_| "alt mlkem_poly_eta failed".to_string())?;
        ShakeArmv8::mldsa_poly_uniform(&dsa_uniform_in, &mut dsa_uniform_alt)
            .map_err(|_| "alt mldsa_poly_uniform failed".to_string())?;
        ShakeArmv8::mldsa_poly_eta2(&dsa_noise_in, &mut dsa_eta2_alt)
            .map_err(|_| "alt mldsa_poly_eta2 failed".to_string())?;
        ShakeArmv8::mldsa_poly_gamma1(&dsa_noise_in, &mut dsa_gamma1_alt)
            .map_err(|_| "alt mldsa_poly_gamma1 failed".to_string())?;
        ShakeArmv8::mldsa_absorb_squeeze(&[&dsa_part_a, &dsa_part_b, &dsa_part_c], &mut dsa_tr_alt)
            .map_err(|_| "alt mldsa_absorb_squeeze failed".to_string())?;
        kem_uniform_in[0] = kem_uniform_in[0].wrapping_add(1);
        kem_eta_in[0] = kem_eta_in[0].wrapping_add(1);
        dsa_uniform_in[0] = dsa_uniform_in[0].wrapping_add(1);
        dsa_noise_in[0] = dsa_noise_in[0].wrapping_add(1);
        dsa_part_a[0] = dsa_part_a[0].wrapping_add(1);
    }
    let alt_elapsed = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    for _ in 0..ITERS {
        baseline_shake128(&kem_uniform_in, &mut kem_uniform_base);
        baseline_shake256(&kem_eta_in, &mut kem_eta_base);
        baseline_shake128(&dsa_uniform_in, &mut dsa_uniform_base);
        baseline_shake256(&dsa_noise_in, &mut dsa_eta2_base);
        baseline_shake256(&dsa_noise_in, &mut dsa_gamma1_base);
        baseline_shake256_parts(&[&dsa_part_a, &dsa_part_b, &dsa_part_c], &mut dsa_tr_base);
        kem_uniform_in[1] = kem_uniform_in[1].wrapping_add(1);
        kem_eta_in[1] = kem_eta_in[1].wrapping_add(1);
        dsa_uniform_in[1] = dsa_uniform_in[1].wrapping_add(1);
        dsa_noise_in[1] = dsa_noise_in[1].wrapping_add(1);
        dsa_part_b[0] = dsa_part_b[0].wrapping_add(1);
    }
    let base_elapsed = t1.elapsed().as_secs_f64();

    black_box((
        &kem_uniform_alt,
        &kem_eta_alt,
        &dsa_uniform_alt,
        &dsa_eta2_alt,
        &dsa_gamma1_alt,
        &dsa_tr_alt,
        &kem_uniform_base,
        &kem_eta_base,
        &dsa_uniform_base,
        &dsa_eta2_base,
        &dsa_gamma1_base,
        &dsa_tr_base,
    ));

    let bytes_per_iter = (kem_uniform_alt.len()
        + kem_eta_alt.len()
        + dsa_uniform_alt.len()
        + dsa_eta2_alt.len()
        + dsa_gamma1_alt.len()
        + dsa_tr_alt.len()) as f64;
    let alt_mibs = (ITERS as f64 * bytes_per_iter) / (1024.0 * 1024.0) / alt_elapsed;
    let base_mibs = (ITERS as f64 * bytes_per_iter) / (1024.0 * 1024.0) / base_elapsed;

    println!(
        "microbench SHAKE (ML-KEM+ML-DSA-like): arm_alt={:.2} MiB/s baseline={:.2} MiB/s speedup={:.2}x",
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
