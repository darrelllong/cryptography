//! Compare Apple-Silicon AES-256 alternative output against baseline output.
//!
//! Usage:
//!   cargo run --release --bin compare_aes256 --manifest-path fast/Apple-Silicon/aarch64-alt/Cargo.toml -- [vectors]

use std::time::Instant;

use aarch64_alt::aes256_armv8::Aes256Armv8;
use cryptography::{Aes256, BlockCipher};

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

fn run_correctness(vectors: usize) -> Result<(), String> {
    if !Aes256Armv8::is_supported() {
        return Err("ARM FEAT_AES is not available on this machine".to_string());
    }

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..vectors {
        let mut key = [0u8; 32];
        let mut block = [0u8; 16];
        fill_bytes(&mut seed, &mut key);
        fill_bytes(&mut seed, &mut block);

        let mut arm_block = block;
        let mut baseline_block = block;

        let arm = Aes256Armv8::new(&key).map_err(|_| "failed to init ARM AES".to_string())?;
        let baseline = Aes256::new(&key);

        arm.encrypt_block(&mut arm_block)
            .map_err(|_| "ARM encrypt failed".to_string())?;
        baseline.encrypt(&mut baseline_block);
        if arm_block != baseline_block {
            return Err(format!("encrypt mismatch at vector {i}"));
        }

        arm.decrypt_block(&mut arm_block)
            .map_err(|_| "ARM decrypt failed".to_string())?;
        baseline.decrypt(&mut baseline_block);
        if arm_block != baseline_block || arm_block != block {
            return Err(format!("decrypt mismatch at vector {i}"));
        }
    }
    Ok(())
}

fn run_microbench() -> Result<(), String> {
    if !Aes256Armv8::is_supported() {
        return Err("ARM FEAT_AES is not available on this machine".to_string());
    }

    let key = [0x42u8; 32];
    let arm = Aes256Armv8::new(&key).map_err(|_| "failed to init ARM AES".to_string())?;
    let baseline = Aes256::new(&key);

    let mut arm_buf = vec![0u8; 1024 * 1024];
    let mut base_buf = arm_buf.clone();

    let t0 = Instant::now();
    for chunk in arm_buf.chunks_exact_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        arm.encrypt_block(&mut block)
            .map_err(|_| "ARM encrypt failed".to_string())?;
        chunk.copy_from_slice(&block);
    }
    let arm_elapsed = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    for chunk in base_buf.chunks_exact_mut(16) {
        baseline.encrypt(chunk);
    }
    let base_elapsed = t1.elapsed().as_secs_f64();

    let mib = 1024.0 * 1024.0;
    let arm_mibs = arm_buf.len() as f64 / mib / arm_elapsed;
    let base_mibs = base_buf.len() as f64 / mib / base_elapsed;

    println!(
        "microbench AES-256 encrypt 1MiB: arm_alt={:.2} MiB/s baseline={:.2} MiB/s speedup={:.2}x",
        arm_mibs,
        base_mibs,
        if base_mibs == 0.0 {
            0.0
        } else {
            arm_mibs / base_mibs
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
