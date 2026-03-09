//! Compare Apple-Silicon ChaCha20 alternative output against baseline output.
//!
//! Usage:
//!   cargo run --release --bin compare_chacha20 --manifest-path fast/Apple-Silicon/aarch64-alt/Cargo.toml -- [vectors]

use std::time::Instant;

use aarch64_alt::chacha20_armv8::ChaCha20Armv8;
use cryptography::ChaCha20;

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
    if !ChaCha20Armv8::is_supported() {
        return Err("ARM NEON path is not available on this machine".to_string());
    }

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..vectors {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        fill_bytes(&mut seed, &mut key);
        fill_bytes(&mut seed, &mut nonce);
        let counter = xorshift64(&mut seed) as u32;
        let len = (xorshift64(&mut seed) as usize) % (64 * 1024);

        let mut arm_data = vec![0u8; len];
        let mut base_data = vec![0u8; len];
        fill_bytes(&mut seed, &mut arm_data);
        base_data.copy_from_slice(&arm_data);

        let mut arm = ChaCha20Armv8::with_counter(&key, &nonce, counter)
            .map_err(|_| "failed to init ARM ChaCha20".to_string())?;
        let mut base = ChaCha20::with_counter(&key, &nonce, counter);

        arm.apply_keystream(&mut arm_data)
            .map_err(|_| "ARM keystream failed".to_string())?;
        base.apply_keystream(&mut base_data);

        if arm_data != base_data {
            return Err(format!("mismatch at vector {i}"));
        }
    }
    Ok(())
}

fn run_microbench() -> Result<(), String> {
    if !ChaCha20Armv8::is_supported() {
        return Err("ARM NEON path is not available on this machine".to_string());
    }

    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut arm = ChaCha20Armv8::with_counter(&key, &nonce, 0)
        .map_err(|_| "failed to init ARM ChaCha20".to_string())?;
    let mut base = ChaCha20::with_counter(&key, &nonce, 0);

    let mut arm_buf = vec![0u8; 16 * 1024 * 1024];
    let mut base_buf = arm_buf.clone();

    let t0 = Instant::now();
    arm.apply_keystream(&mut arm_buf)
        .map_err(|_| "ARM keystream failed".to_string())?;
    let arm_elapsed = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    base.apply_keystream(&mut base_buf);
    let base_elapsed = t1.elapsed().as_secs_f64();

    if arm_buf != base_buf {
        return Err("mismatch during microbench".to_string());
    }

    let mib = 1024.0 * 1024.0;
    let arm_mibs = arm_buf.len() as f64 / mib / arm_elapsed;
    let base_mibs = base_buf.len() as f64 / mib / base_elapsed;

    println!(
        "microbench ChaCha20 apply_keystream 16MiB: arm_alt={:.2} MiB/s baseline={:.2} MiB/s speedup={:.2}x",
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
