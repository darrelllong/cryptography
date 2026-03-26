//! Compare Apple-Silicon SHA-256 alternative output against baseline output.
//!
//! Usage:
//!   cargo run --release --bin compare_sha256 --manifest-path fast/Apple-Silicon/aarch64-alt/Cargo.toml -- [vectors]

use std::time::Instant;

use aarch64_alt::sha256_armv8::Sha256Armv8;
use cryptography::Sha256;

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
    if !Sha256Armv8::is_supported() {
        return Err("ARM FEAT_SHA2 is not available on this machine".to_string());
    }

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..vectors {
        let len = (xorshift64(&mut seed) as usize) % 8192;
        let mut msg = vec![0u8; len];
        fill_bytes(&mut seed, &mut msg);

        let arm =
            Sha256Armv8::digest(&msg).map_err(|_| "failed to hash with ARM SHA2".to_string())?;
        let baseline = Sha256::digest(&msg);
        if arm != baseline {
            return Err(format!("digest mismatch at vector {i}"));
        }
    }
    Ok(())
}

fn run_microbench() -> Result<(), String> {
    if !Sha256Armv8::is_supported() {
        return Err("ARM FEAT_SHA2 is not available on this machine".to_string());
    }

    let mut msg = vec![0u8; 16 * 1024 * 1024];
    let mut seed = 0x42u64;
    fill_bytes(&mut seed, &mut msg);

    let t0 = Instant::now();
    let arm = Sha256Armv8::digest(&msg).map_err(|_| "ARM SHA2 digest failed".to_string())?;
    let arm_elapsed = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let baseline = Sha256::digest(&msg);
    let base_elapsed = t1.elapsed().as_secs_f64();

    if arm != baseline {
        return Err("digest mismatch during microbench".to_string());
    }

    let mib = 1024.0 * 1024.0;
    let arm_mibs = msg.len() as f64 / mib / arm_elapsed;
    let base_mibs = msg.len() as f64 / mib / base_elapsed;

    println!(
        "microbench SHA-256 digest 16MiB: arm_alt={:.2} MiB/s baseline={:.2} MiB/s speedup={:.2}x",
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
