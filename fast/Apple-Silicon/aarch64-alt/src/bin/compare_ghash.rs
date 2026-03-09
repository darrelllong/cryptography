//! Compare Apple-Silicon GHASH alternative output against reference outputs.
//!
//! Usage:
//!   cargo run --release --bin compare_ghash --manifest-path fast/Apple-Silicon/aarch64-alt/Cargo.toml -- [vectors]

use std::hint::black_box;
use std::time::Instant;

use aarch64_alt::ghash_armv8::GhashArmv8;

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn ghash_mul_vt_ref(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if ((x >> (127 - i)) & 1) != 0 {
            z ^= v;
        }
        if (v & 1) == 0 {
            v >>= 1;
        } else {
            v = (v >> 1) ^ R;
        }
    }
    z
}

fn ghash_mul_ct_ref(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        let bit_mask = 0u128.wrapping_sub(bit);
        z ^= v & bit_mask;

        let lsb = v & 1;
        let lsb_mask = 0u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (R & lsb_mask);
    }
    z
}

fn run_correctness(vectors: usize) -> Result<(), String> {
    if !GhashArmv8::is_supported() {
        return Err("ARM FEAT_AES/PMULL path is not available on this machine".to_string());
    }

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..vectors {
        let x = ((xorshift64(&mut seed) as u128) << 64) | (xorshift64(&mut seed) as u128);
        let y = ((xorshift64(&mut seed) as u128) << 64) | (xorshift64(&mut seed) as u128);

        let hw = GhashArmv8::mul(x, y).map_err(|_| "failed to run ARM GHASH".to_string())?;
        let ct = ghash_mul_ct_ref(x, y);
        let vt = ghash_mul_vt_ref(x, y);
        if hw != ct || ct != vt {
            return Err(format!("mismatch at vector {i}"));
        }
    }
    Ok(())
}

fn run_microbench() -> Result<(), String> {
    if !GhashArmv8::is_supported() {
        return Err("ARM FEAT_AES/PMULL path is not available on this machine".to_string());
    }

    const ITERS: usize = 2_000_000;

    let mut seed_hw = 0x1234_5678_9abc_def0u64;
    let mut seed_ct = seed_hw;
    let mut seed_vt = seed_hw;

    let mut acc_hw = 0u128;
    let mut acc_ct = 0u128;
    let mut acc_vt = 0u128;

    let t0 = Instant::now();
    for _ in 0..ITERS {
        let x = ((xorshift64(&mut seed_hw) as u128) << 64) | (xorshift64(&mut seed_hw) as u128);
        let y = ((xorshift64(&mut seed_hw) as u128) << 64) | (xorshift64(&mut seed_hw) as u128);
        acc_hw ^= GhashArmv8::mul(x, y).map_err(|_| "ARM GHASH failed".to_string())?;
    }
    let hw_elapsed = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    for _ in 0..ITERS {
        let x = ((xorshift64(&mut seed_ct) as u128) << 64) | (xorshift64(&mut seed_ct) as u128);
        let y = ((xorshift64(&mut seed_ct) as u128) << 64) | (xorshift64(&mut seed_ct) as u128);
        acc_ct ^= ghash_mul_ct_ref(x, y);
    }
    let ct_elapsed = t1.elapsed().as_secs_f64();

    let t2 = Instant::now();
    for _ in 0..ITERS {
        let x = ((xorshift64(&mut seed_vt) as u128) << 64) | (xorshift64(&mut seed_vt) as u128);
        let y = ((xorshift64(&mut seed_vt) as u128) << 64) | (xorshift64(&mut seed_vt) as u128);
        acc_vt ^= ghash_mul_vt_ref(x, y);
    }
    let vt_elapsed = t2.elapsed().as_secs_f64();

    black_box((acc_hw, acc_ct, acc_vt));

    let hw_mops = ITERS as f64 / hw_elapsed / 1_000_000.0;
    let ct_mops = ITERS as f64 / ct_elapsed / 1_000_000.0;
    let vt_mops = ITERS as f64 / vt_elapsed / 1_000_000.0;

    println!(
        "microbench GHASH mul: arm_alt={:.2} Mops/s ct_ref={:.2} Mops/s vt_ref={:.2} Mops/s speedup_vs_ct={:.2}x speedup_vs_vt={:.2}x",
        hw_mops,
        ct_mops,
        vt_mops,
        if ct_mops == 0.0 { 0.0 } else { hw_mops / ct_mops },
        if vt_mops == 0.0 { 0.0 } else { hw_mops / vt_mops },
    );
    Ok(())
}

fn main() {
    let vectors = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5000);

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
