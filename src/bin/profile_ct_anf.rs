//! Profile Ct ANF helper activity and estimated time share by cipher.
//!
//! Build with:
//!   cargo run --release --features ct_profile --bin profile_ct_anf

#[cfg(feature = "ct_profile")]
use std::hint::black_box;
#[cfg(feature = "ct_profile")]
use std::time::{Duration, Instant};

#[cfg(feature = "ct_profile")]
use cryptography::{
    ct_profile_measure_helper_costs, ct_profile_reset, ct_profile_snapshot, BlockCipher,
    Camellia128Ct, SeedCt, Sm4Ct, Snow3gCt, Zuc128Ct,
};

#[cfg(feature = "ct_profile")]
const MIB: usize = 1024 * 1024;

#[cfg(feature = "ct_profile")]
fn bench_block<C: BlockCipher>(cipher: C) -> Duration {
    let buf_len = MIB - (MIB % C::BLOCK_LEN);
    let mut buf = vec![0u8; buf_len];
    let t0 = Instant::now();
    for chunk in buf.chunks_exact_mut(C::BLOCK_LEN) {
        cipher.encrypt(black_box(chunk));
    }
    let elapsed = t0.elapsed();
    black_box(buf);
    elapsed
}

#[cfg(feature = "ct_profile")]
fn bench_stream<F: FnMut(&mut [u8])>(mut fill: F) -> Duration {
    let mut buf = vec![0u8; MIB];
    let t0 = Instant::now();
    fill(&mut buf);
    let elapsed = t0.elapsed();
    black_box(buf);
    elapsed
}

#[cfg(feature = "ct_profile")]
fn run_case(name: &str) -> (Duration, cryptography::CtAnfProfile) {
    let k16 = [0x01u8; 16];
    let iv16 = [0u8; 16];

    ct_profile_reset();
    let elapsed = match name {
        "camellia128ct" => bench_block(Camellia128Ct::new(&k16)),
        "sm4ct" => bench_block(Sm4Ct::new(&k16)),
        "seedct" => bench_block(SeedCt::new(&k16)),
        "snow3gct" => bench_stream(|buf| Snow3gCt::new(&k16, &iv16).fill(buf)),
        "zuc128ct" => bench_stream(|buf| Zuc128Ct::new(&k16, &iv16).fill(buf)),
        _ => panic!("unknown case: {name}"),
    };
    let profile = ct_profile_snapshot();
    (elapsed, profile)
}

#[cfg(feature = "ct_profile")]
fn main() {
    let helper_cost = ct_profile_measure_helper_costs(2_000_000);

    println!("# Ct ANF Helper Profile (Apple-Silicon)");
    println!();
    println!(
        "- Helper cost estimate: `subset_mask8={:.2} ns`, `parity128={:.2} ns`, `eval_byte_sbox={:.2} ns`",
        helper_cost.subset_mask8_ns, helper_cost.parity128_ns, helper_cost.eval_byte_sbox_ns
    );
    println!("- Workload: encrypt/fill exactly 1 MiB per cipher");
    println!(
        "- Share numbers are capped at 100% because helper-only models can slightly overestimate elapsed time."
    );
    println!();
    println!("| Cipher | MB/s | subset_mask8 calls | parity128 calls | eval_byte_sbox calls | est eval share | est subset share | est parity share |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|");

    for name in ["camellia128ct", "sm4ct", "seedct", "snow3gct", "zuc128ct"] {
        let (elapsed, profile) = run_case(name);
        let elapsed_ns = elapsed.as_secs_f64() * 1e9;
        let mbs = MIB as f64 / elapsed.as_secs_f64() / MIB as f64;

        let eval_share = 100.0
            * (profile.eval_byte_sbox_calls as f64 * helper_cost.eval_byte_sbox_ns)
            / elapsed_ns;
        let subset_share =
            100.0 * (profile.subset_mask8_calls as f64 * helper_cost.subset_mask8_ns) / elapsed_ns;
        let parity_share =
            100.0 * (profile.parity128_calls as f64 * helper_cost.parity128_ns) / elapsed_ns;
        let eval_share = eval_share.clamp(0.0, 100.0);
        let subset_share = subset_share.clamp(0.0, 100.0);
        let parity_share = parity_share.clamp(0.0, 100.0);

        println!(
            "| `{}` | {:.2} | {} | {} | {} | {:.1}% | {:.1}% | {:.1}% |",
            name,
            mbs,
            profile.subset_mask8_calls,
            profile.parity128_calls,
            profile.eval_byte_sbox_calls,
            eval_share,
            subset_share,
            parity_share
        );
    }
}

#[cfg(not(feature = "ct_profile"))]
fn main() {
    eprintln!("profile_ct_anf requires --features ct_profile");
    std::process::exit(1);
}
