//! Ad-hoc bigint microbenchmarks.
//!
//! Usage:
//!   cargo run --release --bin bench_bigint
//!   cargo run --release --bin bench_bigint -- 256 512 1024
//!
//! Prints Markdown with ns/op for core bigint kernels.

use std::hint::black_box;
use std::time::{Duration, Instant};

use cryptography::vt::{BigUint, MontgomeryCtx};
use cryptography::{Csprng, CtrDrbgAes256};

const DEFAULT_BITS: &[usize] = &[256, 512, 1024, 2048, 4096];
const TARGET: Duration = Duration::from_millis(200);
const MAX_ITERS: usize = 1 << 16;

#[derive(Clone, Debug)]
struct Config {
    bits: Vec<usize>,
    repeat: usize,
}

fn parse_config() -> Config {
    let mut out = Vec::new();
    let mut repeat = 1usize;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--repeat" {
            if let Some(value) = args.next() {
                if let Ok(parsed) = value.parse::<usize>() {
                    repeat = parsed.max(1);
                }
            }
            continue;
        }
        if let Ok(bits) = arg.parse::<usize>() {
            out.push(bits);
        }
    }
    let bits = if out.is_empty() {
        DEFAULT_BITS.to_vec()
    } else {
        out
    };
    Config { bits, repeat }
}

fn random_biguint(rng: &mut CtrDrbgAes256, bits: usize) -> BigUint {
    let bits = bits.max(1);
    let byte_len = bits.div_ceil(8);
    let mut bytes = vec![0u8; byte_len.max(1)];
    rng.fill_bytes(&mut bytes);

    let top_bit = (bits - 1) % 8;
    bytes[0] |= 1u8 << top_bit;
    BigUint::from_be_bytes(&bytes)
}

fn random_odd_biguint(rng: &mut CtrDrbgAes256, bits: usize) -> BigUint {
    let mut value = random_biguint(rng, bits);
    if !value.is_odd() {
        value = value.add_ref(&BigUint::one());
    }
    value
}

fn bench_ns_per_op(mut op: impl FnMut(), min_iters: usize) -> (usize, f64) {
    let mut iters = min_iters.max(1);
    loop {
        let start = Instant::now();
        for _ in 0..iters {
            op();
        }
        let elapsed = start.elapsed();
        if elapsed >= TARGET || iters >= MAX_ITERS {
            let ns = elapsed.as_secs_f64() * 1e9 / iters as f64;
            return (iters, ns);
        }
        iters = (iters * 2).min(MAX_ITERS);
    }
}

fn run_for_bits(rng: &mut CtrDrbgAes256, bits: usize) {
    let lhs = random_biguint(rng, bits);
    let rhs = random_biguint(rng, bits);
    let modulus = random_odd_biguint(rng, bits);
    let base = random_biguint(rng, bits);
    let divisor = random_biguint(rng, bits.saturating_sub(3)).add_ref(&BigUint::one());
    let e_65537 = BigUint::from_u64(65_537);
    let exp_random = random_biguint(rng, 256);
    let ctx = MontgomeryCtx::new(&modulus).expect("odd modulus");

    println!("\n### {}-bit", bits);
    println!("| Operation | ns/op | Iters |");
    println!("|-----------|------:|------:|");

    let (iters, ns) = bench_ns_per_op(
        || {
            black_box(lhs.mul_ref(&rhs));
        },
        2,
    );
    println!("| mul_ref | {:.1} | {} |", ns, iters);

    let (iters, ns) = bench_ns_per_op(
        || {
            black_box(BigUint::mod_mul(&lhs, &rhs, &modulus));
        },
        2,
    );
    println!("| mod_mul (odd modulus) | {:.1} | {} |", ns, iters);

    let (iters, ns) = bench_ns_per_op(
        || {
            black_box(ctx.pow(&base, &e_65537));
        },
        1,
    );
    println!("| montgomery_pow (e=65537) | {:.1} | {} |", ns, iters);

    let (iters, ns) = bench_ns_per_op(
        || {
            black_box(ctx.pow(&base, &exp_random));
        },
        1,
    );
    println!("| montgomery_pow (random 256b e) | {:.1} | {} |", ns, iters);

    let (iters, ns) = bench_ns_per_op(
        || {
            black_box(lhs.div_rem(&divisor));
        },
        1,
    );
    println!("| div_rem | {:.1} | {} |", ns, iters);

    let (iters, ns) = bench_ns_per_op(
        || {
            black_box(lhs.modulo(&divisor));
        },
        1,
    );
    println!("| modulo | {:.1} | {} |", ns, iters);
}

fn main() {
    let cfg = parse_config();
    let mut rng = CtrDrbgAes256::new(&[0x4d; 48]);

    println!("# Bigint Kernel Microbenchmarks");
    println!(
        "Columns: nanoseconds per operation and iterations used. (repeat={})",
        cfg.repeat
    );
    for pass in 0..cfg.repeat {
        if cfg.repeat > 1 {
            println!("\n## Pass {}", pass + 1);
        }
        for &bits in &cfg.bits {
            run_for_bits(&mut rng, bits);
        }
    }
}
