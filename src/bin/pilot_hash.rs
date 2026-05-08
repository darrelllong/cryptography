/// Generic hash-throughput benchmark for pilot-bench.
///
/// Usage: pilot_hash <name>
///
/// Hashes a fixed workload with the named hash function or XOF and prints
/// MB/s to stdout.  Pilot-bench calls this repeatedly until statistical
/// confidence is reached.
///
/// Workload size is controlled by `PILOT_HASH_BYTES` (default: 262_144 bytes).
/// XOFs squeeze a fixed `PILOT_HASH_XOF_OUT` bytes (default: 32) per round
/// to make the per-byte input cost the dominant factor.
///
/// Hash names:
///   md5, sha1, ripemd160
///   sha224, sha256, sha384, sha512, sha512_224, sha512_256
///   sha3_224, sha3_256, sha3_384, sha3_512
///   shake128, shake256
use std::hint::black_box;
use std::time::Instant;

use cryptography::{
    Digest, Md5, Ripemd160, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Sha512, Sha512_224, Sha512_256, Shake128, Shake256, Xof,
};

const MIB: usize = 1024 * 1024;
const DEFAULT_WORKLOAD_BYTES: usize = 256 * 1024;
const DEFAULT_XOF_OUT_BYTES: usize = 32;

fn workload_bytes() -> usize {
    std::env::var("PILOT_HASH_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_WORKLOAD_BYTES)
}

fn xof_out_bytes() -> usize {
    std::env::var("PILOT_HASH_XOF_OUT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_XOF_OUT_BYTES)
}

fn bench_digest<H: Digest>(bytes: usize) -> f64 {
    let buf = vec![0u8; bytes];
    let mut h = H::new();
    let t0 = Instant::now();
    h.update(black_box(&buf));
    let mut out = vec![0u8; H::OUTPUT_LEN];
    h.finalize_into(&mut out);
    let elapsed = t0.elapsed();
    black_box(&out);
    bytes as f64 / elapsed.as_secs_f64() / (MIB as f64)
}

fn bench_xof<X: Xof, F: FnOnce() -> X>(make: F, bytes: usize, out_len: usize) -> f64 {
    let buf = vec![0u8; bytes];
    let mut x = make();
    let mut out = vec![0u8; out_len];
    let t0 = Instant::now();
    x.update(black_box(&buf));
    x.squeeze(&mut out);
    let elapsed = t0.elapsed();
    black_box(&out);
    bytes as f64 / elapsed.as_secs_f64() / (MIB as f64)
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pilot_hash <hash-name>");
        std::process::exit(1);
    });

    let bytes = workload_bytes();
    let xof_out = xof_out_bytes();

    let mb_per_sec: f64 = match name.to_ascii_lowercase().as_str() {
        // ── Legacy / Merkle-Damgard ───────────────────────────────────────────
        "md5" => bench_digest::<Md5>(bytes),
        "sha1" => bench_digest::<Sha1>(bytes),
        "ripemd160" => bench_digest::<Ripemd160>(bytes),
        // ── SHA-2 family ──────────────────────────────────────────────────────
        "sha224" => bench_digest::<Sha224>(bytes),
        "sha256" => bench_digest::<Sha256>(bytes),
        "sha384" => bench_digest::<Sha384>(bytes),
        "sha512" => bench_digest::<Sha512>(bytes),
        "sha512_224" => bench_digest::<Sha512_224>(bytes),
        "sha512_256" => bench_digest::<Sha512_256>(bytes),
        // ── SHA-3 family ──────────────────────────────────────────────────────
        "sha3_224" => bench_digest::<Sha3_224>(bytes),
        "sha3_256" => bench_digest::<Sha3_256>(bytes),
        "sha3_384" => bench_digest::<Sha3_384>(bytes),
        "sha3_512" => bench_digest::<Sha3_512>(bytes),
        // ── SHAKE XOFs ────────────────────────────────────────────────────────
        "shake128" => bench_xof::<Shake128, _>(Shake128::new, bytes, xof_out),
        "shake256" => bench_xof::<Shake256, _>(Shake256::new, bytes, xof_out),
        _ => {
            eprintln!("unknown hash: {}", name);
            std::process::exit(1);
        }
    };

    println!("{:.3}", mb_per_sec);
}
