/// SM4 throughput benchmark for pilot-bench.
///
/// Encrypts a 1 MiB buffer in ECB blocks and prints MB/s to stdout.
/// Pilot calls this repeatedly until statistical confidence is achieved.
use std::hint::black_box;
use std::time::Instant;

use cryptography::BlockCipher;
use cryptography::Sm4;

const MIB: usize = 1024 * 1024;
const BLOCK: usize = 16;
const BLOCKS: usize = MIB / BLOCK;

fn main() {
    let key = [0x01u8; 16];
    let cipher = Sm4::new(&key);

    let mut buf = vec![0u8; MIB];

    let t0 = Instant::now();
    for chunk in buf.chunks_exact_mut(BLOCK) {
        cipher.encrypt(black_box(chunk));
    }
    let elapsed = t0.elapsed();
    black_box(&buf);

    // Print throughput in MB/s as a single CSV value.
    let mb_per_sec = (BLOCKS as f64 * BLOCK as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("{:.3}", mb_per_sec);
}
