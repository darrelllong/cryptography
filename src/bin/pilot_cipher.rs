/// Generic cipher throughput benchmark for pilot-bench.
///
/// Usage: pilot_cipher <name>
///
/// Encrypts 1 MiB with the named cipher and prints MB/s to stdout.
/// Pilot-bench calls this repeatedly until statistical confidence is reached.
///
/// Block cipher names (add "ct" suffix for constant-time variant):
///   aes128, aes192, aes256
///   camellia128, camellia192, camellia256
///   cast128, des, 3des
///   grasshopper, magma
///   present80, present128
///   seed, serpent128, serpent192, serpent256
///   sm4, twofish128, twofish192, twofish256
///   simon32_64, simon48_72, simon48_96, simon64_96, simon64_128
///   simon96_96, simon96_144, simon128_128, simon128_192, simon128_256
///   speck32_64, speck48_72, speck48_96, speck64_96, speck64_128
///   speck96_96, speck96_144, speck128_128, speck128_192, speck128_256
///
/// Stream cipher names:
///   chacha20, xchacha20, salsa20, rabbit, zuc128, zuc128ct, snow3g, snow3gct
use std::hint::black_box;
use std::time::Instant;

use cryptography::chacha20::{ChaCha20, XChaCha20};
use cryptography::rabbit::Rabbit;
use cryptography::salsa20::Salsa20;
use cryptography::zuc::{Zuc128, Zuc128Ct};
use cryptography::BlockCipher;
use cryptography::{
    Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct, Camellia128, Camellia128Ct, Camellia192,
    Camellia192Ct, Camellia256, Camellia256Ct, Cast128, Cast128Ct, Des, DesCt, Grasshopper,
    GrasshopperCt, Magma, MagmaCt, Present128, Present128Ct, Present80, Present80Ct, Seed, SeedCt,
    Serpent128, Serpent128Ct, Serpent192, Serpent192Ct, Serpent256, Serpent256Ct, Simon128_128,
    Simon128_192, Simon128_256, Simon32_64, Simon48_72, Simon48_96, Simon64_128, Simon64_96,
    Simon96_144, Simon96_96, Sm4, Sm4Ct, Speck128_128, Speck128_192, Speck128_256, Speck32_64,
    Speck48_72, Speck48_96, Speck64_128, Speck64_96, Speck96_144, Speck96_96, TripleDes,
    Twofish128, Twofish128Ct, Twofish192, Twofish192Ct, Twofish256, Twofish256Ct,
};
use cryptography::{Snow3g, Snow3gCt};

const MIB: usize = 1024 * 1024;

fn bench_block<C: BlockCipher>(cipher: C) -> f64 {
    let buf_len = MIB - (MIB % C::BLOCK_LEN);
    let mut buf = vec![0u8; buf_len];
    let t0 = Instant::now();
    for chunk in buf.chunks_exact_mut(C::BLOCK_LEN) {
        cipher.encrypt(black_box(chunk));
    }
    let elapsed = t0.elapsed();
    black_box(&buf);
    buf_len as f64 / elapsed.as_secs_f64() / (MIB as f64)
}

fn bench_stream<F: FnMut(&mut [u8])>(mut fill: F) -> f64 {
    let mut buf = vec![0u8; MIB];
    let t0 = Instant::now();
    fill(&mut buf);
    let elapsed = t0.elapsed();
    black_box(&buf);
    MIB as f64 / elapsed.as_secs_f64() / (MIB as f64)
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pilot_cipher <cipher-name>");
        std::process::exit(1);
    });

    // Fixed test keys — all zeros of sufficient length for any cipher.
    let k8: &[u8; 8] = &[0x01; 8];
    let k9: &[u8; 9] = &[0x01; 9];
    let k10: &[u8; 10] = &[0x01; 10];
    let k12: &[u8; 12] = &[0x01; 12];
    let k16: &[u8; 16] = &[0x01; 16];
    let k18: &[u8; 18] = &[0x01; 18];
    let k24: &[u8; 24] = &[0x01; 24];
    let k32: &[u8; 32] = &[0x01; 32];

    let mb_per_sec: f64 = match name.to_ascii_lowercase().as_str() {
        // ── AES ───────────────────────────────────────────────────────────────
        "aes128" => bench_block(Aes128::new(k16)),
        "aes128ct" => bench_block(Aes128Ct::new(k16)),
        "aes192" => bench_block(Aes192::new(k24)),
        "aes192ct" => bench_block(Aes192Ct::new(k24)),
        "aes256" => bench_block(Aes256::new(k32)),
        "aes256ct" => bench_block(Aes256Ct::new(k32)),
        // ── Camellia ──────────────────────────────────────────────────────────
        "camellia128" => bench_block(Camellia128::new(k16)),
        "camellia128ct" => bench_block(Camellia128Ct::new(k16)),
        "camellia192" => bench_block(Camellia192::new(k24)),
        "camellia192ct" => bench_block(Camellia192Ct::new(k24)),
        "camellia256" => bench_block(Camellia256::new(k32)),
        "camellia256ct" => bench_block(Camellia256Ct::new(k32)),
        // ── CAST-128 ──────────────────────────────────────────────────────────
        "cast128" | "cast5" => bench_block(Cast128::new(k16)),
        "cast128ct" | "cast5ct" => bench_block(Cast128Ct::new(k16)),
        // ── DES ───────────────────────────────────────────────────────────────
        "des" => bench_block(Des::new(k8)),
        "desct" => bench_block(DesCt::new(k8)),
        "3des" => bench_block(TripleDes::new_3key(k24)),
        // ── Grasshopper (Кузнечик) ────────────────────────────────────────────
        "grasshopper" => bench_block(Grasshopper::new(k32)),
        "grasshopperct" => bench_block(GrasshopperCt::new(k32)),
        // ── Magma ─────────────────────────────────────────────────────────────
        "magma" => bench_block(Magma::new(k32)),
        "magmact" => bench_block(MagmaCt::new(k32)),
        // ── PRESENT ───────────────────────────────────────────────────────────
        "present80" => bench_block(Present80::new(k10)),
        "present80ct" => bench_block(Present80Ct::new(k10)),
        "present128" => bench_block(Present128::new(k16)),
        "present128ct" => bench_block(Present128Ct::new(k16)),
        // ── SEED ──────────────────────────────────────────────────────────────
        "seed" => bench_block(Seed::new(k16)),
        "seedct" => bench_block(SeedCt::new(k16)),
        // ── Serpent ───────────────────────────────────────────────────────────
        "serpent128" => bench_block(Serpent128::new(k16)),
        "serpent128ct" => bench_block(Serpent128Ct::new(k16)),
        "serpent192" => bench_block(Serpent192::new(k24)),
        "serpent192ct" => bench_block(Serpent192Ct::new(k24)),
        "serpent256" => bench_block(Serpent256::new(k32)),
        "serpent256ct" => bench_block(Serpent256Ct::new(k32)),
        // ── SM4 ───────────────────────────────────────────────────────────────
        "sm4" => bench_block(Sm4::new(k16)),
        "sm4ct" => bench_block(Sm4Ct::new(k16)),
        // ── Twofish ───────────────────────────────────────────────────────────
        "twofish128" => bench_block(Twofish128::new(k16)),
        "twofish128ct" => bench_block(Twofish128Ct::new(k16)),
        "twofish192" => bench_block(Twofish192::new(k24)),
        "twofish192ct" => bench_block(Twofish192Ct::new(k24)),
        "twofish256" => bench_block(Twofish256::new(k32)),
        "twofish256ct" => bench_block(Twofish256Ct::new(k32)),
        // ── Simon ─────────────────────────────────────────────────────────────
        "simon32_64" => bench_block(Simon32_64::new(k8)),
        "simon48_72" => bench_block(Simon48_72::new(k9)),
        "simon48_96" => bench_block(Simon48_96::new(k12)),
        "simon64_96" => bench_block(Simon64_96::new(k12)),
        "simon64_128" => bench_block(Simon64_128::new(k16)),
        "simon96_96" => bench_block(Simon96_96::new(k12)),
        "simon96_144" => bench_block(Simon96_144::new(k18)),
        "simon128_128" => bench_block(Simon128_128::new(k16)),
        "simon128_192" => bench_block(Simon128_192::new(k24)),
        "simon128_256" => bench_block(Simon128_256::new(k32)),
        // ── Speck ─────────────────────────────────────────────────────────────
        "speck32_64" => bench_block(Speck32_64::new(k8)),
        "speck48_72" => bench_block(Speck48_72::new(k9)),
        "speck48_96" => bench_block(Speck48_96::new(k12)),
        "speck64_96" => bench_block(Speck64_96::new(k12)),
        "speck64_128" => bench_block(Speck64_128::new(k16)),
        "speck96_96" => bench_block(Speck96_96::new(k12)),
        "speck96_144" => bench_block(Speck96_144::new(k18)),
        "speck128_128" => bench_block(Speck128_128::new(k16)),
        "speck128_192" => bench_block(Speck128_192::new(k24)),
        "speck128_256" => bench_block(Speck128_256::new(k32)),
        // ── Stream ciphers ────────────────────────────────────────────────────
        "chacha20" => {
            let nonce = &[0u8; 12];
            bench_stream(|buf| {
                ChaCha20::new(k32, nonce).apply_keystream(buf);
            })
        }
        "xchacha20" => {
            let nonce = &[0u8; 24];
            bench_stream(|buf| {
                XChaCha20::new(k32, nonce).apply_keystream(buf);
            })
        }
        "salsa20" => {
            let nonce = &[0u8; 8];
            bench_stream(|buf| {
                Salsa20::new(k32, nonce).apply_keystream(buf);
            })
        }
        "rabbit" => {
            let iv = &[0u8; 8];
            bench_stream(|buf| {
                Rabbit::new(k16, iv).apply_keystream(buf);
            })
        }
        "zuc128" => {
            let iv = &[0u8; 16];
            bench_stream(|buf| {
                Zuc128::new(k16, iv).fill(buf);
            })
        }
        "zuc128ct" => {
            let iv = &[0u8; 16];
            bench_stream(|buf| {
                Zuc128Ct::new(k16, iv).fill(buf);
            })
        }
        "snow3g" => {
            let iv = &[0u8; 16];
            bench_stream(|buf| {
                Snow3g::new(k16, iv).fill(buf);
            })
        }
        "snow3gct" => {
            let iv = &[0u8; 16];
            bench_stream(|buf| {
                Snow3gCt::new(k16, iv).fill(buf);
            })
        }
        _ => {
            eprintln!("unknown cipher: {}", name);
            eprintln!("run with --help-ciphers to list available names");
            std::process::exit(1);
        }
    };

    println!("{:.3}", mb_per_sec);
}
